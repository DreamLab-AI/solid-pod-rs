//! Provenance `_prov` API + the composition wiring for the LDP write hook
//! (master-plan §2.4, ADR-059 D1/D5/D7 — Phase 5).
//!
//! Three concerns live here:
//!
//! 1. **`GET /{pod}/_prov/{commit_sha}`** — resolve a git-mark commit SHA back
//!    to the resource it wrote + its [`ProvenanceMark`] (and any block-trail
//!    anchor recorded in the sidecar). Public (the same audience as the
//!    `.prov.ttl` sidecar the route complements).
//! 2. **`POST /{pod}/_prov/anchor`** — NIP-98-authenticated (pod owner),
//!    payment-gated *explicit upgrade* of an existing git-mark to a Bitcoin
//!    block-trail anchor (the high-value opt-in). Debits the caller's Web
//!    Ledger by the pod's configured anchor price, anchors the commit SHA on
//!    the pod's trail via [`MempoolBlockAnchorer`], and rewrites the resource's
//!    `.prov.ttl` sidecar to carry the anchor.
//! 3. **Composition helpers for the LDP write hook** — [`resolve_anchor_policy`]
//!    reads a resource's effective ACL and maps a `ProvenanceAnchor` condition
//!    onto an [`AnchorPolicy`]; [`build_anchorer`] constructs the optional
//!    [`ProvenanceLog::anchorer`]; [`epoch_push_and_maybe_anchor`] backs the
//!    `AnchorPolicy::Epoch` batch (one Bitcoin tx notarises N commits, ADR-059
//!    D5) with a small per-pod persisted [`EpochAccumulator`].
//!
//! All of this is native-only (it shells to `git` and talks to the mempool);
//! the pure composition types ([`ProvenanceLog`], [`AnchorPolicy`],
//! [`EpochAccumulator`]) live in `solid-pod-rs::provenance` and compile to wasm.

use std::sync::Arc;

use actix_web::{web, Error as ActixError, HttpRequest, HttpResponse};
use bytes::Bytes;

use solid_pod_rs::provenance::{
    prov_ttl, AnchorPolicy, BlockAnchorer, ClosedEpoch, EpochAccumulator, ProvenanceMark,
};
use solid_pod_rs::storage::Storage;
use solid_pod_rs::wac::{anchor_mode_of, AnchorMode};

use crate::mempool::{MempoolBlockAnchorer, MempoolHttpClient};
use crate::trail_store::load_trail;
use crate::{extract_pubkey, pod_repo_path, require_pod_owner, AppState};

/// Default epoch close threshold (commit count) when the operator has not
/// configured one. Bounds on-chain cost: one anchor per this many commits
/// (master-plan §5 "ACL writes epoch-only to bound cost"). Read from
/// `JSS_PROV_EPOCH_SIZE` when set.
const DEFAULT_EPOCH_SIZE: usize = 16;

/// Environment override for the epoch close threshold.
pub const EPOCH_SIZE_ENV: &str = "JSS_PROV_EPOCH_SIZE";

/// Pod-storage path of the persisted epoch accumulator (the pending batch of
/// git commit SHAs awaiting a single anchoring tx).
const EPOCH_PATH: &str = "/.well-known/prov/epoch.json";

/// The configured epoch close threshold (clamped to ≥ 1).
fn epoch_size() -> usize {
    std::env::var(EPOCH_SIZE_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n >= 1)
        .unwrap_or(DEFAULT_EPOCH_SIZE)
}

// ---------------------------------------------------------------------------
// Composition wiring for the LDP write hook
// ---------------------------------------------------------------------------

/// Read `resource_path`'s **effective** ACL and resolve the
/// [`AnchorPolicy`] + optional ticker override for a write to it.
///
/// - No `ProvenanceAnchor` condition on the resource (the common case) ⇒
///   [`AnchorPolicy::Never`] — git-mark only, no on-chain cost.
/// - A `ProvenanceAnchor` with `anchorMode "always"`/`"inline"` ⇒
///   [`AnchorPolicy::HighValue`] (anchored inline; the hook passes `high_value
///   = true`).
/// - A `ProvenanceAnchor` with the default `"epoch"` mode ⇒
///   [`AnchorPolicy::Epoch`] (batched into the per-pod epoch).
///
/// Fail-open for provenance: any ACL read error ⇒ `Never` (a missing/broken
/// ACL must never *force* expensive anchoring, and the write itself was
/// already authorised upstream).
pub(crate) async fn resolve_anchor_policy(
    state: &AppState,
    resource_path: &str,
) -> (AnchorPolicy, Option<String>) {
    let acl = match crate::find_effective_acl_dyn(&*state.storage, resource_path).await {
        Ok(Some(doc)) => doc,
        _ => return (AnchorPolicy::Never, None),
    };
    let Some(graph) = acl.graph.as_ref() else {
        return (AnchorPolicy::Never, None);
    };
    // Scan every authorisation's conditions for the first ProvenanceAnchor.
    for auth in graph {
        if let Some(conds) = auth.condition.as_ref() {
            if let Some(mode) = anchor_mode_of(conds) {
                let ticker = conds.iter().find_map(|c| match c {
                    solid_pod_rs::wac::Condition::ProvenanceAnchor(b) => b.ticker.clone(),
                    _ => None,
                });
                let policy = match mode {
                    AnchorMode::Inline => AnchorPolicy::HighValue,
                    AnchorMode::Epoch => AnchorPolicy::Epoch,
                };
                return (policy, ticker);
            }
        }
    }
    (AnchorPolicy::Never, None)
}

/// Build the optional expensive-tier anchorer for a pod, or `None` when the
/// pod is not configured for Bitcoin anchoring (no pay-token / no trail minted)
/// — in which case [`ProvenanceLog`](solid_pod_rs::provenance::ProvenanceLog)
/// degrades to git-mark-only.
///
/// Returns the anchorer plus the resolved `(ticker, network)` so the caller
/// anchors against the right trail. The trail must already be minted on the
/// pod (its `network` is authoritative).
pub(crate) async fn build_anchorer(
    state: &AppState,
    ticker_override: Option<&str>,
) -> Option<(Arc<dyn BlockAnchorer>, String, String)> {
    // The pod must have a configured pay-token (its trail backs the anchor).
    let token = state.pay_config.token.as_ref()?;
    let ticker = ticker_override
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| token.ticker.clone());
    if ticker.is_empty() {
        return None;
    }

    // The trail must be minted on this pod (load its network).
    let trail = load_trail(&state.storage, &ticker).await.ok().flatten()?;
    let network = trail.network.clone();

    let mempool = match &state.mempool_url {
        Some(url) => MempoolHttpClient::new(url.clone()),
        None => MempoolHttpClient::from_env(),
    };
    let anchorer = MempoolBlockAnchorer::with_storage(mempool, state.storage.clone());
    Some((Arc::new(anchorer), ticker, network))
}

/// Load the persisted per-pod pending epoch batch (the commit SHAs awaiting a
/// single anchoring tx). Returns an empty list on any read/parse miss.
async fn load_epoch_commits(storage: &Arc<dyn Storage>) -> Vec<String> {
    match storage.get(EPOCH_PATH).await {
        Ok((bytes, _)) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Persist the per-pod pending epoch batch.
async fn save_epoch_commits(storage: &Arc<dyn Storage>, commits: &[String]) -> Result<(), String> {
    let body = serde_json::to_vec(commits).map_err(|e| e.to_string())?;
    storage
        .put(EPOCH_PATH, Bytes::from(body), "application/json")
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Feed a git commit SHA into the pod's epoch (the `AnchorPolicy::Epoch` path),
/// and when the epoch fills, anchor the **batch Merkle root** with a single
/// Bitcoin tx (ADR-059 D5) and reset the epoch.
///
/// The pending batch is persisted as a plain SHA list; the Merkle root is
/// computed via [`EpochAccumulator`] (the pure, wasm-safe tree) at close time.
///
/// Returns `Ok(Some(closed))` when this push closed an epoch (the batch was
/// anchored — `closed.root` is the value committed on-chain, `closed.commits`
/// the SHAs it notarises), `Ok(None)` when the commit was merely accumulated.
/// Best-effort: the caller (the LDP hook) swallows the error — a failed epoch
/// anchor must never fail the write.
pub(crate) async fn epoch_push_and_maybe_anchor(
    state: &AppState,
    anchorer: &Arc<dyn BlockAnchorer>,
    ticker: &str,
    network: &str,
    commit_sha: &str,
) -> Result<Option<ClosedEpoch>, String> {
    let size = epoch_size();
    let mut commits = load_epoch_commits(&state.storage).await;
    // Idempotency: never double-count the same commit in a batch.
    if !commits.iter().any(|c| c == commit_sha) {
        commits.push(commit_sha.to_string());
    }

    if commits.len() < size {
        // Not full yet — persist the growing batch and wait for more commits.
        save_epoch_commits(&state.storage, &commits).await?;
        return Ok(None);
    }

    // Epoch full → compute the single Merkle root over the batch and anchor it.
    let mut acc = EpochAccumulator::new(size);
    for c in &commits {
        acc.push(c.clone());
    }
    let closed = acc.close().ok_or("epoch close produced nothing")?;
    anchorer
        .anchor(ticker, &closed.root, network)
        .await
        .map_err(|e| e.to_string())?;
    // Reset the on-disk epoch (the batch is now anchored on-chain).
    save_epoch_commits(&state.storage, &[]).await?;
    Ok(Some(closed))
}

// ---------------------------------------------------------------------------
// GET /{pod}/_prov/{commit_sha}
// ---------------------------------------------------------------------------

/// Resolve a git-mark commit SHA to its resource + [`ProvenanceMark`].
///
/// `git show` the commit for metadata + changed files, pick the content file
/// it wrote (excluding sidecars), then load that resource's `.prov.ttl`
/// sidecar — if present and it matches this commit, return the recorded mark
/// (carrying any block-trail anchor); otherwise reconstruct a git-only mark
/// from the commit metadata.
async fn handle_resolve(
    path: web::Path<(String, String)>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ActixError> {
    let (pod, commit_sha) = path.into_inner();

    let Some(repo) = pod_repo_path(&state, &pod) else {
        return Ok(prov_err(
            "git provenance not available (no FS backend / invalid pod)",
            501,
        ));
    };
    if !repo.join(".git").is_dir() {
        return Ok(prov_err("pod is not git-backed", 404));
    }

    let resolved = match solid_pod_rs_git::resolve_commit(&repo, &commit_sha).await {
        Ok(r) => r,
        Err(e) => {
            let code = e.status_code();
            return Ok(prov_err(
                &format!("commit not found: {e}"),
                if code == 404 { 404 } else { 400 },
            ));
        }
    };

    // Pick the resource the write targeted: the first non-sidecar file the
    // commit touched. (A git-mark commits exactly one content file + nothing
    // else; ACL/meta/prov writes are never marked, see `git_mark_write`.)
    let resource_rel = resolved.files.iter().find(|f| !is_sidecar(f)).cloned();
    let Some(resource_rel) = resource_rel else {
        return Ok(prov_err("commit touched no content resource", 404));
    };
    let resource = format!("/{pod}/{resource_rel}");

    // Try the persisted sidecar first (it carries any anchor + the exact mark).
    let sidecar = format!("{resource}.prov.ttl");
    let sidecar_ttl = state
        .storage
        .get(&sidecar)
        .await
        .ok()
        .map(|(b, _)| String::from_utf8_lossy(&b).into_owned());

    // Build the JSON response. The mark is authoritative from the sidecar when
    // present; otherwise reconstruct from git metadata (git-only, no anchor).
    let body = serde_json::json!({
        "pod": pod,
        "resource": resource,
        "commit": {
            "sha": resolved.hash,
            "parent": resolved.parent,
            "agent_did": resolved.author_email,
            "committer": resolved.author_name,
            "subject": resolved.subject,
            "committed_at": resolved.committed_at,
        },
        // The PROV-O sidecar (Turtle), inlined so a caller gets the full mark
        // (incl. any block-trail anchor) without a second round-trip. `null`
        // when no sidecar was persisted (e.g. a commit predating git-marks).
        "prov_ttl": sidecar_ttl,
        "anchored": sidecar_ttl.as_deref().map(|t| t.contains("bt:txid")).unwrap_or(false),
    });

    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .json(body))
}

// ---------------------------------------------------------------------------
// POST /{pod}/_prov/anchor
// ---------------------------------------------------------------------------

/// Body of `POST /{pod}/_prov/anchor`: the commit SHA (git-mark) to upgrade to
/// a Bitcoin block-trail anchor, and an optional trail ticker override.
#[derive(Debug, serde::Deserialize)]
struct AnchorBody {
    /// The git commit SHA (a previously-recorded git-mark) to anchor.
    commit_sha: String,
    /// Optional trail ticker; defaults to the pod's configured pay-token.
    #[serde(default)]
    ticker: Option<String>,
}

/// Explicitly upgrade an existing git-mark to a Bitcoin block-trail anchor
/// (the high-value opt-in). NIP-98-authenticated as the pod owner and
/// payment-gated: the caller's Web Ledger is debited by the pod's configured
/// anchor price before the on-chain anchor is produced.
///
/// On success the commit SHA is anchored on the pod's trail (one MRC20 state),
/// and the resource's `.prov.ttl` sidecar is rewritten to carry the anchor so
/// `GET /{pod}/_prov/{commit_sha}` and the sidecar both reflect the upgrade.
async fn handle_anchor(
    path: web::Path<String>,
    req: HttpRequest,
    state: web::Data<AppState>,
    body: Bytes,
) -> Result<HttpResponse, ActixError> {
    let pod = path.into_inner();

    // (1) AuthN: NIP-98, and the caller MUST be the pod owner (only the owner
    // upgrades their own provenance — keys + on-chain spend live pod-side).
    let owner = match require_pod_owner(&req, &pod).await {
        Some(pk) => pk,
        None => {
            // Distinguish "no/invalid NIP-98" from "authenticated but not owner".
            return Ok(match extract_pubkey(&req).await {
                Some(_) => prov_err("not the pod owner", 403),
                None => prov_err("NIP-98 authentication required", 401),
            });
        }
    };
    let did = format!("did:nostr:{owner}");

    let req_body: AnchorBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => return Ok(prov_err(&format!("malformed anchor request: {e}"), 400)),
    };
    // Validate the commit id shape early (the git resolver also checks).
    if req_body.commit_sha.is_empty()
        || req_body.commit_sha.len() > 64
        || !req_body.commit_sha.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Ok(prov_err("invalid commit_sha", 400));
    }

    let Some(repo) = pod_repo_path(&state, &pod) else {
        return Ok(prov_err("git provenance not available", 501));
    };
    if !repo.join(".git").is_dir() {
        return Ok(prov_err("pod is not git-backed", 404));
    }

    // (2) Resolve the commit → resource (must be a real git-mark).
    let resolved = match solid_pod_rs_git::resolve_commit(&repo, &req_body.commit_sha).await {
        Ok(r) => r,
        Err(e) => return Ok(prov_err(&format!("commit not found: {e}"), 404)),
    };
    let Some(resource_rel) = resolved.files.iter().find(|f| !is_sidecar(f)).cloned() else {
        return Ok(prov_err("commit touched no content resource", 404));
    };
    let resource = format!("/{pod}/{resource_rel}");

    // (3) Build the anchorer (pod must have a minted trail).
    let Some((anchorer, ticker, network)) =
        build_anchorer(&state, req_body.ticker.as_deref()).await
    else {
        return Ok(prov_err(
            "pod not configured for Bitcoin anchoring (no pay-token / trail not minted)",
            400,
        ));
    };

    // (4) Payment gate: charge the pod's configured anchor price. Debit BEFORE
    // the on-chain action; if anchoring then fails, refund (credit back).
    let price = anchor_price_sats(&state);
    if price > 0 {
        if let Err(rsp) = debit(&state, &did, price).await {
            return Ok(rsp);
        }
    }

    // (5) Anchor the commit SHA on the trail (the expensive tier). The anchored
    // state_hash IS the git commit SHA — binding git ↔ Bitcoin (§2.3).
    let anchor = match anchorer.anchor(&ticker, &resolved.hash, &network).await {
        Ok(a) => a,
        Err(e) => {
            // Refund the debit — no anchor was produced.
            if price > 0 {
                let _ = credit(&state, &did, price).await;
            }
            return Ok(prov_err(&format!("anchor failed: {e}"), 502));
        }
    };

    // (6) Rewrite the resource's `.prov.ttl` sidecar to carry the anchor.
    let mark = ProvenanceMark {
        resource: resource.clone(),
        git: solid_pod_rs::provenance::GitMark {
            commit_sha: resolved.hash.clone(),
            repo: pod.clone(),
            branch: "main".to_string(),
            parent: resolved.parent.clone(),
        },
        anchor: Some(anchor.clone()),
        agent_did: resolved.author_email.clone(),
        created: resolved.committed_at,
    };
    let ttl = prov_ttl(&mark);
    let sidecar = format!("{resource}.prov.ttl");
    if let Err(e) = state
        .storage
        .put(&sidecar, Bytes::from(ttl.into_bytes()), "text/turtle")
        .await
    {
        // The on-chain anchor succeeded; the sidecar rewrite is best-effort.
        tracing::warn!(
            target: "solid_pod_rs_server::prov",
            sidecar = %sidecar,
            "anchor sidecar rewrite failed (anchor still on-chain): {e}"
        );
    }

    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .json(serde_json::json!({
            "pod": pod,
            "resource": resource,
            "commit_sha": resolved.hash,
            "anchor": {
                "ticker": anchor.ticker,
                "txid": anchor.txid,
                "vout": anchor.vout,
                "address": anchor.address,
                "network": anchor.network,
                "state_hash": anchor.state_hash,
            },
            "charged_sats": price,
        })))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Whether a repo-relative path is a control-plane / provenance sidecar (never
/// the content resource a git-mark targets).
fn is_sidecar(path: &str) -> bool {
    path.ends_with(".acl") || path.ends_with(".meta") || path.ends_with(".prov.ttl")
}

/// The pod's configured per-anchor price in satoshis (the explicit-upgrade
/// gate). Reuses the pay-token rate as the anchor price; `0` ⇒ ungated.
fn anchor_price_sats(state: &AppState) -> u64 {
    std::env::var("JSS_PROV_ANCHOR_PRICE_SATS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or_else(|| {
            state
                .pay_config
                .token
                .as_ref()
                .map(|t| t.rate.max(1))
                .unwrap_or(0)
        })
}

/// Debit the caller's Web Ledger by `sats`, mapping insufficient-balance to a
/// 402 and other failures to a 500. Uses the same `StoragePaymentStore` ledger
/// path as `/pay/*` so balances are consistent.
async fn debit(state: &AppState, did: &str, sats: u64) -> Result<(), HttpResponse> {
    use crate::handlers::pay::StoragePaymentStore;
    use solid_pod_rs::payments::{PaymentError, PaymentStore};

    let store = StoragePaymentStore::new(&*state.storage);
    let mut ledger = store
        .read_ledger()
        .await
        .map_err(|e| prov_err(&format!("ledger read failed: {e}"), 500))?;
    if let Err(e) = ledger.debit(did, sats) {
        return Err(match e {
            PaymentError::InsufficientBalance { balance, cost } => HttpResponse::PaymentRequired()
                .json(serde_json::json!({
                    "error": "Insufficient balance to anchor",
                    "balance": balance,
                    "cost": cost,
                })),
            other => prov_err(&format!("debit failed: {other}"), 500),
        });
    }
    store
        .write_ledger(&ledger)
        .await
        .map_err(|e| prov_err(&format!("ledger write failed: {e}"), 500))?;
    Ok(())
}

/// Credit the caller's Web Ledger by `sats` (the anchor-failure refund).
async fn credit(state: &AppState, did: &str, sats: u64) -> Result<(), String> {
    use crate::handlers::pay::StoragePaymentStore;
    use solid_pod_rs::payments::PaymentStore;

    let store = StoragePaymentStore::new(&*state.storage);
    let mut ledger = store.read_ledger().await.map_err(|e| e.to_string())?;
    ledger.credit(did, sats);
    store.write_ledger(&ledger).await.map_err(|e| e.to_string())
}

/// JSS-shaped JSON error response.
fn prov_err(msg: &str, status: u16) -> HttpResponse {
    HttpResponse::build(
        actix_web::http::StatusCode::from_u16(status)
            .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR),
    )
    .content_type("application/json")
    .json(serde_json::json!({ "error": msg }))
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

/// Register the `_prov` routes. Must be registered BEFORE the LDP catch-all so
/// `_prov` path segments are never treated as pod resources (mirrors the
/// `/pods/{pk}/_git/*` ordering).
pub fn register(app: &mut web::ServiceConfig) {
    app.route("/{pod}/_prov/anchor", web::post().to(handle_anchor))
        .route("/{pod}/_prov/{commit_sha}", web::get().to(handle_resolve));
}
