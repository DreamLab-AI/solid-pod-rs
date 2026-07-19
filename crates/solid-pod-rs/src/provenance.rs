//! Provenance primitives — composable, cost-tiered traceability for pod writes.
//!
//! Implements the data model and traits from
//! [`docs/design/provenance-upgrade-master-plan.md`](../../docs/design/provenance-upgrade-master-plan.md)
//! §2 and [ADR-059](../../docs/adr/ADR-059-provenance-primitives-block-trails-git-marks.md)
//! (D1, D2, D4, D6). Two tiers compose into one chain:
//!
//! - **git-mark** (cheap, always-on): every pod write becomes a git commit;
//!   the commit SHA is captured as a [`GitMark`]. Content-addressed,
//!   append-only, tamper-evident ordering for free. The native implementation
//!   of [`GitMarker`] lives in `solid-pod-rs-git::mark` (it shells to `git`);
//!   wasm consumers compile against a no-op marker.
//! - **block-trail anchor** (expensive, opt-in): a Bitcoin-anchored MRC20 state
//!   whose taproot UTXO externally timestamps a record ([`BlockTrailAnchor`]).
//!   Reserved for high-value records. The [`BlockAnchorer`] trait is defined
//!   here; a real implementation lands in Phase 4 (`bitcoin_tx.rs` + mempool).
//!
//! A [`ProvenanceMark`] always carries a [`GitMark`] and *optionally* a
//! [`BlockTrailAnchor`]. The anchor's `state_hash` commits to the git SHA (or an
//! epoch Merkle root over many commits), binding both tiers into one chain.
//!
//! ## wasm32 safety
//!
//! Everything in this module — the types and [`prov_ttl`] — is pure logic and
//! compiles for `wasm32-unknown-unknown`. The traits are `?Send` (matching the
//! crate's existing [`crate::payments::PaymentStore`] pattern) so a wasm
//! single-threaded executor can implement them. No `tokio`, no process spawning,
//! no I/O leaks into this surface.

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Data model (§2.1)
// ---------------------------------------------------------------------------

/// A provenance mark over a pod resource write.
///
/// Always carries a git commit ([`GitMark`]); optionally upgraded with a
/// Bitcoin block-trail anchor ([`BlockTrailAnchor`]) for high-value records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceMark {
    /// Pod-relative path of the resource the write targeted.
    pub resource: String,
    /// The git commit the write produced — **always present** (cheap tier).
    pub git: GitMark,
    /// Optional Bitcoin block-trail anchor — **opt-in** (expensive tier).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<BlockTrailAnchor>,
    /// `did:nostr` of the writer (NIP-98 authenticated principal), or an
    /// anonymous marker when the write was unauthenticated.
    pub agent_did: String,
    /// Unix seconds at which the mark was produced.
    pub created: u64,
}

/// The cheap-tier git commit captured for a pod write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitMark {
    /// Git SHA-1 of the commit the write produced.
    pub commit_sha: String,
    /// Pod repo slug (the pod's first path segment / pubkey).
    pub repo: String,
    /// Branch the commit landed on. Pinned to `"main"` by `init.rs`.
    pub branch: String,
    /// Prior commit SHA (the append-only chain link), or `None` for the
    /// genesis commit of a freshly-initialised repo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
}

/// The on-disk `gitmark.json` envelope — the Carvalho-lineage substrate
/// shape (ADR-124, C7), verified byte-for-byte against
/// `microfed/gitmark.json`.
///
/// **Exactly five keys**: `@id`, `genesis`, `nick`, `package`, `repository`.
/// `@context`/`@type`/`commit`/`parent` are deliberately ABSENT — they are
/// not in the ground-truth file (parent-linkage lives in `blocktrails.json`
/// `states[]`/`txo[]`, not here). For byte-parity with create-agent, emit
/// only these five keys.
///
/// `@id` is `gitmark:<commit_sha>:<vout>`; `genesis` is
/// `gitmark:<first-commit-sha>:0` (and equals `@id` for the first mark).
/// This is a *projection* of the internal [`GitMark`] — the in-memory
/// `{commit_sha, repo, branch, parent}` shape (used by the PROV-O sidecar +
/// the composition log) is unchanged; only the on-disk substrate file
/// adopts this shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitMarkEnvelope {
    /// `gitmark:<commit_sha>:<vout>` — the single-use-seal coordinate.
    #[serde(rename = "@id")]
    pub id: String,
    /// `gitmark:<first-commit-sha>:0` — the trail's genesis seal.
    pub genesis: String,
    /// Short human name for the mark (e.g. the package/pod nickname).
    pub nick: String,
    /// Pod-relative package path (e.g. `./package.json`).
    pub package: String,
    /// Repo-relative root (e.g. `./`).
    pub repository: String,
}

impl GitMark {
    /// Project this internal [`GitMark`] onto the canonical 5-key
    /// `gitmark.json` envelope (ADR-124, C7).
    ///
    /// - `vout` is the seal output index for this mark's `@id`
    ///   (`gitmark:<commit_sha>:<vout>`).
    /// - `genesis_sha` is the trail's first commit SHA; pass this mark's own
    ///   `commit_sha` for the genesis mark (then `genesis == @id`).
    /// - `nick`/`package` are the additive projection fields; `repository`
    ///   defaults to `./` (repo-relative root, matching the ground truth).
    ///
    /// `branch`/`parent` are intentionally NOT emitted — they are not part of
    /// the on-disk envelope. Parent-linkage is carried by `blocktrails.json`.
    #[must_use]
    pub fn to_gitmark_envelope(
        &self,
        vout: u32,
        genesis_sha: &str,
        nick: impl Into<String>,
        package: impl Into<String>,
    ) -> GitMarkEnvelope {
        GitMarkEnvelope {
            id: format!("gitmark:{}:{vout}", self.commit_sha),
            genesis: format!("gitmark:{genesis_sha}:0"),
            nick: nick.into(),
            package: package.into(),
            repository: "./".to_string(),
        }
    }

    /// Serialise this mark to the canonical `gitmark.json` text (5-key
    /// envelope, ADR-124). Convenience over [`Self::to_gitmark_envelope`] +
    /// `serde_json::to_string_pretty`.
    pub fn to_gitmark_json(
        &self,
        vout: u32,
        genesis_sha: &str,
        nick: impl Into<String>,
        package: impl Into<String>,
    ) -> Result<String, ProvenanceError> {
        let env = self.to_gitmark_envelope(vout, genesis_sha, nick, package);
        serde_json::to_string_pretty(&env)
            .map_err(|e| ProvenanceError::Store(format!("gitmark.json serialise: {e}")))
    }
}

/// The expensive-tier Bitcoin anchor for a record.
///
/// Reuses the existing [`crate::mrc20`] crypto (`Mrc20State`, `bt_address`,
/// `verify_mrc20_anchor`) — no crypto is re-implemented here. The
/// `state_strings` carry the portable, independently-verifiable proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockTrailAnchor {
    /// Trail ticker / identifier.
    pub ticker: String,
    /// `sha256_hex(jcs(state))` — links into the MRC20 trail and commits to
    /// the git SHA (or an epoch Merkle root).
    pub state_hash: String,
    /// Bitcoin transaction id of the anchoring UTXO.
    pub txid: String,
    /// Output index of the anchoring UTXO.
    pub vout: u32,
    /// Derived P2TR address (`mrc20::bt_address`).
    pub address: String,
    /// `"testnet4"` | `"mainnet"` (or any network the operator configures).
    pub network: String,
    /// Confirmation height; `None` until the anchoring tx confirms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blockheight: Option<u64>,
    /// Portable, independently-verifiable proof — the serialised states.
    #[serde(default)]
    pub state_strings: Vec<String>,
    /// Issuer's compressed pubkey (66-char hex). Together with
    /// `state_strings` it re-derives the taproot `address` via
    /// `mrc20::bt_address` — the read-side check
    /// ([`BlockAnchorer::verify`])
    /// needs it to confirm `address` was not forged. `None` on legacy /
    /// partially-populated anchors (verify then has nothing to re-derive
    /// against and reports `false`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<String>,
}

/// A single UTXO step in a [`BlocktrailEnvelope`] `txo[]` chain — the
/// BIP-341 single-use-seal coordinate (`<txid>:<vout>`) plus its
/// confirmation status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlocktrailTxo {
    /// `<txid>:<vout>` — the seal output this state was sealed under.
    pub outpoint: String,
    /// Confirmation height; `None` until the sealing tx confirms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blockheight: Option<u64>,
}

/// The on-disk `blocktrails.json` envelope — the 4th web-contract layer
/// (ADR-124 §2.2). The `gitmark.json` substrate anchors the reducer/state/
/// ledger layers; `blocktrails.json` is the **trail** layer.
///
/// Per the reconciliation (C6): this shape is reconstructed from the
/// `webcontracts.org` / "Melvo Predicts" reference pattern — it is NOT
/// byte-verifiable against a fetchable create-agent artefact (the
/// create-agent repo contains only `gitmark.json`). Only `gitmark.json` is
/// "verbatim".
///
/// Shape: `@type "Blocktrail"`, `profile "gitmark"` (the anchoring
/// substrate), a BIP-341 single-use-seal chain expressed as `states[]`
/// (the commit SHAs — the ledger states, in order) paired with `txo[]` (the
/// UTXO chain that seals them). `genesis` ties back to the `gitmark.json`
/// genesis seal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlocktrailEnvelope {
    /// `gitmark:<first-commit-sha>:0` — the genesis seal (shared with the
    /// `gitmark.json` `genesis`).
    #[serde(rename = "@id")]
    pub id: String,
    /// Always `"Blocktrail"`.
    #[serde(rename = "@type")]
    pub type_: String,
    /// Anchoring substrate profile — always `"gitmark"` here.
    pub profile: String,
    /// `gitmark:<first-commit-sha>:0`.
    pub genesis: String,
    /// The ledger states in order — commit SHAs the trail notarises.
    pub states: Vec<String>,
    /// The BIP-341 single-use-seal UTXO chain sealing `states[]` (1:1 order).
    pub txo: Vec<BlocktrailTxo>,
}

impl BlocktrailEnvelope {
    /// Build a `Blocktrail` over an ordered set of commit SHAs (`states`)
    /// and their sealing UTXO chain (`txo`), profiled on the `gitmark`
    /// substrate (ADR-124 §2.2, C6 reference shape).
    ///
    /// `genesis_sha` is the trail's first commit SHA; the envelope's `@id`
    /// and `genesis` are both `gitmark:<genesis_sha>:0`.
    #[must_use]
    pub fn new_gitmark_profile(
        genesis_sha: &str,
        states: Vec<String>,
        txo: Vec<BlocktrailTxo>,
    ) -> Self {
        let genesis = format!("gitmark:{genesis_sha}:0");
        Self {
            id: genesis.clone(),
            type_: "Blocktrail".to_string(),
            profile: "gitmark".to_string(),
            genesis,
            states,
            txo,
        }
    }

    /// Serialise to the canonical `blocktrails.json` text.
    pub fn to_blocktrails_json(&self) -> Result<String, ProvenanceError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| ProvenanceError::Store(format!("blocktrails.json serialise: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Failures surfaced by the provenance primitives.
///
/// Hand-rolled (no `thiserror` derive) so the type compiles on `wasm32`
/// without pulling proc-macro evaluation into the pure surface; the variants
/// mirror the crate's error-message style.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceError {
    /// The underlying git operation failed (spawn, commit, rev-parse, …).
    Git(String),
    /// The Bitcoin anchor operation failed (mempool, tx-build, verify, …).
    Anchor(String),
    /// The resource path was rejected (traversal, sidecar suffix, …).
    InvalidPath(String),
    /// Persisting or emitting the mark failed.
    Store(String),
}

impl std::fmt::Display for ProvenanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProvenanceError::Git(m) => write!(f, "git-mark: {m}"),
            ProvenanceError::Anchor(m) => write!(f, "block-anchor: {m}"),
            ProvenanceError::InvalidPath(m) => write!(f, "invalid provenance path: {m}"),
            ProvenanceError::Store(m) => write!(f, "provenance store: {m}"),
        }
    }
}

impl std::error::Error for ProvenanceError {}

// ---------------------------------------------------------------------------
// Traits (§2.2)
// ---------------------------------------------------------------------------

/// Cheap tier. Implemented by `solid-pod-rs-git` (shells to `git`).
///
/// `?Send` for wasm32-safety, matching the crate's [`crate::payments::PaymentStore`]
/// pattern. The wasm `core` consumer compiles against a no-op marker.
#[async_trait::async_trait(?Send)]
pub trait GitMarker: Send + Sync {
    /// Stage `path` and commit it, returning the resulting [`GitMark`].
    ///
    /// `repo` is the absolute filesystem path to the (non-bare) pod repo;
    /// `path` is the repo-relative path written; `agent_did` is recorded as
    /// the commit author email; `message` is the commit subject. When there
    /// is nothing to commit the implementation returns a mark referencing the
    /// current HEAD without erroring.
    async fn mark_write(
        &self,
        repo: &Path,
        path: &str,
        agent_did: &str,
        message: &str,
    ) -> Result<GitMark, ProvenanceError>;

    /// Return the current HEAD commit SHA, or `None` for an unborn branch.
    async fn head(&self, repo: &Path) -> Result<Option<String>, ProvenanceError>;
}

/// Expensive tier. Server-side (mempool + Bitcoin TX), behind feature `mrc20`.
///
/// Defined here; a real implementation lands in Phase 4 (`bitcoin_tx.rs`).
#[async_trait::async_trait(?Send)]
pub trait BlockAnchorer: Send + Sync {
    /// Anchor `state_hash` under `ticker` on `network`, returning the produced
    /// [`BlockTrailAnchor`]. Implemented by
    /// `solid-pod-rs-server::mempool::MempoolBlockAnchorer` (builds + broadcasts
    /// a taproot MRC20 anchoring tx via `bitcoin_tx.rs`).
    async fn anchor(
        &self,
        ticker: &str,
        state_hash: &str,
        network: &str,
    ) -> Result<BlockTrailAnchor, ProvenanceError>;

    /// Verify a previously-produced anchor against the chain / fixtures
    /// (re-derives the taproot address from the portable proof, then confirms a
    /// UTXO sits at it).
    async fn verify(&self, anchor: &BlockTrailAnchor) -> Result<bool, ProvenanceError>;
}

// ---------------------------------------------------------------------------
// Composition policy (§2.3, ADR-059 D1/D5)
// ---------------------------------------------------------------------------

/// When a [`ProvenanceLog::record`] write should incur the expensive Bitcoin
/// block-trail anchor on top of the always-on git-mark.
///
/// The cheap tier (git-mark) runs for *every* policy — these variants only
/// govern the **opt-in** anchor. Pure, `Copy`, wasm-safe: it carries no I/O.
///
/// | Variant | Anchor behaviour |
/// |--------------|--------------------------------------------------------|
/// | [`Never`](AnchorPolicy::Never) | git-mark only — no on-chain cost. The default for ordinary writes. |
/// | [`Always`](AnchorPolicy::Always) | anchor **every** write (commits the git SHA on-chain). Expensive; only for trails where every state must be externally timestamped. |
/// | [`HighValue`](AnchorPolicy::HighValue) | anchor iff the resource is flagged anchor-worthy (its ACL carries a `ProvenanceAnchor` condition / the caller passes the high-value flag). Settlement receipts, elevation/ACSP decisions. |
/// | [`Epoch`](AnchorPolicy::Epoch) | accumulate the git SHA into an [`EpochAccumulator`]; the batch root is anchored **once** on epoch close (one Bitcoin tx notarises many commits — ADR-059 D5). |
///
/// An anchor is attempted only when the policy says so **and** the
/// [`ProvenanceLog`] was built with an anchorer ([`ProvenanceLog::anchorer`]
/// is `Some`). With `anchorer: None` (the wasm / no-Bitcoin pod) every policy
/// degrades to git-mark-only, silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum AnchorPolicy {
    /// git-mark only; never anchor. The default for ordinary pod writes.
    #[default]
    Never,
    /// Anchor every write — the git commit SHA is committed on-chain each time.
    Always,
    /// Anchor only when the resource is flagged high-value (ACL carries a
    /// `ProvenanceAnchor` condition). Otherwise git-mark only.
    HighValue,
    /// Accumulate the commit into the current epoch; the epoch's Merkle root is
    /// anchored once on close (amortised on-chain cost — ADR-059 D5).
    Epoch,
}

impl AnchorPolicy {
    /// Whether *this write* should be anchored inline (i.e. produce a
    /// [`BlockTrailAnchor`] on the returned mark), given whether the resource
    /// is flagged high-value.
    ///
    /// - `Never` / `Epoch` ⇒ never inline (`Epoch` defers to the accumulator).
    /// - `Always` ⇒ always inline.
    /// - `HighValue` ⇒ inline iff `high_value`.
    #[must_use]
    pub fn anchors_inline(self, high_value: bool) -> bool {
        match self {
            AnchorPolicy::Never | AnchorPolicy::Epoch => false,
            AnchorPolicy::Always => true,
            AnchorPolicy::HighValue => high_value,
        }
    }
}

// ---------------------------------------------------------------------------
// Composition log (§2.2 `ProvenanceLog`, §2.3 composition rule)
// ---------------------------------------------------------------------------

/// The composition point for the two provenance tiers (master-plan §2.2/§2.3,
/// ADR-059 D1).
///
/// A `ProvenanceLog` always holds the cheap-tier [`GitMarker`] and *optionally*
/// the expensive-tier [`BlockAnchorer`]. [`record`](ProvenanceLog::record)
/// implements the **cheap-always, expensive-opt-in** rule:
///
/// 1. **Always** `marker.mark_write()` → [`GitMark`] (every write becomes a
///    commit; we capture the SHA).
/// 2. **Conditionally** `anchorer.anchor()` when the [`AnchorPolicy`] says this
///    write anchors inline AND an anchorer is present. The anchor's
///    `state_hash` is set to the git commit SHA — so the Bitcoin UTXO commits
///    to the git history, **binding the two tiers into one chain** (§2.3).
///
/// The returned [`ProvenanceMark`] carries the git-mark always and the anchor
/// when one was produced. Persisting the PROV-O sidecar and emitting the
/// `Updates-via` notification (step 3) is the server's job — kept out of this
/// pure surface so it compiles for wasm.
///
/// ## wasm32 safety
///
/// `Arc<dyn GitMarker>` / `Arc<dyn BlockAnchorer>` are `?Send` trait objects;
/// the type holds no runtime. On wasm the pod constructs it with a no-op marker
/// and `anchorer: None`, so `record` is git-mark-only and never reaches any
/// Bitcoin I/O.
#[derive(Clone)]
pub struct ProvenanceLog {
    /// Cheap tier — always invoked. The native server injects
    /// `solid-pod-rs-git`'s `ShellGitMarker`; wasm injects a no-op.
    pub marker: Arc<dyn GitMarker>,
    /// Expensive tier — optional. `None` in pods that do not pay for Bitcoin
    /// anchoring (and always `None` on wasm).
    pub anchorer: Option<Arc<dyn BlockAnchorer>>,
}

impl std::fmt::Debug for ProvenanceLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvenanceLog")
            .field("marker", &"Arc<dyn GitMarker>")
            .field(
                "anchorer",
                &self.anchorer.as_ref().map(|_| "Arc<dyn BlockAnchorer>"),
            )
            .finish()
    }
}

/// Descriptor of a single pod write passed to [`ProvenanceLog::record`].
///
/// Borrowed (no allocation on the hot path), mirroring
/// [`crate::wac::conditions::RequestContext`]. Bundles the write identity
/// (repo/path/agent/message), the expensive-tier [`AnchorPolicy`] + its
/// `high_value` flag, and the trail coordinates (`ticker`/`network`) an anchor
/// targets. The trail fields are ignored unless the policy actually anchors.
#[derive(Debug, Clone, Copy)]
pub struct WriteRecord<'a> {
    /// Absolute filesystem path to the (non-bare) pod repo.
    pub repo: &'a Path,
    /// Repo-relative path of the resource written.
    pub path: &'a str,
    /// `did:nostr` of the writer (NIP-98 principal), or an anonymous marker.
    pub agent_did: &'a str,
    /// Commit subject (the LDP method + path).
    pub message: &'a str,
    /// Expensive-tier policy (see [`AnchorPolicy`]).
    pub policy: AnchorPolicy,
    /// Whether the resource is flagged high-value (ACL `ProvenanceAnchor`).
    pub high_value: bool,
    /// Trail ticker to anchor against (used only when anchoring).
    pub ticker: &'a str,
    /// Bitcoin network of the trail (used only when anchoring).
    pub network: &'a str,
    /// Unix seconds stamped onto the produced mark.
    pub created: u64,
}

impl ProvenanceLog {
    /// Construct a git-mark-only log (no Bitcoin tier). The common case for
    /// ordinary pods and the only shape available on wasm.
    #[must_use]
    pub fn new(marker: Arc<dyn GitMarker>) -> Self {
        Self {
            marker,
            anchorer: None,
        }
    }

    /// Construct a log with both tiers wired.
    #[must_use]
    pub fn with_anchorer(marker: Arc<dyn GitMarker>, anchorer: Arc<dyn BlockAnchorer>) -> Self {
        Self {
            marker,
            anchorer: Some(anchorer),
        }
    }

    /// Record a pod resource write across both tiers (the composition rule).
    ///
    /// The write is described by a [`WriteRecord`]. Always commits (cheap tier).
    /// Then, iff `policy.anchors_inline(high_value)` — both carried by the
    /// [`WriteRecord`] — AND an anchorer is present, anchors the **git commit
    /// SHA** under the record's `ticker`/`network`, attaching the
    /// [`BlockTrailAnchor`] to the returned mark. The anchor's `state_hash` is
    /// the commit SHA, binding git ↔ Bitcoin (master-plan §2.3).
    ///
    /// For [`AnchorPolicy::Epoch`] this method never anchors inline — the caller
    /// feeds the returned `git.commit_sha` into an [`EpochAccumulator`] and
    /// anchors the batch root on epoch close.
    ///
    /// Errors from the **cheap** tier propagate (the git-mark is the contract).
    /// Errors from the **expensive** tier are returned too, so the caller can
    /// decide its own best-effort policy — the server hook logs+swallows them
    /// (a failed anchor must never fail the LDP write), exactly as it does for
    /// the git-mark.
    pub async fn record(&self, rec: WriteRecord<'_>) -> Result<ProvenanceMark, ProvenanceError> {
        // 1. Cheap tier — ALWAYS. A failure here is a hard error: the git-mark
        //    is the always-on contract.
        let git = self
            .marker
            .mark_write(rec.repo, rec.path, rec.agent_did, rec.message)
            .await?;

        // 2. Expensive tier — opt-in. Only when the policy anchors this write
        //    inline AND an anchorer is wired. The anchored state_hash IS the
        //    git commit SHA — the Bitcoin UTXO now commits to the git history
        //    (master-plan §2.3 "binds both primitives into one chain").
        let anchor = if rec.policy.anchors_inline(rec.high_value) {
            match &self.anchorer {
                Some(a) => Some(a.anchor(rec.ticker, &git.commit_sha, rec.network).await?),
                None => None,
            }
        } else {
            None
        };

        Ok(ProvenanceMark {
            resource: path_to_resource(rec.path),
            git,
            anchor,
            agent_did: rec.agent_did.to_string(),
            created: rec.created,
        })
    }
}

/// Normalise a repo-relative `path` into the pod-relative `resource` form a
/// [`ProvenanceMark`] records (leading slash). Idempotent for already-absolute
/// inputs.
fn path_to_resource(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

// ---------------------------------------------------------------------------
// Epoch Merkle-root anchoring (§2.3, ADR-059 D5) — pure, wasm-safe
// ---------------------------------------------------------------------------

/// Compute a binary SHA-256 Merkle root over `leaves` (each a 32-byte digest),
/// duplicating the last node on an odd level (Bitcoin-style). Returns the
/// all-zero digest for an empty input.
///
/// Pure and wasm-safe — uses only the always-compiled `sha2` dependency. Leaves
/// are hashed *as given*; callers pass `sha256(commit_sha)` so the tree commits
/// to the exact commit identifiers.
fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            // Duplicate the last node when the level is odd.
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                left
            };
            let mut h = Sha256::new();
            h.update(left);
            h.update(right);
            next.push(h.finalize().into());
            i += 2;
        }
        level = next;
    }
    level[0]
}

/// Hash one leaf value (a git commit SHA, as text) into the Merkle leaf digest.
fn merkle_leaf(commit_sha: &str) -> [u8; 32] {
    Sha256::digest(commit_sha.as_bytes()).into()
}

/// A Merkle inclusion proof: the sibling digests from leaf to root, each tagged
/// with whether the sibling sits on the **right** of the running hash at that
/// level. Verified with [`EpochAccumulator::verify_inclusion`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Hex of the leaf value's digest (`sha256(commit_sha)`).
    pub leaf: String,
    /// Sibling steps from the leaf upward: `(sibling_hex, sibling_is_right)`.
    pub siblings: Vec<(String, bool)>,
}

/// Accumulates git commit SHAs into an epoch and, on close, yields the single
/// Merkle root to anchor (ADR-059 D5 — *one Bitcoin tx notarises many
/// commits*).
///
/// Writes whose [`AnchorPolicy`] is [`Epoch`](AnchorPolicy::Epoch) call
/// [`push`](EpochAccumulator::push) with the commit SHA the git-mark produced.
/// When the configured commit-count threshold is reached
/// ([`is_full`](EpochAccumulator::is_full)), the caller [`close`s](EpochAccumulator::close)
/// the epoch to obtain the root (hex) and the batched SHAs, anchors the root
/// **once** via a [`BlockAnchorer`], and starts a fresh epoch. A per-commit
/// [`inclusion_proof`](EpochAccumulator::inclusion_proof) lets any commit be
/// proven against the anchored root without re-anchoring.
///
/// Pure and wasm-safe: the accumulator and Merkle maths carry no I/O; the
/// single anchor call is the caller's, via the (optional) anchorer.
#[derive(Debug, Clone)]
pub struct EpochAccumulator {
    /// Commit SHAs collected so far this epoch (insertion order = leaf order).
    commits: Vec<String>,
    /// Commit-count threshold at which the epoch is considered full. Operator
    /// policy (master-plan §5: "ACL writes epoch-only to bound cost").
    threshold: usize,
}

/// The sealed result of closing an epoch: the Merkle root to anchor plus the
/// batch of commit SHAs it commits to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosedEpoch {
    /// Hex SHA-256 Merkle root over the epoch's commit-SHA leaves — the single
    /// value anchored on-chain for the whole batch.
    pub root: String,
    /// The commit SHAs this root notarises (leaf order).
    pub commits: Vec<String>,
}

impl EpochAccumulator {
    /// New, empty epoch with a close `threshold` (clamped to ≥ 1).
    #[must_use]
    pub fn new(threshold: usize) -> Self {
        Self {
            commits: Vec::new(),
            threshold: threshold.max(1),
        }
    }

    /// Add a git commit SHA to the current epoch.
    pub fn push(&mut self, commit_sha: impl Into<String>) {
        self.commits.push(commit_sha.into());
    }

    /// Number of commits accumulated this epoch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.commits.len()
    }

    /// Whether the epoch holds no commits.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.commits.is_empty()
    }

    /// The configured close threshold.
    #[must_use]
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Whether the epoch has reached its close threshold (time to anchor).
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.commits.len() >= self.threshold
    }

    /// The current Merkle root (hex) over the accumulated commits, without
    /// draining. Returns `None` for an empty epoch (nothing to anchor).
    #[must_use]
    pub fn root(&self) -> Option<String> {
        if self.commits.is_empty() {
            return None;
        }
        let leaves: Vec<[u8; 32]> = self.commits.iter().map(|c| merkle_leaf(c)).collect();
        Some(hex::encode(merkle_root(&leaves)))
    }

    /// Seal the epoch: compute the root, return it with the batched commit SHAs,
    /// and **drain** the accumulator so a fresh epoch begins. Returns `None`
    /// (and drains nothing) for an empty epoch.
    pub fn close(&mut self) -> Option<ClosedEpoch> {
        if self.commits.is_empty() {
            return None;
        }
        let commits = std::mem::take(&mut self.commits);
        let leaves: Vec<[u8; 32]> = commits.iter().map(|c| merkle_leaf(c)).collect();
        let root = hex::encode(merkle_root(&leaves));
        Some(ClosedEpoch { root, commits })
    }

    /// Produce an inclusion proof for the commit at leaf `index` against the
    /// *current* set of accumulated commits. `None` if `index` is out of range.
    ///
    /// The proof verifies against the root produced by [`root`](Self::root) /
    /// [`close`](Self::close) over the same commit set — i.e. against the value
    /// anchored on-chain.
    #[must_use]
    pub fn inclusion_proof(&self, index: usize) -> Option<MerkleProof> {
        let n = self.commits.len();
        if index >= n {
            return None;
        }
        let mut level: Vec<[u8; 32]> = self.commits.iter().map(|c| merkle_leaf(c)).collect();
        let leaf_hex = hex::encode(level[index]);
        let mut idx = index;
        let mut siblings: Vec<(String, bool)> = Vec::new();
        while level.len() > 1 {
            let sibling_idx = if idx.is_multiple_of(2) {
                idx + 1
            } else {
                idx - 1
            };
            // On an odd level the rightmost node is paired with itself.
            let sib = if sibling_idx < level.len() {
                level[sibling_idx]
            } else {
                level[idx]
            };
            let sibling_is_right = idx.is_multiple_of(2);
            siblings.push((hex::encode(sib), sibling_is_right));

            // Build the next level.
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut i = 0;
            while i < level.len() {
                let left = level[i];
                let right = if i + 1 < level.len() {
                    level[i + 1]
                } else {
                    left
                };
                let mut h = Sha256::new();
                h.update(left);
                h.update(right);
                next.push(h.finalize().into());
                i += 2;
            }
            level = next;
            idx /= 2;
        }
        Some(MerkleProof {
            leaf: leaf_hex,
            siblings,
        })
    }

    /// Verify a [`MerkleProof`] against an expected `root_hex` (the anchored
    /// root). Recomputes the path and compares — no accumulator state needed,
    /// so a verifier can check inclusion with only the proof + the on-chain
    /// root.
    #[must_use]
    pub fn verify_inclusion(proof: &MerkleProof, root_hex: &str) -> bool {
        let Ok(mut acc) = hex::decode(&proof.leaf) else {
            return false;
        };
        if acc.len() != 32 {
            return false;
        }
        for (sib_hex, sib_is_right) in &proof.siblings {
            let Ok(sib) = hex::decode(sib_hex) else {
                return false;
            };
            if sib.len() != 32 {
                return false;
            }
            let mut h = Sha256::new();
            if *sib_is_right {
                h.update(&acc);
                h.update(&sib);
            } else {
                h.update(&sib);
                h.update(&acc);
            }
            acc = h.finalize().to_vec();
        }
        hex::encode(acc) == root_hex
    }
}

// ---------------------------------------------------------------------------
// PROV-O serialiser (§2.3 step 3, D7)
// ---------------------------------------------------------------------------

/// Escape a string for inclusion inside a Turtle double-quoted literal
/// (RDF 1.1 Turtle §2.5.3 / §6.4 string escapes).
fn ttl_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

/// Render `secs` (Unix seconds) as an `xsd:dateTime` literal in UTC.
///
/// Pure, allocation-light, and wasm-safe — avoids dragging `chrono`'s
/// formatting into the pure surface (the crate already depends on `chrono`
/// but we keep this self-contained and deterministic for the golden test).
fn xsd_datetime(secs: u64) -> String {
    // Civil-from-days (Howard Hinnant's algorithm) — exact, no leap tables.
    let days = (secs / 86_400) as i64;
    let rem = (secs % 86_400) as i64;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Produce a minimal, correct PROV-O Turtle sidecar for a [`ProvenanceMark`].
///
/// The mark is modelled as a `prov:Activity` (the write) that
/// `prov:generated` the resource entity, was performed by the agent
/// (`prov:wasAssociatedWith`), and is identified by its git commit SHA. The
/// resource entity records `prov:wasGeneratedBy` the activity. When a
/// block-trail anchor is present it is emitted as an associated entity bearing
/// the txid/state-hash so the sidecar carries both tiers.
///
/// Kept deliberately small: stable prefix block, one activity, one entity, one
/// agent, optional anchor entity. Round-trip-safe with the unit tests below.
pub fn prov_ttl(mark: &ProvenanceMark) -> String {
    let sha = &mark.git.commit_sha;
    let resource = ttl_escape(&mark.resource);
    let agent = ttl_escape(&mark.agent_did);
    let branch = ttl_escape(&mark.git.branch);
    let repo = ttl_escape(&mark.git.repo);
    let when = xsd_datetime(mark.created);

    let mut ttl = String::new();
    ttl.push_str("@prefix prov: <http://www.w3.org/ns/prov#> .\n");
    ttl.push_str("@prefix xsd:  <http://www.w3.org/2001/XMLSchema#> .\n");
    ttl.push_str("@prefix git:  <https://w3id.org/git#> .\n");
    ttl.push_str("@prefix bt:   <https://blocktrails.org/ns#> .\n\n");

    // Activity: the write, identified by the commit it produced.
    ttl.push_str(&format!("<urn:git:commit:{sha}> a prov:Activity ;\n"));
    ttl.push_str(&format!("    prov:generated <{resource}> ;\n"));
    ttl.push_str(&format!("    prov:wasAssociatedWith <{agent}> ;\n"));
    ttl.push_str(&format!(
        "    prov:endedAtTime \"{when}\"^^xsd:dateTime ;\n"
    ));
    ttl.push_str(&format!("    git:commit \"{sha}\" ;\n"));
    ttl.push_str(&format!("    git:branch \"{branch}\" ;\n"));
    ttl.push_str(&format!("    git:repo \"{repo}\" "));
    if let Some(parent) = &mark.git.parent {
        let parent = ttl_escape(parent);
        ttl.push_str(&format!(";\n    git:parent \"{parent}\" .\n"));
    } else {
        ttl.push_str(".\n");
    }

    // Entity: the generated resource.
    ttl.push('\n');
    ttl.push_str(&format!("<{resource}> a prov:Entity ;\n"));
    ttl.push_str(&format!(
        "    prov:wasGeneratedBy <urn:git:commit:{sha}> ;\n"
    ));
    ttl.push_str(&format!("    prov:wasAttributedTo <{agent}> .\n"));

    // Agent.
    ttl.push('\n');
    ttl.push_str(&format!("<{agent}> a prov:Agent .\n"));

    // Optional anchor entity (expensive tier).
    if let Some(a) = &mark.anchor {
        let txid = ttl_escape(&a.txid);
        let ticker = ttl_escape(&a.ticker);
        let state_hash = ttl_escape(&a.state_hash);
        let network = ttl_escape(&a.network);
        ttl.push('\n');
        ttl.push_str(&format!("<urn:bt:tx:{txid}:{}> a prov:Entity ;\n", a.vout));
        ttl.push_str(&format!(
            "    prov:wasDerivedFrom <urn:git:commit:{sha}> ;\n"
        ));
        ttl.push_str(&format!("    bt:ticker \"{ticker}\" ;\n"));
        ttl.push_str(&format!("    bt:stateHash \"{state_hash}\" ;\n"));
        ttl.push_str(&format!("    bt:network \"{network}\" ;\n"));
        ttl.push_str(&format!("    bt:txid \"{txid}\" ;\n"));
        ttl.push_str(&format!("    bt:vout \"{}\"^^xsd:integer ", a.vout));
        if let Some(h) = a.blockheight {
            ttl.push_str(&format!(";\n    bt:blockheight \"{h}\"^^xsd:integer .\n"));
        } else {
            ttl.push_str(".\n");
        }
    }

    ttl
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_git() -> GitMark {
        GitMark {
            commit_sha: "a1b2c3d4e5f60718293a4b5c6d7e8f9001122334".into(),
            repo: "deadbeef".into(),
            branch: "main".into(),
            parent: Some("00112233445566778899aabbccddeeff00112233".into()),
        }
    }

    fn sample_mark() -> ProvenanceMark {
        ProvenanceMark {
            resource: "/notes/hello.ttl".into(),
            git: sample_git(),
            anchor: None,
            agent_did: "did:nostr:abcdef".into(),
            created: 1_750_000_000,
        }
    }

    #[test]
    fn git_mark_round_trips() {
        let g = sample_git();
        let json = serde_json::to_string(&g).unwrap();
        let back: GitMark = serde_json::from_str(&json).unwrap();
        assert_eq!(g, back);
    }

    // ── ADR-124: gitmark.json / blocktrails.json substrate envelopes ──────

    #[test]
    fn gitmark_envelope_has_exactly_five_keys() {
        // C7 + CI invariant #6: gitmark.json is EXACTLY {@id, genesis, nick,
        // package, repository}. No @context/@type/commit/parent.
        let g = sample_git();
        let env = g.to_gitmark_envelope(0, &g.commit_sha, "gitmark", "./package.json");
        let v: serde_json::Value = serde_json::to_value(&env).unwrap();
        let obj = v.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["@id", "genesis", "nick", "package", "repository"],
            "gitmark.json must be exactly the 5-key envelope (C7)"
        );
        // The four invented keys must be absent.
        for forbidden in ["@context", "@type", "commit", "parent"] {
            assert!(
                !obj.contains_key(forbidden),
                "gitmark.json must NOT carry `{forbidden}` (not in ground truth)"
            );
        }
    }

    #[test]
    fn gitmark_envelope_projection_values() {
        let g = sample_git();
        // Genesis mark: genesis == @id.
        let env = g.to_gitmark_envelope(0, &g.commit_sha, "pod", "./package.json");
        assert_eq!(env.id, format!("gitmark:{}:0", g.commit_sha));
        assert_eq!(env.genesis, format!("gitmark:{}:0", g.commit_sha));
        assert_eq!(env.repository, "./");
        // Non-genesis mark with a distinct genesis SHA + vout.
        let env2 = g.to_gitmark_envelope(2, "00".repeat(20).as_str(), "pod", "./package.json");
        assert_eq!(env2.id, format!("gitmark:{}:2", g.commit_sha));
        assert_eq!(env2.genesis, format!("gitmark:{}:0", "00".repeat(20)));
        assert_ne!(env2.id, env2.genesis);
    }

    #[test]
    fn gitmark_json_matches_carvalho_shape() {
        // Mirrors microfed/gitmark.json key set + ordering-agnostic shape.
        let g = sample_git();
        let json = g
            .to_gitmark_json(0, &g.commit_sha, "gitmark", "./package.json")
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["@id"], format!("gitmark:{}:0", g.commit_sha));
        assert_eq!(v["nick"], "gitmark");
        assert_eq!(v["package"], "./package.json");
        assert_eq!(v["repository"], "./");
    }

    #[test]
    fn blocktrail_envelope_shape() {
        // C6 webcontracts reference shape: @type Blocktrail, profile gitmark,
        // states[] = commit SHAs, txo[] = UTXO chain.
        let g = sample_git();
        let txo = vec![BlocktrailTxo {
            outpoint: format!("{}:0", "ab".repeat(32)),
            blockheight: Some(840_000),
        }];
        let bt =
            BlocktrailEnvelope::new_gitmark_profile(&g.commit_sha, vec![g.commit_sha.clone()], txo);
        assert_eq!(bt.type_, "Blocktrail");
        assert_eq!(bt.profile, "gitmark");
        assert_eq!(bt.id, format!("gitmark:{}:0", g.commit_sha));
        assert_eq!(bt.genesis, bt.id);
        assert_eq!(bt.states, vec![g.commit_sha.clone()]);
        assert_eq!(bt.txo.len(), 1);

        // JSON shape: @type / profile / states / txo present.
        let v: serde_json::Value =
            serde_json::from_str(&bt.to_blocktrails_json().unwrap()).unwrap();
        assert_eq!(v["@type"], "Blocktrail");
        assert_eq!(v["profile"], "gitmark");
        assert!(v["states"].is_array());
        assert!(v["txo"].is_array());
        assert_eq!(v["txo"][0]["outpoint"], format!("{}:0", "ab".repeat(32)));
    }

    #[test]
    fn blocktrail_envelope_round_trips() {
        let bt = BlocktrailEnvelope::new_gitmark_profile(
            &"cd".repeat(20),
            vec!["aa".repeat(20), "bb".repeat(20)],
            vec![
                BlocktrailTxo {
                    outpoint: "t0:0".into(),
                    blockheight: None,
                },
                BlocktrailTxo {
                    outpoint: "t1:0".into(),
                    blockheight: Some(1),
                },
            ],
        );
        let json = serde_json::to_string(&bt).unwrap();
        let back: BlocktrailEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(bt, back);
    }

    #[test]
    fn provenance_mark_round_trips_without_anchor() {
        let m = sample_mark();
        let json = serde_json::to_string(&m).unwrap();
        // `anchor: None` must be omitted by skip_serializing_if.
        assert!(!json.contains("anchor"));
        let back: ProvenanceMark = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn provenance_mark_round_trips_with_anchor() {
        let mut m = sample_mark();
        m.anchor = Some(BlockTrailAnchor {
            ticker: "PROV".into(),
            state_hash: "ff".repeat(32),
            txid: "ab".repeat(32),
            vout: 1,
            address: "tb1pexample".into(),
            network: "testnet4".into(),
            blockheight: Some(840_000),
            state_strings: vec!["{\"seq\":0}".into(), "{\"seq\":1}".into()],
            pubkey: Some("02".to_string() + &"ab".repeat(32)),
        });
        let json = serde_json::to_string(&m).unwrap();
        let back: ProvenanceMark = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn block_trail_anchor_defaults_state_strings() {
        // state_strings missing in JSON must deserialise to an empty vec.
        let json = r#"{
            "ticker":"PROV","state_hash":"00","txid":"00","vout":0,
            "address":"tb1p","network":"testnet4"
        }"#;
        let a: BlockTrailAnchor = serde_json::from_str(json).unwrap();
        assert!(a.state_strings.is_empty());
        assert!(a.blockheight.is_none());
    }

    #[test]
    fn prov_ttl_contains_core_triples() {
        let ttl = prov_ttl(&sample_mark());
        assert!(ttl.contains("@prefix prov: <http://www.w3.org/ns/prov#> ."));
        assert!(ttl.contains("a prov:Activity"));
        assert!(ttl.contains("prov:wasGeneratedBy"));
        assert!(ttl.contains("prov:wasAssociatedWith <did:nostr:abcdef>"));
        assert!(ttl.contains("a prov:Agent"));
        // Commit sha appears as the activity id + git:commit literal.
        assert!(ttl.contains("<urn:git:commit:a1b2c3d4e5f60718293a4b5c6d7e8f9001122334>"));
        assert!(ttl.contains("git:commit \"a1b2c3d4e5f60718293a4b5c6d7e8f9001122334\""));
        assert!(ttl.contains("git:branch \"main\""));
        assert!(ttl.contains("git:parent \"00112233445566778899aabbccddeeff00112233\""));
        // The generated entity is the resource.
        assert!(ttl
            .contains("<urn:git:commit:a1b2c3d4e5f60718293a4b5c6d7e8f9001122334> a prov:Activity"));
        assert!(ttl.contains("prov:generated </notes/hello.ttl>"));
    }

    #[test]
    fn prov_ttl_omits_parent_when_absent() {
        let mut m = sample_mark();
        m.git.parent = None;
        let ttl = prov_ttl(&m);
        assert!(!ttl.contains("git:parent"));
        // Must still be a well-terminated activity block.
        assert!(ttl.contains("git:repo \"deadbeef\" .\n"));
    }

    #[test]
    fn prov_ttl_emits_anchor_block_when_present() {
        let mut m = sample_mark();
        m.anchor = Some(BlockTrailAnchor {
            ticker: "PROV".into(),
            state_hash: "deadbeef".into(),
            txid: "cafebabe".into(),
            vout: 2,
            address: "tb1pexample".into(),
            network: "testnet4".into(),
            blockheight: Some(840_000),
            state_strings: vec![],
            pubkey: None,
        });
        let ttl = prov_ttl(&m);
        assert!(ttl.contains("<urn:bt:tx:cafebabe:2> a prov:Entity"));
        assert!(ttl.contains("bt:ticker \"PROV\""));
        assert!(ttl.contains("bt:stateHash \"deadbeef\""));
        assert!(ttl.contains("bt:blockheight \"840000\"^^xsd:integer"));
        assert!(ttl.contains("prov:wasDerivedFrom <urn:git:commit:"));
    }

    #[test]
    fn prov_ttl_escapes_quotes_and_backslashes() {
        let mut m = sample_mark();
        m.agent_did = "did:nostr:\"weird\\did".into();
        let ttl = prov_ttl(&m);
        // The raw quote/backslash must be escaped inside the literal.
        assert!(ttl.contains("did:nostr:\\\"weird\\\\did"));
    }

    #[test]
    fn xsd_datetime_known_epoch() {
        // 1_750_000_000 == 2025-06-15T15:06:40Z (verified against `date -u -d @1750000000`).
        assert_eq!(xsd_datetime(1_750_000_000), "2025-06-15T15:06:40Z");
        // Unix epoch.
        assert_eq!(xsd_datetime(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn provenance_error_display() {
        assert_eq!(
            ProvenanceError::Git("boom".into()).to_string(),
            "git-mark: boom"
        );
        assert_eq!(
            ProvenanceError::InvalidPath("/x.acl".into()).to_string(),
            "invalid provenance path: /x.acl"
        );
    }

    // -----------------------------------------------------------------------
    // Phase 5: composition (AnchorPolicy + ProvenanceLog) — pure, mocked tiers
    // -----------------------------------------------------------------------

    use std::sync::atomic::{AtomicUsize, Ordering};

    /// In-memory [`GitMarker`] — fabricates a deterministic SHA per call and
    /// counts invocations. No subprocess, so it compiles + runs on wasm too.
    #[derive(Default)]
    struct MockMarker {
        calls: AtomicUsize,
    }
    #[async_trait::async_trait(?Send)]
    impl GitMarker for MockMarker {
        async fn mark_write(
            &self,
            _repo: &Path,
            path: &str,
            _agent_did: &str,
            _message: &str,
        ) -> Result<GitMark, ProvenanceError> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            // 40-hex deterministic SHA derived from the call ordinal + path.
            let sha =
                hex::encode(Sha256::digest(format!("{n}:{path}").as_bytes()))[..40].to_string();
            Ok(GitMark {
                commit_sha: sha,
                repo: "mockpod".into(),
                branch: "main".into(),
                parent: None,
            })
        }
        async fn head(&self, _repo: &Path) -> Result<Option<String>, ProvenanceError> {
            Ok(None)
        }
    }

    /// In-memory [`BlockAnchorer`] — records the `state_hash` it was asked to
    /// anchor (so a test can assert the git SHA was bound) and counts calls.
    #[derive(Default)]
    struct MockAnchorer {
        calls: AtomicUsize,
        last_state_hash: std::sync::Mutex<Option<String>>,
    }
    #[async_trait::async_trait(?Send)]
    impl BlockAnchorer for MockAnchorer {
        async fn anchor(
            &self,
            ticker: &str,
            state_hash: &str,
            network: &str,
        ) -> Result<BlockTrailAnchor, ProvenanceError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.last_state_hash.lock().unwrap() = Some(state_hash.to_string());
            Ok(BlockTrailAnchor {
                ticker: ticker.into(),
                state_hash: state_hash.into(),
                txid: "ab".repeat(32),
                vout: 0,
                address: "tb1pmock".into(),
                network: network.into(),
                blockheight: None,
                state_strings: vec!["{\"seq\":0}".into()],
                pubkey: Some("02".to_string() + &"ab".repeat(32)),
            })
        }
        async fn verify(&self, _anchor: &BlockTrailAnchor) -> Result<bool, ProvenanceError> {
            Ok(true)
        }
    }

    fn repo() -> &'static Path {
        Path::new("/tmp/mockpod")
    }

    /// Build a [`WriteRecord`] for the mock tiers (PROV trail on testnet4).
    fn rec<'a>(
        path: &'a str,
        policy: AnchorPolicy,
        high_value: bool,
        created: u64,
    ) -> WriteRecord<'a> {
        WriteRecord {
            repo: repo(),
            path,
            agent_did: "did:nostr:a",
            message: "PUT",
            policy,
            high_value,
            ticker: "PROV",
            network: "testnet4",
            created,
        }
    }

    #[test]
    fn anchor_policy_inline_matrix() {
        assert!(!AnchorPolicy::Never.anchors_inline(true));
        assert!(!AnchorPolicy::Never.anchors_inline(false));
        assert!(AnchorPolicy::Always.anchors_inline(false));
        assert!(AnchorPolicy::Always.anchors_inline(true));
        assert!(AnchorPolicy::HighValue.anchors_inline(true));
        assert!(!AnchorPolicy::HighValue.anchors_inline(false));
        // Epoch never anchors inline — it defers to the accumulator.
        assert!(!AnchorPolicy::Epoch.anchors_inline(true));
        assert_eq!(AnchorPolicy::default(), AnchorPolicy::Never);
    }

    #[tokio::test]
    async fn record_cheap_write_is_git_mark_only() {
        // Never policy ⇒ git-mark only, no anchor, anchorer untouched.
        let marker = Arc::new(MockMarker::default());
        let anchorer = Arc::new(MockAnchorer::default());
        let log = ProvenanceLog::with_anchorer(marker.clone(), anchorer.clone());
        let mark = log
            .record(rec(
                "notes/a.ttl",
                AnchorPolicy::Never,
                false,
                1_750_000_000,
            ))
            .await
            .unwrap();
        assert!(mark.anchor.is_none(), "cheap write must carry no anchor");
        assert_eq!(mark.resource, "/notes/a.ttl");
        assert_eq!(
            marker.calls.load(Ordering::SeqCst),
            1,
            "git-mark always runs"
        );
        assert_eq!(
            anchorer.calls.load(Ordering::SeqCst),
            0,
            "anchorer must NOT be called"
        );
    }

    #[tokio::test]
    async fn record_high_value_write_carries_git_mark_and_anchor() {
        // HighValue + high_value=true ⇒ BOTH tiers present, and the anchor's
        // state_hash IS the git commit SHA (the two tiers are bound).
        let marker = Arc::new(MockMarker::default());
        let anchorer = Arc::new(MockAnchorer::default());
        let log = ProvenanceLog::with_anchorer(marker.clone(), anchorer.clone());
        let mark = log
            .record(rec(
                "receipts/r1.ttl",
                AnchorPolicy::HighValue,
                true,
                1_750_000_000,
            ))
            .await
            .unwrap();
        let anchor = mark.anchor.expect("high-value write must carry an anchor");
        assert_eq!(
            anchor.state_hash, mark.git.commit_sha,
            "anchor must commit to the git SHA (binds the two tiers — §2.3)"
        );
        assert_eq!(anchorer.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            anchorer.last_state_hash.lock().unwrap().as_deref(),
            Some(mark.git.commit_sha.as_str())
        );
    }

    #[tokio::test]
    async fn record_high_value_flag_false_is_git_only() {
        // HighValue policy but the resource is NOT flagged ⇒ git-mark only.
        let marker = Arc::new(MockMarker::default());
        let anchorer = Arc::new(MockAnchorer::default());
        let log = ProvenanceLog::with_anchorer(marker, anchorer.clone());
        let mark = log
            .record(rec("notes/x.ttl", AnchorPolicy::HighValue, false, 1))
            .await
            .unwrap();
        assert!(mark.anchor.is_none());
        assert_eq!(anchorer.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn record_always_anchors_every_write() {
        let marker = Arc::new(MockMarker::default());
        let anchorer = Arc::new(MockAnchorer::default());
        let log = ProvenanceLog::with_anchorer(marker, anchorer.clone());
        for i in 0..3 {
            let m = log
                .record(rec(&format!("s/{i}.ttl"), AnchorPolicy::Always, false, 1))
                .await
                .unwrap();
            assert!(m.anchor.is_some());
        }
        assert_eq!(anchorer.calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn record_without_anchorer_degrades_to_git_only() {
        // No anchorer (the wasm / no-Bitcoin pod): even Always degrades to
        // git-mark only, silently.
        let marker = Arc::new(MockMarker::default());
        let log = ProvenanceLog::new(marker.clone());
        assert!(log.anchorer.is_none());
        let mark = log
            .record(rec("notes/a.ttl", AnchorPolicy::Always, true, 1))
            .await
            .unwrap();
        assert!(
            mark.anchor.is_none(),
            "no anchorer ⇒ no anchor regardless of policy"
        );
        assert_eq!(marker.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn record_epoch_defers_anchoring_to_accumulator() {
        // Epoch policy: record() never anchors inline; the caller batches the
        // SHA and anchors the root once on epoch close.
        let marker = Arc::new(MockMarker::default());
        let anchorer = Arc::new(MockAnchorer::default());
        let log = ProvenanceLog::with_anchorer(marker, anchorer.clone());

        let mut epoch = EpochAccumulator::new(3);
        let mut shas = Vec::new();
        for i in 0..3 {
            let m = log
                .record(rec(&format!("e/{i}.ttl"), AnchorPolicy::Epoch, true, 1))
                .await
                .unwrap();
            assert!(m.anchor.is_none(), "epoch writes never anchor inline");
            epoch.push(m.git.commit_sha.clone());
            shas.push(m.git.commit_sha);
        }
        // No per-write anchors happened.
        assert_eq!(anchorer.calls.load(Ordering::SeqCst), 0);

        // Epoch is full → close → ONE anchor for the whole batch root.
        assert!(epoch.is_full());
        let closed = epoch.close().expect("non-empty epoch closes");
        assert_eq!(closed.commits, shas);
        let anchor = anchorer
            .anchor("PROV", &closed.root, "testnet4")
            .await
            .unwrap();
        assert_eq!(
            anchorer.calls.load(Ordering::SeqCst),
            1,
            "ONE anchor notarises N commits"
        );
        assert_eq!(anchor.state_hash, closed.root);
        // Epoch drained — a fresh epoch begins.
        assert!(epoch.is_empty());
    }

    // ── Merkle tree: root determinism + inclusion proofs ──────────────────

    #[test]
    fn merkle_root_empty_and_single() {
        assert_eq!(merkle_root(&[]), [0u8; 32]);
        let leaf = merkle_leaf("deadbeef");
        // A single leaf is its own root.
        assert_eq!(merkle_root(&[leaf]), leaf);
    }

    #[test]
    fn merkle_root_is_deterministic_and_order_sensitive() {
        let a = merkle_leaf("aaa");
        let b = merkle_leaf("bbb");
        let r1 = merkle_root(&[a, b]);
        let r2 = merkle_root(&[a, b]);
        assert_eq!(r1, r2, "deterministic");
        let swapped = merkle_root(&[b, a]);
        assert_ne!(r1, swapped, "leaf order changes the root");
    }

    #[test]
    fn epoch_root_matches_close_root() {
        let mut e = EpochAccumulator::new(10);
        for i in 0..5 {
            e.push(format!("commit{i:040}"));
        }
        let peeked = e.root().unwrap();
        let closed = e.close().unwrap();
        assert_eq!(peeked, closed.root, "root() peek == close() root");
    }

    #[test]
    fn epoch_inclusion_proof_verifies_for_every_leaf() {
        // N commits → one root → each commit's inclusion proof verifies.
        let n = 7; // odd, to exercise last-node duplication
        let mut e = EpochAccumulator::new(n);
        for i in 0..n {
            e.push(format!("c{i:039}")); // 40-char commit-like ids
        }
        let root = e.root().unwrap();
        for i in 0..n {
            let proof = e.inclusion_proof(i).expect("proof for in-range leaf");
            assert!(
                EpochAccumulator::verify_inclusion(&proof, &root),
                "leaf {i} must verify against the anchored root"
            );
        }
        // Out-of-range index → no proof.
        assert!(e.inclusion_proof(n).is_none());
    }

    #[test]
    fn epoch_inclusion_proof_rejects_wrong_root_and_tampered_leaf() {
        let mut e = EpochAccumulator::new(4);
        for i in 0..4 {
            e.push(format!("c{i:039}"));
        }
        let root = e.root().unwrap();
        let mut proof = e.inclusion_proof(1).unwrap();
        // Wrong root → reject.
        assert!(!EpochAccumulator::verify_inclusion(
            &proof,
            &"00".repeat(32)
        ));
        // Tampered leaf → reject against the genuine root.
        proof.leaf = hex::encode(merkle_leaf("forged"));
        assert!(!EpochAccumulator::verify_inclusion(&proof, &root));
    }

    #[test]
    fn epoch_threshold_and_len_tracking() {
        let mut e = EpochAccumulator::new(2);
        assert_eq!(e.threshold(), 2);
        assert!(e.is_empty() && !e.is_full());
        e.push("a");
        assert_eq!(e.len(), 1);
        assert!(!e.is_full());
        e.push("b");
        assert!(e.is_full(), "reaching threshold ⇒ full");
        // Threshold clamps to ≥ 1.
        assert_eq!(EpochAccumulator::new(0).threshold(), 1);
    }

    #[test]
    fn empty_epoch_close_is_none() {
        let mut e = EpochAccumulator::new(3);
        assert!(e.close().is_none());
        assert!(e.root().is_none());
    }

    #[test]
    fn merkle_proof_round_trips() {
        let p = MerkleProof {
            leaf: hex::encode(merkle_leaf("x")),
            siblings: vec![("ab".repeat(32), true), ("cd".repeat(32), false)],
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: MerkleProof = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn anchor_policy_round_trips() {
        for p in [
            AnchorPolicy::Never,
            AnchorPolicy::Always,
            AnchorPolicy::HighValue,
            AnchorPolicy::Epoch,
        ] {
            let json = serde_json::to_string(&p).unwrap();
            let back: AnchorPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(p, back);
        }
    }
}
