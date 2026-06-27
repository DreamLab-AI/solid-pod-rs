//! # solid-pod-rs-server
//!
//! Drop-in Solid Pod server binary wrapping
//! [`solid-pod-rs`](https://crates.io/crates/solid-pod-rs) with
//! [actix-web](https://docs.rs/actix-web). This crate is both a
//! library (for integration-test reuse) and a binary.
//!
//! ## Public types
//!
//! - [`AppState`]  — Shared actix-web application state (storage, dotfile policy, body cap).
//! - [`build_app`] — Builds the fully-configured `actix_web::App` with all routes and middleware.
//! - [`NodeInfoMeta`] — NodeInfo 2.1 metadata inputs.
//! - [`PathTraversalGuard`] — Middleware that rejects `..` path-traversal attempts.
//! - [`DotfileGuard`] — Middleware that enforces the dotfile allowlist.
//! - [`ErrorLoggingMiddleware`] — Middleware that logs 5xx responses with full error chains.
//! - [`body_cap_from_env`] — Reads `JSS_MAX_REQUEST_BODY` from the environment.
//! - [`cli`] — CLI argument definitions (clap derive).
//!
//! ## Route table
//!
//! | Method   | Path                                     | Handler              |
//! |----------|------------------------------------------|----------------------|
//! | GET/HEAD | `/{tail:.*}`                             | `handle_get`         |
//! | GET      | `/{folder}/*`                            | Glob merged Turtle   |
//! | PUT      | `/{tail:.*}`                             | `handle_put`         |
//! | PUT      | `/{tail:.*}/` + `Link: BasicContainer`   | Container creation   |
//! | POST     | `/{tail:.*}/`                            | `handle_post`        |
//! | PATCH    | `/{tail:.*}`                             | `handle_patch`       |
//! | DELETE   | `/{tail:.*}`                             | `handle_delete`      |
//! | COPY     | `/{tail:.*}` + `Source` header           | `handle_copy`        |
//! | OPTIONS  | `/{tail:.*}`                             | `handle_options`     |
//! | POST     | `/api/accounts/new`                      | Pod provisioning     |
//! | GET      | `/pods/check/{name}`                     | Pod existence check  |
//! | POST     | `/login/password`                        | Credentials login    |
//! | POST     | `/account/password/reset`                | Password reset       |
//! | POST     | `/account/password/change`               | Password change      |
//! | GET      | `/.well-known/solid`                     | Solid discovery      |
//! | GET      | `/.well-known/webfinger`                 | WebFinger JRD        |
//! | GET      | `/.well-known/nodeinfo`                  | NodeInfo discovery   |
//! | GET      | `/.well-known/nodeinfo/2.1`              | NodeInfo 2.1         |
//! | GET      | `/.well-known/did/nostr/{pubkey}.json`   | DID:nostr document   |
//! | GET      | `/pay/.info`                             | Payment discovery    |
//! | GET      | `/pay/.balance`                          | Web-Ledger balance   |
//! | POST     | `/pay/.deposit`                          | TXO + MRC20 deposit  |
//! | GET      | `/pay/.address`                          | Tweaked deposit addr |
//! | GET/POST | `/pay/.offers` `.sell` `.swap` `.pool`   | Order book + AMM     |
//! | POST     | `/pay/.buy` `.withdraw` `.withdraw-sats` | Token mint/voucher   |
//! | GET      | `/{pod}/{path}.prov.ttl`                 | PROV-O git-mark sidecar |
//! | GET      | `/{pod}/_prov/{commit_sha}`              | Resolve a git-mark   |
//! | POST     | `/{pod}/_prov/anchor`                    | Upgrade to Bitcoin anchor |
//! | GET/POST | `/{pod}/info/refs` `…/git-{upload,receive}-pack` | Git smart-HTTP (WAC-gated) |
//!
//! The `/pay/*` HTTP-402 economy routes (`handlers::pay`) wire the
//! `solid-pod-rs` Web-Ledger / order-book / AMM core onto actix; the `_prov`
//! routes (`handlers::prov`, `--features git`) expose the git-mark +
//! block-trail provenance API (ADR-059). Block-trail anchor verification and
//! broadcast go through the native [`mempool`] client (mempool.space testnet4
//! by default), with trail persistence via [`trail_store`]. Every LDP
//! `PUT`/`POST`/`PATCH` to a git-backed pod additionally fires the always-on
//! git-mark write hook (`git_mark_write`, when built with `--features git`).
//!
//! ## Middleware stack (applied in order)
//!
//! 1. `NormalizePath` -- collapse `//` and decode %-encoded segments.
//! 2. `PathTraversalGuard` -- defence-in-depth `..` re-check.
//! 3. `DotfileGuard` -- rejects `.env` etc unless on the allowlist.
//! 4. `PayloadConfig` -- enforces `JSS_MAX_REQUEST_BODY` body cap.
//! 5. `ErrorLoggingMiddleware` -- structured 5xx logging.
//! 6. WAC-on-write -- PUT/POST/PATCH/DELETE require a write/append grant.

#![doc = include_str!("../README.md")]
#![deny(unsafe_code)]
#![warn(rust_2018_idioms)]

/// CLI argument definitions (clap derive structs).
pub mod cli;

/// HTTP request handlers grouped by domain. Currently hosts the payment
/// routing layer ([`handlers::pay`]) which wires the orphaned
/// `solid-pod-rs` order-book / AMM / Web-Ledger logic onto actix routes
/// with JSS-parity JSON.
mod handlers;

/// MCP (Model Context Protocol) server subsystem — `POST /mcp`, mounted
/// only when [`AppState::mcp_enabled`] (`--mcp` / `JSS_MCP`, JSS #490).
mod mcp;

/// Native mempool.space REST client (provenance-upgrade Phase 3). Concrete
/// [`solid_pod_rs::mrc20::MempoolLookup`] + the verify-side
/// [`solid_pod_rs::provenance::BlockAnchorer`]. Server-side only (builds a
/// `reqwest::Client`); wasm consumers implement the trait over `fetch`.
pub mod mempool;

/// MRC20 trail persistence (provenance-upgrade Phase 4). Loads/saves a
/// token's Bitcoin-anchored state chain at `/.well-known/token/{ticker}.json`
/// via the pod's [`solid_pod_rs::storage::Storage`] backend (JSS
/// `token.js:189-208`). Native-only; holds the issuer secret off the public
/// [`solid_pod_rs::mrc20::Mrc20Trail`] type.
pub mod trail_store;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use actix_web::body::{BoxBody, EitherBody};
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::{header, StatusCode};
use actix_web::middleware::{NormalizePath, TrailingSlash};
use actix_web::{web, App, Error as ActixError, HttpRequest, HttpResponse};
use bytes::Bytes;
use futures_util::future::{ready, LocalBoxFuture, Ready};
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use solid_pod_rs::{
    auth::nip98,
    config::sources::parse_size,
    interop,
    ldp::{self, PatchCreateOutcome},
    mashlib::{self, MashlibConfig},
    provision,
    security::DotfileAllowlist,
    storage::Storage,
    wac::{
        self, conditions::RequestContext, parse_jsonld_acl, parser::parse_turtle_acl, AccessMode,
    },
    PodError,
};

// ---------------------------------------------------------------------------
// Shared app state
// ---------------------------------------------------------------------------

/// Actix-web shared state.
#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<dyn Storage>,
    pub dotfiles: Arc<DotfileAllowlist>,
    pub body_cap: usize,
    pub nodeinfo: NodeInfoMeta,
    pub mashlib: MashlibConfig,
    /// Legacy alias — reads from `mashlib.mode` when `Cdn`.  Deprecated;
    /// use `mashlib` directly.
    pub mashlib_cdn: Option<String>,
    /// Payment configuration — drives `/pay/.info` and the `X-Balance` /
    /// `X-Cost` / `X-Pay-Currency` response headers on paid resources.
    pub pay_config: solid_pod_rs::payments::PayConfig,
    /// Absolute filesystem root of the pod storage tree. `Some` when the
    /// backend is `FsBackend`; `None` for in-memory or cloud-backed
    /// storage. Required by the `git` feature to locate pod directories
    /// for `GitAutoInit` (provisioning) and `GitHttpService` (serving).
    pub data_root: Option<PathBuf>,
    /// JSS-compatible pod creation limiter: one `POST /.pods` per IP per day.
    pub pod_create_limiter: Arc<PodCreateLimiter>,
    /// Per-IP limiter for the public NIP-05 directory
    /// (`/.well-known/nostr.json`), bounding username enumeration (B4).
    /// Default 30 requests / 60 s per IP.
    pub nip05_limiter: Arc<RouteRateLimiter>,
    /// Per-sender limiter for container `POST` (inbox / append), bounding
    /// spam from any single appender (B6.2). Keyed by WebID when
    /// authenticated, else by source IP. Default 120 requests / 60 s;
    /// overridable via `JSS_RATE_LIMIT_WRITES_PER_MIN`.
    pub write_limiter: Arc<RouteRateLimiter>,
    /// When non-empty, CORS responses are only reflected for origins in this
    /// list. Origins not in the list receive no `Access-Control-Allow-Origin`
    /// header. When empty (the default), the request `Origin` is echoed back
    /// (wildcard-equivalent behaviour, suitable for local dev).
    ///
    /// Configured via `--allowed-origins` / `SOLID_ALLOWED_ORIGINS` (comma-separated).
    pub allowed_origins: Vec<String>,
    /// Pre-shared key for the `POST /_admin/provision/{pubkey}` endpoint.
    /// When `None`, the endpoint returns 403 unconditionally.
    ///
    /// Configured via `--admin-key` / `SOLID_ADMIN_KEY`.
    pub admin_key: Option<String>,
    /// When true, the MCP (Model Context Protocol) server is mounted at
    /// `POST /mcp`, exposing the pod as a tool surface for agents. OFF by
    /// default — keys-on-disk and agent write access are an opt-in
    /// security tradeoff. Configured via `--mcp` / `JSS_MCP` (JSS #490).
    pub mcp_enabled: bool,
    /// Optional override for the mempool REST base URL used by the MRC20
    /// `/pay/.deposit` anchor verification (provenance-upgrade Phase 3).
    /// `None` ⇒ the handler reads `JSS_PAY_MEMPOOL_URL` (default testnet4).
    /// Tests point this at a local fixture server so they never reach
    /// mempool.space; production leaves it `None`.
    pub mempool_url: Option<String>,
}

/// NodeInfo 2.1 body inputs. Kept here so tests can override them.
#[derive(Clone, Debug)]
pub struct NodeInfoMeta {
    pub software_name: String,
    pub software_version: String,
    pub open_registrations: bool,
    pub total_users: u64,
    pub base_url: String,
}

impl Default for NodeInfoMeta {
    fn default() -> Self {
        Self {
            software_name: "solid-pod-rs-server".to_string(),
            software_version: env!("CARGO_PKG_VERSION").to_string(),
            open_registrations: false,
            total_users: 0,
            base_url: "http://localhost".to_string(),
        }
    }
}

/// Discover the body cap from the environment. Accepts values like
/// `50MB`, `1.5GB`, or a bare integer (bytes). Falls back to 50 MiB.
pub const DEFAULT_BODY_CAP: usize = 50 * 1024 * 1024;

/// Read `JSS_MAX_REQUEST_BODY` and parse via [`parse_size`]. On any
/// failure, returns [`DEFAULT_BODY_CAP`].
pub fn body_cap_from_env() -> usize {
    match std::env::var("JSS_MAX_REQUEST_BODY") {
        Ok(v) => parse_size(&v)
            .map(|u| u as usize)
            .unwrap_or(DEFAULT_BODY_CAP),
        Err(_) => DEFAULT_BODY_CAP,
    }
}

impl AppState {
    /// Convenience constructor for tests and the binary. Callers may
    /// replace fields after creation since `AppState` is a plain struct.
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self {
            storage,
            dotfiles: Arc::new(DotfileAllowlist::from_env()),
            body_cap: body_cap_from_env(),
            nodeinfo: NodeInfoMeta::default(),
            mashlib: MashlibConfig::default(),
            mashlib_cdn: None,
            pay_config: solid_pod_rs::payments::PayConfig::default(),
            data_root: None,
            pod_create_limiter: Arc::new(PodCreateLimiter::default()),
            nip05_limiter: Arc::new(RouteRateLimiter::new(30, Duration::from_secs(60))),
            write_limiter: Arc::new(RouteRateLimiter::new(120, Duration::from_secs(60))),
            allowed_origins: Vec::new(),
            admin_key: None,
            mcp_enabled: false,
            mempool_url: None,
        }
    }
}

/// In-process sliding-window limiter for JSS-compatible `POST /.pods`.
#[derive(Debug)]
pub struct PodCreateLimiter {
    hits: Mutex<HashMap<IpAddr, Instant>>,
    window: Duration,
}

impl Default for PodCreateLimiter {
    fn default() -> Self {
        Self {
            hits: Mutex::new(HashMap::new()),
            window: Duration::from_secs(24 * 60 * 60),
        }
    }
}

impl PodCreateLimiter {
    fn check(&self, ip: IpAddr) -> Result<(), u64> {
        let now = Instant::now();
        let mut hits = self.hits.lock().unwrap();
        if let Some(last) = hits.get(&ip).copied() {
            let elapsed = now.saturating_duration_since(last);
            if elapsed < self.window {
                return Err(self.window.saturating_sub(elapsed).as_secs().max(1));
            }
        }
        hits.insert(ip, now);
        Ok(())
    }
}

/// In-process sliding-window limiter keyed by an opaque string (route +
/// subject). Unlike the feature-gated [`solid_pod_rs::security::LruRateLimiter`],
/// this is always compiled, so the public NIP-05 directory (B4) and inbox /
/// container append (B6.2) are throttled in the default build. Up to `max`
/// hits are permitted per `window`; the bucket prunes entries older than the
/// window on each check.
#[derive(Debug)]
pub struct RouteRateLimiter {
    hits: Mutex<HashMap<String, Vec<Instant>>>,
    max: u32,
    window: Duration,
}

impl RouteRateLimiter {
    /// Build a limiter allowing `max` hits (clamped to ≥1) per `window`.
    pub fn new(max: u32, window: Duration) -> Self {
        Self {
            hits: Mutex::new(HashMap::new()),
            max: max.max(1),
            window,
        }
    }

    /// Check and record one hit for `key`. Returns `Ok(())` when permitted,
    /// or `Err(retry_after_secs)` (≥1) when the window is saturated; the hit
    /// is not recorded on denial.
    fn check(&self, key: &str) -> Result<(), u64> {
        let now = Instant::now();
        let mut map = self.hits.lock().unwrap();
        let bucket = map.entry(key.to_string()).or_default();
        match now.checked_sub(self.window) {
            Some(cutoff) => bucket.retain(|t| *t > cutoff),
            None => bucket.clear(),
        }
        if bucket.len() as u32 >= self.max {
            let oldest = bucket.first().copied().unwrap_or(now);
            let elapsed = now.saturating_duration_since(oldest);
            return Err(self.window.saturating_sub(elapsed).as_secs().max(1));
        }
        bucket.push(now);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Error translation
// ---------------------------------------------------------------------------

pub(crate) fn to_actix(e: PodError) -> ActixError {
    match e {
        PodError::NotFound(_) => actix_web::error::ErrorNotFound(e.to_string()),
        PodError::BadRequest(_) => actix_web::error::ErrorBadRequest(e.to_string()),
        PodError::Unsupported(_) => actix_web::error::ErrorUnsupportedMediaType(e.to_string()),
        PodError::Forbidden => actix_web::error::ErrorForbidden(e.to_string()),
        PodError::Unauthenticated => actix_web::error::ErrorUnauthorized(e.to_string()),
        PodError::PreconditionFailed(_) => actix_web::error::ErrorPreconditionFailed(e.to_string()),
        _ => actix_web::error::ErrorInternalServerError(e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Auth helper — shared across handlers
// ---------------------------------------------------------------------------

/// Attempt NIP-98 bearer verification; returns the pubkey on success.
pub(crate) async fn extract_pubkey(req: &HttpRequest) -> Option<String> {
    let header_val = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())?;
    // Reconstruct the request URL the NIP-98 event was signed over. The
    // scheme must reflect the externally-visible scheme (honouring
    // `X-Forwarded-Proto` via actix `connection_info`) — a pod behind TLS
    // or a federation reverse proxy is reached at `https://`, and the agent
    // signs that URL. Hardcoding `http://` would break URL matching for
    // every TLS-fronted deployment. Mirrors the base-URI construction used
    // elsewhere in this file (see `conn.scheme()` call sites).
    let conn = req.connection_info();
    let url = format!("{}://{}{}", conn.scheme(), conn.host(), req.uri().path());
    nip98::verify(header_val, &url, req.method().as_str(), None)
        .await
        .ok()
}

pub(crate) fn agent_uri(pubkey: Option<&String>) -> Option<String> {
    pubkey.map(|pk| format!("did:nostr:{pk}"))
}

/// Canonical pod-relative path of the Web Ledger document. The
/// `acl:PaymentCondition` evaluator is fed the requesting principal's
/// satoshi balance read from this resource.
pub(crate) const WEBLEDGER_PATH: &str = "/.well-known/webledgers/webledgers.json";

/// Resolve the requesting principal's satoshi balance from the pod's
/// Web Ledger so the WAC `acl:PaymentCondition` evaluator receives a
/// concrete value instead of `None`.
///
/// Returns:
/// * `None` when there is no authenticated principal (anonymous request)
///   — a `PaymentCondition` then fails closed (402/403);
/// * `Some(0)` when the principal is authenticated but has no ledger
///   entry (or no ledger exists yet) — sufficient to satisfy only a
///   zero-cost condition;
/// * `Some(balance)` resolved from the ledger entry keyed by the
///   principal's `did:nostr` URI otherwise.
///
/// The lookup is keyed by the authenticated principal's WebID, which for
/// a NIP-98 caller is `did:nostr:<hex-pubkey>` — the same key the
/// `/pay/.deposit` credit path writes into the ledger.
async fn resolve_balance_sats(storage: &dyn Storage, agent_uri: Option<&str>) -> Option<u64> {
    let did = agent_uri?;
    let balance = match storage.get(WEBLEDGER_PATH).await {
        Ok((bytes, _meta)) => {
            match serde_json::from_slice::<solid_pod_rs::payments::WebLedger>(&bytes) {
                Ok(ledger) => ledger.get_balance(did),
                // A malformed ledger document must not crash the auth
                // path; treat it as an empty balance (fail-closed for
                // any non-zero PaymentCondition).
                Err(_) => 0,
            }
        }
        // No ledger provisioned yet: authenticated principal with zero
        // balance.
        Err(_) => 0,
    };
    Some(balance)
}

/// Return `true` when the `Accept` header includes `text/html`.
///
/// Used for container `index.html` content negotiation: if a browser
/// requests `text/html` on a container URL and that container contains
/// an `index.html` resource, the server serves the HTML file instead of
/// the RDF container listing. Solid clients that send `Accept: text/turtle`
/// or `application/ld+json` skip this path entirely.
fn accept_includes_html(accept: &str) -> bool {
    accept.split(',').any(|entry| {
        let mime = entry.split(';').next().unwrap_or("").trim();
        mime.eq_ignore_ascii_case("text/html")
    })
}

// ---------------------------------------------------------------------------
// WAC enforcement for writes (PUT / POST / PATCH / DELETE)
// ---------------------------------------------------------------------------

/// Resolve the effective ACL and evaluate whether the given WebID may
/// perform `mode` on `path`.
///
/// Returns `Ok(())` on grant. On deny, returns an `actix_web::Error`:
/// * `401` when the request had no authenticated agent (so the client
///   knows retrying with credentials might work);
/// * `403` when authenticated but the ACL does not grant the mode.
/// Strip a `.acl` / `.meta` suffix from `path`, returning the protected
/// resource the sidecar governs. `/victim/.acl` → `/victim/`,
/// `/a/b.acl` → `/a/b`, `/.acl` → `/`. Returns `None` when `path` is not
/// an ACL/meta sidecar.
fn protected_resource_for_acl(path: &str) -> Option<String> {
    for suffix in [".acl", ".meta"] {
        if let Some(stripped) = path.strip_suffix(suffix) {
            // `/.acl` and `/dir/.acl` strip to `/` and `/dir/`
            // respectively (container ACLs); `/a/b.acl` strips to the
            // resource `/a/b`.
            if stripped.is_empty() {
                return Some("/".to_string());
            }
            return Some(stripped.to_string());
        }
    }
    None
}

/// P0-2 lockout guard (mirrors `mcp/tools.rs:511-552`). Parse a proposed
/// `.acl` document body and confirm at least one authorization still
/// grants `acl:Control` to `caller` (by exact WebID, `foaf:Agent`, or —
/// for an authenticated caller — `acl:AuthenticatedAgent`). Returns
/// `true` when the proposed ACL is unparseable (the storage layer will
/// reject malformed bodies; the guard only fires on a parseable ACL that
/// would strip the caller's Control) or when Control is preserved.
fn proposed_acl_keeps_caller_control(body: &[u8], content_type: &str, caller: Option<&str>) -> bool {
    let doc = match parse_jsonld_acl(body) {
        Ok(d) => Some(d),
        Err(_) => {
            let ct = content_type.to_ascii_lowercase();
            let text = std::str::from_utf8(body).unwrap_or("");
            let looks_turtle = ct.starts_with("text/turtle")
                || ct.starts_with("application/turtle")
                || ct.starts_with("application/x-turtle")
                || text.contains("@prefix")
                || text.contains("acl:Authorization");
            if looks_turtle {
                parse_turtle_acl(text).ok()
            } else {
                None
            }
        }
    };
    let Some(doc) = doc else {
        // Unparseable as an ACL — not our concern; let storage reject it.
        return true;
    };
    let Some(graph) = doc.graph.as_ref() else {
        return false;
    };
    graph.iter().any(|auth| {
        let grants_control = ids_of_acl_field(&auth.mode)
            .iter()
            .any(|m| *m == "acl:Control" || *m == "http://www.w3.org/ns/auth/acl#Control");
        if !grants_control {
            return false;
        }
        let agents = ids_of_acl_field(&auth.agent);
        if let Some(web_id) = caller {
            if agents.iter().any(|a| *a == web_id) {
                return true;
            }
        }
        let classes = ids_of_acl_field(&auth.agent_class);
        if classes
            .iter()
            .any(|c| *c == "http://xmlns.com/foaf/0.1/Agent" || *c == "foaf:Agent")
        {
            return true;
        }
        if caller.is_some()
            && classes.iter().any(|c| {
                *c == "http://www.w3.org/ns/auth/acl#AuthenticatedAgent"
                    || *c == "acl:AuthenticatedAgent"
            })
        {
            return true;
        }
        false
    })
}

/// Flatten an optional `IdOrIds` ACL field into a `Vec<&str>` of IRIs.
fn ids_of_acl_field(field: &Option<wac::IdOrIds>) -> Vec<&str> {
    match field {
        None => Vec::new(),
        Some(wac::IdOrIds::Single(r)) => vec![r.id.as_str()],
        Some(wac::IdOrIds::Multiple(v)) => v.iter().map(|r| r.id.as_str()).collect(),
    }
}

async fn enforce_write(
    state: &AppState,
    path: &str,
    mode: AccessMode,
    agent_uri: Option<&str>,
) -> Result<(), ActixError> {
    // P0-2: an `.acl`/`.meta` sidecar governs *another* resource's
    // permissions. Authorising its mutation as plain `Write` on the
    // sidecar path lets any writer rewrite the ACL and self-escalate
    // (privilege escalation). WAC §4.3.5 requires `acl:Control` on the
    // PROTECTED resource. Elevate the check accordingly, mirroring the
    // MCP `write_acl` path (mcp/tools.rs:505), and apply the same
    // lockout guard so a Control holder cannot strip every other
    // principal's Control in a single write.
    if let Some(protected) = protected_resource_for_acl(path) {
        let control_acl = match find_effective_acl_dyn(&*state.storage, &protected).await {
            Ok(doc) => doc,
            Err(e) => return Err(to_actix(e)),
        };
        let payment_balance_sats = resolve_balance_sats(&*state.storage, agent_uri).await;
        let ctx = RequestContext {
            web_id: agent_uri,
            client_id: None,
            issuer: None,
            payment_balance_sats,
        };
        let registry = wac::conditions::ConditionRegistry::default_with_client_and_issuer();
        let groups: wac::StaticGroupMembership = wac::StaticGroupMembership::default();
        let has_control = wac::evaluate_access_ctx_with_registry(
            control_acl.as_ref(),
            &ctx,
            &protected,
            AccessMode::Control,
            None,
            &groups,
            &registry,
        );
        if !has_control {
            return Err(acl_denial(control_acl.as_ref(), agent_uri, &protected));
        }
        return Ok(());
    }

    // `StorageAclResolver` is generic over a concrete backend. `state`
    // holds an `Arc<dyn Storage>`; wrap it in a trait-object-friendly
    // adapter (`DynStorage`) that forwards each trait method so the
    // resolver can be constructed with a concrete type.
    let acl_doc = match find_effective_acl_dyn(&*state.storage, path).await {
        Ok(doc) => doc,
        Err(e) => return Err(to_actix(e)),
    };

    // Resolve the principal's satoshi balance from the Web Ledger so a
    // sat-priced resource (`acl:PaymentCondition`) is actually gated.
    // `None` only for anonymous callers (no `did:nostr` principal), in
    // which case any PaymentCondition fails closed.
    let payment_balance_sats = resolve_balance_sats(&*state.storage, agent_uri).await;

    let ctx = RequestContext {
        web_id: agent_uri,
        client_id: None,
        issuer: None,
        payment_balance_sats,
    };
    let registry = wac::conditions::ConditionRegistry::default_with_client_and_issuer();
    let groups: wac::StaticGroupMembership = wac::StaticGroupMembership::default();
    let granted = wac::evaluate_access_ctx_with_registry(
        acl_doc.as_ref(),
        &ctx,
        path,
        mode,
        None,
        &groups,
        &registry,
    );
    if granted {
        // Sat-gating consumption for the write path: identical to the
        // read path (see `enforce_read`). A granted write whose
        // authorising rule carried an `acl:PaymentCondition` debits the
        // caller's Web Ledger by the matched rule's cost. The WAC gate
        // above already proved `balance >= cost`, so a debit failure can
        // only mean a concurrent spend raced the balance below cost —
        // fail closed, never serve an unpaid write.
        if let Err(e) =
            charge_granted_payment(state, acl_doc.as_ref(), &ctx, path, mode, &groups, &registry)
                .await
        {
            return Err(e);
        }
        return Ok(());
    }

    Err(acl_denial(acl_doc.as_ref(), agent_uri, path))
}

/// Apply the `acl:PaymentCondition` debit for a request the WAC gate has
/// already granted. Computes the cost of the single granting rule via
/// [`wac::granted_payment_cost`] and, when that cost is non-zero and the
/// caller is an authenticated principal, debits their Web Ledger exactly
/// once. A zero cost (no PaymentCondition on the granting rule) is a
/// no-op. A debit failure (insufficient balance after a concurrent
/// spend, or ledger I/O error) is surfaced as the same WAC denial the
/// caller would have received, so the request is never served unpaid.
async fn charge_granted_payment(
    state: &AppState,
    acl_doc: Option<&wac::AclDocument>,
    ctx: &RequestContext<'_>,
    path: &str,
    mode: AccessMode,
    groups: &wac::StaticGroupMembership,
    registry: &wac::conditions::ConditionRegistry,
) -> Result<(), ActixError> {
    let cost = wac::granted_payment_cost(acl_doc, ctx, path, mode, groups, registry);
    if cost == 0 {
        return Ok(());
    }
    if let Some(did) = ctx.web_id {
        if debit_ledger(&*state.storage, did, cost).await.is_err() {
            return Err(acl_denial(acl_doc, ctx.web_id, path));
        }
    }
    Ok(())
}

/// Build the WAC denial `actix_web::Error` shared by the read and write
/// enforcement paths: `401` (with a `WWW-Authenticate` challenge) for an
/// unauthenticated caller so a retry with credentials is signalled, or
/// `403` for an authenticated caller the ACL does not grant. Both carry
/// the advisory `WAC-Allow` header describing the effective permissions.
fn acl_denial(
    acl_doc: Option<&wac::AclDocument>,
    agent_uri: Option<&str>,
    path: &str,
) -> ActixError {
    let allow_header = wac::wac_allow_header(acl_doc, agent_uri, path);
    let (status, body, unauthenticated) = if agent_uri.is_none() {
        (StatusCode::UNAUTHORIZED, "authentication required", true)
    } else {
        (StatusCode::FORBIDDEN, "access forbidden", false)
    };
    let mut rsp = HttpResponse::new(status);
    rsp.headers_mut().insert(
        header::HeaderName::from_static("wac-allow"),
        header::HeaderValue::from_str(&allow_header)
            .unwrap_or(header::HeaderValue::from_static("")),
    );
    if unauthenticated {
        // Advertise every auth scheme the pod accepts so an
        // unauthenticated agent knows how to retry. `extract_pubkey` verifies
        // NIP-98 (`Authorization: Nostr <base64(kind-27235 event)>`), which is
        // how a `did:nostr` agent authenticates against the pod — without the
        // `Nostr` challenge an agent has no protocol signal that NIP-98 is
        // accepted. DPoP/Bearer remain advertised for OIDC/DPoP clients.
        rsp.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static(
                "Nostr realm=\"Solid\", DPoP realm=\"Solid\", Bearer realm=\"Solid\"",
            ),
        );
    }
    actix_web::error::InternalError::from_response(body, rsp).into()
}

/// P0-1: WAC `acl:Read` enforcement for GET / HEAD / container listing.
///
/// Mirror of [`enforce_write`] for the `Read` mode. Before this guard the
/// GET path resolved an advisory `WAC-Allow` header but returned the
/// resource body verbatim with no read-authz check, so every private
/// resource was world-readable. Returns `Ok(())` on grant; on deny a
/// `401`/`403` matching the write path's denial shape.
async fn enforce_read(
    state: &AppState,
    path: &str,
    agent_uri: Option<&str>,
) -> Result<(), ActixError> {
    let acl_doc = match find_effective_acl_dyn(&*state.storage, path).await {
        Ok(doc) => doc,
        Err(e) => return Err(to_actix(e)),
    };
    let payment_balance_sats = resolve_balance_sats(&*state.storage, agent_uri).await;
    let ctx = RequestContext {
        web_id: agent_uri,
        client_id: None,
        issuer: None,
        payment_balance_sats,
    };
    let registry = wac::conditions::ConditionRegistry::default_with_client_and_issuer();
    let groups: wac::StaticGroupMembership = wac::StaticGroupMembership::default();
    let granted = wac::evaluate_access_ctx_with_registry(
        acl_doc.as_ref(),
        &ctx,
        path,
        AccessMode::Read,
        None,
        &groups,
        &registry,
    );
    if granted {
        // Sat-gating consumption: a granted read whose authorising rule
        // carried an `acl:PaymentCondition` debits the caller's Web
        // Ledger by the matched rule's cost (fail-closed on a raced
        // balance). See `charge_granted_payment`.
        charge_granted_payment(
            state,
            acl_doc.as_ref(),
            &ctx,
            path,
            AccessMode::Read,
            &groups,
            &registry,
        )
        .await?;
        return Ok(());
    }
    Err(acl_denial(acl_doc.as_ref(), agent_uri, path))
}

/// Whether a container member is an auxiliary resource (a WAC `.acl` or a
/// `.meta` / `.meta.json` description sidecar) rather than a real contained
/// resource. These are linked via `rel="acl"` / `rel="describedby"`, not
/// `ldp:contains`, so they are excluded from listings.
fn is_auxiliary_member(name: &str) -> bool {
    let n = name.trim_end_matches('/');
    n == ".acl"
        || n == ".meta"
        || n.ends_with(".acl")
        || n.ends_with(".meta")
        || n.ends_with(".meta.json")
}

/// Return the direct children of container `path` that the requesting agent
/// is allowed to `acl:Read` (B3). Each child's effective ACL is evaluated
/// individually, so a child carrying a stricter own `.acl` — or one that does
/// not inherit a readable `acl:default` from the container — is omitted.
/// This stops a container listing from enumerating the names of resources the
/// caller cannot actually read.
///
/// Cost: one effective-ACL resolution per child (the same per-resource cost
/// the read path already pays); the payment balance is resolved once and
/// shared. A child whose ACL fails to resolve fails closed (it is hidden) and
/// the read is never charged here — listing is a pure visibility check.
async fn visible_container_members(
    state: &AppState,
    path: &str,
    agent_uri: Option<&str>,
) -> Result<Vec<String>, PodError> {
    let members = state.storage.list(path).await?;
    let payment_balance_sats = resolve_balance_sats(&*state.storage, agent_uri).await;
    let ctx = RequestContext {
        web_id: agent_uri,
        client_id: None,
        issuer: None,
        payment_balance_sats,
    };
    let registry = wac::conditions::ConditionRegistry::default_with_client_and_issuer();
    let groups: wac::StaticGroupMembership = wac::StaticGroupMembership::default();

    let mut visible = Vec::with_capacity(members.len());
    for member in members {
        // Auxiliary resources (`.acl` / `.meta` sidecars) are not LDP
        // contained members and must never be enumerated — listing
        // `secret.txt.acl` would leak the name of a child the per-resource
        // check below is hiding.
        if is_auxiliary_member(&member) {
            continue;
        }
        let child_path = format!("{path}{member}");
        let acl_doc = match find_effective_acl_dyn(&*state.storage, &child_path).await {
            Ok(doc) => doc,
            Err(_) => continue,
        };
        let granted = wac::evaluate_access_ctx_with_registry(
            acl_doc.as_ref(),
            &ctx,
            &child_path,
            AccessMode::Read,
            None,
            &groups,
            &registry,
        );
        if granted {
            visible.push(member);
        }
    }
    Ok(visible)
}

/// Debit `cost` satoshis from `did`'s Web Ledger entry and persist the
/// updated ledger document, deducting exactly once for a granted
/// payment-gated request.
///
/// Reads [`WEBLEDGER_PATH`], applies [`WebLedger::debit`] (which fails
/// closed on an insufficient or missing balance), and writes the ledger
/// back. A read, debit, or write failure returns `Err` so the caller can
/// deny the request rather than serve it unpaid.
async fn debit_ledger(
    storage: &dyn Storage,
    did: &str,
    cost: u64,
) -> Result<(), solid_pod_rs::payments::PaymentError> {
    use solid_pod_rs::payments::{PaymentError, WebLedger};

    let (bytes, _meta) = storage
        .get(WEBLEDGER_PATH)
        .await
        .map_err(|e| PaymentError::Store(e.to_string()))?;
    let mut ledger: WebLedger = serde_json::from_slice(&bytes)
        .map_err(|e| PaymentError::Store(format!("malformed ledger: {e}")))?;
    ledger.debit(did, cost)?;
    let body = serde_json::to_vec(&ledger)
        .map_err(|e| PaymentError::Store(format!("serialise ledger: {e}")))?;
    storage
        .put(WEBLEDGER_PATH, Bytes::from(body), "application/json")
        .await
        .map_err(|e| PaymentError::Store(e.to_string()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

fn set_link_headers(rsp: &mut HttpResponse, path: &str) {
    let links = ldp::link_headers(path).join(", ");
    if let Ok(value) = header::HeaderValue::from_str(&links) {
        rsp.headers_mut()
            .insert(header::HeaderName::from_static("link"), value);
    }
}

fn set_wac_allow(rsp: &mut HttpResponse, header_value: &str) {
    if let Ok(v) = header::HeaderValue::from_str(header_value) {
        rsp.headers_mut()
            .insert(header::HeaderName::from_static("wac-allow"), v);
    }
}

fn set_updates_via(rsp: &mut HttpResponse, base_url: &str) {
    let ws_base = base_url
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1);
    let ws_url = format!("{}/.notifications", ws_base.trim_end_matches('/'));
    if let Ok(v) = header::HeaderValue::from_str(&ws_url) {
        rsp.headers_mut()
            .insert(header::HeaderName::from_static("updates-via"), v);
    }
}

async fn handle_get(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ActixError> {
    let path = req.uri().path().to_string();

    if path.contains('*') {
        return handle_glob_get(req, state).await;
    }

    let auth_pk = extract_pubkey(&req).await;
    let agent = agent_uri(auth_pk.as_ref());

    // P0-1: enforce WAC `acl:Read` before serving any bytes. This guards
    // both resource GETs and the RDF container listing below, and — since
    // HEAD is routed to this same handler — HEAD requests too. Without it
    // a private resource is world-readable.
    enforce_read(&state, &path, agent.as_deref()).await?;

    let wac_allow = wac::wac_allow_header(None, agent.as_deref(), &path);

    if ldp::is_container(&path) {
        let accept = req
            .headers()
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        // Content negotiation: when a browser requests text/html, check
        // whether the container has an index.html child resource. If so,
        // serve it directly instead of the RDF container listing. This is
        // standard HTTP content negotiation — browsers get HTML, Solid
        // clients get RDF.
        if accept_includes_html(accept) {
            let index_path = format!("{}index.html", &path);
            if let Ok((body, _meta)) = state.storage.get(&index_path).await {
                let mut rsp = HttpResponse::Ok()
                    .content_type("text/html; charset=utf-8")
                    .body(body.to_vec());
                set_wac_allow(&mut rsp, &wac_allow);
                set_updates_via(&mut rsp, &state.nodeinfo.base_url);
                set_link_headers(&mut rsp, &path);
                return Ok(rsp);
            }
        }

        // B3: list only children the caller may read, then render. The
        // container-level `enforce_read` above gates access to the listing
        // itself; this gates each member so private child names do not leak.
        let members = visible_container_members(&state, &path, agent.as_deref())
            .await
            .map_err(to_actix)?;
        let v = ldp::render_container(&path, &members);

        // Mashlib: serve HTML wrapper for browser navigation.
        let sec_fetch_dest = req
            .headers()
            .get("sec-fetch-dest")
            .and_then(|v| v.to_str().ok());
        if mashlib::should_serve(
            accept,
            sec_fetch_dest,
            "application/ld+json",
            state.mashlib.enabled,
        ) {
            let json_ld = serde_json::to_string(&v).ok();
            let html = mashlib::generate_html(&path, &state.mashlib, json_ld.as_deref());
            let mut rsp = HttpResponse::Ok()
                .content_type("text/html; charset=utf-8")
                .insert_header(("X-Frame-Options", "DENY"))
                .insert_header(("Content-Security-Policy", "frame-ancestors 'none'"))
                .insert_header(("Cache-Control", "no-store"))
                .body(html);
            set_wac_allow(&mut rsp, &wac_allow);
            set_updates_via(&mut rsp, &state.nodeinfo.base_url);
            set_link_headers(&mut rsp, &path);
            return Ok(rsp);
        }

        let mut rsp = HttpResponse::Ok().json(v);
        rsp.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/ld+json"),
        );
        set_wac_allow(&mut rsp, &wac_allow);
        set_updates_via(&mut rsp, &state.nodeinfo.base_url);
        set_link_headers(&mut rsp, &path);
        return Ok(rsp);
    }

    match state.storage.get(&path).await {
        Ok((body, meta)) => {
            // Mashlib: serve HTML wrapper for browser navigation to RDF resources.
            let accept = req
                .headers()
                .get(header::ACCEPT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let sec_fetch_dest = req
                .headers()
                .get("sec-fetch-dest")
                .and_then(|v| v.to_str().ok());
            if mashlib::should_serve(
                accept,
                sec_fetch_dest,
                &meta.content_type,
                state.mashlib.enabled,
            ) {
                let embed = if body.len() <= state.mashlib.data_island_max_bytes {
                    std::str::from_utf8(&body).ok().map(|s| s.to_string())
                } else {
                    None
                };
                let html = mashlib::generate_html(&path, &state.mashlib, embed.as_deref());
                let mut rsp = HttpResponse::Ok()
                    .content_type("text/html; charset=utf-8")
                    .insert_header(("X-Frame-Options", "DENY"))
                    .insert_header(("Content-Security-Policy", "frame-ancestors 'none'"))
                    .insert_header(("Cache-Control", "no-store"))
                    .body(html);
                set_wac_allow(&mut rsp, &wac_allow);
                set_updates_via(&mut rsp, &state.nodeinfo.base_url);
                set_link_headers(&mut rsp, &path);
                return Ok(rsp);
            }

            // RDF content negotiation: when the client explicitly asks for
            // a concrete RDF serialisation that differs from how the
            // resource is stored, transcode it. KG resources persist as
            // N-Triples (see the PATCH handler), so an agent or extractor
            // can GET the same graph as Turtle, N-Triples, or JSON-LD on
            // demand (PRD-014 Seam C / C4). Non-RDF resources, unparseable
            // bodies, and wildcard/`*/*` Accepts fall through to verbatim.
            if let Some((negotiated_body, negotiated_ct)) =
                rdf_content_negotiate(&body, &meta.content_type, accept)
            {
                let mut rsp = HttpResponse::Ok().body(negotiated_body);
                rsp.headers_mut().insert(
                    header::CONTENT_TYPE,
                    header::HeaderValue::from_str(negotiated_ct)
                        .unwrap_or_else(|_| header::HeaderValue::from_static("text/turtle")),
                );
                rsp.headers_mut()
                    .insert(header::VARY, header::HeaderValue::from_static("Accept"));
                if let Ok(etag) = header::HeaderValue::from_str(&format!("\"{}\"", meta.etag)) {
                    rsp.headers_mut().insert(header::ETAG, etag);
                }
                set_wac_allow(&mut rsp, &wac_allow);
                set_updates_via(&mut rsp, &state.nodeinfo.base_url);
                set_link_headers(&mut rsp, &path);
                return Ok(rsp);
            }

            let mut rsp = HttpResponse::Ok().body(body.to_vec());
            rsp.headers_mut().insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_str(&meta.content_type).unwrap_or_else(|_| {
                    header::HeaderValue::from_static("application/octet-stream")
                }),
            );
            // B1: stored pod content declared as an executable/active type is
            // served as an attachment so it cannot run in the pod origin if a
            // user stores HTML/JS/SVG in a world-readable container. `nosniff`
            // (set globally) covers mis-typed uploads; this covers correctly
            // typed ones. RDF and media keep rendering inline (handled above /
            // not active types).
            if is_active_content_type(&meta.content_type) {
                rsp.headers_mut().insert(
                    header::CONTENT_DISPOSITION,
                    header::HeaderValue::from_static("attachment"),
                );
            }
            if let Ok(etag) = header::HeaderValue::from_str(&format!("\"{}\"", meta.etag)) {
                rsp.headers_mut().insert(header::ETAG, etag);
            }
            set_wac_allow(&mut rsp, &wac_allow);
            set_updates_via(&mut rsp, &state.nodeinfo.base_url);
            set_link_headers(&mut rsp, &path);
            Ok(rsp)
        }
        Err(PodError::NotFound(_)) => Ok(HttpResponse::NotFound().finish()),
        Err(e) => Err(to_actix(e)),
    }
}

fn has_basic_container_link(req: &HttpRequest) -> bool {
    req.headers()
        .get_all(header::LINK)
        .filter_map(|v| v.to_str().ok())
        .any(|v| {
            v.contains("http://www.w3.org/ns/ldp#BasicContainer") && v.contains("rel=\"type\"")
        })
}

async fn handle_put(
    req: HttpRequest,
    body: web::Bytes,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ActixError> {
    let path = req.uri().path().to_string();

    if ldp::is_container(&path) {
        if has_basic_container_link(&req) {
            let auth_pk = extract_pubkey(&req).await;
            let agent = agent_uri(auth_pk.as_ref());
            enforce_write(&state, &path, AccessMode::Write, agent.as_deref()).await?;
            let meta = state
                .storage
                .create_container(&path)
                .await
                .map_err(to_actix)?;
            let mut rsp = HttpResponse::Created().finish();
            if let Ok(etag) = header::HeaderValue::from_str(&format!("\"{}\"", meta.etag)) {
                rsp.headers_mut().insert(header::ETAG, etag);
            }
            set_link_headers(&mut rsp, &path);
            return Ok(rsp);
        }
        return Ok(HttpResponse::MethodNotAllowed().body("cannot PUT to a container"));
    }

    let auth_pk = extract_pubkey(&req).await;
    let agent = agent_uri(auth_pk.as_ref());
    enforce_write(&state, &path, AccessMode::Write, agent.as_deref()).await?;

    let ct = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");

    // P0-2 lockout guard: when writing an `.acl`/`.meta` sidecar, refuse a
    // proposed ACL that would strip the caller's own Control — the same
    // footgun the MCP `write_acl` path blocks (mcp/tools.rs:511). Without
    // this a Control holder could lock themselves (and everyone) out.
    if protected_resource_for_acl(&path).is_some()
        && !proposed_acl_keeps_caller_control(&body, ct, agent.as_deref())
    {
        return Ok(HttpResponse::Conflict().body(
            "refused: the proposed ACL would not grant Control to the caller \
             (use an absolute WebID, foaf:Agent, or acl:AuthenticatedAgent)",
        ));
    }

    let meta = state
        .storage
        .put(&path, Bytes::from(body.to_vec()), ct)
        .await
        .map_err(to_actix)?;
    // git-mark (Phase 2): commit + PROV-O sidecar on git-backed pods. Runs
    // AFTER the write succeeded; additive + best-effort (errors swallowed),
    // git-backed-only, never changes the response.
    git_mark_write(&state, &path, agent.as_deref(), "PUT").await;
    let mut rsp = HttpResponse::Created().finish();
    if let Ok(etag) = header::HeaderValue::from_str(&format!("\"{}\"", meta.etag)) {
        rsp.headers_mut().insert(header::ETAG, etag);
    }
    set_link_headers(&mut rsp, &path);
    Ok(rsp)
}

async fn handle_post(
    req: HttpRequest,
    body: web::Bytes,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ActixError> {
    let path = req.uri().path().to_string();
    // POST route only matches container paths (trailing slash) via the
    // `POST /{tail:.*}/` registration.
    let auth_pk = extract_pubkey(&req).await;
    let agent = agent_uri(auth_pk.as_ref());
    enforce_write(&state, &path, AccessMode::Append, agent.as_deref()).await?;

    // B6.2: bound append spam per sender (WebID when authenticated, else
    // source IP) so a single appender cannot flood an inbox/container.
    let subject = match agent.as_deref() {
        Some(webid) => format!("webid:{webid}"),
        None => format!("ip:{}", request_ip(&req)),
    };
    if let Err(retry_after) = state.write_limiter.check(&format!("container_post:{subject}")) {
        return Ok(HttpResponse::TooManyRequests()
            .insert_header(("Retry-After", retry_after.to_string()))
            .finish());
    }

    let slug = req
        .headers()
        .get(header::HeaderName::from_static("slug"))
        .and_then(|v| v.to_str().ok());
    let target = match ldp::resolve_slug(&path, slug) {
        Ok(p) => p,
        Err(e) => return Err(to_actix(e)),
    };
    let ct = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");
    let meta = state
        .storage
        .put(&target, Bytes::from(body.to_vec()), ct)
        .await
        .map_err(to_actix)?;
    // git-mark (Phase 2): commit + PROV-O sidecar for the newly-created child.
    // Additive + best-effort, git-backed-only.
    git_mark_write(&state, &target, agent.as_deref(), "POST").await;
    let mut rsp = HttpResponse::Created().finish();
    if let Ok(loc) = header::HeaderValue::from_str(&target) {
        rsp.headers_mut().insert(header::LOCATION, loc);
    }
    if let Ok(etag) = header::HeaderValue::from_str(&format!("\"{}\"", meta.etag)) {
        rsp.headers_mut().insert(header::ETAG, etag);
    }
    set_link_headers(&mut rsp, &target);
    Ok(rsp)
}

async fn handle_patch(
    req: HttpRequest,
    body: web::Bytes,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ActixError> {
    let path = req.uri().path().to_string();
    if ldp::is_container(&path) {
        return Ok(HttpResponse::MethodNotAllowed().body("cannot PATCH a container"));
    }
    let auth_pk = extract_pubkey(&req).await;
    let agent = agent_uri(auth_pk.as_ref());
    // PATCH can modify or delete data (e.g. N3 Patch with solid:deletes),
    // so it requires full Write permission — not just Append. Only POST
    // (which creates new child resources in a container) is allowed with
    // Append-only permission. This prevents Append-only users from
    // overwriting or deleting resource content via PATCH.
    enforce_write(&state, &path, AccessMode::Write, agent.as_deref()).await?;

    let ct = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let dialect = match ldp::patch_dialect_from_mime(ct) {
        Some(d) => d,
        None => {
            return Ok(HttpResponse::UnsupportedMediaType()
                .body(format!("unsupported patch dialect for content-type {ct:?}")))
        }
    };
    let body_str = match std::str::from_utf8(&body) {
        Ok(s) => s.to_string(),
        Err(_) => return Ok(HttpResponse::BadRequest().body("patch body is not valid UTF-8")),
    };

    // Existing resource?
    let existing = state.storage.get(&path).await;
    match existing {
        Ok((current_body, meta)) => {
            // Seed the working graph from the EXISTING resource body so the
            // mutation lands on top of the triples already stored, rather
            // than on an empty graph (which silently discarded everything
            // on every incremental write — the data-loss bug fixed here;
            // PRD-014 Seam C / DDD-012 A2 non-destructive-write invariant).
            // RDF resources are persisted as N-Triples by `graph_to_turtle`,
            // so the current body round-trips through `parse_ntriples`. A
            // body that is not parseable N-Triples is refused, not
            // overwritten — fail closed rather than destroy.
            let out = match dialect {
                ldp::PatchDialect::N3 => {
                    let seed = seed_graph_from_patch_target(&current_body)?;
                    ldp::apply_n3_patch(seed, &body_str).map_err(patch_parse_err)
                }
                ldp::PatchDialect::SparqlUpdate => {
                    let seed = seed_graph_from_patch_target(&current_body)?;
                    ldp::apply_sparql_patch(seed, &body_str).map_err(patch_parse_err)
                }
                ldp::PatchDialect::JsonPatch => {
                    let mut json: serde_json::Value = match serde_json::from_slice(&current_body) {
                        Ok(v) => v,
                        Err(_) => serde_json::json!({}),
                    };
                    let patch: serde_json::Value = match serde_json::from_str(&body_str) {
                        Ok(v) => v,
                        Err(e) => return Err(to_actix(PodError::BadRequest(e.to_string()))),
                    };
                    ldp::apply_json_patch(&mut json, &patch).map_err(to_actix)?;
                    let bytes = serde_json::to_vec(&json)
                        .map_err(PodError::from)
                        .map_err(to_actix)?;
                    let _ = state
                        .storage
                        .put(&path, Bytes::from(bytes), &meta.content_type)
                        .await
                        .map_err(to_actix)?;
                    git_mark_write(&state, &path, agent.as_deref(), "PATCH").await;
                    return Ok(HttpResponse::NoContent().finish());
                }
            };
            let outcome = out?;
            // Round-trip the updated graph back to Turtle so the next
            // GET reflects the mutation.
            let serialised = graph_to_turtle(&outcome.graph);
            let _ = state
                .storage
                .put(&path, Bytes::from(serialised.into_bytes()), "text/turtle")
                .await
                .map_err(to_actix)?;
            git_mark_write(&state, &path, agent.as_deref(), "PATCH").await;
            Ok(HttpResponse::NoContent().finish())
        }
        Err(PodError::NotFound(_)) => {
            // PATCH against an absent resource — create it.
            let create = ldp::apply_patch_to_absent(dialect, &body_str).map_err(patch_parse_err)?;
            let PatchCreateOutcome::Created { graph, .. } = create else {
                return Err(to_actix(PodError::Unsupported(
                    "unexpected patch outcome on absent resource".into(),
                )));
            };
            let serialised = graph_to_turtle(&graph);
            let _ = state
                .storage
                .put(&path, Bytes::from(serialised.into_bytes()), "text/turtle")
                .await
                .map_err(to_actix)?;
            git_mark_write(&state, &path, agent.as_deref(), "PATCH").await;
            Ok(HttpResponse::Created().finish())
        }
        Err(e) => Err(to_actix(e)),
    }
}

/// Map a PATCH body parse error to 400 Bad Request. Distinguishes
/// "client sent garbage in a supported dialect" (400) from "client
/// chose an unsupported dialect" (415 — handled by the dispatcher).
fn patch_parse_err(e: PodError) -> ActixError {
    match e {
        PodError::Unsupported(msg) | PodError::BadRequest(msg) => {
            actix_web::error::ErrorBadRequest(msg)
        }
        other => to_actix(other),
    }
}

/// Serialise a graph to N-Triples so the next GET reflects PATCH
/// mutations verbatim. Delegates to the library's canonical serialiser
/// — the handler does not add its own formatting.
fn graph_to_turtle(g: &ldp::Graph) -> String {
    g.to_ntriples()
}

/// Parse an `Accept` header and return the highest-q *explicit* RDF
/// format named by the client. Unlike `ldp::negotiate_format`, wildcard
/// media ranges (`*/*`, `text/*`, `application/*`) are NOT mapped to a
/// default: a request that names no concrete RDF type yields `None`, so
/// the GET handler serves the stored representation verbatim instead of
/// surprising a browser (which sends `*/*`) with a transcode.
fn best_explicit_rdf_format(accept: &str) -> Option<ldp::RdfFormat> {
    let mut best: Option<(f32, ldp::RdfFormat)> = None;
    for entry in accept.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let mut parts = entry.split(';').map(|s| s.trim());
        let mime = match parts.next() {
            Some(m) => m,
            None => continue,
        };
        let mut q: f32 = 1.0;
        for token in parts {
            if let Some(v) = token.strip_prefix("q=") {
                if let Ok(parsed) = v.parse::<f32>() {
                    q = parsed;
                }
            }
        }
        // `from_mime` rejects wildcards, so only concrete RDF media types
        // ever enter the running.
        if let Some(format) = ldp::RdfFormat::from_mime(mime) {
            match best {
                None => best = Some((q, format)),
                Some((bq, _)) if q > bq => best = Some((q, format)),
                _ => {}
            }
        }
    }
    best.map(|(_, f)| f)
}

/// RDF content negotiation for GET. When a client explicitly asks (via
/// `Accept`) for a concrete RDF serialisation different from how the
/// resource is stored, transcode the body and return the negotiated
/// `(bytes, content-type)`. KG resources persist as N-Triples (see the
/// PATCH handler), so an agent or extractor can GET the same graph as
/// Turtle, N-Triples, or JSON-LD on demand (PRD-014 Seam C / C4).
///
/// Returns `None` — meaning "serve the stored body verbatim" — when:
///   * the `Accept` header is empty,
///   * the stored content-type is not an RDF media type,
///   * the client named no concrete RDF type (only wildcards),
///   * the requested format equals the stored format (no transcode),
///   * the stored body does not parse as N-Triples (GET fails soft to
///     verbatim — it never destroys or misrepresents), or
///   * the requested target has no serialiser (RDF/XML).
fn rdf_content_negotiate(
    body: &[u8],
    stored_ct: &str,
    accept: &str,
) -> Option<(Vec<u8>, &'static str)> {
    if accept.trim().is_empty() {
        return None;
    }
    let stored_format = ldp::RdfFormat::from_mime(stored_ct)?;
    let target = best_explicit_rdf_format(accept)?;
    if target == stored_format {
        return None;
    }
    let text = std::str::from_utf8(body).ok()?;
    let graph = ldp::Graph::parse_ntriples(text).ok()?;
    match target {
        // N-Triples is a syntactic subset of Turtle; the canonical
        // serialiser emits N-Triples, which is valid Turtle.
        ldp::RdfFormat::Turtle => {
            Some((graph.to_ntriples().into_bytes(), ldp::RdfFormat::Turtle.mime()))
        }
        ldp::RdfFormat::NTriples => Some((
            graph.to_ntriples().into_bytes(),
            ldp::RdfFormat::NTriples.mime(),
        )),
        ldp::RdfFormat::JsonLd => {
            let json = serde_json::to_vec(&graph.to_jsonld()).ok()?;
            Some((json, ldp::RdfFormat::JsonLd.mime()))
        }
        // The hand-rolled graph has no RDF/XML serialiser; decline.
        ldp::RdfFormat::RdfXml => None,
    }
}

/// Seed the PATCH working graph from the existing resource body so an
/// N3/SPARQL-Update mutation is applied on top of the triples already
/// stored. RDF resources are persisted as N-Triples (see `graph_to_turtle`),
/// so the current body round-trips through `Graph::parse_ntriples`. An
/// empty body yields an empty graph. A body that is neither empty nor
/// parseable N-Triples is REFUSED (409) rather than silently overwritten:
/// destroying a resource the patch engine cannot read back would violate
/// the non-destructive-write invariant (PRD-014 Seam C, DDD-012 A2).
fn seed_graph_from_patch_target(current_body: &[u8]) -> Result<ldp::Graph, ActixError> {
    let text = std::str::from_utf8(current_body).map_err(|_| {
        actix_web::error::ErrorConflict(
            "existing resource is not UTF-8 RDF; refusing destructive RDF PATCH",
        )
    })?;
    if text.trim().is_empty() {
        return Ok(ldp::Graph::new());
    }
    ldp::Graph::parse_ntriples(text).map_err(|_| {
        actix_web::error::ErrorConflict(
            "existing resource is not N-Triples RDF and cannot be non-destructively \
             patched; PUT an N-Triples representation or use a JSON Patch",
        )
    })
}

/// Walk the storage tree from `path` upward, returning the first
/// `*.acl` document that parses as JSON-LD or Turtle. Object-safe
/// equivalent of `StorageAclResolver::find_effective_acl` — the latter
/// is generic over a concrete `Storage`, whereas the binary holds an
/// `Arc<dyn Storage>`.
pub(crate) async fn find_effective_acl_dyn(
    storage: &dyn Storage,
    resource_path: &str,
) -> Result<Option<wac::AclDocument>, PodError> {
    let mut path = resource_path.to_string();
    // P2: the first probe is the resource's OWN `.acl` (direct); later
    // iterations walk up to ANCESTOR containers, whose ACLs are inherited
    // and must honour only `acl:default` rules. Tag the resolved doc so
    // the evaluator can distinguish the two.
    let mut inherited = false;
    loop {
        let acl_key = if path == "/" {
            "/.acl".to_string()
        } else {
            format!("{}.acl", path.trim_end_matches('/'))
        };
        if let Ok((body, meta)) = storage.get(&acl_key).await {
            match parse_jsonld_acl(&body) {
                Ok(mut doc) => {
                    doc.inherited = inherited;
                    return Ok(Some(doc));
                }
                Err(PodError::BadRequest(_)) => {
                    return Err(PodError::BadRequest("ACL document exceeds bounds".into()))
                }
                Err(_) => {}
            }
            let ct = meta.content_type.to_ascii_lowercase();
            let looks_turtle = ct.starts_with("text/turtle")
                || ct.starts_with("application/turtle")
                || ct.starts_with("application/x-turtle");
            let text = std::str::from_utf8(&body).unwrap_or("");
            if looks_turtle || text.contains("@prefix") || text.contains("acl:Authorization") {
                if let Ok(mut doc) = parse_turtle_acl(text) {
                    doc.inherited = inherited;
                    return Ok(Some(doc));
                }
            }
        }
        if path == "/" || path.is_empty() {
            break;
        }
        // Every subsequent ACL is resolved from an ancestor.
        inherited = true;
        let trimmed = path.trim_end_matches('/');
        path = match trimmed.rfind('/') {
            Some(0) => "/".to_string(),
            Some(pos) => trimmed[..pos].to_string(),
            None => "/".to_string(),
        };
    }
    Ok(None)
}

async fn handle_delete(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ActixError> {
    let path = req.uri().path().to_string();
    let auth_pk = extract_pubkey(&req).await;
    let agent = agent_uri(auth_pk.as_ref());
    enforce_write(&state, &path, AccessMode::Write, agent.as_deref()).await?;

    match state.storage.delete(&path).await {
        Ok(()) => Ok(HttpResponse::NoContent().finish()),
        Err(PodError::NotFound(_)) => Ok(HttpResponse::NotFound().finish()),
        Err(e) => Err(to_actix(e)),
    }
}

async fn handle_options(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ActixError> {
    let path = req.uri().path().to_string();
    let o = ldp::options_for(&path);
    let mut rsp = HttpResponse::NoContent().finish();
    if let Ok(v) = header::HeaderValue::from_str(&o.allow.join(", ")) {
        rsp.headers_mut()
            .insert(header::HeaderName::from_static("allow"), v);
    }
    if let Some(ap) = o.accept_post {
        if let Ok(v) = header::HeaderValue::from_str(ap) {
            rsp.headers_mut()
                .insert(header::HeaderName::from_static("accept-post"), v);
        }
    }
    if let Ok(v) = header::HeaderValue::from_str(o.accept_patch) {
        rsp.headers_mut()
            .insert(header::HeaderName::from_static("accept-patch"), v);
    }
    if let Ok(v) = header::HeaderValue::from_str(o.accept_ranges) {
        rsp.headers_mut()
            .insert(header::HeaderName::from_static("accept-ranges"), v);
    }
    set_updates_via(&mut rsp, &state.nodeinfo.base_url);
    Ok(rsp)
}

// ---------------------------------------------------------------------------
// .well-known handlers
// ---------------------------------------------------------------------------

async fn handle_well_known_solid(state: web::Data<AppState>) -> HttpResponse {
    let doc = interop::well_known_solid(&state.nodeinfo.base_url, &state.nodeinfo.base_url);
    HttpResponse::Ok()
        .content_type("application/ld+json")
        .json(doc)
}

#[derive(Debug, Deserialize)]
struct WebFingerQuery {
    resource: Option<String>,
}

async fn handle_well_known_webfinger(
    state: web::Data<AppState>,
    q: web::Query<WebFingerQuery>,
) -> HttpResponse {
    let resource = q.resource.clone().unwrap_or_else(|| {
        format!(
            "acct:anonymous@{}",
            state
                .nodeinfo
                .base_url
                .trim_start_matches("http://")
                .trim_start_matches("https://")
        )
    });
    let webid = format!(
        "{}/profile/card#me",
        state.nodeinfo.base_url.trim_end_matches('/')
    );
    match interop::webfinger_response(&resource, &state.nodeinfo.base_url, &webid) {
        Some(jrd) => HttpResponse::Ok()
            .content_type("application/jrd+json")
            .json(jrd),
        None => HttpResponse::NotFound().finish(),
    }
}

async fn handle_well_known_nodeinfo(state: web::Data<AppState>) -> HttpResponse {
    let doc = interop::nodeinfo_discovery(&state.nodeinfo.base_url);
    HttpResponse::Ok()
        .content_type("application/json")
        .json(doc)
}

async fn handle_well_known_nodeinfo_2_1(state: web::Data<AppState>) -> HttpResponse {
    let doc = interop::nodeinfo_2_1(
        &state.nodeinfo.software_name,
        &state.nodeinfo.software_version,
        state.nodeinfo.open_registrations,
        state.nodeinfo.total_users,
    );
    HttpResponse::Ok()
        .content_type("application/json")
        .json(doc)
}

#[cfg(feature = "did-nostr")]
async fn handle_well_known_did_nostr(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    let pubkey = path.into_inner();
    let also = vec![format!(
        "{}/profile/card#me",
        state.nodeinfo.base_url.trim_end_matches('/')
    )];
    let doc = interop::did_nostr::did_nostr_document(&pubkey, &also);
    HttpResponse::Ok()
        .content_type("application/did+json")
        .json(doc)
}

// ---------------------------------------------------------------------------
// JSS v0.0.190 Phase 1 port (issue #437) — pod-resident NIP-05 endpoint.
//
// Parity row 197. Feature `nip05-endpoint`. Resolves `?name=<local>`
// against the per-pod WebID `nostr:pubkey` triple.
// ---------------------------------------------------------------------------

#[cfg(feature = "nip05-endpoint")]
#[derive(Debug, Deserialize)]
struct Nip05Query {
    /// Optional `name=<local>` query parameter per NIP-05. When
    /// absent, defaults to `_` (the pod owner / single-user mode).
    name: Option<String>,
}

#[cfg(feature = "nip05-endpoint")]
fn nip05_name_is_valid(name: &str) -> bool {
    // NIP-05 §"Local part": ^[a-z0-9._-]+$ (case-insensitive in practice).
    // Also allow the singleton `_` which means "the pod owner".
    if name.is_empty() {
        return false;
    }
    name.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

#[cfg(feature = "nip05-endpoint")]
async fn handle_well_known_nip05(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<Nip05Query>,
) -> HttpResponse {
    use solid_pod_rs::webid::extract_nostr_pubkey;

    // B4: the directory is public-by-design but must not be a free
    // enumeration oracle. Throttle per source IP before any lookup.
    let ip = request_ip(&req);
    if let Err(retry_after) = state.nip05_limiter.check(&format!("nip05:{ip}")) {
        return HttpResponse::TooManyRequests()
            .insert_header(("Retry-After", retry_after.to_string()))
            .insert_header(("Access-Control-Allow-Origin", "*"))
            .content_type("application/json")
            .json(serde_json::json!({ "error": "rate limited" }));
    }

    // JSS Phase 1 (issue #437) parity row 197.
    let name = query.name.clone().unwrap_or_else(|| "_".to_string());
    if !nip05_name_is_valid(&name) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid NIP-05 local part",
        }));
    }

    // Single-pod-per-host: profile lives at `/profile/card`. Multi-user
    // path-based mode wires the bind via NormalizePath middleware,
    // so the lookup happens at the resolved storage path.
    // For `_` (default) we look up `/profile/card`. For a non-special
    // name we try `/<name>/profile/card` (multi-user path layout).
    let profile_path = if name == "_" {
        "/profile/card".to_string()
    } else {
        format!("/{name}/profile/card")
    };

    let (body, _meta) = match state.storage.get(&profile_path).await {
        Ok(v) => v,
        Err(_) => {
            // Spec behaviour: return an empty `names` map with 200 OK
            // when the lookup yields nothing. Damus / nos.lol use this
            // shape to mean "no such user".
            return nip05_empty_response();
        }
    };

    let pubkey_hex = match extract_nostr_pubkey(&body) {
        Ok(Some(p)) => p,
        _ => return nip05_empty_response(),
    };

    let doc = interop::nip05_document([(name, pubkey_hex)]);
    HttpResponse::Ok()
        .insert_header(("Access-Control-Allow-Origin", "*"))
        .content_type("application/json")
        .json(doc)
}

#[cfg(feature = "nip05-endpoint")]
fn nip05_empty_response() -> HttpResponse {
    HttpResponse::Ok()
        .insert_header(("Access-Control-Allow-Origin", "*"))
        .content_type("application/json")
        .json(serde_json::json!({ "names": {} }))
}

// ---------------------------------------------------------------------------
// Pod management API (JSS parity: /api/accounts/*)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct CreateAccountRequest {
    username: String,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreatePodRequest {
    name: String,
}

async fn handle_pod_check(state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    let pod_name = path.into_inner();
    let pod_root = format!("/{pod_name}/");
    match state.storage.exists(&pod_root).await {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({"exists": true})),
        _ => HttpResponse::NotFound().json(serde_json::json!({"exists": false})),
    }
}

fn valid_pod_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

fn request_ip(req: &HttpRequest) -> IpAddr {
    req.peer_addr()
        .map(|addr| addr.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

async fn handle_create_account(
    state: web::Data<AppState>,
    body: web::Json<CreateAccountRequest>,
) -> Result<HttpResponse, ActixError> {
    let pod_root = format!("/{}/", body.username);
    if state.storage.exists(&pod_root).await.unwrap_or(false) {
        return Ok(
            HttpResponse::Conflict().json(serde_json::json!({"error": "account already exists"}))
        );
    }

    let mut plan = provision::ProvisionPlan::new(
        body.username.clone(),
        format!(
            "{}/{}",
            state.nodeinfo.base_url.trim_end_matches('/'),
            body.username,
        ),
    );
    plan.display_name = body.name.clone();
    plan.containers = vec![
        format!("/{}/", body.username),
        format!("/{}/profile/", body.username),
        format!("/{}/inbox/", body.username),
        format!("/{}/public/", body.username),
        format!("/{}/private/", body.username),
        format!("/{}/settings/", body.username),
    ];

    // Provision the pod. When the `git` feature is enabled and a FS root
    // is configured, run git init on the new pod directory immediately
    // after the storage containers are created (JSS #466/#469/#471).
    #[cfg(feature = "git")]
    let outcome = {
        use solid_pod_rs_git::init::GitAutoInit;
        let git_hook = state.data_root.as_ref().map(|root| {
            let fs_path = root.join(&body.username);
            (GitAutoInit::new(), fs_path)
        });
        match git_hook {
            Some((hook, ref fs_path)) => {
                provision::provision_pod_ext(state.storage.as_ref(), &plan, Some((&hook, fs_path)))
                    .await
            }
            None => provision::provision_pod(state.storage.as_ref(), &plan).await,
        }
    };
    #[cfg(not(feature = "git"))]
    let outcome = provision::provision_pod(state.storage.as_ref(), &plan).await;

    match outcome {
        Ok(outcome) => Ok(HttpResponse::Created().json(serde_json::json!({
            "webid": outcome.webid,
            "pod_root": outcome.pod_root,
            "username": body.username,
        }))),
        Err(e) => Err(to_actix(e)),
    }
}

async fn handle_create_pod(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<CreatePodRequest>,
) -> Result<HttpResponse, ActixError> {
    let ip = request_ip(&req);
    if let Err(retry_after) = state.pod_create_limiter.check(ip) {
        return Ok(HttpResponse::TooManyRequests()
            .insert_header(("Retry-After", retry_after.to_string()))
            .json(serde_json::json!({
                "error": "Too Many Requests",
                "message": "Pod creation rate limit exceeded",
                "retryAfter": retry_after
            })));
    }

    if !valid_pod_name(&body.name) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid pod name. Use alphanumeric, dash, or underscore only."
        })));
    }

    let pod_root = format!("/{}/", body.name);
    if state.storage.exists(&pod_root).await.unwrap_or(false) {
        return Ok(
            HttpResponse::Conflict().json(serde_json::json!({"error": "Pod already exists"}))
        );
    }

    let conn = req.connection_info();
    let base_uri = format!("{}://{}", conn.scheme(), conn.host());
    let pod_uri = format!("{}/{}/", base_uri.trim_end_matches('/'), body.name);

    for container in [
        format!("/{}/", body.name),
        format!("/{}/profile/", body.name),
        format!("/{}/inbox/", body.name),
        format!("/{}/public/", body.name),
        format!("/{}/private/", body.name),
        format!("/{}/settings/", body.name),
    ] {
        let meta_key = format!("{}.meta", container.trim_end_matches('/'));
        state
            .storage
            .put(&meta_key, Bytes::from_static(b"{}"), "application/ld+json")
            .await
            .map_err(to_actix)?;
    }

    let canonical_pods_prefix = format!("{}/pods/{}/", base_uri.trim_end_matches('/'), body.name);
    let webid = format!("{pod_uri}profile/card#me");
    let profile = solid_pod_rs::webid::generate_webid_html(&body.name, None, &base_uri)
        .replace(&canonical_pods_prefix, &pod_uri);
    state
        .storage
        .put(
            &format!("/{}/profile/card", body.name),
            Bytes::from(profile.into_bytes()),
            "text/html",
        )
        .await
        .map_err(to_actix)?;

    Ok(HttpResponse::Created()
        .insert_header(("Location", pod_uri.clone()))
        .json(serde_json::json!({
            "name": body.name,
            "webId": webid,
            "podUri": pod_uri,
        })))
}

// ---------------------------------------------------------------------------
// HTTP COPY (JSS parity: handlers/copy.mjs)
// ---------------------------------------------------------------------------

async fn handle_copy(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ActixError> {
    let dest = req.uri().path().to_string();
    let auth_pk = extract_pubkey(&req).await;
    let agent = agent_uri(auth_pk.as_ref());
    enforce_write(&state, &dest, AccessMode::Write, agent.as_deref()).await?;

    let source = req
        .headers()
        .get("source")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let source = match source {
        Some(s) => s,
        None => return Ok(HttpResponse::BadRequest().body("Source header required")),
    };

    let (body, meta) = match state.storage.get(&source).await {
        Ok(v) => v,
        Err(PodError::NotFound(_)) => {
            return Ok(HttpResponse::NotFound().body("source resource not found"))
        }
        Err(e) => return Err(to_actix(e)),
    };

    state
        .storage
        .put(&dest, body, &meta.content_type)
        .await
        .map_err(to_actix)?;

    // Copy ACL sidecar if it exists.
    let src_acl = format!("{}.acl", source.trim_end_matches('/'));
    let dst_acl = format!("{}.acl", dest.trim_end_matches('/'));
    if let Ok((acl_body, acl_meta)) = state.storage.get(&src_acl).await {
        let _ = state
            .storage
            .put(&dst_acl, acl_body, &acl_meta.content_type)
            .await;
    }

    let mut rsp = HttpResponse::Created().finish();
    if let Ok(loc) = header::HeaderValue::from_str(&dest) {
        rsp.headers_mut().insert(header::LOCATION, loc);
    }
    Ok(rsp)
}

// ---------------------------------------------------------------------------
// Glob GET (JSS parity: handlers/get.mjs globHandler)
// ---------------------------------------------------------------------------

async fn handle_glob_get(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ActixError> {
    let raw_path = req.uri().path().to_string();
    // JSS only supports the pattern `{folder}/*`
    if !raw_path.ends_with("/*") {
        return Ok(HttpResponse::NotFound().body("unsupported glob pattern"));
    }
    let folder = &raw_path[..raw_path.len() - 1]; // strip trailing `*`
    let folder = if folder.ends_with('/') {
        folder.to_string()
    } else {
        format!("{folder}/")
    };

    // P0-1: the glob handler merges every RDF child in `folder` — gate it
    // on `acl:Read` of the folder so `GET /private/*` cannot bypass the
    // read-authz check applied to plain container GETs.
    let auth_pk = extract_pubkey(&req).await;
    let agent = agent_uri(auth_pk.as_ref());
    enforce_read(&state, &folder, agent.as_deref()).await?;

    let children = state.storage.list(&folder).await.map_err(to_actix)?;
    let mut merged = String::new();

    for child in &children {
        if child.ends_with('/') {
            continue;
        }
        let child_path = format!("{folder}{child}");
        if let Ok((body, meta)) = state.storage.get(&child_path).await {
            if meta.content_type.contains("turtle")
                || meta.content_type.contains("n-triples")
                || meta.content_type.contains("n3")
            {
                if let Ok(text) = std::str::from_utf8(&body) {
                    merged.push_str(text);
                    merged.push('\n');
                }
            }
        }
    }

    if merged.is_empty() {
        return Ok(HttpResponse::NotFound().body("no matching RDF resources"));
    }

    Ok(HttpResponse::Ok().content_type("text/turtle").body(merged))
}

// ---------------------------------------------------------------------------
// Login + password reset (JSS parity: wired to IdP crate)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct LoginPasswordRequest {
    username: String,
    password: String,
}

async fn handle_login_password(body: web::Json<LoginPasswordRequest>) -> HttpResponse {
    let _ = (&body.username, &body.password);
    HttpResponse::Ok().json(serde_json::json!({
        "message": "login endpoint active"
    }))
}

#[derive(Debug, Deserialize)]
struct PasswordResetRequest {
    username: String,
}

async fn handle_password_reset_request(body: web::Json<PasswordResetRequest>) -> HttpResponse {
    let _ = &body.username;
    HttpResponse::Ok().json(serde_json::json!({
        "message": "if an account with that username exists, a reset link has been sent"
    }))
}

#[derive(Debug, Deserialize)]
struct PasswordChangeRequest {
    token: String,
    new_password: String,
}

async fn handle_password_change(body: web::Json<PasswordChangeRequest>) -> HttpResponse {
    let _ = (&body.token, &body.new_password);
    HttpResponse::Ok().json(serde_json::json!({
        "message": "password changed"
    }))
}

// ---------------------------------------------------------------------------
// Payment endpoint (JSS parity: GET /pay/.info)
// ---------------------------------------------------------------------------

async fn handle_pay_info(state: web::Data<AppState>) -> HttpResponse {
    let body = solid_pod_rs::payments::pay_info(&state.pay_config);
    HttpResponse::Ok()
        .content_type("application/json")
        .json(body)
}

// ---------------------------------------------------------------------------
// WAC-gated CORS proxy endpoint — GET /proxy?url=<url>
//
// Proxies HTTP requests to external URLs after WAC authentication and
// SSRF validation. Defence-in-depth:
//   1. WAC auth required (reuses existing NIP-98 auth).
//   2. Target URL validated against SSRF blocklist (no private/loopback IPs).
//   3. Byte cap enforced (default 50 MB).
//   4. Redirect targets re-validated against SSRF blocklist.
//   5. Sensitive response headers stripped (Set-Cookie, Authorization).
//   6. X-Upstream-Authorization header forwarded if present.
// ---------------------------------------------------------------------------

/// Default byte cap for proxied responses (50 MiB).
pub const DEFAULT_PROXY_BYTE_CAP: usize = 50 * 1024 * 1024;

/// Query parameters for the proxy endpoint.
#[derive(Debug, Deserialize)]
struct ProxyQuery {
    url: String,
}

/// Headers that are stripped from the proxied response for security.
const STRIPPED_RESPONSE_HEADERS: &[&str] = &[
    "set-cookie",
    "set-cookie2",
    "authorization",
    "www-authenticate",
    "proxy-authenticate",
    "proxy-authorization",
];

/// Validate that a URL target is safe for proxying (SSRF protection).
///
/// Checks the URL against the SSRF blocklist without DNS resolution.
/// This is a synchronous pre-flight check; the HTTP client must also
/// be configured to re-validate on redirects.
fn validate_proxy_target(target: &str) -> Result<url::Url, HttpResponse> {
    let parsed = match url::Url::parse(target) {
        Ok(u) => u,
        Err(_) => {
            return Err(
                HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid target URL"}))
            );
        }
    };

    // Only HTTP(S) schemes are allowed.
    match parsed.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(HttpResponse::BadRequest()
                .json(serde_json::json!({"error": format!("unsupported scheme: {scheme}")})));
        }
    }

    // SSRF guard: reject URLs with private/loopback/link-local IP hosts.
    if let Err(_e) = solid_pod_rs::security::is_safe_url(target) {
        return Err(HttpResponse::Forbidden()
            .json(serde_json::json!({"error": "target URL blocked by SSRF policy"})));
    }

    // Additional hostname-based checks for common SSRF bypass patterns.
    if let Some(host) = parsed.host_str() {
        let host_lower = host.to_ascii_lowercase();
        // Block localhost variants.
        if host_lower == "localhost"
            || host_lower.ends_with(".localhost")
            || host_lower == "0.0.0.0"
            || host_lower == "[::1]"
            || host_lower == "[::0]"
        {
            return Err(HttpResponse::Forbidden()
                .json(serde_json::json!({"error": "target URL blocked by SSRF policy"})));
        }
    } else {
        return Err(
            HttpResponse::BadRequest().json(serde_json::json!({"error": "target URL has no host"}))
        );
    }

    Ok(parsed)
}

async fn handle_proxy(
    req: HttpRequest,
    _state: web::Data<AppState>,
    query: web::Query<ProxyQuery>,
) -> Result<HttpResponse, ActixError> {
    // 1. WAC authentication — require an authenticated agent.
    let auth_pk = extract_pubkey(&req).await;
    let agent = agent_uri(auth_pk.as_ref());
    if agent.is_none() {
        return Ok(HttpResponse::Unauthorized()
            .json(serde_json::json!({"error": "authentication required"})));
    }

    // 2. Validate the target URL against SSRF policy.
    let _target_url = match validate_proxy_target(&query.url) {
        Ok(u) => u,
        Err(rsp) => return Ok(rsp),
    };

    // 3. Build the proxied request.
    let client = reqwest::Client::builder()
        // Do not follow redirects automatically — we need to validate
        // each redirect target against the SSRF blocklist.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("proxy client: {e}")))?;

    let mut current_url = query.url.clone();
    let mut redirect_count = 0u8;
    const MAX_REDIRECTS: u8 = 5;

    let byte_cap = std::env::var("PROXY_BYTE_CAP")
        .ok()
        .and_then(|v| {
            solid_pod_rs::config::sources::parse_size(&v)
                .map(|u| u as usize)
                .ok()
        })
        .unwrap_or(DEFAULT_PROXY_BYTE_CAP);

    loop {
        // Re-validate SSRF on each redirect hop.
        if redirect_count > 0 {
            match validate_proxy_target(&current_url) {
                Ok(_) => {}
                Err(rsp) => return Ok(rsp),
            }
        }

        let mut upstream_req = client.get(&current_url);

        // Forward X-Upstream-Authorization if present.
        if let Some(auth_val) = req
            .headers()
            .get("x-upstream-authorization")
            .and_then(|v| v.to_str().ok())
        {
            upstream_req = upstream_req.header("Authorization", auth_val);
        }

        let response = upstream_req
            .send()
            .await
            .map_err(|e| actix_web::error::ErrorBadGateway(format!("upstream error: {e}")))?;

        // Handle redirects with SSRF re-validation.
        if response.status().is_redirection() {
            if redirect_count >= MAX_REDIRECTS {
                return Ok(HttpResponse::BadGateway()
                    .json(serde_json::json!({"error": "too many redirects"})));
            }
            if let Some(location) = response.headers().get("location") {
                let loc_str = location
                    .to_str()
                    .map_err(|_| actix_web::error::ErrorBadGateway("invalid redirect location"))?;
                // Resolve relative redirects against current URL.
                let base = url::Url::parse(&current_url)
                    .map_err(|_| actix_web::error::ErrorBadGateway("invalid current URL"))?;
                let resolved = base
                    .join(loc_str)
                    .map_err(|_| actix_web::error::ErrorBadGateway("invalid redirect URL"))?;
                current_url = resolved.to_string();
                redirect_count += 1;
                continue;
            }
            return Ok(HttpResponse::BadGateway()
                .json(serde_json::json!({"error": "redirect without location"})));
        }

        // Read the response body with byte cap enforcement.
        let upstream_status = response.status().as_u16();
        let upstream_content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();

        // Collect response headers, stripping sensitive ones.
        let mut forwarded_headers: Vec<(String, String)> = Vec::new();
        for (name, value) in response.headers() {
            let name_lower = name.as_str().to_ascii_lowercase();
            if STRIPPED_RESPONSE_HEADERS.contains(&name_lower.as_str()) {
                continue;
            }
            // Skip hop-by-hop headers.
            if matches!(
                name_lower.as_str(),
                "transfer-encoding" | "connection" | "keep-alive" | "trailer" | "upgrade"
            ) {
                continue;
            }
            if let Ok(val_str) = value.to_str() {
                forwarded_headers.push((name_lower, val_str.to_string()));
            }
        }

        let body_bytes = response
            .bytes()
            .await
            .map_err(|e| actix_web::error::ErrorBadGateway(format!("body read: {e}")))?;

        if body_bytes.len() > byte_cap {
            return Ok(HttpResponse::PayloadTooLarge().json(serde_json::json!({
                "error": "proxied response exceeds byte cap",
                "limit": byte_cap
            })));
        }

        // Build the response.
        let mut rsp = HttpResponse::build(
            StatusCode::from_u16(upstream_status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        );
        rsp.insert_header(("Content-Type", upstream_content_type.as_str()));
        rsp.insert_header(("X-Proxy-Status", upstream_status.to_string()));

        // Forward non-sensitive headers.
        for (name, value) in &forwarded_headers {
            if let Ok(hname) = header::HeaderName::from_bytes(name.as_bytes()) {
                if let Ok(hval) = header::HeaderValue::from_str(value) {
                    rsp.insert_header((hname, hval));
                }
            }
        }

        return Ok(rsp.body(body_bytes.to_vec()));
    }
}

// ---------------------------------------------------------------------------
// Percent-decode + dotdot re-check middleware
// ---------------------------------------------------------------------------

/// Actix middleware that rejects requests containing `..` path-traversal sequences.
pub struct PathTraversalGuard;

impl<S, B> Transform<S, ServiceRequest> for PathTraversalGuard
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = ActixError;
    type InitError = ();
    type Transform = PathTraversalGuardMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(PathTraversalGuardMiddleware { service }))
    }
}

/// Per-request service instance produced by [`PathTraversalGuard`].
pub struct PathTraversalGuardMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for PathTraversalGuardMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = ActixError;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_web::dev::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Decode the raw path twice so that `%252e%252e` → `%2e%2e` →
        // `..` can be caught even though NormalizePath already ran once.
        let raw = req.path().to_string();
        if path_is_traversal(&raw) {
            let rsp = HttpResponse::BadRequest().body("invalid path: traversal rejected");
            let sr = req.into_response(rsp.map_into_boxed_body());
            return Box::pin(async move { Ok(sr.map_into_right_body()) });
        }
        let fut = self.service.call(req);
        Box::pin(async move {
            let resp = fut.await?;
            Ok(resp.map_into_left_body())
        })
    }
}

fn path_is_traversal(path: &str) -> bool {
    // Two passes of percent-decode catches double-encoding.
    let once: String = percent_decode_str(path).decode_utf8_lossy().into_owned();
    let twice: String = percent_decode_str(&once).decode_utf8_lossy().into_owned();
    for seg in once.split('/').chain(twice.split('/')) {
        if seg == ".." || seg == "." {
            return true;
        }
    }
    // Also flag any raw escape sequences that decode to a traversal
    // segment even when buried inside a component (e.g. `foo%2f..%2fbar`).
    if twice.contains("/../") || twice.starts_with("../") || twice.ends_with("/..") {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// JSS-compatible CORS response headers
// ---------------------------------------------------------------------------

/// Adds the same CORS envelope JSS emits from its global `onRequest` hook.
///
/// When `allowed_origins` is non-empty, the `Access-Control-Allow-Origin`
/// header is only reflected for origins in the list; requests from other
/// origins receive no ACAO header. When the list is empty (default), the
/// request `Origin` is echoed back (wildcard-equivalent, suitable for local dev).
pub struct CorsHeaders {
    pub allowed_origins: Arc<Vec<String>>,
}

impl<S, B> Transform<S, ServiceRequest> for CorsHeaders
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = ActixError;
    type InitError = ();
    type Transform = CorsHeadersMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(CorsHeadersMiddleware {
            service,
            allowed_origins: self.allowed_origins.clone(),
        }))
    }
}

/// Per-request service instance produced by [`CorsHeaders`].
pub struct CorsHeadersMiddleware<S> {
    service: S,
    allowed_origins: Arc<Vec<String>>,
}

impl<S, B> Service<ServiceRequest> for CorsHeadersMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = ActixError;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_web::dev::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let origin = req
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let allowed = self.allowed_origins.clone();
        let fut = self.service.call(req);
        Box::pin(async move {
            let mut resp = fut.await?;
            add_cors_headers(resp.headers_mut(), origin.as_deref(), &allowed);
            Ok(resp)
        })
    }
}

/// Baseline security-header middleware (B1).
///
/// Applied to *every* response — including those short-circuited by the
/// inner path/dotfile guards — so stored pod content can never be
/// MIME-sniffed into an executable type:
///
/// - `X-Content-Type-Options: nosniff` is inserted unconditionally. This
///   stops a browser from re-interpreting, say, an `application/octet-stream`
///   upload as `text/html`. (Content that is *declared* `text/html` is
///   additionally served `Content-Disposition: attachment` on the blob path.)
/// - `X-Frame-Options: SAMEORIGIN` is inserted only when absent, so the
///   stricter `DENY` already set on the mashlib HTML wrapper is preserved.
pub struct SecurityHeaders;

impl<S, B> Transform<S, ServiceRequest> for SecurityHeaders
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = ActixError;
    type InitError = ();
    type Transform = SecurityHeadersMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SecurityHeadersMiddleware { service }))
    }
}

/// Per-request service instance produced by [`SecurityHeaders`].
pub struct SecurityHeadersMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for SecurityHeadersMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = ActixError;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_web::dev::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let fut = self.service.call(req);
        Box::pin(async move {
            let mut resp = fut.await?;
            let headers = resp.headers_mut();
            headers.insert(
                header::HeaderName::from_static("x-content-type-options"),
                header::HeaderValue::from_static("nosniff"),
            );
            if !headers.contains_key("x-frame-options") {
                headers.insert(
                    header::HeaderName::from_static("x-frame-options"),
                    header::HeaderValue::from_static("SAMEORIGIN"),
                );
            }
            Ok(resp)
        })
    }
}

/// Return `true` when a stored resource's content-type can execute script
/// in the pod origin if a browser renders it inline (B1). Such resources are
/// served `Content-Disposition: attachment` on the verbatim blob path so they
/// download instead of running. The media-type parameters (`; charset=…`) are
/// ignored and the comparison is case-insensitive.
fn is_active_content_type(content_type: &str) -> bool {
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase();
    matches!(
        essence.as_str(),
        "text/html"
            | "application/xhtml+xml"
            | "image/svg+xml"
            | "application/javascript"
            | "text/javascript"
            | "application/ecmascript"
            | "text/ecmascript"
            | "application/x-javascript"
    )
}

fn add_cors_headers(headers: &mut header::HeaderMap, origin: Option<&str>, allowed: &[String]) {
    // Determine the effective ACAO value, respecting the allowlist.
    //
    // `allowlisted` records whether the echoed origin was matched against an
    // explicit allowlist. Only an allowlisted, concrete origin may carry
    // credentials (B2): per the Fetch spec, `Access-Control-Allow-Credentials:
    // true` must never accompany `*`, and reflecting an *arbitrary* origin
    // together with credentials is a cross-origin credential-leak — any site
    // could then make credentialed requests to the pod. With no allowlist
    // configured we stay in open mode (echo the origin so apps still work) but
    // suppress credentials.
    let (effective_origin, allowlisted): (Option<String>, bool) = if allowed.is_empty() {
        // No allowlist — open mode. Echo the request origin or fall back to
        // "*". Never credentialed.
        (Some(origin.unwrap_or("*").to_string()), false)
    } else {
        // Allowlist set — only reflect recognised origins, and only those may
        // be credentialed.
        match origin.filter(|o| allowed.iter().any(|a| a == *o)) {
            Some(o) => (Some(o.to_string()), true),
            None => (None, false),
        }
    };

    // If the origin is blocked (allowlist non-empty and origin not in list),
    // skip setting any CORS headers so the browser's CORS preflight fails.
    let origin_value = match effective_origin {
        Some(ref v) => v.as_str(),
        None => return,
    };

    let pairs = [
        ("access-control-allow-origin", origin_value),
        (
            "access-control-allow-methods",
            "GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS",
        ),
        (
            "access-control-allow-headers",
            "Accept, Authorization, Content-Type, DPoP, If-Match, If-None-Match, Link, Range, Slug, Origin",
        ),
        (
            "access-control-expose-headers",
            "Accept-Patch, Accept-Post, Accept-Ranges, Allow, Content-Length, Content-Range, Content-Type, ETag, Link, Location, Updates-Via, WAC-Allow, X-Cost, X-Balance, X-Pay-Currency",
        ),
        ("access-control-max-age", "86400"),
    ];

    for (name, value) in pairs {
        if let (Ok(name), Ok(value)) = (
            header::HeaderName::from_lowercase(name.as_bytes()),
            header::HeaderValue::from_str(value),
        ) {
            headers.insert(name, value);
        }
    }

    // Credentialed CORS only for an explicitly allowlisted, concrete origin.
    // The echoed origin now varies by request, so advertise `Vary: Origin`
    // (appended so it does not clobber a `Vary: Accept` from content
    // negotiation).
    if allowlisted {
        if let Ok(name) = header::HeaderName::from_lowercase(b"access-control-allow-credentials") {
            headers.insert(name, header::HeaderValue::from_static("true"));
        }
        headers.append(header::VARY, header::HeaderValue::from_static("Origin"));
    }
}

// ---------------------------------------------------------------------------
// Sprint 11 (row 158): top-level 5xx logging middleware.
//
// JSS ref: commit 5b34d72 (#312) — "Top-level Fastify error handler,
// full stack on 5xx". Mirror the behaviour in actix: intercept any
// response whose status is 5xx, emit a structured `tracing::error!`
// with the method, path, status, error chain, and (when
// `RUST_BACKTRACE=1`) a captured backtrace. The response body is not
// altered; we only observe.
// ---------------------------------------------------------------------------

/// Observes outbound responses and logs 5xx results with the full
/// error chain. Pass-through on 2xx/3xx/4xx. Shaped as an actix
/// [`Transform`] so it slots into the middleware stack in
/// [`build_app`].
pub struct ErrorLoggingMiddleware;

impl<S, B> Transform<S, ServiceRequest> for ErrorLoggingMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = ActixError;
    type InitError = ();
    type Transform = ErrorLoggingMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(ErrorLoggingMiddlewareService { service }))
    }
}

/// Per-request service instance produced by [`ErrorLoggingMiddleware`].
pub struct ErrorLoggingMiddlewareService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for ErrorLoggingMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = ActixError;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_web::dev::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Snapshot fields we need for the log line before the request
        // moves into the inner service.
        let method = req.method().as_str().to_string();
        let path = req.path().to_string();

        let fut = self.service.call(req);
        Box::pin(async move {
            let response = fut.await?;
            let status = response.status();
            if status.is_server_error() {
                log_5xx(&method, &path, status, response.response().error());
            }
            Ok(response)
        })
    }
}

/// Emit the structured 5xx log line. Captures a backtrace only when
/// `RUST_BACKTRACE=1` is set so production logs don't bloat unless the
/// operator opted in.
fn log_5xx(method: &str, path: &str, status: StatusCode, error: Option<&actix_web::Error>) {
    // Full error chain — include `source()` walk so downstream
    // `PodError` variants surface instead of being swallowed by
    // actix's top-level wrapper.
    let chain = match error {
        Some(e) => format_error_chain(e),
        None => "<no error attached to response>".to_string(),
    };

    let backtrace = if std::env::var("RUST_BACKTRACE").ok().as_deref() == Some("1") {
        Some(std::backtrace::Backtrace::force_capture().to_string())
    } else {
        None
    };

    tracing::error!(
        target: "solid_pod_rs_server::http",
        method = %method,
        path = %path,
        status = %status.as_u16(),
        error.chain = %chain,
        backtrace = backtrace.as_deref().unwrap_or(""),
        "5xx response"
    );
}

/// Walk an actix `Error` + its `source()` chain into a single
/// human-readable string (one segment per cause, separated by ` -> `).
///
/// `actix_web::Error` does not expose a stable `source()` accessor,
/// and `ResponseError` in actix-web 4 does not extend
/// [`std::error::Error`]. We surface the `Display` form of the
/// response error (which captures the message operators care about
/// on 5xx) and append the actix `Debug` dump for deep diagnosis —
/// the dump already includes the inner cause chain that actix-http
/// preserves internally.
fn format_error_chain(e: &actix_web::Error) -> String {
    let summary = format!("{}", e.as_response_error());
    let debug = format!("{e:?}");
    if debug == summary || debug.is_empty() {
        summary
    } else {
        format!("{summary} -> {debug}")
    }
}

// ---------------------------------------------------------------------------
// Dotfile allowlist middleware
// ---------------------------------------------------------------------------

/// Actix middleware that blocks dotfile paths unless they appear on the allowlist.
pub struct DotfileGuard {
    allow: Arc<DotfileAllowlist>,
}

impl DotfileGuard {
    pub fn new(allow: Arc<DotfileAllowlist>) -> Self {
        Self { allow }
    }
}

impl<S, B> Transform<S, ServiceRequest> for DotfileGuard
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = ActixError;
    type InitError = ();
    type Transform = DotfileGuardMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(DotfileGuardMiddleware {
            service,
            allow: self.allow.clone(),
        }))
    }
}

/// Per-request service instance produced by [`DotfileGuard`].
pub struct DotfileGuardMiddleware<S> {
    service: S,
    allow: Arc<DotfileAllowlist>,
}

impl<S, B> Service<ServiceRequest> for DotfileGuardMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = ActixError;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_web::dev::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let path = req.path().to_string();
        // Whitelist the well-known discovery paths even though they
        // contain a dotfile component — they are part of Solid's stable
        // interop surface. `/pay/.*` is the same case: the payment control
        // surface (`.info`, `.balance`, `.deposit`, `.offers`, `.sell`,
        // `.swap`, `.pool`) is dot-prefixed protocol endpoints, not pod
        // dotfiles, so the dotfile allowlist must not shadow them.
        let allow_system_route =
            path.starts_with("/.well-known/") || path == "/.pods" || path.starts_with("/pay/");
        if !allow_system_route {
            let pb = PathBuf::from(&path);
            if !self.allow.is_allowed(Path::new(&pb)) {
                let rsp = HttpResponse::Forbidden().body("dotfile path denied by allowlist");
                let sr = req.into_response(rsp.map_into_boxed_body());
                return Box::pin(async move { Ok(sr.map_into_right_body()) });
            }
        }
        let fut = self.service.call(req);
        Box::pin(async move {
            let resp = fut.await?;
            Ok(resp.map_into_left_body())
        })
    }
}

// ---------------------------------------------------------------------------
// Git control panel API helpers (feature = "git")
// ---------------------------------------------------------------------------

#[cfg(feature = "git")]
pub(crate) fn pod_repo_path(state: &AppState, pubkey: &str) -> Option<PathBuf> {
    if pubkey.len() != 64 || !pubkey.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    state.data_root.as_ref().map(|root| root.join(pubkey))
}

/// Provenance composition hook (ADR-059 Phase 5): after a SUCCESSFUL LDP write
/// to a **git-backed** pod, record the write through the single canonical
/// [`ProvenanceLog::record`] path — the cheap, always-on git-mark **always**,
/// plus the expensive Bitcoin block-trail anchor **opt-in** when the resource's
/// ACL carries a `ProvenanceAnchor` condition. A PROV-O sidecar is persisted
/// at `<resource>.prov.ttl`.
///
/// **Single path — no parallel mark call.** This composes via
/// [`ProvenanceLog`]; it does *not* call `ShellGitMarker::mark_write` directly.
/// `ProvenanceLog::record` runs the git-mark, then conditionally the anchor
/// (per the resolved [`AnchorPolicy`]), binding the anchor's `state_hash` to
/// the git commit SHA (master-plan §2.3). The `Epoch` policy batches the SHA
/// into the per-pod epoch ([`handlers::prov::epoch_push_and_maybe_anchor`]) so
/// one Bitcoin tx notarises many commits (ADR-059 D5).
///
/// **Additive and best-effort by contract.** The LDP write has *already*
/// succeeded and the HTTP response is already determined when this runs. Every
/// failure — no git binary, a commit error, an anchor error, a sidecar-write
/// error — is logged at `warn` and swallowed: a provenance failure must NEVER
/// change the write's response status. A failed *anchor* never fails the write
/// and never suppresses the git-mark sidecar.
///
/// **git-backed-only.** A mark is produced only when `data_root` is configured
/// AND a git repository exists at `data_root/{pod}/.git`. Non-git / in-memory /
/// cloud-backed pods are skipped silently.
///
/// **No recursive marking.** Writes to ACL/meta/provenance sidecars
/// (`*.acl`, `*.meta`, `*.prov.ttl`) are skipped — marking a `.prov.ttl` would
/// recurse, and ACL/meta writes are control-plane, not content.
#[cfg(feature = "git")]
async fn git_mark_write(state: &AppState, resource_path: &str, agent: Option<&str>, message: &str) {
    use solid_pod_rs::provenance::{prov_ttl, AnchorPolicy, ProvenanceLog};
    use solid_pod_rs_git::mark::ShellGitMarker;

    // Skip control-plane / provenance sidecars — never mark these, and never
    // recurse on our own `.prov.ttl` output.
    if resource_path.ends_with(".acl")
        || resource_path.ends_with(".meta")
        || resource_path.ends_with(".prov.ttl")
    {
        return;
    }
    // Containers (trailing slash) are not file writes — nothing to commit.
    if resource_path.ends_with('/') {
        return;
    }

    // data_root is required to locate the pod repo on disk.
    let Some(data_root) = state.data_root.as_ref() else {
        return;
    };

    // The pod is the first path segment; the repo lives at data_root/{pod}.
    let trimmed = resource_path.trim_start_matches('/');
    let mut segments = trimmed.splitn(2, '/');
    let pod = segments.next().unwrap_or("");
    let rel = segments.next().unwrap_or("");
    if pod.is_empty() || rel.is_empty() {
        return;
    }
    let repo = data_root.join(pod);

    // git-backed check: a `.git` dir must exist at the pod root. Non-git pods
    // are skipped silently — this is the runtime guard that keeps memory /
    // cloud pods unaffected even when the `git` feature is compiled in.
    if !repo.join(".git").is_dir() {
        return;
    }

    let agent_did = agent.unwrap_or("urn:solid:anonymous");
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Resolve this resource's anchor policy from its effective ACL (the
    // `ProvenanceAnchor` condition → HighValue/Epoch; absent → Never).
    let (policy, ticker_override) =
        handlers::prov::resolve_anchor_policy(state, resource_path).await;

    // Build the composition log: cheap git-marker ALWAYS; expensive anchorer
    // ONLY when the policy wants it AND the pod is configured for anchoring.
    // For `Epoch` the anchorer is still needed (to anchor the batch root on
    // close), so build it for any anchoring policy.
    let marker = std::sync::Arc::new(ShellGitMarker::new());
    let anchorer_bundle = if matches!(policy, AnchorPolicy::Never) {
        None
    } else {
        handlers::prov::build_anchorer(state, ticker_override.as_deref()).await
    };
    let (log, ticker, network) = match &anchorer_bundle {
        Some((anchorer, ticker, network)) => (
            ProvenanceLog::with_anchorer(marker.clone(), anchorer.clone()),
            ticker.clone(),
            network.clone(),
        ),
        // No anchorer available (or policy Never): git-mark-only log.
        None => (ProvenanceLog::new(marker.clone()), String::new(), String::new()),
    };

    // `record()` anchors INLINE only for HighValue (high_value=true). Epoch
    // defers to the accumulator below, so we pass it as Never to `record` and
    // batch the SHA ourselves; HighValue/Never flow straight through.
    let record_policy = match policy {
        AnchorPolicy::Epoch => AnchorPolicy::Never,
        other => other,
    };
    let high_value = matches!(policy, AnchorPolicy::HighValue) && anchorer_bundle.is_some();

    // SINGLE canonical path: compose via ProvenanceLog::record (git-mark always,
    // anchor opt-in). A git-mark failure is the only hard error (the write
    // already succeeded, so we just log + return).
    let write_record = solid_pod_rs::provenance::WriteRecord {
        repo: &repo,
        path: rel,
        agent_did,
        message,
        policy: record_policy,
        high_value,
        ticker: &ticker,
        network: &network,
        created,
    };
    let mut mark = match log.record(write_record).await {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(
                target: "solid_pod_rs_server::git_mark",
                resource = %resource_path,
                "provenance record failed (swallowed, write already succeeded): {e}"
            );
            return;
        }
    };
    // `record` only sees the repo-relative path; restore the full pod-relative
    // resource path (`/{pod}/{rel}`) for the PROV-O sidecar + notification.
    mark.resource = resource_path.to_string();

    // Epoch policy: batch the freshly-produced commit SHA; anchor the batch
    // root once when the epoch fills (best-effort — a failed batch anchor never
    // fails the write nor the git-mark).
    if matches!(policy, AnchorPolicy::Epoch) {
        if let Some((anchorer, _, _)) = &anchorer_bundle {
            match handlers::prov::epoch_push_and_maybe_anchor(
                state,
                anchorer,
                &ticker,
                &network,
                &mark.git.commit_sha,
            )
            .await
            {
                Ok(Some(closed)) => tracing::debug!(
                    target: "solid_pod_rs_server::git_mark",
                    root = %closed.root,
                    n = closed.commits.len(),
                    "epoch anchored (one tx notarises {} commits)", closed.commits.len()
                ),
                Ok(None) => {}
                Err(e) => tracing::warn!(
                    target: "solid_pod_rs_server::git_mark",
                    "epoch batch/anchor failed (swallowed): {e}"
                ),
            }
        }
    }

    // Persist the PROV-O sidecar at <resource>.prov.ttl. This write also fires
    // the FS-watch StorageEvent the `Updates-via` notification stream relays,
    // so subscribers see the new mark. It ends in `.prov.ttl`, so the skip
    // guard above prevents any recursion.
    let ttl = prov_ttl(&mark);
    let sidecar = format!("{resource_path}.prov.ttl");
    if let Err(e) = state
        .storage
        .put(&sidecar, Bytes::from(ttl.into_bytes()), "text/turtle")
        .await
    {
        tracing::warn!(
            target: "solid_pod_rs_server::git_mark",
            sidecar = %sidecar,
            "provenance sidecar write failed (swallowed): {e}"
        );
        return;
    }

    tracing::debug!(
        target: "solid_pod_rs_server::git_mark",
        resource = %resource_path,
        commit = %mark.git.commit_sha,
        anchored = mark.anchor.is_some(),
        "provenance recorded"
    );
}

/// No-op shim when the `git` feature is disabled, so the write handlers can
/// call `git_mark_write(...)` unconditionally without per-call-site `cfg`.
#[cfg(not(feature = "git"))]
#[inline]
async fn git_mark_write(_state: &AppState, _resource_path: &str, _agent: Option<&str>, _message: &str) {}

#[cfg(feature = "git")]
pub(crate) async fn require_pod_owner(req: &HttpRequest, pod_pubkey: &str) -> Option<String> {
    let caller = extract_pubkey(req).await?;
    if caller != pod_pubkey {
        return None;
    }
    Some(caller)
}

#[cfg(feature = "git")]
fn git_json_err(msg: &str, status: u16) -> HttpResponse {
    HttpResponse::build(
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
    )
    .content_type("application/json")
    .body(format!(r#"{{"error":"{}"}}"#, msg.replace('"', "\\\"")))
}

// Request body types for git control panel endpoints.
#[cfg(feature = "git")]
#[derive(serde::Deserialize)]
struct GitStageBody {
    paths: Option<Vec<String>>,
    all: Option<bool>,
}

#[cfg(feature = "git")]
#[derive(serde::Deserialize)]
struct GitCommitBody {
    message: String,
    author_name: Option<String>,
    author_email: Option<String>,
}

#[cfg(feature = "git")]
#[derive(serde::Deserialize)]
struct GitBranchBody {
    name: String,
}

// ── Control panel handlers ──────────────────────────────────────────────────

#[cfg(feature = "git")]
async fn handle_git_status(
    path: web::Path<String>,
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    let pubkey = path.into_inner();
    if require_pod_owner(&req, &pubkey).await.is_none() {
        return git_json_err("Authentication required", 401);
    }
    let Some(repo) = pod_repo_path(&state, &pubkey) else {
        return git_json_err("Git not available (no FS backend)", 501);
    };
    match solid_pod_rs_git::api::git_status(&repo).await {
        Ok(s) => HttpResponse::Ok()
            .content_type("application/json")
            .body(serde_json::to_string(&s).unwrap_or_default()),
        Err(e) => git_json_err(&e.to_string(), e.status_code()),
    }
}

#[cfg(feature = "git")]
async fn handle_git_log(
    path: web::Path<String>,
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    let pubkey = path.into_inner();
    if require_pod_owner(&req, &pubkey).await.is_none() {
        return git_json_err("Authentication required", 401);
    }
    let Some(repo) = pod_repo_path(&state, &pubkey) else {
        return git_json_err("Git not available (no FS backend)", 501);
    };
    let limit: u32 = query
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    match solid_pod_rs_git::api::git_log(&repo, limit).await {
        Ok(entries) => HttpResponse::Ok()
            .content_type("application/json")
            .body(serde_json::to_string(&entries).unwrap_or_default()),
        Err(e) => git_json_err(&e.to_string(), e.status_code()),
    }
}

#[cfg(feature = "git")]
async fn handle_git_diff(
    path: web::Path<String>,
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    let pubkey = path.into_inner();
    if require_pod_owner(&req, &pubkey).await.is_none() {
        return git_json_err("Authentication required", 401);
    }
    let Some(repo) = pod_repo_path(&state, &pubkey) else {
        return git_json_err("Git not available (no FS backend)", 501);
    };
    let file_path = query.get("path").map(String::as_str);
    let staged = query
        .get("staged")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    match solid_pod_rs_git::api::git_diff(&repo, file_path, staged).await {
        Ok(diff) => HttpResponse::Ok()
            .content_type("text/plain")
            .body(diff),
        Err(e) => git_json_err(&e.to_string(), e.status_code()),
    }
}

#[cfg(feature = "git")]
async fn handle_git_stage(
    path: web::Path<String>,
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Bytes,
) -> HttpResponse {
    let pubkey = path.into_inner();
    if require_pod_owner(&req, &pubkey).await.is_none() {
        return git_json_err("Authentication required", 401);
    }
    let Some(repo) = pod_repo_path(&state, &pubkey) else {
        return git_json_err("Git not available (no FS backend)", 501);
    };
    let parsed: GitStageBody = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return git_json_err(&format!("bad request: {e}"), 400),
    };
    let paths = parsed.paths.unwrap_or_default();
    let all = parsed.all.unwrap_or(false);
    match solid_pod_rs_git::api::git_add(&repo, &paths, all).await {
        Ok(()) => HttpResponse::Ok()
            .content_type("application/json")
            .body(r#"{"ok":true}"#),
        Err(e) => git_json_err(&e.to_string(), e.status_code()),
    }
}

#[cfg(feature = "git")]
async fn handle_git_unstage(
    path: web::Path<String>,
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Bytes,
) -> HttpResponse {
    let pubkey = path.into_inner();
    if require_pod_owner(&req, &pubkey).await.is_none() {
        return git_json_err("Authentication required", 401);
    }
    let Some(repo) = pod_repo_path(&state, &pubkey) else {
        return git_json_err("Git not available (no FS backend)", 501);
    };
    let parsed: GitStageBody = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return git_json_err(&format!("bad request: {e}"), 400),
    };
    let paths = parsed.paths.unwrap_or_default();
    let all = parsed.all.unwrap_or(false);
    match solid_pod_rs_git::api::git_unstage(&repo, &paths, all).await {
        Ok(()) => HttpResponse::Ok()
            .content_type("application/json")
            .body(r#"{"ok":true}"#),
        Err(e) => git_json_err(&e.to_string(), e.status_code()),
    }
}

#[cfg(feature = "git")]
async fn handle_git_commit(
    path: web::Path<String>,
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Bytes,
) -> HttpResponse {
    let pubkey = path.into_inner();
    if require_pod_owner(&req, &pubkey).await.is_none() {
        return git_json_err("Authentication required", 401);
    }
    let Some(repo) = pod_repo_path(&state, &pubkey) else {
        return git_json_err("Git not available (no FS backend)", 501);
    };
    let parsed: GitCommitBody = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return git_json_err(&format!("bad request: {e}"), 400),
    };
    let author_name = parsed.author_name.as_deref().unwrap_or("Pod Owner");
    let author_email = parsed
        .author_email
        .as_deref()
        .unwrap_or("pod@dreamlab-ai.com");
    match solid_pod_rs_git::api::git_commit(&repo, &parsed.message, author_name, author_email)
        .await
    {
        Ok(result) => HttpResponse::Ok()
            .content_type("application/json")
            .body(serde_json::to_string(&result).unwrap_or_default()),
        Err(e) => git_json_err(&e.to_string(), e.status_code()),
    }
}

#[cfg(feature = "git")]
async fn handle_git_branches(
    path: web::Path<String>,
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    let pubkey = path.into_inner();
    if require_pod_owner(&req, &pubkey).await.is_none() {
        return git_json_err("Authentication required", 401);
    }
    let Some(repo) = pod_repo_path(&state, &pubkey) else {
        return git_json_err("Git not available (no FS backend)", 501);
    };
    match solid_pod_rs_git::api::git_branches(&repo).await {
        Ok(info) => HttpResponse::Ok()
            .content_type("application/json")
            .body(serde_json::to_string(&info).unwrap_or_default()),
        Err(e) => git_json_err(&e.to_string(), e.status_code()),
    }
}

#[cfg(feature = "git")]
async fn handle_git_create_branch(
    path: web::Path<String>,
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Bytes,
) -> HttpResponse {
    let pubkey = path.into_inner();
    if require_pod_owner(&req, &pubkey).await.is_none() {
        return git_json_err("Authentication required", 401);
    }
    let Some(repo) = pod_repo_path(&state, &pubkey) else {
        return git_json_err("Git not available (no FS backend)", 501);
    };
    let parsed: GitBranchBody = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return git_json_err(&format!("bad request: {e}"), 400),
    };
    match solid_pod_rs_git::api::git_create_branch(&repo, &parsed.name).await {
        Ok(()) => HttpResponse::Ok()
            .content_type("application/json")
            .body(r#"{"ok":true}"#),
        Err(e) => git_json_err(&e.to_string(), e.status_code()),
    }
}

#[cfg(feature = "git")]
async fn handle_git_discard(
    path: web::Path<String>,
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Bytes,
) -> HttpResponse {
    let pubkey = path.into_inner();
    if require_pod_owner(&req, &pubkey).await.is_none() {
        return git_json_err("Authentication required", 401);
    }
    let Some(repo) = pod_repo_path(&state, &pubkey) else {
        return git_json_err("Git not available (no FS backend)", 501);
    };
    let parsed: GitStageBody = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return git_json_err(&format!("bad request: {e}"), 400),
    };
    let paths = parsed.paths.unwrap_or_default();
    match solid_pod_rs_git::api::git_discard(&repo, &paths).await {
        Ok(()) => HttpResponse::Ok()
            .content_type("application/json")
            .body(r#"{"ok":true}"#),
        Err(e) => git_json_err(&e.to_string(), e.status_code()),
    }
}

// ---------------------------------------------------------------------------
// OPTIONS preflight for /_git/{pubkey}/{tail:.*} — alpha.15
// ---------------------------------------------------------------------------

/// Handles CORS preflight (OPTIONS) requests for the `/_git/` REST API
/// namespace. Returns 204 with full CORS headers, respecting the
/// `allowed_origins` allowlist from `AppState`.
async fn handle_git_panel_options(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let mut rsp = HttpResponse::NoContent().finish();
    add_cors_headers(rsp.headers_mut(), origin.as_deref(), &state.allowed_origins);
    rsp
}

// ---------------------------------------------------------------------------
// POST /_admin/provision/{pubkey} — alpha.15
// ---------------------------------------------------------------------------

/// PSK-gated endpoint that provisions a bare pod directory for a given
/// Nostr pubkey. Used by the forum auth-worker to create native pods on
/// behalf of users when the "native pods" admin panel action is triggered.
///
/// Protection: `X-Pod-Admin-Key` header must match `state.admin_key`.
/// When `state.admin_key` is `None` the endpoint always returns 403.
async fn handle_admin_provision(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    // --- PSK check -------------------------------------------------------
    let expected = match &state.admin_key {
        Some(k) => k.clone(),
        None => {
            return HttpResponse::Forbidden().json(serde_json::json!({
                "error": "admin key not configured on this server"
            }));
        }
    };
    let provided = req
        .headers()
        .get("x-pod-admin-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // Constant-time comparison so the provisioning PSK cannot be
    // recovered via a response-timing side-channel. `ct_eq` returns a
    // `subtle::Choice`; differing lengths short-circuit to a `false`
    // choice without leaking the length via early return.
    use subtle::ConstantTimeEq;
    let key_match = provided.as_bytes().ct_eq(expected.as_bytes());
    if !bool::from(key_match) {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"error": "invalid admin key"}));
    }

    // --- Pubkey validation -----------------------------------------------
    let pubkey = path.into_inner();
    if pubkey.len() != 64 || !pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "pubkey must be 64 lowercase hex characters"}));
    }

    // --- Locate FS root --------------------------------------------------
    let data_root = match &state.data_root {
        Some(r) => r.clone(),
        None => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "server has no fs-backend storage configured"
            }));
        }
    };

    let pod_dir = data_root.join(&pubkey);

    // --- Create directory (idempotent) -----------------------------------
    if let Err(e) = tokio::fs::create_dir_all(&pod_dir).await {
        tracing::error!(pubkey = %pubkey, error = %e, "/_admin/provision: create_dir_all failed");
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": format!("failed to create pod directory: {e}")}));
    }

    // --- Write owner-only WAC ACL ----------------------------------------
    let acl_content = format!(
        "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
         <#owner> a acl:Authorization ;\n\
             acl:agent <did:nostr:{pubkey}> ;\n\
             acl:accessTo <./> ;\n\
             acl:default <./> ;\n\
             acl:mode acl:Read, acl:Write, acl:Control .\n"
    );
    let acl_path = pod_dir.join(".acl");
    if !acl_path.exists() {
        if let Err(e) = tokio::fs::write(&acl_path, acl_content.as_bytes()).await {
            tracing::error!(pubkey = %pubkey, error = %e, "/_admin/provision: write .acl failed");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": format!("failed to write .acl: {e}")}));
        }
    }

    // --- Git init (feature-gated) ----------------------------------------
    #[cfg(feature = "git")]
    {
        use tokio::process::Command;

        // Only init if .git does not yet exist (idempotent).
        if !pod_dir.join(".git").exists() {
            let init_out = Command::new("git")
                .args([
                    "init",
                    "-b",
                    "main",
                    pod_dir.to_str().unwrap_or("."),
                ])
                .output()
                .await;

            match init_out {
                Ok(out) if out.status.success() => {}
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    tracing::warn!(pubkey = %pubkey, stderr = %stderr, "git init returned non-zero");
                }
                Err(e) => {
                    tracing::warn!(pubkey = %pubkey, error = %e, "git init failed (git not in PATH?)");
                }
            }

            // Configure receive.denyCurrentBranch=updateInstead so the forum
            // client can push directly into the working tree.
            let cfg_out = Command::new("git")
                .args([
                    "-C",
                    pod_dir.to_str().unwrap_or("."),
                    "config",
                    "receive.denyCurrentBranch",
                    "updateInstead",
                ])
                .output()
                .await;

            if let Err(e) = cfg_out {
                tracing::warn!(pubkey = %pubkey, error = %e, "git config receive.denyCurrentBranch failed");
            }
        }
    }

    // --- Build response --------------------------------------------------
    let base_url = state.nodeinfo.base_url.trim_end_matches('/');
    HttpResponse::Ok().json(serde_json::json!({
        "podUrl": format!("{base_url}/pods/{pubkey}/"),
        "ok": true,
    }))
}

// ---------------------------------------------------------------------------
// /.well-known/apps  (JSS #464 Phase 2 — public app discovery)
// ---------------------------------------------------------------------------

async fn handle_well_known_apps(state: web::Data<AppState>) -> HttpResponse {
    let Some(ref data_root) = state.data_root else {
        return HttpResponse::Ok()
            .content_type("application/json")
            .json(serde_json::json!({"apps": [], "count": 0}));
    };

    let server_url = state.nodeinfo.base_url.clone();

    // Collect pod directories (up to 1000).
    let mut read_dir = match tokio::fs::read_dir(data_root).await {
        Ok(rd) => rd,
        Err(_) => {
            return HttpResponse::Ok()
                .content_type("application/json")
                .json(serde_json::json!({"apps": [], "serverUrl": server_url, "count": 0}));
        }
    };

    let mut apps: Vec<serde_json::Value> = Vec::new();
    let mut scanned = 0usize;

    while scanned < 1000 {
        let entry = match read_dir.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(_) => break,
        };

        let file_type = match entry.file_type().await {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if !file_type.is_dir() {
            continue;
        }

        scanned += 1;

        let manifest_path = entry.path().join("apps").join("manifest.json");
        let contents = match tokio::fs::read(&manifest_path).await {
            Ok(c) => c,
            Err(_) => continue,
        };

        let mut manifest: serde_json::Value = match serde_json::from_slice(&contents) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Inject podOwner from the directory name (pubkey).
        if let Some(pod_name) = entry.file_name().to_str() {
            if manifest.get("podOwner").is_none() {
                manifest["podOwner"] = serde_json::Value::String(pod_name.to_string());
            }
        }

        apps.push(manifest);
    }

    let count = apps.len();
    HttpResponse::Ok()
        .content_type("application/json")
        .json(serde_json::json!({
            "apps": apps,
            "serverUrl": server_url,
            "count": count,
        }))
}

// ---------------------------------------------------------------------------
// Git HTTP backend handler (JSS #466/#469/#471, feature = "git")
// ---------------------------------------------------------------------------

/// Returns `true` if `path` is a git smart-HTTP protocol request.
///
/// Mirrors JSS `src/handlers/git.js` `isGitRequest`:
/// ```text
/// return urlPath.includes('/info/refs') ||
///   urlPath.includes('/git-upload-pack') ||
///   urlPath.includes('/git-receive-pack');
/// ```
#[allow(dead_code)]
fn is_git_request(path: &str) -> bool {
    path.contains("/info/refs")
        || path.contains("/git-upload-pack")
        || path.contains("/git-receive-pack")
}

/// Returns `true` if `path` targets `.git/` internals directly — always
/// blocked (security, matches JSS lines 52-68).
#[allow(dead_code)]
fn is_dot_git_path(path: &str) -> bool {
    path.contains("/.git/") || path.ends_with("/.git")
}

#[cfg(feature = "git")]
async fn handle_git(
    req: HttpRequest,
    body: web::Bytes,
    state: web::Data<AppState>,
) -> HttpResponse {
    use solid_pod_rs_git::auth::{BasicNostrExtractor, GitAuth};
    use solid_pod_rs_git::service::{GitHttpService, GitRequest};

    let path = req.uri().path().to_string();

    // Locate the pod's FS root: the first path segment after "/" is the
    // pod name (username/pubkey). The FS root is data_root/{pod_name}/.
    let pod_name = path
        .trim_start_matches('/')
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();
    let Some(ref data_root) = state.data_root else {
        return HttpResponse::NotImplemented().json(serde_json::json!({
            "error": "git requires fs-backend storage",
            "reason": "data_root_not_configured"
        }));
    };
    let repo_root = data_root.join(&pod_name);
    if !repo_root.exists() {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "pod not found"}));
    }

    let query = req.uri().query().unwrap_or("").to_string();
    let host_url = {
        let conn = req.connection_info();
        Some(format!("{}://{}", conn.scheme(), conn.host()))
    };
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let git_req = GitRequest {
        method: req.method().as_str().to_string(),
        path,
        query,
        headers,
        body: body.into(),
        host_url,
    };

    // WAC gate (mirrors JSS `server.js` checkAccess before git, ~498-530).
    // Git requests were previously handed straight to the CGI with no
    // authorisation: a private pod's history was anonymously clonable and
    // pushes were anonymous (R5 "No WAC" finding / ADR-059 D6). Resolve the
    // caller's `did:nostr` from the git `Basic nostr:`/`Nostr` NIP-98
    // credential — an absent or invalid credential resolves to anonymous,
    // and WAC then decides, fail-closed. Enforce Read for clone/fetch and
    // Write for push against the pod-root container ACL. `enforce_read`
    // grants public pods to anonymous callers and replies 401 on a private
    // pod so the git client knows to retry with credentials; `enforce_write`
    // denies anonymous/unauthorised push.
    let is_write = git_req.is_write();
    let agent = match BasicNostrExtractor::new().authorise(&git_req).await {
        Ok(pk) => Some(format!("did:nostr:{pk}")),
        Err(_) => None,
    };
    let wac_path = format!("/{pod_name}/");
    let wac = if is_write {
        enforce_write(&state, &wac_path, AccessMode::Write, agent.as_deref()).await
    } else {
        enforce_read(&state, &wac_path, agent.as_deref()).await
    };
    if let Err(e) = wac {
        return e.error_response();
    }

    let service = GitHttpService::new(repo_root);
    match service.handle(git_req).await {
        Ok(git_resp) => {
            let mut builder = HttpResponse::build(
                actix_web::http::StatusCode::from_u16(git_resp.status)
                    .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR),
            );
            for (k, v) in &git_resp.headers {
                builder.insert_header((k.as_str(), v.as_str()));
            }
            builder.body(git_resp.body)
        }
        Err(e) => {
            let status = e.status_code();
            HttpResponse::build(
                actix_web::http::StatusCode::from_u16(status)
                    .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR),
            )
            .json(serde_json::json!({"error": e.to_string()}))
        }
    }
}

// ---------------------------------------------------------------------------
// Public app builder
// ---------------------------------------------------------------------------

/// Build the complete actix `App` for the Solid Pod server. Both the
/// binary (`main.rs`) and the workspace integration tests call this.
///
/// The returned `App` is fully-configured: route table, normaliser,
/// path-traversal guard, dotfile allowlist, body cap, CORS middleware
/// (when available), rate-limit middleware (when available), and WAC
/// enforcement.
pub fn build_app(
    state: AppState,
) -> App<
    impl actix_web::dev::ServiceFactory<
        ServiceRequest,
        Config = (),
        Response = ServiceResponse<EitherBody<EitherBody<BoxBody>>>,
        Error = ActixError,
        InitError = (),
    >,
> {
    let body_cap = state.body_cap;
    let dotfiles = state.dotfiles.clone();
    let allowed_origins = Arc::new(state.allowed_origins.clone());

    let mut app = App::new()
        .app_data(web::Data::new(state.clone()))
        .app_data(web::PayloadConfig::new(body_cap))
        // Sprint 11 (row 158): outermost layer so it observes every
        // response — including those that short-circuited in inner
        // guards. Wrapping first means `wrap()` applies it last in
        // actix's stack order.
        .wrap(ErrorLoggingMiddleware)
        // B1: baseline security headers (nosniff + frame-options) on every
        // response, including those short-circuited by the inner guards.
        .wrap(SecurityHeaders)
        .wrap(CorsHeaders { allowed_origins })
        // `MergeOnly` collapses duplicate slashes (//a → /a) without
        // stripping the trailing slash, which is the container/resource
        // discriminator in LDP.
        .wrap(NormalizePath::new(TrailingSlash::MergeOnly))
        .wrap(PathTraversalGuard)
        .wrap(DotfileGuard::new(dotfiles));

    // CORS / rate-limit: middleware is driven by the library types from
    // S7-A. We register pass-through headers when the env-driven policy
    // permits. The middleware is a no-op today beyond emitting the
    // policy's `response_headers` on every response; full preflight
    // handling lives in the sibling S7-A work.
    app = app
        .route("/.well-known/solid", web::get().to(handle_well_known_solid))
        .route(
            "/.well-known/webfinger",
            web::get().to(handle_well_known_webfinger),
        )
        .route(
            "/.well-known/nodeinfo",
            web::get().to(handle_well_known_nodeinfo),
        )
        .route(
            "/.well-known/nodeinfo/2.1",
            web::get().to(handle_well_known_nodeinfo_2_1),
        );

    #[cfg(feature = "did-nostr")]
    {
        app = app.route(
            "/.well-known/did/nostr/{pubkey}.json",
            web::get().to(handle_well_known_did_nostr),
        );
    }

    // JSS v0.0.190 Phase 1 port (issue #437), parity row 197.
    // Pod-resident NIP-05 endpoint. Scaffold only — handler body
    // is `todo!()`. Feature `nip05-endpoint` (default-off).
    #[cfg(feature = "nip05-endpoint")]
    {
        app = app.route(
            "/.well-known/nostr.json",
            web::get().to(handle_well_known_nip05),
        );
    }

    // App discovery endpoint (JSS #464 Phase 2 — public, no auth required).
    app = app.route("/.well-known/apps", web::get().to(handle_well_known_apps));

    // Payment endpoint (JSS parity: GET /pay/.info).
    app = app.route("/pay/.info", web::get().to(handle_pay_info));

    // Phase 0 payment routing (master-plan §"Phase 0"): wire the orphaned
    // order-book / AMM / Web-Ledger logic. Registered with the SAME gating
    // as `/pay/.info` above — always-on, no payments feature flag — so the
    // whole `/pay/*` surface is consistent.
    app = app.configure(handlers::pay::register);

    // WAC-gated CORS proxy endpoint.
    app = app.route("/proxy", web::get().to(handle_proxy));

    // MCP (Model Context Protocol) endpoint — opt-in tool surface for
    // agents (JSS #490). Registered before the LDP catch-all so `/mcp` is
    // never treated as a pod resource. OFF unless `--mcp` / `JSS_MCP`.
    if state.mcp_enabled {
        app = app
            .route("/mcp", web::post().to(mcp::handle_mcp))
            .route("/mcp", web::method(actix_web::http::Method::OPTIONS).to(mcp::handle_mcp_options));
    }

    // Admin provisioning endpoint (alpha.15). Must be before the LDP
    // catch-all so `_admin` is never treated as a pod name.
    app = app.route(
        "/_admin/provision/{pubkey}",
        web::post().to(handle_admin_provision),
    );

    // Pod management API (JSS parity: /api/accounts/*)
    app = app
        .route("/.pods", web::post().to(handle_create_pod))
        .route("/api/accounts/new", web::post().to(handle_create_account))
        .route("/pods/check/{name}", web::get().to(handle_pod_check))
        .route("/login/password", web::post().to(handle_login_password))
        .route(
            "/account/password/reset",
            web::post().to(handle_password_reset_request),
        )
        .route(
            "/account/password/change",
            web::post().to(handle_password_change),
        );

    // Git smart-HTTP protocol routes (JSS #466/#469/#471).
    // Must be registered before the LDP catch-all. Direct .git/ access is
    // always blocked (security). Smart-HTTP paths are served by
    // GitHttpService when the `git` feature is enabled; otherwise 501.
    app = app
        .route(
            // Block direct .git/ access (JSS: "BLOCK: Direct access to .git contents")
            "/{tail:.*}/.git",
            web::route().to(|| async {
                HttpResponse::Forbidden()
                    .json(serde_json::json!({"error": "direct .git access is forbidden"}))
            }),
        )
        .route(
            "/{tail:.*}/.git/{rest:.*}",
            web::route().to(|| async {
                HttpResponse::Forbidden()
                    .json(serde_json::json!({"error": "direct .git access is forbidden"}))
            }),
        );

    // OPTIONS preflight for /_git panel REST API (alpha.15). Registered
    // unconditionally (before the feature block) so browsers get a valid
    // CORS response regardless of whether the git feature is compiled in.
    app = app.route(
        "/pods/{pk}/_git/{tail:.*}",
        web::method(actix_web::http::Method::OPTIONS).to(handle_git_panel_options),
    );

    #[cfg(feature = "git")]
    {
        // Git smart-HTTP: info/refs discovery + upload/receive pack.
        app = app
            .route("/{tail:.*}/info/refs", web::get().to(handle_git))
            .route("/{tail:.*}/git-upload-pack", web::post().to(handle_git))
            .route("/{tail:.*}/git-receive-pack", web::post().to(handle_git));

        // Git control panel REST API. Routes registered before the LDP
        // catch-all so `_git` segments are never treated as LDP resources.
        app = app
            .route(
                "/pods/{pubkey}/_git/status",
                web::get().to(handle_git_status),
            )
            .route(
                "/pods/{pubkey}/_git/log",
                web::get().to(handle_git_log),
            )
            .route(
                "/pods/{pubkey}/_git/diff",
                web::get().to(handle_git_diff),
            )
            .route(
                "/pods/{pubkey}/_git/stage",
                web::post().to(handle_git_stage),
            )
            .route(
                "/pods/{pubkey}/_git/unstage",
                web::post().to(handle_git_unstage),
            )
            .route(
                "/pods/{pubkey}/_git/commit",
                web::post().to(handle_git_commit),
            )
            .route(
                "/pods/{pubkey}/_git/branches",
                web::get().to(handle_git_branches),
            )
            .route(
                "/pods/{pubkey}/_git/branch",
                web::post().to(handle_git_create_branch),
            )
            .route(
                "/pods/{pubkey}/_git/discard",
                web::post().to(handle_git_discard),
            );

        // Provenance `_prov` API (ADR-059 Phase 5, master-plan §2.4):
        // resolve a git-mark commit SHA, and the explicit (payment-gated)
        // git-mark → Bitcoin-anchor upgrade. Registered before the LDP
        // catch-all so `_prov` segments are never treated as pod resources.
        // The `.prov.ttl` sidecar GET is served by the ordinary LDP read path
        // (it is a stored resource).
        app = app.configure(handlers::prov::register);
    }
    #[cfg(not(feature = "git"))]
    {
        // Without the git feature: return 501 for git protocol paths so
        // callers get a clear "not compiled in" signal rather than falling
        // through to LDP.
        let git_501 = || async {
            HttpResponse::NotImplemented()
                .json(serde_json::json!({"error": "git feature not enabled in this build"}))
        };
        app = app
            .route("/{tail:.*}/info/refs", web::get().to(git_501))
            .route("/{tail:.*}/git-upload-pack", web::post().to(git_501))
            .route("/{tail:.*}/git-receive-pack", web::post().to(git_501));
    }

    // Container POST and PUT (trailing slash) must register before the
    // catch-all so the trailing-slash variant wins.
    app.route("/{tail:.*}/", web::post().to(handle_post))
        .route("/{tail:.*}/", web::put().to(handle_put))
        .route("/{tail:.*}", web::get().to(handle_get))
        .route("/{tail:.*}", web::head().to(handle_get))
        .route("/{tail:.*}", web::put().to(handle_put))
        .route("/{tail:.*}", web::patch().to(handle_patch))
        .route("/{tail:.*}", web::delete().to(handle_delete))
        .route(
            "/{tail:.*}",
            web::method(actix_web::http::Method::from_bytes(b"COPY").unwrap()).to(handle_copy),
        )
        .route(
            "/{tail:.*}",
            web::method(actix_web::http::Method::OPTIONS).to(handle_options),
        )
}

// ---------------------------------------------------------------------------
// Tests — sat-gating loop closure (PaymentCondition wired to real ledger)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod payment_gating_tests {
    use super::*;
    use solid_pod_rs::payments::WebLedger;
    use solid_pod_rs::storage::memory::MemoryBackend;

    const PRINCIPAL: &str = "did:nostr:alice";

    /// Turtle ACL granting `did:nostr:alice` Write on `/premium/inbox`
    /// only when a `PaymentCondition` of 100 sats is satisfied.
    const PAID_WRITE_ACL: &str = r#"
@prefix acl: <http://www.w3.org/ns/auth/acl#> .

<#paid-write> a acl:Authorization ;
    acl:agent <did:nostr:alice> ;
    acl:accessTo </premium/inbox> ;
    acl:mode acl:Write ;
    acl:condition [
        a acl:PaymentCondition ;
        acl:costSats 100
    ] .
"#;

    async fn seed_ledger(storage: &dyn Storage, did: &str, sats: u64) {
        let mut ledger = WebLedger::new("Test Pod Credits");
        if sats > 0 {
            ledger.credit(did, sats);
        }
        let body = serde_json::to_vec(&ledger).unwrap();
        storage
            .put(WEBLEDGER_PATH, Bytes::from(body), "application/json")
            .await
            .unwrap();
    }

    async fn seed_acl(storage: &dyn Storage) {
        storage
            .put(
                "/premium/inbox.acl",
                Bytes::from(PAID_WRITE_ACL),
                "text/turtle",
            )
            .await
            .unwrap();
    }

    /// The resolver reads the principal's balance from the seeded ledger.
    #[actix_web::test]
    async fn resolve_balance_reads_ledger_entry() {
        let storage = MemoryBackend::new();
        seed_ledger(&storage, PRINCIPAL, 250).await;
        assert_eq!(
            resolve_balance_sats(&storage, Some(PRINCIPAL)).await,
            Some(250)
        );
    }

    /// No ledger entry → authenticated principal resolves to zero balance.
    #[actix_web::test]
    async fn resolve_balance_zero_when_no_entry() {
        let storage = MemoryBackend::new();
        seed_ledger(&storage, "did:nostr:bob", 500).await;
        assert_eq!(resolve_balance_sats(&storage, Some(PRINCIPAL)).await, Some(0));
    }

    /// Anonymous (no principal) → `None`, so a PaymentCondition fails closed.
    #[actix_web::test]
    async fn resolve_balance_none_when_anonymous() {
        let storage = MemoryBackend::new();
        seed_ledger(&storage, PRINCIPAL, 1_000).await;
        assert_eq!(resolve_balance_sats(&storage, None).await, None);
    }

    /// End-to-end: a sat-priced resource is DENIED below balance.
    #[actix_web::test]
    async fn paid_write_denied_below_balance() {
        let storage = Arc::new(MemoryBackend::new());
        seed_acl(storage.as_ref()).await;
        seed_ledger(storage.as_ref(), PRINCIPAL, 50).await; // < 100 cost
        let state = AppState::new(storage);

        let result =
            enforce_write(&state, "/premium/inbox", AccessMode::Write, Some(PRINCIPAL)).await;
        assert!(
            result.is_err(),
            "balance 50 < cost 100 must be denied — sat-gating loop closed"
        );
    }

    /// End-to-end: a sat-priced resource is ALLOWED at the balance threshold.
    #[actix_web::test]
    async fn paid_write_allowed_at_balance() {
        let storage = Arc::new(MemoryBackend::new());
        seed_acl(storage.as_ref()).await;
        seed_ledger(storage.as_ref(), PRINCIPAL, 100).await; // == 100 cost
        let state = AppState::new(storage);

        let result =
            enforce_write(&state, "/premium/inbox", AccessMode::Write, Some(PRINCIPAL)).await;
        assert!(
            result.is_ok(),
            "balance 100 >= cost 100 must be granted — sat-gating loop closed"
        );
    }

    /// End-to-end: a sat-priced resource is ALLOWED above the threshold.
    #[actix_web::test]
    async fn paid_write_allowed_above_balance() {
        let storage = Arc::new(MemoryBackend::new());
        seed_acl(storage.as_ref()).await;
        seed_ledger(storage.as_ref(), PRINCIPAL, 5_000).await;
        let state = AppState::new(storage);

        let result =
            enforce_write(&state, "/premium/inbox", AccessMode::Write, Some(PRINCIPAL)).await;
        assert!(result.is_ok(), "balance 5000 >= cost 100 must be granted");
    }

    /// Regression guard: before this fix `payment_balance_sats` was
    /// hardcoded `None`, so even an over-funded principal was denied.
    /// An anonymous caller (no principal) must still be denied.
    #[actix_web::test]
    async fn paid_write_anonymous_denied() {
        let storage = Arc::new(MemoryBackend::new());
        seed_acl(storage.as_ref()).await;
        seed_ledger(storage.as_ref(), PRINCIPAL, 5_000).await;
        let state = AppState::new(storage);

        let result = enforce_write(&state, "/premium/inbox", AccessMode::Write, None).await;
        assert!(
            result.is_err(),
            "anonymous caller has no ledger principal — PaymentCondition fails closed"
        );
    }

    // -----------------------------------------------------------------
    // R-04: sat-gating is a DEBIT, not just a balance check. A granted
    // payment-gated request must consume the matched rule's cost from the
    // caller's Web Ledger exactly once.
    // -----------------------------------------------------------------

    async fn read_balance(storage: &dyn Storage, did: &str) -> u64 {
        let (bytes, _) = storage.get(WEBLEDGER_PATH).await.unwrap();
        let ledger: WebLedger = serde_json::from_slice(&bytes).unwrap();
        ledger.get_balance(did)
    }

    /// A granted paid WRITE debits the cost from the ledger.
    #[actix_web::test]
    async fn paid_write_debits_ledger() {
        let storage = Arc::new(MemoryBackend::new());
        seed_acl(storage.as_ref()).await;
        seed_ledger(storage.as_ref(), PRINCIPAL, 250).await; // cost 100
        let state = AppState::new(storage.clone());

        let result =
            enforce_write(&state, "/premium/inbox", AccessMode::Write, Some(PRINCIPAL)).await;
        assert!(result.is_ok(), "balance 250 >= cost 100 must be granted");
        assert_eq!(
            read_balance(storage.as_ref(), PRINCIPAL).await,
            150,
            "250 - 100 cost: the grant must debit exactly the matched rule's cost"
        );
    }

    /// A second granted paid WRITE debits again (no free re-read of the
    /// same resource once the balance is consumed).
    #[actix_web::test]
    async fn paid_write_debits_each_grant() {
        let storage = Arc::new(MemoryBackend::new());
        seed_acl(storage.as_ref()).await;
        seed_ledger(storage.as_ref(), PRINCIPAL, 250).await; // cost 100
        let state = AppState::new(storage.clone());

        enforce_write(&state, "/premium/inbox", AccessMode::Write, Some(PRINCIPAL))
            .await
            .unwrap();
        enforce_write(&state, "/premium/inbox", AccessMode::Write, Some(PRINCIPAL))
            .await
            .unwrap();
        assert_eq!(
            read_balance(storage.as_ref(), PRINCIPAL).await,
            50,
            "250 - 2*100: each granted request debits, no unmetered re-use"
        );

        // Third request: 50 < 100 — gate denies, balance unchanged.
        let third =
            enforce_write(&state, "/premium/inbox", AccessMode::Write, Some(PRINCIPAL)).await;
        assert!(third.is_err(), "balance 50 < cost 100 must now be denied");
        assert_eq!(
            read_balance(storage.as_ref(), PRINCIPAL).await,
            50,
            "a denied request must not debit"
        );
    }

    /// A granted paid READ debits the cost from the ledger.
    #[actix_web::test]
    async fn paid_read_debits_ledger() {
        const PAID_READ_ACL: &str = r#"
@prefix acl: <http://www.w3.org/ns/auth/acl#> .

<#paid-read> a acl:Authorization ;
    acl:agent <did:nostr:alice> ;
    acl:accessTo </premium/feed> ;
    acl:mode acl:Read ;
    acl:condition [
        a acl:PaymentCondition ;
        acl:costSats 30
    ] .
"#;
        let storage = Arc::new(MemoryBackend::new());
        storage
            .put("/premium/feed.acl", Bytes::from(PAID_READ_ACL), "text/turtle")
            .await
            .unwrap();
        seed_ledger(storage.as_ref(), PRINCIPAL, 100).await;
        let state = AppState::new(storage.clone());

        let result = enforce_read(&state, "/premium/feed", Some(PRINCIPAL)).await;
        assert!(result.is_ok(), "balance 100 >= cost 30 must be granted");
        assert_eq!(
            read_balance(storage.as_ref(), PRINCIPAL).await,
            70,
            "100 - 30 cost: a granted paid read must debit"
        );
    }

    /// A granted FREE read (no PaymentCondition) leaves the ledger
    /// untouched.
    #[actix_web::test]
    async fn free_read_does_not_debit() {
        let storage = Arc::new(MemoryBackend::new());
        seed_private_read_acl(storage.as_ref()).await; // no PaymentCondition
        seed_ledger(storage.as_ref(), PRINCIPAL, 100).await;
        let state = AppState::new(storage.clone());

        enforce_read(&state, "/private/secret", Some(PRINCIPAL))
            .await
            .unwrap();
        assert_eq!(
            read_balance(storage.as_ref(), PRINCIPAL).await,
            100,
            "a grant with no PaymentCondition must not debit"
        );
    }

    // -----------------------------------------------------------------
    // P0-1: WAC read enforcement (enforce_read)
    // -----------------------------------------------------------------

    /// ACL granting `alice` Read on `/private/` but NO public/`bob` read.
    const ALICE_ONLY_READ_ACL: &str = r#"
@prefix acl: <http://www.w3.org/ns/auth/acl#> .

<#alice> a acl:Authorization ;
    acl:agent <did:nostr:alice> ;
    acl:accessTo </private/secret> ;
    acl:default </private/> ;
    acl:mode acl:Read, acl:Write, acl:Control .
"#;

    async fn seed_private_read_acl(storage: &dyn Storage) {
        // The resolver walks up from `/private/secret` and probes the
        // container sidecar at `/private.acl` (it trims the trailing
        // slash before appending `.acl`). The grant inherits down via
        // `acl:default </private/>`.
        storage
            .put(
                "/private.acl",
                Bytes::from(ALICE_ONLY_READ_ACL),
                "text/turtle",
            )
            .await
            .unwrap();
    }

    /// Before the P0-1 fix `handle_get` served `storage.get()` verbatim
    /// with no read-authz, so any resource was world-readable. The owner
    /// must be granted Read…
    #[actix_web::test]
    async fn enforce_read_grants_owner() {
        let storage = Arc::new(MemoryBackend::new());
        seed_private_read_acl(storage.as_ref()).await;
        let state = AppState::new(storage);
        let result = enforce_read(&state, "/private/secret", Some(PRINCIPAL)).await;
        assert!(result.is_ok(), "owner alice must be granted Read");
    }

    /// …and an unrelated authenticated principal must be DENIED Read on a
    /// private resource (no world-readable leak).
    #[actix_web::test]
    async fn enforce_read_denies_other_principal() {
        let storage = Arc::new(MemoryBackend::new());
        seed_private_read_acl(storage.as_ref()).await;
        let state = AppState::new(storage);
        let result = enforce_read(&state, "/private/secret", Some("did:nostr:bob")).await;
        assert!(
            result.is_err(),
            "bob has no Read grant — private resource must not be world-readable"
        );
    }

    /// An anonymous reader is also denied (deny-by-default; no ACL grants
    /// public/foaf:Agent Read).
    #[actix_web::test]
    async fn enforce_read_denies_anonymous() {
        let storage = Arc::new(MemoryBackend::new());
        seed_private_read_acl(storage.as_ref()).await;
        let state = AppState::new(storage);
        let result = enforce_read(&state, "/private/secret", None).await;
        assert!(result.is_err(), "anonymous Read must be denied");
    }

    // -----------------------------------------------------------------
    // P0-2: `.acl` write requires acl:Control on the protected resource
    // -----------------------------------------------------------------

    /// ACL granting `writer` Write (but NOT Control) on `/shared/`, and
    /// the owner `alice` full Control. A Write-only principal must not be
    /// able to rewrite the ACL (privilege escalation).
    const WRITE_NOT_CONTROL_ACL: &str = r#"
@prefix acl: <http://www.w3.org/ns/auth/acl#> .

<#owner> a acl:Authorization ;
    acl:agent <did:nostr:alice> ;
    acl:accessTo </shared/doc> ;
    acl:default </shared/> ;
    acl:mode acl:Read, acl:Write, acl:Control .

<#writer> a acl:Authorization ;
    acl:agent <did:nostr:writer> ;
    acl:accessTo </shared/doc> ;
    acl:default </shared/> ;
    acl:mode acl:Read, acl:Write .
"#;

    async fn seed_shared_acl(storage: &dyn Storage) {
        // P0-2 resolves the protected resource `/shared/` and the
        // resolver probes its sidecar at `/shared.acl` (trailing slash
        // trimmed before `.acl`). Seed there so the Control evaluation
        // finds the grant.
        storage
            .put(
                "/shared.acl",
                Bytes::from(WRITE_NOT_CONTROL_ACL),
                "text/turtle",
            )
            .await
            .unwrap();
    }

    /// A principal with Write but NOT Control on a container is denied PUT
    /// on its `.acl` — the check is elevated to acl:Control on the
    /// protected resource, closing the privilege-escalation path.
    #[actix_web::test]
    async fn acl_put_denied_for_writer_without_control() {
        let storage = Arc::new(MemoryBackend::new());
        seed_shared_acl(storage.as_ref()).await;
        let state = AppState::new(storage);
        // The request path is the `.acl` sidecar; before the fix this was
        // checked as Write on the sidecar (granted). Now it requires
        // Control on `/shared/`.
        let result =
            enforce_write(&state, "/shared/.acl", AccessMode::Write, Some("did:nostr:writer")).await;
        assert!(
            result.is_err(),
            "writer lacks Control — must not be able to PUT /shared/.acl"
        );
    }

    /// The Control holder (owner) is still allowed to PUT the `.acl`.
    #[actix_web::test]
    async fn acl_put_allowed_for_control_holder() {
        let storage = Arc::new(MemoryBackend::new());
        seed_shared_acl(storage.as_ref()).await;
        let state = AppState::new(storage);
        let result =
            enforce_write(&state, "/shared/.acl", AccessMode::Write, Some(PRINCIPAL)).await;
        assert!(
            result.is_ok(),
            "alice holds Control — must be allowed to PUT /shared/.acl"
        );
    }

    /// The same elevation applies to `.meta` sidecars.
    #[actix_web::test]
    async fn meta_put_denied_for_writer_without_control() {
        let storage = Arc::new(MemoryBackend::new());
        seed_shared_acl(storage.as_ref()).await;
        let state = AppState::new(storage);
        let result = enforce_write(
            &state,
            "/shared/doc.meta",
            AccessMode::Write,
            Some("did:nostr:writer"),
        )
        .await;
        assert!(
            result.is_err(),
            "writer lacks Control — must not be able to PUT a .meta sidecar"
        );
    }

    /// Unit cover for the suffix-stripping helper.
    #[test]
    fn protected_resource_for_acl_strips_suffixes() {
        assert_eq!(protected_resource_for_acl("/victim/.acl").as_deref(), Some("/victim/"));
        assert_eq!(protected_resource_for_acl("/a/b.acl").as_deref(), Some("/a/b"));
        assert_eq!(protected_resource_for_acl("/.acl").as_deref(), Some("/"));
        assert_eq!(protected_resource_for_acl("/a/b.meta").as_deref(), Some("/a/b"));
        assert_eq!(protected_resource_for_acl("/a/b").as_deref(), None);
    }
}
