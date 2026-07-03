//! Framework-agnostic Rust library for serving Solid Protocol 0.11 pods.
//!
//! `solid-pod-rs` provides LDP resource and container semantics, Web Access
//! Control (WAC 1.x + 2.0), WebID profile documents, Solid-OIDC 0.1,
//! NIP-98 HTTP auth, and Solid Notifications 0.2 -- all without coupling
//! to a specific HTTP framework. Wire it into actix-web, axum, hyper, or
//! anything else; the crate never mounts routes itself. On top of the Solid
//! core it adds two composable **provenance primitives** ([`provenance`]):
//! cheap, always-on **git-marks** (every pod write captured as a git commit
//! + a PROV-O sidecar) and expensive, opt-in **block-trails** (a
//! Bitcoin-taproot-anchored, hash-chained state trail — [`mrc20`] /
//! [`bitcoin_tx`]) — and a routed, sovereign HTTP-402 economy: a `did:nostr`-keyed
//! [Web Ledger](payments), `acl:PaymentCondition` ([`wac`]) access gating, an MRC20
//! deposit path, and a peer order book + constant-product AMM ([`trading`]).
//! The HTTP routing for the 402 economy and the `_prov` provenance API lives in
//! the sibling [`solid-pod-rs-server`](https://docs.rs/solid-pod-rs-server). See
//! [ADR-059](https://docs.rs/crate/solid-pod-rs/latest/source/docs/adr/ADR-059-provenance-primitives-block-trails-git-marks.md).
//!
//! For a turnkey binary, use the sibling crate
//! [`solid-pod-rs-server`](https://docs.rs/solid-pod-rs-server).
//!
//! ## Feature flags
//!
//! | Flag | Default | Purpose |
//! |-------------------------|:-------:|-----------------------------------------------|
//! | `core` | off | Pure-logic surfaces only — wasm32 / CF Workers. |
//! | `std` | on | std lib (always; reserved for future no_std).  |
//! | `embedded-docs` | off | Embed the Diataxis `docs/` tree as `pub static DOCS_DIR` (re-exports `include_dir`); consumed by `solid-pod-rs-server`'s MCP docs tools + docs.rs. |
//! | `tokio-runtime` | on | Tokio + tokio-tungstenite + futures-util.       |
//! | `notifications` | on | WebSocketChannel2023 + WebhookChannel2023.      |
//! | `fs-backend` | on | POSIX filesystem storage. |
//! | `memory-backend` | on | In-process `HashMap` storage (tests/demos). |
//! | `s3-backend` | off | AWS S3 / S3-compatible object stores. |
//! | `oidc` | off | Solid-OIDC 0.1 + DPoP. |
//! | `dpop-replay-cache` | off | DPoP `jti` replay cache (pulls `oidc`). |
//! | `nip98-schnorr` | off | BIP-340 signature verification for NIP-98. |
//! | `jss-v04` | off | JSS-parity umbrella (ADR-056); no-op alone — sub-features below switch one bounded context each on. |
//! | `acl-origin` | off | WAC `acl:origin` enforcement (pulls `jss-v04`). |
//! | `security-primitives` | off | SSRF guard + dotfile allowlist (pulls `jss-v04`). |
//! | `legacy-notifications` | off | `solid-0.1` WebSocket adapter (SolidOS). |
//! | `config-loader` | off | Layered config loader with `JSS_*` env vars + YAML/TOML. |
//! | `webhook-signing` | off | RFC 9421 Ed25519 webhook signing. |
//! | `rate-limit` | off | Sliding-window LRU rate limiter + CORS. |
//! | `quota` | off | Per-pod `.quota.json` sidecar (atomic writes). |
//! | `did-nostr-types` | off | Canonical did:nostr types (wasm32-safe). |
//! | `did-nostr` | off | did:nostr DID-Doc ↔ WebID resolver in [`interop`]. |
//! | `mrc20` | off | BIP-341 taproot key chaining + anchor verify/build for MRC20 / block-trails. |
//! | `lws-cid` | off | LWS 1.0 CID self-signed JWT verifier (ES256K). |
//! | `lws-cid-p256` | off | LWS-CID + ES256 (P-256) algorithm. |
//! | `lws-cid-eddsa` | off | LWS-CID + EdDSA (Ed25519) algorithm. |
//! | `lws-cid-full` | off | LWS-CID with all algorithms. |
//! | `provision-keys` | off | Gates the optional `ProvisionPlan::provision_keys` field (IdP key provisioner extension point). |
//! | `nip05-endpoint` | off | Pod-resident `GET /.well-known/nostr.json` (pulls `did-nostr`). |
//! | `export-jsonld` | off | JSON-LD time-chain pod export (`GET /api/exports/all`). |
//! | `git-auto-init` | off | `GitInitHook` trait + `provision_pod_ext` (on-demand `git init` on first push; impl in `solid-pod-rs-git`). |
//!
//! On `wasm32-unknown-unknown` targets the `getrandom` crate is pulled in with
//! its `js` feature (transitively required by `uuid`/`rand`) so randomness
//! resolves via `crypto.getRandomValues()`; this is a target-gated dependency,
//! not a cargo feature you enable.
//!
//! `core` consumers wire the crate via `default-features = false,
//! features = ["core"]` and get only the pure-logic surfaces (no
//! tokio, no reqwest, no DNS resolver, no filesystem). See
//! `RELEASE_NOTES.md` v0.4.0-alpha.3 for the absorbed surfaces map.
//!
//! ## Module overview
//!
//! | Module | Responsibility |
//! |-----------------|--------------------------------------------------------------|
//! | [`storage`] | `Storage` trait + FS / Memory / S3 backends. |
//! | [`ldp`] | Resources, containers, content negotiation, PATCH, `Prefer`. |
//! | [`wac`] | Access control evaluator + WAC 2.0 conditions framework. |
//! | [`webid`] | WebID profile documents (emits `solid:oidcIssuer` + CID). |
//! | [`mashlib`] | SolidOS data-browser HTML wrapper + data-island embed.    |
//! | [`auth`] | NIP-98 HTTP auth + LWS-CID self-signed JWT verifier. |
//! | [`payments`] | HTTP 402, Web Ledgers, multi-chain TXO, payment store. |
//! | [`mrc20`] | MRC20 state chains, JCS, BIP-341 key chaining.       |
//! | [`provenance`] | git-mark / block-trail provenance primitives + PROV-O.  |
//! | [`trading`] | Peer-to-peer order book + AMM constant-product pool.  |
//! | [`notifications`] | WebSocket, Webhook (RFC 9421 signed), legacy adapter. |
//! | [`error`] | Crate-wide [`PodError`] error type. |
//! | [`config`] | Layered configuration schema. |
//! | [`security`] | SSRF guard, dotfile allowlist, CORS, rate limiter. |
//! | [`quota`] | Per-pod byte-quota enforcement. |
//! | [`multitenant`] | `PodResolver` trait; path + subdomain modes. |
//! | [`interop`] | `.well-known/solid`, WebFinger, NodeInfo, did:nostr. |
//! | [`did_nostr_types`] | Canonical `did:nostr` types (wasm32-safe, `core`). |
//! | [`provision`] | Pod bootstrap (WebID + containers + type indexes + ACL). |
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use solid_pod_rs::storage::memory::MemoryBackend;
//! use solid_pod_rs::{Storage, evaluate_access, AccessMode};
//! use bytes::Bytes;
//! use std::sync::Arc;
//!
//! # tokio::runtime::Runtime::new().unwrap().block_on(async {
//! // 1. Create a storage backend.
//! let store = Arc::new(MemoryBackend::new());
//!
//! // 2. PUT a resource.
//! store.put("/hello.txt", Bytes::from("world"), "text/plain").await.unwrap();
//!
//! // 3. GET it back.
//! let (body, meta) = store.get("/hello.txt").await.unwrap();
//! assert_eq!(&body[..], b"world");
//! assert_eq!(meta.content_type, "text/plain");
//!
//! // 4. WAC evaluation (no ACL document = deny by default).
//! let allowed = evaluate_access(None, Some("https://alice.example/profile/card#me"),
//!     "/hello.txt", AccessMode::Read, None);
//! assert!(!allowed);
//! # });
//! ```
//!
//! ## Attribution
//!
//! Rust port of JavaScriptSolidServer. See NOTICE for provenance.

#![doc = include_str!("../README.md")]
#![deny(unsafe_code)]
#![warn(rust_2018_idioms)]

// ---------------------------------------------------------------------------
// Always-compiled (`core`) modules.
//
// Pure-logic surfaces: parsers, validators, type definitions. None of
// these reach for tokio, reqwest, or notify directly. Wasm32 / CF
// Workers consumers wire these via
// `default-features = false, features = ["core"]`.
// ---------------------------------------------------------------------------
pub mod auth;
/// Bitcoin taproot transaction building (block-trail write-side). The module's
/// own inner `#![cfg(all(feature = "mrc20", not(target_arch = "wasm32")))]`
/// gates it: it compiles to nothing on wasm or without the `mrc20` feature, so
/// the tx-building never leaks into the wasm `core` surface (ADR-059 D4).
pub mod bitcoin_tx;
pub mod config;
pub mod error;
pub mod interop;
pub mod ldp;
pub mod mashlib;
pub mod metrics;
pub mod mrc20;
pub mod multitenant;
pub mod payments;
pub mod provenance;
pub mod security;
pub mod trading;
pub mod wac;
pub mod webid;

// ---------------------------------------------------------------------------
// `did-nostr-types`-gated module.
//
// Canonical did:nostr types (NostrPubkey, DID-Doc renderers, ServiceEntry)
// behind a lightweight feature flag. No runtime deps — wasm32 / CF Workers
// consumers get these via `core`.
// ---------------------------------------------------------------------------
#[cfg(feature = "did-nostr-types")]
pub mod did_nostr_types;

// ---------------------------------------------------------------------------
// `tokio-runtime`-gated modules.
//
// These pull tokio (mpsc, fs, broadcast) or reqwest (HTTP client) and
// are unavailable to `core` consumers. They are wired in by the
// `default` feature set so the existing surface from 0.4.0-alpha.2 is
// preserved bit-for-bit on native builds.
// ---------------------------------------------------------------------------
#[cfg(feature = "notifications")]
pub mod notifications;
#[cfg(feature = "tokio-runtime")]
pub mod provision;
#[cfg(feature = "tokio-runtime")]
pub mod quota;
#[cfg(feature = "tokio-runtime")]
pub mod storage;

#[cfg(feature = "oidc")]
pub mod oidc;

// ---------------------------------------------------------------------------
// JSS v0.0.190 Phase 1 port (issue #437) — pod data export.
//
// Parity row 198. Default-off (`export-jsonld`). `export_pod_jsonld` is
// fully implemented and tested (bodies landed in 0.4.0-alpha.11; no
// `todo!()`); the library surface is stable for downstream consumers
// (NRF, dreamlab-ai-website). The `export-jsonld` feature pulls
// `tokio-runtime` and is therefore native-only — the wasm32 CF-Workers
// pod build cannot compile or serve it. Only native `solid-pod-rs-server`
// deployments can expose the export; there is no server route registered
// yet, so consumers call `export_pod_jsonld` directly.
// ---------------------------------------------------------------------------
#[cfg(feature = "export-jsonld")]
pub mod export;

/// Transport-agnostic HTTP / WebSocket handler drivers. Consumers wire
/// these into their HTTP framework of choice. Feature-gated; present
/// only when at least one handler is enabled. Respects the F7
/// library-server boundary — this crate never mounts routes itself.
#[cfg(feature = "legacy-notifications")]
pub mod handlers;

// ---------------------------------------------------------------------------
// `core` re-exports — always available.
// ---------------------------------------------------------------------------
pub use auth::nip98::Nip98Verifier;
pub use auth::self_signed::{
    CidVerifier, ProofEnvelope, SelfSignedError, SelfSignedVerifier, VerifiedSubject,
};
pub use error::PodError;
pub use interop::{
    dev_session, nip05_document, verify_nip05, webfinger_response, well_known_solid, DevSession,
    Nip05Document, SolidWellKnown, WebFingerJrd, WebFingerLink,
};
pub use ldp::{
    apply_json_patch, apply_n3_patch, apply_patch_to_absent, apply_sparql_patch, cache_control_for,
    evaluate_preconditions, is_rdf_content_type, link_headers, negotiate_format, not_found_headers,
    options_for, parse_range_header, parse_range_header_v2, patch_dialect_from_mime,
    server_managed_triples, slice_range, vary_header, ByteRange, ConditionalOutcome,
    ContainerRepresentation, Graph, OptionsResponse, PatchCreateOutcome, PatchDialect,
    PatchOutcome, PreferHeader, RangeOutcome, RdfFormat, Term, Triple, ACCEPT_PATCH, ACCEPT_POST,
    CACHE_CONTROL_RDF, SPARQL_UPDATE_MAX_BYTES,
};
pub use mashlib::{MashlibConfig, MashlibMode, DATA_ISLAND_MAX_BYTES};
pub use metrics::SecurityMetrics;
pub use multitenant::{PathResolver, PodResolver, ResolvedPath, SubdomainResolver};
pub use provenance::{
    prov_ttl, AnchorPolicy, BlockAnchorer, BlockTrailAnchor, BlocktrailEnvelope, BlocktrailTxo,
    ClosedEpoch, EpochAccumulator, GitMark, GitMarkEnvelope, GitMarker, MerkleProof,
    ProvenanceError, ProvenanceLog, ProvenanceMark, WriteRecord,
};
pub use security::{is_path_allowed, DotfileAllowlist, DotfileError, DotfilePathError};
pub use wac::{
    check_origin, evaluate_access, evaluate_access_with_groups, extract_origin_patterns,
    method_to_mode, mode_name, parse_turtle_acl, serialize_turtle_acl, wac_allow_header,
    AccessMode, AclDocument, GroupMembership, Origin, OriginDecision, OriginPattern,
    StaticGroupMembership,
};
pub use webid::{
    extract_nostr_pubkey, extract_oidc_issuer, generate_webid_html,
    generate_webid_html_with_issuer, validate_webid_html,
};

// ---------------------------------------------------------------------------
// `tokio-runtime`-gated re-exports.
// ---------------------------------------------------------------------------
#[cfg(feature = "tokio-runtime")]
pub use provision::{
    check_admin_override, provision_pod, AdminOverride, ProvisionOutcome, ProvisionPlan,
    QuotaTracker,
};
#[cfg(feature = "quota")]
pub use quota::FsQuotaStore;
#[cfg(feature = "tokio-runtime")]
pub use quota::{QuotaExceeded, QuotaPolicy, QuotaUsage};
#[cfg(feature = "tokio-runtime")]
pub use security::{is_safe_url, resolve_and_check, IpClass, SsrfError, SsrfPolicy};
#[cfg(feature = "tokio-runtime")]
pub use storage::{ResourceMeta, Storage, StorageEvent};

// ---------------------------------------------------------------------------
// JSS v0.0.190 Phase 1 port — export re-exports (implemented, not stubs).
// ---------------------------------------------------------------------------
#[cfg(feature = "export-jsonld")]
pub use export::{
    export_pod_jsonld, ExportOptions, PodExportBundle, PodExportEntry, EXPORT_CONTENT_TYPE,
    EXPORT_JSONLD_CONTEXT,
};

// ---------------------------------------------------------------------------
// Embedded documentation tree (feature = "embedded-docs")
// ---------------------------------------------------------------------------

/// Re-exported so dependants can name `include_dir::Dir` without taking a
/// direct dependency on the embedding crate.
#[cfg(feature = "embedded-docs")]
pub use include_dir;

/// The crate's Diataxis `docs/` tree, embedded at compile time. It lives
/// here — inside the owning crate's package root — so dependants (notably
/// `solid-pod-rs-server`'s MCP `list_docs`/`read_docs` tools) serve it from
/// a self-contained binary even when built from the registry tarball, where
/// a `../solid-pod-rs/docs` path escape does not exist.
#[cfg(feature = "embedded-docs")]
pub static DOCS_DIR: include_dir::Dir<'static> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/docs");
