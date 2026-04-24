# Changelog

All notable changes to this crate are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0-alpha.1] - 2026-04-24 (Sprint 8 + Sprint 9 consolidation)

Snapshot at commit `2275146`. Parity vs JSS: **85 % spec-normative**
(91/109 rows) / **66 % strict** on the full 121-row tracker (80/121).
567 tests pass across the workspace with the full Sprint 9 feature
matrix.

### Added — Sprint 9 (WAC 2.0 + pod bootstrap + conditions)

- **`wac::validate_for_write(&AclDocument, &ConditionRegistry)`** —
  returns `UnsupportedCondition` so the binder can emit 422
  `application/problem+json` per WAC 2.0 §5. Bound into the server's
  PUT / PATCH / POST paths for ACL documents.
- **`acl:origin` enforcement (net-new vs JSS).** Feature `acl-origin`
  gates `wac::origin::check_origin_allowed`; a request missing or
  mismatching the `Origin` header against the ACL's origin allowlist
  is denied. This is a strengthening beyond JSS, which does not
  enforce `acl:origin`. Parity row 62a.
- **`oidc::replay::DpopReplayCache`** — per-process LRU of seen `jti`
  claims, clock-aware, bounded, safe under concurrent access.
  Benchmarks in `benches/dpop_replay_bench.rs`. Feature
  `dpop-replay-cache`.
- **`provision::provision_pod`** — idempotent pod bootstrap. Seeds
  base containers (`/profile/`, `/settings/`, `/inbox/`, `/public/`),
  writes a WebID profile (with `solid:oidcIssuer` + CID storage link),
  mounts type indexes (`publicTypeIndex` + `privateTypeIndex` under
  `/settings/`), and installs a public-read root ACL.
- **WAC 2.0 condition framework** (Sprint 6 land-date, Sprint 9
  documentation close): `acl:condition`, `acl:ClientCondition`,
  `acl:IssuerCondition`, `ConditionRegistry`, `RequestContext`,
  `EmptyDispatcher`, `ClientConditionEvaluator`,
  `IssuerConditionEvaluator`. Unknown condition types parse but
  evaluate to `NotApplicable` (fail-closed). Parity rows 53–56.

### Added — Sprint 8 (JSS 0.0.144 – 0.0.154 tracking + LWS 1.0)

- **NIP-98 BIP-340 Schnorr signature verification** under
  `nip98-schnorr`, exercised in the LWS 1.0 Auth Suite rows.
- **CID-bound storage links in WebID** —
  `webid::generate_webid_html_with_cid` emits a Content-Identifier
  reference alongside the storage endpoint for IPFS/IPLD-backed pods.
- **Cache-Control on RDF resources** — containers revalidate,
  resources expire. `ldp::cache_control_for` helper.
- **`.acl` + `.meta` content negotiation** — both discovery resources
  honour `Accept:` and serialise to Turtle, JSON-LD, or N-Triples.
- **did:nostr ↔ WebID `alsoKnownAs` round-trip** (Sprint 6 land,
  Sprint 8 close) — `interop::did_nostr::DidNostrResolver` fetches
  the DID Doc, walks `alsoKnownAs`, fetches each candidate WebID
  profile, and verifies a back-link via `owl:sameAs` or
  `schema:sameAs`.

### Changed

- `PARITY-CHECKLIST.md` recalibrated to 121 rows with explicit
  classification per row (present / partial / missing / net-new /
  deferred / wontfix). Spec-normative denominator excludes wontfix +
  deferred; strict denominator counts every row.
- `oidc::verify_dpop_proof_core` signature extended with an
  `AlgorithmAllowlist` parameter. Existing call sites compile
  unchanged via `AlgorithmAllowlist::default()`.

### Fixed

- **Atomic quota writes (P0, Sprint 8).** `FsQuotaStore::record` and
  `FsQuotaStore::reconcile` now serialise to a temp file under the
  pod root and `fs::rename` into place. Concurrent writers can no
  longer observe a half-written `.quota.json`; the race window closed
  on the Sprint 7 land is confirmed eliminated in
  `tests/quota_fs_atomic.rs`.

### Security

- **DPoP proof signature is now actually verified (P0, CVE-class,
  Sprint 9).** `oidc::verify_dpop_proof_core` previously decoded the
  proof body without verifying the JWT signature against
  `header.jwk` — any forged proof authenticated. The function now
  dispatches on `header.alg` via an allowlist
  (`ES256`/`ES384`, `RS256`/`RS384`/`RS512`, `PS256`/`PS384`/`PS512`,
  `EdDSA`), builds a `DecodingKey::from_jwk`, and rejects `alg=none`
  and the HMAC family unconditionally. RFC 9449 §4.3 conformance
  restored. Parity row 62b. **Deployments that issued DPoP-bound
  access tokens before the upgrade should rotate them.**
- **RFC 9449 §4.3 `ath` binding** — `ath` claim presence + hash match
  against the SHA-256 of the bearer token, constant-time compared.
- **SSRF guard on JWKS + OIDC discovery** — every outbound in
  `oidc::jwks::fetch_jwks` runs the SSRF policy on the issuer host,
  pins the TCP connect to the approved IP via `.resolve()` (defeats
  DNS rebinding between SSRF check and connect), re-runs the policy
  on the discovered `jwks_uri`. 900 s cache TTL mirrors JSS.
- **Dotfile allowlist extended** to `.acl`, `.meta`, `.well-known`,
  `.quota.json`. All other dotfiles are 404 regardless of storage
  presence.
- **SSRF primitives** (`security::ssrf`) — RFC 1918, loopback
  (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10`),
  and cloud-metadata (`169.254.169.254`) addresses are rejected.
- **WAC parser bounds** — 1 MiB Turtle ACL cap (configurable via
  `JSS_MAX_ACL_BYTES`); 32-level JSON-LD depth cap. Defends against
  O(n²) splitter blowup and stack-overflow bombs.

### Deprecated

- None. 0.4.0-alpha.1 is additive over the pre-Sprint-5 surface;
  the Sprint 5 DPoP signature fix was a behavioural change at an
  additive API.

## Unreleased — 2026-04-20 (Sprint 7 — operator surface + server route table)

### Added — operator-surface primitives

- `security/rate_limit.rs` (`RateLimiter` trait + sliding-window
  `LruRateLimiter` reference impl). Per-route + per-subject buckets
  (`Ip`, `WebId`, `Custom`); LRU cap (default 4 096 keys) bounds
  memory under churn; `RateLimitDecision::Deny` carries
  `retry_after_secs`. Feature `rate-limit` (gates the LRU impl;
  trait is always compiled).
- `security/cors.rs` (`CorsPolicy` + `CorsPolicy::from_env`). Reads
  `CORS_ALLOWED_ORIGINS`, `CORS_ALLOW_CREDENTIALS`, `CORS_MAX_AGE`.
  Default `expose_headers` includes `WAC-Allow`, `Link`, `ETag`,
  `Accept-Patch`, `Accept-Post`, `Updates-Via`. Wildcard +
  credentials degrades to echoing the concrete origin per Fetch
  spec; `Vary: Origin` always set so caches don't leak.
- `quota/mod.rs` (`QuotaPolicy` trait + `FsQuotaStore`). Per-pod
  `.quota.json` sidecar; `record` + `reconcile` mirror JSS
  `quota.js`. `PodError::QuotaExceeded` propagates the breach.
  Feature `quota` (gates the FS impl + the error variant).
- `multitenant.rs` (`PodResolver` trait + `PathResolver` default +
  `SubdomainResolver`). Subdomain mode maps `alice.example.org/foo`
  → `(pod=Some("alice"), storage_path="/foo")`. Double-pass `..`
  scrub mirrors JSS `urlToPathWithPod`. Unknown subdomain
  gracefully degrades to path-based (no 400 — JSS parity).
- `config::sources::parse_size` — accepts `50MB`, `1.5GB`, raw
  integer bytes; SI multiplier (1000-based) per the test
  fixtures. Wired so `JSS_DEFAULT_QUOTA` env var decodes via
  `parse_size`.
- `interop::nodeinfo_discovery` + `interop::nodeinfo_2_1` — JSON
  helpers for `/.well-known/nodeinfo` + `/.well-known/nodeinfo/2.1`
  per nodeinfo.diaspora.software §3 + §6. `protocols` advertises
  both `solid` and `activitypub`.

### Added — `solid-pod-rs-server` route table

- Library extracted: `crates/solid-pod-rs-server/src/lib.rs`
  exposes `pub fn build_app(state)` so handlers are testable via
  `actix_web::test::init_service` without a real network port.
  Binary `main.rs` becomes a thin entry point.
- Handlers added:
  - `POST /{tail:.*}/` — Slug-resolved child creation in container
    via `ldp::resolve_slug`; emits `Location:` header.
  - `PATCH /{tail:.*}` — dialect dispatch on `Content-Type`
    (`text/n3`, `application/sparql-update`, `application/json-patch+json`);
    PATCH-creates-resource path returns 201 via
    `ldp::apply_patch_to_absent`.
  - `OPTIONS /{tail:.*}` — `Allow` / `Accept-Post` (containers) /
    `Accept-Patch` / `Accept-Ranges` from `ldp::options_for`.
  - `GET /.well-known/solid` — discovery doc.
  - `GET /.well-known/webfinger` — JRD.
  - `GET /.well-known/nodeinfo` + `/.well-known/nodeinfo/2.1`.
  - `GET /.well-known/did/nostr/{pubkey}.json` (gated `did-nostr`).
- **WAC enforcement on writes** (PUT/POST/PATCH/DELETE) via
  `wac::evaluate_access_ctx_with_registry` — was GET-only at
  alpha.1. 401 on anonymous, 403 on authenticated denial, both
  carry `WAC-Allow` header.
- **`PathTraversalGuard` middleware** — explicit percent-decode +
  `..` segment check (single AND double-encoded). Belt-and-braces
  on top of `actix_web::middleware::NormalizePath`.
- **`DotfileGuard` middleware** — wraps the existing
  `DotfileAllowlist` primitive into the request pipeline.
- **Explicit body-size cap** — `JSS_MAX_REQUEST_BODY` (via
  `parse_size`) registers an `actix_web::web::PayloadConfig`.
  Default 50 MiB. PUTs over the cap return 413 explicitly rather
  than relying on actix defaults.
- **`--mashlib-cdn` CLI flag** — plumbed into `AppState`. Static
  asset wiring deferred to a follow-up.

### Added — optional TLS

- `solid-pod-rs-server` gains feature `tls`; when set and both
  `JSS_SSL_KEY` + `JSS_SSL_CERT` env vars are populated, server
  binds via `actix_web::HttpServer::bind_rustls_0_23`. Falls back
  to plain bind when either var is absent.

### Tests

- ~54 new tests across 8 new files:
  - `rate_limit_lru.rs` (5), `cors_preflight.rs` (6).
  - `quota_fs.rs` (5), `tenancy_subdomain.rs` (6),
    `config_size_parsing.rs` (6).
  - `nodeinfo_jss.rs` (7).
  - `server_routes_jss.rs` (12), `server_security.rs` (7).
- Total tests now well past 480 across the workspace with all
  Sprint 7 features enabled
  (`oidc,dpop-replay-cache,legacy-notifications,jss-v04,acl-origin,security-primitives,config-loader,nip98-schnorr,webhook-signing,did-nostr,rate-limit,quota`).

### New Cargo features

- `rate-limit` — sliding-window LRU rate limiter (`lru` +
  `parking_lot`).
- `quota` — pod-quota filesystem adapter (`config-loader`).
- `tls` (in `solid-pod-rs-server`) — `rustls` + `rustls-pemfile`.

### Known follow-ups (queued for Sprint 8 / GA)

- CORS + rate-limit middleware not yet wired into the server's
  actix middleware stack — primitives are in `state` but not
  `.wrap()`ed. Trivial follow-up once the `Transform` adapter
  lands.
- `--mashlib-cdn` flag plumbed; static-asset routes not mounted.
- xtask CTH harness — invoke `solid/conformance-test-harness`
  against the new server binary.
- Module re-export polish: `lib.rs` re-exports for `quota::*`,
  `multitenant::*`, `security::cors::*`, `security::rate_limit::*`
  exposed via `pub use`.

## Unreleased — 2026-04-20 (Sprint 6 — WAC 2.0, LDP gaps, webhook signing, did:nostr)

### Added — WAC 2.0 conditions framework

- New `acl:condition` predicate plus `acl:ClientCondition` and
  `acl:IssuerCondition` evaluators (https://webacl.org/secure-access-conditions/).
- `wac::Condition` enum with `serde(other)` fail-closed sentinel —
  unknown condition types parse but evaluate to `NotApplicable`,
  which the evaluator treats as deny (WAC 2.0 §5).
- `ConditionRegistry`, `RequestContext`, `EmptyDispatcher`, plus
  `ClientConditionEvaluator` and `IssuerConditionEvaluator` for
  per-request gate decisions.
- `wac::validate_for_write(&AclDocument, &ConditionRegistry)` — handler
  hook that returns `UnsupportedCondition` so the binder can emit a
  422 `application/problem+json` per WAC 2.0.
- `wac_allow_header_with_dispatcher` — request-scoped variant that
  omits gated modes from `WAC-Allow` when the relevant condition
  evaluates to `NotApplicable`.

### Changed — `wac.rs` split into `wac/`

- 908-line `wac.rs` decomposed into nine focused sub-modules
  (`mod`, `document`, `evaluator`, `parser`, `serializer`,
  `conditions`, `client`, `issuer`, `resolver`, plus the existing
  `origin`). Every file is now under the 500-line CLAUDE.md ceiling.
- `evaluate_access` / `evaluate_access_with_groups` retained as
  `pub use` re-exports; new `evaluate_access_ctx` and
  `evaluate_access_ctx_with_registry` accept a `RequestContext` for
  conditions wiring.

### Added — webhook RFC 9421 signing

- New `notifications/signing.rs` module: Ed25519-backed RFC 9421
  HTTP Message Signatures over `@method`, `@target-uri`,
  `content-type`, `content-digest` (RFC 9530), `date`,
  `x-solid-notification-id`. Sign + verify symmetric so receivers
  can re-use the verifier.
- `WebhookChannelManager` extended with `signer`, `max_attempts`,
  `max_backoff`, `circuit_threshold`, plus circuit-breaker state.
  Builder methods for each.
- Delivery semantics overhauled:
  - 2xx → success.
  - 410 Gone → fatal drop.
  - 4xx (other) → retain subscription, retry as transient.
  - 429 / 5xx → exponential back-off with ±20 % clamped jitter,
    `Retry-After` honoured (seconds and HTTP-date forms).
  - Network error → same as 5xx.
  - Circuit opens after `circuit_threshold` consecutive failures;
    sub stays alive but is paused until reset.
- New feature flag `webhook-signing` (implies `jss-v04`); pulls in
  `ed25519-dalek`, `httpdate`, optional `rand` for OS jitter.

### Added — did:nostr resolver

- `interop::did_nostr` (gated `did-nostr`):
  - `did_nostr_well_known_url(origin, pubkey)` mirrors JSS
    `.well-known/did/nostr/<pubkey>.json`.
  - `did_nostr_document(pubkey, also_known_as)` builds the Tier-1
    DID Doc with a `NostrSchnorrKey2024` verification method.
  - `DidNostrResolver` performs bidirectional resolution: fetch DID
    Doc, walk `alsoKnownAs`, fetch each candidate WebID profile,
    verify a back-link via `owl:sameAs` or `schema:sameAs`. SSRF-
    checked at every outbound. 5 min success / 60 s failure TTL
    cache mirroring JSS.
- Closes mesh-rank E.4 without instantiating the empty
  `solid-pod-rs-nostr` crate (Auth + Operator inspector
  recommendation).

### Added — LDP hidden gaps

- `resolve_slug` now returns `Result<String, PodError::BadRequest>`;
  rejects `/`, `..`, `\0`, lengths > 255 bytes, and any character
  outside `[A-Za-z0-9._-]`. Absent slug still falls back to UUID.
- `options_for(path)` branches `Accept-Ranges` on container vs
  resource — containers get `none`, resources get `bytes`. Closes
  PARITY row 23.
- `not_found_headers(path, conneg_enabled)` — JSS-parity helper
  emitting `Allow` (no DELETE), `Accept-Put`, `Accept-Post`
  (containers only), `Link rel=acl`, `Vary`.
- `vary_header(conneg_enabled)` — explicit primitive.
- `apply_patch_to_absent(dialect, body)` + new `PatchCreateOutcome`
  enum so callers can issue 201 vs 204 on PATCH-creates-resource.
- `parse_range_header_v2` returning `RangeOutcome::{Full, Partial,
  NotSatisfiable}` so empty resources + Range requests yield 416
  rather than 412. The original `parse_range_header` retained for
  callers that don't need the new distinction.
- New `PodError::BadRequest(String)` variant (used by slug + ACL
  parser bounds).

### Added — WAC parser bounds

- `MAX_ACL_BYTES = 1 MiB` (configurable via `JSS_MAX_ACL_BYTES`)
  enforced on Turtle ACL parse — defends against O(n²) splitter
  blowup on multi-MB inputs.
- `MAX_ACL_JSON_DEPTH = 32` enforced on JSON-LD ACL parse via a
  pre-parse depth-counted JSON skim — defends against
  stack-overflow recursion bombs (200-level deep crafted input
  rejected within 5 ms).

### Fixed — DPoP iat-skew connective

- `oidc::verify_dpop_proof_core` (`src/oidc/mod.rs:517`) used `&&`
  on two mutually-exclusive `saturating_sub` branches, so the
  iat-skew gate was unreachable — any iat outside tolerance
  authenticated. Switched to `||`. Filed by the Sprint 6 coverage
  agent via an `#[ignore]` test that was promoted to a real test
  alongside the source fix.

### Tests

- ~90 new tests added across 11 new files:
  - `wac2_conditions.rs` (8), `wac_validate_for_write.rs` (3) —
    WAC 2.0 framework.
  - `webhook_signing.rs` (3), `webhook_retry.rs` (4) — RFC 9421 +
    delivery.
  - `did_nostr_resolver.rs` (6) — bidirectional resolver.
  - `ldp_slug_jss.rs` (9), `ldp_headers_jss.rs` (8),
    `ldp_patch_create_jss.rs` (4), `ldp_range_jss.rs` (5),
    `wac_parser_bounds.rs` (5) — LDP hidden gaps + parser DoS caps.
  - `oidc_mod_direct.rs` (13), `notifications_mod_direct.rs` (11),
    `nip98_extended.rs` (4), `oidc_integration.rs` (5) — mesh-and-
    QE-flagged zero-test modules brought to ≥85 % line coverage.
- **Total in-tree test count: 436 passing across 32 suites** with
  `oidc,dpop-replay-cache,legacy-notifications,jss-v04,acl-origin,security-primitives,config-loader,nip98-schnorr,webhook-signing,did-nostr`.

### New Cargo features

- `webhook-signing` — Ed25519 signing via `ed25519-dalek`, RFC 9421
  profile.
- `did-nostr` — bidirectional resolver in `interop`.

## Unreleased — 2026-04-20 (Sprint 5 security remediation)

### Security (P0 fixes — CVE-class)

- **DPoP proof signature is now actually verified.** Previously
  `verify_dpop_proof_core` (`src/oidc/mod.rs`) decoded the proof body
  without verifying the JWT signature against `header.jwk` — any forged
  proof authenticated. The function now dispatches on `header.alg`
  (`ES256`/`RS256`/`EdDSA`), verifies via `DecodingKey::from_jwk`, and
  rejects `alg=none`. RFC 9449 §4.3 conformance restored.
- **OIDC access-token verification now dispatches on `header.alg`
  against a `JwkSet`.** `verify_access_token` no longer hard-codes
  `Algorithm::HS256`; the new signature accepts a `TokenVerifyKey`
  (`Symmetric` for the test/dev path, `Asymmetric(JwkSet)` for
  production OPs). `alg=none` is unconditionally rejected.
- **JWK thumbprint is now RFC 7638 canonical.** `Jwk::thumbprint` was
  built from a hand-rolled `format!()` JSON template; replaced with
  `BTreeMap`-backed canonical serialisation so thumbprints match JSS
  and any RFC-compliant verifier byte-for-byte. Locked by an RFC 7638
  appendix-A test vector.
- **SSRF-guarded JWKS + OIDC discovery fetcher (`src/oidc/jwks.rs`,
  new).** `fetch_jwks(issuer, &SsrfPolicy, &Client)` runs the SSRF
  policy on the issuer host, builds a per-call reqwest client with
  `.resolve()` to pin the TCP connect to the approved IP (defeating
  DNS rebinding between check and connect), re-runs the SSRF policy
  on the discovered `jwks_uri` host (never reuses the issuer
  approval), and caches results with a 900s TTL mirroring JSS.
  Closes the F5 documentation/implementation gap.
- **Legacy `solid-0.1` WebSocket now enforces a WAC read check on
  every subscribe.** `LegacyNotificationChannel::subscribe` previously
  permitted any client to subscribe to any URI. New
  `SubscriptionAuthorizer` trait wires `wac::evaluate_access` for
  `AccessMode::Read`; default authorizer is `DenyAllAuthorizer`
  (fail-closed). Same-origin guard added. Denial frame literal is
  now `forbidden`, matching JSS grammar exactly.

### Fixed (pre-existing test + lint regressions cleared)

- **`wac::path_matches` (`src/wac.rs`)** — `acl:accessTo` now matches
  exact resource + direct children of a container target only (WAC
  §4.2); previously it either matched all descendants (over-grant) or
  failed root-rooted rules entirely. `acl:default` continues to apply
  recursively.
- **`wac::turtle_pop_term` (`src/wac.rs`)** — terminator set extended
  from whitespace-only to `whitespace | ',' | ';' | ']' | ')'`. The
  previous tokeniser welded trailing punctuation onto identifier
  tokens (e.g. `acl:Write,`), silently dropping multi-mode rules.
- **`ldp::extract_block` (`src/ldp.rs`)** — now requires a left word
  boundary AND a `{`-following position before matching `inserts` /
  `deletes` keywords. The previous greedy substring match treated
  `solid:InsertDeletePatch` (which contains both keywords) as a
  block delimiter, parsing both clauses from the same `{ … }`.
- **SPARQL DELETE / INSERT data normalisation (`src/ldp.rs`)** —
  `xsd:string` datatype on plain literals now strips back to `None`,
  matching the `Term::literal` constructor and the N-Triples fast
  path. Without this, `BTreeSet<Triple>` ordering diverged and
  `DELETE DATA` reported zero deletions when the triple was present.
- **NIP-98 test fixture (`src/auth/nip98.rs`)** — `valid_event` now
  computes a real BIP-340 event id (and a real Schnorr signature when
  `nip98-schnorr` is enabled). The previous `id: "0".repeat(64)`
  placeholder caused id-mismatch failures whenever the verify path
  computed the actual id.
- **Workspace clippy** — `rust_2018_idioms` lint group now declares
  `priority = -1` to coexist with future per-lint overrides; the
  group-vs-lint priority error no longer blocks `-D warnings` CI.

### Tests

- 17 new tests across 5 new files exercise the P0 fixes:
  `oidc_dpop_signature.rs` (3), `oidc_thumbprint_rfc7638.rs` (3),
  `oidc_access_token_alg.rs` (3), `oidc_jwks_ssrf.rs` (4),
  `legacy_wac_check.rs` (4).
- Total in-tree test count: **346 passing** across 18 suites with the
  full feature matrix
  (`oidc,dpop-replay-cache,legacy-notifications,jss-v04,acl-origin,security-primitives,config-loader,nip98-schnorr`).

### Documentation

- Engineering report:
  [`docs/explanation/jss-parity-upgrade-2026-04-20.md`](docs/explanation/jss-parity-upgrade-2026-04-20.md)
  (six-inspector mesh against the real JSS, 12 sections, 31
  actionable items, PARITY-CHECKLIST corrections).
- QE addendum:
  [`docs/explanation/jss-parity-upgrade-2026-04-20-QE-ADDENDUM.md`](docs/explanation/jss-parity-upgrade-2026-04-20-QE-ADDENDUM.md)
  (Agentic QE Fleet validation, +1 P0 / +7 P1, per-module
  quality-gate matrix, test-first sequencing for the 3-sprint plan
  to v0.4.0 GA).
- `PARITY-CHECKLIST.md`: Sprint 5 corrections table; 5 new rows
  (53–56 for WAC 2.0 conditions, 62b for DPoP signature). Top-line
  parity recalibrated from a claimed 76% to a verified 59% — the
  drop reflects honest accounting, not regression.

### Dev-dependencies

- `p256`, `pkcs8` (for ES256 keypair generation in OIDC tests).
- `hmac` (for the dpop-replay test helper that previously spliced an
  unsigned signature; now computes a real HMAC).

### Known follow-ups (queued for Sprint 6 + Sprint 7)

See the engineering report and QE addendum. Headline items: WAC 2.0
condition framework, `wac.rs` module split, RFC 9421 webhook signing,
body-size cap, percent-decode path-traversal middleware in the
binary crate, ACL JSON depth bomb cap, did:nostr resolver in
`interop`, operator-surface primitives (rate-limit, CORS, quota,
subdomain MT, TLS, NodeInfo 2.1), CTH harness in `xtask`.

## 0.4.0-alpha.1 — 2026-04-20

### Added

- SSRF guard with IP classification plus allow/deny lists
  (`src/security/ssrf.rs`). Gated behind `security-primitives`.
- Dotfile allowlist (default `.acl`, `.meta`) enforced at the storage
  boundary (`src/security/dotfile.rs`).
- Legacy `solid-0.1` WebSocket notifications adapter for SolidOS
  data-browser compatibility (`src/notifications/legacy.rs`). Gated
  behind `legacy-notifications`.
- WAC `acl:origin` enforcement per the Web Access Control spec §4.3
  (`src/wac/origin.rs`). Gated behind `acl-origin`.
- DPoP `jti` replay cache per Solid-OIDC §5.2 and RFC 9449 §11.1
  (`src/oidc/replay.rs`). Gated behind `dpop-replay-cache`.
- Layered configuration loader (defaults → file → environment) with
  `JSS_*` environment variable mapping for drop-in operational
  parity (`src/config/`). Gated behind `config-loader`.
- Workspace split into `solid-pod-rs` (library) and
  `solid-pod-rs-server` (binary). The binary is a thin actix-web
  shell; the library no longer mounts HTTP routes.
- Reserved sibling crates for the v0.5.0 surface:
  `solid-pod-rs-activitypub`, `solid-pod-rs-git`,
  `solid-pod-rs-idp`, `solid-pod-rs-nostr`.
- Fresh gap analysis against the real JavaScriptSolidServer
  (97 rows, 76 % strict parity).
- ~30 integration tests and four criterion benchmarks covering the
  new surface.

### Changed

- The library crate no longer constructs `actix-web::HttpServer`;
  transport lives in `solid-pod-rs-server`.
- `verify_dpop_proof` now accepts an optional replay cache handle.
- `evaluate_access` now accepts an optional request origin.
- `NOTICE` restructured for clarity.

### Fixed

- Deduplicated residual `jss-v04` feature keys in `Cargo.toml`.

### Security

- Closes five of the six audit findings from the previous release
  cycle. The remaining finding — library-server coupling — is also
  resolved by the workspace split.

## 0.3.0-alpha.3 — 2026-04-20

### Licence migration (BREAKING)

- Licence changed from dual `MIT OR Apache-2.0` to `AGPL-3.0-only`.
- Inherited from the JavaScriptSolidServer (JSS) ecosystem covenant; JSS
  is AGPL-3.0, and solid-pod-rs preserves the network-service copyleft
  protection rather than weakening it with a permissive relicence.
- `LICENSE-MIT` and `LICENSE-APACHE` removed; `LICENSE` added with full
  AGPL-3.0 text.
- `Cargo.toml` `license` field updated to `"AGPL-3.0-only"`.
- `NOTICE` rewritten to document AGPL covenant + full provenance chain.
- `deny.toml` allowlist flipped to permit AGPL-3.0 in dependency graph.
- Consumers: if you're operating solid-pod-rs as a network service, AGPL
  §13 requires you to distribute corresponding source to your users.

## [0.3.0-alpha.1] — 2026-04-20

### Added — Sprint 3 parity close (ADR-053 §"JSS parity gate")

Every remaining `partial` or `missing` row in the JSS parity checklist
is resolved in this release. 67/67 rows are now either `present` (62)
or `explicitly-deferred` (5) with ADR-053 rationale. No `partial` and
no `missing` rows remain.

**WAC / ACL.**
- `wac::parse_turtle_acl` — Turtle ACL parser (accepts `@prefix`,
  `a`-shorthand, `;`-separated predicate lists, `,`-separated object
  lists). The `StorageAclResolver` now falls back to Turtle when the
  JSON-LD parse fails. Covers Solid's Turtle-authored `.acl` documents.
- `wac::serialize_turtle_acl` — canonical Turtle output round-trip.
- `AclDocument`, `AclAuthorization`, `IdOrIds`, `IdRef` now derive
  `Clone + Serialize` (required for `ProvisionPlan` and round-tripping).

**LDP.**
- `ldp::evaluate_preconditions` — RFC 7232 If-Match / If-None-Match,
  including wildcard (`*`) and comma-separated ETag lists. Returns a
  typed `ConditionalOutcome::{Proceed, PreconditionFailed, NotModified}`
  so callers can map to 412 / 304 without repeating logic.
- `ldp::parse_range_header` + `ldp::slice_range` — RFC 7233 byte
  ranges for binary resources. Supports `start-end`, open-ended
  (`start-`), and suffix-length (`-n`) forms; multi-range is rejected
  by design.
- `ldp::options_for` + `ACCEPT_PATCH` — OPTIONS response builder with
  correct `Allow` set per container/resource, `Accept-Post`,
  `Accept-Patch` (n3 / sparql-update / json-patch), and
  `Accept-Ranges: bytes`.
- `ldp::apply_json_patch` — RFC 6902 (`add`, `remove`, `replace`,
  `test`, `copy`, `move`) with JSON Pointer `-` append semantics.
- `PatchDialect::JsonPatch` + `patch_dialect_from_mime` now recognises
  `application/json-patch+json`.
- `PreferHeader::parse` now tolerates multi-IRI `include=` lists
  (`PreferMinimalContainer` + `PreferContainedIRIs` in one directive).

**WebID.**
- `webid::generate_webid_html_with_issuer` — emits `solid:oidcIssuer`
  for Solid-OIDC follow-your-nose discovery.
- `webid::extract_oidc_issuer` — pulls the issuer claim back out of a
  WebID HTML document (accepts string + `{@id:…}` object forms).

**Auth.**
- `auth::nip98::verify_schnorr_signature` — BIP-340 Schnorr signature
  verification over the canonical NIP-01 event hash. Gated behind the
  new `nip98-schnorr` feature (adds `k256` dep). Structural checks
  remain active in both configurations; verifier is invoked
  automatically from `verify_at` when the feature is on.
- `auth::nip98::compute_event_id` — canonical event-id hash per
  NIP-01, reused by the Schnorr verifier.

**Interop / discovery.**
- New `interop` module with:
  - `well_known_solid` — Solid Protocol §4.1.2 discovery document.
  - `webfinger_response` — RFC 7033 JRD with `acct:` and `https://`
    subjects; advertises OIDC issuer + WebID + pim:storage links.
  - `verify_nip05` — NIP-05 identifier verification, `_` wildcard
    fallback for root-of-domain names.
  - `dev_session` / `DevSession` — typed dev-mode bypass; the type is
    constructable only through this helper so callers can gate it
    behind their own env checks without exposing a header-based path.

**Provisioning.**
- New `provision` module with:
  - `ProvisionPlan` + `provision_pod` — declarative pod bootstrap:
    seeded containers (idempotent), WebID profile, optional root ACL,
    optional quota.
  - `QuotaTracker` — atomic reserve/release with `PreconditionFailed`
    on overrun; `None` quota means unlimited.
  - `check_admin_override` — constant-time shared-secret comparison
    that upgrades requests to the new `AdminOverride` marker type.

**Tests.**
- `tests/parity_close.rs` — 20 Sprint 3 integration tests exercising
  every newly-landed feature.
- `tests/interop_jss.rs` grew from 23 to 42 tests (+19 covering Turtle
  ACL, conditional requests, ranges, JSON Patch, OPTIONS response,
  WebID-OIDC, `.well-known/solid`, WebFinger, NIP-05, provisioning,
  quota, admin override, multi-include Prefer, dev session, JSON Patch
  dialect detection, and the `.meta` Link-rel invariant).
- `tests/schnorr_nip98.rs` — 2 Schnorr tests (feature-gated behind
  `nip98-schnorr`).

**Crate metadata.**
- Version bumped `0.2.0-alpha.1` → `0.3.0-alpha.1`.
- New `nip98-schnorr` feature in `Cargo.toml`.

### Explicitly-deferred (with rationale)

These five rows retain the `explicitly-deferred` status with an ADR-053
pointer so the parity checklist is never a moving target:

- **WebID-TLS** — legacy, superseded by Solid-OIDC + DPoP.
- **RDF/XML serialisation** — format negotiated; serialiser is a
  consumer-crate concern (avoids pulling in sophia/oxigraph).
- **S3 backend** — feature flag + `aws-sdk-s3` optional dep retained;
  concrete impl lives in VisionClaw pod-worker (backend boundary).
- **R2 / D1 / KV adapters** — Cloudflare-specific; consumer-crate.
- **RemoteStorage compatibility** — not on Solid Protocol path.

## [0.2.0-alpha.1] — 2026-04-19 (Phase 2 close)

### Added

- Full Solid Notifications Protocol 0.2 (WebSocket + Webhook channel
  managers, discovery document, exponential retry + fatal-drop).
- Solid-OIDC 0.1: DPoP proof verification, dynamic client registration,
  discovery, token introspection, WebID extraction (feature-gated
  under `oidc`).
- LDP PATCH: N3 (`solid:inserts`/`deletes`/`where`) and SPARQL-Update
  (`INSERT DATA` / `DELETE DATA` / `DELETE WHERE`).
- Prefer header parser + server-managed triple enforcement.
- ACL inheritance corpus (31 tests) + JSS interop corpus (23 tests).
- Count rolled from 27/67 to 48/67 present.

## [0.1.0-alpha.1] — 2026-04-19

### Added
- Initial crate scaffold as a VisionClaw workspace member.
- `Storage` trait with associated `ResourceMeta` and `StorageEvent`
  types.
- `MemoryBackend` — in-memory backend for tests, backed by an
  `Arc<RwLock<HashMap<...>>>` with a broadcast channel for change
  events.
- `FsBackend` — filesystem backend rooted at a configurable directory,
  with SHA-256 ETags, `.meta.json` sidecar files for content type and
  Link values, and a `notify`-backed file watcher.
- `wac` module — JSON-LD ACL evaluator supporting `acl:agent`,
  `acl:agentClass`, `acl:mode`, `acl:accessTo`, `acl:default`,
  container inheritance, and the WAC-Allow response header.
- `ldp` module — container/resource distinction, Link header
  generation, slug resolution for POST-to-container.
- `webid` module — WebID profile document generation and validation.
- `auth::nip98` module — structural NIP-98 token verification (kind,
  tags, URL/method/payload matching, timestamp tolerance).
- `error::PodError` — crate-wide error type.
- Conformance test suite (`tests/storage_trait.rs`) covering Memory
  and FS backends.
- WAC smoke tests (`tests/wac_basic.rs`).
- `examples/standalone.rs` — minimal actix-web Solid pod server.

### Notes
- The Phase 1 NIP-98 module implements all structural checks. Schnorr
  signature verification is deferred to Phase 2, behind a feature flag
  that will gate the `k256` dependency.
- Notifications module (`src/notifications.rs`) ships with trait
  signatures and in-memory stubs. Full Solid Notifications Protocol
  (WebSocket, Webhook) is the Phase 2 deliverable.

[0.1.0-alpha.1]: https://github.com/DreamLab-AI/VisionClaw
