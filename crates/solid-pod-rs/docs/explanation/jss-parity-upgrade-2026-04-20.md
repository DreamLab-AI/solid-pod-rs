# JSS Parity & WAC 2.0 Upgrade — Engineering Report

**Date:** 2026-04-20
**Comparator:** JavaScriptSolidServer (JSS) at `/JavaScriptSolidServer/` (gitignored;
local checkout ahead of any upstream tag, package version `0.0.86`).
**Target:** `solid-pod-rs v0.4.0-alpha.1` → `v0.4.0` GA.
**Method:** Six-inspector ruflo-managed mesh (`swarm-1776695334549-c7q3wp`,
mesh topology, gossip consensus). Each inspector read both sides in full and
returned a structured verdict with file:line citations. Cross-cutting findings
synthesised here.
**External input:** `https://webacl.org/secure-access-conditions/` — recommended
by Melvin (JSS) — fetched, distilled, and treated as ground truth for the WAC
2.0 sections of this report.

---

## 0. Executive summary

The current `PARITY-CHECKLIST.md` overstates parity in five rows and silently
omits the most important security finding in the codebase. Expanding the
analysis to **WAC 2.0 (`acl:condition`, ClientCondition, IssuerCondition,
422-on-unknown-condition, fail-closed evaluation)** and to JSS behaviours the
checklist never covered (404 header contract, slug 400, container Accept-Ranges,
PATCH-create-if-absent, HTML data-island PATCH, RFC 9421 webhook signing,
TLS, subdomains, quota, rate-limit, CORS) yields **31 net new actionable items**
spread across 7 modules. Three are **P0 (security or correctness blockers)**,
fourteen are **P1**, the remainder operator-completeness P2/P3.

**The single highest-priority finding:** `oidc::verify_dpop_proof_core`
(`crates/solid-pod-rs/src/oidc/mod.rs:369-377`) base64-decodes the DPoP proof
body and trusts it without verifying the JWT signature. Only `HS256` is wired
(line 457); `ES256`/`RS256` paths do not exist; `alg=none` is not rejected. Any
forged DPoP proof currently authenticates a token. This is **CVE-class** and
must land before any further protocol work.

The second-highest: the legacy WebSocket `LegacyNotificationChannel::subscribe`
performs no WAC read check on the requested target. PARITY row 91 calling this
"present" is incorrect; the channel is a generic-protected-resource information
leak today.

The third: `Authorization` documents in the WAC evaluator carry no `condition`
field, so any `acl:condition` triple in an ACL is silently dropped — a
fail-**open** outcome where WAC 2.0 demands fail-closed.

The remaining 28 items are deferrable to v0.4.x sprints.

Total estimated landing cost for 0.4.0 GA: **~3,200 LOC across 12 modules,
≈14 working days of focused engineering**, of which 2 days are the P0
remediation block.

---

## 1. PARITY-CHECKLIST corrections

The checklist needs the following amendments before this report is considered
canonical:

| Row | Current | Corrected | Source |
|---|---|---|---|
| 23 | `Accept-Ranges: bytes`/`none` — present | **semantic-difference** — `options_for()` hard-codes `"bytes"` even on containers | LDP inspector |
| 26/28 | WAC-Allow + CORS — partial-parity | **partial-parity (binder-uninstrumented)** — library has `wac_allow_header` but `solid-pod-rs-server` never emits it; CORS has no primitive at all | WAC + LDP inspectors |
| 33 | OPTIONS — present | **partial-parity** — body+204 missing | LDP inspector |
| 40 | N3 Patch `where` failure 412 — semantic-difference | **net-new (Rust strictly more conformant)** — JSS never invokes `validatePatch`; silently drops missing deletes | LDP inspector |
| 91 | solid-0.1 legacy notifications — present | **partial-parity** pending: per-sub WAC read check, ancestor-container fanout, frame literal `forbidden`, same-origin guard | Notifications inspector |
| 92 | Webhook delivery — present | **partial-parity** pending: RFC 9421 signing, 4xx-retain (not drop), Retry-After honouring, jitter | Notifications inspector |
| 18 | `describedby` — net-new | **header-only** — link advertised but `.meta` GET returns 404 on both sides | LDP inspector |
| 53 | `acl:condition` — (not tracked) | **NEW ROW: missing P0** — no field on `AclAuthorization`, fail-open by omission | WAC inspector |
| 54 | `acl:client*` / ClientCondition — (not tracked) | **NEW ROW: missing P1** — WAC 2.0 normative | WAC inspector |
| 55 | `acl:issuer*` / IssuerCondition — (not tracked) | **NEW ROW: missing P1** — WAC 2.0 normative | WAC inspector |
| 56 | 422 on ACL PUT with unknown condition — (not tracked) | **NEW ROW: missing P1** — WAC 2.0 normative | WAC inspector |
| 62b | DPoP proof signature verification — (not tracked) | **NEW ROW: missing P0** — body decoded without signature check | Auth inspector |
| 65 | SSRF on JWKS — missing as primitive | **missing as integration** — primitive ships, no `fetch_jwks` consumer | Auth inspector |

PARITY-CHECKLIST.md should be edited to reflect this before the next
release-notes pass.

---

## 2. P0 — security/correctness blockers (must land first)

### P0-1. DPoP proof signature verification

**File:** `crates/solid-pod-rs/src/oidc/mod.rs:369-377` (decode), line 457
(hard-coded HS256 dispatch).
**Current behaviour:** body base64-decoded without `jwtVerify`. Header `jwk`
imported but never used to verify the signature. `alg=none` accepted.
**Required behaviour:** dispatch on `header.alg ∈ {ES256, RS256}`; reject
`none` and `HS256` for proofs (proofs are per-request, public-key only); use
`jsonwebtoken::DecodingKey::from_jwk(&header.jwk)` to verify; verify `cnf.jkt`
matches the access token's confirmation thumbprint; verify `ath` SHA-256 of
the access token (currently uncomputed — Auth inspector §1 row 62 + §6 patch
4); verify `htu` and `htm` exactly; reuse the existing `iat` skew check; feed
the existing `DpopReplayCache` for `jti`.
**Tests to add:**
`oidc_dpop_rejects_unsigned_proof`, `oidc_dpop_alg_none_is_rejected`,
`oidc_dpop_ath_mismatch_rejected`.
**Cost:** ~180 LOC + ~6 tests. **0.5 day.**

### P0-2. SSRF on JWKS / OIDC discovery fetch

**File:** new `crates/solid-pod-rs/src/oidc/jwks.rs`; `oidc/mod.rs` integration
at `verify_access_token`.
**Current behaviour:** library never fetches JWKS; consumer must wire HTTPS
fetch and re-implement SSRF. `SsrfPolicy` exists in
`src/security/ssrf.rs` but has no in-tree consumer.
**Required behaviour:** `fetch_jwks(issuer, &SsrfPolicy, &reqwest::Client)`
that (a) `resolve_and_check`s the issuer host, (b) constructs a `reqwest`
client with `.resolve(host, SocketAddr::new(approved_ip, 443))` to pin the
TCP connect against DNS rebinding, (c) GETs `/.well-known/openid-configuration`,
(d) re-runs `resolve_and_check` against the discovered `jwks_uri` host (never
reuse the issuer approval), (e) GETs JWKS, (f) caches `(issuer, JwkSet, fetched_at)`
with TTL 900s mirroring JSS. `verify_access_token` takes `&JwkSet` and
dispatches `Algorithm::{RS256,ES256,HS256}` on token header `alg`.
**Tests to add:** `oidc_jwks_fetch_blocks_metadata_ip`,
`oidc_jwks_fetch_pins_tcp_connect_to_approved_ip`.
**Cost:** ~250 LOC + ~5 tests + small `OidcConfigCache`/`JwksCache`. **1 day.**

### P0-3. Legacy WebSocket WAC read check

**File:** `crates/solid-pod-rs/src/notifications/legacy.rs:185-196`.
**Current behaviour:** `LegacyNotificationChannel::subscribe` only checks
caps (URL length, sub limit). PARITY row 91 claim of "present" is false; the
channel will gladly broadcast change events to any anonymous client for any
ACL-protected resource.
**Required behaviour:** inject a `SubscriptionAuthorizer` trait
(`fn check(&self, target: &str, web_id: Option<&str>, public_mode: bool) -> Result<(), DenyReason>`)
backed by `wac::checker::evaluate_access_with_groups` for `AccessMode::Read`.
Emit literal `err <uri> forbidden` on denial (matches JSS frame grammar
exactly — Rust's current dashed tokens corrupt SolidOS state). Add same-origin
guard and ancestor-container fanout (port `websocket.js:207-219`).
**Tests to add:** `legacy_wac_denial_emits_forbidden_frame`,
`legacy_cross_origin_subscription_rejected`,
`legacy_ancestor_container_fanout`.
**Cost:** ~200 LOC + ~5 tests. **0.5 day.**

---

## 3. WAC 2.0 — secure-access-conditions implementation plan

Direct mapping of `https://webacl.org/secure-access-conditions/` to the Rust
crate. Inspector #2 verified the spec against both sides.

### 3.1 Vocabulary additions (parser)

Add to `AclAuthorization` struct at `wac.rs:51-78`:

```rust
#[serde(rename = "acl:condition", default, skip_serializing_if = "Option::is_none")]
pub condition: Option<Vec<Condition>>,
```

`Condition` is a tagged enum with one variant per supported condition type:

```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "@type")]
pub enum Condition {
    #[serde(rename = "acl:ClientCondition")]
    Client(ClientConditionBody),
    #[serde(rename = "acl:IssuerCondition")]
    Issuer(IssuerConditionBody),
    #[serde(other)]
    Unknown,  // fail-closed sentinel
}
```

The Turtle parser at `wac.rs:558` (`parse_turtle_authorization`) needs
`parse_bnode` for the `[ … ]` blank-node syntax that conditions use.

### 3.2 Evaluator integration

In `evaluate_access_with_groups` (`wac.rs:253`), after agent + mode + accessTo
all match but before the Control-mode bypass at line 303:

```rust
for cond in auth.condition.iter().flatten() {
    match registry.dispatch(cond, ctx) {
        ConditionOutcome::Satisfied => continue,
        ConditionOutcome::NotApplicable | ConditionOutcome::Denied => {
            base_grant = false;  // FAIL-CLOSED — WAC 2.0 §5
            break;
        }
    }
}
```

`ConditionRegistry` is owned by the pod, registered at boot:

```rust
let mut registry = ConditionRegistry::new();
registry.register(Box::new(ClientConditionEvaluator::new(group_resolver.clone())));
registry.register(Box::new(IssuerConditionEvaluator::new(trusted_issuers.clone())));
```

### 3.3 422 emission

New library helper `wac::validate_for_write(&AclDocument, &ConditionRegistry)
-> Result<(), UnsupportedCondition>` returns `Err` when an `acl:condition` body
references a type the registry has no evaluator for. Consumer binder
(`solid-pod-rs-server` PUT handler for any path ending in `.acl`) calls this
and emits HTTP 422 with `application/problem+json` body listing the offending
condition IRI.

### 3.4 AuthContext wiring

Inspector #3's `AuthContext` shape is the precondition for ClientCondition and
IssuerCondition evaluation:

```rust
pub struct AuthContext {
    pub webid: Option<String>,
    pub client_id: Option<String>,    // WAC 2.0 ClientCondition input
    pub issuer: Option<String>,       // WAC 2.0 IssuerCondition input
    pub dpop_jkt: Option<String>,
    pub scope: Vec<String>,
    pub auth_method: AuthMethod,
}
```

`evaluate_access_ctx(&AuthContext, …)` becomes the new entry point; the
existing `evaluate_access(agent_uri: Option<&str>, …)` is a thin shim for
backwards compatibility (one release window).

### 3.5 Module restructure

`wac.rs` is 882 lines, 76% over the CLAUDE.md 500-line ceiling. Split into:

```
wac/
  mod.rs            # ~80 LOC — re-exports + AccessMode + method_to_mode
  document.rs       # ~120 LOC — AclDocument, AclAuthorization, IdOrIds, serde
  evaluator.rs      # ~200 LOC — evaluate_access*, GroupMembership, path_matches
  parser.rs         # ~260 LOC — parse_turtle_acl + parse_bnode
  serializer.rs     # ~90 LOC — serialize_turtle_acl
  conditions.rs     # ~150 LOC — Condition enum, ConditionRegistry trait
  client.rs         # ~120 LOC — ClientConditionEvaluator + acl:client* parsing
  issuer.rs         # ~120 LOC — IssuerConditionEvaluator + acl:issuer* parsing
  origin.rs         # 374 LOC unchanged
  resolver.rs       # ~90 LOC — AclResolver, StorageAclResolver
```

### 3.6 WAC 2.0 conformance tests

```
wac2_acl_condition_client_matches_permits
wac2_acl_condition_client_mismatch_denies
wac2_acl_condition_issuer_group_membership
wac2_unknown_condition_type_fails_closed
wac2_conjunctive_conditions_and_gate
wac2_put_acl_with_unknown_condition_returns_422
wac2_wac_allow_header_omits_gated_modes
wac2_monotonicity_invariant
```

---

## 4. Hidden LDP gaps (checklist silent)

These behaviours JSS implements that nobody recorded against, and they break
SolidOS clients quietly.

| Gap | Rust file | Fix sketch | Severity |
|---|---|---|---|
| Slug `400` on invalid (`/`, `..`, >255B, allowlist violation) | `ldp.rs:119 resolve_slug` | Return `Result<String, PodError::BadRequest>`; UUID fallback only when slug is *absent* | P1 |
| `Accept-Ranges: none` on containers | `ldp.rs:1336 options_for` | Branch on `is_container(path)` | P1 |
| `not_found_headers()` helper | new in `ldp.rs` | Mirror JSS `getNotFoundHeaders`: `Allow` (no DELETE), `Accept-Put`, `Accept-Post` (containers), `Link rel=acl`, `Vary` | P1 |
| `apply_patch_to_absent()` (PATCH-creates returns 201 not 204) | new in `ldp.rs` | Seed empty `Graph`, apply, return `PatchOutcome::Created` marker | P1 |
| HTML data-island PATCH (`<script type="application/ld+json">`) for `/profile/card` | new in `ldp.rs` | `extract_jsonld_island` + `reembed_jsonld_island` mirroring `resource.js:823-846` | P1 |
| `Storage::put` to existing-container 409 | `storage/mod.rs` doc + `ldp::put_kind` helper | Document trait contract; add `PutKind { Replace, Create, RejectContainer }` | P1 |
| Range zero-length resource (currently 412, must 416) | `ldp.rs:1259-1263` | Map `total == 0` to `RangeNotSatisfiable` variant | P2 |
| Multi-range policy (currently `PodError::Unsupported`, JSS serves full body) | `ldp.rs:1251-1255` | Document the choice or align with JSS | P2 |
| `Vary` builder | new in `ldp.rs` | `vary_header(conneg: bool) -> &'static str` | P2 |
| CORS primitives (see §6.2) | new in `security/cors.rs` | `CorsPolicy` | P2 |

Tests: 5 new files under `tests/ldp_*` plus a JSS HTTP fixture capture
(`tests/fixtures/jss/`) for bytewise diffing.

---

## 5. Notifications hardening

Beyond P0-3 (WAC read check), the webhook channel needs RFC 9421 signing.

### 5.1 Webhook RFC 9421 HTTP Message Signatures

**File:** `crates/solid-pod-rs/src/notifications/mod.rs:362 (deliver_one)` and
new `src/notifications/signing.rs`.
Add `Signature`, `Signature-Input`, `Date`, `X-Solid-Notification-Id` headers.
Per Solid Notifications 0.2 §5 (strong-SHOULD; we treat as MUST for any pod
serving production traffic). Sign with Ed25519; key rotation per channel.

### 5.2 Delivery semantics

- 4xx → retain subscription except `410 Gone` (currently any 4xx drops).
- 403/429 → transient retry.
- Honour `Retry-After`.
- Add ±20% jitter to back-off.
- Circuit-breaker after N consecutive failures with bounded back-off ceiling
  (1h).

### 5.3 SSE — defer 0.5.x with rationale

Not in Solid Notifications 0.2; no SolidOS clients request it; webhook +
WebSocket cover push and pull-via-long-connection. Revisit if/when CG
publishes 0.3 with SSE or a real client ticket lands. **This deferral has
documented rationale** and matches the user's "defer only with rationale"
rule.

---

## 6. Operator surface — promote to v0.4.x (no rationale to defer)

### 6.1 Rate-limit primitive — `security/rate_limit.rs`

```rust
#[async_trait::async_trait]
pub trait RateLimiter: Send + Sync + 'static {
    async fn check(&self, key: &RateLimitKey<'_>) -> RateLimitDecision;
}
pub struct LruRateLimiter { /* parking_lot::Mutex<LruCache<String, SlidingWindow>> */ }
```

Feature-gated `rate-limit` (deps: `lru`, `parking_lot`). Consumer binders
implement `RateLimiter`; we ship the LRU reference impl. ~250 LOC.

### 6.2 CORS primitive — `security/cors.rs`

`CorsPolicy::from_env()` reads `CORS_ALLOWED_ORIGINS`,
`CORS_ALLOW_CREDENTIALS`, `CORS_MAX_AGE`. `preflight_headers` and
`response_headers` produce the header tuples for the binder. Default
`expose_headers` includes `WAC-Allow`, `Link`, `ETag`, `Accept-Patch`,
`Accept-Post`, `Updates-Via`. ~120 LOC.

### 6.3 Subdomain multi-tenancy — `multitenant.rs`

`PodResolver` trait + `PathResolver` (default) + `SubdomainResolver
{ base_domain }`. `solid-pod-rs-server` selects from
`cfg.tenancy.subdomains`; remaps `alice.example.org/foo` → `/alice/foo`.
Reference: JSS `urlToPathWithPod` (`utils/url.js:56-86`) including the
double-pass `..` scrub. ~80 LOC.

### 6.4 Quota primitive — `quota/mod.rs`

`QuotaPolicy` trait + `FsQuotaStore` (sidecar `.quota.json`).
`PodError::QuotaExceeded(usage, limit)`. Hooked into `ldp::put` dispatch via
the `Storage` adapter. Wires `JSS_DEFAULT_QUOTA` (with `parse_size` helper
accepting `50MB`, `1.5GB`). `solid-pod-rs-server` gains `quota reconcile`
subcommand mirroring JSS `bin/jss.js`. ~250 LOC.

### 6.5 TLS in `solid-pod-rs-server`

`JSS_SSL_KEY` + `JSS_SSL_CERT` → `actix_web::HttpServer::bind_rustls`. The
parity claim that we are a drop-in JSS replacement holds only after this
lands. ~40 LOC.

### 6.6 did:nostr in main library — `interop.rs` extension

Fold `did_nostr_document(pubkey)` and `resolve_did_nostr_to_webid(pubkey,
ssrf, http)` (bidirectional `alsoKnownAs` + `owl:sameAs` back-link) into the
main library under feature `did-nostr`. ~200 LOC. Keeps the empty
`solid-pod-rs-nostr` crate reserved for the embedded relay only. The
two-API-break problem (Auth inspector §5) is avoided.

### 6.7 NodeInfo 2.1 — `interop.rs` extension

`/.well-known/nodeinfo` and `/.well-known/nodeinfo/2.1`. ~60 LOC, no AP deps
(the discovery doc itself is independent of federation). Closes PARITY rows
106 and 131.

### 6.8 CTH harness — `xtask cth`

`crates/solid-pod-rs-server/xtask/cth.rs` clones `solid/conformance-test-harness`
into a tempdir, writes a `pod.json` manifest pointing at an ephemeral
`solid-pod-rs-server` instance, runs the LDP-read, LDP-write, WAC-read, WAC-write
suites, asserts `failures == 0`. ~80 LOC + CI workflow entry.

### 6.9 `solid-pod-rs-server` route table

CTH cannot run today because the binary only wires GET/HEAD/PUT/DELETE on
`/{tail:.*}`. Add: POST (Slug-based container append), PATCH (dialect
dispatch via `ldp::patch_dialect_from_mime`), OPTIONS (`Allow`, `Accept-Post`,
`Accept-Patch`, `Accept-Ranges`), `.well-known/solid`, `.well-known/webfinger`,
`.well-known/did/nostr/:pk`, `.well-known/nodeinfo`, `--mashlib-cdn` flag,
WAC enforcement on writes (currently GET-only WAC), CORS hook, rate-limit
hook, dotfile hook (calls existing `DotfileAllowlist`). ~400 LOC.

---

## 7. Reserved-crate triage (confirms / amends ADR-056)

| Crate | Recommendation | Rationale |
|---|---|---|
| `solid-pod-rs-activitypub` | Keep empty; ship 0.5.0 | RSA HTTP-Sig + follower SQLite store + outbox delivery; pulls `rsa`, `sqlx`; doesn't fit no-I/O thesis |
| `solid-pod-rs-git` | Keep empty; ship 0.5.0 | CGI spawn + seccomp + uid isolation; ~450 LOC of platform-guarded code |
| `solid-pod-rs-idp` | Keep empty; post-0.5.0 | 3,500 LOC; ADR-053 rationale (RP-only) holds |
| `solid-pod-rs-nostr` | **Split** | did:nostr resolver to `interop` now (§6.6); relay 0.5.0 |

Three of the four reservations are confirmed correct. The fourth (`-nostr`)
needs the resolver carved off, because keeping it in the empty crate forces
two API breaks (one when the crate lands, one when its API settles) and
deprives `auth::nip98::verify` of the `AuthContext.webid` field WAC 2.0
needs.

---

## 8. Mashlib classification

Server-binary feature, not library. JSS bundles three static files +
CDN-redirect mode. Equivalent in `solid-pod-rs-server`: a single
`actix_files::Files::new("/", mashlib_dir)` line plus a
`--mashlib-cdn https://unpkg.com/mashlib@2.0.0/dist` flag. PARITY row 109
should be closed as "server-binary feature, not library" rather than tracked
as a library gap.

---

## 9. Sequenced rollout — three sprints to 0.4.0 GA

### Sprint 5 (3 days) — security remediation
- P0-1 DPoP signature verification.
- P0-2 SSRF on JWKS + OIDC config cache.
- P0-3 Legacy WebSocket WAC read check.
- AuthContext shape (precondition for §3 and §6.6).
- New tests pass; existing tests pass; clippy clean.
- **Gate to Sprint 6:** zero P0 outstanding.

### Sprint 6 (5 days) — WAC 2.0 + LDP hidden gaps
- §3 condition framework end-to-end (parser, registry, dispatch, 422).
- `wac.rs` module split (§3.5).
- `did:nostr` resolver in `interop` (§6.6).
- Webhook RFC 9421 signing (§5.1) + delivery semantics (§5.2).
- §4 hidden LDP gaps (slug 400, Accept-Ranges container, `not_found_headers`,
  PATCH-create-if-absent, HTML data-island, `put_kind`, range zero-length,
  Vary builder).
- 8 WAC 2.0 tests + 5 LDP test files.
- **Gate to Sprint 7:** WAC 2.0 + LDP suites green; PARITY-CHECKLIST updated.

### Sprint 7 (5 days) — operator surface + CTH
- §6.1 RateLimiter trait + LruRateLimiter.
- §6.2 CorsPolicy.
- §6.3 Subdomain MT.
- §6.4 Quota primitive.
- §6.5 TLS in server.
- §6.7 NodeInfo 2.1.
- §6.8 xtask cth — clone, manifest, run, assert.
- §6.9 server route table — POST/PATCH/OPTIONS/well-knowns, WAC on writes,
  CORS/rate-limit/dotfile hooks.
- ADR-057 "Operator-surface primitives".
- **Gate to GA:** CTH suites pass; binary serves bytewise-equivalent JSS
  responses on 12 captured fixtures.

Total: 13 working days + 1 day buffer = **2 weeks of focused engineering**.

---

## 10. Test infrastructure additions

| Path | Purpose |
|---|---|
| `tests/oidc_dpop_signature.rs` | P0-1 (3 tests) |
| `tests/oidc_jwks_ssrf.rs` | P0-2 (2 tests) |
| `tests/legacy_wac_check.rs` | P0-3 (3 tests) |
| `tests/wac2_conditions.rs` | §3 (8 tests) |
| `tests/wac2_put_422.rs` | §3.3 (1 test against `solid-pod-rs-server`) |
| `tests/auth_context.rs` | §3.4 (2 tests) |
| `tests/ldp_headers_jss.rs` | §4 (4 tests) |
| `tests/ldp_slug_jss.rs` | §4 (5 tests) |
| `tests/ldp_patch_create_jss.rs` | §4 (3 tests) |
| `tests/ldp_patch_html_island.rs` | §4 (3 tests) |
| `tests/ldp_range_jss.rs` | §4 (2 tests) |
| `tests/webhook_signing.rs` | §5.1 (3 tests) |
| `tests/webhook_retry.rs` | §5.2 (3 tests) |
| `tests/rate_limit_lru.rs` | §6.1 (1 test) |
| `tests/cors_preflight.rs` | §6.2 (1 test) |
| `tests/tenancy_subdomain.rs` | §6.3 (1 test) |
| `tests/quota_fs.rs` | §6.4 (2 tests) |
| `tests/did_nostr_resolver.rs` | §6.6 (2 tests) |
| `tests/server_cth_smoke.rs` | §6.8 (1 test, full harness invocation) |
| `tests/fixtures/jss/` | bytewise HTTP captures from a throwaway JSS instance for the 12 most informative operations |

19 new test files, **~70 named tests** added.

---

## 11. New ADRs to record

- **ADR-057** Operator-surface primitives — rate-limit trait, CORS policy,
  subdomain helper, quota primitive land in v0.4.x rather than punting to
  consumer.
- **ADR-058** WAC 2.0 conditions framework — parser, registry, dispatch, 422
  emission. Records fail-closed default and monotonicity invariant.
- **ADR-059** did:nostr resolver in main library — supersedes the
  `solid-pod-rs-nostr` crate's reservation for resolver code; relay-only
  reservation retained.
- **ADR-060** DPoP proof signature verification (security remediation, refers
  to P0-1).
- **ADR-061** SSE deferred to 0.5.x with explicit rationale (deliberately
  documents a deferral so future readers don't classify it as an oversight).

---

## 12. Confidence and limits of this report

Inspector confidence (self-rated, mesh-aggregated): LDP 72%, WAC 86%, Auth 82%,
Notifications 88%, Storage/Config 82%, Operator 78%. **Combined report
confidence ≈ 80%.**

Material uncertainties:

1. The exact PUT-handler 422 path in `solid-pod-rs-server` was not opened by
   the WAC inspector; if an existing handler can be augmented rather than
   added, §3.3 becomes a 30-line edit rather than a new helper. Either way
   the public library API stays as proposed.
2. `Storage::put` container-write semantics are documented loosely; if
   `MemoryBackend` already errors on directory writes, §4's `put_kind`
   helper is doc-only rather than behavioural.
3. The CTH blocker count in §6.9 is medium-confidence — running the harness
   against the new binary will reveal second-order gaps (Link `rel="type"`
   assertion quirks, Prefer-header corner cases) that the static analysis
   missed.
4. The 14-working-day estimate excludes review cycles, design iteration on
   the `ConditionRegistry` API surface, and any unforeseen Cargo feature-flag
   interactions across the new modules.

This report is intended as the engineering plan of record for the
v0.4.0-alpha.1 → v0.4.0 GA window. PARITY-CHECKLIST corrections in §1 should
be applied before any of the listed work begins; the checklist is currently
miscalibrated and would otherwise hide regressions.
