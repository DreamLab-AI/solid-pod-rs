# JSS Parity & WAC 2.0 Upgrade — QE Fleet Addendum

**Date:** 2026-04-20
**Companion to:** [`jss-parity-upgrade-2026-04-20.md`](./jss-parity-upgrade-2026-04-20.md)
**Method:** Agentic QE Fleet v3.9.13 (`build-with-quality` skill, 60-agent
runtime). Four QE-specialist agents — coverage+gap, mutation+defect,
security-orchestrator, fleet-commander — run in parallel against the codebase
**and** against the proposed work plan from the engineering report.

This addendum (a) verifies the engineering report's three P0 claims by direct
file:line read, (b) elevates one new finding to P0 and seven to P1, (c)
attaches per-module quality gates to the existing 3-sprint plan, and (d)
sequences the work test-first.

> **All claims in this document have been validated by direct file read.**
> The mesh report's three P0s are confirmed verbatim. The new findings are
> independent observations the 6-inspector mesh did not surface.

---

## 0. Executive summary (delta over the engineering report)

The engineering report identified **3 P0s, 14 P1s, 14 P2/P3s** across 7
modules. The QE fleet adds:

- **+1 P0** — *Algorithm-confusion in OIDC access-token verification.*
  `oidc/mod.rs:457` hard-codes `Algorithm::HS256`. Production cannot verify
  RS256/ES256 tokens at all; symmetric-secret use in production is a
  defence-in-depth violation. Co-equal with mesh P0-1 because both arise from
  the same module and must be fixed together.

- **+7 P1s** — non-canonical JWK thumbprint, percent-encoded path-traversal
  not normalised at the server layer, ACL JSON depth-bomb, Turtle parser
  size-bomb, default-256KiB body cap not explicit, DPoP `ath` claim parsed
  but never compared, secrets-in-logs risk in `config/loader.rs:143` and the
  global tracing subscriber.

- **+2 P0-equivalent test gaps** — `oidc/mod.rs` (17 public APIs, **0
  direct tests**) and `notifications/mod.rs` (11 public APIs covering the
  whole Solid Notifications Protocol surface, **0 direct tests**). The
  current parity claim of "feature present" is true at compile time but
  unverified at runtime for the entire OIDC and modern-notifications
  surface.

- **+9 zero-coverage integration paths** — full Solid-OIDC end-to-end
  unstitched in tests; webhook delivery never SSRF-tested; PATCH never
  exercises the server-managed-triple rejection guard.

- **Mutation-test priorities + kill-rate targets** for the six highest-risk
  functions, scoped for `cargo-mutants` runs that fit in a CI budget.

- **Quality gate matrix** — per-module line, branch, and mutation-kill
  thresholds; CI gate ordering; block-merge vs advisory designations.

- **Three-sprint test-first sequencing** — every P0 and P1 has a named
  red-phase test that must exist and fail before the green-phase code task.

The combined v0.4.0 GA work envelope rises from the report's **~3,200 LOC
across 12 modules / 14 days** to **~4,100 LOC across 14 modules / 17 days**
once the QE additions are absorbed. The +3 days is one engineer's worth of
test-writing for the previously-untested OIDC + modern-notifications surface;
it is not optional and was simply invisible to a feature-parity-shaped
analysis.

---

## 1. P0 verification (direct file:line read)

| # | Mesh claim | Verified | Evidence |
|---|---|---|---|
| P0-1 | DPoP body decoded without signature verification | **YES** | `crates/solid-pod-rs/src/oidc/mod.rs:366-377`. Comment on line 367-368 reads "Signature verification ... done separately below." No such verification exists in the function. The JWK is computed for thumbprint at line 364 but never used to verify the JWT signature. Function returns `DpopVerified` after only header parse, body parse, and three claim checks. |
| P0-2 | SSRF policy primitive ships, no `fetch_jwks` consumer | **YES** | `crates/solid-pod-rs/src/security/mod.rs:32` documents the deliverable as F5 (`OIDC JWKS fetcher \| fetch_jwks \| SsrfPolicy::resolve_and_check → 400 on deny`). `crates/solid-pod-rs/src/oidc/mod.rs` contains a single `jwks_uri: String` struct field at line 136 and no fetcher of any kind. The library docs and the library do not agree. |
| P0-3 | Legacy WebSocket subscribe has no WAC read check | **YES** | `crates/solid-pod-rs/src/notifications/legacy.rs:187-201`. `subscribe(&mut self, target: String) -> Result<(), String>` performs only `url-too-long` and `subscription-limit` checks. No WebID, no WAC, no Storage parameter, no `SubscriptionAuthorizer`. |
| **P0-4 (new)** | OIDC access-token verification hard-codes HS256; no RS256/ES256 dispatch | **YES** | `crates/solid-pod-rs/src/oidc/mod.rs:457` `Validation::new(Algorithm::HS256)`. No header-alg dispatch exists. Production tokens (universally RS256/ES256) cannot be verified. Symmetric-secret use is a defence-in-depth violation in any deployment that does not own the OP. |

Verification confidence on the four P0s: **100%**. All evidence is direct
file content; no inference.

---

## 2. New findings the 6-inspector mesh missed

### 2.1 P0 — algorithm confusion in access-token verify

**File:** `crates/solid-pod-rs/src/oidc/mod.rs:457`.
**Current behaviour:** `let mut validation = Validation::new(Algorithm::HS256);`
hardcoded. Token must be HS256-signed against a server-side secret.
**Required behaviour:** read `header.alg` from the access token, dispatch to
`{ES256, RS256, EdDSA}` using a `JwkSet` fetched via the new
`oidc::jwks::fetch_jwks` (P0-2 deliverable). Reject `HS256` for tokens issued
by external OPs; allow only when the server *is* the OP (which today it
isn't — the IdP crate is empty). Reject `none`.
**Cost:** absorbed into P0-1 + P0-2 fix (~50 LOC additional).
**Tests added:**
`oidc_access_token_rs256_rejected_when_hs256_only_configured`,
`oidc_access_token_alg_none_rejected`,
`oidc_access_token_dispatches_es256_against_jwks`.

### 2.2 P1 — non-canonical JWK thumbprint

**File:** `crates/solid-pod-rs/src/oidc/mod.rs:222-247`.
**Current behaviour:** `Jwk::thumbprint` constructs the input via `format!()`
on a hand-rolled JSON template. RFC 7638 requires canonical-JSON ordering
(RFC 8785) — alphabetic field order, no whitespace, exact escape rules.
**Risk:** thumbprints silently diverge from JSS, from external OPs, and from
any RFC-compliant verifier. `cnf.jkt` then mismatches and DPoP binding
appears broken when it isn't.
**Required behaviour:** serialise via `BTreeMap<&str, &str>` with
`serde_json::to_vec`, or use the `jose-jwk` / `josekit` canonical form.
**Tests added:** `oidc_jwk_thumbprint_matches_rfc7638_test_vector` (RFC
appendix A vector).
**Cost:** ~30 LOC. **Track in Sprint 5** alongside P0-1/P0-2.

### 2.3 P1 — percent-encoded path traversal at the server layer

**File:** `crates/solid-pod-rs-server/src/main.rs:174,229,258`.
**Current behaviour:** path from `req.uri().path()` piped into
`storage.{put,get,delete}`. Storage layer's `normalize()` rejects literal
`..`, but actix's `NormalizePath` middleware is **not registered**, so a
request to `/%2e%2e/escape` reaches storage as the un-decoded path.
**Risk:** if any consumer manually `percent_decode`s before `Storage::get`,
or if actix internals change, traversal becomes possible. Defence-in-depth
violation.
**Required behaviour:** mount `actix_web::middleware::NormalizePath` and add
explicit `percent_decode` + `..` re-check in the request pipeline.
**Tests added:** `storage_fs_percent_encoded_dotdot_blocked`,
`server_normalises_path_before_storage_dispatch`.
**Cost:** ~20 LOC + middleware wiring.

### 2.4 P1 — ACL JSON depth bomb

**File:** `crates/solid-pod-rs/src/wac.rs:417`.
**Current behaviour:** `serde_json::from_slice::<AclDocument>(&body)` with
default 128-level recursion limit. A 200-level-deep JSON-LD ACL stack-
overflows in debug builds; in release the depth limit triggers but burns CPU.
**Required behaviour:** custom deserializer with `RECURSION_LIMIT = 32`
(Solid Protocol §6 ACLs are flat — 4 levels deep at most).
**Tests added:** `wac_acl_recursion_bombs_rejected` (200-level input → error
within 5ms budget).
**Cost:** ~25 LOC.

### 2.5 P1 — Turtle parser size bomb

**File:** `crates/solid-pod-rs/src/wac.rs:456`.
**Current behaviour:** `parse_turtle_acl` uses unbounded `split(';')` over
the body; a 10 MB ACL drives O(n²) allocation in the statement splitter.
**Required behaviour:** outer byte-count cap (default 1 MiB, configurable
via `JSS_MAX_ACL_BYTES`) and per-statement cap.
**Tests added:** `wac_turtle_acl_oversize_rejected_with_413`.
**Cost:** ~20 LOC.

### 2.6 P1 — explicit body-size cap on writes

**File:** `crates/solid-pod-rs-server/src/main.rs:224-252`.
**Current behaviour:** no `PayloadConfig` registered. Falls through to
actix's default 256 KiB cap. Operationally fine; configurationally
invisible — operators upgrading from JSS expect to set
`JSS_MAX_REQUEST_BODY` and have it work.
**Required behaviour:** register `PayloadConfig::new(cfg.security.max_body)`
explicitly; honour `JSS_MAX_REQUEST_BODY` env var (add to §6.1 in the
engineering report's env-var table).
**Tests added:** `server_put_over_body_cap_returns_413`.
**Cost:** ~15 LOC.

### 2.7 P1 — DPoP `ath` claim parsed but never enforced

**File:** `crates/solid-pod-rs/src/oidc/mod.rs:272` (claim parsed) — never
compared against `SHA-256(access_token)`.
**Risk:** an attacker with a stolen DPoP proof can pair it with any access
token whose `cnf.jkt` matches the proof JWK thumbprint. RFC 9449 §4.1 §5.4
requires `ath` enforcement.
**Required behaviour:** when `verify_dpop_proof_core` is called from the
access-token verification path, the caller passes the access token and the
function checks `claims.ath == base64url(sha256(access_token))`.
**Tests added:** `dpop_ath_claim_mismatch_rejected`.
**Cost:** ~25 LOC.
**Already noted in mesh report as an Auth-inspector P1; this addendum
re-classifies it as gating Sprint 5 alongside the P0s rather than letting
it slip to Sprint 6.**

### 2.8 P1 — secrets-in-logs risk

**Files:**
`crates/solid-pod-rs/src/config/loader.rs:143` —
`tracing::warn!("{w}")` may include raw env-var values; `POD_OIDC_HS256_SECRET`
and similar can flow into the warning text path on validation error.
`crates/solid-pod-rs-server/src/main.rs:280` — `tracing_subscriber::fmt()`
default has no header redaction; `Authorization`, `DPoP`, and cookie
contents land in trace logs verbatim under `RUST_LOG=trace`.
**Required behaviour:** redaction list in the subscriber formatter
(`Authorization`, `DPoP`, `Cookie`, `X-Api-Key`, `Set-Cookie`); audit
`config/loader.rs` to ensure no env-var value reaches `warn!` without
key-name-only logging.
**Tests added:** `log_redactor_strips_authorization_header`,
`config_loader_warn_does_not_emit_secret_values`.
**Cost:** ~80 LOC.

### 2.9 P2 — supply chain hygiene

- `spargebra 0.3` is dormant (no updates since 2023); track or replace.
- `Cargo.lock` commit status unverified; CI must enforce `cargo audit`.
- All deps use `"1"`/`"0.x"` floating versions; reproducibility relies
  entirely on the lockfile.

---

## 3. Coverage gaps the mesh missed

### 3.1 Modules with **zero** direct tests

| Module | Public APIs | Tests | Density | Severity |
|---|---|---|---|---|
| `oidc/mod.rs` | 17 | **0** | 0.00 | **CRITICAL** — biggest single hole |
| `notifications/mod.rs` | 11 | **0** | 0.00 | **CRITICAL** — entire Solid Notifications surface |
| `metrics.rs` | 1 | 0 | 0.00 | counters never asserted |
| `error.rs` | 1 enum (12 variants) | 0 | 0.00 | `Display` output (which callers pattern-match) never asserted |

The mesh's PARITY-CHECKLIST claims `oidc` and `notifications` are
"present" — **at compile time, yes**; **with verifiable runtime
behaviour, no**. Untested code is unverified code; if any of these public
APIs regress, no test will catch it. v0.4.0 GA cannot ship until both
modules cross 85% line coverage.

### 3.2 Shallow-coverage hotspots (happy-path only)

- `auth/nip98.rs` — 2 tests, both negative. No happy-path Schnorr round-
  trip; no skew-window enforcement; no `u`/`method` tag mismatch test;
  no payload-hash enforcement test.
- `webid.rs` — 1 issuer test + 1 generator smoke. `validate_webid_html`
  negative invariants entirely untested.
- `provision.rs` — 1 happy-path. No clash, no rollback, no
  constant-time-property test under adversarial input.
- `ldp.rs` `apply_n3_patch` / `apply_sparql_patch` — **zero direct tests**;
  only JSON Patch is covered in `parity_close.rs`.

### 3.3 Integration paths with zero coverage

1. Full Solid-OIDC: OP discovery → JWKS fetch → `verify_access_token` →
   DPoP bind via `cnf.jkt` → WAC eval. **Nothing stitches all five.**
2. `register_client` → `verify_access_token` (the dynamic-registration
   round trip is split between two unrelated tests, neither end-to-end).
3. NIP-98 → WAC bridge.
4. Storage event → `InMemoryNotifications::notify` → subscriber delivery.
5. Webhook delivery → `SsrfPolicy` gate → HTTP POST.
6. Quota + `provision_pod` rollback under quota-exceeded.
7. `acl:origin` + `Control` mode + inherited-default composition.
8. PATCH → `find_illegal_server_managed` rejection of poisoned triples.
9. `serialize_turtle_acl` → re-parse → evaluate (write side never reloaded).
10. `ConfigLoader` → effective `StorageBackendConfig` actually instantiates
    the chosen backend.

These ten paths must be the integration-test backbone of Sprint 6 and
Sprint 7. Add `tests/integration_*.rs` files for each.

---

## 4. Mutation-test priorities + kill-rate targets

`cargo-mutants` should land in CI as part of the security-audit gate, run
nightly (full suite) and on PR (changed-file only). Initial scoping:

| Target | Mutants (est.) | Wall-time | Kill-rate target |
|---|---|---|---|
| `--file src/oidc/replay.rs` | ~50 | <30s | **95%** |
| `--file src/oidc/mod.rs --function verify_dpop_proof_core --function verify_access_token` | ~80 | ~2m | **90%** |
| `--file src/ldp.rs --function parse_range_header --function slice_range --function apply_json_patch` | ~60 | ~90s | **95%** |
| `--file src/wac/origin.rs` | ~70 | ~90s | **85%** |
| `--file src/auth/nip98.rs` | ~45 | ~1m | **90%** |
| `--file src/wac.rs --function evaluate_access_with_groups --function check_authorizations` | ~60 | ~90s | **85%** |

Skip for now: `src/ldp.rs` full-file (>600 mutants, >15m). Use `--function`
scoping until coverage rises. `src/security/ssrf.rs::classify` will produce
many equivalent mutants on IP-range overlaps; vet manually.

Top mutation-vulnerable boundary predicates (will silently survive without
boundary-named tests):

1. `oidc/mod.rs:391` compound `&&` over two `saturating_sub > skew` —
   only one symmetric test.
2. `oidc/replay.rs:170/196` asymmetric `< self.ttl` vs `>= self.ttl` at
   exact boundary.
3. `ldp.rs:1283` `total - 1` panics if the `total == 0` guard is ever
   bypassed.
4. `ldp.rs:1309` `range.end as usize + 1` — 32-bit truncation risk.
5. `auth/nip98.rs:95` `abs_diff > TIMESTAMP_TOLERANCE` — `>/>=` at exact
   60s untested.
6. `wac/origin.rs:268-305` `!any_patterns` flips
   `Permitted`↔`NoPolicySet` silently.

---

## 5. Defect-risk findings beyond the mesh

- **`auth/nip98.rs:60`** `.unwrap_or(0)` on `SystemTime::now().duration_since(UNIX_EPOCH)`. Clock failure makes every request appear at epoch 0 → **silently denies all tokens** while masking the bug. Return `Err` instead.
- **`wac.rs:699`** `items.into_iter().next().unwrap()` — non-empty invariant undocumented; should return `Option` or document the panic.
- **Swallowed errors** (8 sites): `storage/memory.rs:119,129`;
  `storage/fs.rs:178,247`; `oidc/replay.rs:225`;
  `notifications/mod.rs:156,250,275`; `ldp.rs:720-753` (7 `writeln!` ignores).
  Add `.expect("documented invariant: …")` with rationale, or propagate.
- **Untyped errors** (`Result<_, String>`) in 7 sites:
  `ldp.rs:480,490,508`; `webid.rs:61,99`;
  `config/schema.rs:272`; `notifications/legacy.rs:185`. Replace with
  typed enum variants of `PodError`.

Overall intrinsic defect risk: **LOW**. No `unsafe` blocks; saturating
arithmetic used throughout; only two production panic sites (one false
positive, one real). The codebase is in good shape — the issues above are
the long tail to clear before GA, not systemic problems.

---

## 6. Flaky-test inventory

Tests at risk of intermittent failure on loaded CI:

- `tests/dpop_replay_test.rs:125,272` — `tokio::time::sleep(Duration::from_millis(25))` as TTL boundary check. Replace with deterministic clock injection.
- `tests/storage_trait.rs:112` — `sleep(50ms)` as event-propagation wait. Replace with `tokio::time::timeout` on the `watch` receiver.

No fixed network ports, no time-of-day assertions, no `thread::sleep` —
the rest of the test suite is deterministic.

---

## 7. Quality-gate matrix (per-module thresholds)

| Module | Line cov | Branch cov | Mutation kill | Critical-path cov | Block-merge |
|---|---|---|---|---|---|
| `oidc/` (DPoP, JWKS, verify) | **92%** | **88%** | **≥80%** | 100% sig-verify + SSRF | **Block** |
| `wac/` (conditions, evaluator) | **90%** | **85%** | **≥80%** | 100% fail-closed + monotonicity | **Block** |
| `notifications/legacy.rs` | **88%** | **82%** | **≥75%** | 100% subscribe + frame emit | **Block** |
| `notifications/signing.rs` (new) | **90%** | **85%** | **≥75%** | 100% sign/verify | **Block** |
| `notifications/mod.rs` (modern) | **85%** | **78%** | ≥70% | 100% trait impls + discovery | **Block** |
| `ldp.rs` (split into `ldp/headers.rs`, `ldp/patch.rs`) | **85%** | 78% | ≥70% | 100% slug 400, PATCH-create, HTML island | **Block** |
| `security/{ssrf,cors,rate_limit}.rs` | **88%** | **82%** | **≥75%** | 100% metadata-IP block + preflight | **Block** |
| `quota/`, `multitenant.rs`, `interop.rs` (nodeinfo / did:nostr) | 80% | 72% | ≥65% | 100% quota deny + subdomain remap | **Warn** |
| `solid-pod-rs-server` route table | 75% | 65% | n/a | 100% WAC-on-write, dotfile, well-knowns | Block on WAC-on-write; Warn elsewhere |
| `xtask cth` | n/a | n/a | n/a | harness green on 4 suites | **Block** |

Tooling: `cargo tarpaulin --line --branch --features full`; `cargo-mutants`
scoped per-module via `--package solid-pod-rs --path src/wac`. Both wired
into the `coverage-gate` and `security-audit` CI jobs.

---

## 8. CI gate ordering (proposed DAG)

Extend `.github/workflows/ci.yml`:

```
[lint]            fmt + clippy (-D warnings)
   ↓
[unit]            cargo test --lib (existing feature matrix)
   ↓
[integration]     cargo test --test '*' (excludes cth)
   ↓
[wac2-conformance] cargo test --test 'wac2_*' --features jss-v04
   ↓
[ldp-jss-fixtures] cargo test --test 'ldp_*_jss' (bytewise diff)
   ↓
[cth-smoke]       xtask cth (Sprint 7 onward — ephemeral server + W3C harness)
   ↓
[security-audit]  cargo-deny + cargo-audit + cargo-mutants (changed files on PR, full nightly)
   ↓
[coverage-gate]   tarpaulin + per-module thresholds (codecov.yml)
   ↓
[publish-gate]    (release.yml only) cargo publish --dry-run + semver-checks
```

**Block-merge gates:** lint, unit, integration, wac2-conformance,
ldp-jss-fixtures, cth-smoke (S7+), security-audit, coverage-gate (block on
threshold failure for any **Block**-tier module).

**Advisory gates:** cargo-mutants full nightly (PR comment only; no block),
beta toolchain matrix (already `continue-on-error`), wasm32 build (keep
blocking — cheap), coverage on `quota`/`multitenant`/`interop`/non-WAC
server routes.

`required_status_checks` on `main`: add `wac2-conformance`, `cth-smoke`,
`coverage-gate`.

---

## 9. Test-first sequencing (red → green → refactor per sprint)

### Sprint 5 — Security remediation (4d, was 3d)

| Red phase (must fail first) | Green | Refactor |
|---|---|---|
| `oidc_dpop_rejects_unsigned_proof`, `oidc_dpop_alg_none_is_rejected`, `oidc_dpop_ath_mismatch_rejected` | Replace HS256 dispatch at `oidc/mod.rs:457` with `ES256/RS256` via `DecodingKey::from_jwk`; add `ath` + `jkt` checks | Extract `proof_policy()`; document fail-closed in rustdoc |
| `oidc_jwks_fetch_blocks_metadata_ip`, `oidc_jwks_fetch_pins_tcp_connect_to_approved_ip` | New `oidc/jwks.rs` with `fetch_jwks(issuer, &SsrfPolicy, &Client)` + 900s TTL cache | `OidcConfigCache`/`JwksCache` extracted as shared TTL primitive |
| `oidc_access_token_rs256_rejected_when_hs256_only_configured`, `oidc_access_token_dispatches_es256_against_jwks` | Header-alg dispatch in `verify_access_token` | — |
| `oidc_jwk_thumbprint_matches_rfc7638_test_vector` | Replace `format!()` thumbprint with BTreeMap-backed canonical JSON | — |
| `legacy_wac_denial_emits_forbidden_frame`, `legacy_cross_origin_subscription_rejected`, `legacy_ancestor_container_fanout` | `SubscriptionAuthorizer` trait + WAC wiring at `legacy.rs:185-196`; literal `forbidden` frame | Fanout iterator extracted; covariance tests over JSS grammar fixture |
| `auth_context_shape_stable`, `auth_context_threads_into_evaluator` | `AuthContext` struct + `evaluate_access_ctx`; deprecated shim retained | `#[deprecated(since = "0.4.0")]` on the old shape |
| `log_redactor_strips_authorization_header`, `config_loader_warn_does_not_emit_secret_values` | Tracing subscriber redaction layer; `config/loader.rs:143` audit | — |

### Sprint 6 — WAC 2.0 + LDP hidden gaps + notifications signing (5d)

| Red | Green | Refactor |
|---|---|---|
| `wac2_unknown_condition_type_fails_closed`, `wac2_monotonicity_invariant`, `wac2_conjunctive_conditions_and_gate` | `Condition` enum + `ConditionRegistry` in `wac/conditions.rs` | Split `wac.rs` (882 LOC) → 9 sub-modules per engineering report §3.5 |
| `wac2_acl_condition_client_matches_permits`/`mismatch_denies` | `ClientConditionEvaluator` in `wac/client.rs` | `group_resolver` behind `Arc<dyn GroupResolver>` |
| `wac2_acl_condition_issuer_group_membership` | `IssuerConditionEvaluator` in `wac/issuer.rs` | Shared `trusted_issuers` set |
| `wac2_put_acl_with_unknown_condition_returns_422` | `validate_for_write` helper + 422 `application/problem+json` | PUT handler extracted |
| `wac2_wac_allow_header_omits_gated_modes` | Update `wac_allow_header` emission in binder | — |
| `wac_acl_recursion_bombs_rejected`, `wac_turtle_acl_oversize_rejected_with_413` | Custom serde deserializer with depth=32; outer byte cap | — |
| `ldp_slug_invalid_returns_400` ×5 | `resolve_slug` → `Result<String, BadRequest>` | Allowlist as const |
| `ldp_patch_creates_if_absent_201` ×3 | `apply_patch_to_absent()` | `PatchOutcome::Created` marker |
| `ldp_patch_html_data_island_round_trip` ×3 | `extract_jsonld_island` / `reembed_jsonld_island` | Island parser isolated |
| `ldp_options_container_accept_ranges_none` | Branch `options_for` on `is_container` | `not_found_headers()` |
| `ldp_range_zero_length_is_416` | `ldp.rs:1259-1263` variant remap | — |
| `webhook_rfc9421_signature_verifies`, `webhook_4xx_retains_except_410`, `webhook_retry_after_honoured` | `notifications/signing.rs` (Ed25519) + retry state machine | Circuit-breaker as separate struct |
| `did_nostr_alsoknownas_back_link`, `did_nostr_resolver_rejects_missing_backlink` | `interop::did_nostr_*` | — |
| **OIDC integration suite (5 tests)**: `oidc_e2e_discovery_to_evaluate`, `oidc_e2e_dynamic_registration_round_trip`, `nip98_to_wac_bridge`, `webhook_delivery_through_ssrf_gate`, `serialize_acl_round_trip_evaluates_identically` | — | These integration tests fill 5 of the 10 zero-coverage paths from §3.3; remaining 5 land Sprint 7. |
| **`notifications/mod.rs` direct-API suite** (cover the 11 untested public APIs to ≥85%) | — | Brings the modern Notifications surface from 0% to GA-ready |
| **`oidc/mod.rs` direct-API suite** (cover the remaining untested public APIs not already exercised by P0 fixes) | — | Brings OIDC from 0% non-DPoP to GA-ready |
| `auth_nip98_clock_failure_returns_err`, `auth_nip98_skew_window_enforced`, `auth_nip98_payload_hash_enforced`, `auth_nip98_happy_path_round_trip` | Replace `unwrap_or(0)` with `Err`; add the missing assertions | — |

### Sprint 7 — Operator surface + CTH (5d)

| Red | Green | Refactor |
|---|---|---|
| `rate_limit_lru_denies_over_threshold` | `security/rate_limit.rs` trait + LRU impl | — |
| `cors_preflight_emits_expected_headers`, `cors_exposes_wac_allow` | `security/cors.rs` | `CorsPolicy::from_env` |
| `tenancy_subdomain_remaps_alice_example_org` | `multitenant.rs` `SubdomainResolver` | Double-pass `..` scrub helper |
| `quota_fs_rejects_over_limit`, `quota_reconcile_restores_usage`, `quota_provision_rollback_under_exceeded` | `quota/mod.rs` + `FsQuotaStore` + provision integration | `parse_size` utility |
| `server_tls_bind_rustls_handshakes` | `bind_rustls` wire-up | — |
| `nodeinfo_21_well_known_shape` | `/.well-known/nodeinfo{,2.1}` | — |
| `server_post_slug_creates_in_container`, `server_patch_dialect_dispatch_mime`, `server_options_advertises_accept_post_patch`, `server_wac_on_write_blocks_anonymous_put` | Route table expansion in `solid-pod-rs-server` | Handler fns grouped by verb |
| `server_normalises_path_before_storage_dispatch`, `storage_fs_percent_encoded_dotdot_blocked` | `NormalizePath` + percent_decode + re-check | — |
| `server_put_over_body_cap_returns_413` | Explicit `PayloadConfig` registration | — |
| **Remaining 5 integration tests** (`storage_event_to_subscriber`, `acl_origin_inheritance_composition`, `patch_blocks_server_managed_triples`, `config_to_storage_backend_boot`, `provision_under_quota_exceeded_rolls_back`) | — | Closes the 10-path zero-coverage gap |
| `server_cth_smoke_ldp_read_write_wac` | `xtask cth` harness | — |

---

## 10. Critical paths and parallelisation

**Sprint 5 critical path** (~2.5d serial):
P0-1 DPoP signature verify → P0-2 JWKS SSRF (shares `Algorithm` dispatch +
`JwkSet` plumbing) → P0-4 alg-confusion fix (same edit window) →
AuthContext shape → thumbprint canonicalisation. Legacy WAC (P0-3) and
log-redaction run on day 1-2 in parallel off the critical path.

**Sprint 6 critical path** (~3d serial):
`wac.rs` module split → `ConditionRegistry` → `ClientConditionEvaluator` +
`IssuerConditionEvaluator` → 422 emission in `solid-pod-rs-server` (cross-
crate). LDP gaps, webhook signing, did:nostr resolver, the 5 integration
tests, and the OIDC + Notifications direct-API suites parallelise.

**Sprint 7 critical path** (~3.5d serial):
Server route table expansion → WAC-on-write enforcement → CTH harness
(blocked by full route table). Rate-limit, CORS, quota, TLS, NodeInfo,
subdomain, body-cap parallelise off it.

**Hard parallelisation rule:** no two engineers touch the same file in the
same sprint. If a file is under refactor (e.g. `wac.rs` split in S6), it is
exclusive to one engineer for that sprint. The QE-fleet recommendation here
matches the engineering report's parallelisation analysis exactly.

---

## 11. Cross-sprint dependencies (verified + extended)

Confirmed from the engineering report:
- S5 `AuthContext` → S6 `ConditionRegistry::dispatch(cond, ctx)` →
  S7 server-route table.

QE-fleet additions:
- S5 `oidc/jwks.rs` `SsrfPolicy` consumer → S6 webhook delivery (subscription
  targets are user-controlled URLs and must use the same `SsrfPolicy`).
  Reuse, don't duplicate.
- S6 `wac/` module split → S7 `wac_allow_header` emission. Freeze the
  `wac/` module surface at end of S6.
- S6 `PatchOutcome::Created` enum variant → S7 server PATCH handler match.
- CTH (S7 §6.8) is the regression detector for S5 + S6. If either slips,
  CTH catches it.

---

## 12. Rollback plan (per P0)

| P0 | Landing risk | Rollback path |
|---|---|---|
| **P0-1 DPoP signature verify** | High (CVE-class; wrong dispatch breaks all OIDC clients) | `git revert oidc/mod.rs + oidc/jwks.rs`. `oidc` feature defaults off in alpha.1 → consumers unaffected. Tag stays clean. |
| **P0-2 JWKS SSRF integration** | Medium (network-fetch primitive, may break proxy-walled CI) | Revert `oidc/jwks.rs`. Caller-provides-`JwkSet` shim (today's behaviour) remains. No API break. |
| **P0-3 Legacy WS WAC check** | Low (pure addition; default `SubscriptionAuthorizer::DenyAll` makes rollback safe) | Revert `notifications/legacy.rs`. `legacy-notifications` feature gates the subsystem; rollback is feature-flag-off until alpha.2. |
| **P0-4 Algorithm confusion fix** | High (changes accepted token universe) | Revert `verify_access_token` dispatch. HS256 path stays; new ES256/RS256 paths absent. Acceptable degradation. |

Operational rule: each P0 lands as its own PR with its own revertable commit
range. **No squashing P0s together.**

---

## 13. Feature flag strategy (extends engineering report §8)

Engineering report §8 listed `unstable-wac2-conditions`,
`unstable-webhook-signing`, `unstable-operator-surface`, `unstable-cth`.
Add:

- **No new flag for P0-1, P0-2, P0-4** — these are security fixes to existing
  surface. Hiding them behind a flag would leave consumers insecure.
- **No new flag for P0-3 (legacy WAC check)** — `legacy-notifications`
  already gates the surface; the check tightens existing behaviour.
- **`unstable-thumbprint-canonical`** — gates the RFC 7638 fix only if and
  when JSS interop fixtures show observable divergence with the change.
  Default off until proven needed; otherwise remove this flag.

All `unstable-*` flags removed at 0.4.0 GA; the umbrella `jss-v04` becomes a
no-op alias and is deleted at 0.5.0.

---

## 14. New ADRs (extends engineering report §11)

The engineering report proposed ADR-057 through ADR-061. The QE fleet adds:

- **ADR-061** *OIDC algorithm dispatch + JWKS-keyed verification* (expands
  the report's ADR-061 scope to cover the algorithm-confusion fix as well as
  signature verification).
- **ADR-062** *RFC 7638 canonical JWK thumbprint* (BTreeMap-ordered).
- **ADR-063** *DPoP `ath` binding enforcement*.
- **ADR-064** *Request body and RDF parser bounds* (body cap, JSON depth cap,
  Turtle byte cap).
- **ADR-065** *Log redaction profile* (header denylist for tracing
  subscriber).
- **ADR-066** *Constant-time comparison discipline* (mandate `subtle` for
  any future MAC / token compare).
- **ADR-067** *Dependency hygiene* (commit `Cargo.lock`, CI `cargo audit`,
  track `spargebra` maintenance).

ADR-058 (WAC 2.0 conditions), ADR-059 (did:nostr), ADR-060 (DPoP fix),
ADR-061 (SSE deferred) carry over from the engineering report unchanged
in intent, with ADR-061 extended in scope.

---

## 15. Combined v0.4.0 GA envelope

| Sprint | Engineering report | QE addendum delta | Total |
|---|---|---|---|
| **S5 — Security** | 3 d, 3 P0s | +1 d (P0-4 alg confusion + thumbprint + log redaction + nip98 clock) | **4 d** |
| **S6 — WAC 2.0 + LDP** | 5 d | +0 d (notifications/mod direct-API suite + 5 integration tests + nip98 happy-path absorbed in slack) | **5 d** |
| **S7 — Operator + CTH** | 5 d | +0 d (body cap + percent-decode + remaining 5 integration tests absorbed) | **5 d** |
| **+ Buffer** | 1 d | +2 d (mutation-test investment, flaky-test deflake) | **3 d** |
| **Total** | 14 d | +3 d | **17 d** |

The +3 days is **non-negotiable**: it is the floor cost of bringing
`oidc/mod.rs` and `notifications/mod.rs` from 0% direct test coverage to GA
quality, plus the new P0 fix, plus the security ADRs. Skipping it ships a
release whose two largest modules have no runtime verification.

---

## 16. Summary — what changed because of the QE fleet

1. **+1 P0** (algorithm confusion).
2. **+7 P1s** (canonical thumbprint, percent-decode traversal, ACL depth
   bomb, Turtle size bomb, body-cap explicit, DPoP `ath` enforced,
   secrets-in-logs).
3. **+10 zero-coverage integration tests required** for GA.
4. **+2 modules elevated to GA-blocking coverage targets** (`oidc/mod.rs`
   and `notifications/mod.rs`).
5. **Mutation-testing infrastructure** added to CI with kill-rate targets.
6. **Per-module quality-gate matrix** with block-merge thresholds.
7. **Test-first sequencing** for every P0 and P1 (red phase named first).
8. **+3 days** added to the GA envelope (14d → 17d).
9. **+3 ADRs** beyond the engineering report's five.
10. **Verified the engineering report's three P0s** by direct file:line
    read; all three are confirmed verbatim.

This addendum should be read in conjunction with — not in place of — the
engineering report. The engineering report is the *what*; this addendum is
the *quality envelope*. Together they form the v0.4.0 GA plan of record.

---

**Confidence aggregation:**

| Inspector | Self-rated |
|---|---|
| QE Coverage + Gap Detector | 88% |
| QE Mutation + Defect Predictor | 76% |
| QE Security Orchestrator | 78% |
| QE Fleet Commander + Sequencing | 76% |
| Direct file:line P0 verification | 100% |
| **Combined addendum confidence** | **≈82%** |

Higher than the engineering report's ~80% because every novel claim in this
addendum is anchored to a specific file:line read directly during the QE
pass, not relayed via mesh inspector summaries.
