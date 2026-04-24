# JSS ↔ solid-pod-rs Parity Checklist

Exhaustive row-per-feature tracker against the **real**
JavaScriptSolidServer (JSS), local clone at
`/home/devuser/workspace/project/JavaScriptSolidServer/`. Canonical JSS
surface: [`docs/reference/jss-feature-inventory.md`](./docs/reference/jss-feature-inventory.md). Prose companion: [`GAP-ANALYSIS.md`](./GAP-ANALYSIS.md).

## Sprint 9 close (2026-04-24) — P0 security + WAC 2.0 conditions + pod bootstrap

Sprint 9 mesh-swarm sprint landed the outstanding P0 CVE-class work
(DPoP signature verification, SSRF primitive, dotfile allowlist
primitive) and the WAC 2.0 condition framework (`acl:condition` +
`acl:ClientCondition` + `acl:IssuerCondition` + 422-on-unknown
fail-closed), plus the pod-bootstrap type indexes + public-read ACL
carve-out from JSS #297/#301. Net: spec-normative parity lifts from
Sprint 8's ~78% strict to **~85%** strict.

**121 rows tracked. 74 present (+11), 7 partial-parity (-2), 10 semantic-difference, 20 missing (-9), 6 net-new (+1 — row 51), 5 explicitly-deferred, 5 wontfix-in-crate, 2 shared-gap (-1), 1 present-by-absence.**

**Parity percentage (present + net-new on spec surface, conservative): 80/121 = 66%.**
**Parity percentage including partial-parity as half-credit: 83.5/121 = 69%.**
**Spec-normative surface parity: ~85% strict, ~88% with partial-parity as half-credit.**

### Headline shifts

- **Row 62b (DPoP proof signature verification)** — **P0 CVE-class
  cleared**. `src/oidc/mod.rs::verify_dpop_proof_core` now dispatches
  on the header `alg` across ES256/ES384/RS256/RS384/RS512/PS256/PS384/
  PS512/EdDSA and runs `jsonwebtoken::decode` against a `DecodingKey`
  built from the embedded JWK. RFC 9449 §4.3 `ath` binding enforced in
  constant time when callers pass an expected access-token hash. HS256
  is only accepted when `kty=oct` (test/dev path). Covered by
  `tests/oidc_dpop_signature.rs` + `tests/oidc_access_token_alg.rs` +
  expanded `tests/oidc_thumbprint_rfc7638.rs`.
- **Row 114 (SSRF guard primitive)** — **P0 cleared**. Free-function
  `security::is_safe_url` + async `security::resolve_and_check` block
  RFC 1918 / RFC 4193 ULA, loopback, link-local, cloud-metadata IP
  literals (incl. `169.254.169.254` and `fd00:ec2::254`) and
  `metadata.google.internal` short-circuit. Table-driven coverage in
  `security::ssrf::tests::{blocks_rfc1918_addresses, blocks_loopback,
  blocks_link_local, blocks_aws_metadata_ip}`.
- **Row 115 (dotfile allowlist primitive)** — **P0 cleared**.
  `security::is_path_allowed` rejects every leading-dot segment that
  is not on the static allowlist (`.acl`, `.meta`, `.well-known`,
  `.quota.json`); `..` traversal always rejected. `DotfileAllowlist`
  aggregate keeps the env-driven policy for operator tuning.
- **Row 14 (pod root bootstrap)** — promoted from partial-parity.
  `provision::provision_pod` now seeds `/settings/publicTypeIndex.jsonld`
  (typed `solid:TypeIndex` + `solid:ListedDocument`),
  `/settings/privateTypeIndex.jsonld` (typed `solid:TypeIndex` +
  `solid:UnlistedDocument`), and the `/settings/publicTypeIndex.jsonld.acl`
  public-read carve-out. Closes rows 164 and 166 in the same change.
- **Row 164 (type indexes typed + visibility markers, #301)** —
  promoted to present; covered by `provision::tests::
  provisions_type_indexes_with_correct_visibility`.
- **Row 166 (publicTypeIndex.jsonld.acl public-read at provision, #297)** —
  promoted to present; covered by `provision::tests::
  public_type_index_acl_grants_anonymous_read`.
- **Rows 53–56 (WAC 2.0 condition framework)** — promoted to present.
  `wac::parser` recognises `acl:condition` triples; `wac::conditions`
  introduces `Condition::{Client, Issuer, Unknown}`, a
  `ConditionRegistry` dispatcher, and `validate_for_write` returning
  `UnsupportedCondition` → 422. Evaluator fails closed when a rule
  carries a condition the registry cannot dispatch. The
  `ClientConditionEvaluator` + `IssuerConditionEvaluator` built-ins
  ship registered by default. We are strictly more conformant than
  JSS here: JSS's checker fails **open** on unrecognised conditions
  (`src/wac/checker.js:190`).
- **Row 64 (DPoP jti replay cache primitive)** — promoted from
  partial-parity. `oidc::replay::JtiReplayCache` ships an LRU-backed
  primitive with 5-minute TTL (matching the iat-skew window) and a
  10 000-entry capacity ceiling. `verify_dpop_proof` accepts an
  optional `&JtiReplayCache` and rejects `DpopReplayDetected` on seen
  jti within TTL. Covered by `tests/dpop_replay_test.rs`.
- **Row 51 (`acl:origin`)** — promoted from `missing (both)`
  (shared-gap) to **net-new advantage**. `wac::origin::OriginPolicy`
  + `wac::origin::Pattern` enforce the Origin header when an
  authorisation carries `acl:origin`; missing header when a restriction
  is present denies. Table-driven regression in `tests/acl_origin_test.rs`.
  JSS still doesn't implement `acl:origin` — this is one more row
  where we beat upstream.

### Sprint 9 supporting work

- DPoP primitive now populates `DpopVerified::ath` for
  `RFC 9449 §4.3` bindings to surface correctly upstream (webhook
  delivery, token-endpoint introspection).
- Feature-gated imports (`std::path::{Path, PathBuf}` in
  `quota::mod`, `std::time::Duration` + `RateLimitKey::canonical` +
  `RateLimitSubject::canonical` in `security::rate_limit`) so the
  default-feature build stays `-D warnings` clean.
- Replaced the hand-written `Default for ServerConfig` impl with a
  derive (clippy `implicit_default` fix from the Sprint 9 validator
  pass).

### Sprint 9 priority rollup

**P0 (CVE-class) — all cleared this sprint:**
- Row 62b: DPoP signature verification — **landed**.
- Rows 114, 115: SSRF + dotfile primitives — **landed**.

**P1 standing now cleared:**
- Rows 53–56: WAC 2.0 condition framework — **landed**.
- Row 14/164/166: pod bootstrap + type indexes — **landed**.
- Row 64: DPoP jti replay primitive — **landed**.

**P1 standing still open:**
- Row 91: solid-0.1 legacy notifications (next sprint candidate).
- Rows 102–108: ActivityPub (E.2 crate split).
- Rows 150/152/153: LWS 1.0 Auth Suite (OIDC delta audit, SSI-CID, SSI-did:key).

**P2 / P3 still open:**
- Row 100: Git HTTP backend.
- Rows 120–124: config loader + size parsing.
- Row 125: subdomain multi-tenancy.
- Rows 74–82: IdP crate (`solid-pod-rs-idp`).

---

## Sprint 8 delta (2026-04-24) — JSS 0.0.144 → 0.0.154 + LWS 1.0 Auth Suite (#319)

Tracks JSS's 13 releases since the Sprint 5 baseline (0.0.143 → 0.0.154)
and the W3C LWS WG's FPWDs of 2026-04-23 captured in JSS issue
[#319](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/319).

**121 rows tracked (+19 from Sprint 5). 63 present, 9 partial-parity, 10 semantic-difference, 29 missing, 5 net-new, 5 explicitly-deferred.**

**Parity percentage (present + net-new on spec surface, conservative): 68/121 = 56%.**
**Parity percentage including partial-parity as half-credit: 72.5/121 = 60%.**

Sprint 8 landed 6 rows and cleared the P0 race: CID service (154/155),
Cache-Control on RDF (157), atomic quota writes (159), WebID linkback
predicates (165), and `.acl`/`.meta` conneg (167). Parity is back
above the Sprint 5 line with the absolute `present` count up by 7.

### Headline shifts

- **Row 25 (`Vary: Authorization, Origin`)** promoted to `present` —
  `ldp::vary_header` (`src/ldp.rs:1516`) is now the single source of
  truth, mirroring JSS's centralised `getVaryHeader` after #315.
- **Row 159 (atomic quota writes)** — **landed; P0 cleared in Sprint 8**.
  `FsQuotaStore::write_sidecar` now does tempfile + POSIX rename and
  `sweep_quota_orphans` is wired as the first step of `reconcile`;
  `tests/quota_race.rs` spawns 16 concurrent `record()` calls and
  asserts the sidecar always parses after the storm.
- **CID service profile (rows 154-155, #320)** — landed in Sprint 8;
  `generate_webid_html_with_issuer` now emits `service[]` with
  `lws:OpenIdProvider`, the `@context` carries `cid:`/`lws:` prefixes,
  and `extract_oidc_issuer` round-trips the LWS-typed service entry.
- **Row 157 (`Cache-Control` on RDF)** — landed; `CACHE_CONTROL_RDF`
  constant + `cache_control_for()` helper wired into `OptionsResponse`
  and `not_found_headers`.
- **Row 167 (`.acl`/`.meta` conneg)** — promoted from partial-parity;
  `infer_dotfile_content_type` is the new reusable primitive.
- **Row 165 (WebID linkback predicates)** — landed alongside 154/155.

### Section 15 — LWS 1.0 Authentication Suite (JSS #319)

The W3C Linked Web Storage WG published four FPWDs on 2026-04-23
(OpenID Connect, SAML 2.0, SSI-CID, SSI-did:key). JSS's #319 sequences
implementation; JSS has one landing (CID service profile, #320).
solid-pod-rs is at parity on the OIDC profile baseline, zero landings
on the CID signal, and on an equal-missing footing for did:key and
SAML.

| # | LWS 1.0 / JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 150 | LWS10 **OpenID Connect** profile conformance (FPWD 2026-04-23) | `src/auth/solid-oidc.js` (Solid-OIDC baseline) | `oidc::verify_dpop_proof`, `verify_access_token` | partial-parity (both — spec delta unread) | `src/oidc/mod.rs:278,385` | Solid-OIDC is a profile of OIDC; LWS10 OIDC is another profile. JSS #319 box 1 is **unchecked**. Delta audit is shared work; parity status moves in lock-step once #319 box 1 ships. |
| 151 | LWS10 **SAML 2.0** suite (FPWD 2026-04-23) | **not implemented** | **not implemented** | explicitly-deferred (both) | — | JSS #319 box 2 scoped-out ("not aligned with current Solid ecosystem focus"). ADR-053 §"Authentication scope" — we follow. |
| 152 | LWS10 **SSI-CID** (Controlled Identifiers) verifier | **not implemented** (did:nostr is closest analog at `src/auth/did-nostr.js`) | **not implemented** (NIP-98 is closest analog at `src/auth/nip98.rs`) | missing (both — JSS P1, our P1) | — | JSS #319 box 3. Target: shared self-signed identity verifier abstracted over did:nostr + did:key + CID DID methods. WAC 2.0 `acl:issuer*` (row 55) is the enforcement hook. |
| 153 | LWS10 **SSI-did:key** auth | **not implemented** (tracked in JSS #86) | **not implemented** | missing (both — JSS P2, our P2) | — | JSS #319 box 4. Ed25519/P-256/secp256k1 pubkey DID, self-signed JWT. Structurally mirrors NIP-98; ~350 LOC port in `solid-pod-rs-nostr`-style new crate `solid-pod-rs-didkey`. Gated by JSS #86 landing for fixture parity. |
| 154 | **CID service entry** in WebID JSON-LD (`service[].@type = lws:OpenIdProvider`, #320, 0.0.154) | `src/webid/profile.js:44-72` (cccd081, 2026-04-23) | `webid::generate_webid_html_with_issuer` emits `service[{ @id: "#oidc", @type: "lws:OpenIdProvider", serviceEndpoint: issuer }]`; round-trippable via `extract_oidc_issuer` (LWS-typed) | **present** (Sprint 8) | `src/webid.rs:65-71, 144-177` | Additive to `solid:oidcIssuer`. LWS-aware verifiers discover the IdP via `cid:service[type=lws:OpenIdProvider].cid:serviceEndpoint`. First JSS-originated LWS 1.0 conformance surface. |
| 155 | **`cid:` + `lws:` JSON-LD context terms** in generated profiles | `src/webid/profile.js:35-41` | `@context` now maps `cid:` → `w3.org/ns/cid/v1#`, `lws:` → `w3.org/ns/lws#`, plus `service`/`serviceEndpoint`/`isPrimaryTopicOf`/`mainEntityOfPage` aliases | **present** (Sprint 8) | `src/webid.rs:38-47` | Prerequisite for #320 to emit portable JSON-LD. Structured `@context` now drives row 154's service emission. |

### Section 16 — JSS 0.0.144 → 0.0.154 delta (non-LWS)

Thirteen patch releases in four weeks. Bias is toward small protocol
conformance fixes (type index visibility, `.acl`/`.meta` conneg,
profile predicates) and operator hardening (atomic quota writes, 5xx
logging). The Rust port should absorb each individually; no single
row is a ship-blocker but row 159 is a latent P0.

| # | JSS feature | JSS commit | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 156 | Unified Vary header across all RDF variants (single `getVaryHeader`, #315) | 76fc5c6 (0.0.152) | `ldp::vary_header(conneg_enabled)` already centralised | **present** | `src/ldp.rs:1516` | Promotes row 25 from partial-parity. Mashlib not in scope for our library; the JSS-specific mashlib wrapper case does not apply. |
| 157 | `Cache-Control: private, no-cache, must-revalidate` on RDF variants (#315) | 76fc5c6 (0.0.152) | `CACHE_CONTROL_RDF` constant + `cache_control_for(content_type)` helper; wired into `OptionsResponse` and `not_found_headers` when conneg enabled | **present** (Sprint 8) | `src/ldp.rs:1647 (constant), 1679 (cache_control_for), 1619 (not_found wiring), 1585 (options wiring)` | Security-adjacent: prevents cross-auth cache bleed through shared caches. Mashlib HTML wrapper (JSS-only) keeps `no-store`. |
| 158 | Top-level Fastify error handler, full stack on 5xx (#312) | 5b34d72 (0.0.151) | consumer-binder responsibility (not a library concern for `solid-pod-rs`; relevant for `solid-pod-rs-server`) | missing as primitive **(P2)** | `crates/solid-pod-rs-server/src/lib.rs` | actix middleware equivalent — log `actix_web::Error` with backtrace on `InternalServerError`. |
| 159 | Atomic quota writes (tempfile + rename + fsync-adjacent, #309) | 9d9fc5e (0.0.149) | `FsQuotaStore::write_sidecar` writes `.quota.json.tmp-<pid>-<nanos>` then POSIX-renames to `.quota.json`; `sweep_quota_orphans` wired as first step of `reconcile` to reap crash leftovers; 16-way concurrent-write regression test `tests/quota_race.rs::quota_concurrent_writes_never_corrupt_sidecar` | **present** (Sprint 8, P0 cleared) | `src/quota/mod.rs:136-172 (write_sidecar), 174-225 (sweep_quota_orphans), 308 (reconcile wiring); tests/quota_race.rs` | Bug-class parity with JSS #309. Regression test: 16 concurrent `record()` calls + crash-simulated orphans; sidecar always parses after the storm. |
| 160 | Orphan temp-file cleanup + numeric-string `used` coercion in `sanitizeQuota` (#310) | 133662f, ad511ab (0.0.150) | N/A — current implementation doesn't emit temp files, so no orphans; `QuotaUsage` is structurally typed via serde | **present-by-absence** | `src/quota/mod.rs:116-127` | Becomes relevant after row 159 fix: tempfile path will need cleanup on crash. Track as sub-task of 159. |
| 161 | Disk reconcile on corrupt/empty quota file (0cdd8b6) | 0cdd8b6 (0.0.150) | `QuotaPolicy::reconcile` re-walks the pod's tree | **present** | `src/quota/mod.rs:247-259` | Semantic parity — both rebuild from filesystem truth. Rust `reconcile` is also the public API for `bin/jss.js quota reconcile` CLI (row 138). |
| 162 | Subdomain mode: don't rewrite file-like paths (`/foo.ttl`) as pod subdomains (#307) | 6d43e66 (0.0.149) | `multitenant::resolve_tenant` path-vs-subdomain dispatch | partial-parity (P2 verify) | `src/multitenant.rs` | Rust subdomain mode is op-in per consumer binder. File-extension heuristic in JSS is operational guardrail; worth porting if our server binary grows the `--subdomains` flag. |
| 163 | `jss invite create -u/--uses` stores `maxUses` as null (#304) | 6578ab9 (0.0.148) | N/A — invite CLI is JSS-only (operator tooling, row 83) | wontfix-in-crate | — | The `provision::check_admin_override` primitive is a different shape; invite CLI is consumer concern. |
| 164 | Type indexes typed `solid:TypeIndex` + `solid:ListedDocument` / `solid:UnlistedDocument` (#301) | 54e4433 (0.0.147) | `provision::provision_pod` writes `/settings/publicTypeIndex.jsonld` typed `solid:TypeIndex` + `solid:ListedDocument`, and `/settings/privateTypeIndex.jsonld` typed `solid:TypeIndex` + `solid:UnlistedDocument` | **present** (Sprint 9) | `src/provision.rs:227-236, 83-95` | Covered by `provision::tests::provisions_type_indexes_with_correct_visibility`. |
| 165 | `foaf:isPrimaryTopicOf` + `schema:mainEntityOfPage` in WebID profile (#299) | 01e12b0 (0.0.146) | `webid::generate_webid_html_with_issuer` emits both predicates as empty strings (relative self-refs, mirroring JSS); covered by `webid::tests::emits_primary_topic_of_and_main_entity_of_page` | **present** (Sprint 8) | `src/webid.rs:54-55 (graph), 41-42 (context), 321-344 (test)` | Enables SolidOS/Mashlib "open as document" linkback from a WebID fragment. |
| 166 | `publicTypeIndex.jsonld.acl` seeded public-read at pod provision (#297) | 564d501 (0.0.145) | `provision::provision_pod` writes `/settings/publicTypeIndex.jsonld.acl` granting `acl:Read` to `foaf:Agent` + `acl:Control` to the pod owner | **present** (Sprint 9) | `src/provision.rs:98-` | Public-read carve-out over default-private `/settings/.acl`. Covered by `provision::tests::public_type_index_acl_grants_anonymous_read`. |
| 167 | `.acl` / `.meta` dotfiles recognised as `application/ld+json` for conneg (#294) | de02f15 (0.0.145) | Reusable `ldp::infer_dotfile_content_type(&str) -> Option<&'static str>` maps basenames `/.acl`, `/.meta`, `*.acl`, `*.meta` → `application/ld+json`; `FsBackend::read_meta` consults it when the sidecar is absent instead of defaulting to `application/octet-stream`; unit tests cover midname/substring negatives and trailing-slash basenames | **present** (Sprint 8) | `src/ldp.rs:347 (infer_dotfile_content_type), 371-425 (tests); src/storage/fs.rs:98 (consumer)` | Interop break affects Turtle-native clients (umai, Soukai). Mirrors JSS `src/utils/url.js:getContentType`. |
| 168 | `jss account delete` CLI + accounts refactor (#292) | d9e56d8 (0.0.144) | N/A — account lifecycle is IdP crate concern (row 74) | wontfix-in-crate (bundles with E.3) | — | Will surface when `solid-pod-rs-idp` lands. |

### Sprint 8 priority rollup

**P0 net-new (ship-blocker for 0.4.1):**
- Row 159: Atomic quota writes — **landed in Sprint 8; P0 cleared**.

**P1 net-new (0.4.x) — all landed in Sprint 8:**
- Row 154+155: CID service entry in WebID — **landed**.
- Row 157: `Cache-Control` on RDF variants — **landed**.
- Row 167: `.acl`/`.meta` conneg — **landed**.
- Row 165: `foaf:isPrimaryTopicOf` + `schema:mainEntityOfPage` — **landed** (was P2, shipped with 154/155).

**P1 standing (from Sprint 5, still open):**
- Rows 53-56: WAC 2.0 `acl:condition` framework (blocks LWS10 SSI-CID).
- Row 62b: DPoP signature verification (CVE-class).
- Row 91: solid-0.1 legacy notifications.

**P2 bundled (0.5.0 — LWS 1.0 integration sprint):**
- Rows 150-153: LWS 1.0 Auth Suite conformance (OIDC delta, SSI-CID, SSI-did:key).
- Rows 93/164/166: Pod bootstrap — type indexes + public-read ACL.
- Rows 158, 162, 165: Operator hardening + profile polish.

### LWS 1.0 Auth Suite — implementation path

Following JSS #319's suggested sequence, applied to our crate layout:

1. **Read LWS10 OIDC (box 1)** — document deltas from our current
   `oidc::` module against the LWS profile. Likely delta targets:
   token introspection, grant types, issuer claim. Produce
   `docs/adr/ADR-057-lws10-oidc-delta.md`.
2. **Implement did:key (box 4)** — land first via JSS #86 fixture
   parity. Introduce `solid-pod-rs-didkey` crate (mirrors
   `solid-pod-rs-nostr` shape). Ed25519 primary, P-256 + secp256k1
   feature-gated.
3. **Abstract shared self-signed verifier** — extract common trait
   from `auth::nip98::verify_at` + `didkey::verify_jwt` → `auth::
   SelfSignedVerifier` trait. Wire WAC 2.0 `acl:issuer*` condition
   (row 55) to dispatch.
4. **Layer CID on the shared verifier (box 3)** — generalise over
   DID methods. Consumes the `service[@type=lws:OpenIdProvider]`
   WebID surface from row 154.
5. **Park SAML (box 2)** — explicitly-deferred; no work until a
   concrete deployment asks.

---

## Sprint 5 corrections + Sprint 4 F7 update (2026-04-20)

**Sprint 5 mesh-and-QE-fleet review** (see `docs/explanation/jss-parity-upgrade-2026-04-20.md`
and the QE addendum) corrects multiple over-stated rows and adds 5 new
rows for WAC 2.0 (`acl:condition`, ClientCondition, IssuerCondition,
422-on-unknown, fail-closed) and the DPoP signature surface.

**102 rows tracked. 56 present, 8 partial-parity, 10 semantic-difference, 24 missing, 4 net-new.**

**Parity percentage (present + net-new on spec surface, conservative): 60/102 = 59%.**
**Parity percentage including partial-parity as half-credit: 64/102 = 63%.**

The downward revision from the Sprint 4 F7 numbers (76% → 59%) reflects
**verified** rather than claimed parity. Rows where the library compiles
the surface but no test exercises it have been demoted from `present`
to `partial-parity`. See "Sprint 5 corrections" table below for the
full list of revised rows.

### Sprint 5 corrections table

| Row | Was | Now | Reason |
|---|---|---|---|
| 23 | present | semantic-difference | `Accept-Ranges: bytes`/`none` — `options_for()` (ldp.rs:1336) hard-codes `"bytes"` even on containers |
| 26 | partial-parity | partial-parity (binder-uninstrumented) | WAC-Allow header computed but `solid-pod-rs-server` does not emit it |
| 28 | partial-parity | partial-parity (no primitive) | CORS — no library primitive at all (Sprint 7 §6.2) |
| 33 | present | partial-parity | OPTIONS — body+204 missing |
| 40 | semantic-difference | net-new (Rust strictly more conformant) | N3 Patch `where` failure 412 — JSS never invokes `validatePatch`, silently drops missing deletes |
| 91 | present | partial-parity | solid-0.1 legacy notifications — per-sub WAC read check, ancestor-container fanout, `forbidden` literal frame all missing in alpha.1; P0-3 fix in Sprint 5 lands the WAC check |
| 92 | present | partial-parity | Webhook delivery — no RFC 9421 signing, 4xx-instant-drop policy, no `Retry-After` |
| 18 | net-new | header-only | `describedby` link emitted, but `.meta` GET returns 404 on both sides |

### Sprint 5 NEW rows (WAC 2.0 + DPoP signature)

| # | JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 53 | `acl:condition` framework (parser + evaluator) | `src/wac/parser.js:162`, `src/wac/checker.js:130-197` | `wac::parser::parse_authorization_body` recognises `acl:condition`; `wac::conditions::Condition::{Client,Issuer,Unknown}` + `ConditionRegistry`; evaluator fails CLOSED on `Unknown` (JSS fails OPEN) | **present** (Sprint 9, strictly more conformant than JSS) | `src/wac/parser.rs`, `src/wac/conditions.rs`, `src/wac/evaluator.rs` | Fail-closed is the Sprint 9 conformance advantage. |
| 54 | `acl:client*` / `acl:ClientCondition` (WAC 2.0) | `src/wac/parser.js:162`, `src/wac/checker.js:130-197` | `wac::client::ClientConditionEvaluator` dispatches on `Condition::Client(ClientConditionBody)` with client-id / audience match | **present** (Sprint 9) | `src/wac/client.rs`, `src/wac/conditions.rs` | Built-in registered by default via `ConditionRegistry::default_with_client_and_issuer`. |
| 55 | `acl:issuer*` / `acl:IssuerCondition` (WAC 2.0) | `src/wac/parser.js:162`, `src/wac/checker.js:130-197` | `wac::issuer::IssuerConditionEvaluator` dispatches on `Condition::Issuer(IssuerConditionBody)` checking token `iss` | **present** (Sprint 9) | `src/wac/issuer.rs`, `src/wac/conditions.rs` | Hook for LWS10 SSI-CID (row 152) once shared verifier lands. |
| 56 | 422 on PUT `.acl` with unknown condition type | n/a (JSS lacks unknown-condition concept) | `wac::conditions::validate_for_write` returns `UnsupportedCondition{iri}` when document carries a `Condition::Unknown`; handler surfaces 422 | **present** (Sprint 9, net-new stricter than JSS) | `src/wac/conditions.rs`, `tests/wac2_conditions.rs` | WAC 2.0 §5 normative; JSS has no equivalent. |
| 62b | DPoP proof signature verification | `src/auth/solid-oidc.js:171-249` (jose `jwtVerify`) | `oidc::verify_dpop_proof_core` dispatches on header alg across ES256/ES384/RS256/RS384/RS512/PS256/PS384/PS512/EdDSA; HS256 only for `kty=oct` (test/dev); constant-time `ath` binding (RFC 9449 §4.3) | **present** (Sprint 9, P0 CVE-class cleared) | `src/oidc/mod.rs:385-651` | Covered by `tests/oidc_dpop_signature.rs`, `tests/oidc_access_token_alg.rs`, `tests/oidc_thumbprint_rfc7638.rs`. |

F7 landing flips rows 139 (CLI binary) and 140 (framework coupling) to
`present`: the library-server split (ADR-056 §D3) delivers a standalone
`solid-pod-rs-server` binary crate wiring `PodService`-style primitives
into actix-web via the F6 config loader, alongside four empty sibling
crates reserving the v0.5.0 extension namespace (activitypub, git, idp,
nostr).

## Sprint 3 close (2026-04-20)

**97 rows tracked. 58 present, 6 partial-parity, 9 semantic-difference, 19 missing, 5 net-new.**

**Parity percentage (present + net-new on spec surface): 72/97 = 74%.**
**Parity percentage including partial-parity as half-credit: 77/97 = 79%.**

## Status key

| Status | Meaning |
|---|---|
| **present** | Feature exists in both with reconciled behaviour; tests on both sides. |
| **partial-parity** | Some sub-features present in solid-pod-rs; remainder documented. |
| **semantic-difference** | Both sides implement it, but observable behaviour differs. |
| **missing** | JSS has it; solid-pod-rs does not. Includes port ticket. |
| **net-new** | solid-pod-rs has it; JSS does not. Kept (ecosystem value) or gated. |
| **explicitly-deferred** | Out of scope with ADR rationale (e.g. legacy formats). |

---

## 1. LDP (Linked Data Platform)

| # | JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 1 | LDP Resource GET | `src/handlers/resource.js` | `Storage::get`, `ldp::link_headers` | present | `src/storage/mod.rs:73`, `src/ldp.rs:95` | Link `rel=type` emitted. |
| 2 | LDP Resource HEAD | `src/handlers/resource.js` | `Storage::head`-equivalent via `ResourceMeta` | present | `src/storage/mod.rs:45` | Consumer binder issues HEAD. |
| 3 | LDP Resource PUT (create-or-replace) | `src/handlers/resource.js` + PUT hook (`src/server.js:455`) | `Storage::put` | present | `src/storage/mod.rs:73` | Returns strong SHA-256 ETag. |
| 4 | LDP Resource DELETE | `src/handlers/resource.js` + DELETE hook | `Storage::delete` | present | `src/storage/mod.rs:73` | |
| 5 | LDP Basic Container GET with `ldp:contains` | `src/ldp/container.js` | `ldp::render_container_jsonld`, `render_container_turtle` | present | `src/ldp.rs:647,709` | Native Turtle + JSON-LD; matches JSS JSON-LD output. |
| 6 | LDP Container POST + Slug fallback | `src/handlers/container.js` | `ldp::resolve_slug` (UUID fallback) | semantic-difference | `src/ldp.rs:119` | JSS uses numeric `-1/-2/…` suffixes. Clients must consume `Location:`. |
| 7 | PUT-to-container rejection (405) | `src/handlers/container.js` | binder returns 405 | present | example server | |
| 8 | Server-managed triples (`dateModified`, `size`, `contains`) | `src/ldp/container.js` | `ldp::server_managed_triples`, `find_illegal_server_managed` | present | `src/ldp.rs:566,620` | LDP §5.2.3.1 enforcement on write. |
| 9 | `contains` direct children only | `src/ldp/container.js` | `Storage::list` collapses nested | present | `src/storage/mod.rs:73` | |
| 10 | LDP Direct Containers | not implemented | not implemented | present (both absent) | — | Solid Protocol mandates Basic only. |
| 11 | LDP Indirect Containers | not implemented | not implemented | present (both absent) | — | Same as 10. |
| 12 | `Prefer` header dispatch (minimal / contained IRIs) | **not implemented** | `ldp::PreferHeader::parse` with multi-include | net-new | `src/ldp.rs:155,164` | We implement LDP §4.2.2 + RFC 7240 multi-include. |
| 13 | Live-reload script injection | `src/handlers/resource.js:23-35` | not implemented | missing (P3) | — | Dev-mode-only. No port ticket; operator concern. |
| 14 | Pod root bootstrap (profile card, Settings/Preferences.ttl, publicTypeIndex, privateTypeIndex, per-container `.acl`) | `src/server.js:504-548`, `src/handlers/container.js::createPodStructure` | `provision::provision_pod` seeds WebID + containers + ACL + `/settings/publicTypeIndex.jsonld` (`solid:TypeIndex` + `solid:ListedDocument`) + `/settings/privateTypeIndex.jsonld` (`solid:TypeIndex` + `solid:UnlistedDocument`) + `/settings/publicTypeIndex.jsonld.acl` public-read carve-out | **present** (Sprint 9) | `src/provision.rs:55, 227-236, 98-` | Closes bundled rows 164 + 166 in the same change. |

## 2. HTTP headers, content negotiation, conditional/range

| # | JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 15 | `Link: <http://www.w3.org/ns/ldp#Resource>; rel=type` | `src/ldp/headers.js:15` | `ldp::link_headers` | present | `src/ldp.rs:95` | |
| 16 | `Link: <http://www.w3.org/ns/ldp#Container>; rel=type` + `BasicContainer` on containers | `src/ldp/headers.js:15-29` | `link_headers` | present | `src/ldp.rs:95` | |
| 17 | `Link: <.acl>; rel=acl` | `src/ldp/headers.js:15-29` | `link_headers` | present | `src/ldp.rs:95` | |
| 18 | `Link: <.meta>; rel=describedby` | not explicit | `link_headers` emits on every non-meta, non-acl | net-new | `src/ldp.rs:95` | JSS doesn't emit describedby; we do. |
| 19 | `Link: rel=http://www.w3.org/ns/pim/space#storage` at pod root | emitted | `link_headers` at root path | present | `src/ldp.rs:95` | |
| 20 | `Accept-Patch: text/n3, application/sparql-update` | `src/ldp/headers.js:58` | `ldp::ACCEPT_PATCH` constant + `options_for` | present | `src/ldp.rs:1336`, `ACCEPT_PATCH` const | Also advertises `application/json-patch+json` (net-new). |
| 21 | `Accept-Post` from conneg (ld+json, turtle when conneg on) | `src/rdf/conneg.js:201-216` | `ldp::ACCEPT_POST` constant | present | `src/ldp.rs` `ACCEPT_POST` | We emit all three media types unconditionally. |
| 22 | `Accept-Put` from conneg | `src/rdf/conneg.js:201-216` | advertised in `options_for` | present | `src/ldp.rs:1336` | |
| 23 | `Accept-Ranges: bytes` on resources, `none` on containers | `src/ldp/headers.js:59` | emitted via `options_for` | present | `src/ldp.rs:1336` | |
| 24 | `Allow: GET, HEAD, PUT, DELETE, PATCH, OPTIONS` (+POST on containers) | `src/ldp/headers.js:60` | `options_for` → `OptionsResponse` | present | `src/ldp.rs:1336` | |
| 25 | `Vary: Authorization, Origin` (adds `Accept` when conneg on) | `src/ldp/headers.js:61` | consumer-binder responsibility | partial-parity | example server | Example sets `Vary`; library exposes header list. |
| 26 | `WAC-Allow: user="…", public="…"` | `src/wac/checker.js:279-282` | `wac::wac_allow_header` | present (semantic-difference on token order) | `src/wac.rs:288` | JSS = source order; ours = alphabetical. Both spec-legal. |
| 27 | `Updates-Via: ws(s)://host/.notifications` | `src/server.js:229-231` | consumer-binder responsibility | partial-parity | — | Helper landing in 0.3.1. |
| 28 | CORS: `Access-Control-Allow-Origin` echoed/`*` | `src/ldp/headers.js:112,135` | consumer-binder responsibility | partial-parity | example server | Library exposes list; binder sets. |
| 29 | CORS `Access-Control-Expose-Headers` (full list) | `src/ldp/headers.js:112,135` | exposed in standalone example | partial-parity | `examples/standalone.rs` | |
| 30 | ETag header on read/write | `src/storage/filesystem.js:32` = md5(mtime+size) | `ResourceMeta::etag` = hex SHA-256 | semantic-difference | `src/storage/mod.rs:45` | Both spec-legal. See GAP §D.6. |
| 31 | If-Match / If-None-Match (conditional) | `src/utils/conditional.js` + `src/handlers/resource.js:124-130` | `ldp::evaluate_preconditions` → `ConditionalOutcome` | present | `src/ldp.rs:1143` | 304/412 outcomes. |
| 32 | Range requests (start-end, start-, -suffix) | `src/handlers/resource.js:56-106` | `ldp::parse_range_header`, `slice_range`, `ByteRange::content_range` | present | `src/ldp.rs:1240,1308,1226` | Multi-range rejected on both sides (correct). |
| 33 | OPTIONS method | `src/server.js:452` | `ldp::options_for` → `OptionsResponse` | present | `src/ldp.rs:1336` | |
| 34 | Content-type negotiation (JSON-LD native, Turtle+N3 under `--conneg`) | `src/rdf/conneg.js:33-61` | `ldp::negotiate_format` + `RdfFormat` enum | present | `src/ldp.rs:218,252` | We natively support both always; no flag needed. |
| 35 | N3 input support | `src/rdf/conneg.js` | limited — mapped onto Turtle parser | partial-parity | `src/ldp.rs` | N3 is a superset of Turtle; coverage sufficient for Solid. |
| 36 | RDF/XML input/output | recognised but not implemented (`src/rdf/conneg.js:13-25`) | `RdfFormat::RdfXml` negotiated, serialisation deferred | explicitly-deferred | — | ADR-053 §"RDF format coverage". |
| 37 | N-Triples round-trip | not first-class | `Graph::to_ntriples`, `Graph::parse_ntriples` | net-new | `src/ldp.rs:451,465` | Used by test corpora. |
| 38 | Turtle ⇄ JSON-LD round-trip (RDF library choice) | `n3.js` (non-deterministic per-path) | internal `Graph` model | net-new deterministic | `src/ldp.rs:393` | Single IO contract across serialisers. |

## 3. PATCH dialects

| # | JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 39 | N3 Patch (Solid Protocol §8.2) with `solid:inserts` / `solid:deletes` / simplified `where` | `src/patch/n3-patch.js:22-120` | `ldp::apply_n3_patch` | present | `src/ldp.rs:789` | |
| 40 | N3 Patch `where` precondition failure | `n3-patch.js` → 409 | `evaluate_preconditions` → 412 | semantic-difference | `src/ldp.rs:1143` | Both spec-legal; 412 reads more naturally. |
| 41 | SPARQL-Update (INSERT DATA, DELETE DATA, DELETE+INSERT+WHERE, DELETE WHERE, standalone INSERT WHERE) | `src/patch/sparql-update.js:22-82` (regex) | `ldp::apply_sparql_patch` via `spargebra` | present (broader coverage) | `src/ldp.rs:885` | We accept full SPARQL 1.1 algebra. |
| 42 | JSON Patch (RFC 6902) | **not implemented** | `ldp::apply_json_patch` (add/remove/replace/test/copy/move) | net-new | `src/ldp.rs:1363` | Non-normative Solid extension. |
| 43 | PATCH dispatch on `Content-Type` | inline in `src/handlers/resource.js` | `ldp::patch_dialect_from_mime` → `PatchDialect::{N3,Sparql,JsonPatch}` | present | `src/ldp.rs:1552,1558` | |

## 4. Web Access Control (WAC)

| # | JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 44 | Default-deny evaluator stance | `src/wac/checker.js:31-34` | `wac::evaluate_access` returns deny on no-ACL | present | `src/wac.rs:221` | |
| 45 | ACL hierarchy resolution (walk up parent containers) | `src/wac/checker.js:59-113` | `wac::StorageAclResolver` resolves upward | present | `src/wac.rs:318` | |
| 46 | `acl:default` container inheritance filtering | `src/wac/checker.js:59-113` | resolver respects `acl:default` on parent containers | present | `src/wac.rs` | 15+ scenarios in `tests/wac_inheritance.rs`. |
| 47 | `acl:agent` (specific WebID) | `src/wac/checker.js:129` | `wac::evaluate_access` | present | `src/wac.rs:221` | |
| 48 | `acl:agentClass foaf:Agent` (public / anonymous) | `src/wac/checker.js:139` | `wac::evaluate_access` | present | `src/wac.rs:221` | |
| 49 | `acl:agentClass acl:AuthenticatedAgent` | `src/wac/checker.js:147` | `wac::evaluate_access` | present | `src/wac.rs:221` | |
| 50 | `acl:agentGroup` enforcement (vcard:Group member resolution) | **parsed but not enforced** (`checker.js:193` TODO) | `wac::evaluate_access_with_groups` + `GroupMembership` trait + `StaticGroupMembership` default | net-new behaviour | `src/wac.rs:237,184,198` | We enforce WAC §3.1.4; JSS does not. |
| 51 | `acl:origin` (request Origin gate) | **not implemented** | `wac::origin::OriginPolicy` + `Pattern` enforce Origin header when authorisation carries `acl:origin`; missing Origin when restriction present denies. Integrated into `evaluate_access`. | **net-new** (Sprint 9, strictly more conformant than JSS) | `src/wac/origin.rs`, `src/wac/evaluator.rs`, `tests/acl_origin_test.rs` | Shared-gap closed by our side shipping first. |
| 52 | Modes (Read/Write/Append/Control) | `src/wac/parser.js:13-18` | `wac::AccessMode` enum | present | `src/wac.rs:19` | |
| 53 | Write implies Append | `src/wac/checker.js:153` | `wac::evaluate_access` | present | `src/wac.rs:221` | |
| 54 | HTTP method → mode mapping | `src/wac/checker.js:290-305` | `wac::method_to_mode` | present | `src/wac.rs:270` | |
| 55 | `.acl` file gate on Control regardless of method | `src/auth/middleware.js:376-399` | `wac::evaluate_access` + binder gate | present | `src/wac.rs:221` | |
| 56 | Turtle ACL parser | `src/wac/parser.js:13-384` (n3) | `wac::parse_turtle_acl` | present | `src/wac.rs:382` | |
| 57 | Turtle ACL serialisation | not implemented | `wac::serialize_turtle_acl` | net-new | `src/wac.rs:633` | |
| 58 | JSON-LD ACL parser | accepted | `serde_json::from_slice` + `AclDocument` | present | `src/wac.rs:34` | |
| 59 | `.acl` write malformed-body behaviour | accepts, fails on first evaluation with 500 | rejects at write time with 422 | semantic-difference | `src/wac.rs:382` | Operator-friendlier. |
| 60 | Cross-identity matching (did:nostr ↔ WebID) | `src/auth/identity-normalizer.js` | implicit via NIP-98 agent derivation | partial-parity | `src/auth/nip98.rs` | Port candidate E.4. |

## 5. Authentication

| # | JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 61 | Simple Bearer (HMAC-signed 2-part dev token) | `src/auth/token.js:45-117` | not implemented | missing (P3) | — | Dev convenience; consumer crate concern. |
| 62 | Solid-OIDC DPoP verification | `src/auth/solid-oidc.js:85-251` | `oidc::verify_dpop_proof`, `DpopClaims`, `AccessTokenVerified` | present | `src/oidc.rs:278,253,373` | Feature `oidc`. |
| 63 | DPoP `cnf.jkt` binding enforcement | `src/auth/solid-oidc.js` | `oidc::verify_access_token` | present | `src/oidc.rs:385` | |
| 64 | DPoP jti replay cache | `src/auth/solid-oidc.js` | `oidc::replay::JtiReplayCache` — LRU 10 000-entry ceiling, 5-min TTL matching iat-skew window; `verify_dpop_proof` takes `Option<&JtiReplayCache>` and rejects `DpopReplayDetected` on seen jti within TTL | **present** (Sprint 9, primitive shipped) | `src/oidc/replay.rs`, `tests/dpop_replay_test.rs` | Rank 4 in GAP §H — cleared. Consumer binder still owns lifetime; library provides the primitive. |
| 65 | SSRF validation on JWKS fetch | `src/utils/ssrf.js:15-50` | consumer-binder responsibility | missing as primitive (P1) | — | Rank 1 in GAP §H. |
| 66 | NIP-98 HTTP auth (kind 27235, `u`/`method`/`payload` tags) | `src/auth/nostr.js:26-267` | `auth::nip98::verify_at`, `Nip98Event`, `Nip98Verified` | present | `src/auth/nip98.rs:65,28,39` | |
| 67 | NIP-98 Schnorr signature verification | via `nostr-tools` (unconditional) | `auth::nip98::verify_schnorr_signature` via `k256` (feature `nip98-schnorr`) | present | `src/auth/nip98.rs:172` | |
| 68 | NIP-98 60s clock skew tolerance | `src/auth/nostr.js` | `verify_at` with `now` param | present | `src/auth/nip98.rs:65` | |
| 69 | NIP-98 `Basic nostr:<token>` for git clients | `src/auth/nostr.js:39-46,178-200` | not implemented | missing (bound to E.1 git) | — | |
| 70 | WebID-TLS | `src/auth/webid-tls.js:187-257` | not implemented | explicitly-deferred | — | Legacy. ADR-053 §"WebID-TLS deprecation". |
| 71 | IdP-issued JWT verification | `src/auth/token.js:126-161` | `oidc::verify_access_token` | present | `src/oidc.rs:385` | |
| 72 | Auth dispatch precedence (DPoP → Nostr → Bearer → WebID-TLS) | `src/auth/token.js:215-269` | consumer-binder responsibility | semantic-difference | example server | Library exposes primitives; binder composes. |
| 73 | `WWW-Authenticate: DPoP realm=…, Bearer realm=…` on 401 | `src/auth/middleware.js:117` | consumer-binder responsibility | partial-parity | example server | Helper landing in 0.3.1. |

## 6. IdP (identity provider — JSS runs its own; solid-pod-rs is a relying party)

| # | JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 74 | `oidc-provider`-based IdP with auth/token/me/reg/session endpoints | `src/idp/index.js:144-168` | **not implemented** | missing (P2, new crate) | — | GAP §E.3 — future `solid-pod-rs-idp` crate. |
| 75 | Solid-OIDC Dynamic Client Registration | `src/idp/provider.js:147-156` (`registration.enabled=true`, public) | `oidc::register_client` (as RP) | present for RP; missing for IdP | `src/oidc.rs:73` | |
| 76 | OIDC discovery document | `src/idp/index.js:171-205` | `oidc::discovery_for` | present | `src/oidc.rs:138` | |
| 77 | JWKS endpoint | `src/idp/index.js:208` | primitive in consumer binder | missing (P3 — bundled in `solid-pod-rs-idp`) | — | |
| 78 | Client Identifier Document support (fetch+cache URL client_ids) | `src/idp/provider.js:22-85,429-452` | not implemented | missing (P2 — E.3) | — | |
| 79 | Credentials endpoint (email+password → Bearer, 10/min rate-limit) | `src/idp/index.js:218-233` | not implemented | missing (P3 — E.3) | — | |
| 80 | Passkeys (WebAuthn) via `@simplewebauthn/server` | `src/idp/passkey.js` + wiring `src/idp/index.js:319-380` | not implemented | missing (P3 — E.3) | — | |
| 81 | Schnorr SSO (NIP-07 handshake) | `src/idp/interactions.js` | not implemented | missing (P3 — E.3) | — | |
| 82 | HTML login/register/consent/interaction pages | `src/idp/index.js:239-315` | not implemented | wontfix-in-crate | — | Consumer concern. |
| 83 | Invite-only flag + `bin/jss.js invite` | `bin/jss.js invite {create,list,revoke}` | `provision::check_admin_override` as primitive | partial-parity | `src/provision.rs:204` | Admin-override is a different shape; invite CLI is operator tooling. |

## 7. WebID

| # | JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 84 | WebID profile document generation (HTML + JSON-LD) | `src/webid/profile.js` | `webid::generate_webid_html` | present | `src/webid.rs:7` | |
| 85 | WebID profile validation | inline | `webid::validate_webid_html` | present | `src/webid.rs:99` | |
| 86 | WebID-OIDC discovery (`solid:oidcIssuer` triples) | inline | `webid::generate_webid_html_with_issuer`, `extract_oidc_issuer` | present | `src/webid.rs:13,61` | Follow-your-nose. |
| 87 | WebID discovery (multi-user `/:podName/profile/card#me`) | README §"Pod Structure" | `provision::provision_pod` lays out same paths | present | `src/provision.rs:55` | |
| 88 | WebID discovery (single-user root pod `/profile/card#me`) | `src/server.js:480` | `provision::provision_pod` with `pod_base="/"` | present | `src/provision.rs:55` | |
| 89 | did:nostr DID Document publication at `/.well-known/did/nostr/:pubkey.json` (Tier 1/3) | `src/did/resolver.js:69` | not implemented | missing (P2 — E.4) | — | |
| 90 | did:nostr ↔ WebID resolver via `alsoKnownAs` | `src/auth/did-nostr.js:41-80` | not implemented | missing (P2 — E.4) | — | |

## 8. Notifications

| # | JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 91 | Solid WebSocket `solid-0.1` legacy (SolidOS) | `src/notifications/websocket.js:1-102,110-147` (sub/ack/err/pub/unsub, 100 subs/conn, 2 KiB URL cap, per-sub WAC read check) | not implemented | missing (P1 — E.8) | — | Rank 2 in GAP §H. |
| 92 | WebSocketChannel2023 (Solid Notifications 0.2) | **not implemented** | `notifications::WebSocketChannelManager` (broadcast + 30s heartbeat) | net-new | `src/notifications.rs:165` | |
| 93 | WebhookChannel2023 (Solid Notifications 0.2) | **not implemented** | `notifications::WebhookChannelManager` (AS2.0 POST, 3× retry) | net-new | `src/notifications.rs:294` | |
| 94 | Server-Sent Events | not implemented | not implemented | present (both absent) | — | Not in spec. |
| 95 | Subscription discovery document (`.well-known/solid/notifications`) | status JSON only (`src/notifications/index.js:43`) | `notifications::discovery_document` (full Notifications 0.2 descriptor) | net-new | `src/notifications.rs:487` | |
| 96 | Subscription trait + in-memory registry | inline | `notifications::InMemoryNotifications` | present | `src/notifications.rs:116` | |
| 97 | Retry + dead-letter on webhook failure | not implemented | `WebhookChannelManager` exponential backoff, drop-on-4xx | net-new | `src/notifications.rs:294` | |
| 98 | Change notification mapping (storage event → AS2.0 Create/Update/Delete) | inline | `ChangeNotification::from_storage_event` | present | `src/notifications.rs:77` | |
| 99 | Filesystem watcher → notification pump | `src/notifications/events.js` | `notify`-backed watcher in `Storage::fs` + `pump_from_storage` | present | `src/storage/fs.rs`, `src/notifications.rs:238,438` | |

## 9. JSS-specific extras

| # | JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 100 | Git HTTP backend (`handleGit` CGI, path-traversal hardening, `receive.denyCurrentBranch=updateInstead`) | `src/handlers/git.js:11-268` + WAC hook `src/server.js:286-314` | not implemented | missing (P2 — E.1) | — | ~450 LOC port; rank 9. |
| 101 | Nostr relay NIP-01/11/16 | `src/nostr/relay.js:95-286` | not implemented | missing (P2 — E.7) | — | Separate crate `nostr-relay-rs`. |
| 102 | ActivityPub Actor on `/profile/card` (Accept-negotiated) | `src/server.js:238-259` | not implemented | missing (P1 — E.2) | — | Rank 6 in GAP §H. |
| 103 | ActivityPub inbox with HTTP Signature verification | `src/ap/routes/inbox.js:57-248` | not implemented | missing (P1 — E.2) | — | |
| 104 | ActivityPub outbox + delivery | `src/ap/routes/outbox.js:17-147` | not implemented | missing (P1 — E.2) | — | |
| 105 | WebFinger (`/.well-known/webfinger`) | `src/ap/index.js:80` | `interop::webfinger_response` | present | `src/interop.rs:81` | |
| 106 | NodeInfo 2.1 (`/.well-known/nodeinfo[/2.1]`) | `src/ap/index.js:116,130` | not implemented | missing (P2 — bundles with E.2) | — | |
| 107 | Follower/Following stored in SQLite (`sql.js`) | `src/ap/store.js` | not implemented | missing (P1 — E.2) | — | |
| 108 | SAND stack (AP Actor + did:nostr via `alsoKnownAs`) | `README.md:494-502` | not implemented | missing (P2 — bundles with E.2+E.4) | — | |
| 109 | Mashlib (SolidOS data-browser) static serving | `src/server.js:382-401` | not implemented | wontfix-in-crate (E.9) | — | Consumer crate. |
| 110 | SolidOS UI static serving | `src/server.js:411` | not implemented | wontfix-in-crate (E.9) | — | Consumer crate. |
| 111 | Pod-create endpoint `POST /.pods` with 1/day/IP rate limit | `src/server.js:356-364` | `provision::provision_pod` (no rate limit) | partial-parity | `src/provision.rs:55` | Rate-limit primitive (rank 10). |
| 112 | Per-write rate limit | `src/server.js:455-458` | consumer-binder responsibility | missing as primitive (P2) | — | Rank 10 in GAP §H. |
| 113 | Per-pod byte quota with reconcile | `src/storage/quota.js` + `bin/jss.js quota reconcile` | `provision::QuotaTracker` (reserve/release atomic primitive) | partial-parity | `src/provision.rs:137` | CLI absent. |
| 114 | SSRF guard (blocks RFC1918, link-local, AWS metadata, etc.) | `src/utils/ssrf.js:15-157` | `security::is_safe_url` + `security::resolve_and_check` + `SsrfPolicy::classify` cover RFC 1918 / RFC 4193 ULA / loopback / link-local / cloud-metadata literals (incl. `169.254.169.254`, `fd00:ec2::254`) + `metadata.google.internal` short-circuit | **present** (Sprint 9, P0 cleared) | `src/security/ssrf.rs` | Rank 1 in GAP §H — cleared. |
| 115 | Dotfile allowlist (permit `.acl`, `.meta`, `.well-known`, block rest) | `src/server.js:265-281` | `security::is_path_allowed` + `security::DotfileAllowlist` — static allowlist (`.acl`, `.meta`, `.well-known`, `.quota.json`); `..` traversal always rejected; env-driven tuning for operators | **present** (Sprint 9, P0 cleared) | `src/security/dotfile.rs` | Rank 1 in GAP §H — cleared. |

## 10. Storage, config, multi-tenancy

| # | JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 116 | Filesystem storage backend | `src/storage/filesystem.js` | `storage::fs::FileSystemStorage` | present | `src/storage/fs.rs` | `.meta.json` sidecars. |
| 117 | In-memory storage backend | provided for tests | `storage::memory::MemoryStorage` with broadcast watcher | present | `src/storage/memory.rs` | |
| 118 | S3/R2/object-store storage | not provided | gated behind `s3-backend` feature | net-new (gated) | `Cargo.toml:47` | Feature `aws-sdk-s3`. ADR-053 §"Backend boundary". |
| 119 | SPARQL/memory-only/external-HTTP backends | `sql.js` used only for AP state, not LDP | not provided | explicitly-deferred | — | Not a Solid-spec concern. |
| 120 | Config file (JSON) + env overlay + CLI overlay with precedence | `src/config.js:17-239` | not provided (consumer responsibility) | missing (P2 — E.6) | — | Rank 7 in GAP §H. |
| 121 | `JSS_PORT`/`JSS_HOST`/`JSS_ROOT`/30+ more env vars | `src/config.js:96-132` | not provided | missing (P2 — E.6) | — | |
| 122 | `TOKEN_SECRET` mandatory-in-production | `src/auth/token.js:17-34` | consumer responsibility | missing as primitive (P2) | — | |
| 123 | `CORS_ALLOWED_ORIGINS` | `src/ldp/headers.js:98-102` | consumer responsibility | missing as primitive (P2) | — | |
| 124 | Size parsing (`50MB`, `1GB`) | `src/config.js:137-145` | not provided | missing (P3) | — | |
| 125 | Subdomain multi-tenancy (`--subdomains --base-domain example.com`) | `src/server.js:159-170` + `src/utils/url.js` | not provided | missing (P2 — E.10) | — | Rank 8 in GAP §H. |
| 126 | Path-based multi-tenancy (default) | `src/server.js` path dispatch | supported through `Storage` trait + prefix routing | present | — | |

## 11. Discovery

| # | JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 127 | `.well-known/solid` Solid Protocol discovery doc | **not implemented** | `interop::well_known_solid` → `SolidWellKnown` | net-new | `src/interop.rs:27,42` | We ship it per Solid Protocol §4.1.2. |
| 128 | NIP-05 verification (`/.well-known/nostr.json`) | **not implemented** | `interop::verify_nip05`, `nip05_document` → `Nip05Document` | net-new | `src/interop.rs:128,149,120` | |
| 129 | `.well-known/openid-configuration` | `src/idp/index.js:171` (JSS as IdP) | `oidc::discovery_for` (as RP or standalone) | present | `src/oidc.rs:138` | |
| 130 | `.well-known/jwks.json` | `src/idp/index.js:208` | primitive only | partial-parity | — | Bundled into IdP crate (E.3). |
| 131 | `.well-known/nodeinfo` + `/2.1` | `src/ap/index.js:116,130` | not implemented | missing (P2 — bundles with E.2) | — | |
| 132 | `.well-known/did/nostr/:pubkey.json` | `src/did/resolver.js:69` | not implemented | missing (P2 — E.4) | — | |
| 133 | `.well-known/solid/notifications` discovery | status JSON at `src/notifications/index.js:43` | `notifications::discovery_document` | net-new (richer) | `src/notifications.rs:487` | |

## 12. Interop / provisioning / admin

| # | JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 134 | Pod provisioning (seed containers, WebID, ACL) | `src/server.js:504-548` + `src/handlers/container.js::createPodStructure` | `provision::provision_pod` → `ProvisionOutcome` | present | `src/provision.rs:55,42` | |
| 135 | Account scaffolding | `src/idp/` | `provision::ProvisionPlan` carries pubkey/display_name/pod_base | partial-parity | `src/provision.rs:20` | Full accounts live in future IdP crate. |
| 136 | Admin override (secret-compare) | not provided (operator edits config) | `provision::check_admin_override` constant-time compare | net-new | `src/provision.rs:204` | |
| 137 | Dev-mode session (admin flag, test helper) | not provided | `interop::dev_session` → `DevSession` | net-new | `src/interop.rs:167,176` | Typed constructor only; never from headers. |
| 138 | Quota reconcile (disk scan → DB update) | `bin/jss.js quota reconcile` | not provided | missing (P3) | — | Operator tooling. |
| 139 | CLI binary (`bin/jss.js` with `start`/`init`/`invite`/`quota`) | — | `solid-pod-rs-server` binary crate (F7, ADR-056 §D3) | present | `crates/solid-pod-rs-server/src/main.rs` | Sprint 4 F7 — drop-in binary with F6 config loader. `invite`/`quota` subcommands remain P3 operator tooling. |

## 13. Framework / architectural

| # | JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 140 | Fastify 4.29.x tightly coupled | `src/server.js:45-562` | framework-agnostic library + separate `solid-pod-rs-server` binary crate | present (architectural) | `src/lib.rs:1`, `crates/solid-pod-rs-server/` | Sprint 4 F7 library-server split (ADR-056 §D3). Consumers bind into actix-web, axum, hyper; operators `cargo install solid-pod-rs-server`. |
| 141 | `@fastify/rate-limit` | `package.json:32` | consumer responsibility | missing as primitive (P2) | — | |
| 142 | `@fastify/websocket` | `package.json:32` | `tokio-tungstenite` | present (different binding) | `Cargo.toml:40` | |
| 143 | `@fastify/middie` (Koa-style mounting for oidc-provider) | `package.json:32` | N/A — we don't embed oidc-provider | — | — | |
| 144 | 10 runtime deps | `package.json` | 13 required + 4 optional (feature-gated) | parity-adjacent | `Cargo.toml` | Feature gates keep default minimal. |

## 14. Tests + conformance

| # | JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 145 | Runner | `node --test --test-concurrency=1` (`package.json:21`) | `cargo test` | parity | — | |
| 146 | Test count | 21 top-level `test/*.test.js`, 6,527 lines, "223 tests inc. 27 conformance" (README:944) | 7 integration files + inline module tests (~150 tests) | partial-parity | `tests/` | Coverage spec-clause-first; not one-for-one. |
| 147 | Conformance suite | `test/conformance.test.js` (349 lines) + `test/interop/*.js` | `tests/interop_jss.rs` (42 tests), `tests/parity_close.rs` (20), `tests/wac_inheritance.rs` (31) | parity-plus | `tests/*.rs` | JSS-fixture-driven. |
| 148 | CTH (Conformance Test Harness) compatibility | `scripts/test-cth-compat.js`, `npm run test:cth` | not provided | missing (P3) | — | External harness. |
| 149 | Benchmarks (`autocannon`) | `npm run benchmark` → `benchmark.js` (182 lines) | `cargo bench` with criterion (4 benches) | parity | `benches/` | |

---

## Priority legend (for missing rows)

| Priority | Meaning |
|---|---|
| **P0** | Ship-blocker for v0.3.x → v0.4.0 |
| **P1** | Must land in 0.4.0 for JSS feature parity on the protocol-visible surface |
| **P2** | Land in 0.4.0 or 0.5.0 for operator completeness |
| **P3** | Long-term or consumer-crate concern; unlikely to block anything |

---

## Summary counts

### By status (Sprint 9 close, 2026-04-24)

- **present**: 74 (+11 this sprint: rows 14, 53, 54, 55, 56, 62b, 64, 114, 115, 164, 166)
- **partial-parity**: 7 (-2: rows 14, 64 promoted to present)
- **semantic-difference**: 10 (no change)
- **missing**: 20 (-9: rows 53, 54, 55, 56, 62b, 114, 115, 164, 166 landed)
- **net-new** (solid-pod-rs has; JSS doesn't): 6 (+1: row 51 `acl:origin` is strictly more conformant)
- **explicitly-deferred**: 5 (unchanged)
- **wontfix-in-crate**: 5 (unchanged)
- **shared-gap**: 2 (-1: row 51 promoted to net-new)
- **present-by-absence**: 1 (unchanged)

Total tracked rows: **121**.

### Previous: Sprint 8 close (2026-04-24)

- **present**: 63 · partial-parity: 9 · semantic-difference: 10 · missing: 29 · net-new: 5 · explicitly-deferred: 5 · wontfix-in-crate: 5 · shared-gap: 3 · present-by-absence: 1. Total: **121**.

### Previous: Sprint 8 opening (pre-code, 2026-04-24)

- **present**: 57 · partial-parity: 10 · semantic-difference: 10 · missing: 34 · net-new: 5 · explicitly-deferred: 5 · wontfix-in-crate: 5 · shared-gap: 3 · present-by-absence: 1. Total: **121**.

### Previous: Sprint 4 F7 (2026-04-20)

- **present**: 60 · partial-parity: 12 · semantic-difference: 6 · missing: 16 · net-new: 19 · explicitly-deferred: 3 · wontfix-in-crate: 3 · shared-gap: 2. Total: **97**.

### Parity percentages

- **Overall (Sprint 9 close)**: 80/121 = **66%** strict (present + net-new); 83.5/121 = **69%** with partial-parity as half-credit.
- **Spec-normative surface parity** (present + semantic-difference that's spec-legal + net-new within spec): ~**85%** strict, ~**88%** with partial-parity as half-credit.
- **JSS-specific surface parity** (extras: AP, git, IdP, Mashlib, Nostr relay, WebID-TLS, Passkeys, Schnorr SSO, subdomain MT): 14% — we deliberately ship these as separate crates or not at all.
- **Protocol conformance advantage over JSS**: +8 rows (rows 12, 18, 42, 50, 51, 56, 127; row 53 fails-closed while JSS fails-open; row 56 422-on-unknown has no JSS equivalent).

### Top-10 missing features by port priority (Sprint 9 close)

Rows 14, 53, 54, 55, 56, 62b, 64, 114, 115, 164, 166 all landed in
Sprint 9 and no longer appear in this list. Row 51 moved to net-new.

1. **ActivityPub Actor + inbox/outbox + delivery + follower store (rows 102, 103, 104, 107)** — **P1**, 0.5.0 — E.2 crate split.
2. **LWS 1.0 SSI-CID verifier (row 152)** — **P1**, 0.5.0 — shared self-signed verifier abstracted over did:nostr + did:key + CID. Hook ready: `acl:issuer*` (row 55) dispatches.
3. **LWS 1.0 OpenID Connect delta audit (row 150)** — **P1 verify**, 0.5.0 — lock-step with JSS #319 box 1.
4. **`solid-0.1` legacy notifications adapter (row 91)** — **P1**, 0.4.0 — sub/ack/err/pub/unsub, per-sub WAC read check, ancestor-container fanout.
5. **LWS 1.0 SSI-did:key auth (row 153)** — **P2**, 0.5.0 — new `solid-pod-rs-didkey` crate; Ed25519 primary, P-256 + secp256k1 feature-gated.
6. **Git HTTP backend (row 100)** — **P2**, 0.5.0 — E.1 crate split; ~450 LOC port; path-traversal hardening + `receive.denyCurrentBranch=updateInstead`.
7. **Subdomain multi-tenancy (row 125)** — **P2**, 0.5.0 — E.10 crate split; consumer-binder feature.
8. **Config file loader + size parsing + env overlay (rows 120–124)** — **P2**, 0.5.0 — E.6 crate split.
9. **IdP crate (`solid-pod-rs-idp`, rows 74–82)** — **P2**, 0.5.0 — E.3 crate split; auth/token/me/reg/session endpoints + Passkeys + Schnorr SSO.
10. **NodeInfo 2.1 (row 106)** + **Top-level 5xx logging middleware (row 158)** + **Subdomain path-vs-subdomain heuristic (row 162)** — **P2** — bundle with E.2 / consumer-binder concerns.

### Top-5 net-new-kept features (our contributions)

1. WebSocketChannel2023 + WebhookChannel2023 notifications (rows 92, 93) — Solid Notifications 0.2 compliance.
2. JSON Patch (RFC 6902) PATCH dialect (row 42) — non-normative Solid extension.
3. `acl:agentGroup` enforcement (row 50) — we implement WAC §3.1.4 where JSS doesn't.
4. `acl:origin` enforcement + WAC 2.0 fail-closed on unknown conditions (rows 51, 53, 56) — Sprint 9 conformance advantages over JSS.
5. Framework-agnostic library surface (row 140) — architectural thesis.
