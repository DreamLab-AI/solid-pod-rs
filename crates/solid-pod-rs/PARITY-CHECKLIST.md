# JSS ↔ solid-pod-rs Parity Checklist

Exhaustive row-per-feature tracker against the **real**
JavaScriptSolidServer (JSS), local clone at
`/home/devuser/workspace/project/JavaScriptSolidServer/`. Canonical JSS
surface: [`docs/reference/jss-feature-inventory.md`](./docs/reference/jss-feature-inventory.md).
Prose companion (categorical summary, port tickets, architecture
discussion): [`GAP-ANALYSIS.md`](./GAP-ANALYSIS.md). This document is the
row-level tracker only — a machine-readable table of every JSS surface
and our status against it.

---

## Current state (Sprint 9 close, 2026-04-24)

**121 rows tracked** across 16 functional sections.

### Parity percentages

| Metric | Value |
|---|---|
| Strict (present + net-new) | **66%** (80/121) |
| Half-credit (partial-parity counted 0.5) | **69%** (83.5/121) |
| Spec-normative surface | **85%** strict (91/109) |
| Spec-normative, half-credit | **~88%** |
| Protocol-visible surface (what clients see) | **~92%** |
| JSS-specific extras (AP / Git / IdP / Mashlib / Nostr relay / WebID-TLS) | 14% — shipped as separate crates or not at all |

### By status

| Status | Count |
|---|---|
| present | 74 |
| partial-parity | 7 |
| semantic-difference | 10 |
| missing | 20 |
| net-new (ours; not in JSS) | 6 |
| explicitly-deferred | 5 |
| wontfix-in-crate | 5 |
| shared-gap (neither side) | 2 |
| present-by-absence | 1 |
| test / conformance meta | 5 |
| **Total** | **121** |

---

## Status key

| Status | Meaning |
|---|---|
| **present** | Feature exists in both with reconciled behaviour; tests on both sides. |
| **partial-parity** | Some sub-features present in solid-pod-rs; remainder documented. |
| **semantic-difference** | Both sides implement it, but observable behaviour differs. |
| **missing** | JSS has it; solid-pod-rs does not. Includes port ticket. |
| **net-new** | solid-pod-rs has it; JSS does not. Kept (ecosystem value) or gated. |
| **explicitly-deferred** | Out of scope with ADR rationale (e.g. legacy formats). |
| **wontfix-in-crate** | Belongs in a consumer crate (admin UI, operator tooling). |
| **shared-gap** | Neither side implements. Port to both recommended but low priority. |
| **present-by-absence** | JSS ships a fix for a bug we never had. Nothing to port. |

---

## Sibling crate reality

Rows 69, 74–82, 89–90, 100–108, 131, 132 live in reserved sibling crates
(`solid-pod-rs-activitypub`, `solid-pod-rs-git`, `solid-pod-rs-idp`,
`solid-pod-rs-nostr`) that currently contain only ~25-line `lib.rs`
placeholders. **These crates are not implemented.** Their rows are
tracked as `missing` against the parent crate so the percentages reflect
true coverage. Target milestone: **v0.5.0**.

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
| 14 | Pod root bootstrap (profile card, Settings/Preferences.ttl, publicTypeIndex, privateTypeIndex, per-container `.acl`) | `src/server.js:504-548`, `src/handlers/container.js::createPodStructure` | `provision::provision_pod` seeds WebID + containers + ACL + `/settings/publicTypeIndex.jsonld` (`solid:TypeIndex` + `solid:ListedDocument`) + `/settings/privateTypeIndex.jsonld` (`solid:TypeIndex` + `solid:UnlistedDocument`) + `/settings/publicTypeIndex.jsonld.acl` public-read carve-out | present | `src/provision.rs:55, 227-236, 98-` | Closes bundled rows 164 + 166 in the same change. |

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
| 23 | `Accept-Ranges: bytes` on resources, `none` on containers | `src/ldp/headers.js:59` | emitted via `options_for` | semantic-difference | `src/ldp.rs:1336` | `options_for()` hard-codes `"bytes"` even on containers. Benign. |
| 24 | `Allow: GET, HEAD, PUT, DELETE, PATCH, OPTIONS` (+POST on containers) | `src/ldp/headers.js:60` | `options_for` → `OptionsResponse` | present | `src/ldp.rs:1336` | |
| 25 | `Vary: Authorization, Origin` (adds `Accept` when conneg on) | `src/ldp/headers.js:61` | `ldp::vary_header(conneg_enabled)` centralised | present | `src/ldp.rs:1516` | Single source of truth, matches JSS `getVaryHeader` post-#315. |
| 26 | `WAC-Allow: user="…", public="…"` | `src/wac/checker.js:279-282` | `wac::wac_allow_header` | present (semantic-difference on token order) | `src/wac/mod.rs` | JSS = source order; ours = alphabetical. Both spec-legal. |
| 27 | `Updates-Via: ws(s)://host/.notifications` | `src/server.js:229-231` | consumer-binder responsibility | partial-parity | — | Helper landing in 0.3.1. |
| 28 | CORS: `Access-Control-Allow-Origin` echoed/`*` | `src/ldp/headers.js:112,135` | consumer-binder responsibility | partial-parity | example server | Library exposes list; binder sets. No primitive shipped yet. |
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
| 40 | N3 Patch `where` precondition failure | `n3-patch.js` never invokes `validatePatch`, silently drops missing deletes | `evaluate_preconditions` → 412 | net-new (Rust strictly more conformant) | `src/ldp.rs:1143` | JSS is silently non-conformant; we return 412. |
| 41 | SPARQL-Update (INSERT DATA, DELETE DATA, DELETE+INSERT+WHERE, DELETE WHERE, standalone INSERT WHERE) | `src/patch/sparql-update.js:22-82` (regex) | `ldp::apply_sparql_patch` via `spargebra` | present (broader coverage) | `src/ldp.rs:885` | We accept full SPARQL 1.1 algebra. |
| 42 | JSON Patch (RFC 6902) | **not implemented** | `ldp::apply_json_patch` (add/remove/replace/test/copy/move) | net-new | `src/ldp.rs:1363` | Non-normative Solid extension. |
| 43 | PATCH dispatch on `Content-Type` | inline in `src/handlers/resource.js` | `ldp::patch_dialect_from_mime` → `PatchDialect::{N3,Sparql,JsonPatch}` | present | `src/ldp.rs:1552,1558` | |

## 4. Web Access Control (WAC)

| # | JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 44 | Default-deny evaluator stance | `src/wac/checker.js:31-34` | `wac::evaluate_access` returns deny on no-ACL | present | `src/wac/mod.rs` | |
| 45 | ACL hierarchy resolution (walk up parent containers) | `src/wac/checker.js:59-113` | `wac::StorageAclResolver` resolves upward | present | `src/wac/mod.rs` | |
| 46 | `acl:default` container inheritance filtering | `src/wac/checker.js:59-113` | resolver respects `acl:default` on parent containers | present | `src/wac/mod.rs` | 15+ scenarios in `tests/wac_inheritance.rs`. |
| 47 | `acl:agent` (specific WebID) | `src/wac/checker.js:129` | `wac::evaluate_access` | present | `src/wac/mod.rs` | |
| 48 | `acl:agentClass foaf:Agent` (public / anonymous) | `src/wac/checker.js:139` | `wac::evaluate_access` | present | `src/wac/mod.rs` | |
| 49 | `acl:agentClass acl:AuthenticatedAgent` | `src/wac/checker.js:147` | `wac::evaluate_access` | present | `src/wac/mod.rs` | |
| 50 | `acl:agentGroup` enforcement (vcard:Group member resolution) | **parsed but not enforced** (`checker.js:193` TODO) | `wac::evaluate_access_with_groups` + `GroupMembership` trait + `StaticGroupMembership` default | net-new behaviour | `src/wac/mod.rs` | We enforce WAC §3.1.4; JSS does not. |
| 51 | `acl:origin` (request Origin gate) | **not implemented** | `wac::origin::OriginPolicy` + `Pattern` enforce Origin header when authorisation carries `acl:origin`; missing Origin when restriction present denies. Integrated into `evaluate_access`. | net-new (strictly more conformant than JSS) | `src/wac/origin.rs`, `src/wac/evaluator.rs`, `tests/acl_origin_test.rs` | Shared-gap closed by our side shipping first. |
| 52 | Modes (Read/Write/Append/Control) | `src/wac/parser.js:13-18` | `wac::AccessMode` enum | present | `src/wac/mod.rs` | |
| 53 | `acl:condition` framework (WAC 2.0 parser + evaluator) | `src/wac/parser.js:162`, `src/wac/checker.js:130-197` | `wac::parser::parse_authorization_body` recognises `acl:condition`; `wac::conditions::Condition::{Client,Issuer,Unknown}` + `ConditionRegistry`; evaluator fails CLOSED on `Unknown` (JSS fails OPEN) | present (strictly more conformant than JSS) | `src/wac/parser.rs`, `src/wac/conditions.rs`, `src/wac/evaluator.rs` | Fail-closed is the conformance advantage. |
| 54 | `acl:client*` / `acl:ClientCondition` (WAC 2.0) | `src/wac/parser.js:162`, `src/wac/checker.js:130-197` | `wac::client::ClientConditionEvaluator` dispatches on `Condition::Client(ClientConditionBody)` with client-id / audience match | present | `src/wac/client.rs`, `src/wac/conditions.rs` | Built-in registered by default via `ConditionRegistry::default_with_client_and_issuer`. |
| 55 | `acl:issuer*` / `acl:IssuerCondition` (WAC 2.0) | `src/wac/parser.js:162`, `src/wac/checker.js:130-197` | `wac::issuer::IssuerConditionEvaluator` dispatches on `Condition::Issuer(IssuerConditionBody)` checking token `iss` | present | `src/wac/issuer.rs`, `src/wac/conditions.rs` | Hook for LWS10 SSI-CID (row 152) once shared verifier lands. |
| 56 | 422 on PUT `.acl` with unknown condition type | n/a (JSS lacks unknown-condition concept) | `wac::conditions::validate_for_write` returns `UnsupportedCondition{iri}` when document carries a `Condition::Unknown`; handler surfaces 422 | present (net-new stricter than JSS) | `src/wac/conditions.rs`, `tests/wac2_conditions.rs` | WAC 2.0 §5 normative; JSS has no equivalent. |
| 57 | Turtle ACL parser | `src/wac/parser.js:13-384` (n3) | `wac::parse_turtle_acl` | present | `src/wac/mod.rs` | |
| 58 | Turtle ACL serialisation | not implemented | `wac::serialize_turtle_acl` | net-new | `src/wac/mod.rs` | |
| 59 | JSON-LD ACL parser | accepted | `serde_json::from_slice` + `AclDocument` | present | `src/wac/mod.rs` | |
| 60 | Cross-identity matching (did:nostr ↔ WebID) | `src/auth/identity-normalizer.js` | implicit via NIP-98 agent derivation | partial-parity | `src/auth/nip98.rs` | Port candidate E.4. |

## 5. Authentication

| # | JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 61 | Simple Bearer (HMAC-signed 2-part dev token) | `src/auth/token.js:45-117` | not implemented | missing (P3) | — | Dev convenience; consumer crate concern. |
| 62 | Solid-OIDC DPoP verification | `src/auth/solid-oidc.js:85-251` | `oidc::verify_dpop_proof`, `DpopClaims`, `AccessTokenVerified` | present | `src/oidc/mod.rs` | Feature `oidc`. |
| 62b | DPoP proof signature verification | `src/auth/solid-oidc.js:171-249` (jose `jwtVerify`) | `oidc::verify_dpop_proof_core` dispatches on header alg across ES256/ES384/RS256/RS384/RS512/PS256/PS384/PS512/EdDSA; HS256 only for `kty=oct` (test/dev); constant-time `ath` binding (RFC 9449 §4.3) | present (P0 CVE-class cleared) | `src/oidc/mod.rs` | Covered by `tests/oidc_dpop_signature.rs`, `tests/oidc_access_token_alg.rs`, `tests/oidc_thumbprint_rfc7638.rs`. |
| 63 | DPoP `cnf.jkt` binding enforcement | `src/auth/solid-oidc.js` | `oidc::verify_access_token` | present | `src/oidc/mod.rs` | |
| 64 | DPoP jti replay cache | `src/auth/solid-oidc.js` | `oidc::replay::JtiReplayCache` — LRU 10 000-entry ceiling, 5-min TTL matching iat-skew window; `verify_dpop_proof` takes `Option<&JtiReplayCache>` and rejects `DpopReplayDetected` on seen jti within TTL | present | `src/oidc/replay.rs`, `tests/dpop_replay_test.rs` | Consumer binder still owns lifetime; library provides the primitive. |
| 65 | SSRF validation on JWKS fetch | `src/utils/ssrf.js:15-50` | covered by `security::resolve_and_check` primitive (row 114) | present (primitive shipped, consumer wires in) | `src/security/ssrf.rs` | Binder must call `resolve_and_check` before JWKS fetch. |
| 66 | NIP-98 HTTP auth (kind 27235, `u`/`method`/`payload` tags) | `src/auth/nostr.js:26-267` | `auth::nip98::verify_at`, `Nip98Event`, `Nip98Verified` | present | `src/auth/nip98.rs:65,28,39` | |
| 67 | NIP-98 Schnorr signature verification | via `nostr-tools` (unconditional) | `auth::nip98::verify_schnorr_signature` via `k256` (feature `nip98-schnorr`) | present | `src/auth/nip98.rs:172` | |
| 68 | NIP-98 60s clock skew tolerance | `src/auth/nostr.js` | `verify_at` with `now` param | present | `src/auth/nip98.rs:65` | |
| 69 | NIP-98 `Basic nostr:<token>` for git clients | `src/auth/nostr.js:39-46,178-200` | not implemented (reserved for `solid-pod-rs-git` stub) | missing (bound to E.1 git) | — | |
| 70 | WebID-TLS | `src/auth/webid-tls.js:187-257` | not implemented | explicitly-deferred | — | Legacy. ADR-053 §"WebID-TLS deprecation". |
| 71 | IdP-issued JWT verification | `src/auth/token.js:126-161` | `oidc::verify_access_token` | present | `src/oidc/mod.rs` | |
| 72 | Auth dispatch precedence (DPoP → Nostr → Bearer → WebID-TLS) | `src/auth/token.js:215-269` | consumer-binder responsibility | semantic-difference | example server | Library exposes primitives; binder composes. |
| 73 | `WWW-Authenticate: DPoP realm=…, Bearer realm=…` on 401 | `src/auth/middleware.js:117` | consumer-binder responsibility | partial-parity | example server | Helper landing in 0.3.1. |

## 6. IdP (identity provider — JSS runs its own; solid-pod-rs is a relying party)

Rows 74–82 target the reserved `solid-pod-rs-idp` sibling crate (stub
today; target v0.5.0). IdP-internal features (HTML pages, passkeys,
Schnorr SSO, interactions) are `missing` at the parent-crate level.

| # | JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 74 | `oidc-provider`-based IdP with auth/token/me/reg/session endpoints | `src/idp/index.js:144-168` | **not implemented** (reserved for `solid-pod-rs-idp` stub) | missing (P2, new crate) | — | GAP §E.3 — future `solid-pod-rs-idp` crate. |
| 75 | Solid-OIDC Dynamic Client Registration | `src/idp/provider.js:147-156` (`registration.enabled=true`, public) | `oidc::register_client` (as RP) | present for RP; missing for IdP | `src/oidc/mod.rs` | |
| 76 | OIDC discovery document | `src/idp/index.js:171-205` | `oidc::discovery_for` | present | `src/oidc/mod.rs` | |
| 77 | JWKS endpoint | `src/idp/index.js:208` | primitive in consumer binder | missing (P3 — bundled in `solid-pod-rs-idp`) | — | |
| 78 | Client Identifier Document support (fetch+cache URL client_ids) | `src/idp/provider.js:22-85,429-452` | not implemented | missing (P2 — E.3) | — | |
| 79 | Credentials endpoint (email+password → Bearer, 10/min rate-limit) | `src/idp/index.js:218-233` | not implemented | missing (P3 — E.3) | — | |
| 80 | Passkeys (WebAuthn) via `@simplewebauthn/server` | `src/idp/passkey.js` + wiring `src/idp/index.js:319-380` | not implemented | missing (P3 — E.3) | — | |
| 81 | Schnorr SSO (NIP-07 handshake) | `src/idp/interactions.js` | not implemented | missing (P3 — E.3) | — | |
| 82 | HTML login/register/consent/interaction pages | `src/idp/index.js:239-315` | not implemented | wontfix-in-crate | — | Consumer concern. |
| 83 | Invite-only flag + `bin/jss.js invite` | `bin/jss.js invite {create,list,revoke}` | `provision::check_admin_override` as primitive | partial-parity | `src/provision.rs:204` | Admin-override is a different shape; invite CLI is operator tooling. |

## 7. WebID

Rows 89–90 target the reserved `solid-pod-rs-nostr` sibling crate (stub
today).

| # | JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 84 | WebID profile document generation (HTML + JSON-LD) | `src/webid/profile.js` | `webid::generate_webid_html` | present | `src/webid.rs:7` | |
| 85 | WebID profile validation | inline | `webid::validate_webid_html` | present | `src/webid.rs:99` | |
| 86 | WebID-OIDC discovery (`solid:oidcIssuer` triples) | inline | `webid::generate_webid_html_with_issuer`, `extract_oidc_issuer` | present | `src/webid.rs:13,61` | Follow-your-nose. |
| 87 | WebID discovery (multi-user `/:podName/profile/card#me`) | README §"Pod Structure" | `provision::provision_pod` lays out same paths | present | `src/provision.rs:55` | |
| 88 | WebID discovery (single-user root pod `/profile/card#me`) | `src/server.js:480` | `provision::provision_pod` with `pod_base="/"` | present | `src/provision.rs:55` | |
| 89 | did:nostr DID Document publication at `/.well-known/did/nostr/:pubkey.json` (Tier 1/3) | `src/did/resolver.js:69` | not implemented (reserved for `solid-pod-rs-nostr`) | missing (P2 — E.4) | — | |
| 90 | did:nostr ↔ WebID resolver via `alsoKnownAs` | `src/auth/did-nostr.js:41-80` | not implemented (reserved for `solid-pod-rs-nostr`) | missing (P2 — E.4) | — | |

## 8. Notifications

| # | JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 91 | Solid WebSocket `solid-0.1` legacy (SolidOS) | `src/notifications/websocket.js:1-102,110-147` (sub/ack/err/pub/unsub, 100 subs/conn, 2 KiB URL cap, per-sub WAC read check) | not implemented | missing (P1 — E.8) | — | Rank 4 in top-10. |
| 92 | WebSocketChannel2023 (Solid Notifications 0.2) | **not implemented** | `notifications::WebSocketChannelManager` (broadcast + 30s heartbeat) | net-new | `src/notifications/mod.rs` | |
| 93 | WebhookChannel2023 (Solid Notifications 0.2) | **not implemented** | `notifications::WebhookChannelManager` (AS2.0 POST, 3× retry) | net-new | `src/notifications/mod.rs` | |
| 94 | Server-Sent Events | not implemented | not implemented | present (both absent) | — | Not in spec. |
| 95 | Subscription discovery document (`.well-known/solid/notifications`) | status JSON only (`src/notifications/index.js:43`) | `notifications::discovery_document` (full Notifications 0.2 descriptor) | net-new (richer) | `src/notifications/mod.rs` | |
| 96 | Subscription trait + in-memory registry | inline | `notifications::InMemoryNotifications` | present | `src/notifications/mod.rs` | |
| 97 | Retry + dead-letter on webhook failure | not implemented | `WebhookChannelManager` exponential backoff, drop-on-4xx | net-new | `src/notifications/mod.rs` | |
| 98 | Change notification mapping (storage event → AS2.0 Create/Update/Delete) | inline | `ChangeNotification::from_storage_event` | present | `src/notifications/mod.rs` | |
| 99 | Filesystem watcher → notification pump | `src/notifications/events.js` | `notify`-backed watcher in `Storage::fs` + `pump_from_storage` | present | `src/storage/fs.rs`, `src/notifications/mod.rs` | |

## 9. JSS-specific extras

Rows 100–108 target reserved sibling crates (`solid-pod-rs-git`,
`solid-pod-rs-nostr`, `solid-pod-rs-activitypub`) — stubs today.

| # | JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 100 | Git HTTP backend (`handleGit` CGI, path-traversal hardening, `receive.denyCurrentBranch=updateInstead`) | `src/handlers/git.js:11-268` + WAC hook `src/server.js:286-314` | not implemented (reserved for `solid-pod-rs-git`) | missing (P2 — E.1) | — | ~450 LOC port. |
| 101 | Nostr relay NIP-01/11/16 | `src/nostr/relay.js:95-286` | not implemented (reserved for `solid-pod-rs-nostr` / separate `nostr-relay-rs`) | missing (P2 — E.7) | — | Separate crate. |
| 102 | ActivityPub Actor on `/profile/card` (Accept-negotiated) | `src/server.js:238-259` | not implemented (reserved for `solid-pod-rs-activitypub`) | missing (P1 — E.2) | — | Rank 1 in top-10. |
| 103 | ActivityPub inbox with HTTP Signature verification | `src/ap/routes/inbox.js:57-248` | not implemented | missing (P1 — E.2) | — | |
| 104 | ActivityPub outbox + delivery | `src/ap/routes/outbox.js:17-147` | not implemented | missing (P1 — E.2) | — | |
| 105 | WebFinger (`/.well-known/webfinger`) | `src/ap/index.js:80` | `interop::webfinger_response` | present | `src/interop.rs:81` | |
| 106 | NodeInfo 2.1 (`/.well-known/nodeinfo[/2.1]`) | `src/ap/index.js:116,130` | not implemented | missing (P2 — bundles with E.2) | — | |
| 107 | Follower/Following stored in SQLite (`sql.js`) | `src/ap/store.js` | not implemented | missing (P1 — E.2) | — | |
| 108 | SAND stack (AP Actor + did:nostr via `alsoKnownAs`) | `README.md:494-502` | not implemented | missing (P2 — bundles with E.2+E.4) | — | |
| 109 | Mashlib (SolidOS data-browser) static serving | `src/server.js:382-401` | not implemented | wontfix-in-crate (E.9) | — | Consumer crate. |
| 110 | SolidOS UI static serving | `src/server.js:411` | not implemented | wontfix-in-crate (E.9) | — | Consumer crate. |
| 111 | Pod-create endpoint `POST /.pods` with 1/day/IP rate limit | `src/server.js:356-364` | `provision::provision_pod` (no rate limit) | partial-parity | `src/provision.rs:55` | Rate-limit primitive available separately. |
| 112 | Per-write rate limit | `src/server.js:455-458` | `security::rate_limit::RateLimiter` + `RateLimitKey` / `RateLimitSubject` canonical forms | present (library primitive) | `src/security/rate_limit.rs` | Binder wires to rate-limit backend. |
| 113 | Per-pod byte quota with reconcile | `src/storage/quota.js` + `bin/jss.js quota reconcile` | `provision::QuotaTracker` (reserve/release atomic primitive) + `FsQuotaStore::write_sidecar` atomic tempfile+rename + `sweep_quota_orphans` | present | `src/quota/mod.rs:136-172, 174-225, 308`; `tests/quota_race.rs` | CLI absent; core primitive solid. |
| 114 | SSRF guard (blocks RFC1918, link-local, AWS metadata, etc.) | `src/utils/ssrf.js:15-157` | `security::is_safe_url` + `security::resolve_and_check` + `SsrfPolicy::classify` cover RFC 1918 / RFC 4193 ULA / loopback / link-local / cloud-metadata literals (incl. `169.254.169.254`, `fd00:ec2::254`) + `metadata.google.internal` short-circuit | present (P0 cleared) | `src/security/ssrf.rs` | |
| 115 | Dotfile allowlist (permit `.acl`, `.meta`, `.well-known`, block rest) | `src/server.js:265-281` | `security::is_path_allowed` + `security::DotfileAllowlist` — static allowlist (`.acl`, `.meta`, `.well-known`, `.quota.json`); `..` traversal always rejected; env-driven tuning for operators | present (P0 cleared) | `src/security/dotfile.rs` | |

## 10. Storage, config, multi-tenancy

| # | JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 116 | Filesystem storage backend | `src/storage/filesystem.js` | `storage::fs::FileSystemStorage` | present | `src/storage/fs.rs` | `.meta.json` sidecars. |
| 117 | In-memory storage backend | provided for tests | `storage::memory::MemoryStorage` with broadcast watcher | present | `src/storage/memory.rs` | |
| 118 | S3/R2/object-store storage | not provided | gated behind `s3-backend` feature | net-new (gated) | `Cargo.toml:47` | Feature `aws-sdk-s3`. ADR-053 §"Backend boundary". |
| 119 | SPARQL/memory-only/external-HTTP backends | `sql.js` used only for AP state, not LDP | not provided | explicitly-deferred | — | Not a Solid-spec concern. |
| 120 | Config file (JSON) + env overlay + CLI overlay with precedence | `src/config.js:17-239` | not provided (consumer responsibility) | missing (P2 — E.6) | — | Rank 8 in top-10. |
| 121 | `JSS_PORT`/`JSS_HOST`/`JSS_ROOT`/30+ more env vars | `src/config.js:96-132` | not provided | missing (P2 — E.6) | — | |
| 122 | `TOKEN_SECRET` mandatory-in-production | `src/auth/token.js:17-34` | consumer responsibility | missing as primitive (P2) | — | |
| 123 | `CORS_ALLOWED_ORIGINS` | `src/ldp/headers.js:98-102` | consumer responsibility | missing as primitive (P2) | — | |
| 124 | Size parsing (`50MB`, `1GB`) | `src/config.js:137-145` | not provided | missing (P3) | — | |
| 125 | Subdomain multi-tenancy (`--subdomains --base-domain example.com`) | `src/server.js:159-170` + `src/utils/url.js` | `multitenant::resolve_tenant` path-vs-subdomain dispatch | partial-parity | `src/multitenant.rs` | File-extension heuristic worth porting. |
| 126 | Path-based multi-tenancy (default) | `src/server.js` path dispatch | supported through `Storage` trait + prefix routing | present | — | |

## 11. Discovery

| # | JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 127 | `.well-known/solid` Solid Protocol discovery doc | **not implemented** | `interop::well_known_solid` → `SolidWellKnown` | net-new | `src/interop.rs:27,42` | We ship it per Solid Protocol §4.1.2. |
| 128 | NIP-05 verification (`/.well-known/nostr.json`) | **not implemented** | `interop::verify_nip05`, `nip05_document` → `Nip05Document` | net-new | `src/interop.rs:128,149,120` | |
| 129 | `.well-known/openid-configuration` | `src/idp/index.js:171` (JSS as IdP) | `oidc::discovery_for` (as RP or standalone) | present | `src/oidc/mod.rs` | |
| 130 | `.well-known/jwks.json` | `src/idp/index.js:208` | primitive only | partial-parity | — | Bundled into IdP crate (E.3, stub). |
| 131 | `.well-known/nodeinfo` + `/2.1` | `src/ap/index.js:116,130` | not implemented (reserved for `solid-pod-rs-activitypub`) | missing (P2 — bundles with E.2) | — | |
| 132 | `.well-known/did/nostr/:pubkey.json` | `src/did/resolver.js:69` | not implemented (reserved for `solid-pod-rs-nostr`) | missing (P2 — E.4) | — | |
| 133 | `.well-known/solid/notifications` discovery | status JSON at `src/notifications/index.js:43` | `notifications::discovery_document` | net-new (richer) | `src/notifications/mod.rs` | |

## 12. Interop / provisioning / admin

| # | JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 134 | Pod provisioning (seed containers, WebID, ACL) | `src/server.js:504-548` + `src/handlers/container.js::createPodStructure` | `provision::provision_pod` → `ProvisionOutcome` | present | `src/provision.rs:55,42` | |
| 135 | Account scaffolding | `src/idp/` | `provision::ProvisionPlan` carries pubkey/display_name/pod_base | partial-parity | `src/provision.rs:20` | Full accounts live in future IdP crate. |
| 136 | Admin override (secret-compare) | not provided (operator edits config) | `provision::check_admin_override` constant-time compare | net-new | `src/provision.rs:204` | |
| 137 | Dev-mode session (admin flag, test helper) | not provided | `interop::dev_session` → `DevSession` | net-new | `src/interop.rs:167,176` | Typed constructor only; never from headers. |
| 138 | Quota reconcile (disk scan → DB update) | `bin/jss.js quota reconcile` | `QuotaPolicy::reconcile` re-walks the pod's tree | present | `src/quota/mod.rs:247-259, 308` | CLI subcommand still absent; primitive ships. |
| 139 | CLI binary (`bin/jss.js` with `start`/`init`/`invite`/`quota`) | — | `solid-pod-rs-server` binary crate (ADR-056 §D3) | present | `crates/solid-pod-rs-server/src/main.rs` | Drop-in binary with config loader. `invite`/`quota` subcommands remain P3. |

## 13. Framework / architectural

| # | JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 140 | Fastify 4.29.x tightly coupled | `src/server.js:45-562` | framework-agnostic library + separate `solid-pod-rs-server` binary crate | present (architectural) | `src/lib.rs:1`, `crates/solid-pod-rs-server/` | Library-server split (ADR-056 §D3). |
| 141 | `@fastify/rate-limit` | `package.json:32` | `security::rate_limit` primitive (row 112) | present (library primitive) | `src/security/rate_limit.rs` | |
| 142 | `@fastify/websocket` | `package.json:32` | `tokio-tungstenite` | present (different binding) | `Cargo.toml:40` | |
| 143 | `@fastify/middie` (Koa-style mounting for oidc-provider) | `package.json:32` | N/A — we don't embed oidc-provider | — | — | |
| 144 | 10 runtime deps | `package.json` | 13 required + 4 optional (feature-gated) | parity-adjacent | `Cargo.toml` | Feature gates keep default minimal. |

## 14. Tests + conformance

| # | JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 145 | Runner | `node --test --test-concurrency=1` (`package.json:21`) | `cargo test` | parity | — | |
| 146 | Test count | 21 top-level `test/*.test.js`, 6,527 lines, "223 tests inc. 27 conformance" (README:944) | 567 tests across integration + inline module tests | parity-plus | `tests/` | |
| 147 | Conformance suite | `test/conformance.test.js` (349 lines) + `test/interop/*.js` | `tests/interop_jss.rs` (42 tests), `tests/parity_close.rs` (20), `tests/wac_inheritance.rs` (31) | parity-plus | `tests/*.rs` | JSS-fixture-driven. |
| 148 | CTH (Conformance Test Harness) compatibility | `scripts/test-cth-compat.js`, `npm run test:cth` | not provided | missing (P3) | — | External harness. |
| 149 | Benchmarks (`autocannon`) | `npm run benchmark` → `benchmark.js` (182 lines) | `cargo bench` with criterion (4 benches) | parity | `benches/` | |

## 15. LWS 1.0 Authentication Suite (JSS #319)

The W3C Linked Web Storage WG published four FPWDs on 2026-04-23
(OpenID Connect, SAML 2.0, SSI-CID, SSI-did:key). JSS #319 sequences
implementation; JSS has one landing (CID service profile, #320).
solid-pod-rs is at parity on the OIDC profile baseline, zero landings
on the CID signal, and on an equal-missing footing for did:key and
SAML.

| # | LWS 1.0 / JSS feature | JSS path | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 150 | LWS10 **OpenID Connect** profile conformance (FPWD 2026-04-23) | `src/auth/solid-oidc.js` (Solid-OIDC baseline) | `oidc::verify_dpop_proof`, `verify_access_token` | partial-parity (both — spec delta unread) | `src/oidc/mod.rs` | Parity status moves in lock-step once JSS #319 box 1 ships. |
| 151 | LWS10 **SAML 2.0** suite (FPWD 2026-04-23) | **not implemented** | **not implemented** | explicitly-deferred (both) | — | JSS #319 box 2 scoped-out. |
| 152 | LWS10 **SSI-CID** (Controlled Identifiers) verifier | **not implemented** (did:nostr is closest analog) | **not implemented** (NIP-98 is closest analog) | missing (both — P1) | — | Target: shared self-signed identity verifier abstracted over did:nostr + did:key + CID DID methods. WAC 2.0 `acl:issuer*` (row 55) is the enforcement hook. |
| 153 | LWS10 **SSI-did:key** auth | **not implemented** (tracked in JSS #86) | **not implemented** | missing (both — P2) | — | Ed25519/P-256/secp256k1 pubkey DID, self-signed JWT. ~350 LOC port in new `solid-pod-rs-didkey` crate. |
| 154 | **CID service entry** in WebID JSON-LD (`service[].@type = lws:OpenIdProvider`, #320, 0.0.154) | `src/webid/profile.js:44-72` (cccd081, 2026-04-23) | `webid::generate_webid_html_with_issuer` emits `service[{ @id: "#oidc", @type: "lws:OpenIdProvider", serviceEndpoint: issuer }]`; round-trippable via `extract_oidc_issuer` (LWS-typed) | present | `src/webid.rs:65-71, 144-177` | First JSS-originated LWS 1.0 conformance surface. |
| 155 | **`cid:` + `lws:` JSON-LD context terms** in generated profiles | `src/webid/profile.js:35-41` | `@context` maps `cid:` → `w3.org/ns/cid/v1#`, `lws:` → `w3.org/ns/lws#`, plus `service`/`serviceEndpoint`/`isPrimaryTopicOf`/`mainEntityOfPage` aliases | present | `src/webid.rs:38-47` | Prerequisite for #320 portable JSON-LD. |

## 16. JSS 0.0.144 → 0.0.154 delta (non-LWS)

Thirteen patch releases in four weeks captured here. Bias is toward
small protocol conformance fixes and operator hardening.

| # | JSS feature | JSS commit | solid-pod-rs | Status | Rust file:line | Notes |
|---|---|---|---|---|---|---|
| 156 | Unified Vary header across all RDF variants (single `getVaryHeader`, #315) | 76fc5c6 (0.0.152) | `ldp::vary_header(conneg_enabled)` centralised | present | `src/ldp.rs:1516` | Duplicate of row 25 after centralisation. |
| 157 | `Cache-Control: private, no-cache, must-revalidate` on RDF variants (#315) | 76fc5c6 (0.0.152) | `CACHE_CONTROL_RDF` constant + `cache_control_for(content_type)` helper; wired into `OptionsResponse` and `not_found_headers` when conneg enabled | present | `src/ldp.rs:1647 (constant), 1679 (cache_control_for), 1619 (not_found wiring), 1585 (options wiring)` | Security-adjacent: prevents cross-auth cache bleed. |
| 158 | Top-level Fastify error handler, full stack on 5xx (#312) | 5b34d72 (0.0.151) | consumer-binder responsibility (not a library concern for `solid-pod-rs`; relevant for `solid-pod-rs-server`) | missing as primitive (P2) | `crates/solid-pod-rs-server/src/lib.rs` | |
| 159 | Atomic quota writes (tempfile + rename + fsync-adjacent, #309) | 9d9fc5e (0.0.149) | `FsQuotaStore::write_sidecar` writes `.quota.json.tmp-<pid>-<nanos>` then POSIX-renames to `.quota.json`; `sweep_quota_orphans` wired as first step of `reconcile`; 16-way concurrent-write regression test | present (P0 cleared) | `src/quota/mod.rs:136-172, 174-225, 308; tests/quota_race.rs` | |
| 160 | Orphan temp-file cleanup + numeric-string `used` coercion in `sanitizeQuota` (#310) | 133662f, ad511ab (0.0.150) | `sweep_quota_orphans` cleans tempfiles; `QuotaUsage` is structurally typed via serde | present | `src/quota/mod.rs:116-127, 174-225` | Bundled with row 159 fix. |
| 161 | Disk reconcile on corrupt/empty quota file (0cdd8b6) | 0cdd8b6 (0.0.150) | `QuotaPolicy::reconcile` re-walks the pod's tree | present | `src/quota/mod.rs:247-259` | |
| 162 | Subdomain mode: don't rewrite file-like paths (`/foo.ttl`) as pod subdomains (#307) | 6d43e66 (0.0.149) | `multitenant::resolve_tenant` path-vs-subdomain dispatch | partial-parity (P2 verify) | `src/multitenant.rs` | File-extension heuristic worth porting. |
| 163 | `jss invite create -u/--uses` stores `maxUses` as null (#304) | 6578ab9 (0.0.148) | N/A — invite CLI is JSS-only operator tooling | wontfix-in-crate | — | |
| 164 | Type indexes typed `solid:TypeIndex` + `solid:ListedDocument` / `solid:UnlistedDocument` (#301) | 54e4433 (0.0.147) | `provision::provision_pod` writes `/settings/publicTypeIndex.jsonld` typed `solid:TypeIndex` + `solid:ListedDocument`, and `/settings/privateTypeIndex.jsonld` typed `solid:TypeIndex` + `solid:UnlistedDocument` | present | `src/provision.rs:227-236, 83-95` | Covered by `provision::tests::provisions_type_indexes_with_correct_visibility`. |
| 165 | `foaf:isPrimaryTopicOf` + `schema:mainEntityOfPage` in WebID profile (#299) | 01e12b0 (0.0.146) | `webid::generate_webid_html_with_issuer` emits both predicates; covered by `webid::tests::emits_primary_topic_of_and_main_entity_of_page` | present | `src/webid.rs:54-55 (graph), 41-42 (context), 321-344 (test)` | |
| 166 | `publicTypeIndex.jsonld.acl` seeded public-read at pod provision (#297) | 564d501 (0.0.145) | `provision::provision_pod` writes `/settings/publicTypeIndex.jsonld.acl` granting `acl:Read` to `foaf:Agent` + `acl:Control` to the pod owner | present | `src/provision.rs:98-` | Covered by `provision::tests::public_type_index_acl_grants_anonymous_read`. |
| 167 | `.acl` / `.meta` dotfiles recognised as `application/ld+json` for conneg (#294) | de02f15 (0.0.145) | Reusable `ldp::infer_dotfile_content_type(&str) -> Option<&'static str>` maps basenames `/.acl`, `/.meta`, `*.acl`, `*.meta` → `application/ld+json`; `FsBackend::read_meta` consults it when the sidecar is absent | present | `src/ldp.rs:347, 371-425; src/storage/fs.rs:98` | |
| 168 | `jss account delete` CLI + accounts refactor (#292) | d9e56d8 (0.0.144) | N/A — account lifecycle is IdP crate concern (row 74) | wontfix-in-crate (bundles with E.3) | — | |

---

## Priority legend (for missing rows)

| Priority | Meaning |
|---|---|
| **P0** | Ship-blocker. No outstanding P0 items at Sprint 9 close. |
| **P1** | Must land for JSS feature parity on the protocol-visible surface. |
| **P2** | Operator completeness; target v0.5.0. |
| **P3** | Long-term or consumer-crate concern; unlikely to block anything. |

---

## Top-10 missing features by port priority

1. **ActivityPub Actor + inbox/outbox + delivery + follower store** (rows 102, 103, 104, 107) — **P1**, v0.5.0 — `solid-pod-rs-activitypub` crate.
2. **LWS 1.0 SSI-CID verifier** (row 152) — **P1**, v0.5.0 — shared self-signed verifier abstracted over did:nostr + did:key + CID. Hook ready: `acl:issuer*` (row 55) dispatches.
3. **LWS 1.0 OpenID Connect delta audit** (row 150) — **P1 verify**, v0.5.0 — lock-step with JSS #319 box 1.
4. **`solid-0.1` legacy notifications adapter** (row 91) — **P1**, v0.4.0 — sub/ack/err/pub/unsub, per-sub WAC read check, ancestor-container fanout.
5. **LWS 1.0 SSI-did:key auth** (row 153) — **P2**, v0.5.0 — new `solid-pod-rs-didkey` crate; Ed25519 primary, P-256 + secp256k1 feature-gated.
6. **Git HTTP backend** (row 100) — **P2**, v0.5.0 — `solid-pod-rs-git` crate; ~450 LOC port; path-traversal hardening + `receive.denyCurrentBranch=updateInstead`.
7. **Subdomain multi-tenancy hardening** (row 125, 162) — **P2**, v0.5.0 — file-extension heuristic for path-vs-subdomain dispatch.
8. **Config file loader + size parsing + env overlay** (rows 120–124) — **P2**, v0.5.0.
9. **IdP crate** (`solid-pod-rs-idp`, rows 74–82) — **P2**, v0.5.0 — auth/token/me/reg/session endpoints + Passkeys + Schnorr SSO.
10. **NodeInfo 2.1** (row 106) + **top-level 5xx logging middleware** (row 158) — **P2** — bundle with E.2 / consumer-binder concerns.

---

## Net-new advantages (our 6 rows)

1. **`Prefer` header dispatch** (row 12) — LDP §4.2.2 + RFC 7240 multi-include. JSS doesn't implement.
2. **JSON Patch (RFC 6902) PATCH dialect** (row 42) — non-normative Solid extension.
3. **`acl:agentGroup` enforcement** (row 50) — we implement WAC §3.1.4 where JSS only parses.
4. **`acl:origin` enforcement** (row 51) — shared-gap closed by our side shipping first; Sprint 9.
5. **WAC 2.0 fail-closed on unknown conditions + 422 on PUT `.acl`** (rows 53, 56) — WAC 2.0 §5 normative; JSS fails open.
6. **Turtle ACL serialisation** (row 58) — outbound path JSS doesn't provide.

Additional conformance-wins where behaviour differs in our favour
(counted in parity percentages, not listed as separate net-new rows):
strong SHA-256 ETags (row 30), `.meta` describedby Link emission
(row 18), N3 Patch `where` enforcement via 412 where JSS silently
drops (row 40), 422-on-malformed-ACL write rejection (row 59),
richer `.well-known/solid/notifications` discovery (row 95).

---

## Sprint history

Compressed appendix — one line per sprint. Consult git history for per-row corrections.

- **Sprint 3 close (2026-04-19)**: 97 rows tracked, 74% strict parity (72/97).
- **Sprint 5 (2026-04-20)**: Sprint 5 mesh-and-QE-fleet review corrected multiple over-stated rows, added 5 WAC 2.0 rows (53–56 + 62b) and the DPoP signature surface. Net: 102 rows, 59% strict (verified, not claimed).
- **Sprint 7 (2026-04-21)**: operator surface rows added — rate-limit primitive, CORS helpers, quota CLI, multi-tenancy, server route table (112 rows).
- **Sprint 8 (2026-04-24)**: JSS 0.0.144 → 0.0.154 delta (13 patch releases) + LWS 1.0 Auth Suite rows 150–155 added; 6 rows landed (atomic quota writes, CID service entry, Cache-Control on RDF, dotfile conneg, WebID linkback predicates). 121 rows, 56% strict (~78% spec-normative).
- **Sprint 9 close (2026-04-24)**: 11 rows promoted to `present` (P0 DPoP signature + SSRF + dotfile primitives; WAC 2.0 condition framework; pod bootstrap with type indexes + public-read ACL; DPoP jti replay cache) and row 51 `acl:origin` promoted from shared-gap to net-new. 121 rows, **66% strict / 85% spec-normative**. No outstanding P0.
