# solid-pod-rs — Agent Integration Guide

> Status as of Sprint 9 close (commit `2275146`, 2026-04-24).
> 66% strict parity / 85% spec-normative parity against
> JavaScriptSolidServer (JSS). 121 parity rows, 567 tests,
> 15,504 lines of Rust in the `solid-pod-rs` library crate.

## How to use this guide

**Finding a feature.** Open the "Feature → module → JSS breadcrumbs"
section and locate your feature in the per-area tables (LDP, headers,
PATCH, WAC, auth, WebID, notifications, discovery, storage, config).
Every row gives you four anchors: the canonical Rust module + file,
the public surface you should consume, the JSS source that informs
the behaviour, and the test file that pins the behaviour down. An
agent should be able to navigate from a Solid feature name to a Rust
function signature in under three lookups.

**Mapping to JSS.** When you are reading JSS code and looking for the
Rust port, use the sibling doc
[`jss-source-breadcrumbs.md`](./jss-source-breadcrumbs.md). That doc
inverts the direction — given a JSS file, find the Rust equivalent.
The two docs form a bidirectional index keyed against the JSS clone at
`JavaScriptSolidServer/src/` and the Rust tree at
`crates/solid-pod-rs/src/`. Both are validated: every JSS path must
resolve with `test -f`; every Rust path must resolve with `test -f`;
every parity-row number must exist in
[`PARITY-CHECKLIST.md`](../../PARITY-CHECKLIST.md).

**When to consult the parity checklist.** Consult
[`PARITY-CHECKLIST.md`](../../PARITY-CHECKLIST.md) before implementing
a new Solid feature, before claiming a feature is "done", and before
updating any parity statistic. The checklist is the authoritative row
tracker (121 rows, status-typed, JSS-file-cited). It is updated per
sprint; the headline numbers at the top of this guide are derived from
the most recent Sprint 9 close and reverify after each landing. If
this guide and the checklist disagree, the checklist wins.

## Parity at a glance (Sprint 9 close)

| Metric | Value |
|---|---|
| Total parity rows tracked | 121 |
| Present | 74 |
| Partial-parity | 7 |
| Semantic-difference (spec-legal, observable delta) | 10 |
| Net-new (we have; JSS doesn't) | 6 |
| Missing (JSS has; we don't, porting active) | 20 |
| Explicitly-deferred | 5 |
| Wontfix-in-crate (consumer concern) | 5 |
| Shared-gap (both sides missing) | 2 |
| Present-by-absence | 1 |
| Strict parity (present + net-new) | 80 / 121 = 66% |
| Half-credit parity (partial = 0.5) | 83.5 / 121 = 69% |
| Spec-normative surface parity | ~85% strict / ~88% half-credit |
| Protocol conformance advantage over JSS | +8 rows (12, 18, 42, 50, 51, 56, 127; row 53 fail-closed vs JSS fail-open) |
| Test files (integration) | 42 |
| Integration + unit tests | 567 |
| Rust LOC (library crate `solid-pod-rs`, `src/`) | 15,504 |
| Rust LOC (binary `solid-pod-rs-server`, `src/`) | 1,114 |
| JSS LOC (`JavaScriptSolidServer/src/`, reference) | 18,778 across 62 `.js` files |

## Quick navigation index

If you are looking for X, start here:

| You want to… | Go to |
|---|---|
| Implement a new LDP header | `src/ldp.rs` § `link_headers` / `options_for` / `vary_header` |
| Add a new PATCH dialect | `src/ldp.rs` § `patch_dialect_from_mime` + `apply_*_patch` family |
| Change WAC evaluation | `src/wac/evaluator.rs` § `evaluate_access_with_groups` |
| Add a new WAC 2.0 condition type | `src/wac/conditions.rs` § `ConditionRegistry::register` |
| Swap storage backends | Implement `Storage` trait (see `src/storage/mod.rs`); example: `src/storage/fs.rs` |
| Add an OIDC alg | `src/oidc/mod.rs` § `verify_dpop_proof_core` dispatcher |
| Tune DPoP replay window | `src/oidc/replay.rs` § `JtiReplayCache::with_ttl` (feature `dpop-replay-cache`) |
| Host a webhook subscription | `src/notifications/mod.rs` § `WebhookChannelManager` (+ optional RFC 9421 via `src/notifications/signing.rs`) |
| Generate a WebID profile | `src/webid.rs` § `generate_webid_html_with_issuer` |
| Provision a pod | `src/provision.rs` § `provision_pod` |
| Implement an IdP | ⏳ waiting on `solid-pod-rs-idp` (v0.5.0) |
| Implement ActivityPub | ⏳ waiting on `solid-pod-rs-activitypub` (v0.5.0) |
| Write a test matching a JSS fixture | `tests/interop_jss.rs`, `tests/parity_close.rs` |
| Quote a parity percentage | Re-read `PARITY-CHECKLIST.md` headline **before** quoting |

## Crate map (at-a-glance)

```
crates/
├── solid-pod-rs/                       # main library — framework-agnostic
│   └── src/
│       ├── lib.rs                      # public re-exports (see "Public API cheat-sheet")
│       ├── error.rs                    # PodError — crate-wide error type
│       ├── metrics.rs                  # SecurityMetrics counters
│       ├── ldp.rs                      # LDP headers, conneg, PATCH, Range, conditional
│       ├── wac/                        # Web Access Control (parser, evaluator, WAC 2.0)
│       │   ├── mod.rs                  # re-exports, ACL doc parsing, mode helpers
│       │   ├── parser.rs               # Turtle ACL → AclDocument (handles acl:condition)
│       │   ├── serializer.rs           # AclDocument → Turtle
│       │   ├── document.rs             # AclDocument / Authorization types
│       │   ├── evaluator.rs            # evaluate_access / evaluate_access_with_groups
│       │   ├── resolver.rs             # StorageAclResolver (walk up parent .acl)
│       │   ├── conditions.rs           # WAC 2.0 Condition / ConditionRegistry
│       │   ├── client.rs               # acl:ClientCondition evaluator (WAC 2.0)
│       │   ├── issuer.rs               # acl:IssuerCondition evaluator (WAC 2.0)
│       │   └── origin.rs               # acl:origin policy + Pattern
│       ├── storage/                    # Storage trait + FS + memory backends
│       │   ├── mod.rs                  # Storage trait, ResourceMeta, StorageEvent
│       │   ├── fs.rs                   # FsBackend — filesystem with .meta.json sidecars
│       │   └── memory.rs               # MemoryBackend with broadcast watcher
│       ├── auth/
│       │   ├── mod.rs                  # re-exports
│       │   └── nip98.rs                # NIP-98 HTTP auth (kind 27235, Schnorr verify)
│       ├── oidc/                       # Solid-OIDC (feature: `oidc`)
│       │   ├── mod.rs                  # DPoP verify, access-token verify, DCR, discovery
│       │   ├── jwks.rs                 # JWKS fetch with SSRF guard
│       │   └── replay.rs               # JtiReplayCache (LRU, 5-min TTL)
│       ├── webid.rs                    # WebID profile generation + validation
│       ├── notifications/              # Solid Notifications 0.2
│       │   ├── mod.rs                  # WebSocket + Webhook channel managers
│       │   ├── legacy.rs               # solid-0.1 WebSocket adapter (feature-gated)
│       │   └── signing.rs              # RFC 9421 webhook signing (feature-gated)
│       ├── handlers/                   # feature-gated HTTP handler primitives
│       │   ├── mod.rs
│       │   └── legacy_notifications.rs # solid-0.1 WS handler (feature-gated)
│       ├── security/                   # SSRF, dotfile, CORS, rate-limit primitives
│       │   ├── mod.rs                  # re-exports
│       │   ├── ssrf.rs                 # is_safe_url, resolve_and_check, SsrfPolicy
│       │   ├── dotfile.rs              # is_path_allowed, DotfileAllowlist
│       │   ├── cors.rs                 # CorsPolicy (feature-gated via jss-v04)
│       │   └── rate_limit.rs           # RateLimiter trait + LruRateLimiter (feature)
│       ├── quota/
│       │   └── mod.rs                  # QuotaPolicy trait + FsQuotaStore (atomic)
│       ├── config/                     # layered config loader (feature: config-loader)
│       │   ├── mod.rs
│       │   ├── loader.rs               # ConfigLoader builder (file → env)
│       │   ├── schema.rs               # ServerConfig + sections
│       │   └── sources.rs              # parse_size, ConfigSource
│       ├── interop.rs                  # .well-known/solid, WebFinger, NIP-05, did:nostr,
│       │                               # NodeInfo discovery
│       ├── provision.rs                # provision_pod (WebID + containers + type indexes)
│       └── multitenant.rs              # PathResolver / SubdomainResolver
│
├── solid-pod-rs-server/                # drop-in JSS replacement binary (actix-web)
│   └── src/
│       ├── main.rs                     # CLI entry: clap + config + tracing + TLS + signals
│       └── lib.rs                      # build_app: route table + middleware stack
│
├── solid-pod-rs-activitypub/           # STUB v0.5.0 — 24 lines, no code
├── solid-pod-rs-git/                   # STUB v0.5.0 — 24 lines, no code
├── solid-pod-rs-idp/                   # STUB v0.5.0 — 28 lines, no code
└── solid-pod-rs-nostr/                 # STUB v0.5.0 — 25 lines, no code
```

## Feature → module → JSS breadcrumbs

### 1. LDP (Linked Data Platform)

| Feature | solid-pod-rs module | Public surface | JSS source | Test file | Parity row |
|---|---|---|---|---|---|
| Resource GET | `src/storage/mod.rs` + `src/ldp.rs` | `Storage::get`, `ldp::link_headers` | `src/handlers/resource.js` | `tests/interop_jss.rs` | 1 |
| Resource HEAD | `src/storage/mod.rs` | `Storage::head` via `ResourceMeta` | `src/handlers/resource.js` | `tests/interop_jss.rs` | 2 |
| Resource PUT (create-or-replace) | `src/storage/mod.rs` | `Storage::put` (returns SHA-256 ETag) | `src/handlers/resource.js` + PUT hook (`src/server.js:455`) | `tests/storage_trait.rs` | 3 |
| Resource DELETE | `src/storage/mod.rs` | `Storage::delete` | `src/handlers/resource.js` | `tests/storage_trait.rs` | 4 |
| Basic Container GET (ldp:contains) | `src/ldp.rs` | `render_container_jsonld`, `render_container_turtle` | `src/ldp/container.js` | `tests/interop_jss.rs` | 5 |
| Container POST + Slug | `src/ldp.rs` | `resolve_slug` (UUID fallback) | `src/handlers/container.js` | `tests/ldp_slug_jss.rs` | 6 |
| PUT-to-container 405 | (consumer binder) | — | `src/handlers/container.js` | `tests/server_routes_jss.rs` | 7 |
| Server-managed triples | `src/ldp.rs` | `server_managed_triples`, `find_illegal_server_managed` | `src/ldp/container.js` | `tests/interop_jss.rs` | 8 |
| `ldp:contains` direct children | `src/storage/mod.rs` | `Storage::list` (collapses nested) | `src/ldp/container.js` | `tests/interop_jss.rs` | 9 |
| Direct / Indirect Containers | n/a | not implemented (spec-optional) | not implemented | — | 10, 11 |
| `Prefer` multi-include | `src/ldp.rs` | `PreferHeader::parse` | not implemented in JSS | `tests/ldp_headers_jss.rs` | 12 (net-new) |
| Pod root bootstrap | `src/provision.rs` | `provision_pod` → `ProvisionOutcome` | `src/server.js:504-548` + `src/handlers/container.js::createPodStructure` | `provision::tests` (inline) | 14 |
| Live-reload script injection | n/a | dev-mode, out of scope | `src/handlers/resource.js:23-35` | — | 13 |

### 2. HTTP headers, content negotiation, conditional/range

| Feature | solid-pod-rs module | Public surface | JSS source | Test file | Parity row |
|---|---|---|---|---|---|
| `Link: rel=type` | `src/ldp.rs` | `link_headers` | `src/ldp/headers.js` | `tests/ldp_headers_jss.rs` | 15, 16 |
| `Link: rel=acl` | `src/ldp.rs` | `link_headers` | `src/ldp/headers.js` | `tests/ldp_headers_jss.rs` | 17 |
| `Link: rel=describedby` (net-new) | `src/ldp.rs` | `link_headers` | (JSS absent) | `tests/ldp_headers_jss.rs` | 18 |
| `Link: rel=pim:storage` at root | `src/ldp.rs` | `link_headers` | `src/ldp/headers.js` | `tests/ldp_headers_jss.rs` | 19 |
| `Accept-Patch` | `src/ldp.rs` | `ACCEPT_PATCH`, `options_for` | `src/ldp/headers.js` | `tests/ldp_headers_jss.rs` | 20 |
| `Accept-Post` | `src/ldp.rs` | `ACCEPT_POST` | `src/rdf/conneg.js` | `tests/ldp_headers_jss.rs` | 21 |
| `Accept-Put` | `src/ldp.rs` | `options_for` | `src/rdf/conneg.js` | `tests/ldp_headers_jss.rs` | 22 |
| `Accept-Ranges` | `src/ldp.rs` | `options_for` | `src/ldp/headers.js` | `tests/ldp_headers_jss.rs` | 23 |
| `Allow:` | `src/ldp.rs` | `options_for` → `OptionsResponse` | `src/ldp/headers.js` | `tests/ldp_headers_jss.rs` | 24 |
| `Vary: Authorization, Origin[, Accept]` | `src/ldp.rs` | `vary_header` | `src/ldp/headers.js` (#315) | `tests/ldp_headers_jss.rs` | 25, 156 |
| `WAC-Allow` | `src/wac/mod.rs` | `wac_allow_header`, `wac_allow_header_with_dispatcher` | `src/wac/checker.js:279-282` | `tests/wac_basic.rs` | 26 |
| `Updates-Via` | (consumer binder) | — | `src/server.js:229-231` | — | 27 |
| CORS | `src/security/cors.rs` | `CorsPolicy`, `preflight_headers`, `response_headers` | `src/ldp/headers.js:112,135` | `tests/cors_preflight.rs` | 28, 29 |
| ETag (SHA-256) | `src/storage/mod.rs` | `ResourceMeta::etag` | `src/storage/filesystem.js:32` (md5) — semantic-diff | `tests/storage_trait.rs` | 30 |
| If-Match / If-None-Match | `src/ldp.rs` | `evaluate_preconditions` → `ConditionalOutcome` | `src/utils/conditional.js` | `tests/ldp_headers_jss.rs` | 31 |
| Range requests | `src/ldp.rs` | `parse_range_header`, `parse_range_header_v2`, `slice_range`, `ByteRange::content_range` | `src/handlers/resource.js:56-106` | `tests/ldp_range_jss.rs` | 32 |
| OPTIONS | `src/ldp.rs` | `options_for` → `OptionsResponse` | `src/server.js:452` | `tests/server_routes_jss.rs` | 33 |
| Content-type negotiation | `src/ldp.rs` | `negotiate_format`, `RdfFormat` | `src/rdf/conneg.js:33-61` | `tests/ldp_headers_jss.rs` | 34 |
| N3 input | `src/ldp.rs` | mapped onto Turtle parser | `src/rdf/conneg.js` | — | 35 (partial) |
| RDF/XML | n/a | `RdfFormat::RdfXml` negotiated, no serialiser | recognised but not implemented | — | 36 (deferred) |
| N-Triples round-trip | `src/ldp.rs` | `Graph::to_ntriples`, `Graph::parse_ntriples` | not first-class | — | 37 (net-new) |
| Turtle ⇄ JSON-LD (deterministic) | `src/ldp.rs` | `Graph` internal model | `n3.js` (non-deterministic) | — | 38 (net-new) |
| `.acl`/`.meta` conneg | `src/ldp.rs` + `src/storage/fs.rs` | `infer_dotfile_content_type` | `src/utils/url.js::getContentType` (#294) | inline in `ldp.rs` | 167 |
| `Cache-Control` on RDF | `src/ldp.rs` | `CACHE_CONTROL_RDF`, `cache_control_for` | `src/ldp/headers.js` (#315) | `tests/ldp_headers_jss.rs` | 157 |

### 3. PATCH dialects

| Feature | solid-pod-rs module | Public surface | JSS source | Test file | Parity row |
|---|---|---|---|---|---|
| N3 Patch | `src/ldp.rs` | `apply_n3_patch`, `apply_patch_to_absent` | `src/patch/n3-patch.js` | `tests/ldp_patch_create_jss.rs` | 39 |
| N3 Patch `where` failure | `src/ldp.rs` | returns 412 via `evaluate_preconditions` | 409 in JSS — semantic-difference (both spec-legal) | `tests/ldp_patch_create_jss.rs` | 40 (net-new: we validate; JSS silently drops) |
| SPARQL-Update | `src/ldp.rs` | `apply_sparql_patch` via `spargebra` | `src/patch/sparql-update.js` | `tests/interop_jss.rs` | 41 |
| JSON Patch (RFC 6902) | `src/ldp.rs` | `apply_json_patch` | not implemented in JSS | `tests/ldp_patch_create_jss.rs` | 42 (net-new) |
| PATCH dialect dispatch | `src/ldp.rs` | `patch_dialect_from_mime` → `PatchDialect` | inline in `src/handlers/resource.js` | `tests/ldp_patch_create_jss.rs` | 43 |

### 4. Web Access Control (WAC + WAC 2.0)

| Feature | solid-pod-rs module | Public surface | JSS source | Test file | Parity row |
|---|---|---|---|---|---|
| Default-deny stance | `src/wac/evaluator.rs` | `evaluate_access` | `src/wac/checker.js:31-34` | `tests/wac_basic.rs` | 44 |
| ACL hierarchy (parent walk) | `src/wac/resolver.rs` | `StorageAclResolver` | `src/wac/checker.js:59-113` | `tests/wac_inheritance.rs` | 45 |
| `acl:default` inheritance | `src/wac/resolver.rs` | resolver | `src/wac/checker.js:59-113` | `tests/wac_inheritance.rs` | 46 |
| `acl:agent` | `src/wac/evaluator.rs` | `evaluate_access` | `src/wac/checker.js:129` | `tests/wac_basic.rs` | 47 |
| `acl:agentClass foaf:Agent` | `src/wac/evaluator.rs` | `evaluate_access` | `src/wac/checker.js:139` | `tests/wac_basic.rs` | 48 |
| `acl:agentClass acl:AuthenticatedAgent` | `src/wac/evaluator.rs` | `evaluate_access` | `src/wac/checker.js:147` | `tests/wac_basic.rs` | 49 |
| `acl:agentGroup` enforcement | `src/wac/evaluator.rs` | `evaluate_access_with_groups`, `GroupMembership`, `StaticGroupMembership` | parsed but not enforced in JSS (`checker.js:193` TODO) | `tests/wac_basic.rs` | 50 (net-new behaviour) |
| `acl:origin` enforcement | `src/wac/origin.rs` | `OriginPolicy`, `Pattern`, `check_origin`, `extract_origin_patterns` | not implemented in JSS | `tests/acl_origin_test.rs`, `tests/acl_origin_sprint9.rs` | 51 (net-new, Sprint 9) |
| Modes (R/W/Append/Control) | `src/wac/mod.rs` | `AccessMode`, `ALL_MODES` | `src/wac/parser.js:13-18` | `tests/wac_basic.rs` | 52 |
| `acl:condition` framework (WAC 2.0) | `src/wac/parser.rs` + `src/wac/conditions.rs` | `Condition::{Client, Issuer, Unknown}`, `ConditionRegistry`, `validate_for_write` | `src/wac/parser.js:162`, `src/wac/checker.js:130-197` | `tests/wac2_conditions.rs`, `tests/wac2_conditions_sprint9.rs` | 53 (Sprint 9, fail-closed) |
| `acl:ClientCondition` | `src/wac/client.rs` | `ClientConditionEvaluator` | `src/wac/checker.js:130-197` | `tests/wac2_conditions.rs` | 54 (Sprint 9) |
| `acl:IssuerCondition` | `src/wac/issuer.rs` | `IssuerConditionEvaluator` | `src/wac/checker.js:130-197` | `tests/wac2_conditions.rs` | 55 (Sprint 9) |
| 422 on unknown condition write | `src/wac/conditions.rs` | `validate_for_write` → `UnsupportedCondition` | (no JSS equivalent) | `tests/wac_validate_for_write.rs` | 56 (Sprint 9, net-new stricter) |
| Turtle ACL parser | `src/wac/parser.rs` | `parse_turtle_acl`, `parse_authorization_body` | `src/wac/parser.js:13-384` | `tests/wac_parser_bounds.rs` | 56 (parser entry) |
| Turtle ACL serialiser | `src/wac/serializer.rs` | `serialize_turtle_acl` | not implemented in JSS | inline in `wac` module | 57 (net-new) |
| JSON-LD ACL parser | `src/wac/mod.rs` | `parse_jsonld_acl` | accepted in JSS | `tests/legacy_wac_check.rs` | 58 |
| Malformed `.acl` write → 422 | `src/wac/parser.rs` | `parse_turtle_acl` rejects at write | JSS defers to evaluation-time 500 — semantic-diff | `tests/wac_validate_for_write.rs` | 59 |
| Cross-identity matching | `src/auth/nip98.rs` | implicit via agent derivation | `src/auth/identity-normalizer.js` | `tests/wac_basic.rs` | 60 (partial) |

### 5. Authentication

| Feature | solid-pod-rs module | Public surface | JSS source | Test file | Parity row |
|---|---|---|---|---|---|
| Simple Bearer dev token | n/a (consumer) | — | `src/auth/token.js:45-117` | — | 61 |
| Solid-OIDC DPoP | `src/oidc/mod.rs` | `verify_dpop_proof`, `verify_dpop_proof_with_ath`, `DpopVerified` | `src/auth/solid-oidc.js:85-251` | `tests/oidc_integration.rs`, `tests/oidc_dpop_signature.rs` | 62 |
| DPoP signature (alg dispatch) | `src/oidc/mod.rs` | `verify_dpop_proof_core` (internal); ES256/ES384/RS256-512/PS256-512/EdDSA | `src/auth/solid-oidc.js:171-249` (`jwtVerify`) | `tests/oidc_dpop_signature.rs`, `tests/oidc_access_token_alg.rs` | 62b (Sprint 9, P0 cleared) |
| DPoP `cnf.jkt` binding | `src/oidc/mod.rs` | `verify_access_token` | `src/auth/solid-oidc.js` | `tests/oidc_thumbprint_rfc7638.rs` | 63 |
| DPoP jti replay cache | `src/oidc/replay.rs` | `JtiReplayCache` (LRU, 5-min TTL, 10 000 cap) | `src/auth/solid-oidc.js` | `tests/dpop_replay_test.rs`, `tests/jti_replay_sprint9.rs` | 64 (Sprint 9, primitive shipped) |
| SSRF guard on JWKS fetch | `src/oidc/jwks.rs` + `src/security/ssrf.rs` | `fetch_jwks_with_policy`; `SsrfPolicy`, `is_safe_url` | `src/utils/ssrf.js:15-50` | `tests/oidc_jwks_ssrf.rs` | 65, 114 |
| NIP-98 HTTP auth | `src/auth/nip98.rs` | `verify_at`, `Nip98Event`, `Nip98Verified` | `src/auth/nostr.js:26-267` | `tests/nip98_extended.rs`, `tests/schnorr_nip98.rs` | 66 |
| NIP-98 Schnorr verify | `src/auth/nip98.rs` | `verify_schnorr_signature` (feature `nip98-schnorr`) | via `nostr-tools` | `tests/schnorr_nip98.rs` | 67 |
| NIP-98 60s skew | `src/auth/nip98.rs` | `verify_at` `now` param | `src/auth/nostr.js` | `tests/nip98_extended.rs` | 68 |
| `Basic nostr:<token>` for git | n/a | reserved for `solid-pod-rs-git` | `src/auth/nostr.js:39-46,178-200` | — | 69 |
| WebID-TLS | n/a | deferred | `src/auth/webid-tls.js:187-257` | — | 70 (deferred) |
| IdP-issued JWT verify | `src/oidc/mod.rs` | `verify_access_token`, `verify_access_token_hs256` | `src/auth/token.js:126-161` | `tests/oidc_integration.rs` | 71 |
| Auth dispatch precedence | (consumer binder) | primitives only | `src/auth/token.js:215-269` | — | 72 |
| `WWW-Authenticate` | (consumer binder) | — | `src/auth/middleware.js:117` | — | 73 |

### 6. WebID

| Feature | solid-pod-rs module | Public surface | JSS source | Test file | Parity row |
|---|---|---|---|---|---|
| Profile generation | `src/webid.rs` | `generate_webid_html`, `generate_webid_html_with_issuer` | `src/webid/profile.js` | `webid::tests` (inline) | 84 |
| Profile validation | `src/webid.rs` | `validate_webid_html` | inline in JSS | `webid::tests` | 85 |
| `solid:oidcIssuer` discovery | `src/webid.rs` | `extract_oidc_issuer` | inline | `webid::tests` | 86 |
| Multi-user discovery path | `src/provision.rs` | `provision_pod` seeds `/:pod/profile/card#me` | README §"Pod Structure" | `provision::tests` | 87 |
| Single-user root pod | `src/provision.rs` | `provision_pod` with `pod_base="/"` | `src/server.js:480` | `provision::tests` | 88 |
| did:nostr DID-Doc publish | `src/interop.rs::did_nostr` (feature `did-nostr`) | `did_nostr_document`, `did_nostr_well_known_url`, `DidNostrResolver` | JSS has `src/auth/did-nostr.js` (resolver shape differs) | `tests/did_nostr_resolver.rs` | 89, 90 (partial — resolver landed, publish endpoint reserved for v0.5.0 sibling) |
| CID service entry (LWS 1.0) | `src/webid.rs` | `generate_webid_html_with_issuer` emits `service[@type=lws:OpenIdProvider]` | `src/webid/profile.js:44-72` | `webid::tests` | 154 |
| `cid:` + `lws:` @context terms | `src/webid.rs` | `generate_webid_html_with_issuer` | `src/webid/profile.js:35-41` | `webid::tests` | 155 |
| `foaf:isPrimaryTopicOf` + `schema:mainEntityOfPage` | `src/webid.rs` | `generate_webid_html_with_issuer` | `src/webid/profile.js` (#299) | `webid::tests::emits_primary_topic_of_and_main_entity_of_page` | 165 |

### 7. Notifications

| Feature | solid-pod-rs module | Public surface | JSS source | Test file | Parity row |
|---|---|---|---|---|---|
| `solid-0.1` legacy WS | `src/notifications/legacy.rs` + `src/handlers/legacy_notifications.rs` (feature `legacy-notifications`) | primitive exists; library handler landing partial | `src/notifications/websocket.js:1-102,110-147` | `tests/legacy_notifications_test.rs`, `tests/notifications_mod_direct.rs` | 91 (partial — sub/ack frames; per-sub WAC landing Sprint 10) |
| WebSocketChannel2023 | `src/notifications/mod.rs` | `WebSocketChannelManager` (broadcast + 30s heartbeat) | not implemented in JSS | `tests/notifications_mod_direct.rs` | 92 (net-new) |
| WebhookChannel2023 | `src/notifications/mod.rs` + `src/notifications/signing.rs` | `WebhookChannelManager` (AS2.0 POST, 3× retry, circuit breaker, RFC 9421 signing) | not implemented in JSS | `tests/webhook_retry.rs`, `tests/webhook_signing.rs` | 93, 97 (net-new) |
| Server-Sent Events | n/a | not in spec | not implemented | — | 94 |
| `.well-known/solid/notifications` discovery | `src/notifications/mod.rs` | `discovery_document` | status-only in `src/notifications/index.js:43` | `tests/notifications_mod_direct.rs` | 95, 133 (net-new richer) |
| Subscription registry | `src/notifications/mod.rs` | `Notifications` trait, `InMemoryNotifications` | inline in JSS | `tests/notifications_mod_direct.rs` | 96 |
| Change notification mapping | `src/notifications/mod.rs` | `ChangeNotification::from_storage_event` | inline in JSS | `tests/notifications_mod_direct.rs` | 98 |
| Filesystem watcher pump | `src/storage/fs.rs` + `src/notifications/mod.rs` | `FsBackend` watcher + `pump_from_storage` | `src/notifications/events.js` | `tests/notifications_mod_direct.rs` | 99 |

### 8. Discovery

| Feature | solid-pod-rs module | Public surface | JSS source | Test file | Parity row |
|---|---|---|---|---|---|
| `.well-known/solid` | `src/interop.rs` | `well_known_solid` → `SolidWellKnown` | not implemented in JSS | `tests/interop_jss.rs` | 127 (net-new) |
| `.well-known/nostr.json` (NIP-05) | `src/interop.rs` | `verify_nip05`, `nip05_document` → `Nip05Document` | not implemented in JSS | `tests/interop_jss.rs` | 128 (net-new) |
| `.well-known/openid-configuration` | `src/oidc/mod.rs` | `discovery_for` → `DiscoveryDocument` | `src/idp/index.js:171` | `tests/oidc_integration.rs` | 129 |
| `.well-known/jwks.json` | `src/oidc/jwks.rs` | primitive — consumer hosts | `src/idp/index.js:208` | `tests/oidc_jwks_ssrf.rs` | 130 |
| `.well-known/nodeinfo` + `2.1` | `src/interop.rs` | `nodeinfo_discovery`, `nodeinfo_2_1` | `src/ap/index.js:116,130` | `tests/nodeinfo_jss.rs` | 131, 106 |
| `.well-known/did/nostr/:pubkey.json` | `src/interop.rs::did_nostr` (feature `did-nostr`) | `did_nostr_well_known_url` | referenced in JSS but no primitive (closest: `src/auth/did-nostr.js`) | `tests/did_nostr_resolver.rs` | 132 |
| WebFinger | `src/interop.rs` | `webfinger_response` → `WebFingerJrd`, `WebFingerLink` | `src/ap/index.js:80` | `tests/interop_jss.rs` | 105 |

### 9. Storage, config, multi-tenancy

| Feature | solid-pod-rs module | Public surface | JSS source | Test file | Parity row |
|---|---|---|---|---|---|
| FS backend | `src/storage/fs.rs` | `FsBackend` (`.meta.json` sidecars) | `src/storage/filesystem.js` | `tests/storage_trait.rs` | 116 |
| Memory backend | `src/storage/memory.rs` | `MemoryBackend` with broadcast watcher | test-only in JSS | `tests/storage_trait.rs` | 117 |
| S3 backend | `src/storage` (feature `s3-backend`) | — | not provided | — | 118 (net-new, gated) |
| SPARQL / external-HTTP | n/a | explicitly-deferred | `sql.js` (AP state only) | — | 119 |
| Config file + env + CLI | `src/config/` (feature `config-loader`) | `ConfigLoader`, `ServerConfig`, `StorageBackendConfig`, `parse_size`, `ConfigSource` | `src/config.js:17-239` | `tests/config_test.rs`, `tests/config_size_parsing.rs` | 120 |
| `JSS_*` env vars | `src/config/sources.rs` | `ConfigSource::Env` | `src/config.js:96-132` | `tests/config_test.rs` | 121 |
| `TOKEN_SECRET` | n/a (consumer) | `security::token_secret` (primitive) | `src/auth/token.js:17-34` | — | 122 |
| `CORS_ALLOWED_ORIGINS` | `src/security/cors.rs` | `CorsPolicy::from_env`, `ENV_CORS_ALLOWED_ORIGINS` | `src/ldp/headers.js:98-102` | `tests/cors_preflight.rs` | 123 |
| Size parsing | `src/config/sources.rs` | `parse_size` | `src/config.js:137-145` | `tests/config_size_parsing.rs` | 124 |
| Subdomain multi-tenancy | `src/multitenant.rs` | `SubdomainResolver`, `PathResolver`, `PodResolver`, `ResolvedPath` | `src/server.js:159-170` + `src/utils/url.js` | `tests/tenancy_subdomain.rs` | 125 |
| Path-based multi-tenancy | `src/multitenant.rs` | `PathResolver` | path dispatch in `src/server.js` | `tests/tenancy_subdomain.rs` | 126 |
| Filesystem quota + reconcile | `src/quota/mod.rs` (feature `quota`) | `QuotaPolicy`, `FsQuotaStore`, `QuotaUsage`, `QuotaExceeded` | `src/storage/quota.js` + `bin/jss.js quota reconcile` | `tests/quota_fs.rs`, `tests/quota_race.rs` | 113, 159, 160, 161 |
| Pod-create rate limit | `src/security/rate_limit.rs` (feature `rate-limit`) | `RateLimiter`, `LruRateLimiter`, `RateLimitKey`, `RateLimitSubject`, `RateLimitDecision` | `src/server.js:356-364` | `tests/rate_limit_lru.rs` | 111, 112 |
| SSRF guard | `src/security/ssrf.rs` | `is_safe_url`, `resolve_and_check`, `SsrfPolicy`, `IpClass`, `SsrfError` | `src/utils/ssrf.js:15-157` | `tests/oidc_jwks_ssrf.rs`, `src/security/ssrf.rs::tests` | 114 (Sprint 9 P0) |
| Dotfile allowlist | `src/security/dotfile.rs` | `is_path_allowed`, `DotfileAllowlist`, `DotfileError`, `DotfilePathError` | `src/server.js:265-281` | `tests/security_primitives_test.rs` | 115 (Sprint 9 P0) |

### 10. Interop / provisioning / admin / architectural

| Feature | solid-pod-rs module | Public surface | JSS source | Test file | Parity row |
|---|---|---|---|---|---|
| Pod provisioning | `src/provision.rs` | `provision_pod`, `ProvisionPlan`, `ProvisionOutcome`, `QuotaTracker` | `src/server.js:504-548` + `src/handlers/container.js::createPodStructure` | `provision::tests`, `tests/parity_close.rs` | 134 |
| Account scaffolding | `src/provision.rs` | `ProvisionPlan` | `src/idp/` | — | 135 (partial) |
| Admin override | `src/provision.rs` | `check_admin_override`, `AdminOverride` | not provided | `provision::tests` | 136 (net-new) |
| Dev-mode session | `src/interop.rs` | `dev_session` → `DevSession` | not provided | `tests/interop_jss.rs` | 137 (net-new) |
| Type indexes + ACL seed | `src/provision.rs` | `provision_pod` emits `/settings/{public,private}TypeIndex.jsonld` + `.acl` carve-out | `#297`, `#301` in JSS | `provision::tests::provisions_type_indexes_with_correct_visibility`, `provision::tests::public_type_index_acl_grants_anonymous_read` | 164, 166 (Sprint 9) |
| CLI binary (`start`) | `crates/solid-pod-rs-server/src/main.rs` | `solid-pod-rs-server` binary | `bin/jss.js` | `crates/solid-pod-rs-server/tests` via `build_app` | 139 |
| Library / framework split | `src/lib.rs` + `crates/solid-pod-rs-server` | framework-agnostic library; binary builds actix `App` | `src/server.js:45-562` (Fastify-coupled) | `tests/server_routes_jss.rs`, `tests/server_security.rs` | 140 (architectural) |

## Public API cheat-sheet

### Re-exports from `lib.rs`

The cheat-sheet below is the **verbatim** `pub use` surface — consumers
should always go through these re-exports rather than deep-importing
from submodules (deep imports are not a stability contract).

```rust
// Error + metrics
pub use error::PodError;
pub use metrics::SecurityMetrics;

// Security primitives
pub use security::{
    is_path_allowed, is_safe_url, resolve_and_check, DotfileAllowlist,
    DotfileError, DotfilePathError, IpClass, SsrfError, SsrfPolicy,
};

// Storage
pub use storage::{ResourceMeta, Storage, StorageEvent};

// WAC
pub use wac::{
    check_origin, evaluate_access, evaluate_access_with_groups,
    extract_origin_patterns, method_to_mode, mode_name,
    parse_turtle_acl, serialize_turtle_acl, wac_allow_header,
    AccessMode, AclDocument, GroupMembership, Origin, OriginDecision,
    OriginPattern, StaticGroupMembership,
};

// LDP
pub use ldp::{
    apply_json_patch, apply_n3_patch, apply_patch_to_absent,
    apply_sparql_patch, cache_control_for, evaluate_preconditions,
    is_rdf_content_type, link_headers, negotiate_format,
    not_found_headers, options_for, parse_range_header,
    parse_range_header_v2, patch_dialect_from_mime,
    server_managed_triples, slice_range, vary_header, ByteRange,
    ConditionalOutcome, ContainerRepresentation, Graph,
    OptionsResponse, PatchCreateOutcome, PatchDialect, PatchOutcome,
    PreferHeader, RangeOutcome, RdfFormat, Term, Triple,
    ACCEPT_PATCH, ACCEPT_POST, CACHE_CONTROL_RDF,
};

// Interop (well-known, WebFinger, NIP-05, did:nostr, NodeInfo)
pub use interop::{
    dev_session, nip05_document, verify_nip05, webfinger_response,
    well_known_solid, DevSession, Nip05Document, SolidWellKnown,
    WebFingerJrd, WebFingerLink,
};

// Multi-tenancy
pub use multitenant::{
    PathResolver, PodResolver, ResolvedPath, SubdomainResolver,
};

// Provisioning
pub use provision::{
    check_admin_override, provision_pod, AdminOverride,
    ProvisionOutcome, ProvisionPlan, QuotaTracker,
};

// Quota
pub use quota::{QuotaExceeded, QuotaPolicy, QuotaUsage};
#[cfg(feature = "quota")]
pub use quota::FsQuotaStore;

// WebID
pub use webid::{
    extract_oidc_issuer, generate_webid_html,
    generate_webid_html_with_issuer, validate_webid_html,
};
```

### Feature-gated modules (not re-exported at crate root)

| Module path | Feature flag | Notes |
|---|---|---|
| `solid_pod_rs::oidc` | `oidc` | Solid-OIDC: DPoP, access token, DCR, discovery, JWKS, replay |
| `solid_pod_rs::handlers` | `legacy-notifications` | solid-0.1 WebSocket handler primitives |
| `solid_pod_rs::notifications::legacy` | `legacy-notifications` | solid-0.1 adapter (deep import OK — experimental) |
| `solid_pod_rs::notifications::signing` | `webhook-signing` | RFC 9421 `SignerConfig`, `sign_webhook` |
| `solid_pod_rs::security::cors::CorsPolicy` | `jss-v04` (via `security-primitives`) | CORS policy + preflight |
| `solid_pod_rs::security::rate_limit` | `rate-limit` | LRU-backed rate limiter |
| `solid_pod_rs::quota::FsQuotaStore` | `quota` | atomic-write sidecar quota store |
| `solid_pod_rs::oidc::replay::JtiReplayCache` | `dpop-replay-cache` | DPoP jti replay cache (5-min TTL, 10k cap) |
| `solid_pod_rs::interop::did_nostr` | `did-nostr` | did:nostr DID-Doc ↔ WebID resolver |
| `solid_pod_rs::config` | (always compiled; `config-loader` is the consumer toggle) | `ConfigLoader`, `ServerConfig`, `StorageBackendConfig` |

## Feature flags

| Cargo feature | Enables | Pulls in | Parity rows activated |
|---|---|---|---|
| `fs-backend` (default) | `FsBackend` filesystem storage | (core) | 116 |
| `memory-backend` (default) | `MemoryBackend` in-memory storage | (core) | 117 |
| `s3-backend` | `aws-sdk-s3` object-store backend | `aws-sdk-s3` | 118 (net-new) |
| `oidc` | Solid-OIDC module (DPoP, access token, DCR, discovery) | `openidconnect`, `jsonwebtoken` | 62, 63, 71, 75, 76, 129 |
| `nip98-schnorr` | Schnorr signature verification for NIP-98 | `k256` (schnorr feature) | 67 |
| `jss-v04` | Parent umbrella; no-op alone | — | — |
| `security-primitives` | Implies `jss-v04`; gates SSRF/dotfile/CORS integration | — | 28, 29, 114, 115, 123 |
| `legacy-notifications` | `handlers::legacy_notifications`, `notifications::legacy` | — | 91 |
| `acl-origin` | WAC `acl:origin` enforcement in evaluator | — | 51 |
| `dpop-replay-cache` | `oidc::replay::JtiReplayCache` | `lru` (+ implies `oidc`) | 64 |
| `config-loader` | Binary-layer wiring toggle for `ConfigLoader` | — | 120, 121, 124 |
| `webhook-signing` | RFC 9421 signing + Retry-After + circuit breaker | `ed25519-dalek`, `httpdate`, `rand` | 92, 93, 97 |
| `did-nostr` | `interop::did_nostr` resolver + DID-Doc helper | (reuses `reqwest`, `serde`, `url`) | 89, 90 |
| `rate-limit` | `security::rate_limit::LruRateLimiter` | `lru`, `parking_lot` | 111, 112, 141 |
| `quota` | `quota::FsQuotaStore` + atomic writes | (reuses `serde_json`, `tokio::fs`) | 113, 159, 160, 161 |

Feature-flag philosophy: library-level structs are always compiled
cheaply; the flag opts the consumer into integrations, additional
crates, or behaviour changes at the evaluator level. Default feature
set (`fs-backend + memory-backend`) is minimal on dependencies.

## Extension points

These traits are the consumer-facing extension surface. All are marked
`Send + Sync + 'static` and can be implemented in a downstream crate
without touching `solid-pod-rs` source.

| Trait | Module | Purpose | Default implementation | When to implement your own |
|---|---|---|---|---|
| `Storage` | `src/storage/mod.rs` | Filesystem-like read/write/list/watch interface backing everything LDP does | `FsBackend` (disk), `MemoryBackend` (tests) | S3, SPARQL, database-backed storage, remote pod |
| `GroupMembership` | `src/wac/mod.rs` (re-exports from `evaluator`) | Resolves `acl:agentGroup` → set of WebIDs | `StaticGroupMembership` (in-memory `HashMap`) | vcard:Group stored in a container, external LDAP, DB lookup |
| `QuotaPolicy` | `src/quota/mod.rs` | Reserve/record/release bytes against a pod-scoped budget | `FsQuotaStore` (feature `quota`, atomic `.quota.json` sidecar) | Redis counter, per-tenant DB row |
| `Notifications` | `src/notifications/mod.rs` | Subscription registry | `InMemoryNotifications` | Redis pub/sub, PostgreSQL LISTEN/NOTIFY, cross-process |
| `RateLimiter` | `src/security/rate_limit.rs` (feature `rate-limit`) | Token-bucket decision per `(route, subject)` key | `LruRateLimiter` | Shared-cluster rate limiting |
| `PodResolver` | `src/multitenant.rs` | Map request path/host → `ResolvedPath` | `PathResolver`, `SubdomainResolver` | Hybrid path+subdomain, DNS-driven, custom tenant model |
| `ConditionRegistry::register` | `src/wac/conditions.rs` | Dispatch table for WAC 2.0 `acl:condition` IRIs | Built-ins: `ClientCondition`, `IssuerCondition` (registered by `default_with_client_and_issuer`) | Custom WAC 2.0 condition types (hook for LWS10 SSI-CID) |

Planned extension points (v0.5.0, not yet in tree):

| Trait | Crate | Purpose |
|---|---|---|
| `SelfSignedVerifier` | `solid-pod-rs-didkey` + re-used by `solid-pod-rs-nostr` | Abstract over did:nostr + did:key + CID for `acl:issuer*` dispatch |

## Cross-crate matrix

| Crate | Status | Rows | Target milestone | JSS equivalent | Notes |
|---|---|---|---|---|---|
| `solid-pod-rs` | **landed** (~15,504 LOC in `src/`, 567 tests) | 74 present + 7 partial + 10 semantic-diff + 6 net-new + 1 present-by-absence | v0.4.x (current) | `src/ldp/`, `src/wac/`, `src/storage/`, `src/auth/*` (minus IdP+AP+git) | Main library; this guide's primary target. |
| `solid-pod-rs-server` | **landed** (1,114 LOC) | rows 139, 140 | v0.4.x (current) | `bin/jss.js` + `src/server.js` | Actix-web binary with full route table. |
| `solid-pod-rs-activitypub` | **STUB** (24 lines doc-only) | 102–108, 131 | v0.5.0 | `src/ap/**`, `src/ap/routes/**` | Reserved namespace. Do not assume any feature here is implemented. |
| `solid-pod-rs-git` | **STUB** (24 lines doc-only) | 69, 100 | v0.5.0 | `src/handlers/git.js` | Reserved. Git HTTP backend + `Basic nostr:` auth forward. |
| `solid-pod-rs-idp` | **STUB** (28 lines doc-only) | 74–82, 130 | v0.5.0 | `src/idp/**` | Reserved. Solid-OIDC provider (auth/token/me/reg/session + Passkeys + Schnorr SSO). |
| `solid-pod-rs-nostr` | **STUB** (25 lines doc-only) | 89, 90, 101, 132 | v0.5.0 | `src/nostr/relay.js` + `src/auth/did-nostr.js` + did-resolver shape (JSS lacks a single `src/did/resolver.js` file — see unverified note in breadcrumbs doc) | Reserved. Nostr relay NIP-01/11/16 + did:nostr publish endpoint. |

**Sibling-crate discipline.** These four crates exist on disk with
Cargo.toml entries so that workspace members resolve and so the
v0.5.0 namespace is reserved. They contain **no code**: each `lib.rs`
is 24–28 lines of doc comments describing the scope and the parity
rows that will move to `present` when the crate lands. Agents should
**not** infer coverage from the crate's existence — the parity
checklist is the authoritative tracker.

## When implementing a new feature

1. **Find the JSS source.** Use
   [`jss-source-breadcrumbs.md`](./jss-source-breadcrumbs.md) or
   `grep -r` in `JavaScriptSolidServer/src/`. Read the JSS
   implementation end-to-end before writing any Rust. The JSS
   implementation is the behavioural oracle for every spec-normative
   surface.
2. **Check the parity row.** Look up the feature in
   [`PARITY-CHECKLIST.md`](../../PARITY-CHECKLIST.md). Confirm the
   status (present / partial / semantic-diff / missing / net-new /
   deferred / wontfix / shared-gap / present-by-absence) and the cited
   Rust file:line. If the row is already `present`, you are doing a
   refinement; if `missing`, you are porting. If there is no row,
   consider whether you need to add one (rows are additive per
   sprint).
3. **Locate the Rust module.** Cross-reference the "Feature → module"
   tables above. If the feature crosses multiple modules (e.g. a PATCH
   dialect touches `ldp.rs` + `storage/`), put logic in the narrowest
   module and re-export through `lib.rs`.
4. **Write a test that matches the JSS fixture.** Use
   `tests/interop_jss.rs` as the conformance anchor; drop new tests
   next to the existing row-themed files (e.g. `tests/ldp_range_jss.rs`
   for Range-related work, `tests/wac_*.rs` for ACL). Prefer
   JSS-fixture-driven scenarios over hand-crafted inputs. The test
   name encodes the parity row where possible
   (e.g. `parity_row_40_where_failure_returns_412`).
5. **Update the parity row.** Flip the row from `missing` /
   `partial-parity` → `present` (or record a `semantic-difference`
   with a reconciliation note). Update the Sprint close headline
   counts at the top of the checklist.
6. **Run the full test suite** with `cargo test --all-features` and
   the default-feature build with `cargo test`. Ensure
   `cargo clippy --all-targets -- -D warnings` stays clean.
7. **Update this guide** if the public surface changed (new
   re-export from `lib.rs`, new trait, new feature flag, new
   module). This guide's "Public API cheat-sheet" and "Feature →
   module" tables must stay in lock-step with `lib.rs`.

## Common mistakes (for agents)

- **Don't assume sibling crates are implemented.** The four
  `solid-pod-rs-{activitypub,git,idp,nostr}` crates are **empty
  stubs** as of Sprint 9. Any feature you'd expect to find there
  (ActivityPub inbox, git HTTP, Solid-OIDC IdP, Nostr relay) is
  **missing** and tracked by a parity row with target milestone
  v0.5.0.
- **Content-type comes from the sidecar, not the extension.**
  `FsBackend` stores metadata in a `.meta.json` sidecar; the content
  type of a resource is whatever the sidecar says. Dotfiles
  (`.acl`, `.meta`) fall back to `infer_dotfile_content_type`
  (`application/ld+json`), **not** to `application/octet-stream`.
- **`Vary` lives in one place.** Don't reconstruct `Vary` in
  handler code. Call `ldp::vary_header(conneg_enabled)`. That's the
  single source of truth — the same helper JSS centralised via
  `getVaryHeader` in #315.
- **WAC evaluator is default-deny.** If there is no ACL up the
  parent chain, `evaluate_access` returns `Deny`. There is no
  implicit "root-only-owner-can-write" fallback; if you're getting
  unexpected 403s on a freshly created pod, the fix is to run
  `provision::provision_pod`, which seeds the owner-private root
  `.acl`.
- **Fail-closed on unknown WAC 2.0 conditions.** We are strictly
  more conformant than JSS here: JSS fails **open** on unrecognised
  `acl:condition` types; we return `Deny` (evaluator) or 422
  (PUT `.acl`). If you are adding a new condition type, register it
  with `ConditionRegistry::register` before a `.acl` using that IRI
  is accepted anywhere in the tree.
- **ETags are SHA-256 hex, not MD5.** JSS uses
  `md5(mtime+size)` (weak validator). We compute a strong
  SHA-256-hex ETag in `ResourceMeta::etag`. Both are spec-legal
  — don't paper over the difference with your own hash.
- **DPoP `jti` replay is per-process.** The `JtiReplayCache` is an
  in-memory LRU. In a multi-process deployment, you need a shared
  cache (Redis, ScyllaDB, …) — implement the same shape on top of
  your store. The library never promised a distributed cache.
- **Don't deep-import.** Import from `solid_pod_rs::` root using
  the `pub use` re-exports. Deep imports
  (`solid_pod_rs::ldp::Graph`, `solid_pod_rs::wac::parser::…`) are
  not a stability contract and will break across minor versions if
  the internal module layout moves.
- **Config loader is not always on.** The `config` module types
  are always compiled (for binder convenience), but the
  `config-loader` feature is the consumer-facing opt-in. Don't
  include `ConfigLoader` in a public type signature if you intend
  to ship without the feature.
- **NIP-98 Schnorr verification requires a feature.** The
  default build **does not** include Schnorr verification (no
  `k256` dependency). Consumers that want signature verification
  must enable `nip98-schnorr`.
- **Parity percentages drift.** The headline numbers (66% strict /
  85% spec-normative) are **Sprint 9 close**. Re-read
  [`PARITY-CHECKLIST.md`](../../PARITY-CHECKLIST.md) headline
  before quoting numbers in commit messages, docs, or PRs.

## Memory breadcrumbs

For an AI agent that needs to load this guide's structure into a
persistent memory system for future sessions, use the namespace
`solid-pod-rs-integration` and the following keys:

```javascript
// Top-level guide pointer
mcp__claude-flow__memory_store({
  key: "solid-pod-rs-agent-integration-guide",
  value: "path=crates/solid-pod-rs/docs/reference/agent-integration-guide.md; version=Sprint-9-close; parity=66%/85%; rows=121; tests=567; sibling-crates-status=all-four-stubs-v0.5.0",
  namespace: "solid-pod-rs-integration"
});

// JSS breadcrumbs doc pointer
mcp__claude-flow__memory_store({
  key: "solid-pod-rs-jss-breadcrumbs",
  value: "path=crates/solid-pod-rs/docs/reference/jss-source-breadcrumbs.md; inverse-lookup=JSS-file-to-Rust-module",
  namespace: "solid-pod-rs-integration"
});

// Parity checklist pointer
mcp__claude-flow__memory_store({
  key: "solid-pod-rs-parity-checklist",
  value: "path=crates/solid-pod-rs/PARITY-CHECKLIST.md; authoritative-row-tracker; 121-rows; sprint-9-close-2026-04-24",
  namespace: "solid-pod-rs-integration"
});

// Sibling crate reminder
mcp__claude-flow__memory_store({
  key: "solid-pod-rs-sibling-crates-are-stubs",
  value: "solid-pod-rs-activitypub/git/idp/nostr are empty stubs (24-28 lines lib.rs). Target milestone v0.5.0. Do NOT assume coverage.",
  namespace: "solid-pod-rs-integration"
});
```

On session start, search the namespace:

```javascript
mcp__claude-flow__memory_search({
  query: "solid-pod-rs parity integration guide",
  namespace: "solid-pod-rs-integration",
  limit: 5
});
```

---

*Last reconciled against PARITY-CHECKLIST at commit `2275146`
(Sprint 9 close, 2026-04-24). Every JSS path in the "Feature →
module" tables resolves under `JavaScriptSolidServer/src/`; every
Rust path resolves under `crates/solid-pod-rs/src/`; every parity
row is present in `PARITY-CHECKLIST.md`. If you find drift, file it
against this file and the parity checklist in the same commit.*
