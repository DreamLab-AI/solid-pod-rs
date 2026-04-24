# JSS → solid-pod-rs source breadcrumbs

> Inverse lookup companion to
> [`agent-integration-guide.md`](./agent-integration-guide.md). Given a
> JavaScriptSolidServer (JSS) source file, find the solid-pod-rs
> equivalent, its parity status, and the checklist row that tracks it.
> Verified against JSS clone at `/home/devuser/workspace/solid-pod-rs/JavaScriptSolidServer/`
> (62 `.js` files under `src/`, 18,778 lines of JSS source under that tree) and
> the Rust source tree at `crates/solid-pod-rs/src/`.

## How to use

Paired with
[`agent-integration-guide.md`](./agent-integration-guide.md). Use
**this** doc when you are reading JSS code and want to know:

- Do we have a port? (look at the status column)
- Where does it live in Rust? (file path)
- Which parity row(s) track the behaviour?
- Is the port complete, partial, semantically different, or blocked
  behind a v0.5.0 sibling crate?

Use the **other** doc when you start from a Solid feature name and
need a Rust module. The two are reciprocal indexes keyed on the same
parity rows in
[`PARITY-CHECKLIST.md`](../../PARITY-CHECKLIST.md).

## Status legend

| Glyph | Meaning |
|---|---|
| ✅ Present | Full port; behaviour reconciled; tests on both sides. |
| 🟡 Partial / semantic-difference | Some sub-features ported; delta documented. |
| 🔄 Net-new | solid-pod-rs has it; JSS does not. |
| ⏳ Sibling-stub | Port reserved for a v0.5.0 sibling crate; currently **not implemented**. |
| ❌ Missing | JSS has it; solid-pod-rs does not; no port under way. |
| 🚫 Deferred / wontfix | Out of scope (ADR or consumer concern). |

## File-by-file mapping

### Core JSS modules (root)

| JSS file | JSS lines | solid-pod-rs equivalent | Status | Parity row |
|---|---|---|---|---|
| `src/server.js` | 669 | `crates/solid-pod-rs-server/src/lib.rs` + `crates/solid-pod-rs-server/src/main.rs`; library helpers in `crates/solid-pod-rs/src/lib.rs` (framework-agnostic) | ✅ | 139, 140 |
| `src/index.js` | — | `crates/solid-pod-rs-server/src/main.rs` (CLI entry) + bin `solid-pod-rs-server` | ✅ | 139 |
| `src/config.js` | — | `src/config/loader.rs` + `src/config/schema.rs` + `src/config/sources.rs` | ✅ (feature `config-loader`) | 120, 121, 122, 123, 124 |
| `src/mashlib/index.js` | — | not implemented (consumer concern; `AppState::mashlib_cdn` exposes redirect URL only) | 🚫 wontfix-in-crate | 109 |
| `src/webledger.js` | 190 | not implemented (out of Solid spec scope) | 🚫 wontfix-in-crate | — |
| `src/webrtc/index.js` | 430 | not implemented (out of Solid spec scope) | 🚫 wontfix-in-crate | — |
| `src/remotestorage.js` | — | not implemented (out of Solid spec scope) | 🚫 wontfix-in-crate | — |
| `src/token.js` | — | `src/oidc/mod.rs::verify_access_token` (the newer Solid-OIDC token verification); dev Bearer helper is consumer concern | 🟡 | 61, 71 |
| `src/mrc20.js` | — | not implemented (out of scope) | 🚫 | — |
| `src/terminal/index.js` | — | not implemented (ops tooling, not library) | 🚫 wontfix-in-crate | — |
| `src/tunnel/index.js` | — | not implemented (ops tooling) | 🚫 wontfix-in-crate | — |

### LDP surface

| JSS file | JSS lines | solid-pod-rs equivalent | Status | Parity row |
|---|---|---|---|---|
| `src/ldp/container.js` | 48 | `src/ldp.rs` (`render_container_jsonld`, `render_container_turtle`, `server_managed_triples`, `find_illegal_server_managed`, container collect helpers) | ✅ | 5, 8, 9 |
| `src/ldp/headers.js` | 145 | `src/ldp.rs` (`link_headers`, `options_for`, `vary_header`, `cache_control_for`, `ACCEPT_PATCH`, `ACCEPT_POST`, `CACHE_CONTROL_RDF`) | ✅ | 15–29, 156, 157 |
| `src/handlers/resource.js` | 1031 | `src/ldp.rs` + `src/storage/mod.rs::Storage` trait + consumer binder (`crates/solid-pod-rs-server/src/lib.rs::handle_get` etc.) | ✅ | 1, 2, 3, 4 |
| `src/handlers/container.js` | 348 | `src/ldp.rs` (container handling, slug resolution) + `src/provision.rs::provision_pod::createPodStructure` equivalent | ✅ | 5, 6, 7, 8, 9, 14 |

### Content negotiation and RDF serialisation

| JSS file | JSS lines | solid-pod-rs equivalent | Status | Parity row |
|---|---|---|---|---|
| `src/rdf/conneg.js` | 226 | `src/ldp.rs` (`negotiate_format`, `RdfFormat`, `infer_dotfile_content_type`, `is_rdf_content_type`) | ✅ | 34, 35, 36, 167 |
| `src/rdf/turtle.js` | 487 | `src/ldp.rs` (`Graph::parse_turtle`, `Graph::parse_ntriples`, `Graph::to_ntriples`, `Term`, `Triple`) | ✅ | 37, 38 |

### PATCH dialects

| JSS file | JSS lines | solid-pod-rs equivalent | Status | Parity row |
|---|---|---|---|---|
| `src/patch/n3-patch.js` | 539 | `src/ldp.rs` (`apply_n3_patch`, `apply_patch_to_absent`, `PatchDialect::N3`) | ✅ | 39, 40 |
| `src/patch/sparql-update.js` | 401 | `src/ldp.rs` (`apply_sparql_patch` via `spargebra` crate — broader SPARQL 1.1 algebra coverage than JSS regex approach) | ✅ | 41 |

### Web Access Control

| JSS file | JSS lines | solid-pod-rs equivalent | Status | Parity row |
|---|---|---|---|---|
| `src/wac/parser.js` | 403 | `src/wac/parser.rs` + `src/wac/document.rs` (`parse_turtle_acl`, `parse_authorization_body`, `AclDocument`, `Authorization`) | ✅ | 56 |
| `src/wac/checker.js` | 327 | `src/wac/evaluator.rs` (`evaluate_access`, `evaluate_access_with_groups`) + `src/wac/resolver.rs` (`StorageAclResolver`) + `src/wac/conditions.rs` (WAC 2.0 dispatcher) | ✅ | 44–50, 51, 52–55 |

WAC 2.0 structure (Sprint 9 landings; no JSS equivalent for most of
this surface):

| Rust file | Scope | Parity row |
|---|---|---|
| `src/wac/conditions.rs` | `Condition::{Client,Issuer,Unknown}`, `ConditionRegistry`, `validate_for_write` (422-on-unknown) | 53, 56 |
| `src/wac/client.rs` | `ClientConditionEvaluator` — dispatches `acl:client*` | 54 |
| `src/wac/issuer.rs` | `IssuerConditionEvaluator` — dispatches `acl:issuer*` | 55 (hook for LWS10 SSI-CID) |
| `src/wac/origin.rs` | `OriginPolicy`, `Pattern`, `check_origin`, `extract_origin_patterns` | 51 (net-new vs JSS) |
| `src/wac/serializer.rs` | `serialize_turtle_acl` — no JSS equivalent | 57 |

### Authentication

| JSS file | JSS lines | solid-pod-rs equivalent | Status | Parity row |
|---|---|---|---|---|
| `src/auth/token.js` | 252 | consumer binder (primitives from `src/oidc/mod.rs::verify_access_token`); dev Bearer helper is out-of-scope | 🟡 / (consumer concern) | 61, 71, 72 |
| `src/auth/token-secret.js` | 122 | consumer binder responsibility (env-var handling) | 🚫 missing as primitive | 122 |
| `src/auth/solid-oidc.js` | 344 | `src/oidc/mod.rs` (`verify_dpop_proof`, `verify_dpop_proof_with_ath`, `verify_access_token`, `DpopVerified`, `AccessTokenVerified`, `CnfClaim`); alg dispatch in `verify_dpop_proof_core` | ✅ (Sprint 9 P0) | 62, 62b, 63, 64, 71 |
| `src/auth/nostr.js` | 273 | `src/auth/nip98.rs` (`verify_at`, `verify_schnorr_signature`, `Nip98Event`, `Nip98Verified`) | ✅ | 66, 67, 68 |
| `src/auth/nostr.js:39-46,178-200` (Basic nostr: for git) | — | ⏳ reserved for `solid-pod-rs-git` | ⏳ | 69 |
| `src/auth/did-nostr.js` | 232 | `src/interop.rs::did_nostr::DidNostrResolver` (feature `did-nostr`; resolver + DID-Doc helper); **publish endpoint** reserved for `solid-pod-rs-nostr` sibling crate | 🟡 (resolver present; publisher in sibling) | 89, 90 |
| `src/auth/webid-tls.js` | 270 | not implemented (legacy; ADR-053 defers) | 🚫 deferred | 70 |
| `src/auth/middleware.js` | 430 | consumer binder (actix) in `crates/solid-pod-rs-server/src/lib.rs`; WAC-on-write + dotfile gate + rate-limit live in the binder | 🟡 (primitives in place) | 55, 72, 73, 141 |

### IdP (Solid-OIDC provider — `solid-pod-rs-idp`, Sprint 10 + 11)

| JSS file | JSS lines | solid-pod-rs equivalent | Status | Parity row |
|---|---|---|---|---|
| `src/idp/index.js` | 431 | `crates/solid-pod-rs-idp/src/provider.rs` + `axum_binder.rs` | ✅ | 74 |
| `src/idp/provider.js` | 455 | `crates/solid-pod-rs-idp/src/provider.rs` + `registration.rs` — DCR + CID support | ✅ | 75, 78 |
| `src/idp/accounts.js` | 451 | `crates/solid-pod-rs-idp/src/user_store.rs` | ✅ | 135 |
| `src/idp/adapter.js` | 204 | `crates/solid-pod-rs-idp/src/session.rs` | ✅ | 74 |
| `src/idp/credentials.js` | 226 | `crates/solid-pod-rs-idp/src/credentials.rs` — email+password flow | ✅ | 79 |
| `src/idp/interactions.js` | 693 | `crates/solid-pod-rs-idp/src/schnorr.rs` — NIP-07 Schnorr SSO handshake | ✅ | 81 |
| `src/idp/invites.js` | 181 | `crates/solid-pod-rs-idp/src/invites.rs` + `solid-pod-rs-server invite create` CLI | ✅ | 83, 163 |
| `src/idp/keys.js` | 206 | `crates/solid-pod-rs-idp/src/jwks.rs` — JWKS with rotation | ✅ | 77, 130 |
| `src/idp/passkey.js` | 311 | `crates/solid-pod-rs-idp/src/passkey.rs` — `webauthn-rs 0.5` backend (Sprint 11) | ✅ | 80 |
| `src/idp/views.js` | 952 | HTML pages — wontfix-in-crate; row 82 explicit | 🚫 | 82 |

### LWS 1.0 Auth Suite (Sprint 11)

| JSS file | JSS lines | solid-pod-rs equivalent | Status | Parity row |
|---|---|---|---|---|
| `src/auth/solid-oidc.js` | — | `src/oidc/mod.rs` + `docs/adr/ADR-057-lws10-oidc-delta.md` | ✅ (delta audit) | 150 |
| (not implemented in JSS; tracked in JSS #86) | — | `crates/solid-pod-rs-didkey/` — Ed25519/P-256/secp256k1 encoding + JWT verify + `DidKeyVerifier` | 🔄 net-new | 153 |
| (not implemented in JSS) | — | `src/auth/self_signed.rs::{SelfSignedVerifier, CidVerifier}` + wiring into `wac::issuer::IssuerCondition` | 🔄 net-new | 152 |

### WebID

| JSS file | JSS lines | solid-pod-rs equivalent | Status | Parity row |
|---|---|---|---|---|
| `src/webid/profile.js` | 149 | `src/webid.rs` (`generate_webid_html`, `generate_webid_html_with_issuer`, `validate_webid_html`, `extract_oidc_issuer`) | ✅ | 84, 85, 86, 87, 88, 154, 155, 165 |

### Notifications

| JSS file | JSS lines | solid-pod-rs equivalent | Status | Parity row |
|---|---|---|---|---|
| `src/notifications/index.js` | 52 | `src/notifications/mod.rs` (`discovery_document`, `Notifications` trait, `InMemoryNotifications`) | ✅ / 🔄 (richer discovery) | 95, 96, 133 |
| `src/notifications/websocket.js` | 273 | `src/notifications/legacy.rs::LegacyWebSocketSession` (feature `legacy-notifications`) — full sub/ack/err/pub/unsub protocol; per-sub WAC Read re-check; 100 subs/conn cap; 2 KiB URL cap; ancestor-container fanout on publish (Sprint 11) | ✅ | 91 |
| `src/notifications/events.js` | 77 | `src/storage/fs.rs` watcher + `src/notifications/mod.rs::pump_from_storage` | ✅ | 99 |
| (no JSS equivalent) | — | `src/notifications/mod.rs::WebSocketChannelManager` — Solid Notifications 0.2 WebSocketChannel2023 | 🔄 net-new | 92 |
| (no JSS equivalent) | — | `src/notifications/mod.rs::WebhookChannelManager` + `src/notifications/signing.rs` (RFC 9421) | 🔄 net-new | 93, 97 |

### Discovery (well-known)

| JSS file/route | JSS lines | solid-pod-rs equivalent | Status | Parity row |
|---|---|---|---|---|
| `src/ap/index.js:80` (`/.well-known/webfinger`) | (in 217-line file) | `src/interop.rs::webfinger_response` → `WebFingerJrd`, `WebFingerLink` | ✅ | 105 |
| `src/ap/index.js:116,130` (`/.well-known/nodeinfo[/2.1]`) | (in 217) | `src/interop.rs::nodeinfo_discovery`, `nodeinfo_2_1` + server route registered | ✅ | 106, 131 |
| (no JSS equivalent) `/.well-known/solid` | — | `src/interop.rs::well_known_solid` → `SolidWellKnown` | 🔄 net-new | 127 |
| (no JSS equivalent) `/.well-known/nostr.json` | — | `src/interop.rs::verify_nip05`, `nip05_document` → `Nip05Document` | 🔄 net-new | 128 |
| `src/idp/index.js:171` (`/.well-known/openid-configuration`) | (in 431) | `src/oidc/mod.rs::discovery_for` → `DiscoveryDocument` | ✅ | 129 |
| `src/idp/index.js:208` (`/.well-known/jwks.json`) | (in 431) | `src/oidc/jwks.rs` primitive; endpoint hosted by consumer/IdP crate | 🟡 | 130 |
| (JSS reference — no single file, JSS closest is `src/auth/did-nostr.js`) `/.well-known/did/nostr/:pubkey.json` | — | `src/interop.rs::did_nostr::did_nostr_well_known_url` + route in `crates/solid-pod-rs-server/src/lib.rs` (feature `did-nostr`) | ✅ (resolver); 🟡 (publisher via sibling) | 132 |
| `src/notifications/index.js:43` (`/.well-known/solid/notifications` status) | (in 52) | `src/notifications/mod.rs::discovery_document` (full Solid Notifications 0.2 descriptor, richer than JSS status JSON) | 🔄 net-new | 95, 133 |

### ActivityPub (`solid-pod-rs-activitypub`, Sprint 10 — functional)

| JSS file | JSS lines | solid-pod-rs equivalent | Status | Parity row |
|---|---|---|---|---|
| `src/ap/index.js` | 217 | `crates/solid-pod-rs-activitypub/src/lib.rs` + `discovery.rs`. WebFinger also lives in core `src/interop.rs`. | ✅ | 102, 105 |
| `src/ap/keys.js` | 64 | `crates/solid-pod-rs-activitypub/src/http_sig.rs` — draft-cavage v12 | ✅ | 102 |
| `src/ap/store.js` | 276 | `crates/solid-pod-rs-activitypub/src/store.rs` — sqlx follower/following store | ✅ | 107 |
| `src/ap/routes/actor.js` | 70 | `crates/solid-pod-rs-activitypub/src/routes/actor.rs` | ✅ | 102 |
| `src/ap/routes/collections.js` | 46 | `crates/solid-pod-rs-activitypub/src/routes/collections.rs` | ✅ | 104, 107 |
| `src/ap/routes/inbox.js` | 247 | `crates/solid-pod-rs-activitypub/src/routes/inbox.rs` — HTTP Sig verify landed | ✅ | 103 |
| `src/ap/routes/outbox.js` | 149 | `crates/solid-pod-rs-activitypub/src/routes/outbox.rs` — retry delivery | ✅ | 104 |
| `src/ap/routes/mastodon.js` | 154 | `crates/solid-pod-rs-activitypub/src/routes/mastodon.rs` | ✅ | 102, 108 |
| `src/ap/routes/oauth.js` | 311 | `crates/solid-pod-rs-activitypub/src/routes/oauth.rs` | ✅ | 102 |

### Git HTTP backend (`solid-pod-rs-git`, Sprint 10 — functional)

| JSS file | JSS lines | solid-pod-rs equivalent | Status | Parity row |
|---|---|---|---|---|
| `src/handlers/git.js` | 269 | `crates/solid-pod-rs-git/src/cgi.rs` — `git-http-backend` bridge | ✅ | 100 |
| (WAC hook in `src/server.js:286-314`) | — | `crates/solid-pod-rs-git/src/auth.rs::BasicNostrExtractor` delegates to core NIP-98 | ✅ | 100 |

### Storage and quota

| JSS file | JSS lines | solid-pod-rs equivalent | Status | Parity row |
|---|---|---|---|---|
| `src/storage/filesystem.js` | 187 | `src/storage/fs.rs` (`FsBackend` with `.meta.json` sidecars + `notify` watcher) | ✅ | 116 |
| `src/storage/quota.js` | 238 | `src/quota/mod.rs` (feature `quota`) — `QuotaPolicy`, `FsQuotaStore`, atomic `write_sidecar`, `sweep_quota_orphans`, `reconcile` | ✅ (Sprint 8 P0 cleared) | 113, 159, 160, 161 |

### Utilities

| JSS file | JSS lines | solid-pod-rs equivalent | Status | Parity row |
|---|---|---|---|---|
| `src/utils/ssrf.js` | 157 | `src/security/ssrf.rs` (`is_safe_url`, `resolve_and_check`, `SsrfPolicy`, `IpClass`, `SsrfError`) | ✅ (Sprint 9 P0 cleared) | 65, 114 |
| `src/utils/conditional.js` | 153 | `src/ldp.rs::evaluate_preconditions` → `ConditionalOutcome` | ✅ | 31 |
| `src/utils/url.js` | 292 | `src/ldp.rs::infer_dotfile_content_type` (the "getContentType for dotfiles" portion) + URL helpers inline in relevant modules | 🟡 partial (we port the conneg-relevant parts) | 167 |
| `src/utils/error-handler.js` | 24 | `src/error.rs::PodError` + consumer binder error mapping in `crates/solid-pod-rs-server/src/lib.rs` | ✅ | — |

### Nostr relay (`solid-pod-rs-nostr`, Sprint 10 — functional)

| JSS file | JSS lines | solid-pod-rs equivalent | Status | Parity row |
|---|---|---|---|---|
| `src/nostr/relay.js` | — | `crates/solid-pod-rs-nostr/src/relay.rs` — NIP-01 core + NIP-11 info + NIP-16 replaceable | ✅ | 101 |
| (JSS closest analog `src/auth/did-nostr.js`) | — | `crates/solid-pod-rs-nostr/src/did.rs` (publisher, tier 1/3 DID Document) + core `src/interop.rs::did_nostr` (resolver) + `crates/solid-pod-rs-nostr/src/resolver.rs` (bidirectional WebID ↔ did:nostr) | ✅ | 89, 90, 132 |

### did:key + self-signed JWT (`solid-pod-rs-didkey`, Sprint 11 — NEW)

| JSS file | JSS lines | solid-pod-rs equivalent | Status | Parity row |
|---|---|---|---|---|
| (not implemented in JSS; tracked in JSS #86) | — | `crates/solid-pod-rs-didkey/src/did.rs` — W3C did:key Method encoding/decoding (multibase + multicodec) | 🔄 net-new | 153 |
| (not implemented in JSS) | — | `crates/solid-pod-rs-didkey/src/pubkey.rs` — Ed25519 / P-256 / secp256k1 DER + raw-key parsing | 🔄 net-new | 153 |
| (not implemented in JSS) | — | `crates/solid-pod-rs-didkey/src/jwt.rs` — hand-rolled self-signed JWT verify with algorithm dispatch and `alg=none` hard-reject | 🔄 net-new | 152, 153 |
| (not implemented in JSS) | — | `crates/solid-pod-rs-didkey/src/verifier.rs` — `DidKeyVerifier` impl of core `SelfSignedVerifier` trait | 🔄 net-new | 152, 153 |

### DB (embedded SQLite used by JSS for AP state)

| JSS file | JSS lines | solid-pod-rs equivalent | Status | Parity row |
|---|---|---|---|---|
| `src/db/index.js` | 306 | not applicable (`sql.js` used for AP state only; our AP port will choose its own store) | 🚫 deferred | 119 |
| `src/db/store.js` | 154 | not applicable | 🚫 deferred | 119 |

### Binary / CLI

| JSS file | JSS lines | solid-pod-rs equivalent | Status | Parity row |
|---|---|---|---|---|
| `bin/jss.js` (commands: `start`, `init`, `invite`, `quota`) | — | `crates/solid-pod-rs-server/src/main.rs` (CLI with `--config`, `--host`, `--port`, `--log`, `--mashlib-cdn`; TLS via `ssl-key`/`ssl-cert`); `invite` and `quota` subcommands reserved as P3 operator tooling | ✅ (`start`) / ❌ (`invite`, `quota`, `init`) | 139 |

### Ops and deployment helpers (root-level, not under `src/`)

| JSS file | Role | solid-pod-rs equivalent | Status |
|---|---|---|---|
| `benchmark.js` | `autocannon`-based HTTP perf | `benches/*.rs` with criterion (4 benches: storage, wac, conneg, nip98; plus `dpop_replay_bench`) | ✅ |
| `visualize-results.js` | Benchmark viz | — | 🚫 deferred |
| `clock-updater.mjs` | Clock scenarios for tests | test harness helpers | 🚫 ops concern |
| `scripts/test-cth-compat.js` | CTH conformance runner | — | ❌ missing (row 148) |

---

## Reverse index: features blocked behind sibling-crate stubs

### Blocked behind `solid-pod-rs-activitypub` (v0.5.0)

| JSS file | Parity row |
|---|---|
| `src/ap/index.js` (minus WebFinger) | 102 |
| `src/ap/keys.js` | 102 |
| `src/ap/store.js` | 107 |
| `src/ap/routes/actor.js` | 102 |
| `src/ap/routes/collections.js` | 104, 107 |
| `src/ap/routes/inbox.js` | 103 |
| `src/ap/routes/outbox.js` | 104 |
| `src/ap/routes/mastodon.js` | 102, 108 |
| `src/ap/routes/oauth.js` | 102 |

### Blocked behind `solid-pod-rs-git` (v0.5.0)

| JSS file | Parity row |
|---|---|
| `src/handlers/git.js` | 100 |
| `src/auth/nostr.js:39-46,178-200` (`Basic nostr:` for git clients) | 69 |

### Blocked behind `solid-pod-rs-idp` (v0.5.0)

| JSS file | Parity row |
|---|---|
| `src/idp/index.js` | 74 |
| `src/idp/provider.js` | 75, 78 |
| `src/idp/accounts.js` | 135 |
| `src/idp/adapter.js` | 74 |
| `src/idp/credentials.js` | 79 |
| `src/idp/interactions.js` | 81 |
| `src/idp/keys.js` | 77, 130 |
| `src/idp/passkey.js` | 80 |
| `src/idp/views.js` | 82 (also wontfix-in-crate for HTML pages) |
| `src/idp/invites.js` (JSS-side) | 83, 163 (operator tooling) |

### Blocked behind `solid-pod-rs-nostr` (v0.5.0)

| JSS file | Parity row |
|---|---|
| `src/nostr/relay.js` | 101 |
| `/.well-known/did/nostr/:pubkey.json` publisher | 132 (resolver already present in `src/interop.rs`) |
| `src/auth/did-nostr.js` publisher-side surfaces | 89, 90 (resolver-side landed; publisher reserved) |

### Wontfix-in-crate (consumer concern, not a sibling crate)

| JSS file | Rationale | Parity row |
|---|---|---|
| `src/mashlib/index.js` | SolidOS data-browser static serving — consumer's job (E.9) | 109 |
| `src/webledger.js`, `src/webrtc/index.js`, `src/remotestorage.js`, `src/mrc20.js`, `src/terminal/index.js`, `src/tunnel/index.js`, `src/handlers/pay.js` | Out of Solid spec scope — JSS-specific extensions the library does not adopt | — |
| `src/idp/views.js` (HTML login/register pages) | HTML UI is consumer concern | 82 |

---

## Verification checklist

For an agent updating this doc (or a reviewer auditing a breadcrumb),
run the following checks:

1. **Every JSS path resolves.** For each row's JSS file, run
   `test -f /home/devuser/workspace/solid-pod-rs/JavaScriptSolidServer/<path>`;
   expect exit 0. Paths that don't resolve are bugs — flag with
   `⚠️ unverified` until fixed, never silently retain.
2. **Every Rust path resolves.** Same for
   `test -f /home/devuser/workspace/solid-pod-rs/crates/solid-pod-rs/<path>`
   (or the sibling crate's path for ⏳ entries — there the stub
   `lib.rs` is the target).
3. **Every parity row exists.** Each row number in the "Parity row"
   column must appear in
   [`PARITY-CHECKLIST.md`](../../PARITY-CHECKLIST.md) (row numbers
   never re-shuffle; additions are strictly appended). Use
   `grep -E '^\| [0-9]+ ' PARITY-CHECKLIST.md` to enumerate.
4. **Status glyph matches the parity row.** If the parity row says
   `missing` but this doc shows ✅, or vice versa, the checklist wins
   — update this doc.
5. **Sibling-stub claims are real stubs.** Every ⏳ entry should
   correspond to a crate whose `lib.rs` is ≤ 30 lines and contains
   only doc comments (not Rust items). Confirm with
   `wc -l crates/solid-pod-rs-<name>/src/lib.rs` (expect 24–28
   lines).
6. **Line counts are current.** JSS files are edited upstream; if
   the "JSS lines" column drifts by more than 5%, refresh with
   `wc -l`.

### Known unverified references (flagged for future work)

| Reference | Issue | Action |
|---|---|---|
| `src/did/resolver.js` (mentioned in sprint context as a planned `solid-pod-rs-nostr` target) | File does not exist under `JavaScriptSolidServer/src/` — the closest JSS analog is `src/auth/did-nostr.js`. | Marked `⚠️ unverified` under the Nostr-relay section. When `solid-pod-rs-nostr` lands, the port should target `src/auth/did-nostr.js` (publisher path) and the Nostr-specific fragments in that file. |

---

*Last reconciled against PARITY-CHECKLIST at commit `2275146`
(Sprint 9 close, 2026-04-24). 62 JSS `.js` files under `src/`
(18,778 LOC) mapped. 41 Rust files under
`crates/solid-pod-rs/src/` indexed (15,504 LOC). 4 sibling-crate
stubs documented. 121 parity rows cross-referenced. If you find
drift, update both this file and the parity checklist in the same
commit.*
