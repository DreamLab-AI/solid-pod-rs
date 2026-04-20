# JSS ↔ solid-pod-rs Parity Checklist

Tracks every Solid protocol feature implemented by
JavaScriptSolidServer (JSS, vendored at
`references/javascript-solid-server/`) against solid-pod-rs. Updated
every time a feature ships or regresses.

## Status key

| Status    | Meaning                                                              |
|-----------|----------------------------------------------------------------------|
| present   | Feature works in solid-pod-rs and has passing tests.                 |
| partial   | Some sub-features exist; gaps documented in the Notes column.        |
| missing   | Not yet implemented.                                                 |

## Core LDP

| Feature                                          | Status  | Target | Notes |
|--------------------------------------------------|---------|--------|-------|
| LDP Resource (RDF/non-RDF) GET/HEAD              | present | P1     | `Storage::get`/`head`; Link `rel=type` emitted. |
| LDP Resource PUT (create-or-replace)             | present | P1     | `Storage::put`; returns ETag. |
| LDP Resource DELETE                              | present | P1     | `Storage::delete`. |
| LDP Basic Container GET (contains triples)       | present | P1     | `ldp::render_container`. |
| LDP Container POST (Slug → child resource)       | present | P1     | `ldp::resolve_slug`; UUID fallback. |
| LDP PUT-to-container rejection                   | present | P1     | Example server returns 405. |
| Server-managed triples (dateModified, size)      | present | P2     | `ldp::server_managed_triples` emits `dc:modified`, `stat:size`, `stat:mtime`, `ldp:contains`. Client attempts blocked via `find_illegal_server_managed`. |
| `contains` triples include direct children only  | present | P1     | `Storage::list` collapses nested. |
| Prefer headers (PreferMinimalContainer, PreferContainedIRIs) | present | P2 | `ldp::PreferHeader::parse`; selects representation mode. |
| Accept-Post on containers                        | present | P2     | `ldp::ACCEPT_POST` constant + `link_headers` emits all three media types. |

## Web Access Control (WAC)

| Feature                                          | Status  | Target | Notes |
|--------------------------------------------------|---------|--------|-------|
| `acl:Read` mode                                  | present | P1     | `wac::evaluate_access`. |
| `acl:Write` mode (implies Append)                | present | P1     | Unit-tested. |
| `acl:Append` mode                                | present | P1     | |
| `acl:Control` mode                               | present | P1     | |
| `acl:agent` (specific agent)                     | present | P1     | Multi-agent block covered by inheritance corpus. |
| `acl:agentClass foaf:Agent` (public)             | present | P1     | |
| `acl:agentClass acl:AuthenticatedAgent`          | present | P1     | |
| `acl:agentGroup` (vcard:Group)                   | present | P2     | `tests/wac_inheritance.rs::group_membership_grants_access` evaluates group resolver. |
| `acl:accessTo` exact + child match               | present | P1     | |
| `acl:default` container inheritance              | present | P1     | Expanded in inheritance corpus (15+ scenarios). |
| `.acl` sidecar resolution walking up tree        | present | P1     | `StorageAclResolver`. |
| `WAC-Allow` response header                      | present | P1     | `wac::wac_allow_header`. |
| ACL document read via HTTP (GET `.acl`)          | present | P2     | Interop tests `acl_read_via_http`. |
| ACL document write requires `acl:Control`        | present | P2     | Interop test `acl_write_requires_control`. |
| Turtle-serialized ACL documents                  | partial | P2     | JSON-LD path exercised throughout; Turtle deserialisation still the ecosystem-crate concern. |

## Authentication

| Feature                                          | Status  | Target | Notes |
|--------------------------------------------------|---------|--------|-------|
| NIP-98 HTTP auth (kind 27235, `u`/`method`/`payload` tags) | present | P1 | `auth::nip98::verify_at` — all structural checks. |
| NIP-98 Schnorr signature verification            | partial | P2     | Structural checks done; signature verification to be wired via `k256` in P2. |
| NIP-98 timestamp tolerance (60s)                 | present | P1     | |
| Solid-OIDC auth (DPoP-bound tokens)              | present | P2     | `oidc::verify_access_token` + `verify_dpop_proof`, feature `oidc`. HS256 covered by tests; ES256/RS256 supported via jsonwebtoken. |
| OIDC Dynamic Client Registration (RFC 7591)      | present | P2     | `oidc::register_client`. |
| OIDC Discovery document                          | present | P2     | `oidc::discovery_for`. |
| Token introspection (RFC 7662)                   | present | P2     | `oidc::IntrospectionResponse`. |
| WebID extraction (`webid` claim + url-shaped sub) | present | P2    | `oidc::extract_webid`. |
| WebID-TLS                                        | missing | deferred | Legacy; not a priority. |
| Dev-mode session bypass                          | missing | P2     | VisionClaw-specific; will live in consumer crate. |

## WebID

| Feature                                          | Status  | Target | Notes |
|--------------------------------------------------|---------|--------|-------|
| WebID profile document generation (HTML+JSON-LD) | present | P1     | `webid::generate_webid_html`. |
| WebID profile validation                         | present | P1     | `webid::validate_webid_html`. |
| WebID-OIDC discovery (`solid:oidcIssuer`)        | partial | P2+    | Discovery doc lists issuer; profile integration deferred. |

## Content negotiation

| Feature                                          | Status  | Target | Notes |
|--------------------------------------------------|---------|--------|-------|
| Content-type passthrough                         | present | P1     | |
| Turtle ⇄ JSON-LD conversion                      | present | P2     | `render_container_jsonld` / `render_container_turtle` + shared `Graph` model. |
| N-Triples                                        | present | P2     | `Graph::to_ntriples` / `Graph::parse_ntriples`. |
| RDF/XML                                          | partial | P2+    | Format negotiated; serialisation deferred to consumer crate. |
| Accept header negotiation                        | present | P2     | `ldp::negotiate_format`, q-value aware. |

## Metadata / Link headers

| Feature                                          | Status  | Target | Notes |
|--------------------------------------------------|---------|--------|-------|
| `Link: <...>; rel="type"` for LDP types          | present | P1     | `ldp::link_headers`. |
| `Link: <.acl>; rel="acl"`                        | present | P1     | |
| `Link: <.meta>; rel="describedby"`               | present | P2     | Emitted for every non-meta, non-acl path. |
| `Link: rel="http://www.w3.org/ns/pim/space#storage"` | present | P2 | Emitted for pod root `/`. |
| ETag header on read/write                        | present | P1     | SHA-256 hex. |
| If-Match / If-None-Match conditional requests    | partial | P2     | Storage layer returns ETag; conditional enforcement is P2. |
| Range requests                                   | missing | P2     | |

## PATCH

| Feature                                          | Status  | Target | Notes |
|--------------------------------------------------|---------|--------|-------|
| JSON Patch (RFC 6902)                            | missing | P2     | Present in pod-worker; deliberately not ported to keep surface focused. |
| N3 PATCH (solid-protocol)                        | present | P2     | `ldp::apply_n3_patch`; handles `inserts`/`deletes`/`where`. |
| SPARQL-Update PATCH                              | present | P2     | `ldp::apply_sparql_patch` via `spargebra`. |

## Notifications

| Feature                                          | Status  | Target | Notes |
|--------------------------------------------------|---------|--------|-------|
| Subscription trait + in-memory registry          | present | P1     | `notifications::InMemoryNotifications`. |
| WebhookChannel2023 delivery                      | present | P2     | `WebhookChannelManager`: AS2.0 POST, 3× exponential retry on 5xx, drop on 4xx. |
| WebSocketChannel2023 delivery                    | present | P2     | `WebSocketChannelManager`: broadcast channel feeds per-connection WebSocket writers; 30s heartbeat. |
| Subscription discovery (.notifications)          | present | P2     | `notifications::discovery_document`. |
| Retry + dead-letter                              | present | P2     | Exponential backoff + fatal-drop tracking. |

## Storage backends

| Feature                                          | Status  | Target | Notes |
|--------------------------------------------------|---------|--------|-------|
| Memory backend                                   | present | P1     | Includes broadcast watcher. |
| Filesystem backend                               | present | P1     | `.meta.json` sidecars + `notify`-based watcher. |
| S3 backend                                       | partial | P2     | Feature flag `s3-backend` declared; impl is P2. |
| R2 / D1 / KV adapters                            | missing | P2+    | Consumer-crate concern. |
| Quota enforcement                                | missing | P2     | Pod-worker has it; deferred for parity. |

## Provisioning

| Feature                                          | Status  | Target | Notes |
|--------------------------------------------------|---------|--------|-------|
| `.provision` endpoint creating seeded containers | missing | P2     | Pod-worker ships this; example server lacks it. |
| WebID + account scaffolding                      | missing | P2     | |
| Admin override                                   | missing | P2     | |

## Interop / discovery

| Feature                                          | Status  | Target | Notes |
|--------------------------------------------------|---------|--------|-------|
| `.well-known/solid` discovery doc                | partial | P2     | OIDC discovery doc implemented via `oidc::discovery_for`; Solid-wide discovery deferred. |
| WebFinger integration                            | missing | P2     | Present in pod-worker; deferred. |
| NIP-05 verification                              | missing | P2     | |
| RemoteStorage compatibility                      | missing | P2+    | |

## Tests

| Feature                                          | Status  | Target | Notes |
|--------------------------------------------------|---------|--------|-------|
| Storage trait conformance suite                  | present | P1     | Memory + FS both pass. |
| WAC smoke tests                                  | present | P1     | |
| ACL inheritance corpus                           | present | P2     | `tests/wac_inheritance.rs` — 28 scenarios derived from WAC §5/§6. |
| JSS interop parity corpus                        | present | P2     | `tests/interop_jss.rs` — 22 fixture-driven tests covering Link headers, content-neg, ACL gating, LDP containment, error codes. |
| NIP-98 structural tests                          | present | P1     | |
| LDP container rendering                          | present | P1     | |
| LDP PATCH tests (N3 + SPARQL)                    | present | P2     | `ldp::tests` covers insert/delete/where, INSERT DATA, DELETE DATA. |
| OIDC access-token + DPoP tests                   | present | P2     | Feature-gated under `oidc`. |
| Example server (actix-web)                       | present | P1     | `cargo run --example standalone`. |

## Phase 2 coverage by spec clause

| Test                                            | Validates                                |
|-------------------------------------------------|------------------------------------------|
| `link_headers_root_exposes_pim_storage`         | LDP 4.2.1.3 + pim:storage advertisement  |
| `link_headers_include_acl_and_describedby`      | Solid Protocol §4.1.1 (metadata discovery) |
| `prefer_minimal_container_parsed`               | LDP 4.2.2 / 7240 (Prefer)                |
| `prefer_contained_iris_parsed`                  | LDP 4.2.2                                |
| `negotiate_prefers_explicit_turtle`             | Solid Protocol §3.1                      |
| `ntriples_roundtrip`                            | RDF 1.1 N-Triples                        |
| `server_managed_triples_include_ldp_contains`   | LDP 5.2.1.4                              |
| `find_illegal_server_managed_flags_ldp_contains`| LDP 5.2.3.1 (server-managed restriction) |
| `n3_patch_insert_and_delete`                    | Solid Protocol §8.2 (N3 Patch)           |
| `n3_patch_where_failure_returns_precondition`   | Solid Protocol §8.2 (precondition)       |
| `sparql_insert_data`, `sparql_delete_data`      | SPARQL 1.1 Update §3.1.1, §3.1.2         |
| `websocket_manager_broadcasts_events`           | Notifications 0.2 §6 (WebSocketChannel)  |
| `discovery_lists_both_channels`                 | Notifications 0.2 §5                      |
| `change_notification_maps_event_types`          | Activity Streams 2.0                      |
| `access_token_binds_to_dpop_jkt`                | Solid-OIDC §5.2 (DPoP binding)           |
| `access_token_rejects_wrong_jkt`                | Solid-OIDC §5.2 (binding enforcement)    |
| `extract_webid_from_explicit_claim`             | Solid-OIDC §5.4                           |
| `extract_webid_falls_back_to_sub_when_url`      | Solid-OIDC §5.4 fallback                  |
| `dynamic_registration_returns_client_id`        | RFC 7591                                  |
| `discovery_contains_standard_endpoints`         | OpenID Connect Discovery 1.0              |

## Phase 1 → Phase 2 boundary

Everything marked `P2` in the status column is in-scope for this
sprint. Any `missing` in a P1/P2 row is a regression. P2+ items are
consumer-crate concerns tracked for informational purposes only.

## Summary counts (Phase 2 close)

- **present**: 48 (was 27)
- **partial**: 8 (was 7)
- **missing**: 11 (was 25)
