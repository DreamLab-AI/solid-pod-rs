# JSS ↔ solid-pod-rs Parity Checklist

Tracks every Solid protocol feature implemented by the JavaScript
Solid Server (JSS, vendored at `references/community-solid-server/`)
against solid-pod-rs. Updated every time a feature ships or regresses.

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
| Server-managed triples (dateModified, size)      | partial | P2     | `ResourceMeta.modified/size` present; not yet rendered as triples. |
| `contains` triples include direct children only  | present | P1     | `Storage::list` collapses nested. |
| Prefer headers (PreferMinimalContainer, PreferContainedIRIs) | missing | P2 | Not yet parsed. |

## Web Access Control (WAC)

| Feature                                          | Status  | Target | Notes |
|--------------------------------------------------|---------|--------|-------|
| `acl:Read` mode                                  | present | P1     | `wac::evaluate_access`. |
| `acl:Write` mode (implies Append)                | present | P1     | Unit-tested. |
| `acl:Append` mode                                | present | P1     | |
| `acl:Control` mode                               | present | P1     | |
| `acl:agent` (specific agent)                     | present | P1     | |
| `acl:agentClass foaf:Agent` (public)             | present | P1     | |
| `acl:agentClass acl:AuthenticatedAgent`          | present | P1     | |
| `acl:agentGroup` (vcard:Group)                   | missing | P2     | JSS supports group membership resolution. |
| `acl:accessTo` exact + child match               | present | P1     | |
| `acl:default` container inheritance              | present | P1     | |
| `.acl` sidecar resolution walking up tree        | present | P1     | `StorageAclResolver`. |
| `WAC-Allow` response header                      | present | P1     | `wac::wac_allow_header`. |
| ACL document read via HTTP (GET `.acl`)          | partial | P2     | Storage supports it; HTTP handler in example only. |
| ACL document write requires `acl:Control`        | partial | P2     | Logic exists in source port; HTTP wiring is P2. |
| Turtle-serialized ACL documents                  | missing | P2     | JSON-LD only at P1 (matches pod-worker source). |

## Authentication

| Feature                                          | Status  | Target | Notes |
|--------------------------------------------------|---------|--------|-------|
| NIP-98 HTTP auth (kind 27235, `u`/`method`/`payload` tags) | present | P1 | `auth::nip98::verify_at` — all structural checks. |
| NIP-98 Schnorr signature verification            | partial | P2     | Structural checks done; signature verification to be wired via `k256` in P2. |
| NIP-98 timestamp tolerance (60s)                 | present | P1     | |
| Solid-OIDC auth (DPoP-bound tokens)              | missing | P2+    | JSS supports full Solid-OIDC; out-of-scope for pod-worker extraction. |
| WebID-TLS                                        | missing | deferred | Legacy; not a priority. |
| Dev-mode session bypass                          | missing | P2     | VisionClaw-specific; will live in consumer crate. |

## WebID

| Feature                                          | Status  | Target | Notes |
|--------------------------------------------------|---------|--------|-------|
| WebID profile document generation (HTML+JSON-LD) | present | P1     | `webid::generate_webid_html`. |
| WebID profile validation                         | present | P1     | `webid::validate_webid_html`. |
| WebID-OIDC discovery (`solid:oidcIssuer`)        | missing | P2+    | |

## Content negotiation

| Feature                                          | Status  | Target | Notes |
|--------------------------------------------------|---------|--------|-------|
| Content-type passthrough                         | present | P1     | |
| Turtle ⇄ JSON-LD conversion                      | missing | P2     | Requires RDF library; not needed by pod-worker. |
| N-Triples, N3, RDF/XML                           | missing | P2+    | |
| Accept header negotiation                        | missing | P2     | Pod-worker does passthrough only. |

## Metadata / Link headers

| Feature                                          | Status  | Target | Notes |
|--------------------------------------------------|---------|--------|-------|
| `Link: <...>; rel="type"` for LDP types          | present | P1     | `ldp::link_headers`. |
| `Link: <.acl>; rel="acl"`                        | present | P1     | |
| `Link: <.meta>; rel="describedby"`               | missing | P2     | Planned via `.meta` sidecars (FS backend already has them). |
| `Link: rel="http://www.w3.org/ns/pim/space#storage"` | missing | P2 | Pod-root marker. |
| ETag header on read/write                        | present | P1     | SHA-256 hex. |
| If-Match / If-None-Match conditional requests    | partial | P2     | Storage layer returns ETag; conditional enforcement is P2. |
| Range requests                                   | missing | P2     | |

## PATCH

| Feature                                          | Status  | Target | Notes |
|--------------------------------------------------|---------|--------|-------|
| JSON Patch (RFC 6902)                            | missing | P2     | Present in pod-worker; deliberately not ported to P1 to keep surface focused. |
| N3 PATCH                                         | missing | P2+    | JSS-native format. |
| SPARQL-Update PATCH                              | missing | P2+    | |

## Notifications

| Feature                                          | Status  | Target | Notes |
|--------------------------------------------------|---------|--------|-------|
| Subscription trait + in-memory registry          | present | P1     | `notifications::InMemoryNotifications`. |
| WebhookChannel2023 delivery                      | missing | P2     | Trait stub only. |
| WebSocketChannel2023 delivery                    | missing | P2     | |
| Subscription discovery (.notifications)          | missing | P2     | |
| Retry + dead-letter                              | missing | P2     | |

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
| `.well-known/solid` discovery doc                | missing | P2     | |
| WebFinger integration                            | missing | P2     | Present in pod-worker; deferred. |
| NIP-05 verification                              | missing | P2     | |
| RemoteStorage compatibility                      | missing | P2+    | |

## Tests

| Feature                                          | Status  | Target | Notes |
|--------------------------------------------------|---------|--------|-------|
| Storage trait conformance suite                  | present | P1     | Memory + FS both pass. |
| WAC smoke tests                                  | present | P1     | |
| NIP-98 structural tests                          | present | P1     | |
| LDP container rendering                          | present | P1     | |
| Example server (actix-web)                       | present | P1     | `cargo run --example standalone`. |

## Phase 1 → Phase 2 boundary

Everything marked `P2` is explicitly deferred. `P1` is the scope of
this sprint; anything other than present/partial in P1 rows is a
regression. P2+ covers items that aren't even on JSS's core path and
will only be tackled if a VisionClaw consumer needs them.

## Summary counts (Phase 1 close)

- **present**: 27
- **partial**: 7
- **missing**: 25
