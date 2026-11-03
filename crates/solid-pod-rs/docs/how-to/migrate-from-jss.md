# How to migrate from JSS (JavaScriptSolidServer)

**Goal:** move a production pod from
[JavaScriptSolidServer (JSS)](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer)
to a solid-pod-rs-backed server, with no data loss and a tested
rollback.

This guide is written for operators who already run JSS and want to
replace the runtime while keeping their pod data intact. Both JSS and
solid-pod-rs are licensed **AGPL-3.0-only**; solid-pod-rs inherits
the licence from the JSS ecosystem covenant. Replacing the server
runtime does not change the licence of data stored in the pod, and it
does not change your AGPL compliance surface — AGPL §13 continues to
require that users of the network service receive the corresponding
source code. You are swapping one AGPL server for another AGPL server;
licence-wise, nothing changes.

## TL;DR

1. Freeze writes to the JSS pod.
2. Copy `$JSS_ROOT/` (default `./data/`) to your new pod's storage root.
3. Translate container ACL locations and verify their targets and owner grants in staging.
4. Stand up solid-pod-rs pointing at the same directory.
5. Cut the DNS / load balancer over.
6. Keep JSS running read-only for 24 h as rollback.

## 1. Semantic differences you must know

| Concern | JSS default | solid-pod-rs |
|---|---|---|
| WAC default | multiuser signup scaffolds `/.acl`; `public: true` disables WAC entirely | **deny-by-default**; no ACL = no access, no runtime switch |
| Authentication | Solid-OIDC via built-in IdP (`oidc-provider`); optional WebID-TLS | Main resource routes consume NIP-98; enabling the OIDC library does not wire resource admission |
| Storage layout | `$JSS_ROOT/<pod-or-user>/...` | `<root>/<path>` mirroring the pod URI directly |
| Quota | `defaultQuota` config (50 MB default) | `QuotaTracker` (explicit, per-pod) |
| Provisioning endpoint | IdP signup flow (`multiuser: true`) | `provision_pod` plus `POST /.pods`; secure account-policy integration remains operator work |
| HTTP framework | Fastify | Actix server binary; framework-agnostic core |
| JSON Patch (RFC 6902) | not implemented | supported as a Rust extension |
| ActivityPub federation | built in | `solid-pod-rs-activitypub` sibling crate |
| Licence | AGPL-3.0-only | AGPL-3.0-only (inherited) |

The most important difference is the WAC default. **Do not start
solid-pod-rs in production without first installing a `/.acl`
document**, or every request will 401. See
[tutorial 3](../tutorials/03-adding-access-control.md).

## 2. Configuration mapping

### Environment variables

| JSS env var                              | solid-pod-rs equivalent             | Notes |
|------------------------------------------|-------------------------------------|-------|
| `JSS_PORT`                               | `server.port` / server CLI wiring   | Supported by the layered config loader |
| `JSS_HOST`                               | `server.host` / server CLI wiring   | — |
| `JSS_ROOT`                               | `storage.root` / `FsBackend::new(path)` | default `./data` in JSS |
| `JSS_SSL_KEY` / `JSS_SSL_CERT`           | terminate TLS in your HTTP framework or reverse proxy | — |
| `JSS_IDP` / `JSS_IDP_ISSUER`             | `auth.oidc.issuer` / `solid-pod-rs-idp` | The IdP crate exists, but the canonical server does not yet mount its complete authenticated flow |
| `JSS_MULTIUSER`                          | `multitenant` resolver + provisioning policy | No single compatibility switch |
| `JSS_PUBLIC`                             | install permissive `/.acl` manually | solid-pod-rs has no public-mode switch |
| `JSS_READ_ONLY`                          | enforce at the HTTP framework layer | — |
| `JSS_NOTIFICATIONS`                      | none in the bundled server | The WebSocket, webhook and legacy (`solid-0.1`) channels exist as library features, but `solid-pod-rs-server` mounts no notifications endpoint (parity row 279) |
| `JSS_NOSTR`                              | none in the bundled server | The relay is a library crate (`solid-pod-rs-nostr`) for embedders; no server feature or flag mounts it (parity rows 278, 280) |
| `JSS_ACTIVITYPUB`                        | server `activitypub` cargo feature | Rebuild required, and only the actor document is served; inbox and outbox are library-only (parity row 281) |
| `JSS_MASHLIB`                            | core `mashlib` feature and server route wiring | Compile-time rather than runtime selection |
| `JSS_BODY_LIMIT`                         | `server.body_cap` (`JSS_MAX_REQUEST_BODY` alias) | Rust default 50 MiB; JSS `0.0.220` default 20 MB |
| `JSS_MCP`                                | server MCP enable flag | Off by default |

### Config-file mapping

JSS is configured via `JSS_*` env vars + optional `config.json` (CLI
args take precedence). The core Rust crate remains framework-agnostic, while
`solid-pod-rs-server` supplies a layered JSON/TOML/environment config loader.
The rough equivalence:

| JSS setting                                | solid-pod-rs equivalent                                   |
|--------------------------------------------|-----------------------------------------------------------|
| `root` (data directory)                    | `storage::fs::FsBackend::new(path)`                       |
| in-memory testing backend                  | `storage::memory::MemoryBackend`                          |
| WAC evaluation                             | `wac::StorageAclResolver` + `wac::evaluate_access`        |
| Link / type header emission                | `ldp::link_headers`                                       |
| `Prefer` header handling                   | `ldp::PreferHeader::parse`                                |
| WebSocket + webhook notifications          | `notifications::WebSocketChannelManager` + `WebhookChannelManager` |
| OIDC dynamic client registration           | `oidc::register_client`                                   |
| DPoP proof validation                      | `oidc::verify_dpop_proof`                                 |

If a mapping is missing, it is either in the [parity
checklist](../../PARITY-CHECKLIST.md) or deliberately out of scope
(consumer-crate concern, or JSS-specific feature like ActivityPub).

## 3. Data migration

### Layout translation

JSS data layout (default filesystem store):

```
./data/                    (or $JSS_ROOT)
├── <pod-name>/            (or per-user dir in multiuser mode)
│   ├── profile/card
│   ├── profile/card.acl
│   └── ...
└── ...
```

solid-pod-rs layout:

```
/var/lib/mypod/
├── profile/
│   ├── card                  (body)
│   ├── card.meta.json        ({"content_type":"text/turtle","links":[]})
│   ├── card.acl              (body)
│   └── card.acl.meta.json
└── ...
```

### Migration script (rsync + meta-sidecar generation)

```bash
#!/usr/bin/env bash
set -euo pipefail
SRC=./data/mypod       # $JSS_ROOT/<pod>
DST=/var/lib/mypod

# 1. Copy bodies straight across.
rsync -av "$SRC/" "$DST.tmp/"

# 2. For every body file, synthesise a .meta.json sidecar so
#    solid-pod-rs can serve it with the correct Content-Type.
find "$DST.tmp" -type f ! -name '*.acl' ! -name '*.meta.json' | while read -r f; do
  case "$f" in
    *.ttl)    ct="text/turtle";;
    *.jsonld) ct="application/ld+json";;
    *.nt)     ct="application/n-triples";;
    *.json)   ct="application/json";;
    *.html)   ct="text/html";;
    *)        ct="application/octet-stream";;
  esac
  printf '{"content_type":"%s","links":[]}\n' "$ct" > "$f.meta.json"
done

mv "$DST.tmp" "$DST"
```

Verify counts:

```bash
find ./data/mypod -type f | wc -l
find /var/lib/mypod -type f ! -name '*.meta.json' | wc -l
# Numbers should match.
```

If your JSS deployment uses non-default file naming (for example transcoded
sidecars for content negotiation), inspect a staging copy and adjust the
stripper accordingly. JSS `0.0.220` stores bodies verbatim by default.

### ACL translation

JSS stores ACL as Turtle (`.acl` files); solid-pod-rs accepts both
a subset of Turtle and JSON-LD ACLs. Representation support is not full RDF
semantic equivalence: JSON-LD context expansion and ACL target IRI resolution
have known gaps. For the root ACL `/.acl`, use explicit server-root targets:

```turtle
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<#owner>
  a acl:Authorization ;
  acl:agent <https://me.example/profile/card#me> ;
  acl:accessTo </> ;
  acl:default </> ;
  acl:mode acl:Read, acl:Write, acl:Control .
```

This root policy uses the path convention the evaluator currently consumes.
For a nested container, use its actual server-root path, such as `/profile/`,
in both target predicates. A corresponding compact JSON-LD root policy is:

```json
{
  "@context": { "acl": "http://www.w3.org/ns/auth/acl#" },
  "@graph": [{
    "@id": "#owner",
    "@type": "acl:Authorization",
    "acl:agent":    { "@id": "https://me.example/profile/card#me" },
    "acl:accessTo": { "@id": "/" },
    "acl:default":  { "@id": "/" },
    "acl:mode":     [
      { "@id": "acl:Read" },
      { "@id": "acl:Write" },
      { "@id": "acl:Control" }
    ]
  }]
}
```

### Container ACL locations

The native resolver associates `/profile/` with `/profile.acl`, not
`/profile/.acl`. The root still uses `/.acl`; a document such as
`/profile/card` uses `/profile/card.acl`. Discovery now calls the shared
resolver helper, so a current server advertises that same association. Clients
must follow the `Link: ...; rel="acl"` target rather than construct a filename.
See [WAC ACL discovery](https://solidproject.org/TR/wac#acl-resource-discovery).

Earlier server responses advertised inner container ACLs that the resolver
ignored. A restrictive policy stored there could leave a broader inherited
grant in effect. Updating the server does not move those stored files or make
them authoritative. Some admin-provisioned pods contain both forms; automatic
precedence changes or overwriting one with the other can change permissions.

On a staging copy, enumerate both locations for every container and review the
intended owner, public grants, target paths and inheritance. Preserve both
originals in the rollback backup. Install the intended policy at the resolver's
canonical location; use the authenticated ACL URL when the owner retains
Control, or the operator's offline storage procedure if already locked out.
Do not blindly concatenate policies or replace relative IRIs as strings.
Verify an owner read and write, a refused unrelated identity, anonymous access
according to intent, and a nested child. Resolve every conflicting pair before
cutover. Retire an obsolete inner copy only after verifying its consumers.

The new candidate-write guard refuses unreadable policies and policies that do
not retain the caller's effective Control. It does not repair older files,
fully expand JSON-LD, or make absolute ACL targets work. Those limitations
remain migration acceptance work.

## 4. Standing up solid-pod-rs

Storage construction example (this alone starts no HTTP server):

```rust
use std::sync::Arc;
use solid_pod_rs::storage::{fs::FsBackend, Storage};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let storage: Arc<dyn Storage> =
        Arc::new(FsBackend::new("/var/lib/mypod").await?);
    // Wire your HTTP framework's handlers against `storage`, or deploy the
    // bundled solid-pod-rs-server binary for the maintained Actix surface.
    Ok(())
}
```

Do not forget:

- Install `/.acl` before flipping traffic (deny-by-default).
- Register a NIP-98 verifier if your JSS was OIDC-only — see
  [how-to/configure-nip98-auth.md](configure-nip98-auth.md). Keeping OIDC clients
  requires a separately implemented and tested resource-admission integration;
  the library feature alone is insufficient.
- Expose `.well-known/openid-configuration` if you are keeping OIDC
  clients.

## 5. Cutover

1. Drop write permissions on the JSS pod (make the data directory
   read-only, or throw 503 at the load balancer for mutating methods).
2. Run the migration script.
3. Start solid-pod-rs pointing at the new directory.
4. Smoke test:
   ```bash
   curl -sI https://pod.example/profile/card | grep -iE '^(link|wac-allow):'
   ```
5. Cut DNS / the load balancer to solid-pod-rs.

## 6. Rollback strategy

Keep JSS running **read-only** for 24 h on a different port. If
anything breaks:

1. Stop solid-pod-rs.
2. Point the load balancer back at JSS.
3. Writes made to solid-pod-rs during the cutover window need to be
   re-applied to JSS (rsync in reverse, with the sidecar-strip logic
   inverted).

Retain the original ACL paths and representations in the rollback backup.
The translation is not automatically symmetric, and post-cutover permission
changes need an explicit reverse mapping before replaying them to JSS.

## 7. What you lose

- **Built-in IdP** — an optional Rust IdP crate exists, but its pre-built Axum
  binder has the critical identity-header finding AUD-001 and is not a safe
  drop-in replacement yet.
- **ActivityPub federation** — available as a transport-agnostic optional
  crate, with signature/actor-binding findings AUD-016 and AUD-017.
- **Nostr relay (`JSS_NOSTR`)** — available as an embeddable optional crate;
  the bundled server does not mount it and embedders must apply AUD-018 limits.
- **Mashlib / SolidOS UI** — Mashlib rendering and a legacy notification
  adapter exist, but this is not a full JSS UI distribution.
- **WebID-TLS** — legacy; deliberately not ported.

## 8. What you gain

- Single static binary, no Node runtime.
- `cargo test` against the storage trait passes on memory + FS
  today, so regression tests in CI are cheap.
- Strong typing at every API boundary — `AccessMode`, `RdfFormat`,
  `PatchDialect`, `StorageEvent`.
- A stable trait seam for custom S3, R2, IPFS, or database backends. No stock
  object-store implementation ships yet.
- AGPL-3.0-only licensing inherited from JSS — same covenant, different
  runtime, no change in your obligations as a network-service operator.

## See also

- [explanation/comparison-vs-jss.md](../explanation/comparison-vs-jss.md)
- [PARITY-CHECKLIST.md](../../PARITY-CHECKLIST.md)
- [reference/env-vars.md](../reference/env-vars.md)
