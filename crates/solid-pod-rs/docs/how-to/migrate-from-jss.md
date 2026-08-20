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
3. Rewrite `.acl` paths if the layout differs (it usually doesn't).
4. Stand up solid-pod-rs pointing at the same directory.
5. Cut the DNS / load balancer over.
6. Keep JSS running read-only for 24 h as rollback.

## 1. Semantic differences you must know

| Concern | JSS default | solid-pod-rs |
|---|---|---|
| WAC default | multiuser signup scaffolds `/.acl`; `public: true` disables WAC entirely | **deny-by-default**; no ACL = no access, no runtime switch |
| Authentication | Solid-OIDC via built-in IdP (`oidc-provider`); optional WebID-TLS | NIP-98 is first-class; Solid-OIDC behind the `oidc` feature |
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
| `JSS_NOTIFICATIONS`                      | notification feature selection and server wiring | WebSocket, webhook, and legacy adapters are separate Rust features |
| `JSS_NOSTR` / `JSS_ACTIVITYPUB`          | sibling crates / compile-time features | Rebuild required; there is no runtime plugin loader |
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
Turtle and JSON-LD ACLs. Both are semantically equivalent. Minimum
worked example — JSS Turtle ACL:

```turtle
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<#owner>
  a acl:Authorization ;
  acl:agent <https://me.example/profile/card#me> ;
  acl:accessTo <./> ;
  acl:default <./> ;
  acl:mode acl:Read, acl:Write, acl:Control .
```

...is accepted as-is by solid-pod-rs (Turtle ACLs are parsed via
`wac::parse_turtle_acl`). If you prefer JSON-LD:

```json
{
  "@context": { "acl": "http://www.w3.org/ns/auth/acl#" },
  "@graph": [{
    "@id": "#owner",
    "@type": "acl:Authorization",
    "acl:agent":    { "@id": "https://me.example/profile/card#me" },
    "acl:accessTo": { "@id": "./" },
    "acl:default":  { "@id": "./" },
    "acl:mode":     [
      { "@id": "acl:Read" },
      { "@id": "acl:Write" },
      { "@id": "acl:Control" }
    ]
  }]
}
```

Store at the same filename the JSS server used (e.g. `/profile/.acl`).

## 4. Standing up solid-pod-rs

Minimal production wire-up:

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
  [how-to/configure-nip98-auth.md](configure-nip98-auth.md). Or turn
  on the `oidc` feature to continue accepting Solid-OIDC tokens.
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

Because both servers address the same filesystem layout format once
translated, forward and backward migration are symmetric.

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
