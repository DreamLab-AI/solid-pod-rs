# solid-pod-rs — diagrams

Architecture and flow diagrams for the `solid-pod-rs` crate. Each diagram has
a Mermaid source under `src/` and (where tooling permits) a rendered PNG under
`rendered/`.

## Rendering

The PNGs in `rendered/` are produced from the `.mmd` sources with
[`@mermaid-js/mermaid-cli`](https://github.com/mermaid-js/mermaid-cli):

```bash
npm install -g @mermaid-js/mermaid-cli   # one-off
for f in src/*.mmd; do
  out="rendered/$(basename "${f%.mmd}").png"
  mmdc -i "$f" -o "$out" -b transparent -s 2 -w 2000
done
```

Flags:

- `-b transparent` — transparent background (dark-mode friendly).
- `-s 2` — 2× scale for retina-quality output.
- `-w 2000` — max width 2000 px.

A puppeteer config with `--no-sandbox` (`puppeteer.config.json`) is included
for container / CI environments.

## Palette

All diagrams share a single colour vocabulary so the viewer can read them
at a glance:

| Colour | Hex | Role |
|--------|-----|------|
| Violet | `#8B5CF6` | Governance / auth (NIP-98, OIDC, WebID, payloads) |
| Cyan | `#00D4FF` | Orchestration / services (LDP, WebID helpers) |
| Emerald | `#10B981` | Storage / persistence, success edges |
| Amber | `#F59E0B` | Decision / gate points (WAC, DPoP checks) |
| Red | `#EF4444` | Error / denied paths |
| Off-white | `#E8F4FC` | Text, strokes |

## Index

| # | Source | Rendered | Explains |
|---|--------|----------|----------|
| 1 | [`src/01-architecture-overview.mmd`](src/01-architecture-overview.mmd) | [`rendered/01-architecture-overview.png`](rendered/01-architecture-overview.png) | 3-layer crate architecture: HTTP handlers → services (LDP, WAC, Notifications, OIDC) → `Storage` trait + backends. Shows the ACL evaluation touchpoint in the request path. |
| 2 | [`src/02-request-lifecycle.mmd`](src/02-request-lifecycle.mmd) | [`rendered/02-request-lifecycle.png`](rendered/02-request-lifecycle.png) | Sequence for a typical `PUT`: NIP-98 verify → WAC check (`wac::evaluate_access_ctx_with_registry`) → storage → response. Includes 401/403/5xx error branches. |
| 3 | [`src/03-wac-inheritance.mmd`](src/03-wac-inheritance.mmd) | [`rendered/03-wac-inheritance.png`](rendered/03-wac-inheritance.png) | WAC ACL resolution: nearest `.acl` wins — the resolver walks up only while no `.acl` exists; a direct ACL honours `acl:accessTo` + `acl:default`, an inherited ACL honours only `acl:default`. |
| 4 | [`src/04-ldp-containment.mmd`](src/04-ldp-containment.mmd) | [`rendered/04-ldp-containment.png`](rendered/04-ldp-containment.png) | LDP `BasicContainer` with `ldp:contains` member IRIs, server-managed triples (`dc:modified`, `stat:size`), and the `Link: rel=type` headers emitted on GET. |
| 5 | [`src/05-notifications-flow.mmd`](src/05-notifications-flow.mmd) | [`rendered/05-notifications-flow.png`](rendered/05-notifications-flow.png) | Solid Notifications pipeline: `StorageEvent` → tokio broadcast channel → per-subscription WebSocket receiver + webhook dispatcher with full-jitter exponential backoff and circuit breaker. AS 2.0 envelope shape. |
| 6 | [`src/06-oidc-dpop.mmd`](src/06-oidc-dpop.mmd) | [`rendered/06-oidc-dpop.png`](rendered/06-oidc-dpop.png) | Solid-OIDC authorisation flow: RFC 7591 dynamic registration, discovery, DPoP proof creation, access-token issuance with `cnf.jkt`, per-request DPoP verification, WebID extraction. |
| 7 | [`src/07-nip98-vs-oidc.mmd`](src/07-nip98-vs-oidc.mmd) | [`rendered/07-nip98-vs-oidc.png`](rendered/07-nip98-vs-oidc.png) | Two swim lanes reaching the same AuthZ decision: NIP-98 (Nostr signed event, body-hash binding, freshness) vs OIDC+DPoP (bearer + proof, `cnf.jkt`, `ath`). |
| 8 | [`src/08-storage-trait.mmd`](src/08-storage-trait.mmd) | [`rendered/08-storage-trait.png`](rendered/08-storage-trait.png) | `trait Storage` class diagram with methods (`get`/`put`/`delete`/`list`/`head`/`exists`/`create_container`/`watch`) and its implementations: `FsBackend` and `MemoryBackend` (the `s3-backend` feature flag is declared but no S3 backend ships yet). |
| 9 | [`src/09-provenance-tiers.mmd`](src/09-provenance-tiers.mmd) | _(pending render)_ | Provenance tiers (ADR-059): the cheap always-on **git-mark** (write-as-commit → `GitMark` + PROV-O `.prov.ttl` sidecar) and the opt-in expensive **block-trail** Bitcoin anchor (taproot UTXO, byte-parity tx-builder), composed by `ProvenanceLog::record` under an `AnchorPolicy` (incl. epoch Merkle-root batching), plus the `_prov` API and independent (pod-trustless) anchor verification. |

## Re-rendering a single diagram

```bash
mmdc -i src/03-wac-inheritance.mmd -o rendered/03-wac-inheritance.png -b transparent -s 2 -w 2000
```

If `mmdc` is unavailable in your environment, the `.mmd` sources are the
source of truth — any Mermaid renderer (GitHub, VS Code Mermaid preview,
`mermaid.live`) will draw them directly.
