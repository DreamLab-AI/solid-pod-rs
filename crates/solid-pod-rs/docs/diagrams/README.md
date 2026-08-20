# solid-pod-rs — diagrams

Architecture and flow diagrams for the `solid-pod-rs` crate. Each diagram has
a Mermaid source under `src/` and two rendered outputs under `rendered/`: a
print-safe `.svg` (the RES-b gate format) and a `.png` for viewers that want a
raster.

## Rendering (RES-c)

The `rendered/` outputs are produced from the `.mmd` sources with the
**VisionFlow canon diagram renderer** — the RES-b render gate — not with
`mmdc`. The canon renderer drives a real headless Chrome (the
`browsercontainer:9223` GPU sidecar in this environment, or any CDP endpoint
via `DIAGRAM_CDP_URL`) with a locally vendored Mermaid bundle (no CDN), applies
Mermaid's **light `default` theme**, and bakes the browser-computed text fill
plus a white background into every SVG. That is deliberate: the sources are
authored for a dark theme, and a dark-theme export onto a white PDF page is
exactly how earlier renders shipped invisible text — the defect RES-b exists to
stop. Light-theme rendering with baked fills makes every label print-safe.

The renderer lives at `VisionFlow/scripts/diagram-render/` and its
text-visibility checker at `VisionFlow/scripts/check-diagram-text.js`. To
regenerate all nine diagrams, run the renderer against this repo's `src/*.mmd`
(the canon `render.mjs` reads its own repo's diagram dir, so a thin runner that
imports the canon `lib/cdp.mjs` + `lib/preprocess.mjs` + vendored Mermaid and
points `SRC_DIR`/`OUT_DIR` at this repo does the regeneration). Each source
renders to `rendered/<name>.svg` (baked fills) and, via a CDP screenshot at 2×,
`rendered/<name>.png`. The checker then asserts every SVG has visible text and
carries its source's key label words:

```bash
node VisionFlow/scripts/check-diagram-text.js <path-to>/rendered
```

Line breaks in node labels use Mermaid's `<br/>` (kept by the canon
preprocess), not `\n` escapes — the canon label-word checker treats a `\n` as a
letter glued to the next word, so `<br/>` is required for a clean gate pass.

### Staleness guard

`scripts/check-diagram-staleness.sh` (wired into CI as the `diagrams` job)
fails when any `src/*.mmd` is newer than its rendered `.svg`/`.png`, or when a
render is missing. Freshness is measured by git commit time, with a working-
tree fallback so an edited-but-not-re-rendered source is caught pre-commit.
Commit a source and its re-render together and the guard passes.

A puppeteer config with `--no-sandbox` (`puppeteer.config.json`) is retained
for the legacy `mmdc` path; the canon renderer does not use it.

> **RES-b dependency.** RES-c does not self-certify its render. The
> "verified render" claim (visual-regression on top of the text-visibility
> check) belongs to VisionFlow's RES-b gate. This repo regenerates the outputs
> and guards their freshness; it does not score RES-c closed until the RES-b
> gate is live.

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
| 8 | [`src/08-storage-trait.mmd`](src/08-storage-trait.mmd) | [`rendered/08-storage-trait.png`](rendered/08-storage-trait.png) | `trait Storage` class diagram with methods (`get`/`put`/`delete`/`list`/`head`/`exists`/`create_container`/`watch`) and its shipped implementations: `FsBackend` and `MemoryBackend`. |
| 9 | [`src/09-provenance-tiers.mmd`](src/09-provenance-tiers.mmd) | [`rendered/09-provenance-tiers.png`](rendered/09-provenance-tiers.png) | Provenance tiers (ADR-059): the cheap always-on **git-mark** (write-as-commit → `GitMark` + PROV-O `.prov.ttl` sidecar) and the opt-in expensive **block-trail** Bitcoin anchor (taproot UTXO, byte-parity tx-builder), composed by `ProvenanceLog::record` under an `AnchorPolicy` (incl. epoch Merkle-root batching), plus the `_prov` API and independent (pod-trustless) anchor verification. |

## Re-rendering

Re-render the whole set through the canon renderer (above); a single diagram
is regenerated the same way by rendering all sources — the render is fast and
keeps every output on one Chrome/Mermaid version, which the staleness guard and
the canon `--diff` word-drift check both rely on.

If the canon renderer is unavailable in your environment, the `.mmd` sources
are the source of truth — any Mermaid renderer (GitHub, VS Code Mermaid
preview, `mermaid.live`) will draw them directly. Do not hand-edit the rendered
outputs; regenerate them so the staleness guard stays honest.
