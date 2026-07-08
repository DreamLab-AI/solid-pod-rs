# P1 evidence — RES-c diagram render (WP-4 / ADR-060 Decision 5)

**Item:** Regenerate the 9 stale/missing architecture diagrams from their
`.mmd` sources using the VisionFlow canon renderer (RES-b engine), run the
canon `check-diagram-text.js` over the outputs, and add a local staleness check
wired into CI.
**Base commit verified against:** `48c826a` (`gap-close/2026-07`)
**Maturity:** `scaffolded` → repo-local regeneration `integrated`; the
"verified render" claim remains gated on VisionFlow's RES-b visual-regression
gate (declared dependency, not self-certified).

## What changed

| File | Change |
|---|---|
| `crates/solid-pod-rs/docs/diagrams/rendered/*.svg` (9, new) | Light-theme, baked-text-fill SVGs — the RES-b gate format — for all 9 diagrams incl. the previously-missing `09-provenance-tiers`. |
| `crates/solid-pod-rs/docs/diagrams/rendered/*.png` (9, regenerated) | 2× raster of each SVG via CDP screenshot; the 8 stale PNGs refreshed, `09` added. |
| `crates/solid-pod-rs/docs/diagrams/src/{01,03,04,05,07,09}.mmd` | Line-break escapes `\n` → Mermaid `<br/>` (the canon convention the two sequence diagrams already used; renders identical breaks); `05`/`07` two long labels wrapped so `activitystreams` and `DELETE` stay whole (07 previously clipped `DELETE`→`DEL`). |
| `crates/solid-pod-rs/docs/diagrams/README.md` | Rendering section rewritten to the canon renderer + SVG/PNG outputs; `09` index row de-"pending"; staleness guard + RES-b dependency documented. |
| `scripts/check-diagram-staleness.sh` (new) | Git-commit-time (+ working-tree fallback) staleness guard; fails when a `.mmd` is newer than its render or a render is missing. |
| `.github/workflows/ci.yml` | New required `diagrams` job running the staleness guard; added to the `ci-required` aggregator. |

The renderer used is the canon engine at
`/home/devuser/workspace/VisionFlow/scripts/diagram-render/` — its vendored
Mermaid bundle, `lib/cdp.mjs`, `lib/preprocess.mjs` and LIGHT-theme in-page
renderer — driven against the `browsercontainer:9223` Chrome sidecar. The
render invocation is a thin runner that imports that lib and points it at this
repo's `src/*.mmd` (the canon `render.mjs` reads its own repo's diagram dir).

## Receipts

### R2 — render run (all 9, 100% visible text nodes)

```
$ date -u '+%Y-%m-%dT%H:%M:%SZ'   # 2026-07-08T12:44:35Z
$ node <runner importing canon lib> against docs/diagrams/src/*.mmd
browser: connected ws://172.20.0.3:9223/devtools/browser/…
  rendered 01-architecture-overview.mmd -> …svg + …png  (text nodes: 176, visible: 176, 1230x1313)
  rendered 02-request-lifecycle.mmd    -> …  (text nodes: 91,  visible: 91,  1732x1311)
  rendered 03-wac-inheritance.mmd      -> …  (text nodes: 274, visible: 274, 1435x1641)
  rendered 04-ldp-containment.mmd      -> …  (text nodes: 148, visible: 148, 1173x912)
  rendered 05-notifications-flow.mmd   -> …  (text nodes: 187, visible: 187, 2017x902)
  rendered 06-oidc-dpop.mmd            -> …  (text nodes: 90,  visible: 90,  1851x1846)
  rendered 07-nip98-vs-oidc.mmd        -> …  (text nodes: 248, visible: 248, 1218x1636)
  rendered 08-storage-trait.mmd        -> …  (text nodes: 202, visible: 202, 1227x758)
  rendered 09-provenance-tiers.mmd     -> …  (text nodes: 205, visible: 205, 965x1886)
Rendered 9 diagram(s) to …/rendered
```

Every diagram: `visible == total` — zero invisible text nodes, i.e. the RES-b
failure mode (dark-theme near-white text on white page) is absent by
construction (light theme + baked fill + white bg rect).

### R2b — canon `check-diagram-text.js` over the outputs (9/9 pass)

Run with a byte-identical copy of the canon checker
(`md5 e04f992859f397f42f1ddb5df34593d1` == the canon
`VisionFlow/scripts/check-diagram-text.js`) in a staged canon layout so its
hard-coded `SRC_DIR` resolves this repo's `.mmd` sources for the label-word
assertion:

```
$ date -u '+%Y-%m-%dT%H:%M:%SZ'   # 2026-07-08T12:44:44Z
$ node <staged canon>/check-diagram-text.js
  ok    01-architecture-overview.svg: 106 visible text nodes, 51/51 label words
  ok    02-request-lifecycle.svg: 64 visible text nodes, 3/3 label words
  ok    03-wac-inheritance.svg: 171 visible text nodes, 56/56 label words
  ok    04-ldp-containment.svg: 84 visible text nodes, 35/35 label words
  ok    05-notifications-flow.svg: 113 visible text nodes, 66/66 label words
  ok    06-oidc-dpop.svg: 66 visible text nodes, 4/4 label words
  ok    07-nip98-vs-oidc.svg: 164 visible text nodes, 72/72 label words
  ok    08-storage-trait.svg: 116 visible text nodes, 27/27 label words
  ok    09-provenance-tiers.svg: 126 visible text nodes, 73/73 label words

All 9 diagram(s) passed: visible text + key labels present.
（exit 0）
```

(A direct `check-diagram-text.js <rendered-dir>` invocation validates the same
visible-text gate but reports "no matching .mmd source" for every file, because
the canon checker's `SRC_DIR` is hard-coded to its own repo — hence the staged
byte-identical run above for the label-word half.)

### R2c — staleness guard: passes clean, fails on an edited-but-unrendered source

```
$ bash scripts/check-diagram-staleness.sh    # working tree, after render
  ok     01-architecture-overview.svg: up to date
  … (all 18 outputs ok) …
All 9 diagram source(s) current against their rendered .svg + .png.
（exit 0）

# negative control — append to a source without re-rendering:
$ bash scripts/check-diagram-staleness.sh
  STALE  04-ldp-containment.svg: src/04-ldp-containment.mmd (1783514789) is newer than rendered/04-ldp-containment.svg (1783514679)
  STALE  04-ldp-containment.png: …
（exit 1）
```

### R2d — `ls` of regenerated diagrams

```
$ ls docs/diagrams/rendered/
01-architecture-overview.png   01-architecture-overview.svg
02-request-lifecycle.png       02-request-lifecycle.svg
03-wac-inheritance.png         03-wac-inheritance.svg
04-ldp-containment.png         04-ldp-containment.svg
05-notifications-flow.png      05-notifications-flow.svg
06-oidc-dpop.png               06-oidc-dpop.svg
07-nip98-vs-oidc.png           07-nip98-vs-oidc.svg
08-storage-trait.png           08-storage-trait.svg
09-provenance-tiers.png        09-provenance-tiers.svg     ← previously missing
```

## Falsification (WP-4) — how this survives it

- *"a PNG ships older than its `.mmd` source without the staleness check
  failing"* → R2c negative control fails (exit 1) on exactly that.
- *"diagram 9 remains unrendered"* → `09-provenance-tiers.{svg,png}` present
  (R2d) and pass the gate (R2b).
- *"a regenerated PNG carries invisible text (the RES-b failure mode)"* → R2
  shows `visible == total` for all 9; R2b's canon checker passes the
  text-visibility gate.
- *"RES-c is scored closed while RES-b's verified-render gate does not yet
  exist"* → not scored closed; the README and ADR-060 Decision 5 declare the
  RES-b dependency, and this evidence claims only repo-local regeneration
  `integrated`, with "verified render" deferred to RES-b.
