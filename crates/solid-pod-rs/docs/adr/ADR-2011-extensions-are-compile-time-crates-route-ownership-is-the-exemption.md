---
id: ADR-2011
title: Extensions are workspace crates composed at compile time; route ownership is the WAC exemption
date: 2026-11-01
decision_status: proposed
implementation_status: partial
activation_status: live
supersedes: []
superseded_by: []
verified_commit: e1d16ad
verified_paths: [crates/solid-pod-rs-server/src/lib.rs, crates/solid-pod-rs-server/src/main.rs, crates/solid-pod-rs-forge/src/request.rs, crates/solid-pod-rs-forge/src/lib.rs, crates/solid-pod-rs-forge/src/mirror.rs]
owner: jjohare
review_trigger: a second crate mounted under its own prefix; a consumer that must run third-party code it cannot recompile; JSS changing `src/plugins.js` or shipping the #603 (resource events) or #604 (authorize) plugin APIs; `build_app` gaining an embedder `configure` hook
repo: solid-pod-rs
domain: BASELINE-solid-pod-rs.md
evidence_class: source+runtime
acceptance_boundary: Establishes that the forge is the only mounted extension, owns every method under `/forge` (runtime: PUT under `/forge` returns 404, nothing written), and that the dotfile guard and shutdown hook do not yet meet this decision (runtime 403 on a dot segment under `/forge`; `MirrorHandle::stop` uncalled). Does not establish anything about a second extension, which does not exist.
lineage: "Gives checklist rows 221 and 223-229 (runtime-plugin cluster, not applicable) and GAP-ANALYSIS's runtime-plugin stance an authority; until now no ADR recorded it. Generalises the bounded-comparator method of ADR-2009. Source audit: docs/reference/jss-parity-audit-2026-11-01.md, lane 4."
---

# ADR-2011 — Extensions are workspace crates composed at compile time; route ownership is the WAC exemption

## Context
JSS loads plugins at runtime: `createServer({ plugins })` and `--plugin` import a module
and call `activate(api)` (`src/plugins.js`, #206). Plugins may import only `auth.js`, so each
internal they need becomes an API negotiated upstream (#603 events and #604 authorize are still
open). Upstream measures no isolation between plugins (`plugins/NOTES.md:213-225`). solid-pod-rs
is a statically linked actix server; its one extension, the forge, is a workspace crate behind
Cargo features (ADR-2009, ADR-2010). The checklist has classed the runtime-plugin rows as not
applicable since 0.0.204 without an ADR behind it.

## Decision
1. An extension is a workspace crate, mounted by a Cargo feature. There is no runtime loader
   (`dlopen`, `abi_stable`) and no WASM or out-of-process plugin host.
2. A mounted extension owns **every HTTP method** under its prefix, registered ahead of the pod
   catch-all, so no request under the prefix reaches the LDP handlers. Owning the route is the
   exemption: the pod's WAC, git lane and dotfile guard defer to a mounted prefix by
   construction, and the extension authorises its own requests.
3. No `PodExtension` trait is extracted until a second crate is mounted. The template is the
   forge's shape: a framework-neutral `ForgeRequest` → `ForgeService::handle(req, agent)` →
   `ForgeResponse`, its own credential resolver, a dot-directory data dir, and an all-methods
   route block. The trait is extracted from two concrete cases, never from the JSS api object.
4. Parity with the JSS plugin system means capability parity for what plugins achieve (identity
   resolution, prefix ownership, reserved paths, origin, private storage, events, authorisation),
   the core-side exemptions JSS grants app prefixes, and a bounded per-plugin comparator, as
   ADR-2009 set for the forge, when a specific plugin is ported. The `activate(api)` contract
   itself is never a parity target.
5. A mounted extension that holds tasks or connections is stopped on server shutdown.

## Consequences
- Composition errors are compile errors; there is no plugin ABI to version.
- Third-party code cannot be added without recompiling. That is accepted until a consumer needs it.
- Rule 2 means no verb under a mounted prefix can reach the LDP handlers, so a WAC exemption
  never extends past what the extension itself authorises. Upstream's own comment
  (`src/plugins.js:324-330`) names the hazard a partial route block would create.
- Follow-on work this decision requires, open at `e1d16ad`:
  - the dotfile guard runs before routing and does not defer to `/forge` (checklist row 291);
  - the forge and mirror live in a process-static `OnceLock` and `MirrorHandle::stop()` is never
    called, so rule 5 is unmet (row 292);
  - a forge construction failure at boot is logged and the server keeps running, returning 500
    on every `/forge` request; it should be fatal when `forge` is compiled in (row 293).

## Verification
Source: the forge is the only mounted extension (`crates/solid-pod-rs-server/src/lib.rs:4999-5000`,
`:5306-5307`); the request shape is `crates/solid-pod-rs-forge/src/request.rs:23,85` and
`crates/solid-pod-rs-forge/src/lib.rs:336`. Runtime, at `e1d16ad`, server built with
`--features forge` against a seeded bare repository: `PUT /forge/...` returned 404 and wrote nothing
(rule 2 holds); `GET /forge/<o>/<r>/raw/HEAD/.gitignore` returned 403 from `DotfileGuard`
(`lib.rs:3844-3846`, `:5198`), so the exemption in rule 2 is incomplete. Hence
`implementation_status: partial`.
