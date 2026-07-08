# PRD: Gap-Close Sprint — solid-pod-rs slice

**Owner:** solid-pod-rs maintainers (DreamLab AI)
**Status:** Proposed
**Date:** 2026-07-08
**Governed by:** [Meta-PRD Gap-Close Sprint](../../../../VisionFlow/docs/PRD-gap-close-sprint.md), [ADR-004 Gap-Close Sprint Governance](../../../../VisionFlow/docs/ADR-004-gap-close-sprint-governance.md), [ADR-002 Ecosystem Alignment Governance]
**Bounded context:** [DDD Gap-Close solid-pod Context](DDD-gap-close-solid-pod-context.md), conformist to [DDD Gap-Close Context](../../../../VisionFlow/docs/DDD-gap-close-context.md)
**Local decision record:** [ADR-060 Gap-Close solid-pod slice](adr/ADR-060-gap-close-solid-pod-slice.md)

**Naming note.** This repository carries no numbered PRD/DDD series; its ADRs are numbered (`adr/ADR-0NN-slug.md`, next free number 060). For this sprint the repository adopts the canon's unnumbered child-document convention: one `PRD-gap-close-solid-pod.md` and one `DDD-gap-close-solid-pod-context.md` alongside the numbered ADR. The pre-existing `sprint-12-prd.md` is a one-off and not part of any series.

## TL;DR

solid-pod-rs owns four items in the register: the REC-1 non-destructive PATCH fix, the NIP-98 verifier consolidation, the REC-11 provenance-trail share, and the RES-c stale diagrams. Recon against the `gap-close/2026-07` HEAD (branched from `closeout/2026-07-03`, workspace at `0.5.0-alpha.4`) finds three of the four already carry more code than the register credits, and the honest work is closure-with-receipt plus one contract definition, not fresh implementation.

The PATCH bug the register lists open is already fixed: commit `791977a` (2026-05-29) seeds the working graph from the stored resource before applying the patch, and three regression tests pass. The NIP-98 verifier is already single-sourced in `core`; every other crate delegates to it, so the consolidation the register asks for is achieved in-repo, and what remains is a documented edge-local exception for the out-of-repo forum/CF tier. The provenance composition (git-mark plus block-trail) is wired into the LDP write path, but the query surface is point-lookup only, so solid-pod-rs's REC-11 contribution is to define the pod-wide trace contract that VisionClaw and agentbox consume, not to build the unified trace itself. The diagrams are 8/9 stale-rendered and 1/9 never rendered, and their refresh depends on VisionFlow's RES-b render gate.

solid-pod-rs sits below the four-surface line. Its closures are preconditions and substrate: REC-1 is part of the P0 security floor, RES-c is a P1 documentation-freshness item, and REC-11 is a P2 data-moat contribution. None of its items scores directly on the forum/desktop/MR/voice lens; they clear the floor the scored surfaces stand on.

## Owned Items and Maturity

Current tier is the ADR-002 seven-tier vocabulary read against the code at HEAD, not the register's implicit "open". Where the register understates the state, this table states the honest current tier and the PRD claims closure-with-receipt.

| Item | Register wave | Current tier (evidence) | Target tier | Loop-closing |
|---|---|---|---|---|
| REC-1 PATCH non-destructive merge | P0 | `integrated` — fix `791977a`, 3 tests green at alpha.4 | `integrated` confirmed; `released` at manifest pin | Yes (regression canary) |
| NIP-98 single verifier (in-repo) | P0 | `integrated` — `core` verifier, all tiers delegate | `integrated` (hold) | Yes (auth-wire canary) |
| NIP-98 cross-tier replay-store seam | P0 | `scaffolded` — concrete `Nip98ReplayCache`, no trait | `standalone` (trait) + documented edge-local exception | No |
| REC-11 per-commit provenance | P2 | `integrated` under `--features git`; `scaffolded` in the default build (feature off) | `integrated` (hold, caveat labelled) | Yes (provenance-wire canary) |
| REC-11 pod-wide trace index | P2 | `planned` — no pod-wide enumeration endpoint | `planned`, contract defined (build VisionClaw-led) | Yes (registered, fires when built) |
| RES-c diagram render | P1 | `scaffolded` — pipeline documented, outputs stale | `integrated` under the RES-b render gate | No (dependency, not a wire) |

## Work Packages

### WP-1: PATCH Correctness (REC-1)

The register lists REC-1's PATCH sub-item as an open P0 security gap. The code disagrees. `handle_patch` (`crates/solid-pod-rs-server/src/lib.rs:1210`) now seeds the working graph from the existing stored resource via `seed_graph_from_patch_target` (`lib.rs:1467`) before dispatching to `ldp::apply_n3_patch` / `ldp::apply_sparql_patch` (`crates/solid-pod-rs/src/ldp.rs:1124,1251`). The former path seeded an empty `Graph::new()`, which silently discarded every pre-existing triple a patch did not restate. An unparseable existing body now fails closed with 409 rather than being overwritten. The fix landed in commit `791977a` (2026-05-29, "fix(server): PATCH no longer destroys pre-existing triples") and is recorded in `docs/reference/patch-semantics.md` and the `0.5.0-alpha` CHANGELOG entries.

Three regression tests cover the fix in `crates/solid-pod-rs-server/tests/patch_non_destructive_integration.rs`: `sparql_patch_preserves_existing_triples` (line 63), `n3_patch_preserves_existing_triples` (line 103), `patch_refuses_unparseable_body_rather_than_destroying_it` (line 142). Running `cargo test -p solid-pod-rs-server --test patch_non_destructive_integration --features git` passes all three in 0.05s after compile.

This work package is therefore a **closure-with-receipt against a stale register entry**, not an implementation. The one residual is documentation drift: the test file's doc-comment (`patch_non_destructive_integration.rs:1`) cites `PRD-014 Seam C, DDD-012 A2`, which are external ecosystem IDs with no file in this repo. The child ADR corrects the meta-register entry to point at commit `791977a` and the test file.

**Current maturity:** `integrated` — the fix is on-branch, tested, and documented. **Target:** `integrated` confirmed by the anti-fox verifier; `released` only when the wave's release manifest pins the SHA per ADR-002.

**Acceptance criteria:**
1. A PATCH that adds a triple to a resource holding sibling triples preserves the siblings, proven by `sparql_patch_preserves_existing_triples` and `n3_patch_preserves_existing_triples` passing against the pinned SHA.
2. A PATCH whose stored target body is not valid N-Triples returns 409 rather than overwriting, proven by `patch_refuses_unparseable_body_rather_than_destroying_it`.
3. The meta-register REC-1 PATCH entry cites commit `791977a` and the test file; the compatibility matrix records the item at `integrated`.
4. The anti-fox verifier re-runs the three tests on a different model family against the pinned SHA and the canary fires.

**Falsification statement.** *WP-1 is falsified if a PATCH that preserves sibling triples today regresses to destroying them without `patch_non_destructive_integration.rs` failing first; if the closure is claimed on the register correction alone without the three tests passing against the pinned SHA in the anti-fox re-run; or if the 409-on-unparseable-body path is removed and the refusal test still passes.*

### WP-2: Shared Verifier (NIP-98 consolidation)

The register asks solid-pod-rs to move the replay-store abstraction into `core` so one NIP-98 verifier serves every tier. Within this repository the verifier is already single-sourced: `crates/solid-pod-rs/src/auth/nip98.rs` holds `verify` / `verify_at` / `verify_at_with_policy` / `verify_schnorr_signature` / `mint`, and every consumer delegates rather than reimplementing:

- `crates/solid-pod-rs-git/src/auth.rs:144` — the git-over-HTTP Basic-nostr bridge calls `verify_at_with_policy` with `MatchPolicy::GitLenient`.
- `crates/solid-pod-rs-idp/src/schnorr.rs` — `Nip07SchnorrSso` wraps `verify_schnorr_signature`.
- `crates/solid-pod-rs-server/src/cli/install.rs:139` — token minting calls `nip98::mint`.

The replay cache `Nip98ReplayCache` (`crates/solid-pod-rs/src/auth/replay.rs:73`, feature `nip98-replay`) is also already in `core` and shared server-side through a process-local `LazyLock`. Live testing (RuVector `nostr-surface-live-test-results-2026-07-03`) confirms enforcement is genuine: anonymous 401, tampered-signature 401, wrong-URL 401, and a re-presented token inside the ±120s window treated as unauthenticated.

The gap the register's wording targets is cross-tier, not in-repo. `Nip98ReplayCache` is a concrete in-memory LRU, not a trait; `replay.rs:20` records that the forum/CF edge tier "has no shared datastore the way the forum/CF tier does". That tier lives in a sibling repository, so its verifier state cannot be inspected or consolidated from here. Two honest moves are available: extract a `trait ReplayStore` in `core` so an out-of-repo KV/Redis-backed tier can depend on this crate's nonce semantics instead of re-deriving them (raising the seam to `standalone`), and record the edge-local exception in the compatibility matrix (the forum/CF tier's verifier stays out of scope, consuming this crate's trait if and when it is wired).

**Current maturity:** in-repo single verifier `integrated`; the cross-tier seam `scaffolded` (concrete struct, no trait). **Target:** hold the in-repo verifier at `integrated`; raise the seam to `standalone` by extracting `trait ReplayStore`; the cross-tier consolidation stays a documented edge-local exception and reaches `integrated` only when a second tier consumes the trait.

**Acceptance criteria:**
1. No crate in the workspace carries a second NIP-98 verification path; every consumer delegates to `auth::nip98`, evidenced by a grep receipt showing zero reimplementations.
2. A live request with a re-presented NIP-98 token (same NIP-01 event id) inside the timestamp tolerance returns 401 (`Nip98ReplayCache` hit); anonymous and tampered-signature requests return 401.
3. Either a `trait ReplayStore` exists in `core` with `Nip98ReplayCache` as one implementor, or the compatibility matrix records the edge-local exception with the reason (out-of-repo tier, per-replica process-local cache).
4. The multi-replica caveat (per-replica replay window, `replay.rs`) is stated in the compatibility matrix so no cross-ecosystem claim assumes one shared verification boundary.

**Falsification statement.** *WP-2 is falsified if the shipped server binds only a slice the library implements without that being documented; if any crate reintroduces a NIP-98 verifier that does not delegate to `auth::nip98`; if a replayed token is accepted inside the tolerance window in a live session; or if the seam is claimed `integrated` while no second tier consumes it.*

### WP-3: Provenance Trail (REC-11 share)

REC-11 consolidates the data moat into one queryable trace, with VisionClaw leading and solid-pod-rs, agentbox and VisionClaw sharing. solid-pod-rs's contribution is the pod-side provenance record and the contract by which VisionClaw and agentbox pull it.

The composition is built and wired. `provenance.rs` carries `GitMark`, `BlockTrailAnchor`, the `GitMarker`/`BlockAnchorer` traits, `ProvenanceLog::record` (line 517), and `EpochAccumulator` Merkle batching. `ShellGitMarker` (`crates/solid-pod-rs-git/src/mark.rs`) commits with the `did:nostr` agent as author; `MempoolBlockAnchorer` (`crates/solid-pod-rs-server/src/mempool.rs`) anchors a Bitcoin taproot UTXO. The LDP write path calls this via `git_mark_write` (`crates/solid-pod-rs-server/src/lib.rs:2838`, "SINGLE canonical path: compose via `ProvenanceLog::record`" at `lib.rs:2917`), landed in commit `182ed31` (2026-06-13).

Two honest constraints bound the claim:

1. **The `git` feature is off in the default build** (`crates/solid-pod-rs-server/Cargo.toml` default feature set empty; the `#[cfg(not(feature = "git"))]` shim at `lib.rs:3007` is a no-op). A default build records zero provenance marks. Provenance requires building with `--features git`. Any REC-11 criterion assuming "always-on" provenance must read it as "on every write when compiled with `git`".
2. **The query surface is point-lookup only.** `GET /{pod}/_prov/{commit_sha}` (`crates/solid-pod-rs-server/src/handlers/prov.rs:213,227`) resolves one commit SHA; per-resource `GET /{pod}/{path}.prov.ttl` sidecars exist. No endpoint enumerates all marks for a pod, so a consumer must already hold a commit SHA or walk resources individually. That is the concrete gap for "one queryable trace".

solid-pod-rs's REC-11 deliverable in this sprint is the **provenance-trace contract**: the shape of a pod-wide index (a `GET /{pod}/_prov/` enumeration, or a SPARQL-queryable merged graph over the `*.prov.ttl` sidecars) that VisionClaw and agentbox consume without pre-knowing SHAs. Building the endpoint is P2 and led by VisionClaw against this contract; solid-pod-rs specifies the wire and registers the canary. The child ADR also corrects ADR-059's stale Status-detail section (`ADR-059:19-24` marks D3/D5/D7 "Still Proposed / not built" although they shipped in `182ed31`).

**Current maturity:** per-commit provenance `integrated` under `--features git`, `scaffolded` in the default build; pod-wide trace index `planned`. **Target:** hold per-commit provenance at `integrated` with the default-off caveat labelled; define the pod-wide trace contract (`planned`, contract-defined) with the build deferred to VisionClaw's P2 lead.

**Acceptance criteria:**
1. Under `--features git`, an LDP `PUT`/`POST`/`PATCH` produces a git-mark commit resolvable through `GET /{pod}/_prov/{commit_sha}`, evidenced by a live request/response receipt.
2. The default-off caveat is stated in the compatibility matrix; no REC-11 claim reads provenance as on-by-default.
3. A provenance-trace contract document specifies the pod-wide index shape (endpoint or SPARQL merged graph), the enumeration semantics, and the `did:nostr` agent-attribution field VisionClaw and agentbox consume.
4. ADR-059's Status-detail section is corrected to match shipped code, with the two real residuals (default-off feature, missing pod-wide index) named.

**Falsification statement.** *WP-3 is falsified if the pod-wide trace is claimed delivered while only point-lookup `_prov` exists; if a REC-11 acceptance elsewhere assumes provenance records on a default build (feature off); if the contract is asserted without naming the enumeration semantics VisionClaw consumes; or if ADR-059 still reports the shipped composition as "not built".*

### WP-4: Diagram Render (RES-c)

Eight of the nine architecture diagrams are stale and the ninth is unrendered. The rendered PNGs (`crates/solid-pod-rs/docs/diagrams/rendered/01`…`08`) were last committed 2026-04-20 (`3583a2b`); their `.mmd` sources were last committed 2026-06-12 (`fa84a12`, "verify mermaid diagrams against crate code; correct drifted claims"). Diagram 9 (`src/09-provenance-tiers.mmd`, committed 2026-06-13 in `b9a7891`, covering the ADR-059 provenance tiers) has no PNG at all; the index in `docs/diagrams/README.md` marks it "_(pending render)_".

The render command is documented in `README.md` (`mmdc -i "$f" -o rendered/... -b transparent -s 2 -w 2000`, with `puppeteer.config.json` for containers). RES-c depends on VisionFlow's RES-b render gate: RES-b owns the verified render step plus visual-regression check (ADR-111 execution) that prevents the published-invisible-text failure RES-b was raised for. solid-pod-rs regenerates the nine PNGs and adds a local staleness check that fails when a `.mmd`'s commit is newer than its PNG's, but it does not claim its own render verified until the RES-b gate is in service. `mmdc` (Node/npm) availability in the build environment is unconfirmed and is a precondition for the regeneration.

**Current maturity:** `scaffolded` — the pipeline and command are documented, the outputs are stale. **Target:** `integrated` once all nine PNGs regenerate and the RES-b verified-render gate passes them; declared blocked on RES-b until then.

**Acceptance criteria:**
1. All nine PNGs regenerate from their `.mmd` sources, including `09-provenance-tiers.png`, with no PNG older than its source's commit.
2. A staleness check (CI or pre-commit) fails when any `.mmd`'s commit timestamp is newer than its rendered PNG's.
3. Regenerated PNGs pass VisionFlow's RES-b visual-regression check; no PNG ships with invisible or unrendered text.
4. The dependency on RES-b is declared in the compatibility matrix; RES-c is not scored closed until RES-b's gate is live.

**Falsification statement.** *WP-4 is falsified if a PNG ships older than its `.mmd` source without the staleness check failing; if diagram 9 remains unrendered; if a regenerated PNG carries invisible text (the RES-b failure mode); or if RES-c is scored closed while RES-b's verified-render gate does not yet exist.*

## Liveness Canaries

Loop-closing items register a canary against VisionClaw's `LivenessHarness` (RES-a). A canary fires only in a live session; a registered-but-unfired canary keeps its item `Open`. RES-c is not loop-closing (no wire carries traffic); its gate is RES-b's visual-regression check, not a liveness canary.

| Canary ID | Wire observed | Firing means | Item | Durability |
|---|---|---|---|---|
| `solid-pod.patch-nondestructive` | PATCH write path: `handle_patch` (lib.rs:1210) → `seed_graph_from_patch_target` (lib.rs:1467) → `ldp::apply_*_patch` | The three `patch_non_destructive_integration.rs` tests pass green against the pinned SHA; a sibling-preserving patch keeps siblings and an unparseable body 409s | WP-1 | One-shot per SHA (correctness fix; DDD open-issue 2) |
| `solid-pod.nip98-replay-reject` | WAC-gated write auth path through `auth::nip98::verify_at` and `Nip98ReplayCache` (replay.rs:73) | A re-presented NIP-98 token (same event id) inside the ±120s window returns 401; anonymous and tampered-signature requests return 401 | WP-2 | Standing monitor, per replica |
| `solid-pod.prov-mark-live` | LDP write → `git_mark_write` (lib.rs:2838, `--features git`) → git commit → `GET /{pod}/_prov/{commit_sha}` | A `PUT` under `--features git` produces a git-mark commit resolvable by its SHA through the `_prov` point-lookup | WP-3 | Standing monitor under `--features git` |
| `solid-pod.prov-trace-index` | Pod-wide provenance index (contract defined here, built VisionClaw-led in P2) | An enumerate/query over a pod returns every recorded mark without a pre-known SHA | WP-3 | Registered now; fires only when the P2 index ships; item stays `planned` until then |

## Evaluation Lens

solid-pod-rs owns no forum, desktop, MR or voice surface, so it scores nothing directly on the 40/30/20/10 lens. Its items are substrate:

- **REC-1** and **WP-2** are P0 floor. The meta-PRD's framing is that nothing above P0 is worth measuring until the security floor closes; the non-destructive PATCH and the enforced single-source NIP-98 verifier are two boards of that floor.
- **REC-11** feeds the desktop and forum surfaces indirectly through the data moat, once the pod-wide trace contract is built and consumed. It carries no surface score itself.
- **RES-c** is documentation freshness under the P1 render discipline; it clears a book-production residual, not a surface gap.

## Cross-Reference

- Meta-register: [PRD-gap-close-sprint.md](../../../../VisionFlow/docs/PRD-gap-close-sprint.md) Table B (REC-1, REC-11), Table C (RES-c); solid-pod-rs work-package section.
- Governance: [ADR-004](../../../../VisionFlow/docs/ADR-004-gap-close-sprint-governance.md) (canary gate, anti-fox, wave gating), ADR-002 (maturity vocabulary, compatibility matrix, release manifest).
- Local: [ADR-060](adr/ADR-060-gap-close-solid-pod-slice.md) (the decisions this slice forces), [ADR-059](adr/ADR-059-provenance-primitives-block-trails-git-marks.md) (provenance primitives, Status-detail correction pending), `docs/reference/patch-semantics.md`, `docs/diagrams/README.md`.
- Upstream dependency: VisionClaw RES-a `LivenessHarness` (canary registration); VisionFlow RES-b render gate (RES-c gate); VisionClaw REC-11 lead (trace-index build).
