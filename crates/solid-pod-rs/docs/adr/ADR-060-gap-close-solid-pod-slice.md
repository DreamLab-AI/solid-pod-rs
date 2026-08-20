# ADR-060: Gap-Close sprint — decisions the solid-pod-rs slice forces

**Status:** Proposed
**Date:** 2026-07-08
**Decision Owners:** solid-pod-rs maintainers
**Supersedes:** none
**Related:** [PRD-gap-close-solid-pod](../PRD-gap-close-solid-pod.md), [DDD-gap-close-solid-pod-context](../DDD-gap-close-solid-pod-context.md), [ADR-059](ADR-059-provenance-primitives-block-trails-git-marks.md), the meta-PRD and [ADR-004](https://github.com/DreamLab-AI/VisionFlow/blob/main/docs/ADR-004-gap-close-sprint-governance.md) at the VisionFlow canon, ADR-002 (ecosystem alignment)

**Naming note.** This slice's PRD and DDD adopt the canon's unnumbered child-document convention (`PRD-gap-close-solid-pod.md`, `DDD-gap-close-solid-pod-context.md`); this ADR keeps the repository's numbered series, taking the next free number, 060.

## Context

The meta-PRD assigns solid-pod-rs four items: REC-1 (non-destructive PATCH), the NIP-98 verifier consolidation, the REC-11 provenance-trail share, and RES-c (stale diagrams). Recon against `gap-close/2026-07` HEAD (`cded64f`, off `closeout/2026-07-03`, workspace `0.5.0-alpha.4`) finds the code ahead of the register on three of the four. The decisions below are the ones that finding forces: how to close an item the register still lists open, how far to take a consolidation the repository has already largely done, what solid-pod-rs owes REC-11 when the composition is built but the query surface is thin, and how to treat a documentation-freshness item that depends on another repository's gate.

ADR-004's canary-and-receipt discipline sets the frame. A closure is code-verified at a stated maturity tier, never documentation alone, and a loop-closing item is not closed until its canary fires. That discipline changes what "close an already-fixed bug" means: the receipt is the passing test against the pinned SHA, not the assertion that the fix exists.

## Decision 1 — Close REC-1 PATCH with a receipt and correct the register, rather than re-implement

The non-destructive PATCH fix already landed. `handle_patch` (`crates/solid-pod-rs-server/src/lib.rs:1210`) seeds the working graph from the stored resource through `seed_graph_from_patch_target` (`lib.rs:1467`) before applying the patch, and fails closed with 409 on an unparseable existing body. Three regression tests pass (`patch_non_destructive_integration.rs:63,103,142`). The fix is commit `791977a` (2026-05-29).

The decision is to treat REC-1's PATCH sub-item as **closure-with-receipt against a stale register entry**: cite commit `791977a` and the test file, run the three tests against the pinned SHA under the anti-fox verifier, register the one-shot regression canary, and correct the meta-register so it stops listing the item open.

**Alternatives considered.**

| Alternative | Verdict | Rationale |
|---|---|---|
| Treat the item as open and re-fix | Rejected | The fix landed 2026-05-29 with passing regression tests; re-implementing would risk regressing a correct write path and produce no new evidence. |
| Close on the register correction alone | Rejected | Violates ADR-004 Decision 2 and DDD Invariant 2. A register that closes on documentation reproduces the D5 defect the sprint exists to prevent. |
| Close-with-receipt: cite commit + tests, re-run under anti-fox, fire the canary, correct the register | Chosen | Honours the receipt discipline; the register correction chains forward per the immutability invariant rather than editing a published claim in place. |

## Decision 2 — Keep NIP-98 single-sourced in-repo; extract a `ReplayStore` seam to `standalone` and record the edge-local exception, rather than build the cross-tier store now

The verifier is already single-sourced: `crates/solid-pod-rs/src/auth/nip98.rs` is the one implementation, and `solid-pod-rs-git` (`auth.rs:144`), `solid-pod-rs-idp` (`schnorr.rs`) and the server CLI (`cli/install.rs:139`) delegate. The replay cache `Nip98ReplayCache` (`replay.rs:73`) is in `core` but concrete, and `replay.rs:20` records that the forum/CF edge tier keeps a different datastore. That tier is out of this repository, so its verifier cannot be consolidated from here.

The decision is to hold the in-repo verifier at `integrated`, extract a `trait ReplayStore` in `core` (with `Nip98ReplayCache` as one implementor) so an out-of-repo tier can depend on this crate's nonce semantics, and record the **edge-local exception** in the compatibility matrix: the forum/CF verifier stays out of scope and the seam reaches `integrated` only when a second tier consumes the trait. The per-replica replay-window caveat is stated so no cross-ecosystem claim assumes one shared verification boundary.

**Alternatives considered.**

| Alternative | Verdict | Rationale |
|---|---|---|
| Build a cross-tier shared replay store now | Rejected | The consuming forum/CF tier is a sibling repository with different datastore semantics (`replay.rs:20`); building its store here is speculative and unverifiable from this repo, and would claim an integration no second tier yet exercises. |
| Leave `Nip98ReplayCache` concrete with no seam | Rejected | Gives a second tier no way to reuse the nonce semantics; it would re-derive replay handling and reintroduce exactly the duplication the consolidation targets. |
| Extract `trait ReplayStore` (standalone) + record the edge-local exception | Chosen | Provides the seam without over-claiming; matches the meta-PRD's rule that the shared verifier is `integrated` only when a second tier consumes it, otherwise a `standalone` exception, labelled. |

## Decision 3 — Define the REC-11 provenance-trace contract; do not build the pod-wide index in this sprint; correct ADR-059's stale status

The git-mark plus block-trail composition is wired into the LDP write path (`git_mark_write`, `lib.rs:2838`; "SINGLE canonical path" at `lib.rs:2917`; commit `182ed31`). The query surface is point-lookup only: `GET /{pod}/_prov/{commit_sha}` (`handlers/prov.rs:213,227`) plus per-resource `.prov.ttl` sidecars. No endpoint enumerates a pod's marks, so "one queryable trace" is not yet delivered.

REC-11 is a P2 item with VisionClaw leading. The decision is that solid-pod-rs's contribution is the **contract** for a pod-wide trace (a `GET /{pod}/_prov/` enumeration or a SPARQL-queryable merged graph over the sidecars, with the enumeration semantics and the `did:nostr` agent-attribution field named), not the endpoint itself. The `solid-pod.prov-trace-index` canary is registered now and fires only when the endpoint ships; the item stays `planned` until then. ADR-059's Status-detail section (`ADR-059:19-24`), which marks D3/D5/D7 "Still Proposed / not built" although they shipped in `182ed31`, is corrected in the same slice so the ADR stops understating REC-11's real state.

**Alternatives considered.**

| Alternative | Verdict | Rationale |
|---|---|---|
| Build the pod-wide index now | Rejected | REC-11 is P2 and VisionClaw-led; the index shape must serve VisionClaw and agentbox consumers whose query needs are not yet fixed. Building ahead of the contract risks a wire the consumers cannot use. |
| Claim REC-11 delivered via the existing point-lookup | Rejected | Point-lookup by known SHA is not a unified queryable trace; claiming it would be a maturity overclaim the register's honesty discipline forbids. |
| Define the contract, register the canary, correct ADR-059 | Chosen | Delivers solid-pod-rs's honest REC-11 share (the wire spec) while leaving the build to the lead; the canary makes the deferred endpoint visibly `planned` rather than folded into a closed parent. |

## Decision 4 — Keep the `git` provenance feature off by default in this sprint

Provenance marks require `--features git`; the default build's `git_mark_write` is a no-op shim (`lib.rs:3007`), so a default build records nothing. ADR-059 already flags this. The decision is to **hold the default off** for this sprint and label the caveat wherever a REC-11 claim is made, rather than flip the default.

**Alternatives considered.**

| Alternative | Verdict | Rationale |
|---|---|---|
| Flip `git` on by default | Rejected | Carries a build-size and write-latency cost across every deployment and is outside the register's scope for this wave; a default-flip is a compatibility change that belongs in its own PRD. |
| Leave default off, unlabelled | Rejected | Lets a REC-11 claim read as "always-on provenance" when a default build records zero marks — a silent overclaim. |
| Leave default off, caveat labelled, canary runs under `--features git` | Chosen | Honest about what a default build does; the `solid-pod.prov-mark-live` canary observes the wire under the feature that actually enables it. |

## Decision 5 — Regenerate the RES-c diagrams under VisionFlow's RES-b render gate; declare the dependency, do not ship a local render claim

Eight of nine PNGs are stale (`rendered/` at `3583a2b`, 2026-04-20; sources at `fa84a12`, 2026-06-12) and diagram 9 is unrendered. The decision is to regenerate all nine PNGs and add a local staleness check (fail when a `.mmd` commit is newer than its PNG), but to **declare RES-c blocked on RES-b's verified-render and visual-regression gate** rather than claim a local render verified. RES-b exists precisely because a local render shipped invisible text; solid-pod-rs does not reproduce that by self-certifying its own render.

**Alternatives considered.**

| Alternative | Verdict | Rationale |
|---|---|---|
| Render locally and score RES-c closed | Rejected | RES-b owns the verified render plus visual-regression check; a local render with no visual check is the exact failure (invisible text) RES-b was raised to catch. |
| Defer RES-c entirely | Rejected | RES-c is P1; 8/9 diagrams are stale and one is missing, and the provenance diagram (09) documents shipped ADR-059 behaviour readers need. |
| Regenerate all nine + local staleness check, gated on RES-b | Chosen | Does the repo-local work now, declares the cross-repo dependency, and defers the "verified" claim to the gate that can actually make it. |

## What This ADR Does Not Govern

- The implementation of REC-11's pod-wide index (VisionClaw-led, P2) or the out-of-repo forum/CF replay store — this ADR defines the contract and the seam, not their code.
- The RES-b render gate itself (VisionFlow owns it); this ADR consumes it.
- Re-rating any register severity or wave; the canon owns those, and a move is a register edit, not an ADR revision (ADR-004 Decision 7).
- Flipping the `git` default feature — a separate compatibility PRD.

## Consequences

### Positive

- REC-1 and the NIP-98 verifier close honestly against evidence already on-branch; the P0 floor for this substrate is receipt-backed, not asserted.
- REC-11's deferred half is visible as `planned` with a registered canary, so a design accepted here cannot be scored closed until its wire carries traffic — the ADR-004 structural answer applied locally.
- ADR-059 stops understating shipped provenance code, so downstream scoping reads the true state.

### Tradeoffs

- The cross-tier NIP-98 consolidation and the pod-wide trace index remain open across a repository boundary; solid-pod-rs supplies the seam and the contract but cannot close them alone, and the canaries for both sit registered-but-unfired until the consuming tiers land.
- Default-off provenance means a default build records nothing; the caveat travels with every REC-11 claim, which is coordination cost the compatibility matrix must carry.

### Risks

- **RES-c is gated on RES-b, which is outside this repository.** If RES-b's render gate slips, RES-c cannot reach `integrated` on schedule even though the repo-local regeneration is done. The mitigation is to land the regeneration and the staleness check now and declare the block, so the delay registers against RES-b, not solid-pod-rs.
- **The `mmdc` toolchain is unconfirmed in the build environment.** The regeneration precondition (Node/npm `@mermaid-js/mermaid-cli`) must be verified before WP-4 can run; an absent toolchain re-opens RES-c.

## Governance

- Reconcile each closed item into `docs/architecture/compatibility-matrix.md` at the canon, at the tier its evidence supports (ADR-002).
- Register the four canaries against VisionClaw's `LivenessHarness` (RES-a) before this slice enters its wave; a loop item with no fired canary stays `Open`.
- The anti-fox verifier for these closures is a party on a different model family, running at least one counter-example probe (re-running the PATCH regression suite and the NIP-98 replay-reject path against the pinned SHA).
