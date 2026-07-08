# DDD: Gap-Close solid-pod-rs slice — bounded-context view

**Status:** Living document
**Date:** 2026-07-08
**Scope:** solid-pod-rs's owned slice of the four-surface gap register — REC-1 PATCH correctness, NIP-98 verifier consolidation, the REC-11 provenance-trail share, RES-c diagram render
**Governed by:** [PRD-gap-close-solid-pod](PRD-gap-close-solid-pod.md), [ADR-060](adr/ADR-060-gap-close-solid-pod-slice.md)
**Conformist to:** [DDD Gap-Close Context](../../../../VisionFlow/docs/DDD-gap-close-context.md), ADR-002 Ecosystem Alignment

**Naming note.** This repository carries no numbered DDD series; for this sprint it adopts the canon's unnumbered child-document convention, matching `PRD-gap-close-solid-pod.md`.

---

## 1. Bounded Context

This document is the solid-pod-rs view of the Gap-Close Context. It does not restate the canon's model; it names the local aggregates, invariants and events this slice's four items touch, and shows how each maps onto the upstream Gap-Close vocabulary it conforms to. It owns the pod-side code that closes these items; it does not own the register, the waves, or the scoring, which stay at the canon.

The slice sits below the four-surface line. It supplies substrate: a non-destructive write path, a single-source signature verifier, a provenance record, and current diagrams. Its closures are consumed by the scored surfaces, never scored directly.

---

## 2. Context Map

| Context | Relationship | Notes |
|---|---|---|
| **Gap-Close Sprint** (canon) | Upstream, Conformist | Owns `GapRegister`, `SprintWave`, the maturity vocabulary and the closure protocol this slice obeys. solid-pod-rs supplies a `RepoWorkPackage` and its `ClosureEvidence`. |
| **Ecosystem Alignment** (ADR-002) | Upstream, Conformist | Supplies the seven-tier maturity vocabulary and the compatibility-matrix machinery, used verbatim. |
| **VisionClaw** | Downstream customer for REC-11; upstream host of the `LivenessHarness` (RES-a) and the RES-b render dependency chain | solid-pod-rs supplies the provenance-trace contract VisionClaw's REC-11 lead consumes, and registers its canaries against VisionClaw's harness. |
| **agentbox** | Downstream customer for REC-11 | Consumes the same provenance-trace contract; supplies the `did:nostr` agent identity that authors git-marks. |
| **Forum / CF edge tier** (out of repo) | Downstream customer for the NIP-98 `ReplayStore` seam | Sibling-repository tier that may implement `trait ReplayStore` against this crate; the edge-local exception (ADR-060 Decision 2). |

### Relationship types

- **Gap-Close → this slice:** Customer/Supplier. This slice supplies its work package and evidence; the canon defines the falsification, receipt and canary protocol the supply meets.
- **This slice → VisionClaw / agentbox (REC-11):** Customer/Supplier. solid-pod-rs is the supplier of the provenance record and the trace contract; VisionClaw leads the consuming unified trace.
- **This slice → forum/CF tier (NIP-98):** Supplier of a published `trait ReplayStore`; the consuming tier is out of repo, so the relationship is a documented exception until it is wired.

---

## 3. Aggregates This Slice Touches

Local aggregates from the solid-pod-rs model, mapped to the Gap-Close aggregates they supply evidence for.

| Local aggregate | Root | This slice's concern | Gap-Close mapping |
|---|---|---|---|
| `PatchOperation` over an LDP `Resource` | `Resource` | Non-destructive merge: the working graph is seeded from the stored resource before the patch applies (`seed_graph_from_patch_target`, lib.rs:1467) | REC-1 `Gap` → `ClosureEvidence` (the three regression tests) |
| `Nip98Verification` | `Nip98Verified` | One canonical verifier (`auth/nip98.rs`) and a replay cache (`Nip98ReplayCache`, replay.rs:73) every tier shares | NIP-98 `Commitment` → `ClosureEvidence` (delegation grep + replay-reject canary) |
| `ProvenanceLog` | `ProvenanceLog` | Composition of `GitMark` and `BlockTrailAnchor` on the LDP write path (`ProvenanceLog::record`, provenance.rs:517; `git_mark_write`, lib.rs:2838) | REC-11 `Commitment` → `ClosureEvidence` (provenance-wire canary) + the trace contract |
| `DiagramSet` | `docs/diagrams/README.md` index | Rendered PNGs current against their `.mmd` sources | RES-c `Residual` → gated on RES-b, no canary |

Members inherited from the canon's `GapRegister`, `SprintWave` and `RepoWorkPackage` aggregates are consumed unchanged; this slice adds none.

---

## 4. Entities

| Entity | Identity | Owner | This slice |
|---|---|---|---|
| `Gap` / `Commitment` / `Residual` | Register ID (REC-1, REC-11, RES-c; NIP-98 sub-item) | GapRegister (canon) | Referenced, not owned |
| `ChildDocument` | `solid-pod` + `gap-close` + type | solid-pod-rs | The PRD, this DDD, ADR-060 |
| `LivenessCanary` | Canary ID against the harness | VisionClaw (harness), solid-pod-rs (registration) | Four canaries, listed in §6 |
| `GitMark` | Commit SHA + resource path | solid-pod-rs | Provenance record; resolvable via `_prov` point-lookup |
| `BlockTrailAnchor` | Taproot UTXO / anchor tx | solid-pod-rs | Opt-in block-trail tier |
| `Nip98ReplayCache` entry | Canonical NIP-01 event id | solid-pod-rs | Replay-window nonce; process-local per replica |

---

## 5. Value Objects (conformist)

| Value Object | Fields | This slice's use |
|---|---|---|
| `MaturityTier` | historical, planned, scaffolded, standalone, integrated, federation-verified, released | REC-1 `integrated`; in-repo verifier `integrated`, cross-tier seam `scaffolded`→`standalone`; per-commit provenance `integrated` (default build `scaffolded`), pod-wide trace `planned`; RES-c `scaffolded`→`integrated` |
| `Wave` | P0, P1, P2 | REC-1 and NIP-98 P0; RES-c P1; REC-11 P2 |
| `ExitCriterion` | Predicate over live state | Carried from the meta-PRD's solid-pod-rs acceptance criteria |
| `FalsificationStatement` | Predicate whose truth means not done | One per work package, in the PRD |
| `GitFeatureState` | on (`--features git`) / off (default) | Provenance records only when compiled with `git`; the caveat that travels with every REC-11 claim (ADR-060 Decision 4) |

---

## 6. Domain Events

Canon events this slice publishes or consumes, plus the local events its canaries observe.

| Event | Trigger | Publisher | Consumer |
|---|---|---|---|
| `WorkPackageMinted` | This slice's PRD/ADR/DDD authored | solid-pod-rs | Gap-Close context (this act) |
| `FalsificationStated` | The four falsification statements written before work | solid-pod-rs | Gap-Close context |
| `CanaryRegistered` | The four canaries registered against RES-a | solid-pod-rs | SprintWave |
| `CanaryFired` | A canary observes live traffic (see below) | VisionClaw `LivenessHarness` | SprintWave, `ClosureEvidence` |
| `ClosureEvidenced` | Receipt + maturity claim + canary result recorded per item | solid-pod-rs | Anti-fox verifier |
| `RegisterSuperseded` | REC-1 PATCH entry corrected to cite `791977a` (forward-chaining, not in-place) | VisionFlow canon | All consumers |
| *local:* `PatchApplied (non-destructive)` | A PATCH seeds from the stored resource and preserves siblings | solid-pod-rs-server | `solid-pod.patch-nondestructive` canary |
| *local:* `Nip98Rejected (replay/anon/tamper)` | A re-presented or invalid token returns 401 | solid-pod-rs-server | `solid-pod.nip98-replay-reject` canary |
| *local:* `GitMarkRecorded` | An LDP write under `--features git` commits a git-mark | solid-pod-rs-server | `solid-pod.prov-mark-live` canary |
| *local:* `ProvTraceQueried` | A pod-wide index enumerates marks (endpoint not yet built) | solid-pod-rs-server (planned) | `solid-pod.prov-trace-index` canary (registered, unfired) |

---

## 7. Invariants

Canon invariants this slice must uphold, plus the local write-path invariants the items defend.

1. **Non-destructive write (REC-1).** A PATCH preserves every triple the patch does not restate; an unparseable stored body fails closed with 409 rather than being overwritten. This is the DDD-012 A2 invariant the regression tests cite; it maps to canon Invariant 2 (closure is code-verified — here by the three passing tests, not by the fix's existence).

2. **Single-source verification (NIP-98).** No workspace crate carries a second NIP-98 verifier; every tier delegates to `auth/nip98.rs`. The cross-tier seam reaches `integrated` only when a second tier consumes `trait ReplayStore` — canon Invariant 6 (maturity claimed conservatively): the seam is `standalone`, labelled, until then.

3. **Provenance reaches the wire (REC-11).** A closed provenance claim requires a git-mark that a live write actually produced and a query actually resolves, not the composition's presence in code. This is canon Invariant 4 (no canary, no closure) applied to the provenance record; the pod-wide trace stays `Open` until `solid-pod.prov-trace-index` fires.

4. **Register immutability (REC-1 correction).** The REC-1 PATCH correction is a forward-chaining register edit citing `791977a`, never an in-place edit of a published register — canon Invariant 5.

5. **Maturity honesty on the default-off feature.** Provenance is claimed at the tier the default build supports (`scaffolded`), with the `--features git` tier (`integrated`) labelled separately. A default build records zero marks; no claim folds the deferred default-flip into a closed parent — canon Invariant 6.

6. **RES-c is gated, not self-certified.** RES-c reaches `integrated` only through VisionFlow's RES-b verified-render and visual-regression gate; a local render does not close it. This defends against the RES-b failure mode (published invisible text).

---

## 8. Ubiquitous Language (local additions)

Terms this slice adds to the shared Gap-Close language, drawn from the solid-pod-rs model.

| Term | Meaning |
|---|---|
| **Seed graph** | The working graph a PATCH starts from, seeded from the stored resource (`seed_graph_from_patch_target`) so a merge preserves pre-existing triples. Its absence was the REC-1 data-loss bug. |
| **Git-mark** | The cheap, always-on-when-compiled provenance tier: an LDP write committed as a git commit authored by the `did:nostr` agent, with a PROV-O `.prov.ttl` sidecar. |
| **Block-trail** | The opt-in expensive provenance tier: a Bitcoin taproot anchor over a state chain, independently verifiable without trusting the pod. |
| **Prov-trace** | The pod-wide queryable provenance surface REC-11 needs: an enumeration or SPARQL merged graph over a pod's marks, distinct from the existing per-commit point-lookup. Contract defined here, built by VisionClaw's lead. |
| **Replay cache** | The process-local LRU (`Nip98ReplayCache`) that rejects a re-presented NIP-98 token inside its timestamp window; per replica, not shared across replicas. |
| **ReplayStore seam** | The `trait ReplayStore` extracted so an out-of-repo tier can reuse this crate's nonce semantics; the edge-local exception until a second tier consumes it. |

---

## 9. Ownership Summary

| solid-pod-rs owns | solid-pod-rs does not own |
|---|---|
| The non-destructive PATCH write path and its regression suite | The register, the waves, the four-surface score |
| The single-source NIP-98 verifier and the `ReplayStore` seam in `core` | The out-of-repo forum/CF replay store that would consume the seam |
| The pod-side provenance record (git-mark, block-trail) and the trace contract | The unified queryable trace across substrates (VisionClaw leads REC-11) |
| Regeneration of the nine diagrams and a local staleness check | The RES-b verified-render and visual-regression gate (VisionFlow) |
| The four canaries' registration and the local events they observe | The `LivenessHarness` that records `CanaryFired` (VisionClaw, RES-a) |

---

## 10. Open Issues

1. **Cross-tier consolidation boundary (NIP-98).** The sub-item boundary between solid-pod-rs's `trait ReplayStore` and the forum/CF tier's implementation is fixed here as: solid-pod-rs publishes the trait and holds the reference implementation; the edge tier owns its own datastore-backed implementor. The seam's `integrated` promotion depends on that out-of-repo tier, which cannot be verified from this repository.
2. **REC-11 trace-contract shape.** Whether the pod-wide trace is a `GET /{pod}/_prov/` enumeration or a SPARQL-queryable merged graph over `*.prov.ttl` sidecars is left to the contract document and VisionClaw's consuming needs; the DDD fixes only that a pre-known SHA must not be required.
3. **Canary durability split.** `solid-pod.patch-nondestructive` is one-shot (a correctness fix, per canon open-issue 2); `solid-pod.nip98-replay-reject` and `solid-pod.prov-mark-live` are standing monitors; `solid-pod.prov-trace-index` is registered but unfired until the P2 endpoint ships. This split is recorded so a one-shot canary is not mistaken for a missing monitor.
