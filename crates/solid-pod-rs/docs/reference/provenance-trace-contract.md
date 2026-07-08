# Provenance-trace contract (REC-11)

**Status:** Contract defined; endpoint `planned` (build VisionClaw-led, P2)
**Date:** 2026-07-08
**Owner:** solid-pod-rs maintainers (DreamLab AI)
**Governed by:** [PRD-gap-close-solid-pod](../PRD-gap-close-solid-pod.md) WP-3,
[ADR-060](../adr/ADR-060-gap-close-solid-pod-slice.md) Decision 3,
[ADR-059](../adr/ADR-059-provenance-primitives-block-trails-git-marks.md)
**Consumers:** VisionClaw (REC-11 lead, builds the unified trace), agentbox
(supplies the `did:nostr` agent identity that authors git-marks)

> **Default-off caveat (applies to every claim in this document).** Provenance
> marks are produced only when the server is compiled with `--features git`.
> The default build's write hook is a no-op shim
> (`solid-pod-rs-server/src/lib.rs`, `#[cfg(not(feature = "git"))]`), so a
> **default build records zero marks and a trace over it is empty**. Read every
> "the trace returns …" sentence below as "on a pod served by a
> `--features git` build". Flipping the default is out of scope (ADR-060
> Decision 4); this contract does not assume on-by-default provenance.

## 1. Why this contract exists

REC-11 consolidates the ecosystem's provenance into one queryable trace, with
VisionClaw leading and solid-pod-rs, agentbox and VisionClaw sharing.
solid-pod-rs already **produces** the pod-side record and **resolves it by a
known commit SHA**, but has no surface that **enumerates** a pod's marks. That
enumeration is the missing wire for "one queryable trace"; this document is its
contract.

What already ships (commit `182ed31`, ADR-059 Phase 5, under `--features git`):

- **The composition.** Every LDP `PUT`/`POST`/`PATCH` runs
  `ProvenanceLog::record` — the cheap git-mark always, a Bitcoin block-trail
  anchor per `AnchorPolicy` — via the single canonical write path
  (`git_mark_write` → `ProvenanceLog::record`).
- **Per-commit point-lookup.** `GET /{pod}/_prov/{commit_sha}` resolves one
  commit to its resource + `ProvenanceMark`
  (`solid-pod-rs-server/src/handlers/prov.rs`).
- **Per-resource sidecar.** Each written resource carries a PROV-O
  `<resource>.prov.ttl` Turtle sidecar.
- **Anchor upgrade.** `POST /{pod}/_prov/anchor` upgrades a git-mark to a
  block-trail anchor.

What is **missing** and this contract specifies: a **pod-wide enumeration** that
returns every recorded mark **without a pre-known SHA**, so a consumer can walk
or query a whole pod's trail from cold.

## 2. The contract: `GET /{pod}/_prov/`

A consumer that holds no SHA must be able to list a pod's marks. The trailing
slash distinguishes the collection (`/{pod}/_prov/`) from the point-lookup
(`/{pod}/_prov/{commit_sha}`). The route is registered before the LDP
catch-all, exactly as the existing `_prov` routes are, so `_prov` segments are
never treated as pod resources.

### 2.1 Request

```
GET /{pod}/_prov/?limit=100&after=<cursor>&resource=<path-prefix>&agent=<did:nostr>&anchored=<bool>
```

| Parameter | Meaning | Default |
|---|---|---|
| `limit` | Max marks per page (1–1000). | 100 |
| `after` | Opaque cursor from a prior page's `next` (see §2.3). Absence starts at the newest mark. | — |
| `resource` | Restrict to marks whose resource path starts with this pod-relative prefix (e.g. `/{pod}/alice/notes/`). | all |
| `agent` | Restrict to marks authored by this `did:nostr` agent. | all |
| `anchored` | `true` → only block-trail-anchored marks; `false` → only git-only marks. | all |

**No pre-known SHA is required or accepted here.** A consumer enumerates from
cold; the point-lookup route is the only SHA-keyed surface. This is the
invariant the DDD fixes (open issue 2): the pod-wide trace must not require a
SHA the caller cannot yet have.

### 2.2 Enumeration semantics

- **Source of truth: the git-mark chain.** Marks are enumerated by walking the
  pod repo's commit history on `main` (the branch `GitMark.branch` pins),
  newest first. Each git-mark commit touches exactly one content resource plus
  nothing else (ACL/meta/prov sidecar writes are never marked), so one commit
  maps to one mark. This makes the enumeration **complete** (every write is a
  commit) and **ordered** (topological, newest-first) without a separate index
  to keep in sync.
- **Sidecar overlay.** For each commit, the resource's `.prov.ttl` sidecar (if
  present and matching) supplies the authoritative mark incl. any block-trail
  anchor; absent a sidecar the mark is reconstructed git-only (no anchor) — the
  same precedence the point-lookup already applies.
- **Completeness caveat.** A commit predating git-marks, or one whose sidecar
  was pruned, still enumerates as a git-only mark from commit metadata; it is
  never silently dropped.
- **Filtering** (`resource`/`agent`/`anchored`) is applied over the walked
  marks, not pushed into git, so the semantics are identical whether the
  implementation walks commits or reads a future materialised index.

### 2.3 Response

`200 application/json`. Each element is the **same mark shape the point-lookup
returns**, so a consumer parses one schema for both surfaces:

```json
{
  "pod": "npub1…",
  "count": 100,
  "next": "<opaque cursor, or null at the end of the trail>",
  "marks": [
    {
      "resource": "/npub1…/alice/notes/foo.ttl",
      "commit": {
        "sha": "…40-hex…",
        "parent": "…40-hex or null…",
        "agent_did": "did:nostr:<pubkey>",
        "committer": "<git author name>",
        "subject": "<commit subject>",
        "committed_at": "2026-06-13T10:12:30Z"
      },
      "prov_ttl": "@prefix prov: … (the resource's .prov.ttl, inlined)",
      "anchored": false
    }
  ]
}
```

- **`commit.agent_did` is the attribution field** VisionClaw and agentbox
  consume: the `did:nostr` of the NIP-98-authenticated writer, recorded as the
  git-commit author e-mail and as `prov:wasAssociatedWith` / `prov:Agent` in
  the sidecar. agentbox supplies this identity; VisionClaw keys the unified
  trace on it. An anonymous write (no NIP-98 principal) records an anonymous
  marker rather than a `did:nostr`, and enumerates as such.
- **`anchored`** is `true` when the sidecar carries a block-trail anchor
  (`bt:txid`); the anchor's taproot txid/vout live inline in `prov_ttl`.
- **`prov_ttl`** is the inlined PROV-O Turtle so a consumer gets the full mark
  (incl. anchor) without a second round-trip; `null` for a commit with no
  persisted sidecar.
- **`next`** is an opaque cursor (an encoded "walk resumes before commit X"
  position); `null` ends the trail. Cursors are stable under appends: a new
  write prepends a newer mark and never renumbers older pages.

### 2.4 Authorisation

The enumeration is a read over the whole pod's history, so it is gated at least
as strictly as reading the pod's resources: the pod owner (NIP-98 `did:nostr`
matching the pod) always may; other principals may only if WAC grants read over
the pod root. The point-lookup's existing `501`/`404` failure modes carry over:
`501` when no FS/git backend is available, `404` when the pod is not
git-backed.

## 3. Alternative shape: SPARQL over the merged sidecar graph

Where a consumer needs graph queries rather than a paged list, the equivalent
contract is a **SPARQL-queryable merged graph** over the pod's `*.prov.ttl`
sidecars. The merge is well-defined because every sidecar uses one vocabulary
(emitted by `provenance.rs`):

```turtle
@prefix prov: <http://www.w3.org/ns/prov#> .
@prefix git:  <https://w3id.org/git#> .
@prefix bt:   <https://blocktrails.org/ns#> .

<urn:git:commit:{sha}> a prov:Activity ;
    prov:generated <{resource}> ;
    prov:wasAssociatedWith <did:nostr:{pubkey}> ;
    prov:endedAtTime "…"^^xsd:dateTime .
<{resource}> a prov:Entity ;
    prov:wasGeneratedBy <urn:git:commit:{sha}> ;
    prov:wasAttributedTo <did:nostr:{pubkey}> .
<did:nostr:{pubkey}> a prov:Agent .
# when anchored:
<urn:bt:tx:{txid}:{vout}> a prov:Entity ;
    prov:wasDerivedFrom <urn:git:commit:{sha}> .
```

A consumer asks, e.g., "every resource `did:nostr:X` generated after time T" as
one SPARQL query over the union of sidecars, keyed on `prov:wasAssociatedWith`
/ `prov:wasAttributedTo`. This shape and the JSON enumeration are two
projections of the same underlying marks; a build MAY provide either or both.
The contract fixes the vocabulary and the "no pre-known SHA" invariant, not the
query transport.

## 4. What this contract does and does not commit solid-pod-rs to

- **Defines** the pod-wide enumeration wire (request, semantics, response,
  attribution field, auth) and its SPARQL-graph equivalent, aligned to ADR-060
  Decision 3.
- **Does not build** the endpoint in this sprint. REC-11 is P2 and
  VisionClaw-led; the index shape must serve VisionClaw's and agentbox's query
  needs, so building ahead of their consumption risks a wire they cannot use.
- **Registers a canary** — `solid-pod.prov-trace-index` — against VisionClaw's
  `LivenessHarness`. It fires only when an enumerate/query over a pod returns
  every recorded mark without a pre-known SHA. Until it fires, the pod-wide
  trace stays `planned`; the point-lookup and per-resource sidecars are all
  that ship.

## 5. Falsification (the claims a verifier attacks)

This contract is falsified if any of the following hold:

1. The pod-wide trace is claimed **delivered** while only the point-lookup
   `GET /{pod}/_prov/{commit_sha}` exists (no `/{pod}/_prov/` enumeration).
2. A REC-11 acceptance elsewhere assumes provenance records on a **default
   build** (git feature off), contradicting the caveat at the head of this
   document.
3. The contract is asserted **without naming the enumeration semantics** (the
   commit-chain walk, newest-first, one commit → one mark, sidecar overlay,
   no-pre-known-SHA) or **without the `did:nostr` `agent_did` attribution
   field** VisionClaw consumes.
4. The `solid-pod.prov-trace-index` canary is treated as fired (item scored
   closed) before an enumeration over a pod actually returns its marks.
