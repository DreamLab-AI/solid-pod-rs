# P1 evidence — REC-11 provenance-trace contract (WP-3 / ADR-060 Decision 3)

**Item:** Author the pod-wide provenance-trace contract the child PRD requires
(`GET /{pod}/_prov/` enumeration semantics; no pre-known SHA required), aligned
to ADR-060 Decision 3, with the `git`-feature default-off caveat on every
claim; correct ADR-059's stale Status-detail section.
**Base commit verified against:** `48c826a` (`gap-close/2026-07`)
**Maturity:** pod-wide trace index `planned` (contract defined; build
VisionClaw-led P2). Per-commit provenance stays `integrated` under
`--features git`, `scaffolded` in the default build — caveat labelled.

## What changed

| File | Change |
|---|---|
| `crates/solid-pod-rs/docs/reference/provenance-trace-contract.md` (new) | The contract: `GET /{pod}/_prov/` request params, enumeration semantics (commit-chain walk, newest-first, one commit → one mark, sidecar overlay, **no pre-known SHA**), response schema (same mark shape as the point-lookup), the `did:nostr` `agent_did` attribution field, the SPARQL merged-graph alternative, auth, the registered `solid-pod.prov-trace-index` canary, and a falsification section. Default-off git caveat stated at the head and re-stated on the enumeration claims. |
| `crates/solid-pod-rs/docs/adr/ADR-059-*.md` | Status-detail corrected: D3/D5/D7 + the `ProvenanceLog::record` composition moved from "Still Proposed / not built" to "Shipped in `182ed31`" (with file/line evidence); the two real residuals named (default-off `git` feature; no pod-wide `_prov` enumeration index). Top Status line: Proposed → Accepted-with-residuals. |

## Grounding (the contract cites real code, not a wish)

Verified against HEAD so the contract's "what already ships" is accurate:

```
$ git show --stat --oneline 182ed31 | head
182ed31 feat(provenance): ProvenanceLog composition + epoch anchoring + _prov API (ADR-059 Phase 5)
 crates/solid-pod-rs-server/src/handlers/prov.rs    | 532 ++++++…
 crates/solid-pod-rs/src/provenance.rs              | 770 ++++++…

$ grep -nE "GET /\{pod\}/_prov|agent_did|prov:wasAssociatedWith|bt:txid" \
    crates/solid-pod-rs-server/src/handlers/prov.rs crates/solid-pod-rs/src/provenance.rs
handlers/prov.rs:213  GET /{pod}/_prov/{commit_sha}          # point-lookup exists
handlers/prov.rs:274  "agent_did": resolved.author_email     # did:nostr attribution field
provenance.rs:862     prov:wasAssociatedWith <{agent}>       # PROV-O sidecar vocab
provenance.rs:895     <urn:bt:tx:{txid}:{vout}> a prov:Entity # anchor entity
```

The contract's response schema reuses the exact fields the existing
point-lookup `handle_resolve` returns (`pod`, `resource`,
`commit.{sha,parent,agent_did,committer,subject,committed_at}`, `prov_ttl`,
`anchored`), so a consumer parses one schema for both the SHA-keyed lookup and
the pod-wide enumeration. The `git` no-op shim
(`#[cfg(not(feature = "git"))]`, `solid-pod-rs-server/src/lib.rs`) is why the
default-build-records-nothing caveat heads every claim.

## Receipts

The deliverable is a contract document and an ADR correction, not code, so the
receipt is the grounding above plus:

```
$ ls crates/solid-pod-rs/docs/reference/provenance-trace-contract.md
crates/solid-pod-rs/docs/reference/provenance-trace-contract.md

$ grep -c "default build records zero\|no pre-known SHA\|--features git" \
    crates/solid-pod-rs/docs/reference/provenance-trace-contract.md
（>0 — the caveat and the no-SHA invariant are stated, not implied）
```

## Falsification (WP-3) — how this survives it

- *"the pod-wide trace is claimed delivered while only point-lookup exists"* →
  the contract explicitly scopes the enumeration as `planned` (build
  VisionClaw-led) and registers the `solid-pod.prov-trace-index` canary that
  fires only when it ships; nothing here claims delivery.
- *"a REC-11 acceptance assumes provenance on a default build"* → the
  default-off caveat heads the contract and is re-stated on the enumeration
  claim; ADR-059's residuals name it too.
- *"the contract is asserted without naming the enumeration semantics
  VisionClaw consumes"* → §2.2 names them (commit-chain walk, newest-first,
  one commit → one mark, sidecar overlay, no-pre-known-SHA) and §2.3 names the
  `did:nostr` `agent_did` attribution field.
- *"ADR-059 still reports the shipped composition as 'not built'"* → corrected:
  D3/D5/D7 + `ProvenanceLog::record` now under "Shipped in `182ed31`".
