---
id: ADR-2012
title: Prompt versions, run records and eval cases are typed pod resources carrying provenance marks
date: 2026-11-23
decision_status: proposed
implementation_status: none
activation_status: inactive
supersedes: []
superseded_by: []
verified_commit: c24ab7c
owner: jjohare
review_trigger: a consumer (nostr-rust-forum ADR-2035 or another) dispatching agent work that cites a prompt version; the owner's decision on where typed business records live (register item WORK-RECORDS-HOME)
repo: solid-pod-rs
evidence_class:
acceptance_boundary:
---

# ADR-2012 — Prompt versions, run records and eval cases are typed pod resources carrying provenance marks

## Context
- Shared agent workflows need three durable things beside the task itself: the prompt version that ran, a record of each run, and eval cases that judge output. Without them a shared workflow can't be improved or audited.
- The crate already has the parts: LDP containers and JSON-LD (`ldp.rs`, `rdf_input.rs`), type indexes provisioned per pod (`provision.rs:10-14`, `public_type_index`), WAC (`wac/`), notifications (`notifications/`) and provenance marks: a git-mark on every write, with an optional block-trail anchor (`provenance.rs:1-25`, `ProvenanceMark`, `ProvenanceLog`).
- No crate type names these records, so each consumer would invent its own JSON shape and lose interop and the provenance chain.
- Event kinds on a relay suit hot, last-write-wins state such as a card's column. They suit versioned, auditable artefacts less well, because those need history, access control per resource and content addressing.

## Decision
1. Add a `work-records` cargo feature (default off). It ships three JSON-LD resource types, validation and type-index registration helpers. The feature contains pure logic and compiles for `wasm32-unknown-unknown`, like `provenance.rs`.
   - `PromptVersion`: `text` or a `body` reference, `status` ∈ {`testing`, `production`, `retired`}, `supersedes`, `step` (the process step it serves) and `sha256` of the canonical body. Only a holder of Control on the container may change `status`.
   - `RunRecord`: modelled as `prov:Activity`. It records `prov:used` (input and the PromptVersion URL with its hash), `prov:generated` (output URL with hash), `prov:wasAssociatedWith` (the agent's `did:nostr`), `prov:wasStartedBy` (the intent's signer), start and end times, an `outcome`, and the `ProvenanceMark` of its write.
   - `EvalCase`: `input`, `criteria`, and `judge` ∈ {`ai`, `code`, `human`}, linked to the PromptVersion `step` it tests.
2. References between records carry the target's URL plus `#sha256=<hex>`. A consumer verifies the hash before relying on content, so a pod edit can't silently change what a past run cited.
3. Each type is registered in the pod's type index on first write (public or private, chosen by the caller). Other Solid apps can then discover the records without knowing any one consumer.
4. On a deployment with a git marker (the native server with `solid-pod-rs-git`), each write of these types records a `GitMark`. Block-trail anchoring stays opt-in per `AnchorPolicy`.
5. Out of scope: typed business records (projects, people, teams, customers). Whether they live as pod JSON-LD or as Nostr addressable kinds is an owner decision (register item WORK-RECORDS-HOME). This ADR neither forecloses nor presumes it.

## Consequences
- A dispatcher (forum ADR-2035) can cite an exact prompt version, and a reviewer can open the run record behind any agent output and check its provenance.
- Retiring a prompt version keeps its history. A past run still resolves the exact text it used.
- Costs: three types with validation and tests; a vocabulary choice where PROV-O is reused and the remaining terms go in a small crate namespace; documentation in BASELINE-solid-pod-rs.md on acceptance. Proposed records don't amend the baseline.
- Worker-tier consumers without a git marker get type and hash integrity but no git-mark ordering. Their run records say so through a skipped provenance stage (`ProvenanceSkip`) instead of claiming a mark.

## Verification
- At `c24ab7c`: `rg -n "PromptVersion|RunRecord|EvalCase|work-records" crates` returns no match outside this record.
- `provision.rs:10-14` provisions the public and private type indexes, and `provenance.rs` defines `ProvenanceMark`, `GitMark`, `ProvenanceLog` and `ProvenanceSkip`. These are the parts the Decision composes.
- `implementation_status: none`.
