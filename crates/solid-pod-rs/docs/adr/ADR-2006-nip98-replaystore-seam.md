---
id: ADR-2006
title: Single-source NIP-98 and expose a ReplayStore seam, not a cross-tier store
date: 2026-08-31
decision_status: accepted
implementation_status: complete
activation_status: staged
supersedes: []
superseded_by: []
verified_commit: e093e88
owner: jjohare
review_trigger: a second tier (forum/CF edge) consumes ReplayStore, or a multi-replica deployment relies on replay protection
repo: solid-pod-rs
domain: BASELINE-solid-pod-rs.md
lineage: Distils archived ADR-060 Decision 2 (hold the verifier in-repo, extract a ReplayStore seam, record the edge-local exception) and ADR-059 D6 (wire replay protection on the write path).
---

# ADR-2006 — Single-source NIP-98 and expose a ReplayStore seam, not a cross-tier store

## Context

NIP-98 HTTP-signature auth is used by the core library, the git smart-HTTP
backend, and the IdP; an out-of-repo forum/CF edge tier needs the same nonce
semantics but keeps its own datastore. Two temptations existed: re-implement
the verifier per crate, or build a shared cross-tier replay store now against a
consumer that does not yet exist.

## Decision

Keep exactly one verifier in `auth/nip98.rs` (siblings delegate:
`solid-pod-rs-git/src/auth.rs:144,157`, `solid-pod-rs-idp/src/schnorr.rs`) and
factor replay protection behind `trait ReplayStore`
(`auth/replay_store.rs:68`), with the process-local `Nip98ReplayCache` as the
reference implementor (`auth/replay.rs`). Do not build the cross-tier store: the
seam lets a second tier depend on this crate's nonce contract without this crate
depending on that tier's storage. The replay cache is process-local by design —
it does not span replicas — so the deferral constrains deployment: any
multi-replica or cross-tier deployment must supply shared `ReplayStore` state
before relying on replay rejection, and no security claim may assume one shared
verification boundary.

## Consequences

- Forecloses re-implementing NIP-98 in a sibling — that is a regression, not an
  optimisation.
- The seam sits at `staged`: it is fully built but reaches integrated only when
  a second tier consumes the trait; until then the cross-tier guarantee is
  unexercised and must not be claimed.
- Process-local replay means a naive horizontal scale-out silently weakens
  replay protection; the burden is on the deployer to add shared state.
- Building the store speculatively was rejected to avoid claiming an integration
  no consumer exercises — the honest cost is an open seam across a repo boundary.

## Verification

- `auth/replay_store.rs:68` `trait ReplayStore: Send + Sync` with
  `check_and_record`; reference impl `Nip98ReplayCache` in `auth/replay.rs`.
- `solid-pod-rs-git/src/auth.rs:144,157` delegates to
  `solid_pod_rs::auth::nip98::verify_at_with_policy`; no sibling re-implements
  the verifier, confirmed at `e093e88`.
