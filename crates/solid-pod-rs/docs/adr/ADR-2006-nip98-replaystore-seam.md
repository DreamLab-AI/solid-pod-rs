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

## Closeout extension — 2026-09-04

Work packages: CP-04/08. Accountable owner: the existing owner above, with storage, identity and release maintainers for consumer acceptance. Historical status axes and verified commits are preserved; no deployment is re-certified.

The ReplayStore interface exists, but the reference bounded LRU can evict an unexpired entry. A prior isolated capacity-one probe accepts the original event again within the replay window after eviction. Sharing one process or trait does not guarantee full-window retention, restart persistence or cross-replica rejection.

**Acceptance condition:** Specify capacity/overflow policy relative to the replay window and use a backend with atomic check-and-record. Test capacity pressure, concurrency, expiry, restart and multi-replica reuse on each deployed adapter. The forum D1 adapter is a distinct source path; its existence does not prove this trait is consumed there.

Dependencies: CP-01 release identity and CP-04 effective authority. Reopen when the governed implementation, adapter, dependency, feature or deployment profile changes. See the [storage review](../../../../../VisionFlow/docs/estate-review/storage-and-authority.md) and [source revalidation](../../../../../VisionFlow/docs/estate-review/evidence/pod-closeout-snapshot.json). Scoped implementation status does not close these cross-service requirements.

## Acceptance progress — 2026-09-05

**Implemented.** The reference `ReplayStore` no longer trades replay
protection for capacity.

The finding: `Nip98ReplayCache::check_and_record` inserted through
`LruCache::put`, which evicts the least-recently-used entry when full — an
entry still inside its TTL. A capacity-one probe therefore accepted the
original event again within the replay window. The old test
`capacity_eviction_is_bounded` asserted exactly that behaviour as intended,
describing it as "the documented capacity-driven replay window"; it was in
fact a hole in the guarantee the store exists to provide.

`crates/solid-pod-rs/src/auth/replay.rs` now, on a new id at capacity:

1. reclaims entries that have genuinely **expired** — an expired id is no
   longer replayable, since the NIP-98 freshness check rejects the token
   regardless, so forgetting it costs nothing; and
2. if every live entry is still unexpired, returns the new
   `ReplayError::CapacityExhausted { capacity, ttl }` and refuses the
   credential.

**An unexpired entry is never evicted.** Re-presenting a previously seen id
whose entry has expired reuses that entry's own slot, so it can never be
refused for capacity. `evict_expired` and the capacity path now share one
`reclaim_expired` helper, so they cannot disagree about what is reclaimable.

The trade-off is stated in the module docs rather than left implicit: an
attacker offering unique ids faster than the TTL drains them can push the
cache to capacity and cause legitimate requests to be refused. That is an
availability failure, which is recoverable; accepting a replayed credential is
an authentication failure, which is not. `sizing_floor(peak_rps, ttl)` =
`ceil(peak_rps × ttl)` was added so an operator can size the cache such that
the refusal path stays a safety net; the shipped defaults (10 000 entries at
120 s) cover ~83 rps, which the test asserts rather than merely claims.

**Contract tightened on the seam.** `crates/solid-pod-rs/src/auth/replay_store.rs`
now states three requirements on `check_and_record` — atomicity (one
indivisible check-and-record, so concurrent calls for the same id yield
exactly one `Ok`), never accepting a replay inside the window to stay under
capacity, and no expiry refresh on rejection — plus explicit restart
semantics. `ReplayError` is `#[non_exhaustive]` so a future store can add a
refusal mode without breaking downstream matches.

**Tests + results.** `crates/solid-pod-rs/src/auth/replay.rs` unit tests, 13
passing:

- *capacity pressure* — `capacity_pressure_refuses_new_ids_and_never_evicts_unexpired`
  (a third id at capacity two is refused; both original ids are still
  rejected as replays) and `capacity_one_cannot_be_made_to_accept_a_replay`,
  which is the reproduced probe: capacity one, 64 filler ids, and the original
  event is *still* rejected. Under the previous policy it was accepted.
- *concurrency* — `concurrent_first_sightings_admit_exactly_one` (32 tasks
  race the same id; exactly one `Ok`, proving the check and record are
  atomic) and `concurrent_distinct_ids_never_exceed_capacity` (64 tasks, 8
  slots → exactly 8 admitted, 56 refused, length never overshoots).
- *expiry* — `expired_entries_are_reclaimed_to_admit_a_new_id`,
  `re_presenting_an_expired_id_reuses_its_slot_at_capacity`,
  `evict_expired_frees_the_store_for_reuse`, plus the retained
  `expired_entry_treated_as_fresh`.
- *restart semantics* — `restart_semantics_reopen_the_window` pins the
  documented tier limit as a test so process-local storage cannot be mistaken
  for durability.
- *sizing* — `sizing_floor_covers_the_offered_rate`.

Full workspace: 1801 passed, 0 failed. Clippy clean.

**Receipts.** `../estate-closeout/2026-09-05/test-run.md`.

**Compatibility.** `ReplayError` gained a variant. It is `#[non_exhaustive]`
from this change onward, and `nip98-replay` is not part of the `core` feature
set that `nostr-rust-forum` consumes (it pins
`solid-pod-rs =0.5.0-alpha.7, features = ["core"]`), so no in-estate consumer
is affected. Any future out-of-repo implementor must handle
`CapacityExhausted` as an authentication failure. No version was bumped.

**Remaining.** The seam stays `standalone`, not `integrated`: only one tier
implements `ReplayStore` in this repository. The out-of-repo forum/CF tier —
the documented edge-local exception — keeps its own datastore and has not been
wired to the trait, so the per-replica and restart replay windows still hold
and no cross-ecosystem claim may assume one shared verification boundary.
Deployed-tier verification (capacity behaviour observed on a running pod under
load) is not covered by these in-process tests.

**Governed paths changed.** `crates/solid-pod-rs/src/auth/replay.rs`,
`crates/solid-pod-rs/src/auth/replay_store.rs`. `verified_commit` unchanged.
