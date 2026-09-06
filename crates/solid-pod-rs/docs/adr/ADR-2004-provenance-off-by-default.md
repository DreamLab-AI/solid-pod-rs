---
id: ADR-2004
title: Keep git-mark provenance opt-in behind the git feature
date: 2026-08-31
decision_status: accepted
implementation_status: complete
activation_status: live
supersedes: []
superseded_by: []
verified_commit: e093e88
owner: jjohare
review_trigger: a deployment mandates always-on provenance, or a PRD proposes flipping the git default
repo: solid-pod-rs
domain: BASELINE-solid-pod-rs.md
lineage: Distils archived ADR-059 D1 (git-mark described as always-on, contradicted by its own capability caveat) and ADR-060 Decision 4 (hold the git default off this sprint, label the caveat, canary under --features git).
---

# ADR-2004 — Keep git-mark provenance opt-in behind the git feature

## Context

The provenance composition (`ProvenanceLog::record` — git-mark always, Bitcoin
anchor per policy) is fully built and wired into every LDP write. ADR-059
described the git-mark tier as "always-on", yet the server ships with an empty
default feature set, so a stock build records nothing. Flipping git on by
default would add build-size and per-write latency to every deployment.

## Decision

The `git` feature stays off in the default build; git-mark provenance is opt-in
via `--features git`. This is a live deferral, not a bug: `default = []`
(`solid-pod-rs-server/Cargo.toml:123`) means `git_mark_write` compiles to the
no-op shim `#[cfg(not(feature = "git"))]` (`lib.rs:3490`) and a default build
records zero marks; the real write path (`lib.rs:3317`, canonical composition at
`lib.rs:3400`) exists only under `--features git` (`lib.rs:3316`). The deferral
constrains current work: every provenance claim in docs, PRDs, or interfaces
must carry the `--features git` caveat, because the default build's behaviour is
"no provenance", and any REC-11 trace assertion is conditional on the feature.

## Consequences

- Forbids reading "provenance is on every write" without the feature caveat;
  an unqualified claim is a silent overclaim against a zero-mark default build.
- Downstream consumers must build the server with `git` to get any trace; a
  default `cargo build` gives them none.
- Keeps the stock binary small and write-latency low — the reason for the hold.
- Flipping the default later is a compatibility change that needs its own PRD
  and supersedes this record; it is not a config tweak.

## Verification

- `solid-pod-rs-server/Cargo.toml:123` `default = []`; `:150` defines the `git`
  feature.
- `lib.rs:3488-3490` no-op `git_mark_write` shim under
  `cfg(not(feature = "git"))`; `lib.rs:3316-3317` real impl under
  `cfg(feature = "git")`; canonical composition comment at `lib.rs:3400`,
  verified at `e093e88`.

## Closeout extension — 2026-09-04

Work packages: CP-04/08. Accountable owner: the existing owner above, with storage, identity and release maintainers for consumer acceptance. Historical status axes and verified commits are preserved; no deployment is re-certified.

The server still has default = [] and an opt-in git feature. Even with git enabled, resource storage succeeds before git marking and optional anchoring; the server can log a mark failure after a successful mutation.

**Acceptance condition:** Expose resource-stored, local-mark-committed and anchor-confirmed receipts separately. Test default and git builds, excluded paths, failed marking, interrupted anchoring and restoration with provenance reconciliation. The feature decision remains implemented; full provenance durability is a separate open contract.

Dependencies: CP-01 release identity and CP-04 effective authority. Reopen when the governed implementation, adapter, dependency, feature or deployment profile changes. See the [storage review](../../../../../VisionFlow/docs/estate-review/storage-and-authority.md) and [source revalidation](../../../../../VisionFlow/docs/estate-review/evidence/pod-closeout-snapshot.json). Scoped implementation status does not close these cross-service requirements.

## Acceptance progress — 2026-09-05

**Implemented.** The three provenance tiers are now distinct, inspectable
results rather than a single best-effort side effect.

The finding: the LDP write succeeded first, then `git_mark_write` ran and every
failure — no git binary, a commit error, an anchor error, a sidecar-write
error — was logged at `warn` and swallowed. The client received `201 Created`
whether or not any provenance existed, so "stored" and "stored and provably
marked" were indistinguishable from outside the process.

`crates/solid-pod-rs/src/provenance.rs` gained `ProvenanceStage`, an ordered
enum naming what a write actually achieved:

| Stage | Claim |
|---|---|
| `Skipped` | not eligible for marking; no provenance claimed or attempted |
| `ResourceStored` | bytes are in storage and nothing more — the mark was attempted and **failed** |
| `LocalMarkCommitted` | a local git commit records the write (rewritable by the repo's controller) |
| `AnchorSubmitted` | an anchoring transaction exists but is unconfirmed, so the timestamp is not yet final |
| `AnchorConfirmed` | the anchoring transaction is confirmed at a known height |

`AnchorSubmitted` was added deliberately: `BlockTrailAnchor::blockheight` is
`None` until the anchoring transaction confirms, and an unconfirmed
transaction can still be replaced, so reporting it as `anchor-confirmed` would
overstate the provenance.

`ProvenanceReceipt` carries the mark, the anchor, per-tier typed errors
(`mark_error`, `anchor_error`) and a `ProvenanceSkip` reason. `ProvenanceLog::record_receipt`
returns one instead of a `Result`: it never errors (the write has already
succeeded and provenance must not change its status) but reports each tier
separately. A failed anchor never suppresses a successful git-mark — the
receipt carries the mark **and** the anchor error.

`ProvenanceSkip` distinguishes the configurations where marking is correctly
not attempted (`NotConfigured`, `NotGitBacked`, `ExcludedPath`, `Container`,
`UnresolvablePath`) from actual faults, so an in-memory pod does not read as
broken. `has_failure()` is false for every skip.

**Surfaced to the caller.** `git_mark_write` in `solid-pod-rs-server` now
returns a `ProvenanceReceipt`, and PUT, POST and all three PATCH paths emit it
as `X-Provenance: <stage>[; skipped=…][; mark-error=…][; anchor-error=…]` plus
`X-Provenance-Commit: <sha>`. The status code is unchanged, preserving the
ADR's "a provenance failure must never change the write's response status"
contract — what changed is that the failure is no longer invisible. Error text
is flattened to bounded, printable US-ASCII so it is header-safe. The `git`-disabled
shim returns `Skipped { NotConfigured }` so call sites stay uniform.

**Tests + results.** `crates/solid-pod-rs/tests/provenance_receipts.rs`, 14
tests, all passing, driving the pure composition surface with stub
markers/anchorers (no git binary, no network), so they run on the **default**
build:

- *default build* — `default_build_reaches_local_mark_committed` asserts the
  git-mark-only pod reports `LocalMarkCommitted`, not an anchor, and that the
  cheap tier runs exactly once.
- *git build* — `a_confirmed_anchor_is_a_distinct_stronger_result`,
  `an_unconfirmed_anchor_is_not_reported_as_confirmed`,
  `high_value_anchors_only_when_flagged`,
  `the_anchor_is_not_attempted_when_the_policy_does_not_ask_for_it`
  (`Never`/`Epoch`/unflagged `HighValue`).
- *failed marking* — `a_failed_mark_is_surfaced_not_swallowed` (stage falls to
  `ResourceStored`, `mark_error` is populated and typed, summary starts
  `resource-stored; mark-error=`), `a_failed_anchor_never_suppresses_a_successful_mark`,
  `an_anchor_policy_with_no_anchorer_is_reported_not_silently_degraded` — the
  case the previous code degraded to git-mark-only "silently".
- *excluded paths* — `skipped_receipts_are_not_failures`,
  `excluded_control_plane_paths_have_their_own_skip_reason`.
- *header safety* — `the_summary_is_header_safe` (CR/LF, tabs, ANSI escapes
  and separators stripped) and `the_summary_is_bounded`.
- *serialisation* — `the_receipt_round_trips_through_json`, since the receipt
  is what a manifest or audit log stores.

The pre-existing git-backed integration test `solid-pod-rs-server/tests/git_marks.rs`
continues to pass unchanged. Full workspace: 1801 passed, 0 failed. Clippy
clean under `--all-features`.

**Receipts.** `../estate-closeout/2026-09-05/test-run.md`.

**Remaining.** (a) Ordering is unchanged: the resource write still commits to
storage *before* marking, so a crash between the two leaves a stored resource
with no mark. Making that atomic needs a staged write or a write-ahead
provenance journal, which is a storage-layer change beyond this ADR's scope —
the receipt now makes the window observable rather than closing it.
(b) `X-Provenance` is an unregistered, non-standard header; it is a local
convention, not an interop claim. (c) Deployed-tier verification — receipts
observed on a running git-backed pod, and the anchor-confirmed path against a
real chain — is not covered by these in-process tests.
(d) `activation_status` unchanged.

**Governed paths changed.** `crates/solid-pod-rs/src/provenance.rs`,
`crates/solid-pod-rs/src/lib.rs`, `crates/solid-pod-rs-server/src/lib.rs`.
New: `crates/solid-pod-rs/tests/provenance_receipts.rs`. `verified_commit`
unchanged.
