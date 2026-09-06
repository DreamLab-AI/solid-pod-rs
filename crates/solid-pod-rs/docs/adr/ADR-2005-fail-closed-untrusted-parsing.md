---
id: ADR-2005
title: Parse untrusted access-control input fail-closed and bounded
date: 2026-08-31
decision_status: accepted
implementation_status: complete
activation_status: live
supersedes: []
superseded_by: []
verified_commit: e093e88
owner: jjohare
review_trigger: any change to the ACL parser, the pod-label sanitiser, or the byte/depth caps on untrusted input
repo: solid-pod-rs
domain: BASELINE-solid-pod-rs.md
lineage: Distils archived ADR-058 rows 169-170 (safeJsonParse size-capped ACL parse, iterative dotdot sanitisation) from the JSS v0.0.60-v0.0.71 drift analysis, both listed there as open P0 gaps.
---

# ADR-2005 — Parse untrusted access-control input fail-closed and bounded

## Context

Two untrusted inputs reach security-critical parsers: externally-uploaded WAC
ACL bodies and client-supplied pod labels in subdomain mode. A lenient or
unbounded reading of either is exploitable — an oversize ACL is a parse-bomb
DoS, and a single-pass `..` strip is defeated by `....//` collapsing back into
a traversal after one removal.

## Decision

Both parsers fail closed against a defined bound rather than doing best-effort
recovery. ACL parsing rejects any body over `MAX_ACL_BYTES` (default 1 MiB,
`JSS_MAX_ACL_BYTES`) *before* serde runs, returning `PayloadTooLarge`
(`wac/parser.rs:40-45`, cap `wac/mod.rs:28`). Pod-label sanitisation scrubs `..`
with `scrub_dotdot`, an iterative loop that repeats until the string stops
shrinking (`multitenant.rs:181-198`), and the caller additionally refuses any
label with a residual `..` (`multitenant.rs:118`) rather than trusting one pass.
The choice is to reject on doubt, not to sanitise-and-continue.

## Consequences

- Forecloses lenient parsing: a legitimate but oversize ACL is rejected, not
  truncated or streamed; operators who need larger ACLs must raise the env cap
  consciously.
- Reverting `scrub_dotdot` to a single pass silently reopens the `....//`
  traversal bypass — the iterative loop is load-bearing, not cosmetic.
- Removing the byte cap reopens the parse-bomb DoS; the cap must stay at the
  parse boundary, ahead of serde, or the guarantee is void.
- Marginally more code and two failure modes callers must handle (413-equivalent
  and label rejection), accepted as the cost of a fail-closed boundary.

## Verification

- `wac/parser.rs:41-42` returns `PodError::PayloadTooLarge` when
  `input.len() > max_bytes`; cap `wac/mod.rs:28` = 1_048_576.
- `multitenant.rs:181-198` `scrub_dotdot` loops until fixed point;
  `multitenant.rs:118` rejects any surviving `..`, verified at `e093e88`.

## Closeout extension — 2026-09-04

**Work package:** CP-04, identity/authority/storage. **Accountable owner:** the
existing owner above; cross-tier work also needs the forum pod maintainer.

The complete implementation status above describes the parser bounds and
pod-label checks in this decision. It does **not** establish fail-closed ACL
resolution. The current `src/wac/resolver.rs` can skip malformed specific policy
or storage read errors and inherit a broader grant. A temporary-crate probe
using the actual resolver produced an allowed Read for a malformed
`/secret.acl` with a permissive root ACL. The edge resolver also treats failed
or invalid reads as misses. See the [estate evidence](../../../../../VisionFlow/docs/estate-review/storage-and-authority.md)
and [probe receipt](../../../../../VisionFlow/docs/estate-review/evidence/pod-probes.json).

**Remaining work:** define separate missing, invalid and unavailable policy
outcomes and carry them through native and edge handlers. Preserve legitimate
inheritance for missing policy; do not infer it from a failed restrictive-policy
read. Map the change to each consumer's resolved version and features (CP-01).

**Acceptance:** demonstrate valid missing-policy inheritance, denied invalid
specific policy despite a permissive ancestor, bounded oversized input,
backend read failure, and revocation with ancestor/legacy fallback. Record the
native and edge revisions and results. Current evidence verifies the gap; it
does not verify its repair or deployed activation. Re-review this ADR and the
baseline when those receipts are available.

## Acceptance progress — 2026-09-05

**Implemented.** Fail-closed ACL resolution now exists as a typed contract
rather than a single `Result<Option<_>, _>` that conflated absence with
failure.

`crates/solid-pod-rs/src/wac/resolver.rs` gained `PolicyOutcome` with four
terminal states and an explicit handling rule for each:

| Outcome | Meaning | Handling |
|---|---|---|
| `Missing` | no `.acl` at this level | **inherit** — the legitimate WAC §4.2 walk |
| `Found` | `.acl` present and parsed | evaluate it |
| `Invalid { policy_path, reason }` | `.acl` present, unparseable or over-bounds | **deny, never inherit** |
| `Unavailable { policy_path, detail }` | backend read failed | **deny, never inherit** |

`InvalidPolicyReason` separates `Malformed` / `TooLarge` / `TooDeep` /
`NotUtf8` so a parser bound firing is distinguishable from an authoring
mistake. The decisive change is that only `Missing` — a *fact* established by
the backend returning `NotFound` — permits the walk to ascend. Every other
non-success is an *unknown*, and an unknown can no longer be laundered into
the ancestor's grant.

`classify_policy_read` is the pure, runtime-free, single-level decision
function; it compiles on the `core` surface. `resolve_policy_from_storage` is
the native walk built on it, object-safe in its `&dyn Storage` argument.

**Duplicate resolver removed.** `solid-pod-rs-server` carried a second copy of
the walk (`find_effective_acl_dyn`) which had drifted — it lacked even the
`PayloadTooLarge` arm the native one had. Both now delegate to the single core
implementation, so the two paths cannot diverge again. `enforce_read_ctx` and
`enforce_write_ctx` resolve via `resolve_policy_dyn` and deny on a failure
outcome: `Invalid` → 403 (the operator's own policy is unreadable, so nothing
is granted), `Unavailable` → 503 (retryable, and not mistakable for a
deliberate denial). Both are logged with the offending policy path.

`find_effective_acl` is retained and still fail-closed: `PolicyOutcome::into_result`
maps `Invalid`/`Unavailable` to `Err`, preserving the existing 413/400 statuses
for the bound violations. The `AclResolver` trait gained `resolve_policy` as a
**provided** method defaulting to `PolicyOutcome::from_legacy`, so an
out-of-repo implementor that supplies only `find_effective_acl` keeps compiling
and still reports fail-closed outcomes.

**Tests + results.** `crates/solid-pod-rs/tests/wac_policy_outcomes.rs`, 20
tests, all passing — one per acceptance item plus the classifier surface:

1. *valid missing-policy inheritance* — `missing_specific_policy_inherits_from_the_ancestor`,
   `no_policy_anywhere_is_missing_not_a_failure`, `a_direct_policy_is_not_tagged_inherited`.
2. *denied invalid specific policy despite a permissive ancestor* —
   `malformed_specific_policy_denies_and_never_inherits` reproduces the probe
   shape exactly (malformed `/secret.acl` under a permissive root ACL) and
   asserts `Invalid`, `!may_inherit()`, `document().is_none()`;
   `non_utf8_policy_denies_and_never_inherits`,
   `an_invalid_ancestor_policy_also_stops_the_walk`.
3. *bounded oversized input* — `oversized_policy_is_invalid_not_inherited`
   (>`MAX_ACL_BYTES` → `TooLarge` → HTTP 413),
   `depth_bombed_policy_is_invalid_not_inherited` (>`MAX_ACL_JSON_DEPTH` →
   `TooDeep` → HTTP 400).
4. *backend read failure* — `backend_read_failure_is_unavailable_not_a_miss`
   and `a_failing_ancestor_read_also_denies`, driven through a `FaultyBackend`
   that returns `PodError::Backend` (deliberately **not** `NotFound`) for a
   named key.
5. *revocation with ancestor / legacy fallback* —
   `revoking_a_specific_policy_falls_back_to_the_ancestor` (deleting the child
   `.acl` legitimately restores the ancestor default),
   `revocation_to_no_policy_at_all_denies_by_default`,
   `legacy_find_effective_acl_stays_fail_closed`,
   `trait_default_resolve_policy_adapts_a_legacy_implementor`.

Full workspace: 1801 passed, 0 failed, across 114 binaries.
`cargo clippy --all-targets --all-features -- -D warnings` clean.
`cargo check --no-default-features --features core` clean (the edge surface).

**Receipts.** `../estate-closeout/2026-09-05/test-run.md`.

**Residual behaviour worth recording.** `parse_turtle_acl` is lenient: a body
that *looks* like Turtle but does not parse yields `Ok` with no
authorisations rather than an error. The security property still holds — the
walk terminates at that level (`Found`, `inherited == false`) and the empty
document grants nothing, so the permissive ancestor is never reached, which
`broken_turtle_policy_denies_and_never_inherits` asserts for both a named and
an arbitrary agent. The cost is diagnostic, not authorisation: a corrupt
Turtle ACL reads as a deliberate deny-all and is not reported as a fault.
Tightening this means distinguishing "parsed to nothing" from "deliberately
empty", which would change behaviour for a legitimately empty deny-all ACL;
it is deferred rather than guessed at.

**Remaining.** (a) The edge/WASM resolver is **not in this repository** — it
lives in `nostr-rust-forum` (`crates/nostr-bbs-pod-worker/src/acl.rs`), which
pins `solid-pod-rs =0.5.0-alpha.7, default-features = false, features =
["core"]`. The typed outcomes and `classify_policy_read` are deliberately
`core`-compilable so that tier can adopt them without a runtime dependency,
but doing so requires a published version it can pin; no version was bumped
here. Until then the edge tier still treats failed or invalid reads as misses,
and the cross-tier claim stays open. (b) Deployed-tier checks — denial
observed through the real cache and across a restart — are not covered by
these in-process tests. (c) `activation_status` is unchanged: this evidence
verifies the repair in-repo, not its deployed activation.

**Governed paths changed.** `crates/solid-pod-rs/src/wac/resolver.rs`,
`crates/solid-pod-rs/src/wac/mod.rs`, `crates/solid-pod-rs/src/lib.rs`,
`crates/solid-pod-rs-server/src/lib.rs`. New:
`crates/solid-pod-rs/tests/wac_policy_outcomes.rs`. `verified_commit`
unchanged (this work is uncommitted).
