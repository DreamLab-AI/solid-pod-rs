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
