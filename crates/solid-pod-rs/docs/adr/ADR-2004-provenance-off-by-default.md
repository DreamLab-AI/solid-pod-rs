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
