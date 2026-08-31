---
id: ADR-2002
title: Ground access control on Web Access Control, not ACP
date: 2026-08-31
decision_status: accepted
implementation_status: complete
activation_status: live
supersedes: []
superseded_by: []
verified_commit: e093e88
owner: jjohare
review_trigger: a consumer or Solid interop target that requires ACP policy graphs, or a WAC-2.0 spec revision
repo: solid-pod-rs
domain: BASELINE-solid-pod-rs.md
lineage: No dedicated legacy record; distils the implicit access-model substrate that ADR-058 (WAC ACL parser hardening) and ADR-059 D6 (WAC-gate the git routes) both build on and never state as a choice.
---

# ADR-2002 — Ground access control on Web Access Control, not ACP

## Context

Solid specifies two mutually-exclusive authorisation systems: Web Access
Control (WAC, `acl:` triples per resource) and Access Control Policy (ACP,
a policy/matcher graph under `acp:`). A pod must pick one; a resource server
cannot half-honour both without ambiguous evaluation. The crate wires its
authorisation decision entirely through a WAC evaluator, extended with the
non-standard "WAC 2.0" client/issuer/payment condition gates.

## Decision

Access control is WAC and only WAC. The evaluator lives in `wac/` and reads
`http://www.w3.org/ns/auth/acl#` documents (`wac/mod.rs:1`, mode mapping at
`wac/mod.rs:167`); local extensions add client, issuer and payment condition
gates (`wac/conditions.rs`, `wac/payment.rs`) as *additional* WAC constraints,
never an ACP policy graph. No `acp:` vocabulary, matcher, or policy resolver
is implemented anywhere in the workspace. Any new access rule is expressed as
a WAC authorisation or a WAC 2.0 condition, not an ACP policy.

## Consequences

- Forecloses ACP: pods authored against ACP-only clients (some CSS
  deployments) are not interoperable here without a new evaluator; that is
  accepted, not a defect.
- The condition extensions are a private dialect — an interop partner must
  understand the WAC 2.0 client/issuer/payment predicates, which are not in the
  ratified WAC spec.
- Keeps one evaluation path, so `enforce_read`/`enforce_write` have a single
  semantics to audit; a second (ACP) path would double the authorisation
  attack surface.
- Locks the crate to WAC's per-resource-ACL inheritance model; pod-wide policy
  changes mean touching ACL documents, not one policy graph.

## Verification

- `wac/mod.rs:1` header declares a Web Access Control evaluator; `wac/mod.rs:167`
  maps `acl:Read`/`acl:Write` modes.
- `grep -rin "ns/solid/acp\|AccessControlPolicy\|acp#" crates/ --include=*.rs`
  returns nothing at `e093e88` — no ACP implementation exists.
- Condition gates present: `wac/conditions.rs`, `wac/client.rs`,
  `wac/issuer.rs`, `wac/payment.rs`.
