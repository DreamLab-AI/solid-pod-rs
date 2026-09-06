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

## Closeout extension — 2026-09-04

Work packages: CP-04/08. Accountable owner: the existing owner above, with storage, identity and release maintainers for consumer acceptance. Historical status axes and verified commits are preserved; no deployment is re-certified.

The WAC choice is retained. Parser rejection, effective ACL resolution and delivery caching are different contracts: prior local probes show malformed child policy can fall through to a permissive ancestor, while the forum edge advertises successful private responses as publicly cacheable.

**Acceptance condition:** Exercise missing versus malformed policy, inheritance, sidecar control, delegation and grant removal on each consumed version. Verify denial through caches and restart. Preserve the deliberate private condition dialect; this review does not assess current external standards conformance.

Dependencies: CP-01 release identity and CP-04 effective authority. Reopen when the governed implementation, adapter, dependency, feature or deployment profile changes. See the [storage review](../../../../../VisionFlow/docs/estate-review/storage-and-authority.md) and [source revalidation](../../../../../VisionFlow/docs/estate-review/evidence/pod-closeout-snapshot.json). Scoped implementation status does not close these cross-service requirements.

## Acceptance progress — 2026-09-05

**Implemented.** Delivery caching is now keyed on the response's *audience*
rather than its media type.

The finding: `cache_control_for` decided the header from `content_type` alone.
RDF variants got `private, no-cache, must-revalidate`; everything else — a
private JPEG, a PDF, an octet-stream in an authenticated container — went out
with **no `Cache-Control` header at all**. Under RFC 9111 §4.2.2 a response
carrying no explicit freshness information may be cached heuristically, and
with no `private` directive a *shared* cache is free to store it and re-serve
it to a different user. A private response was therefore advertised as
publicly cacheable.

`crates/solid-pod-rs/src/ldp.rs` gained `ResponseAudience` (`Public` /
`Private`), `CACHE_CONTROL_PRIVATE = "private, no-store"`, and
`cache_control_for_response(content_type, audience)`. A private response
always yields a value, so a caller emitting `Some(v)` cannot accidentally
leave one unmarked. `private` forbids a shared cache from storing it;
`no-store` forbids any cache from writing it to disk — applied together
because a pod's private resources are exactly the class of data that must not
survive in an intermediary. `cache_control_for` is retained with its
limitation documented in place.

**Implemented at the server layer.** `enforce_read_ctx` now returns the
audience it computed while it already held the resolved ACL: it re-evaluates
the *same* document with `web_id: None` to answer "could an anonymous client
have received this body?". This is pure and adds no I/O. A sidecar read
(elevated to `Control`) is forced `Private` regardless of what the ACL says,
since it discloses the whole authorisation graph; a payment-gated read fails
the anonymous evaluation for want of a balance and so classifies correctly
too. `handle_get` applies the policy on every response branch — index.html
negotiation, the RDF container listing, both mashlib wrappers, the RDF
content-negotiation branch and the verbatim body — and adds
`Vary: Authorization` on private responses so a cache keyed on the request
cannot fuse an authenticated body with the anonymous denial for the same URL.
`set_cache_policy` never overwrites a `Cache-Control` a handler set
deliberately.

The fix is deliberately not "mark everything private": an authenticated read
of a world-readable resource stays `Public`, because an anonymous client would
have received identical bytes. Being conservative there would have been a
caching regression dressed up as a security fix.

**Tests + results.** `crates/solid-pod-rs-server/tests/cache_control_policy.rs`,
10 tests, all passing, driven end-to-end through `build_app` +
`actix_web::test` with NIP-98-authenticated requests against an in-memory pod
seeded with a public and a private tree:

- *the finding* — `private_binary_response_is_not_publicly_cacheable` (the
  exact response that previously carried no header at all) and
  `private_pdf_response_is_not_publicly_cacheable`.
- *RDF strengthened* — `private_rdf_response_is_no_store_not_merely_no_cache`:
  the old RDF policy forbade re-use without revalidation but still permitted
  storage.
- *cache keying* — `private_responses_vary_on_authorization`.
- *no caching regression* — `public_rdf_keeps_the_rdf_policy`,
  `public_binary_is_left_to_ordinary_caching`,
  `an_authenticated_read_of_a_public_resource_stays_public`.
- *containers and sidecars* — `a_private_container_listing_is_not_publicly_cacheable`
  (the listing discloses child names, so it is as sensitive as the bodies),
  `an_acl_sidecar_read_is_always_private`.
- *the policy function* — `the_policy_function_never_leaves_a_private_response_unmarked`
  across seven media types including the empty string.

Full workspace: 1801 passed, 0 failed. Clippy clean.

**Receipts.** `../estate-closeout/2026-09-05/test-run.md`.

**Note on the WAC decision itself.** Unchanged and unaffected: no ACP
implementation was added, and `grep -rin "ns/solid/acp\|AccessControlPolicy\|acp#"
crates/ --include=*.rs` still returns nothing. The missing-versus-malformed
policy half of this ADR's acceptance condition is discharged under
[ADR-2005](ADR-2005-fail-closed-untrusted-parsing.md), whose typed
`PolicyOutcome` this crate's read path now consumes.

**Remaining.** (a) The **forum edge** is where the "private responses
advertised as publicly cacheable" finding was originally observed, and it is
not in this repository — it lives in `nostr-rust-forum`
(`crates/nostr-bbs-pod-worker`), which pins
`solid-pod-rs =0.5.0-alpha.7, features = ["core"]`. `ResponseAudience` and
`cache_control_for_response` are `core`-compilable so that tier can adopt the
same policy, but doing so needs a published version to pin; no version was
bumped here. The edge finding therefore stays open. (b) Verification *through
a real cache* and *across a restart*, as the closeout condition asks, is a
deployed-tier check these in-process tests do not perform. (c) Delegation and
grant-removal scenarios on each consumed version remain a cross-service
(CP-01) requirement. (d) `activation_status` unchanged.

**Governed paths changed.** `crates/solid-pod-rs/src/ldp.rs`,
`crates/solid-pod-rs/src/lib.rs`, `crates/solid-pod-rs-server/src/lib.rs`.
New: `crates/solid-pod-rs-server/tests/cache_control_policy.rs`.
`verified_commit` unchanged.
