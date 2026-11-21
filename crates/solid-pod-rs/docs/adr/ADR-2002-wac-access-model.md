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

> Note 2026-11-21 (SP-PATCH-WRITE-REBASE, SP-PAR-276): a fixed-IRI-space design
> for the Write path of PATCH (read the stored body and the patch against a
> placeholder `https://patch-base.invalid/<path>`, write placeholder IRIs back
> as relative references, write JSON-LD back as JSON-LD) was attempted and
> withdrawn; PATCH is back at its previous behaviour (Host-derived base unless
> `public_base_url` is set; Turtle and N-Triples bodies only; `acl_targets_as_paths`
> for ACLs). Security review found four defects. (a) The stored body was read in
> the placeholder space while SPARQL patches are read with no base, so a client
> naming a triple by its real absolute URL matched nothing: an N3 patch got 409,
> but a SPARQL delete that matches nothing is ignored, so "replace value"
> returned 204 keeping the old triple and adding a duplicate, and a SPARQL
> `DELETE DATA` revoking an `acl:agent` returned 204 and left the grant. (b)
> Relativisation used `strip_prefix` on the origin string, so
> `https://patch-base.invalid.other.example/x`, `...invalid@h/x` and
> `...invalid:8443/x` became relative references, and literal datatypes were
> never relativised, leaking the placeholder host into stored data (the JSON-LD
> writer had the same flaw for `@type`). (c) An Append-only caller could append
> an absolute placeholder IRI that the owner's next Write PATCH rewrote into a
> same-pod reference. (d) With no origin configured a Turtle ACL's `<./a/>`
> (which denies) became `</a/>` (which grants) after any PATCH. Requirements a
> future design must meet: origin-equivalence when `public_base_url` is set; a
> loud refusal of an absolute-IRI delete that cannot match; relativisation by
> parsing URLs (origin compared as a whole), including literal datatypes; and a
> base no caller can name. The Write-path rebase onto a request `Host` when
> `public_base_url` is unset (SP-PATCH-WRITE-REBASE) and PATCH of JSON-LD and
> HTML-island bodies (SP-PAR-276) therefore remain open; setting
> `public_base_url` still closes the first for a deployment.

> Note 2026-11-21 (SP-PAR-276, second withdrawal): a later attempt, PATCH of stored JSON-LD and HTML data islands
> against the configured origin, was also withdrawn (commit 6d976fc reverted; PARITY row 276 is `missing` again;
> nothing of its `jsonld_patch.rs` was kept). Review found three defects. (1) The write-back emitted a bare
> top-level array with no `@context` and full-IRI keys, while `extract_oidc_issuer` and `extract_nostr_pubkey`
> (`webid.rs`, about line 207) read a top-level object, so any PATCH to a WebID profile card (stored as HTML with a
> JSON-LD island; SolidOS edits names this way) broke Solid-OIDC login and the Nostr binding; non-IRI keys were
> dropped and `@list` was flattened, all answering 204. (2) JSON-LD ACLs became patchable and a SPARQL
> `DELETE DATA` that matched nothing answered 204, so a revocation could report success and leave the grant. The
> claim that this matched JSS was wrong: JSS answers 409 "Triple to delete not found" for both dialects
> (`src/patch/quads.js`, about line 161 in the reference clone). (3) The island was located by string search, not
> by an HTML parser. Requirements for a future attempt: write-back preserves the stored document's shape
> (`@context`, compaction, a top-level object, `@list`), as JSS does; a delete that removes fewer triples than it
> names answers 409 in both dialects; the island is located with a
> real HTML parser and by the same locator the readers use (`webid.rs` and the conneg reader).

> Note 2026-11-21 (SP-PAR-265, SP-PAR-288): relative `acl:accessTo` / `acl:default`
> targets are read differently by the two ACL syntaxes while no pod origin
> (`public_base_url`) is configured. A JSON-LD ACL is expanded
> (`crates/solid-pod-rs/src/wac/jsonld_acl.rs`), which resolves `./a/` against
> the ACL's own path whatever the configuration; a Turtle ACL is read as written
> and leaves `./a/` unresolved, so it denies. Absolute IRIs deny in both, and
> with a configured origin (`wac::AclBase`) both resolve identically, an origin
> match being required for an absolute IRI. This is not a cross-origin leak
> (a relative reference can only name this pod); it is an inconsistency to close
> by resolving Turtle relative targets the same way or by requiring an origin.

> Note 2026-11-21 (SP-PAR-290, implemented as an opt-in): the container-ACL location is now a setting,
> `--acl-layout sidecar|inner|both`, default `sidecar` (unchanged behaviour); the four requirements above are met
> as follows. (a) `both` reads the sidecar first and falls back to the inner file only when the sidecar is
> absent, so a pod with two differing copies is read as it always was (the sidecar governs). (b) Nothing is honoured
> automatically: the default ignores inner files, and `--acl-layout-report` lists every inner ACL, both-form
> container (and whether they differ) and sidecar-only container for operator review before opting in. (c) The
> refusal to create beneath an ACL or meta document lives in `Storage::put` and `create_container` of the
> filesystem and memory backends (`wac::path_beneath_sidecar`), so HTTP, MCP and provisioning all pass it;
> DELETE beneath stays allowed for repair. A `git push` into a pod working tree writes files directly and does not
> pass `Storage`; it needs the git route's Write grant, not Control, so a pushed `.acl` is not covered by (c).
> (d) A directory at an ACL key reads as absent (`resolver::read_acl_key`); a read failure that is not a directory,
> such as a permission error, still denies. Under `inner` and `both`, writing the sidecar form of a container
> additionally requires Control on the container's inner form (`enforce_write_inner`), because that sidecar is, or
> can become, the live ACL. Tests: `crates/solid-pod-rs-server/tests/acl_layout_*.rs`.

> Note 2026-11-21: three open decisions recorded here, none changed by code.
> (1) SP-ACL-REVIEW-02, whether a Web-Ledger fee is for *admission* or for
> *successful service*. Today it is debited at admission
> (`charge_granted_payment`, `crates/solid-pod-rs-server/src/lib.rs`, called from
> `enforce_write_ctx` / `enforce_read_ctx`; `handlers/pay.rs`) before the handler
> runs, so a request that then fails is still charged. Options: keep (simple,
> never serves unpaid), refund on failure (needs an idempotent credit path and a
> hook on every handler exit), or debit after serving (can serve a request
> unpaid, reversing "never serve unpaid"). A product choice. (2)
> SP-APPEND-UNBOUNDED, the deployment policy for `acl:Append`: with no quota
> configured an Append-only agent can grow a resource without bound (only the
> 4 MiB RDF parse cap limits it, indirectly), and the per-resource lock is
> in-process. Options: require a quota when Append grants exist, or add a size
> cap for append-only writers. (3) SP-PAR-290, container ACL location: this server reads a container's ACL
> only at `<container>.acl` (`crates/solid-pod-rs/src/wac/resolver.rs`,
> `acl_sidecar_key`). A pod migrated from the reference JavaScript server's
> layout (`<container>/.acl`) MUST have its container ACLs moved to the sidecar
> location: an inner ACL is not read, so the container inherits its parent's
> access (verified 2026-11-21: with a public root ACL, a private `/docs/.acl`
> leaves `/docs/a.txt` readable). Reading both locations was implemented and
> withdrawn on 2026-11-21. The requirements a future change must meet: (a) pods
> provisioned by v0.5.0-alpha.10 to .22 hold both copies (`/_admin/provision`
> wrote the sidecar and an inner "courtesy" copy) and owners' edits touch only
> the sidecar, so those pods have differing pairs, and "both present and
> different" must not deny them on upgrade. (b) An inner ACL could be created
> without Control in early releases (Append via POST with a Slug before
> v0.5.0-alpha.4, Write via PUT before v0.4.0-alpha.16), so honouring existing
> inner files can grant access nobody with Control chose: a migration needs an
> operator-reviewed list of inner files, not an automatic read. (c) Nothing may
> be creatable beneath an ACL or meta document (`/docs/.acl/x`), including
> through the MCP tool paths; a request-path check in the HTTP middleware alone
> does not cover them. (d) A directory at an ACL key must not read as an error:
> this is a pre-existing lock-out, still OPEN, where an agent with Write on a
> parent can create `/docs.acl/x` (a directory at the sidecar key), after which
> the resolver's read of that key fails and everything under `/docs/` is
> unavailable with no HTTP repair (remove the directory on disk). Whether inner
> ACLs are honoured is an owner decision with risk on both sides.

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
