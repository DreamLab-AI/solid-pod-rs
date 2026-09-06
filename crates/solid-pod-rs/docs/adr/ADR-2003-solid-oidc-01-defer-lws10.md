---
id: ADR-2003
title: Hold the OIDC wire at Solid-OIDC 0.1 and defer the LWS10 delta
date: 2026-08-31
decision_status: accepted
implementation_status: complete
activation_status: live
supersedes: []
superseded_by: []
verified_commit: e093e88
owner: jjohare
review_trigger: LWS10 leaves FPWD for a stable Recommendation, or a client requires cnf.webid / PAR / EdDSA discovery
repo: solid-pod-rs
domain: BASELINE-solid-pod-rs.md
lineage: Distils archived ADR-057 (LWS10 OIDC delta, ten port tickets, partial-parity), whose P1 low-cost items were enumerated as negligible-cost yet deliberately never landed.
---

# ADR-2003 — Hold the OIDC wire at Solid-OIDC 0.1 and defer the LWS10 delta

## Context

The Solid OIDC profile is mid-migration from Solid-OIDC 0.1 to the W3C LWS10
draft (FPWD 2026-04-23). Archived ADR-057 enumerated the ten-ticket delta and
flagged four of them (EdDSA in discovery, `lws_supported`, `cnf.webid`, the
`iss` response flag) as negligible-cost P1 work. None shipped. The crypto path
already accepts EdDSA tokens; the wire metadata does not advertise it.

## Decision

The published OIDC surface stays Solid-OIDC 0.1 and the LWS10 delta stays
deferred — not because it is hard, but as a deliberate hold against a draft
still at FPWD. Discovery advertises `dpop_signing_alg_values_supported:
["ES256","RS256"]` and `solid_oidc_supported`, with no `lws_supported`,
no EdDSA, no `authorization_response_iss_parameter_supported`
(`oidc/mod.rs:184-185`); `extract_webid` reads only top-level `webid` and a
URL-shaped `sub`, with no `cnf.webid` branch (`oidc/mod.rs:864`). The deferral
constrains present work: OIDC changes must land on the 0.1 wire, and the
discovery/verifier lockstep invariant governs any alg change — the verifier
accepts EdDSA (`oidc/mod.rs:549,765`) but discovery must not advertise it until
they move together.

## Consequences

- LWS10-only clients (PAR-mandatory, `cnf.webid` identity, EdDSA-required) do
  not interoperate; that is chosen, not missing.
- The verifier-advertises-EdDSA-but-discovery-omits-it asymmetry is a standing
  wart the deferral keeps alive; it is safe only while discovery stays the
  narrower set.
- Deferring avoids chasing a moving FPWD whose fields may change before REC;
  the cost is a visible parity gap in the discovery document.
- Cheap P1 items being *available* but unshipped means any future "we did the
  cheap LWS10 wins" claim is false until this ADR is superseded.

## Verification

- `oidc/mod.rs:184` discovery emits ES256/RS256 only; `:185` emits
  `solid_oidc_supported`, no `lws_supported`.
- `oidc/mod.rs:864` `extract_webid` has no `cnf.webid` branch.
- `oidc/mod.rs:549,765` verifier dispatches `Algorithm::EdDSA` — proving the
  gap is wire-only, established at `e093e88`.

## Closeout extension — 2026-09-04

Work packages: CP-01/04/08. Accountable owner: the existing owner above, with storage, identity and release maintainers for consumer acceptance. Historical status axes and verified commits are preserved; no deployment is re-certified.

Current source discovery advertises ES256/RS256 and extract_webid reads the top-level webid or URL-shaped sub. The older standard-maturity statements in this record are historical context, not a newly checked standards status.

**Acceptance condition:** Keep a versioned discovery/verifier/client compatibility matrix. Test advertised algorithms, unsupported identity shapes, issuer/audience and token binding on the selected profile. A future profile change requires an explicit decision and interop receipts; this documentation pass neither adopts it nor certifies deployed OIDC interoperability.

Dependencies: CP-01 release identity and CP-04 effective authority. Reopen when the governed implementation, adapter, dependency, feature or deployment profile changes. See the [storage review](../../../../../VisionFlow/docs/estate-review/storage-and-authority.md) and [source revalidation](../../../../../VisionFlow/docs/estate-review/evidence/pod-closeout-snapshot.json). Scoped implementation status does not close these cross-service requirements.

## Acceptance progress — 2026-09-05

**Implemented.** The discovery/verifier claims are no longer source
observations: they are a versioned matrix in docs, pinned by executable tests.

New: [`../reference/solid-oidc-compatibility-matrix.md`](../reference/solid-oidc-compatibility-matrix.md),
headed with the crate version it describes (`0.5.0-alpha.8`, cited from
`[workspace.package] version`; not modified). It carries a spec-version matrix
(Solid-OIDC 0.1, OIDC Core 1.0, RFC 6749, 7662, 7591, 9449, 7638, 7517, 7519,
and the WebID-OIDC predecessor) stating per row what is implemented, what is
deliberately not, and the module and function that carries it; a discovery
matrix over every field `discovery_for` emits; a verifier matrix for access
tokens and DPoP proofs separately; a list of unsupported identity shapes with
the exact `PodError` each returns; and a *Deferred: LWS-10* section restating
the defer and declaring the matrix the compatibility contract until it is
lifted. Where the code's behaviour differs from what the specification — or
this ADR's own prose — would lead a reader to expect, the doc records the
**actual** behaviour and marks it.

New: `crates/solid-pod-rs/tests/oidc_compat_matrix.rs`, 28 tests, all passing,
gated `#![cfg(feature = "oidc")]` with the DPoP module additionally behind
`dpop-replay-cache`. No new dependencies, no network. Coverage: discovery
field set and issuer normalisation (`a1` compares the serialised document
against the doc's own table, so the doc cannot silently drift); issuer
validation including near-misses (trailing slash, case, the
`https://op.example.evil` prefix attack); audience behaviour; unsupported
identity shapes; expiry including the boundary and its ordering against the
`cnf` check; and the DPoP ⇄ access-token binding stitch.

Verified: `cargo test -p solid-pod-rs --test oidc_compat_matrix` — 28 passed,
0 failed, under default features, `--features oidc`, and
`--features oidc,dpop-replay-cache,jss-v04`. Full workspace 1801 passed, 0
failed. Clippy clean.

**Receipts.** `../estate-closeout/2026-09-05/test-run.md`.

**Findings — where the code diverges from this ADR's implied claims.** These
are now documented and pinned rather than latent:

1. **Audience is not validated at all.** `verify_access_token` sets
   `validate_aud = false` and takes no expected-audience argument, so any
   `aud` verifies — another pod's URL, `[]`, `12345`, `null`. The only thing
   enforced is *presence*: `SolidOidcClaims::aud` has no `#[serde(default)]`,
   so a token omitting `aud` fails deserialisation. Both halves are pinned
   (`c1`, `c2`) and the verifier matrix records this as a **gap, not a
   feature**. A deployment needing audience restriction must enforce it above
   this API. This is the most consequential item on the list.
2. **A malformed `webid` claim is silently ignored rather than rejected.**
   `extract_webid` skips a `webid` failing the `http(s)` prefix test and falls
   through to `sub`, so `webid: ""` / `"not-a-url"` / `"did:web:…"` with a
   URL-shaped `sub` all succeed, returning the `sub`. A client sending a broken
   `webid` gets a silent substitution, not a 401 (`d2`).
3. **Issuer comparison is raw string equality while `discovery_for`
   normalises.** `discovery_for("https://op.example/")` yields
   `https://op.example`, but a token with `iss: "https://op.example"` fails
   against `expected_issuer = "https://op.example/"`. The two halves of the
   crate disagree on canonical form; the safe wiring (normalise once through
   `discovery_for(...).issuer`) is documented and pinned (`b3`).
4. **The access-token `alg` allowlist is narrower than the DPoP allowlist** —
   DPoP accepts nine asymmetric algorithms, access tokens only RS256/ES256/
   EdDSA (`d10`).
5. **`htu` comparison lower-cases the whole URL including the path**, so
   `/Foo` and `/foo` compare equal — looser than RFC 3986 (`g2`).
6. **RFC 9449 §8 DPoP nonce is entirely absent** — no issuance, no `nonce`
   claim read. Now on the contract.
7. **`cnf.jkt` is compared with a plain `!=`**, not constant-time, whereas
   `ath` deliberately is. The thumbprint is not secret, so this is defensible,
   but the inconsistency is recorded.
8. **`discovery_for` performs no URL validation** — it is a pure string
   builder, so the "absolute URL" guarantee holds only if the caller passes an
   absolute issuer (`a1`/`a2`).

**Remaining.** (a) The defer of LWS-10 stands; nothing here lifts it.
(b) Findings 1–3 are *documented and pinned*, not *fixed* — fixing them
changes verifier behaviour for existing consumers and needs its own decision
about audience policy and whether a malformed `webid` should hard-fail. They
are the natural next ADR. (c) The matrix should be linked from
`crates/solid-pod-rs/docs/README.md`'s reference index, which was outside the
change's scope. (d) Deployed-tier verification against a real external OIDC
issuer is not covered. (e) `implementation_status` and `activation_status`
unchanged: this work adds a verified compatibility contract and executable
checks, it does not alter the OIDC wire.

**Governed paths changed.** New only:
`crates/solid-pod-rs/docs/reference/solid-oidc-compatibility-matrix.md`,
`crates/solid-pod-rs/tests/oidc_compat_matrix.rs`. No source file under
`crates/solid-pod-rs/src/oidc/` was modified. `verified_commit` unchanged.
