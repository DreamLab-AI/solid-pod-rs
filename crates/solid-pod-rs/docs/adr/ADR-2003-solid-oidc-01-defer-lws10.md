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
