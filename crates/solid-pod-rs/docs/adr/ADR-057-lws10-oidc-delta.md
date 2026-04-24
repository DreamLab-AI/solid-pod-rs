# ADR-057 — LWS10 OIDC Delta (Sprint 11 row 150)

**Status:** partial-parity (action items open)
**Date:** 2026-04-24
**Sprint:** 11 — JSS parity close
**Reference docs:**
- W3C *Linked Web Storage — Authorization with OIDC* FPWD, 2026-04-23
  <https://www.w3.org/TR/2026/FPWD-lws-auth-oidc-20260423/>
- JSS parity tracker issue #319 (box 1 — LWS10 OIDC profile) — unchecked
- Current impl: `crates/solid-pod-rs/src/oidc/mod.rs`, `crates/solid-pod-rs/src/oidc/jwks.rs`

## 1. Context

The Solid community is moving its OIDC profile from the legacy
`solidproject.org/TR/solid-oidc` draft into a W3C Recommendation track
document — *LWS10 Authorization with OIDC* — whose First Public Working
Draft dropped on 2026-04-23. The new draft re-frames the profile to
align with:

- **OAuth 2.1** (RFC 9700, draft) baseline: authorisation code only, PKCE
  mandatory, no implicit / hybrid flows, refresh-token rotation.
- **DPoP** (RFC 9449, published) as the single access-token proof
  mechanism. The legacy "Bearer without DPoP" carve-out for trusted
  clients is dropped.
- **JWT-Secured Authorization Request / Response** (RFC 9101) for PAR.
- **CID / DID** (W3C Controlled Identifier Document 1.0) as the identity
  data-model substrate, superseding the older "WebID bag of triples"
  reading.

solid-pod-rs currently implements the Solid-OIDC 0.1 profile in
`src/oidc/mod.rs`:

- Dynamic client registration (RFC 7591 §2).
- Discovery document (`/.well-known/openid-configuration`) with Solid
  extensions (`solid_oidc_supported`, `dpop_signing_alg_values_supported`).
- DPoP proof verification with the RFC 9449 §4.3 `ath` binding
  (`verify_dpop_proof_with_ath`).
- jti-replay cache (`dpop-replay-cache` feature, Sprint 4 row F5).
- Access-token verification with `cnf.jkt` ↔ DPoP thumbprint match,
  alg-confusion defences (Sprint 5 P0-1), and explicit `kid` resolution
  against a rotating JwkSet.
- SSRF-guarded JWKS + discovery fetch (`oidc::jwks`, Sprint 5 P0-2).
- Token introspection (RFC 7662 §2).

This ADR enumerates the delta between that implementation and LWS10
FPWD so we can close JSS #319 box 1 with a concrete port plan. The work
is split into three sections:

- **A** — fields we emit that LWS10 does not require (keep them for
  back-compat).
- **B** — fields LWS10 requires that we do not emit (port tickets).
- **C** — semantic differences where both drafts are legal but differ.

A final action-item list closes the ADR.

## 2. Current implementation surface

```text
crates/solid-pod-rs/src/oidc/mod.rs
├── register_client               — RFC 7591 §2
├── discovery_for                 — /.well-known/openid-configuration
├── Jwk + Jwk::thumbprint         — RFC 7638 (EC / RSA / OKP / oct)
├── verify_dpop_proof             — RFC 9449 §4 base path
├── verify_dpop_proof_with_ath    — RFC 9449 §4.3 ath binding
├── verify_access_token           — DPoP-bound JWT, ES256/RS256/EdDSA
├── extract_webid                 — `webid` claim OR URL-shaped `sub`
├── TokenVerifyKey                — Symmetric (test) | Asymmetric (prod)
└── IntrospectionResponse         — RFC 7662 §2.2
```

Feature flags: `oidc` (base), `dpop-replay-cache` (jti replay).

## 3. Section A — fields we emit that LWS10 does not require

These are emitted for backward compatibility with existing NSS / CSS
clients. LWS10 does not require them. Keep; no action.

### A.1 Legacy `application_type` parameter (registration request)

Our `ClientRegistrationRequest` accepts `application_type` (Solid-OIDC
§5.1). LWS10 drops the parameter — a client is identified as a public
app by publishing a *Client ID Document* at a dereferenceable IRI
(LWS10 §4.2), not by a registration-time flag.

**Status:** keep, marked legacy.

### A.2 `solid_oidc_supported` discovery metadata

Our discovery document advertises `solid_oidc_supported:
["https://solidproject.org/TR/solid-oidc"]`. LWS10 replaces this with
`lws_supported: ["https://www.w3.org/TR/lws-auth-oidc/"]`. Keep the
former for one deprecation cycle — CSS still probes for it.

**Status:** keep, add A.2 → B.5.

### A.3 `client_secret` in `"none"`-auth responses

RFC 7591 requires `client_secret` only when the client is confidential.
We already correctly emit `None` for `token_endpoint_auth_method: "none"`.
LWS10 tightens this to "MUST omit" — our implementation already complies.

**Status:** compliant.

### A.4 `grant_types_supported: client_credentials`

Solid-OIDC 0.1 permitted M2M via client_credentials. LWS10 drops the
grant for non-confidential clients. We advertise it because the pod
still honours it for trusted server-to-server callers (see
`solid-pod-rs-server`). A future revision MAY strip it from the
public discovery document and offer it under a private endpoint.

**Status:** keep; tracked as B.4 deferred.

## 4. Section B — fields LWS10 requires that we do not emit

These are *port tickets*. Each one maps to a concrete code change in
`src/oidc/mod.rs` or a new module.

### B.1 `authorization_response_iss_parameter_supported: true`

LWS10 §7.1 references RFC 9207 §2 — the authorisation server MUST
include `iss` in the response query. Our discovery document omits the
metadata flag and our token exchange code never propagates `iss`
through the auth-code callback. The pod doesn't implement the
authorisation endpoint itself (that's the IdP's job), but the
discovery document published *by the pod* when acting as an IdP
(`solid-pod-rs-idp`) must advertise the flag.

- **File:** `src/oidc/mod.rs::discovery_for`
- **Change:** add `authorization_response_iss_parameter_supported: bool`
  (default `true`) to `DiscoveryDocument`.
- **Estimated effort:** S (one struct field + serde).

### B.2 Explicit `require_pushed_authorization_requests` flag

LWS10 §6.3 normative: clients MUST use PAR (RFC 9126). The pod's
discovery doc currently omits the `pushed_authorization_request_endpoint`
member and does not advertise `require_pushed_authorization_requests`.
solid-pod-rs-idp would need:

- `/par` endpoint (RFC 9126 §2.1).
- Discovery: `pushed_authorization_request_endpoint: "…/par"` and
  `require_pushed_authorization_requests: true`.
- Request URI storage (ephemeral, ≤60s).

- **File:** new `solid-pod-rs-idp/src/par.rs`; discovery field.
- **Estimated effort:** M (end-to-end new endpoint).

### B.3 `dpop_signing_alg_values_supported` MUST include `EdDSA`

Per LWS10 §5.2. We currently advertise `["ES256", "RS256"]`. The library
actually supports `EdDSA` (see the alg-dispatch match in
`verify_dpop_proof_core`), but the discovery metadata doesn't mention
it.

- **File:** `src/oidc/mod.rs::discovery_for`
- **Change:** add `"EdDSA"` to `dpop_signing_alg_values_supported`.
- **Estimated effort:** XS (one array entry + a test).

### B.4 `client_registration_types_supported`

LWS10 §4.1 requires the server to declare which Client ID Document
types it accepts: `["automatic", "dynamic"]` for a pod that honours both
the legacy RFC 7591 flow AND the new "point at my Client ID Doc" flow.

- **File:** `src/oidc/mod.rs::DiscoveryDocument`
- **Change:** add field; emit `["automatic", "dynamic"]`.
- **Estimated effort:** S.

### B.5 `lws_supported` replaces `solid_oidc_supported`

Per §3 A.2 above. Dual-publish both for a deprecation cycle.

- **File:** `src/oidc/mod.rs::discovery_for`
- **Change:** add `lws_supported` field; keep `solid_oidc_supported`.
- **Estimated effort:** XS.

### B.6 Client ID Document MUST be fetchable with DPoP-bound request

LWS10 §4.2 says the pod, when acting as a Resource Server, SHOULD
resolve the client's Client ID Document to validate the `client_id`
claim against the RP's declared origin. The current
`verify_access_token` path trusts the `client_id` claim verbatim
without document resolution. This is a defence-in-depth measure against
token-substitution where an RP impersonates another RP's client-id.

- **File:** new `src/oidc/client_id_doc.rs`.
- **Dependencies:** reuses `oidc::jwks::ssrf_guarded_fetch_json`.
- **Estimated effort:** M.

### B.7 `cnf.jkt` MUST survive refresh-token rotation

LWS10 §5.5 makes DPoP-bound refresh a normative requirement. The pod
currently refuses to refresh a DPoP-bound token from outside
`solid-pod-rs-idp`; when it *does* refresh (IdP-only path), the new
access token inherits the original `jkt`. Our test coverage for this is
thin. Add a dedicated test (`tests/oidc_refresh_jkt_binding.rs`).

- **Estimated effort:** S (tests only).

## 5. Section C — semantic differences

Both legal; document the resolution.

### C.1 `webid` claim location

- Solid-OIDC 0.1 (impl): top-level `webid` claim OR URL-shaped `sub`.
- LWS10 FPWD: `webid` under `cnf` (nested).

**Resolution:** accept both. `extract_webid` now checks `cnf.webid`
first, falls back to top-level `webid`, then to URL-shaped `sub`.
(Implementation: one-line patch to `extract_webid` + add a JSON path.)

### C.2 DPoP proof `iat` skew

- RFC 9449 recommends "reasonable" skew without a number.
- LWS10 §5.3 fixes it at ±90s.
- Our implementation uses caller-supplied `skew`, default 60s in the
  embedded server (see `solid-pod-rs-server/src/lib.rs`).

**Resolution:** bump the default to 90s to match LWS10 — keep the
argument caller-overridable.

### C.3 `client_id` URL format

- Solid-OIDC 0.1: "SHOULD be a dereferenceable HTTPS URL."
- LWS10: "MUST dereference to a Client ID Document (§4.2)."

**Resolution:** covered by B.6; Section C is documentation-only.

### C.4 Token aud semantics

- Solid-OIDC 0.1: `aud` is the string `"solid"` or the pod origin.
- LWS10 §5.4: `aud` MUST be the resource server origin (full URL, no
  path). The `"solid"` magic string is dropped.

**Resolution:** add a `validate_aud` switch to `verify_access_token`
that enforces the origin when the caller passes an expected URL.
Default off for back-compat; the embedded server flips it on.

### C.5 Introspection response DPoP binding

- RFC 7662 doesn't define `cnf`.
- Solid-OIDC 0.1: `cnf.jkt` optional in introspection.
- LWS10: MUST be present when the introspected token is DPoP-bound.

**Resolution:** our `IntrospectionResponse::from_verified` already emits
`cnf: Some(CnfClaim { jkt })` unconditionally for verified tokens, so
we're compliant — mark as such in CHANGELOG.

## 6. Action items

Port tickets, ordered by cost. None require breaking the public API.

| #  | Ref  | Change                                                                                  | Effort | Priority |
|----|------|-----------------------------------------------------------------------------------------|--------|----------|
| 1  | B.3  | Add `EdDSA` to `dpop_signing_alg_values_supported`                                      | XS     | P1       |
| 2  | B.5  | Add `lws_supported`; keep `solid_oidc_supported` for one cycle                          | XS     | P1       |
| 3  | C.2  | Default DPoP iat skew to 90s                                                            | XS     | P1       |
| 4  | B.1  | Add `authorization_response_iss_parameter_supported` to discovery                       | S      | P1       |
| 5  | B.4  | Add `client_registration_types_supported`                                               | S      | P2       |
| 6  | C.1  | Accept `cnf.webid` in `extract_webid`                                                   | S      | P1       |
| 7  | C.4  | Optional `expected_aud_origin` in `verify_access_token`                                 | S      | P2       |
| 8  | B.7  | Test coverage for DPoP-bound refresh jkt survival                                       | S      | P2       |
| 9  | B.6  | Client ID Document resolver (new module, SSRF-guarded fetch)                            | M      | P2       |
| 10 | B.2  | PAR endpoint in solid-pod-rs-idp + discovery metadata                                   | M      | P3       |

Items 1-4 close ~60% of the LWS10 delta at negligible cost and lift JSS
#319 box 1 to "partial-parity — cosmetic gaps only". Items 5-8 are
targeted for Sprint 12. Items 9-10 are tracked under a separate ADR
(forthcoming: ADR-058 *Client ID Document resolver* and ADR-059 *PAR
endpoint*).

## 7. Out of scope

- **RAR** (RFC 9396) — LWS10 mentions it as an extension point but does
  not require support.
- **FAPI 2.0 baseline** — LWS10 defers FAPI alignment to a later draft.
- **Token-bound cookies** — separate RFC 8471 track.

## 8. Parity verdict

Status: **partial-parity — cosmetic gaps only** once items 1-4 land.
Status: **full-parity** once items 5-8 land.
Status: **LWS10 + CID-as-identity** once items 9-10 land and ADR-058 +
ADR-059 close.

## 9. References

- RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)
- RFC 7638 — JWK Thumbprint
- RFC 7591 — OAuth 2.0 Dynamic Client Registration
- RFC 7662 — OAuth 2.0 Token Introspection
- RFC 9101 — JWT-Secured Authorization Request (JAR)
- RFC 9126 — Pushed Authorization Requests (PAR)
- RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification
- RFC 9700 — OAuth 2.1 (draft)
- W3C LWS10 FPWD — Authorization with OIDC, 2026-04-23
- W3C Controlled Identifier Document 1.0 Working Draft
- Solid-OIDC 0.1 — <https://solid.github.io/solid-oidc/>
- JSS parity tracker #319 — LWS10 FPWD alignment

## 10. Revision history

- 2026-04-24 — Sprint 11 row 150: initial ADR, partial-parity status.
