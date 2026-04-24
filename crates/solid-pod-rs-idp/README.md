# solid-pod-rs-idp

**Status: Reserved stub for v0.5.0. Not yet implemented.**

This crate is a namespace placeholder in the `solid-pod-rs` workspace.
`src/lib.rs` contains a doc comment and nothing else. Do not depend on
it from integrator code — the module graph is empty until v0.5.0.

The core library's `oidc` module implements the Solid-OIDC **relying
party** surface (discovery, DPoP, token verification, JWKS fetch).
This sibling crate will add the **provider** surface — operators who
want an embedded IDP instead of delegating to an external one.

## Target scope

- Solid-OIDC provider: `/auth`, `/token`, `/me`, `/reg`, `/session`
  endpoints matching JSS `src/idp/index.js`.
- OIDC discovery + JWKS publication.
- Dynamic client registration (provider side of parity row 75).
- Client Identifier Documents (fetch + cache).
- Credentials flow (email + password, rate-limited).
- Passkeys / WebAuthn via a host-app integration trait.
- Schnorr SSO (NIP-07 handshake) bridging Nostr identities into
  Solid-OIDC sessions.
- HTML login / register / consent pages behind a templating trait
  so consumers pick their own view layer.

Target LOC: ~3,500 plus templates, shipped on an independent release
cycle from the library core.

## Parity rows

Rows that will close when this crate lands (see
[`../solid-pod-rs/PARITY-CHECKLIST.md`](../solid-pod-rs/PARITY-CHECKLIST.md)):

- **74** — OIDC `/auth` endpoint.
- **75** — Dynamic client registration (provider side).
- **76** — OIDC `/token` endpoint.
- **77** — `/me` session info.
- **78** — `/session` cookie handling.
- **79** — Client Identifier Documents.
- **80** — Credentials flow.
- **81** — Passkeys / WebAuthn integration.
- **82** — HTML interaction pages (login / consent).
- **130** — JWKS publication (provider side).

## JSS references

- `src/idp/index.js`
- `src/idp/provider.js`
- `src/idp/passkey.js`
- `src/idp/interactions.js`

## Licence

AGPL-3.0-only.
