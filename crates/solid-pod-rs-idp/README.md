# solid-pod-rs-idp

**Status: 0.4.0-alpha.1 — Sprint 10 minimum-viable Solid-OIDC provider.**

Rust port of the JSS identity provider (`JavaScriptSolidServer/src/idp/*`).
This crate owns the **protocol** surface; transport framing is the
consumer's decision (enable `axum-binder` for a ready-made Router,
or plug `Provider` into any router you like).

## What landed in Sprint 10

Parity rows flipped from `missing` → `present` (tracked in
`../../docs/PARITY-CHECKLIST.md`):

| Row | Endpoint / feature                   | JSS ref                        |
|----:|--------------------------------------|--------------------------------|
|  74 | `/idp/auth` — authorization-code flow | `src/idp/provider.js:307-317`  |
|  75 | `/idp/reg` — Dynamic Client Registration | `src/idp/provider.js:147-156`  |
|  76 | `/.well-known/openid-configuration`  | `src/idp/index.js:203-237`     |
|  77 | `/.well-known/jwks.json`             | `src/idp/index.js:240-244`     |
|  78 | Client Identifier Documents (SSRF-guarded) | `src/idp/provider.js:22-85`    |
|  79 | `/idp/credentials` (email+password + rate-limit) | `src/idp/credentials.js`       |
| 130 | JWKS publication (IdP side)          | `src/idp/keys.js`              |

## What is `partial-parity`

These rows have **trait hooks** shipped so consumer crates can plug
real implementations in without breaking `Provider`'s API. The
default impls return `Err(Unimplemented)`; a follow-up sprint will
land the real backends.

| Row | What's deferred                      | Why                            |
|----:|--------------------------------------|--------------------------------|
|  80 | Passkeys / WebAuthn — trait [`PasskeyBackend`] behind `passkey` feature | Real impl needs `webauthn-rs` (~400 LOC of attestation/assertion fixture wiring) |
|  81 | Schnorr SSO (NIP-07) — trait [`SchnorrBackend`] behind `schnorr-sso` feature | Real impl needs `nip98-schnorr` feature chain + `did-nostr` WebID mapping from core |

When the backend lands, nothing in `Provider` changes — the consumer
passes a real `Arc<dyn PasskeyBackend>` instead of `Arc<NullPasskeyBackend>`.

## What is `wontfix-in-crate`

| Row | Why                                  |
|----:|--------------------------------------|
|  82 | HTML interaction pages (login / consent / register). JSS bundles Handlebars templates in `src/idp/views.js`. We do not ship a view layer because the right choice depends on the consumer's existing stack (Askama, Leptos, Tera, Yew, or plain `format!`). A minimal Askama adapter on top of this crate is < 300 LOC and should live in a host-app crate where the operator controls the HTML. |

## Minimum-viable flow

```rust,no_run
use std::sync::Arc;
use solid_pod_rs_idp::{
    Provider, ProviderConfig, Jwks, SessionStore,
    registration::ClientStore,
    user_store::{InMemoryUserStore, UserStore},
};

// 1. Seed stores.
let user_store: Arc<dyn UserStore> = Arc::new(InMemoryUserStore::new());
let client_store = ClientStore::new();
let session_store = SessionStore::new();
let jwks = Jwks::generate_es256().unwrap();

// 2. Build the provider.
let provider = Provider::new(
    ProviderConfig::new("https://pod.example/"),
    client_store,
    session_store,
    user_store,
    jwks,
);

// 3. Serve discovery + JWKS directly from the provider:
let _discovery = provider.discovery_document();
let _jwks_doc = provider.jwks().public_document();
```

## Axum binder

Enable `axum-binder` to get a Router with discovery, JWKS,
registration, and credentials pre-wired:

```toml
[dependencies]
solid-pod-rs-idp = { version = "0.4", features = ["axum-binder"] }
```

`/idp/auth` and `/idp/token` are NOT on the binder — their request
shape (session cookies, form-encoded bodies, 302 redirects) is too
app-specific for a generic binder. Wire them against your own
framework session middleware.

## Design deviations from JSS

Honest list of shape differences (not behaviour differences — those
should be zero):

1. **Signing algorithm.** JSS publishes both RS256 and ES256; we
   publish ES256 only in Sprint 10 (Solid-OIDC mandates ES256 for
   DPoP, every Solid RP we checked accepts ES256 id-tokens, and it
   skips pulling `rsa` into our dep graph). Additional algs can be
   inserted via `Jwks::insert_signing_key`.
2. **Password hash.** JSS uses `bcrypt` (`src/idp/accounts.js`);
   we use `argon2id` (stronger, OWASP-preferred). Re-hashing on
   next successful login is the consumer's migration story.
3. **Session storage.** JSS persists sessions to disk via
   `oidc-provider`'s filesystem adapter. We ship an in-memory store
   with a pluggable trait; disk persistence is the consumer's
   choice (serialise the `SigningKey::private_pem` and session
   records to their own backend).
4. **Code format.** JSS generates opaque client ids as
   `client_<base36-timestamp>_<random>`. We mirror the format.
5. **View layer.** JSS bundles Handlebars templates; we don't (see
   row 82 above).

## Tests

39 unit tests cover:

- Discovery document shape (`webid` in scopes, `none` auth method,
  DPoP algs, PKCE S256, issuer trailing-slash normalisation).
- JWKS publication, key rotation with retention window, prune-expired,
  round-trip through PKCS8 PEM.
- Opaque dynamic client registration + Client Identifier Documents
  (fetch, cache, id-mismatch rejection, SSRF guard trips on private
  IP, missing-redirect-uris rejection).
- Session create/lookup/revoke + authorisation-code single-use + TTL
  expiry.
- `/idp/credentials` email+password: correct password, wrong
  password, unknown user, blank input, DPoP-bound vs Bearer, rate
  limit tripping at 11th attempt.
- Authorisation-code flow end-to-end: issue code → redeem at
  `/token` → verify DPoP-bound access token. Plus negative cases
  (missing DPoP, wrong htu, PKCE mismatch, unregistered redirect,
  no PKCE attempt).
- Access-token issuance with DPoP `cnf.jkt` binding; Bearer issuance
  when no DPoP thumbprint is passed; `ath_hash` known-value check.
- Trait hook callability (passkey / schnorr null backends return
  `Unimplemented`).

## Licence

AGPL-3.0-only.
