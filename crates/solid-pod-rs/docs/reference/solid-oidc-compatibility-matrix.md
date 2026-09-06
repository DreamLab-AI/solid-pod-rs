# Solid-OIDC compatibility matrix

**Version: `solid-pod-rs` 0.5.0-alpha.8** (workspace `Cargo.toml`,
`[workspace.package] version`). This matrix describes the OIDC surface
of *that* crate version. It is the compatibility contract referenced by
[ADR-2003](../adr/ADR-2003-solid-oidc-01-defer-lws10.md) — "Hold the
OIDC wire at Solid-OIDC 0.1 and defer the LWS10 delta" — whose closeout
asks for a *versioned* discovery/verifier/client matrix backed by
executable checks rather than source observations.

Everything below is grounded in [`src/oidc/mod.rs`](../../src/oidc/mod.rs)
and [`src/oidc/jwks.rs`](../../src/oidc/jwks.rs) as of this version. Where
the code's behaviour differs from what the specification (or the ADR's
prose) would lead you to expect, this document records the **actual**
behaviour and marks it. Everything asserted here that can be asserted
in-process is asserted by
[`tests/oidc_compat_matrix.rs`](../../tests/oidc_compat_matrix.rs).

The whole module is behind the `oidc` cargo feature. Without it, none of
these surfaces exist.

## Spec-version matrix

| Specification | Implemented here | Deliberately not implemented | Carrier |
|---|---|---|---|
| **Solid-OIDC 0.1** (`solidproject.org/TR/solid-oidc`) | DPoP-bound access tokens; `cnf.jkt` ⇄ DPoP-key binding; `webid` claim with URL-shaped `sub` fallback; `solid_oidc_supported` in discovery; `webid` scope advertised | LWS 1.0 delta (see *Deferred: LWS-10*); `cnf.webid`; client-ID-document (`application_type`) fetch and validation — the field is parsed but never dereferenced | `oidc::verify_access_token`, `oidc::extract_webid`, `oidc::discovery_for`, `oidc::CnfClaim` |
| **OpenID Connect Core 1.0** | Discovery-document *shape* for the subset a Solid client needs; `iss`/`sub`/`aud`/`exp`/`iat` claim parsing; issuer fixation on fetched discovery documents | No ID-token verification, no `nonce`/`at_hash`/`c_hash` checks, no UserInfo client, no authorization-code or session management, no `acr`/`amr`. `userinfo_endpoint` is *advertised*, not *served* by this crate | `oidc::DiscoveryDocument`, `oidc::discovery_for`, `oidc::jwks::fetch_oidc_config` |
| **OAuth 2.0 — RFC 6749** | Grant/response/auth-method metadata advertised in discovery | No authorization server: no `/authorize`, `/token`, or refresh implementation lives in this crate. The endpoints in the discovery document are URL strings an embedding server must actually serve | `oidc::discovery_for` |
| **OAuth 2.0 Token Introspection — RFC 7662** | Response *body* builder for active and inactive tokens (`active`, `webid`, `client_id`, `exp`, `iss`, `scope`, `cnf`) | No introspection *endpoint*, no client authentication for it, no `token_type_hint` handling, no `nbf`/`jti`/`username`/`aud` members | `oidc::IntrospectionResponse::{from_verified, inactive}` |
| **OAuth 2.0 Dynamic Client Registration — RFC 7591** | Request/response types and an in-memory `register_client` that mints `client-<uuid>` / `secret-<uuid>`, honouring `token_endpoint_auth_method: "none"` (public client, no secret) | No persistence, no registration access token, no `client_secret` rotation or expiry (`client_secret_expires_at` is always `0` = never expires), no software statement, no redirect-URI validation | `oidc::register_client`, `oidc::ClientRegistrationRequest`, `oidc::ClientRegistrationResponse` |
| **RFC 9449 (DPoP)** | Proof signature verification against the embedded header `jwk`; `typ=dpop+jwt`; `htm`/`htu`/`iat`-skew checks; `ath` binding (§4.3); asymmetric-only `alg` allowlist (§5); `jti` replay cache (opt-in) | **No DPoP nonce** (§8): no `DPoP-Nonce` issuance, no `nonce` claim check — a `nonce` claim on a proof is ignored. No `exp` on proofs. No authorization-code binding (`dpop_jkt` request parameter). ES512 unavailable (see *Verifier matrix*) | `oidc::verify_dpop_proof`, `oidc::verify_dpop_proof_with_ath`, `oidc::replay::DpopReplayCache` |
| **RFC 7638 (JWK thumbprint)** | SHA-256 thumbprints over the exact required-member set for `EC`, `RSA`, `OKP`, `oct`, canonicalised via `BTreeMap` + `serde_json` (lexicographic, no whitespace), base64url-no-pad | No SHA-384/SHA-512 thumbprint variants; no `kty` outside the four above | `oidc::Jwk::thumbprint` |
| **RFC 7517 (JWK)** | A minimal local `Jwk` carrying `kty`, `alg`, `kid`, `use`, `crv`, `x`, `y`, `n`, `e`, `k`; `jsonwebtoken::jwk::JwkSet` for the verification keyset | No `x5c`/`x5t`/`x5u` chain validation, no key-`use`/`key_ops` enforcement, no encryption keys | `oidc::Jwk`, `oidc::TokenVerifyKey::Asymmetric` |
| **RFC 7519 (JWT)** | Header-`alg` dispatch with a closed allowlist; signature verification; `iss` exact match; manual `exp` check | `aud` **not** validated; `nbf` not checked; `jti`/`sub` format not constrained; `crit` header not processed; JWE (encrypted tokens) unsupported | `oidc::verify_access_token` |
| **WebID-OIDC (predecessor of Solid-OIDC 0.1)** | Its identity model survives as the `sub`-as-WebID fallback in `extract_webid`, so pre-Solid-OIDC tokens whose `sub` is the WebID URL still resolve | No `id_token` "PoP token" flow, no `key`/`cnf` JWK-in-ID-token, no legacy WebID-TLS bridge, no legacy `iss` discovery from a WebID profile *inside this module* (WebID profile parsing lives in [`src/webid.rs`](../../src/webid.rs)) | `oidc::extract_webid`; `webid::extract_oidc_issuer`, `webid::extract_cid_openid_provider` |

## Discovery matrix

`discovery_for(issuer)` is a **pure string builder**. It performs no
network access, no URL parsing and no validation: the only normalisation
is `issuer.trim_end_matches('/')`, which strips *every* trailing slash.
Case is preserved, paths are preserved, and a non-URL input is echoed
back verbatim. Every endpoint is `{normalised_issuer}{suffix}`, so it is
absolute exactly when the supplied issuer was.

| Field | Source spec | Value emitted | May consumers rely on it? |
|---|---|---|---|
| `issuer` | OIDC Discovery §3 | the argument with trailing `/` trimmed | **Yes.** This is the exact string `verify_access_token` expects as `expected_issuer` |
| `authorization_endpoint` | RFC 6749 §3.1 | `{issuer}/authorize` | Shape only — this crate does not serve it |
| `token_endpoint` | RFC 6749 §3.2 | `{issuer}/token` | Shape only |
| `userinfo_endpoint` | OIDC Core §5.3 | `{issuer}/userinfo` | Shape only |
| `jwks_uri` | OIDC Discovery §3 / RFC 7517 | `{issuer}/jwks` | Shape only. Note `jwks::fetch_oidc_config` reads the *remote* OP's `jwks_uri`; it does not assume this layout |
| `registration_endpoint` | RFC 7591 §3 | `{issuer}/register` | Shape only |
| `introspection_endpoint` | RFC 7662 §2 | `{issuer}/introspect` | Shape only |
| `scopes_supported` | OIDC Discovery §3 | `["openid","profile","webid","offline_access"]` | **Yes** — fixed for this crate version |
| `response_types_supported` | OIDC Core §3 | `["code","id_token"]` | **Yes** — fixed |
| `grant_types_supported` | RFC 6749 | `["authorization_code","refresh_token","client_credentials"]` | **Yes** — fixed |
| `token_endpoint_auth_methods_supported` | OIDC Core §9 | `["client_secret_basic","client_secret_post","private_key_jwt","none"]` | **Yes** — fixed |
| `dpop_signing_alg_values_supported` | RFC 9449 §5.1 | `["ES256","RS256"]` | **Yes**, and deliberately *narrower* than the verifier accepts — see the note below |
| `solid_oidc_supported` | Solid-OIDC 0.1 §6 | `["https://solidproject.org/TR/solid-oidc"]` | **Yes** |
| `id_token_signing_alg_values_supported` | OIDC Discovery §3 | `["RS256","ES256"]` | Advertised only; this crate verifies no ID tokens |

Fields a Solid-OIDC/LWS client might look for and **will not find**:
`lws_supported`, `authorization_response_iss_parameter_supported`,
`pushed_authorization_request_endpoint`,
`require_pushed_authorization_requests`,
`code_challenge_methods_supported`, `end_session_endpoint`,
`claims_supported`, `subject_types_supported`. Their absence is the
LWS-10 deferral in wire form.

> **Discovery/verifier asymmetry (recorded, not fixed).** Discovery
> advertises DPoP `ES256`/`RS256` only, while the DPoP verifier accepts
> nine asymmetric algorithms and the access-token verifier accepts
> `EdDSA`. ADR-2003 keeps this asymmetry deliberately: it is safe only
> in this direction (advertise less than you accept), and discovery must
> not widen until a decision lifts the LWS-10 defer.

### Remote discovery (`oidc::jwks`)

`fetch_oidc_config` / `fetch_jwks` / `CachedFetcher` are the *client*
side — fetching another OP's metadata. They are separately hardened and
their guarantees are part of this contract:

| Property | Behaviour |
|---|---|
| SSRF | `SsrfPolicy::resolve_and_check` runs twice — once for the issuer URL, again for the `jwks_uri` it returns. Approving the issuer does not approve the JWKS URL |
| DNS rebinding | The connect-time resolver is pinned to the approved IP via `reqwest::ClientBuilder::resolve` |
| Issuer fixation | The fetched document's `issuer` must equal the URL it was fetched from, modulo trailing slash (OIDC Core §3, RFC 8414 §3.3) |
| Timeout | 10 s per request, hard |
| Cache | 900 s TTL (`DEFAULT_CACHE_TTL`); `SHORT_CACHE_TTL` = 300 s |
| Unknown fields | Preserved via `serde(flatten)` into `OidcDiscoveryDoc::extra` — an OP publishing extensions is never rejected |

## Verifier matrix

### Access tokens — `verify_access_token(token, keyset, expected_issuer, dpop_jkt, now)`

| Aspect | Supported | Rejected |
|---|---|---|
| `alg` (asymmetric, `TokenVerifyKey::Asymmetric`) | `RS256`, `ES256`, `EdDSA` | Everything else, including `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES384` — `PodError::Nip98("… not permitted …")`. Narrower than the DPoP allowlist |
| `alg` (symmetric, `TokenVerifyKey::Symmetric`) | `HS256` **test/dev only** | Any asymmetric `alg` against a symmetric keyset — `"… but only a symmetric keyset is configured"` |
| `alg=none` | — | Always. `jsonwebtoken::Algorithm` has no `None` variant, so `decode_header` fails: `"access token header decode failed: …"` |
| Alg confusion | — | `HS256` against an asymmetric keyset — `"HS256 not permitted for external OIDC — asymmetric keyset required"` |
| Key types | Whatever `jsonwebtoken::jwk::JwkSet` + `DecodingKey::from_jwk` accept for the three algs above (EC P-256, RSA, Ed25519) | A `kid` absent from the configured keyset; an alg with no matching JWK when the token carries no `kid` |
| Key selection | Exact `kid` match first; otherwise the first JWK whose `key_algorithm` parses to the token's `alg` | — |
| Signature | Verified by `jsonwebtoken::decode` before any claim is trusted | Any tampered segment — `"access token decode failed: …"` |
| **Issuer** | `Validation::set_issuer(&[expected_issuer])` — **exact string equality** | Any difference at all: trailing slash, host/scheme case, `https://op.example.evil`, a prefix, an empty expectation. There is no URL normalisation on this path — unlike `discovery_for`, which trims trailing slashes. Normalise once through `discovery_for(...).issuer` and use that string on both sides |
| **Audience** | **Not validated.** `validation.validate_aud = false` ("Solid-OIDC allows arbitrary aud") and the function takes no expected-audience argument, so *any* `aud` value verifies — including another pod's URL, an empty array, a number or `null` | Only *absence*: `SolidOidcClaims::aud` has no `#[serde(default)]`, so a token omitting `aud` fails to deserialise (`"access token decode failed"`). **This is a gap, not a feature.** A deployment that needs audience restriction must enforce it above this API |
| Expiry | Checked manually as `claims.exp < now` → `"access token expired"`. `exp == now` is still valid. Checked *before* `cnf` and before WebID extraction | — |
| `nbf` | Not checked | — |
| `cnf` / `jkt` binding | `claims.cnf.jkt` must equal the caller-supplied `dpop_jkt` byte-for-byte | Absent `cnf` — `"access token missing cnf"`. Mismatch — `"cnf.jkt does not match DPoP thumbprint"`. Note the comparison here is a plain `!=`, not constant-time (unlike the `ath` check) |
| Replay | Not applicable — access tokens are not replay-tracked; the `jti` replay cache guards DPoP proofs only | — |
| Error type | Every failure above is `PodError::Nip98(String)`, which the [error-code reference](./error-codes.md) maps to HTTP 401 | — |

`verify_access_token_hs256` is a `#[deprecated]` shim that wraps the
secret in `TokenVerifyKey::Symmetric` and delegates; it is otherwise
identical.

### DPoP proofs — `verify_dpop_proof[_with_ath]`

Signature shape depends on the `dpop-replay-cache` feature: with it, the
functions are `async` and take a trailing `Option<&DpopReplayCache>`;
without it, they are synchronous and take no cache argument.

| Aspect | Supported | Rejected |
|---|---|---|
| `typ` header | `dpop+jwt` only | Anything else — `"DPoP typ must be dpop+jwt"` |
| `jwk` header | Required; parsed twice (local `Jwk` for the thumbprint, `jsonwebtoken::jwk::Jwk` for the key) | Absent — `"DPoP header missing jwk"`. Structurally incomplete — the thumbprint step fails first with `PodError::Unsupported` |
| `alg` | `ES256`, `ES384`, `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `EdDSA` | `alg=none`; all `HS*`. `ES512` is listed by RFC 9449 §5 but `jsonwebtoken` 9.x exposes no `ES512` variant, so it is out of scope for this build — documented, not silently claimed |
| `alg` (test-only) | `HS256` **with `kty=oct`**, compiled only under `cfg(test)` or the non-default `dpop-symmetric-test` feature | In any production build `HS256` falls through to the reject arm |
| Key types (thumbprint) | `EC` (needs `crv`,`x`,`y`), `RSA` (`e`,`n`), `OKP` (`crv`,`x`), `oct` (`k`) | Any other `kty` — `PodError::Unsupported("unsupported JWK kty: …")`; a supported `kty` missing a required member — e.g. `"EC JWK missing y"` |
| Signature | Verified against the embedded `jwk` — the proof is authenticated, not merely well-formed | `"DPoP proof signature verification failed: …"` |
| `jkt` derivation | RFC 7638 over the header `jwk`, surfaced as `DpopVerified::jkt`; this is the value fed to `verify_access_token`'s `dpop_jkt` | — |
| `htm` | Compared case-insensitively (`to_uppercase` on both sides) | `"DPoP htm mismatch: … vs …"` |
| `htu` | Compared after `trim_end_matches('/')` + `to_ascii_lowercase()`. **Note:** this lower-cases the whole URL including the path, so `/Foo` and `/foo` compare equal — looser than RFC 3986 | `"DPoP htu mismatch: … vs …"`. No query/fragment stripping is performed |
| `iat` | Must be within `±skew` of `now` (bidirectional; a historic `&&` made this gate a no-op and is fixed) | `"DPoP iat outside tolerance"` |
| `exp` | Not present and not checked — freshness is `iat` + replay cache | — |
| `nonce` | **Not implemented.** No `DPoP-Nonce` challenge is issued and the claim is not read | — |
| `ath` (RFC 9449 §4.3) | Enforced when the caller passes `expected_ath`: the claim must be present and equal, compared in constant time | Missing — `"DPoP proof missing ath but access token present"`. Mismatched — `"DPoP ath does not match access-token hash"`. With `expected_ath = None` the binding is **off** |
| `jti` replay | Opt-in via `Some(&DpopReplayCache)` (feature `dpop-replay-cache`), checked *after* signature and claim validation. Default TTL 60 s, capacity 10 000, overridable via `SOLID_POD_DPOP_REPLAY_TTL_SECS` / `SOLID_POD_DPOP_REPLAY_MAX_SIZE` | `"DPoP jti replay detected: …"`, incrementing `DPOP_REPLAY_REJECTED_TOTAL`. With `None`, replays are **accepted** — detection is strictly opt-in |
| Error type | `PodError::Nip98` for every claim/signature failure; `PodError::Unsupported` for thumbprint/key-type failures | — |

## Unsupported identity shapes

`extract_webid` accepts a string only if it starts with the literal
`http://` or `https://` — a case-sensitive prefix test, not URL parsing.
It prefers `webid`, then falls back to `sub`.

| Shape | Result | Error |
|---|---|---|
| `webid` is a `http(s)` URL | Accepted | — |
| `webid` absent, `sub` is a `http(s)` URL | Accepted (WebID-OIDC compatibility) | — |
| **`webid` blank or non-URL, `sub` is a `http(s)` URL** | **Accepted — silently falls back to `sub`.** A malformed `webid` claim is *skipped*, not rejected. Applies to `""`, `"   "`, `"not-a-url"`, `"did:…"` alike | — |
| `webid` absent **and** `sub` non-URL (e.g. an opaque `0xabc`) | Rejected | `Nip98("no WebID present in access token (neither webid claim nor url-shaped sub)")` |
| `webid` blank **and** `sub` non-URL | Rejected | same as above |
| `did:nostr:…`, `did:web:…`, `urn:uuid:…`, `mailto:…` in either member | Rejected — these are not WebIDs at this layer | same as above |
| Scheme-relative `//me.example/profile#me` | Rejected | same as above |
| Upper-case scheme `HTTPS://me.example/…` | Rejected — the prefix test is case-sensitive | same as above |
| `cnf.webid` identity (LWS-10) | Not read at all; no branch exists | falls through to the message above |
| `cnf` absent (unbound bearer token) | Rejected | `Nip98("access token missing cnf")` |
| `cnf.jkt` ≠ presented DPoP key thumbprint | Rejected | `Nip98("cnf.jkt does not match DPoP thumbprint")` |
| `alg: "none"` | Rejected under every keyset | `Nip98("access token header decode failed: …")` |
| `alg: HS256` with an asymmetric keyset (alg confusion) | Rejected | `Nip98("HS256 not permitted for external OIDC — asymmetric keyset required")` |
| `alg: RS256/ES256/EdDSA` with a symmetric keyset | Rejected | `Nip98("access token uses asymmetric alg … but only a symmetric keyset is configured")` |
| Any other `alg` on the access-token path (`RS384`, `PS256`, `ES384`, `HS384`, `HS512`, …) | Rejected | `Nip98("access token alg … not permitted (ES256/RS256/EdDSA for production, HS256 for test-only)")` |
| Symmetric keys outside the test-only feature | On the DPoP path, `HS256`+`oct` is compiled only under `cfg(test)` / `dpop-symmetric-test`; a release build rejects it | `Nip98("DPoP alg HS256 is not permitted (RFC 9449 §5 …)")` |
| `aud` member absent | Rejected — but for a *deserialisation* reason, not an audience policy | `Nip98("access token decode failed: …")` |
| Unregistered JWK `kty` in a DPoP header | Rejected | `Unsupported("unsupported JWK kty: …")` |

## Deferred: LWS-10

ADR-2003 holds the published OIDC wire at **Solid-OIDC 0.1** and defers
the W3C LWS 1.0 delta. The deferral is a decision, not an oversight: LWS
1.0 was at First Public Working Draft (2026-04-23) when the ADR was
taken, and chasing an FPWD whose fields may change before Recommendation
costs more than the parity gap. Concretely deferred:

- **`lws_supported`** is not advertised in discovery.
- **EdDSA in `dpop_signing_alg_values_supported`** is not advertised —
  even though the verifier accepts `EdDSA` access tokens and `EdDSA`
  DPoP proofs. Discovery and verifier must move together, and only in
  that order (advertise no more than you accept).
- **`cnf.webid`** is not read; `extract_webid` has no branch for it.
- **`authorization_response_iss_parameter_supported`** (the RFC 9207
  `iss` response flag) is not advertised.
- **PAR** (RFC 9126) is neither advertised nor implemented.

Consequences the ADR accepts: LWS10-only clients — those that mandate
PAR, require `cnf.webid` identity, or require EdDSA in discovery — do
not interoperate, by choice. Any future claim that "the cheap LWS-10
wins landed" is false until ADR-2003 is superseded.

**Until that defer is lifted, this matrix is the compatibility contract.**
A change to the discovery document, to the verifier's algorithm
allowlist, or to the accepted identity shapes is a change to this
contract and requires an explicit decision record plus interop receipts —
not merely a passing test run. This document neither adopts LWS 1.0 nor
certifies deployed OIDC interoperability; it states what this crate
version does.

## Verification

Every row above that is assertable in-process is asserted by
[`tests/oidc_compat_matrix.rs`](../../tests/oidc_compat_matrix.rs), whose
sections mirror this document: **A** discovery (field set, issuer
normalisation, endpoint shape, advertised algorithm lists and the absent
LWS-10 fields), **B** issuer validation including near-misses, **C** the
audience behaviour exactly as described above, **D** every unsupported
identity shape with its concrete `PodError` variant, **E** the expiry
boundary, **F** the deprecated HS256 shim, and **G** the DPoP-proof →
`cnf.jkt` stitch. The tests mint every token in-process with a test-only
symmetric secret and perform no network access.

```bash
cargo test -p solid-pod-rs --features oidc --test oidc_compat_matrix
cargo test -p solid-pod-rs \
    --features oidc,dpop-replay-cache,jss-v04 --test oidc_compat_matrix
```

`a1_discovery_emits_exactly_the_documented_field_set` compares the
serialised discovery document against the field list in the *Discovery
matrix* table above, so adding or removing a field without updating this
document fails the build.

## See also

- [ADR-2003](../adr/ADR-2003-solid-oidc-01-defer-lws10.md) — the deferral decision.
- [Error code reference](./error-codes.md) — `PodError::Nip98` → HTTP 401 mapping.
- [`src/oidc/mod.rs`](../../src/oidc/mod.rs) — discovery, DPoP, access tokens, introspection, registration.
- [`src/oidc/jwks.rs`](../../src/oidc/jwks.rs) — SSRF-guarded remote discovery and JWKS fetch.
- [`src/webid.rs`](../../src/webid.rs) — WebID profile generation and `solid:oidcIssuer` / LWS `service` discovery.
