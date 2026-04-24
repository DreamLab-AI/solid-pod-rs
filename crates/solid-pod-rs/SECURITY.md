# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x (latest minor) | Yes |
| 0.x (previous minor) | Yes |
| older | No |

## Reporting

Private disclosure preferred. Contact the maintainers via the channel listed at the repository's contact page on GitHub (Insights → Community Standards), or open a GitHub Security Advisory via the repository's "Security" tab → "Report a vulnerability".

Please do NOT open a public issue for suspected vulnerabilities.

## Process

1. Acknowledgement within 5 business days.
2. Assessment + scoped fix plan within 15 business days.
3. Coordinated disclosure within 90 days of initial report, or sooner if a public exploit exists.
4. CVE assignment where applicable; credit to the reporter on request.

## Scope

In scope: the `solid-pod-rs` crate, its default features, its documented public API, its CI/CD configuration.

Out of scope: downstream consumers' integrations (VisionClaw, community-forum-rs, etc.) — report those directly to those projects.

## Cryptographic verification

The following properties are enforced by the library core and exercised
by the workspace test suite. They are load-bearing invariants; a
regression in any of them should be reported as a vulnerability.

### DPoP proof verification (RFC 9449)

- **Signature verified against the proof's embedded `header.jwk`.**
  `oidc::verify_dpop_proof_core` dispatches on `header.alg` against a
  hard-coded allowlist and rejects the proof if the signature does not
  validate. This is the Sprint 9 P0 fix (parity row 62b); the
  pre-fix code path decoded the body without signature verification and
  is considered CVE-class.
- **Algorithm allowlist.**
  `ES256`, `ES384`, `RS256`, `RS384`, `RS512`, `PS256`, `PS384`,
  `PS512`, `EdDSA`. `alg=none` and the entire HMAC family (`HS256`,
  `HS384`, `HS512`) are unconditionally rejected.
- **`ath` access-token hash binding** (RFC 9449 §4.3). The `ath` claim
  must be present and equal to `base64url(SHA-256(bearer_token))`;
  comparison is constant-time.
- **`htm` / `htu` binding.** The proof's `htm` claim must match the
  request method; `htu` must match the request's target URI after
  normalisation.
- **`jti` replay cache.** Under `dpop-replay-cache`, a bounded LRU of
  seen `jti` values closes the replay window (Solid-OIDC §5.2,
  RFC 9449 §11.1). Cache is clock-aware and safe under concurrent
  access.
- **`iat` skew gate.** Proof-JWT `iat` must lie within the configured
  tolerance window (default ±60 s). The Sprint 6 fix corrected a
  short-circuit bug that made this gate unreachable.

### JWT + JWK handling

- **`Algorithm::None` rejected** at every boundary — DPoP proofs,
  access tokens, webhook signatures, ID tokens.
- **RFC 7638 canonical JWK thumbprints.** `Jwk::thumbprint` uses
  `BTreeMap`-backed canonical JSON serialisation; verified byte-for-
  byte against the spec's appendix-A test vector.
- **Access-token verification dispatches on `header.alg` against a
  `JwkSet`.** `verify_access_token` accepts `TokenVerifyKey::Symmetric`
  (test/dev) or `TokenVerifyKey::Asymmetric(JwkSet)` (production).

### SSRF defence

Applied to every outbound HTTP fetch in the library:

- **Rejected address classes.** RFC 1918 private ranges
  (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback
  (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10`),
  and the cloud-metadata endpoint (`169.254.169.254`).
- **DNS-rebinding defence.** After the SSRF policy approves a
  hostname, the per-call reqwest client is constructed with
  `.resolve()` pinning the TCP connect to the approved IP. A
  rebind between the SSRF check and the connect cannot redirect
  the request to an unapproved address.
- **JWKS discovery re-checks.** `fetch_jwks` runs the SSRF policy
  once on the issuer host and a second time on the discovered
  `jwks_uri` host; the issuer approval does not transfer to the
  JWKS host.

### Dotfile allowlist

Only the following dotfiles are served; all other dotfile requests
return 404 regardless of storage-layer presence:

- `.acl` — WAC access-control documents.
- `.meta` — RDF metadata sidecars.
- `.well-known` — the standard discovery tree.
- `.quota.json` — per-pod quota sidecar (when `quota` is enabled).

The allowlist is enforced at the storage boundary (`security::dotfile`)
and again by the server's `DotfileGuard` middleware.

### WAC parser bounds

- **1 MiB Turtle ACL input cap** (configurable via
  `JSS_MAX_ACL_BYTES`). Defends against O(n²) splitter blowup on
  multi-MB inputs.
- **32-level JSON-LD depth cap** enforced via a pre-parse depth-
  counted JSON skim. Defends against stack-overflow recursion bombs
  (200-level crafted inputs are rejected within ~5 ms).

### Webhook signing (RFC 9421)

Under `webhook-signing`, every outbound webhook delivery is signed
with Ed25519 over `@method`, `@target-uri`, `content-type`,
`content-digest` (RFC 9530), `date`, `x-solid-notification-id`. The
verifier is symmetric so receivers can reuse it to validate inbound
signatures.

### Quota integrity

`FsQuotaStore` serialises quota mutations to a temp file under the
pod root and `fs::rename`s into place. Concurrent writers cannot
observe a torn `.quota.json`.
