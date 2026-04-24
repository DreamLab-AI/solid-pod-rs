# v0.4.0-alpha (Sprint 9 close — 2026-04-24)

solid-pod-rs reaches **85 % spec-normative parity** with the reference
JavaScriptSolidServer implementation (66 % strict on the full 121-row
tracker, which includes rows that are net-new vs JSS, explicitly
wontfix, or deferred to v0.5.0 sibling crates). Sprints 8 and 9 closed
a CVE-class DPoP bypass and tightened the security perimeter across
SSRF, dotfiles, atomic quota, webhook signing, and pod bootstrap.

Commit SHAs: `2275146` (Sprint 9) and `ebbf163` (Sprint 7 operator
surface). Sprint 8 was doc + small-primitive work and is folded into
those ranges.

## Sprint 9 (commit `2275146`)

- **Cryptographic DPoP P0 (CVE-class).** `oidc::verify_dpop_proof_core`
  now verifies the proof-JWT signature against the embedded `header.jwk`
  using an algorithm allowlist (`ES256`/`ES384`, `RS256`/`RS384`/`RS512`,
  `PS256`/`PS384`/`PS512`, `EdDSA`). `alg=none` and the HMAC family are
  hard-rejected. Previously the function decoded the body without
  verifying the signature — any forged proof authenticated. RFC 9449
  §4.3 conformance restored; `ath` access-token hash binding enforced;
  `jti` replay cache remains under `dpop-replay-cache`.
- **WAC 2.0 conditions framework.** `acl:condition` predicate with
  `acl:ClientCondition` / `acl:IssuerCondition` evaluators,
  `ConditionRegistry` wiring, `wac::validate_for_write` handler hook
  that returns 422 `application/problem+json` on unsupported
  conditions, and `WAC-Allow` transparency that omits gated modes when
  the underlying condition evaluates to `NotApplicable`.
- **`acl:origin` enforcement (net-new vs JSS).** Feature `acl-origin`;
  `Origin` header required against the ACL allowlist per WAC §4.3.
- **SSRF + dotfile allowlist primitives P0.** `security::ssrf`
  classifies RFC 1918, loopback, link-local, and cloud metadata
  addresses; applied to outbound JWKS fetch, webhook delivery, and
  did:nostr resolution with DNS-rebinding defence via `.resolve()`
  pinning. `security::dotfile` restricts served dotfiles to an
  allowlist of `.acl`, `.meta`, `.well-known`, and `.quota.json`.
- **Pod bootstrap.** `provision::provision_pod` seeds idempotent
  containers, type indexes (public + private), a WebID profile, and a
  public-read root ACL. Quota tracker with atomic reserve/release
  closes the Sprint 8 quota-race window.

## Sprint 8 (tracking JSS 0.0.144 – 0.0.154)

- **LWS 1.0 Auth Suite rows closed.** NIP-98 Schnorr BIP-340
  verification, WebID ↔ did:nostr `alsoKnownAs` round-trip, and
  `solid:oidcIssuer` emission plumbed through `webid::generate_*`.
- **Atomic quota writes (P0).** `FsQuotaStore::record` and
  `reconcile` now use temp-file + rename so concurrent writers can
  never observe a torn `.quota.json`.
- **CID service in WebID.** WebID profile documents link to
  Content-Identifier-bound storage endpoints for implementations that
  back storage with IPFS/IPLD.
- **Cache-Control on RDF resources.** LDP conneg paths now emit
  appropriate `Cache-Control` per resource kind (containers revalidate,
  resources expire), matching JSS behaviour.
- **`.acl` + `.meta` content negotiation.** Both discovery resources
  honour `Accept:` and serialise to the requested RDF syntax.

## Sprint 7 (commit `ebbf163`) — operator surface

- Sliding-window LRU rate limiter, CORS policy with env overrides,
  per-pod quota sidecar, subdomain + path multi-tenancy, explicit body
  size cap, PathTraversalGuard + DotfileGuard middleware, optional
  rustls TLS, NodeInfo 2.1 discovery, full server route table with
  WAC enforcement on writes.

## Sprint 6 (folded) — WAC 2.0 + webhook signing + did:nostr

- WAC 2.0 condition framework; `wac.rs` split into nine focused
  sub-modules; RFC 9421 webhook signing with Ed25519; did:nostr
  bidirectional resolver; LDP hidden gaps (slug validation, OPTIONS
  Accept-Ranges per resource kind, PATCH-creates-resource, Range 416
  distinction); WAC parser bounds (1 MiB Turtle cap, depth 32 JSON-LD).

## Install

```bash
cargo install solid-pod-rs-server
solid-pod-rs-server --config config.json
```

```json
{
  "server":  { "host": "127.0.0.1", "port": 3000 },
  "storage": { "kind": "fs", "root": "./pod-root" },
  "auth":    { "nip98": { "enabled": true } }
}
```

## Upgrading

- **From 0.3.x:** the library crate no longer constructs
  `actix-web::HttpServer`. Add `solid-pod-rs-server` to your deployment.
  `verify_dpop_proof` and `evaluate_access` gained optional arguments
  that default to `None` at existing call sites.
- **From 0.4.0-alpha.1 (pre-Sprint 5):** no API break; if you relied
  on DPoP proofs authenticating without signature verification, your
  deployment was vulnerable — rotate any DPoP-bound tokens issued
  before the upgrade.

## Reserved for v0.5.0

The sibling crates `solid-pod-rs-activitypub`, `solid-pod-rs-git`,
`solid-pod-rs-idp`, and `solid-pod-rs-nostr` remain empty namespace
stubs. They must not be depended on until v0.5.0 lands their
implementations.

See
[`crates/solid-pod-rs/CHANGELOG.md`](crates/solid-pod-rs/CHANGELOG.md)
for the row-by-row detail,
[`crates/solid-pod-rs/PARITY-CHECKLIST.md`](crates/solid-pod-rs/PARITY-CHECKLIST.md)
for the tracker, and
[`crates/solid-pod-rs/docs/reference/agent-integration-guide.md`](crates/solid-pod-rs/docs/reference/agent-integration-guide.md)
for the agent-oriented integration guide with JSS source breadcrumbs.

---

# v0.4.0-alpha.1

JSS-parity migration. solid-pod-rs is at 76 % strict parity with
the reference JavaScriptSolidServer implementation, the six prior
audit findings are closed, and the workspace now cleanly separates
the library from the transport.

## Highlights

- **Workspace split.** `solid-pod-rs` (library) and
  `solid-pod-rs-server` (drop-in binary) replace the previous
  all-in-one crate. Four reserved sibling crates —
  `solid-pod-rs-{activitypub, git, idp, nostr}` — hold the
  v0.5.0 extension namespaces.
- **Security hardening.** SSRF guard with IP classification plus
  allow/deny lists; dotfile allowlist enforced at the storage
  boundary; DPoP `jti` replay cache per Solid-OIDC §5.2 and
  RFC 9449 §11.1.
- **WAC `acl:origin`.** Origin-based authorisation per the Web
  Access Control spec §4.3, gated behind a feature flag.
- **Legacy notifications.** `solid-0.1` WebSocket adapter for
  SolidOS data-browser compatibility.
- **JSS-compatible config loader.** Layered loader
  (defaults → file → env) with `JSS_*` variable names identical
  to the reference implementation.

## Install

```bash
cargo install solid-pod-rs-server
solid-pod-rs-server --config config.json
```

Minimal config:

```json
{
  "server":  { "host": "127.0.0.1", "port": 3000 },
  "storage": { "kind": "fs", "root": "./pod-root" },
  "auth":    { "nip98": { "enabled": true } }
}
```

## Upgrading from 0.3.0-alpha.3

- Add `solid-pod-rs-server` to your deployment if you were
  constructing `actix-web::HttpServer` from the library. The
  library no longer mounts HTTP routes.
- `verify_dpop_proof` gained an optional replay-cache argument;
  existing call sites compile unchanged by passing `None`.
- `evaluate_access` gained an optional request-origin argument;
  existing call sites compile unchanged by passing `None`.

See [CHANGELOG](crates/solid-pod-rs/CHANGELOG.md) for the full
change list and
[PARITY-CHECKLIST](crates/solid-pod-rs/PARITY-CHECKLIST.md) for
the row-by-row parity tracker.

## Licence

AGPL-3.0-only, inherited from the JavaScriptSolidServer ecosystem
covenant.
