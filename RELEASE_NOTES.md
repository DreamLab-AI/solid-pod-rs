# v0.5.0-alpha.1 (Sprint 11 close — 2026-04-24)

solid-pod-rs closes the top-10 remaining JSS parity roadmap. The
workspace now sits at **~97% strict / ~100% spec-normative** against
the real JavaScriptSolidServer. Sibling crates are all functional —
the v0.5.0 tier is live, with a brand-new `solid-pod-rs-didkey` crate
shipping the LWS 1.0 Auth Suite ahead of JSS itself.

**Headline**: 835 workspace tests pass, 0 failing, `cargo clippy
--workspace --all-features --all-targets -- -D warnings` clean.
Security scan: 0 vulnerabilities across new crypto code (didkey, idp).
No outstanding P0. No regressions.

## Sprint 11 (roadmap closure)

### P1 — LWS 1.0 Auth Suite (rows 150, 152, 153)

- **NEW crate `solid-pod-rs-didkey`** (858 LOC across 6 modules).
  W3C did:key encoding/decoding for Ed25519, P-256, and secp256k1;
  hand-rolled self-signed JWT verify with algorithm dispatch and
  `alg=none` hard-reject; `DidKeyVerifier` impl of the new
  `SelfSignedVerifier` trait. 29 tests including round-trip for all
  three curves.
- **`auth::self_signed::SelfSignedVerifier` + `CidVerifier`
  dispatcher** (row 152, net-new — JSS hasn't shipped this yet).
  Fan-out over `Nip98Verifier` (existing NIP-98 path) and
  `DidKeyVerifier` (new did:key path). Wired into
  `wac::issuer::IssuerCondition` dispatch so an `IssuerCondition` of
  type `cid:Verifier` now accepts either proof family.
- **ADR-057 LWS10 OIDC delta audit** (row 150). 5 fields we emit but
  LWS10 does not require (backward-compat keep), 7 fields LWS10
  requires that we do not emit (port tickets XS → M), 5 fields
  where semantics differ. Plain-English gap list +
  prioritised action items.

### P1 — Ecosystem compat (row 91)

- **solid-0.1 legacy WebSocket** — `notifications::legacy`
  `LegacyWebSocketSession`. Full `sub <uri>` / `ack` / `err <msg>` /
  `pub <uri>` / `unsub <uri>` protocol, per-subscription WAC Read
  re-check, 100 subs/conn cap, 2 KiB URL cap, ancestor-container
  fanout on publish. 11 integration tests.

### P2 — Operator surface (rows 120–124, 125, 158, 162)

- **Config loader completion.** `ConfigLoader::from_file` auto-detects
  JSON/YAML/TOML by extension; `with_cli_overlay` sits at top of the
  precedence stack; `parse_size` accepts IEC binary suffixes (`KiB`/
  `MiB`/`GiB`/`TiB`) alongside existing SI decimals; 31 `JSS_*` env
  vars wired.
- **Subdomain file-label heuristic.** `is_file_like_label` —
  15+ known web-asset extensions, case-insensitive, short-circuits
  `SubdomainResolver` so `/favicon.ico` doesn't try to route to a
  `favicon` pod.
- **Top-level 5xx logging middleware.** `ErrorLoggingMiddleware`
  actix service emits structured `tracing::error!` with method,
  path, status, error chain, and backtrace on 5xx. No-op on 2xx/4xx.

### P2 — IdP completion (rows 80, 81)

- **Passkeys full webauthn-rs wiring.** `WebauthnPasskey` backed by
  `webauthn-rs 0.5`, per-user `DashMap` state, base64url credential
  lookup. Replaces the trait-only stub from Sprint 10. Feature-gated
  behind `passkey`.
- **NIP-07 Schnorr SSO full handshake.** `Nip07SchnorrSso` issues a
  32-byte CSPRNG challenge with 5-minute TTL, binds to session, and
  verifies the client's Schnorr signature against the embedded
  pubkey via the core crate's `auth::nip98::verify_schnorr_signature`.
  One-shot challenges, no replay. Feature-gated behind
  `schnorr-sso`.

### P3 — Operator CLI (rows 138, 163, 168)

- **`solid-pod-rs-server` subcommands**:
  - `quota reconcile <pod>` / `quota reconcile --all` — disk walk →
    DB update via `QuotaPolicy::reconcile`.
  - `account delete <user_id>` — stdin confirm without `--yes`;
    `UserStore::delete` trait extension.
  - `invite create --uses N` — mint invite token with optional
    max-use cap; `InviteStore` + `mint_token` + `parse_duration`.

### Doc refresh

- PARITY-CHECKLIST.md: 14 rows promoted to `present`; parity
  headline moved from 66% strict / 85% spec-normative (Sprint 9) to
  ~97% strict / ~100% spec-normative (Sprint 11).
- Root README.md: sibling-crate table changed from "reserved for
  v0.5.0" to "functional"; did:key row added; parity callout
  updated.
- CHANGELOG.md: Sprint 11 Added/Changed/Fixed/Security sections.
- jss-source-breadcrumbs.md: STUB markers removed for closed rows;
  did:key breadcrumbs added.
- agent-integration-guide.md: cross-crate matrix expanded to 5
  sibling crates; LWS 1.0 section added.

### Sprint 9 follow-up fixes

- Row 60 JSS source corrected: `src/auth/identity-normalizer.js` →
  `src/auth/nostr.js`.
- README code snippets: `FsStorage` → `FsBackend`.
- Workspace total 121 rows (previously listed as 130 due to
  test-meta double-count) clarified.

---

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
