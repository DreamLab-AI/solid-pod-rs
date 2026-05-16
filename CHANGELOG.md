# Changelog

All notable changes to solid-pod-rs will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.4.0-alpha.11] — 2026-05-16 — JSS Phase 1 port

Implements the three Phase 1 features shipped by JSS v0.0.190 (May
2026, issue #437). All three feature flags are default-off so existing
consumers see no surface change unless they opt in. Type shapes
declared in the alpha.10 scaffold (`KeyProvisioningOutcome`,
`KeyProvisioningPlan`, `PodExportBundle`, `PodExportEntry`,
`ExportOptions`) are preserved as ABI — downstream crates (NRF,
dreamlab-ai-website) can import unchanged.

### Added

- **`provision-keys` feature** (`solid-pod-rs-idp`, default-off,
  parity row 196). `key_provisioning::provision_pod_keys` generates a
  BIP-340 Schnorr secp256k1 keypair, NIP-19 bech32-encodes `npub` and
  `nsec` (hand-rolled bech32 encoder — no new dependency on `bech32`),
  writes `/private/privkey.jsonld` and an owner-only JSON-LD ACL
  sibling, and patches the WebID `/profile/card` JSON-LD island to
  include the `nostr:pubkey` triple. Accepts deterministic entropy
  for test reproducibility. Depends on `solid-pod-rs/did-nostr` +
  core's `nip98-schnorr` + `dep:k256`. 3 integration tests cover
  deterministic seeding, ACL evaluator round-trip, and WebID patching
  idempotency.
- **`nip05-endpoint` feature** (`solid-pod-rs` + `solid-pod-rs-server`,
  default-off, parity row 197). Wires `GET /.well-known/nostr.json?name=<local>`.
  Validates the NIP-05 local-part regex, resolves `_` → `/profile/card`
  and `<name>` → `/<name>/profile/card`, extracts `nostr:pubkey` from
  the JSON-LD data island via the new `webid::extract_nostr_pubkey`
  helper, returns `application/json` with `Access-Control-Allow-Origin: *`.
  5 actix-test integration tests in `solid-pod-rs-server`.
- **`export-jsonld` feature** (`solid-pod-rs`, default-off, parity row
  198). `export::export_pod_jsonld` walks the pod tree, excludes
  `/private/*` by default, opt-in via `ExportOptions::include_private`,
  base64-encodes each resource body (binary-safe), sorts entries
  ascending by `created` (mirrored from `modified` on backends that
  don't track creation separately). Bundle envelope carries
  `@context = "https://solid-pod-rs.dev/ns/export/v1"`. 3 integration
  tests cover default exclusion, opt-in inclusion, and time-chain
  ordering.
- **`webid::extract_nostr_pubkey`** helper (always available) — locates
  the `nostr:pubkey` triple inside a WebID's JSON-LD data island.
  Mirrors `extract_oidc_issuer` semantics; returns `Ok(None)` when
  absent.

### Changed

- **`PARITY-CHECKLIST.md`**: rows 196–198 promoted from `scheduled` to
  `present` (Phase 1 port). Tally restored to ~98% strict parity
  (129/135). Row 128 (NIP-05) updated — builder primitives still ship
  as `net-new`; the pod-resident server route lands via row 197.
- **`solid-pod-rs-idp/Cargo.toml`**: added `bytes` to direct
  dependencies (was transitive through `solid-pod-rs`); the
  `provision-keys` feature flag inherits `solid-pod-rs/did-nostr` plus
  `dep:k256`.

### Cross-repo consumer chain

- **NRF (nostr-bbs forum primitive)**: now upgradable to alpha.11 —
  the `KeyProvisioningOutcome` shape is stable; NRF can opt into the
  `provision-keys` feature for its registration flow.
- **dreamlab-ai-website**: can call `export_pod_jsonld` via the
  `export-jsonld` feature for "download my data" surfaces.

### Upgrade path (alpha.10 → alpha.11)

No breaking changes to default-feature builds. Consumers who pinned
`solid-pod-rs = "0.4.0-alpha.10"` bump the patch component; struct
literals constructing `ProvisionPlan` will gain a new optional
`provision_keys` field gated on the `provision-keys` feature — only
visible when the consumer enables that flag.

## [BIP-340 Schnorr Fix] - 2026-05-12

### Fixed

- **NIP-98 BIP-340 Schnorr pre-hashing mismatch (BREAKING).** The
  Schnorr signature verifier in `auth::nip98::verify_schnorr_signature`
  was calling `vk.verify()` (the k256 `Verifier` trait method, which
  applies an extra SHA-256 tagged hash per the k256 Verifier trait
  semantics) instead of `vk.verify_raw()` (BIP-340 correct, raw 32-byte
  message). This caused signature verification to fail against any
  standard Nostr client that signs per BIP-340 (raw event-id bytes),
  breaking SSO interoperability with the nostr-bbs relay and forum.
  The fix switches to `verify_raw()` for verification and `sign_raw()`
  for test fixture signing. The k256 `signature::Verifier` trait import
  is no longer used.
- Test and bench fixtures updated to use `sk.sign_raw(&id_bytes,
  &[0u8; 32])` instead of `sk.sign()`, matching the BIP-340 raw
  signing convention: `tests/cid_verifier_sprint11.rs`,
  `tests/nip98_extended.rs`, `tests/oidc_integration.rs`,
  `benches/nip98_verify_bench.rs`.

## [Security Audit Sprint] - 2026-05-11

DreamLab ecosystem-wide security audit. 8 fixes applied to solid-pod-rs
covering P0 critical, P1 high, P2 medium, and Round 2 P0 findings.

### Security

- **P0-07**: HTTP signature Date header freshness check enforced at +/-5
  minutes in http_sig.rs, rejecting replayed signatures with stale
  timestamps that previously passed verification indefinitely
- **P0-08**: SSRF guard added to actor key resolver in http_sig.rs and
  new ssrf.rs module, blocking requests to RFC-1918 private addresses,
  link-local, loopback, and metadata endpoints when resolving remote
  ActivityPub actor keys
- **P0-09**: SSRF guard added to ActivityPub delivery outbound POST in
  delivery.rs, applying the same private-address blocklist to prevent
  the server from being used as an HTTP proxy to internal services
- **R2-P0-04**: IPv4-compatible IPv6 SSRF bypass fixed in ssrf.rs;
  addresses like ::ffff:10.0.0.1 and ::ffff:127.0.0.1 now correctly
  resolve to their IPv4 equivalents before the private-range check
- **R2-P0-05**: Same IPv4-in-IPv6 fix applied in the ActivityPub SSRF
  module (activitypub ssrf.rs), plus 6to4 (2002::/16) address bypass
  blocked

### Fixed

- **P1-25**: WAC PATCH operations now require Write permission instead of
  Append in server lib.rs, matching the Solid Protocol specification
  where PATCH replaces resource content
- **P1-26**: Passkey credential counter updated on successful
  authentication in passkey.rs, enabling clone detection per the
  WebAuthn specification
- **P2-09**: Notification buffer bounded to 10,000 entries in
  notifications/mod.rs, preventing unbounded memory growth from
  slow or disconnected subscribers
