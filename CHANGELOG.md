# Changelog

All notable changes to solid-pod-rs will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
