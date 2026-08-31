# ADR-058: JSS v0.0.60–v0.0.71 Feature Drift Analysis

**Status**: Accepted
**Date**: 2026-05-06
**Supersedes**: Sprint 11 close (ADR-057)

## Context

JSS shipped 12 releases (v0.0.60–v0.0.71) since our Sprint 11 freeze
(2026-04-24). These releases span 4,184 insertions across 24 files,
introducing security hardening, ActivityPub federation improvements,
error pages, and operator surface enhancements. This ADR maps every
observable drift item, assigns bounded contexts (DDD), and feeds the
Sprint 12 PRD.

## Drift Inventory

### Security Hardening (6 commits — P0/P1)

| JSS commit | Feature | Impact | Our status | Priority |
|---|---|---|---|---|
| `1feead2` | Minimum password length validation (IdP) | CWE-521: weak password | **gap** — our `argon2` login accepts any length | P1 |
| `204fdfb` | `safeJsonParse` in WAC ACL parser (size-capped, catches parse bombs) | CWE-400: DoS | **gap** — our `serde_json::from_slice` has no size cap at ACL parse boundary | P0 |
| `2569811` | Iterative `..` sanitization for podName in subdomain mode | CWE-22: path traversal | **present** — `is_file_like_label` + our guard strips `..` but single-pass; need iterative | P0 |
| `b10ad65` | DPoP jti replay cache (Map-based with periodic cleanup) | replay attack | **present** — row 64 `JtiReplayCache` LRU 10K + 5-min TTL, already ahead | — |
| `4dbf039` | Block requests on DNS resolution failure (SSRF) | SSRF bypass via DNS errors | **partial** — `resolve_and_check` returns Err but caller may not short-circuit on ResolveFailed | P1 |
| `0b1b5b4` | Path traversal fix in git handler (iterative `..` removal + prefix check) | CWE-22 | **present** — row 100 `guard::path_safe` does canonicalize + starts_with, stronger than JSS | — |

### ActivityPub Federation (8 commits — P2)

| JSS commit | Feature | Impact | Our status | Priority |
|---|---|---|---|---|
| `25fa813` (v0.0.67) | Outbox POST — create Note + deliver to followers | AP interop | **partial** — our `handle_outbox` stamps activities but lacks direct Note→Create wrapping + delivery in POST path | P2 |
| `8247293` (v0.0.65) | User-Agent header on AP federation fetches | federation etiquette | **gap** — our `DeliveryWorker` uses bare `reqwest::Client` | P2 |
| `03aec0d` (v0.0.64) | AP federation fixes (multiple) | stability | need audit against our `inbox.rs` / `delivery.rs` | P2 |
| `d5a82a8` | Cloudflare `cf-visitor` header for protocol detection | proxy compat | **gap** — our actor/outbox URL construction doesn't check `cf-visitor` | P3 |
| `6f58d9a` | AP actor handler: shared state instead of scoped decoration | architecture | N/A — different framework | — |
| `929ca9c` | AP route not blocking LDP profile serving | architecture | N/A — our library-first design avoids this class of bug | — |
| `0837ee2` (v0.0.62) | ActivityPub CLI options (`--ap-username`, `--ap-display-name`, `--ap-summary`, `--ap-nostr-pubkey`) | operator | **gap** — our config has no AP-specific CLI/env knobs | P3 |
| `bfc37db` | Dedicated route for AP profile (content-negotiation) | conneg | **partial** — our `Actor::render_actor` exists but binder doesn't negotiate Accept for AP vs LDP on `/profile/card` | P2 |

### Identity Provider (2 commits — P1/P2)

| JSS commit | Feature | Impact | Our status | Priority |
|---|---|---|---|---|
| `32c0db2` (v0.0.69) | Allow `.account` in dotfile filter for IdP login | IdP functionality | **gap** — our `DotfileAllowlist` has `.acl`, `.meta`, `.well-known`, `.quota.json` but not `.account` | P1 |
| `1feead2` | Min password length (8 chars) | see Security above | see above | P1 |

### Error Pages / Mashlib (4 commits — P3)

| JSS commit | Feature | Impact | Our status | Priority |
|---|---|---|---|---|
| `ae796d0` (v0.0.68) | Beautiful 401/403 HTML error pages | UX | **wontfix-in-crate** — consumer binder concern, but we should provide a helper | P3 |
| `d995810` (v0.0.71) | Mashlib for 401 pages when enabled | UX | **wontfix-in-crate** | — |
| `52583f9` | Fix 401 error page infinite loop | bug fix | N/A — we don't serve HTML error pages | — |
| `4aa9b2e` (v0.0.70) | Fix 401 page login link | bug fix | N/A | — |

### Platform (3 commits — explicitly-deferred)

| JSS commit | Feature | Impact | Our status | Priority |
|---|---|---|---|---|
| `6d58cc4` (v0.0.60) | Android/Termux support, bcryptjs fallback | mobile | **N/A** — Rust cross-compiles natively; no JS fallback needed | — |
| `be82d7e` (v0.0.63) | sql.js fallback for Android/WASM | mobile | **N/A** — sqlx compiles to all targets | — |
| `07b08bb` | Termux installer script | distribution | **N/A** — cargo install handles this | — |

### Design Docs (informational)

| JSS commit | Feature | Our status |
|---|---|---|
| `837f984` | Nostr-Solid browser extension design doc | No action — design doc only, no implementation landed |

## Bounded Context Assignment (DDD)

```
┌─────────────────────────────────────────────────────────┐
│ BC: Security Primitives                                  │
│ Aggregate: SsrfPolicy, DotfileAllowlist, JsonParseGuard │
│ Events: DnsResolutionFailed, OversizedPayloadRejected    │
│ Files: security/ssrf.rs, security/dotfile.rs, wac/parser │
│ Items: safeJsonParse, iterative sanitize, DNS block,     │
│        .account allowlist                                │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ BC: Identity Provider                                    │
│ Aggregate: Credentials, PasswordPolicy                   │
│ Events: WeakPasswordRejected                             │
│ Files: solid-pod-rs-idp/src/credentials.rs               │
│ Items: min password length validation                    │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ BC: ActivityPub Federation                               │
│ Aggregate: OutboxHandler, DeliveryWorker, ActorProfile   │
│ Events: NoteCreated, DeliveryAttempted                   │
│ Files: solid-pod-rs-activitypub/src/{outbox,delivery,    │
│        actor,discovery}.rs                               │
│ Items: outbox POST create, User-Agent, cf-visitor,       │
│        AP config knobs, Accept-negotiated actor          │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ BC: Config / Operator Surface                            │
│ Aggregate: ServerConfig, ExtrasConfig                    │
│ Files: config/schema.rs, config/sources.rs               │
│ Items: AP CLI options, error page helper (optional)      │
└─────────────────────────────────────────────────────────┘
```

## Decision

Sprint 12 implements all P0 and P1 items (6 items), plus P2 AP
federation improvements (4 items). P3 items (error pages, AP CLI,
cf-visitor) are documented but deferred to Sprint 13.

## New Parity Rows

| Row | Feature | BC | Priority |
|---|---|---|---|
| 169 | `safeJsonParse` equivalent — size-capped ACL parsing | Security | P0 |
| 170 | Iterative `..` sanitization in subdomain resolver | Security | P0 |
| 171 | DNS resolution failure → request block in SSRF | Security | P1 |
| 172 | `.account` in dotfile allowlist | Security | P1 |
| 173 | Minimum password length validation (8 chars) | IdP | P1 |
| 174 | AP outbox POST (Note → Create wrapping + delivery) | AP | P2 |
| 175 | User-Agent header on AP federation fetches | AP | P2 |
| 176 | AP actor Accept-negotiation (AP JSON-LD vs LDP Turtle) | AP | P2 |
| 177 | Cloudflare `cf-visitor` protocol detection | AP | P3 |
| 178 | AP CLI/env config knobs | Config | P3 |
| 179 | HTML error page helper (401/403) | Config | P3 |

## Consequences

- 11 new rows bring tracker to 132 total
- P0+P1 implementation (6 items) is security-critical
- P2 AP items (4 items) complete federation interop
- Estimated effort: 1 sprint (10 items, ~2,000 LOC)
- Parity after Sprint 12: ~98% strict (assuming P0-P2 land)
