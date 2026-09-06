# solid-pod-rs-activitypub

**Status: 0.5.0-alpha.9 — functional ActivityPub federation crate.**

Rust port of the JSS ActivityPub surface (`JavaScriptSolidServer/src/ap/*`).
4,453 LOC across 9 modules; 53 tests. Integrators may take a dependency
today.

## What ships

| Module | Responsibility |
|--------|---------------|
| `actor` | Actor document rendering + `negotiate_actor_format()` (Accept-negotiation between `application/activity+json` and LDP profiles). |
| `inbox` | `POST /inbox` handling with HTTP Signature verification (draft-cavage-http-signatures v12). |
| `outbox` | `handle_outbox()` (pre-formed activities) + `handle_outbox_post()` (raw Notes auto-wrapped in `Create`). Follower fan-out delivery. |
| `delivery` | HTTP Signature signing, SHA-256 digest headers, exponential retry, `enqueue_to_inboxes()` batch helper. |
| `http_sig` | `HttpSignatureVerifier` + `HttpActorKeyResolver` implementing draft-cavage v12 over RSA-SHA256. |
| `store` | SQLite-backed follower/following/outbox/delivery-queue persistence. Actor cache with 24-hour freshness. |
| `error` | Typed error hierarchy (`InboxError`, `OutboxError`, `DeliveryError`, `StoreError`). |
| `webfinger` | AP-specific WebFinger JRD rendering. |
| `nodeinfo` | NodeInfo 2.1 document emission. |

## Federation flow

```mermaid
sequenceDiagram
    participant Author as Author (Local)
    participant Outbox as Outbox Handler
    participant Store as SQLite Store
    participant DQ as Delivery Queue
    participant Remote as Remote Inbox

    Author->>Outbox: POST /outbox
    Note over Outbox: Raw Note or Content-only body?
    Note over Outbox: Auto-wrap in Create activity

    Outbox->>Outbox: Stamp UUID id + actor + published
    Outbox->>Store: record_outbox(activity)
    Store-->>Outbox: activity_id

    Outbox->>Store: follower_inboxes(actor)
    Store-->>Outbox: [inbox_a, inbox_b, ...]

    loop Each follower inbox
        Outbox->>DQ: enqueue_delivery(id, inbox)
    end

    Outbox-->>Author: 201 Created + OutboundDelivery

    Note over DQ: Async delivery with retry

    loop Delivery worker
        DQ->>DQ: Sign request (HTTP Sig draft-cavage v12)
        DQ->>DQ: SHA-256 Digest header
        DQ->>Remote: POST /inbox (signed)
        alt 2xx
            DQ->>Store: mark delivered (drop queue item)
        else 5xx / 408 / 429 / network error
            DQ->>DQ: Backoff schedule 30s → 2m → 10m → 1h → 6h → 24h,<br/>then permanent failure
        else other 4xx
            DQ->>Store: permanent failure — drop, no retry
        end
    end

    Note over DQ,Remote: SSRF guard — deliveries to private-IP /<br/>metadata-endpoint inboxes are dropped
```

```mermaid
flowchart LR
    REQ["Inbound request<br/>Accept header"] --> NEG{"negotiate_actor_format()"}
    NEG -->|"activity+json<br/>ld+json (profile=activitystreams)"| AJ["ActivityJson<br/>AP Actor document"]
    NEG -->|"text/turtle<br/>application/n-triples<br/>*/*"| LDP["LdpProfile<br/>WebID profile doc"]

    style REQ fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style AJ fill:#e67e22,stroke:#bf6516,color:#fff
    style LDP fill:#2ecc71,stroke:#1a9850,color:#fff
```

## Parity rows

Rows closed by this crate (see
[`../solid-pod-rs/PARITY-CHECKLIST.md`](../solid-pod-rs/PARITY-CHECKLIST.md)):

- **102** — ActivityPub Actor discovery.
- **103** — inbox with HTTP Signature verification.
- **104** — outbox emission.
- **105** — Follow / Accept / Undo handling.
- **106** — Create activity delivery.
- **107** — Follower + Following collections.
- **108** — ActivityPub conformance subset.
- **131** — NodeInfo 2.0 (AP-specific fields).

Sprint 12 additions (JSS v0.0.60–v0.0.71 delta):

- **169** — Outbox POST with Note→Create wrapping.
- **170** — Accept-negotiation for actor profiles.
- **171** — Actor cache with freshness check.
- **172** — `enqueue_to_inboxes()` batch delivery.

## Sprint 12 changes

- `handle_outbox_post()` — accepts `Note`, pre-formed Activity, or
  content-only body. Notes are auto-wrapped in `Create` with UUID IDs
  and ISO 8601 timestamps. Matches JSS v0.0.67 outbox behaviour.
- `negotiate_actor_format(accept: &str)` — returns `ActorFormat::ActivityJson`
  or `ActorFormat::LdpProfile` based on the request `Accept` header.
- `Store::cache_actor()` / `get_cached_actor()` / `is_actor_cache_fresh()`
  — 24-hour chrono-based freshness window.
- `enqueue_to_inboxes()` — batch delivery helper.
- User-Agent updated to `solid-pod-rs-activitypub/0.4.0`.

## JSS references

- `src/ap/index.js`
- `src/ap/routes/inbox.js`
- `src/ap/routes/outbox.js`
- `src/ap/store.js`
- `src/ap/keys.js`

## Licence

AGPL-3.0-only.
