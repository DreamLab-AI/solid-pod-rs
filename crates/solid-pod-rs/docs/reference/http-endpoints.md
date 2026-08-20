# HTTP endpoint reference

The `solid-pod-rs` core library is framework-agnostic. The workspace also
ships the Actix-based `solid-pod-rs-server` binary. This page describes the
protocol surface implemented by
[`solid-pod-rs-server/src/lib.rs`](../../../solid-pod-rs-server/src/lib.rs)
and the reusable LDP handlers in the core crate.

## Method matrix

| Path kind                    | GET | HEAD | PUT | POST | DELETE | PATCH |
|------------------------------|-----|------|-----|------|--------|-------|
| Pod root `/`                 | ✓ container | ✓ | ✗ 405 | ✓ | ✗ 405 | ✗ 405 |
| Container `/c/`              | ✓ container | ✓ | ✗ 405 | ✓ | ✓ if empty | ✗ 405 |
| Resource `/c/r`              | ✓ body | ✓ | ✓ | ✗ 405 | ✓ | ✓ N3 or SPARQL |
| ACL sidecar `/c/r.acl`       | ✓ | ✓ | ✓ (acl:Control required) | ✗ | ✓ | ✗ |
| Meta sidecar `/c/r.meta`     | ✓ | ✓ | server-managed | ✗ | ✗ | ✗ |
| `.well-known/openid-configuration` | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |
| `.notifications`             | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |
| `.notifications/websocket`   | ✗ | ✗ | ✗ | ✓ (subscribe) | ✗ | ✗ |
| `.notifications/webhook`     | ✗ | ✗ | ✗ | ✓ (subscribe) | ✗ | ✗ |
| `/.well-known/solid`         | partial (OIDC discovery only) | | | | | |

## Response status codes

| Code | Use |
|---|---|
| 200 OK | `GET` / `HEAD` success |
| 201 Created | `PUT` (new resource) or `POST` (Slug → child) |
| 204 No Content | `DELETE`, successful `PATCH` |
| 400 Bad Request | Malformed body, invalid path, base64/hex/JSON decode error |
| 401 Unauthorized | Missing or invalid NIP-98 / OIDC token (send `WWW-Authenticate`) |
| 403 Forbidden | ACL evaluator denied |
| 404 Not Found | `PodError::NotFound` |
| 405 Method Not Allowed | See matrix |
| 409 Conflict | `PodError::AlreadyExists` — usually only for idempotent-create semantics |
| 412 Precondition Failed | N3 PATCH `where` clause missed, or `If-Match` mismatch |
| 415 Unsupported Media Type | Unknown `Content-Type` for resource kind or PATCH |
| 500 Internal Server Error | I/O, backend, or `PodError::Backend` |

See [reference/error-codes.md](error-codes.md) for the `PodError` →
status mapping.

## Response headers (per method / path kind)

### All non-error responses

- `Link` — see [reference/link-headers.md](link-headers.md).
- `WAC-Allow` — derived via `wac::wac_allow_header`. Shape
  `user="…", public="…"`.
- `ETag` — strong validator on resource bodies (SHA-256 hex).
- `Accept-Post` — on containers: `text/turtle, application/ld+json,
  application/n-triples` (`ldp::ACCEPT_POST`).
- `Content-Type` — passed through from `ResourceMeta.content_type` for
  resources; `application/ld+json` or the negotiated RDF format for
  containers.

### `401`

```
WWW-Authenticate: Nostr
WWW-Authenticate: DPoP algs="ES256 RS256"
```

## Request headers the server honours

| Header | Effect |
|---|---|
| `Authorization: Nostr <b64>` | NIP-98 authentication — `auth::nip98::verify`. |
| `Authorization: DPoP <token>` | Solid-OIDC access token (feature `oidc`). |
| `DPoP` | DPoP proof — `oidc::verify_dpop_proof`. |
| `Content-Type` | Stored verbatim on `PUT`; selects PATCH dialect (`text/n3` or `application/sparql-update`). |
| `Accept` | Drives RDF format for container GET — `ldp::negotiate_format`. |
| `Prefer` | Controls container representation — `ldp::PreferHeader::parse`. See [reference/prefer-headers.md](prefer-headers.md). |
| `Slug` | On `POST` to container: UTF-8 child name. Rejected if contains `/` or `..`. |
| `If-Match` / `If-None-Match` | P2 item — the storage layer returns canonical ETags; middleware enforces. |

## Path conventions

- Container paths end with `/`; resources do not.
- ACL sidecar for a resource `/c/r` lives at `/c/r.acl`.
- ACL sidecar for a container `/c/` lives at `/c/.acl`.
- Meta sidecar for `/c/r` lives at `/c/r.meta`.
- Pod root ACL lives at `/.acl`.
- Root path `/` is always a container.
- Paths are resolved case-sensitive.
- Backends MUST reject paths containing `..` or `\0`.

## Slug semantics on POST

```rust
pub fn resolve_slug(container: &str, slug: Option<&str>) -> String;
```

- If `slug` is `Some(s)` and `s` is non-empty, contains no `/`, and
  contains no `..`: append `s` to `container`.
- Otherwise: append a fresh UUID v4.

## Discovery endpoints

### `GET /.well-known/openid-configuration`

Feature `oidc` required. Build with `oidc::discovery_for(issuer)`.

### `GET /.notifications`

Returns the subscription-discovery JSON-LD document. Build with
`notifications::discovery_document(pod_base)`.

```json
{
  "@context": ["https://www.w3.org/ns/solid/notifications-context/v1"],
  "id":            "https://pod.example/.notifications",
  "channelTypes": [
    { "id": "WebSocketChannel2023", "endpoint": ".../websocket", "features": ["as:Create","as:Update","as:Delete"] },
    { "id": "WebhookChannel2023",   "endpoint": ".../webhook",   "features": ["as:Create","as:Update","as:Delete"] }
  ]
}
```

## Payment (HTTP 402) economy endpoints

Present in the `solid-pod-rs-server` binary, mounted unconditionally next
to the always-on `/pay/.info` discovery route (there is no payments
feature flag). Backed by `handlers::pay` and the `solid-pod-rs`
`payments` / `trading` core. Every route except `.info`, `.offers`,
`.address`, and `GET /pay/.pool` requires NIP-98 auth (resolved to
`did:nostr:<pubkey>`); an unauthenticated call to a gated route gets
`401` with `{"error":"NIP-98 authentication required"}`. See
[explanation/payments-and-web-ledger.md](../explanation/payments-and-web-ledger.md).

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET  | `/pay/.info`          | none   | Payment discovery (cost, chains, pay-token). |
| GET  | `/pay/.balance`       | NIP-98 | The caller's Web-Ledger balance — `{did, balance, cost, unit}`. |
| POST | `/pay/.deposit`       | NIP-98 | Credit a deposit. TXO body (`"<txid>:<vout>"` / `{"txo":…}`) or MRC20 body (`{"type":"mrc20", state, prevState, anchor}`, mempool-verified). Replay-guarded. |
| GET  | `/pay/.address`       | none   | Derive a deposit address. `?user=<did:nostr:…>&chain=<id>` for a per-user tweaked address; both optional. |
| GET  | `/pay/.offers`        | none   | List open sell orders. Optional `?sell=<cur>&buy=<cur>`. |
| POST | `/pay/.sell`          | NIP-98 | Place a sell order (`sell_currency`, `sell_amount`, `buy_currency`, `price`). |
| POST | `/pay/.swap`          | NIP-98 | Execute against an open order (`{id}`). |
| GET  | `/pay/.pool`          | none   | AMM pool state. `?a=<cur>&b=<cur>` for one pool, else the registry. |
| POST | `/pay/.pool`          | NIP-98 | AMM op — `action` ∈ `swap` / `add-liquidity` / `remove-liquidity`. |
| POST | `/pay/.buy`           | NIP-98 | Primary market — buy the pod's pay-token with sats. |
| POST | `/pay/.withdraw`      | NIP-98 | Withdraw a sat balance as portable MRC20 tokens (+ proof). |
| POST | `/pay/.withdraw-sats` | NIP-98 | Withdraw sats as a fresh TXO voucher. |

The order book (`/pay/.sell` / `.swap` / `.offers`) and the
constant-product AMM (`/pay/.pool`) are live and routed. `.buy` /
`.withdraw` / `.withdraw-sats` exercise the Bitcoin write-side
(`bitcoin_tx`, feature `mrc20`): the balance is debited only after a
successful broadcast.

## Provenance (`_prov`) endpoints

Present when built with `--features git`. Expose the git-mark +
block-trail provenance primitives (ADR-059). The `_prov` routes register
*before* the LDP catch-all so `_prov` segments are never treated as pod
resources. See
[explanation/provenance-and-trust-ledger.md](../explanation/provenance-and-trust-ledger.md).

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET  | `/{pod}/{path}.prov.ttl`     | per ACL | PROV-O git-mark sidecar for a resource (served by the ordinary LDP read path; WAC-gated like any resource). |
| GET  | `/{pod}/_prov/{commit_sha}`  | per ACL | Resolve a git-mark commit SHA → resource + `ProvenanceMark` (inlines the sidecar, incl. any anchor). |
| POST | `/{pod}/_prov/anchor`        | NIP-98 (pod owner), payment-gated | Upgrade an existing git-mark (`{commit_sha, ticker?}`) to a Bitcoin block-trail anchor. Debits the configured anchor price; refunds on anchor failure. |

## Git smart-HTTP endpoints

Present when built with `--features git`. The git smart-protocol routes
are **WAC-gated** (ADR-059 D6 — closing the prior anonymous clone/push
hole): `handle_git` resolves the caller's `did:nostr` from the git
`Basic nostr:` / `Nostr` NIP-98 credential and enforces `acl:Read` for
clone/fetch and `acl:Write` for push against the pod-root container ACL.
A public pod clones anonymously; a private pod replies `401` so the git
client retries with credentials; anonymous/unauthorised push is denied.
A first push to a not-yet-initialised git-backed pod auto-runs
`git init -b main` (replacing the prior 404-on-missing-repo).

| Method | Path | Purpose |
|---|---|---|
| GET  | `/{tail}/info/refs`          | Smart-protocol ref advertisement (clone/fetch — Read). |
| POST | `/{tail}/git-upload-pack`    | Fetch negotiation (clone/fetch — Read). |
| POST | `/{tail}/git-receive-pack`   | Push (Write). |

## Admin / provisioning endpoints

These endpoints are only present in the `solid-pod-rs-server` binary and
require the `git` feature (or the standalone binary build with admin routes
compiled in).  They are **not** part of the core library surface.

### `POST /_admin/provision/{pubkey}`

Creates a new pod for the given owner public key.

| Attribute | Value |
|---|---|
| Auth | PSK — `X-Pod-Admin-Key: <secret>` header. Requests without a valid key receive `403 Forbidden`. The key must match `SOLID_ADMIN_KEY` / `--admin-key`. |
| Feature gate | Compiled only when `--features git` is passed (or the default server build that includes it). |
| Path parameter | `pubkey` — hex-encoded Nostr/secp256k1 public key of the future pod owner. |
| Request body | None. |

**Response `200 OK`:**

```json
{ "podUrl": "https://pods.example.com/<pubkey>/", "ok": true }
```

**What it does:**

1. Creates the pod directory under the configured storage root.
2. Writes an owner-only `.acl` granting full control to the pubkey.
3. Runs `git init -b main` and sets `receive.denyCurrentBranch=updateInstead`
   so the pod directory is a bare-ish working-tree repo that can receive
   `git push` over HTTP via `/_git/{pubkey}/`.

**Error responses:**

| Code | Condition |
|---|---|
| `400 Bad Request` | `pubkey` is not valid hex or fails secp256k1 key validation. |
| `403 Forbidden` | Missing or incorrect `X-Pod-Admin-Key`. |
| `409 Conflict` | Pod directory already exists. |
| `500 Internal Server Error` | I/O error or `git init` failure. |

**Security note:** This endpoint is intended for the CF Workers ↔ agentbox
handshake only.  Bind the server to a non-public interface or protect it
with a firewall; the PSK is a defence-in-depth measure, not a public API.

## Git Control Panel endpoints

Present only when built with `--features git`.

### `OPTIONS /_git/{pubkey}/{tail}`

CORS preflight handler for the Git HTTP smart-protocol routes used by the
forum's VS Code-style Source Control panel.

| Attribute | Value |
|---|---|
| Auth | None — OPTIONS responses are unauthenticated by design. |
| Feature gate | `git` feature. |
| Path | `/_git/{pubkey}/{tail}` — matches any sub-path under a pubkey's git namespace. |
| Request body | None. |

**Response `204 No Content`** with the following headers:

```
Access-Control-Allow-Origin:  <origin> | *
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization, X-Pod-Admin-Key
Access-Control-Max-Age:       86400
```

The `Access-Control-Allow-Origin` value is determined by the
`SOLID_ALLOWED_ORIGINS` / `--allowed-origins` list.  If the request
`Origin` is present in the allowlist it is echoed back verbatim;
otherwise `*` is returned when the allowlist is empty (dev default).
When the allowlist is non-empty and the origin is not on it, `*` is
**not** returned — the header is omitted so the browser blocks the
preflight.

## See also

- [reference/api.md](api.md) — the Rust API backing each endpoint.
- [reference/link-headers.md](link-headers.md)
- [reference/prefer-headers.md](prefer-headers.md)
- [reference/content-types.md](content-types.md)
- [reference/patch-semantics.md](patch-semantics.md)
