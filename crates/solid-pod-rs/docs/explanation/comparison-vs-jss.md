# Comparison vs JSS

JSS — [JavaScriptSolidServer](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer)
— is a JavaScript implementation of the Solid Protocol, licensed
AGPL-3.0-only and maintained by the JavaScriptSolidServer
contributors. This page compares solid-pod-rs to JSS across runtime,
protocol support, operations, and extensibility. It is meant to set
expectations for operators evaluating a migration and to help
contributors understand where the two implementations diverge.

See also [PARITY-CHECKLIST.md](../../PARITY-CHECKLIST.md) for a
feature-level status table.

## At a glance

|                                | JSS 0.0.220 (`f9f7a4d`) | solid-pod-rs 0.5.0-alpha.7 |
|--------------------------------|-----------------------|---------------------------|
| Language                       | JavaScript (Node 18+) | Rust 2021 / MSRV 1.88     |
| Binary distribution            | `npm install -g javascript-solid-server` → `jss` | Build from source; drop-in crate |
| Licence                        | AGPL-3.0-only         | AGPL-3.0-only (inherited) |
| HTTP framework                 | Fastify               | Agnostic; actix/axum/hyper|
| Configuration                  | `JSS_*` env vars + optional config | Typed library config plus server JSON/TOML/env loader |
| Memory footprint (idle)        | Not re-benchmarked in this audit | Not re-benchmarked in this audit |
| Startup time                   | Not re-benchmarked in this audit | Not re-benchmarked in this audit |

## Protocol coverage

| Feature                                 | JSS       | solid-pod-rs |
|-----------------------------------------|-----------|---------------|
| LDP RDF + non-RDF GET/PUT/DELETE        | full      | full          |
| LDP container GET                       | full      | full          |
| LDP Slug→child via POST                 | full      | full          |
| `Prefer` header parsing                 | not first-class | full include/omit composition |
| Content negotiation (Turtle/JSON-LD/N-Triples/RDF-XML) | full | Turtle/JSON-LD/N-Triples full; RDF-XML partial (negotiated, serialisation deferred) |
| `Link`: type, acl, describedby, storage | full      | full          |
| Strong ETag (SHA-256)                   | optional  | always        |
| If-Match enforcement                    | full      | full          |
| Range requests                          | full      | full          |
| `WAC-Allow` header                      | full      | full          |
| WAC agent / agentClass / agentGroup     | full      | full          |
| `.acl` walk-up resolution               | full      | full          |
| JSON Patch (RFC 6902)                   | not implemented | full (Rust extension) |
| N3 PATCH (solid-protocol)               | full      | full          |
| SPARQL-Update PATCH                     | full      | subset (INSERT DATA, DELETE DATA, DELETE/INSERT WHERE with ground templates) |
| Legacy `solid-0.1` WebSocket             | full      | full adapter  |
| Notifications 0.2 WebSocketChannel2023  | not implemented | full     |
| Notifications 0.2 WebhookChannel2023    | not implemented | full (3× retry, exponential backoff) |
| Solid-OIDC DPoP                         | full      | full (feature `oidc`)         |
| OIDC dynamic client registration        | full      | full          |
| OIDC discovery doc                      | full      | full          |
| Token introspection (RFC 7662)          | full      | full          |
| WebID extraction                        | full      | full          |
| WebID-TLS                               | feature-flagged (`webidTls`) | not supported (legacy) |
| NIP-98                                  | via Nostr relay feature | full (structural) |
| `.provision` / account scaffold         | full (IdP + multiuser) | full (`provision_pod`) |
| `.well-known/solid`                     | full      | full          |
| WebFinger / NIP-05                      | full (via ActivityPub + Nostr features) | full |
| Git smart-HTTP clone/push               | full      | full (**WAC-gated** — Read for fetch, Write for push; auto-init on first push) |
| HTTP 402 Web Ledger + `PaymentCondition`| full      | full          |
| `/pay/.balance` `.deposit` `.address`   | full      | full (TXO + mempool-verified MRC20; replay-guarded) |
| Order book (`/pay/.sell` `.swap` `.offers`) | full  | full (currency-pair model; routed) |
| AMM pool (`/pay/.pool`)                 | full      | full (constant-product `x·y=k`, 30 bps; routed) |
| Bitcoin write-side (`/pay/.buy` `.withdraw` `.withdraw-sats`) | full | full (P2TR / BIP-341 / BIP-340, byte-parity with `token.js`) |
| Block-trail / MRC20 anchor verify+build | full      | full (feature `mrc20`) |
| git-marks (write-as-commit provenance)  | n/a (JSS has no PROV sidecar) | net-new — every write → commit + PROV-O `.prov.ttl` |
| Generalised provenance trail + `_prov` API | n/a    | net-new (ADR-059 — git ↔ Bitcoin composition, epoch batching) |

## Defaults that differ (gotchas for JSS migrants)

### ACL posture

- **JSS default:** multiuser-enabled; pods created through the IdP
  signup flow receive a scaffolded `/.acl`. A `public: true` option
  disables WAC entirely for trusted single-user deployments.
- **solid-pod-rs:** deny-by-default, always. You cannot read a pod
  without an `.acl` being in effect somewhere up the tree. No runtime
  switch to disable WAC — it is a library invariant.

Mitigation: commit `/.acl` as the first write to any new pod. See
[tutorial 3](../tutorials/03-adding-access-control.md).

### Content-type storage

- **JSS:** stores the body as the client `PUT`s it, with a sidecar
  describing content type. Content-type negotiation at read time is
  opt-in via the `conneg` flag.
- **solid-pod-rs:** stores the body verbatim with its original
  `Content-Type`. No on-the-fly transcoding. If a client `PUT`s
  Turtle and another `GET`s with `Accept: application/ld+json`, we
  serve the stored Turtle with a 200 (client ignores Accept) —
  *unless* you wire up transcoding in your HTTP layer using the
  `Graph` primitives.

### PATCH dialect support

- **JSS:** supports N3 Patch and a SPARQL Update subset; it does not implement
  JSON Patch.
- **solid-pod-rs:** all three dialects supported; SPARQL-Update is a
  documented subset (INSERT DATA, DELETE DATA, DELETE/INSERT WHERE
  with ground templates only).

## Operational comparison

### Configuration

- **JSS:** `JSS_*` environment variables (e.g. `JSS_PORT`, `JSS_HOST`,
  `JSS_ROOT`) overlaid on an optional `config.json` file, overlaid on
  CLI arguments. Precedence: CLI > env > file > defaults.
- **solid-pod-rs:** the library is configured in Rust; the canonical server
  also has a typed layered runtime config loader with JSON/TOML and `JSS_*`
  environment aliases.

Pros and cons:

- JSS gives you runtime configurability; you can change the storage
  root without rebuilding. solid-pod-rs requires a rebuild to swap
  backends — but the build takes <2 s incremental and your whole
  server is a static binary.
- Rust configuration is type-checked. Misconfigurations show up at
  compile time, not on startup.

### Observability

- **JSS:** logs via Fastify's pino-based logger.
- **solid-pod-rs:** `tracing`. Structured JSON logs + spans.

### Monitoring

- **JSS:** emits logs; no built-in metrics exporter.
- **solid-pod-rs:** library does not export metrics itself; you
  instrument at the HTTP framework layer.

### Backup

- **JSS:** filesystem backup of `JSS_ROOT` (default `./data`) works.
- **solid-pod-rs:** filesystem backup of `$POD_FS_ROOT` works; include
  the `.meta.json` sidecars.

## Extensibility

### Writing a custom storage backend

- **JSS:** the data layer is monolithic (filesystem + optional sql.js
  for accounts); swapping it requires a fork.
- **solid-pod-rs:** implement the `Storage` trait (7 async methods).
  Pass `tests/storage_trait.rs` and you're done.

### Writing custom auth

- **JSS:** fastify plugin architecture; add middleware or a custom
  auth hook via Fastify's hook API.
- **solid-pod-rs:** write middleware in your HTTP framework; call
  `auth::nip98::verify` or `oidc::verify_access_token` (or your own
  logic) and populate request-scoped state.

### Writing a notification backend

- **JSS:** `@fastify/websocket` plugin; extension requires a fork.
- **solid-pod-rs:** implement `Notifications` trait (3 async methods)
  and feed it from `Storage::watch()`.

## What you give up moving to solid-pod-rs

- JSS's integrated `oidc-provider` HTML interaction experience. The Rust IdP
  crate implements protocol logic, but its optional pre-built Axum router must
  not be exposed until the open identity-header audit finding is fixed.
- Recompile-free runtime plugins and WAC-exempt app mounts introduced in JSS
  `0.0.213–0.0.219`.
- Some Prefer-header nuances (handling=strict vs handling=lenient —
  we always parse leniently).

## What you gain moving to solid-pod-rs

- A single static binary; measure its actual size for your selected features.
- Strong typing at every boundary (`AccessMode`, `PatchDialect`,
  `StorageEvent`, `RdfFormat`).
- First-class NIP-98 authentication (useful for Nostr ecosystems).
- A core-only WASM surface for edge consumers.
- Workspace-wide Rust tests and strict Clippy gates.
- AGPL-3.0-only licensing inherited from the JSS ecosystem covenant — same
  network-service copyleft protection, different runtime — fewer compliance
  concerns when embedding into proprietary or non-AGPL services.

## When to stay on JSS

- You need the mature built-in IdP UI and account-signup flow.
- You rely on JSS-specific features (`mashlib`, `solidosUi`, Git HTTP
  backend, invite-only registration).
- You need WebID-TLS.
- You need recompile-free runtime plugins or app mounts.

## When to pick solid-pod-rs

- You are building a NIP-98-authenticated app and want Solid on top.
- You need a tiny, embeddable pod for IoT / edge / serverless.
- You want to add solid-pod-rs as a library inside an existing Rust
  service (VisionClaw, federated forum, etc.).
- You need strict deny-by-default WAC.
- Your deployment demands static binaries (k8s, distroless, single-
  container deployments).
- AGPL-3.0 network-service copyleft is acceptable for your deployment.

## See also

- [PARITY-CHECKLIST.md](../../PARITY-CHECKLIST.md)
- [how-to/migrate-from-jss.md](../how-to/migrate-from-jss.md)
- [explanation/architecture-decisions.md](architecture-decisions.md)
