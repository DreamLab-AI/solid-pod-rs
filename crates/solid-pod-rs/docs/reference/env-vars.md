# Environment variables reference

The core `solid-pod-rs` crate is a library; its config loader and the bundled
`solid-pod-rs-server` binary do read the JSS-compatible variables below.
Custom embedders decide whether to use that loader.

CLI arguments override environment and config-file values in the bundled
server. Consult `solid-pod-rs-server --help` for the exact command-line
surface.

## Recommended conventional env vars

Use these names when building a custom pod binary. They are conventions;
the authoritative bundled-server names are in the JSS-compatible table.

| Variable | Type / default | Consumed by | Purpose |
|---|---|---|---|
| `POD_BIND`               | `host:port` string, default `127.0.0.1:8765` | your HTTP framework | Listen address. |
| `POD_BASE_URL`           | URL, e.g. `https://pod.example` | `notifications::ChangeNotification::from_storage_event`, `oidc::discovery_for` | Canonical public URL of the pod. |
| `POD_STORAGE_BACKEND`    | `fs`, `memory`, or a custom value | your wiring | Selects the `Storage` implementation your application constructs. No stock S3 implementation exists. |
| `POD_FS_ROOT`            | path | `FsBackend::new` | Root directory for the FS backend. |
| `POD_S3_BUCKET`          | bucket name | your custom backend | Suggested convention; ignored by the library and bundled server. |
| `POD_S3_PREFIX`          | key prefix | your custom backend | Suggested convention; ignored by the library and bundled server. |
| `POD_NIP98_TOLERANCE`    | seconds, default 60 | your NIP-98 middleware | Override the timestamp window. Don't exceed 300. |
| `POD_OIDC_ISSUER`        | URL | `oidc::discovery_for` | OIDC issuer identity. Ignored when `oidc` feature is off. |
| `POD_OIDC_HS256_SECRET`  | bytes (UTF-8 OK) | `oidc::verify_access_token` | HS256 secret for test-path token verification. Production deployments use ES256/RS256 and a JWKS instead. |
| `POD_WEBHOOK_RETRY_BASE` | ms, default 500 | `WebhookChannelManager::retry_base` | Base backoff for webhook retries. |
| `POD_WEBHOOK_MAX_RETRIES`| integer, default 3 | `WebhookChannelManager::max_retries` | Max retries on 5xx. |
| `POD_WS_HEARTBEAT`       | seconds, default 30 | `WebSocketChannelManager::with_heartbeat` | WebSocket ping interval. |

## JSS-compatible env vars

The `solid-pod-rs-server` binary and the `config` module honour JSS-
compatible environment variables so existing deployment scripts work
unchanged.

| Variable | Type / default | Consumed by | Purpose |
|---|---|---|---|
| `JSS_HOST`             | string, default `127.0.0.1` | `config::ConfigLoader` | Bind address. |
| `JSS_PORT`             | u16, default `3000` | `config::ConfigLoader` | Listen port. |
| `JSS_BASE_URL`         | URL | `config::ConfigLoader` | Externally visible base URL. |
| `JSS_STORAGE_ROOT`     | path | `config::ConfigLoader` | Filesystem root for the FS backend. |
| `JSS_OIDC_ISSUER`      | URL | `config::ConfigLoader` | Identity provider discovery URL. |
| `JSS_WORKERS`          | usize, default CPUs | `config::ConfigLoader` | actix-web worker count. |
| `JSS_LOG_LEVEL`        | string | `config::ConfigLoader` | `trace` / `debug` / `info` / `warn` / `error`. |
| `JSS_LIVE_RELOAD`      | bool, default `false` | `solid-pod-rs-server` | Injects the development reload WebSocket script into HTML responses. Do not enable it on a public production service. |
| `JSS_DISABLE_DOTFILES` | bool | `config::ConfigLoader` | If set, no dotfiles served even on allowlist. |
| `JSS_MAX_ACL_BYTES`    | bytes, default `1048576` (1 MiB) | `wac::parse_turtle_acl_with_limit`, `wac::parse_jsonld_acl_with_limits` | Maximum ACL document size before rejection (CWE-400 DoS protection). Added Sprint 12. |
| `DOTFILE_ALLOWLIST`    | comma-separated | `security::dotfile::DotfileAllowlist::from_env` | Override the default dotfile allowlist (`.acl`, `.meta`, `.account`). |

None of the `POD_*` vars above are parsed by the library. The `JSS_*`
vars are consumed by the config loader when the `config-loader` feature
is enabled. This table is a suggested vocabulary so multi-pod
deployments can share config conventions.

## solid-pod-rs-server (alpha.15+)

These variables are consumed by the `solid-pod-rs-server` binary directly
(not by the library). They were added in alpha.15.

| Variable | CLI flag | Type / default | Purpose |
|---|---|---|---|
| `SOLID_ALLOWED_ORIGINS` | `--allowed-origins` | Comma-separated URL list, default empty | CORS origin allowlist for git and pod routes. When non-empty, only listed origins receive `Access-Control-Allow-Origin` in responses. Empty = wildcard (`*`) — suitable for local dev only. Example: `https://dreamlab-ai.com,https://staging.dreamlab-ai.com`. |
| `SOLID_ADMIN_KEY` | `--admin-key` | String (opaque secret), default unset | Pre-shared key (PSK) for the `POST /_admin/provision/{pubkey}` endpoint. The endpoint returns `403` on every request when this variable is unset. Generate with `openssl rand -hex 32`. Treat as a credential — do not log, do not commit. |
| `TOKEN_SECRET` | — | At least 32 bytes, default unset | Enables JSS-compatible two-part development bearer tokens. Tokens are HMAC-SHA256 authenticated and must contain valid `iat`, `exp`, and HTTP(S) WebID claims. An absent or short secret disables this authentication path. |

If `JSS_PORT` or `--port` names an occupied port, the server tries the next ten
ports and reports the actual base URL. Port `0` asks the operating system for
one ephemeral port. Production supervisors should still monitor the reported
address rather than assume the requested port was selected.

## Payments + provenance (0.5.0-alpha.0)

Consumed by the `solid-pod-rs-server` binary's payment (`handlers::pay`)
and provenance (`handlers::prov`, `--features git`) routes. See
[explanation/payments-and-web-ledger.md](../explanation/payments-and-web-ledger.md)
and [explanation/provenance-and-trust-ledger.md](../explanation/provenance-and-trust-ledger.md).

| Variable | Type / default | Consumed by | Purpose |
|---|---|---|---|
| `JSS_PAY_MEMPOOL_URL` | URL, default `https://mempool.space/testnet4` | `mempool::MempoolHttpClient::from_env` (`MEMPOOL_URL_ENV`) | Base URL of the mempool.space-style REST API used for block-trail anchor UTXO lookup + tx broadcast (MRC20 `/pay/.deposit`, `.buy`, `.withdraw*`, `_prov/anchor`). A trailing `/` is trimmed. Deployments on the DreamLab mesh SHOULD point this at the LAN node `http://192.168.2.27:<port>` once ADR-061's acceptance checklist passes (public default retained as the no-LAN fallback; see ADR-061). Tests override per-request via `AppState.mempool_url` (a fixture server) so CI never reaches mempool.space. |
| `JSS_PROV_EPOCH_SIZE` | usize ≥ 1, default `16` | `handlers::prov::epoch_size` (`EPOCH_SIZE_ENV`) | Epoch close threshold: the commit count at which an `AnchorPolicy::Epoch` batch is anchored as one Merkle root in a single Bitcoin tx (ADR-059 D5). Bounds on-chain cost — one anchor per this many commits. |
| `JSS_PROV_ANCHOR_PRICE_SATS` | u64, default = the pay-token rate (`0` ⇒ ungated) | `handlers::prov` (`anchor_price_sats`) | Price in satoshis the caller's Web Ledger is debited for an explicit `POST /{pod}/_prov/anchor` git-mark → Bitcoin upgrade. Refunded if the on-chain anchor then fails. |

The mempool, epoch, and anchor-price variables are read directly by the
server binary (not by the `solid_pod_rs` library). Block-trail anchoring
also requires the `mrc20` feature; provenance routes require `git`.

## Tracing / logging

solid-pod-rs uses the `tracing` crate.

| Variable | Consumer | Effect |
|---|---|---|
| `RUST_LOG` | `tracing_subscriber::EnvFilter` | Filter spec. `solid_pod_rs=info`, `solid_pod_rs=debug` for ACL resolver traces, etc. |
| `RUST_LOG_STYLE` | `tracing_subscriber::fmt` | `auto`, `always`, `never`. |

Example production settings:

```
RUST_LOG=solid_pod_rs=info,tower_http=info,actix_web=warn
```

## Unsupported object-store configuration

No S3 or R2 implementation ships, and the former dependency-only
`s3-backend` Cargo feature has been removed. `storage.type=s3` and
`JSS_STORAGE_TYPE=s3` now fail validation instead of falling back to the
filesystem. AWS environment variables are not consumed by this workspace.

## `notify` filesystem watcher

`FsBackend` uses `notify` internally. There is no exposed env var.
The watcher inherits platform defaults (inotify on Linux, FSEvents
on macOS, ReadDirectoryChangesW on Windows).

Very large Pods may hit platform `inotify` limits:

```bash
sudo sysctl -w fs.inotify.max_user_watches=524288
```

## Compile-time features (not env vars)

These are feature flags in `Cargo.toml`, set at build time:

| Feature        | Default | Effect |
|----------------|---------|--------|
| `fs-backend`   | yes     | Compiles `FsBackend`. |
| `memory-backend` | yes   | Compiles `MemoryBackend`. |
| `oidc`         | no      | Compiles the `oidc` module. |

## Testing

For tests, use `tempfile` to create a throwaway `POD_FS_ROOT`:

```rust
use tempfile::TempDir;
let tmp = TempDir::new().unwrap();
let backend = FsBackend::new(tmp.path()).await?;
```

No env var needed.

## See also

- [how-to/deploy-to-production.md](../how-to/deploy-to-production.md)
- [how-to/migrate-from-jss.md](../how-to/migrate-from-jss.md) — includes a
  JSS → solid-pod-rs env-var mapping table.
- [reference/api.md](api.md)
