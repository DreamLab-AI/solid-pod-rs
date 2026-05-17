# solid-pod-rs-server

Binary distribution of [`solid-pod-rs`](../solid-pod-rs/) — a drop-in
JSS replacement that runs as a single static-ish Rust binary.

## Install

Once published to crates.io (target: v0.4.0):

```bash
cargo install solid-pod-rs-server
solid-pod-rs-server --config config.json
```

Until then, build from source:

```bash
cargo build --release -p solid-pod-rs-server
./target/release/solid-pod-rs-server --help
```

## Architecture

This crate is a thin binary shell over [`solid-pod-rs`](../solid-pod-rs/).
Per ADR-056 §D3 (F7 library-server split):

- [`solid-pod-rs`](../solid-pod-rs/) — pure library. No `#[tokio::main]`,
  no `actix-web::HttpServer`. Framework-agnostic.
- `solid-pod-rs-server` (this crate) — owns the actix-web HTTP server,
  the tokio runtime, clap CLI, the F6 layered config loader, and signal
  handling. Depends on the library and wires its `PodService`-style
  primitives into concrete HTTP routes.

## Configuration

Configuration is loaded by [`solid_pod_rs::config::ConfigLoader`]
(F6, PRD §F6). Precedence (later overrides earlier):

```text
Defaults  <  File  <  EnvVars  <  CLI flags
```

See [`crates/solid-pod-rs/src/config/sources.rs`](../solid-pod-rs/src/config/sources.rs)
for the full `JSS_*` environment variable table.

## Mashlib / SolidOS data browser

Enable the mashlib data browser to render RDF resources in the browser:

```bash
# CDN mode (zero config — loads from unpkg.com)
solid-pod-rs-server --mashlib

# CDN with a specific version
solid-pod-rs-server --mashlib --mashlib-cdn 2.1.0

# ES module mode (LOSOS shell)
solid-pod-rs-server --mashlib-module https://host/path/to/mashlib.js
```

When enabled, browser navigation (`Accept: text/html`) to RDF
resources returns an HTML wrapper that loads mashlib client-side.
The resource's JSON-LD is embedded inline as a data island (up to
256 KiB) for a zero-network-roundtrip render.  XHR / `fetch()`
requests (`Sec-Fetch-Dest: empty`) still receive raw RDF.

| Env var | CLI flag | Default |
|---|---|---|
| `JSS_MASHLIB` | `--mashlib` | off |
| `JSS_MASHLIB_CDN` | `--mashlib-cdn` | `2.0.0` |
| `JSS_MASHLIB_MODULE` | `--mashlib-module` | — |

## Admin API and Native Pod Mesh (alpha.15+)

### Provision endpoint

`POST /_admin/provision/{pubkey}` creates a new pod for a Nostr pubkey in one
atomic step: pod directory, owner-only `.acl`, and a `git init` that sets
`receive.denyCurrentBranch=updateInstead` so the pod is immediately pushable
over HTTP via `/_git/{pubkey}/`.

```bash
curl -X POST https://pods.example.com/_admin/provision/<hex-pubkey> \
     -H "X-Pod-Admin-Key: $SOLID_ADMIN_KEY"
# → { "podUrl": "https://pods.example.com/<hex-pubkey>/", "ok": true }
```

This endpoint is the CF Workers ↔ agentbox handshake: `auth-worker` calls it
during WebAuthn registration to atomically provision a Solid pod alongside the
Nostr identity. The PSK (`SOLID_ADMIN_KEY` / `--admin-key`) must be set for the
endpoint to be active; it returns `403` unconditionally when unset.

Generate a key with:

```bash
openssl rand -hex 32
```

### CORS allowlist for the forum git client

The forum's Source Control panel (`components/git_panel.rs`) drives
`/_git/{pubkey}/` over HTTP from a cross-origin browser context.
`SOLID_ALLOWED_ORIGINS` / `--allowed-origins` is a comma-separated list of
origins that will receive `Access-Control-Allow-Origin` headers.

```bash
# Production — lock to known origins
SOLID_ALLOWED_ORIGINS=https://dreamlab-ai.com,https://pods.dreamlab-ai.com

# Development default — empty = wildcard (*)
```

OPTIONS preflights for `/_git/{pubkey}/**` are handled automatically
(feature `git` required, which is on by default in this binary).

### Deployment

For the full agentbox mesh deployment (solid-pod-rs-server alongside
`auth-worker`, R2, and the forum client) see:

```
docker-compose.solid-pods.yml   # in the dreamlab-ai-website agentbox repo
```

That compose file wires `SOLID_ADMIN_KEY`, `SOLID_ALLOWED_ORIGINS`,
`JSS_STORAGE_ROOT`, and the CF Worker `PROVISION_URL` binding together.

## Feature flags

This binary enables the following `solid-pod-rs` features by default:

| Feature | Purpose |
|---|---|
| `fs-backend` | Filesystem storage (JSS default) |
| `memory-backend` | In-memory storage (test / dev) |
| `config-loader` | F6 layered config loader |
| `legacy-notifications` | F3 `solid-0.1` WS notifications adapter |

Other feature flags (`oidc`, `dpop-replay-cache`, `nip98-schnorr`,
`s3-backend`) can be opted into by the operator via a custom build.

## Licence

**AGPL-3.0-only**. See [`LICENSE`](./LICENSE). Operating this binary as a
network service triggers AGPL §13 source-disclosure obligations.

## Sibling crates (all functional)

- [`solid-pod-rs-activitypub`](../solid-pod-rs-activitypub/) — ActivityPub federation (4,453 LOC)
- [`solid-pod-rs-git`](../solid-pod-rs-git/) — Git HTTP backend (1,685 LOC)
- [`solid-pod-rs-idp`](../solid-pod-rs-idp/) — Solid-OIDC identity provider (6,160 LOC)
- [`solid-pod-rs-nostr`](../solid-pod-rs-nostr/) — did:nostr + embedded Nostr relay (2,177 LOC)
- [`solid-pod-rs-didkey`](../solid-pod-rs-didkey/) — did:key (Ed25519/P-256/secp256k1) + JWT (1,167 LOC)
