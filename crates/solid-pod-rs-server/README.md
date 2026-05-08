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
