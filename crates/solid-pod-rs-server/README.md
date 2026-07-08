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

## RDF content negotiation on GET

`GET` transcodes a stored RDF resource into the syntax the client names in
`Accept`. KG resources persist as N-Triples; agents and the elevation
extractor can read the same graph as Turtle or JSON-LD without a separate
conversion step. Recognised concrete media types:

| `Accept` value | Served as |
|---|---|
| `text/turtle` | Turtle (N-Triples is a syntactic subset, emitted verbatim) |
| `application/n-triples` | N-Triples |
| `application/ld+json` | JSON-LD (expanded form) |

Transcoded responses carry `Content-Type` of the negotiated format plus
`Vary: Accept`. The body is served verbatim when:

- the client names no concrete RDF type (`*/*`, `application/*`, empty);
- the requested format already equals the stored format;
- the stored body does not parse as N-Triples (fails soft, never destroys);
- the target is `application/rdf+xml` (no serialiser — declined, served as-is).

Non-RDF resources are always served verbatim. PATCH likewise seeds its
working graph from the existing N-Triples body, so an N3/SPARQL-Update
mutation is applied on top of pre-existing triples rather than replacing
them; a body that is neither empty nor parseable N-Triples is refused with
`409` rather than silently overwritten.

## Agent write path (NIP-98)

Write verbs (`PUT` / `POST` / `PATCH` / `DELETE` / `COPY`) authenticate the
caller via NIP-98: `extract_pubkey` reconstructs the signed request URL from
actix `connection_info`, honouring `X-Forwarded-Proto` so a `did:nostr` agent
signing `https://` behind TLS or a reverse proxy is not rejected with a
spurious `401` URL mismatch. The authenticated pubkey resolves to a
`did:nostr:{pubkey}` WebID that WAC evaluates against the effective ACL.

On an unauthenticated write the `WWW-Authenticate` challenge advertises
`Nostr realm="Solid", DPoP realm="Solid", Bearer realm="Solid"`, so an agent
discovers the NIP-98 scheme the write path actually accepts. WAC denial of an
authenticated caller returns `403`; a missing credential returns `401`.

Verification is hardened three ways (closeout 0.5.0-alpha.4):

- **Single-use replay guard** — every accepted NIP-98 token id is recorded in
  a shared process-local `Nip98ReplayCache`; a re-presented token is treated as
  unauthenticated (`extract_pubkey` returns `None`) so the WAC gate denies with
  `401`, closing the ±120s replay window the stateless verifier leaves open.
  Tunable via `SOLID_POD_NIP98_REPLAY_TTL_SECS` / `SOLID_POD_NIP98_REPLAY_MAX_SIZE`;
  per-process (multi-replica deployments share no state).
- **Fail-open compile guard** — the binary references a `const fn` that exists
  only when BIP-340 Schnorr verification is compiled in, so a build that ever
  dropped signature verification fails to compile rather than silently
  accepting any forged pubkey.
- **`acl:origin` gate** — the request `Origin` header is threaded into the WAC
  evaluator, so ACLs declaring `acl:origin` triples gate cross-origin access.
  Plain ACLs are unaffected; `acl:Control` bypasses the origin gate so an owner
  can always repair a mis-configured ACL. `acl:origin` is the only WAC 2.0
  condition satisfiable end-to-end today — `client_id` / `issuer` conditions
  still evaluate deny (no authenticated OIDC client_id / issuer is surfaced
  yet).

The optional `export-jsonld` build adds `GET /api/exports/all`, an
`acl:Control`-gated JSON-LD time-chain export of the whole pod (native-only).

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

```text
docker-compose.solid-pods.yml   # in the dreamlab-ai-website agentbox repo
```

That compose file wires `SOLID_ADMIN_KEY`, `SOLID_ALLOWED_ORIGINS`,
`JSS_STORAGE_ROOT`, and the CF Worker `PROVISION_URL` binding together.

## MCP server (Model Context Protocol)

`POST /mcp` exposes the pod as a Model Context Protocol 2025-03-26 tool
surface over the Streamable HTTP transport. Requests are JSON-RPC 2.0;
responses are single-shot JSON, with an SSE upgrade for the streaming
`subscribe` tool. The endpoint is **off by default**:

```bash
solid-pod-rs-server --mcp          # enable
solid-pod-rs-server --no-mcp       # force off (overrides JSS_MCP)
JSS_MCP=1 solid-pod-rs-server      # enable via env
```

Identity reuses the pod's NIP-98 verifier, so every tool call receives
the same WAC treatment as the equivalent REST request; an unauthenticated
`/mcp` call runs as the anonymous principal. Sixteen tools are exposed:

| Group | Tools |
|---|---|
| Resources | `list_resources`, `read_resource`, `write_resource`, `create_resource`, `delete_resource`, `head_resource` |
| Access control | `read_acl`, `write_acl` |
| Skills & docs | `list_skills`, `get_skill`, `get_pod_skill`, `list_docs`, `read_docs` |
| Pod & federation | `pod_info`, `subscribe`, `call_remote_pod` |

`call_remote_pod` is gated to `/private/federation/` for `did:nostr`
identities with a depth-3 recursion cap, so an agent cannot fan out an
unbounded pod-to-pod call graph. Built-in docs and skills are embedded at
compile time via `include_dir`.

| Env var | CLI flag | Default |
|---|---|---|
| `JSS_MCP` | `--mcp` / `--no-mcp` | off |

## `install` subcommand — push a Solid app into a pod

`solid-pod-rs-server install <app-spec>...` clones one or more Solid apps
and pushes them into a pod over the git smart protocol (the same
`/_git/{pubkey}/` path the forum git client uses). The app-spec grammar
mirrors JSS `src/cli/install.js`:

```text
<name>                 → https://github.com/solid-apps/<name>
<org>/<repo>           → https://github.com/<org>/<repo>
<full-git-url>         → used verbatim (https / git@ / ssh://)
<spec>#<ref>           → clone a specific branch/tag/commit
<spec>=<dest>          → rename the destination directory
```

```bash
# Install the bundled mashlib browser into the default pod
NOSTR_PRIVKEY=<hex> solid-pod-rs-server install mashlib

# Pin a ref, rename the destination, target an explicit pod
solid-pod-rs-server install \
    solid/contacts#v2=address-book \
    --pod https://pods.example.com/<hex-pubkey>/ \
    --nostr-privkey <hex>

# Preview without pushing
solid-pod-rs-server install mashlib --dry-run
```

Each app is pushed to **both** `HEAD:main` and `HEAD:gh-pages` so apps
that publish from either branch land correctly. Authentication uses a
single NIP-98 token minted over the destination repo URL with a `*`
method wildcard, injected via git `http.extraHeader` so it covers the
multi-request smart protocol with one static header. A `--token` bearer
fallback is accepted when NIP-98 signing is unavailable.

The scratch clone is created under the platform temp directory
(`std::env::temp_dir()`, which honours `$TMPDIR`) and removed on both
success and failure, so `install` works on Linux/macOS/Windows and
sandboxed environments such as Termux without a hardcoded `/tmp` — the
Rust equivalent of JSS #518.

| Flag | Env var | Default |
|---|---|---|
| `--pod` | `JSS_POD` | `http://localhost:4443` |
| `--nostr-privkey` | `NOSTR_PRIVKEY` | — |
| `--token` | `JSS_BEARER_TOKEN` | — |
| `--branches` | — | `main,gh-pages` |
| `--dry-run` | — | off |

NIP-98 minting requires the `install` cargo feature (which pulls in
`solid-pod-rs/nip98-schnorr`):

```bash
cargo build --release -p solid-pod-rs-server --features install
```

Without that feature the subcommand still compiles, but only the
`--token` bearer path can authenticate; the NIP-98 path returns a clear
runtime error telling the operator to rebuild with `--features install`.

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
