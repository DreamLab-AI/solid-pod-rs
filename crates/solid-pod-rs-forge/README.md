# solid-pod-rs-forge

A clean-room Rust reimplementation of the JavaScriptSolidServer `forge`
plugin: a zero-build, server-rendered Git forge (a Gogs/Gitea slice)
composed almost entirely from primitives `solid-pod-rs` already ships.

## Design

The forge is ~90% composition of existing solid-pod-rs primitives and
~10% new glue. It reuses:

- **git smart-HTTP** (clone/fetch/push, auto-init) — `solid-pod-rs-git`
- **repo browse porcelain** (log/diff/branches/commit) — `solid-pod-rs-git::api`
- **write-as-commit provenance + Bitcoin anchoring** — `solid-pod-rs::provenance` / `mrc20` / `bitcoin_tx`
- **NIP-98 auth** — `solid-pod-rs::auth::nip98`
- **`did:nostr` identity** — `solid-pod-rs::did_nostr_types`
- **ownership gating** — the embedding server gates the forge scope before
  `handle`; the bundled `solid-pod-rs-server` applies the forge's own
  fail-closed namespace-ownership guard (`ownership`) rather than the pod's
  WAC ACL evaluator

New in this crate: the spine index (`spine`, issues today), the pod-hosted
body reader/loopback fetch (`bodies`), hosted storage for podless
`did:nostr` agents (`hosted`), the forge push token (`token`), the
namespace-ownership guard (`ownership`), the HTML rendering layer (`html`)
and the repo browse porcelain (`repo`) that extends the git API. Forks and
pull requests, the NIP-34 announcement builder/signer and the marks manager
are **planned** (Phases 4–7): their `pulls/` and `marks/` directories are
created and the `anchoring` / `announce` features compile, but no code yet
uses them.

## Architecture rule

**"Words in pods, metadata in the forge."** Issue/PR/comment bodies live
in the author's own pod (WAC-governed, author-owned); the forge keeps only
a spine of pointers and re-fetches bodies at read time (bounded). Podless
`did:nostr` agents store bodies in forge-hosted storage instead.

## IP posture

Everything is derived from the forge plugin's published *behaviour* and
expressed as fresh Rust on solid-pod-rs's own primitives. JSS is cited by
function/section name only — no upstream JavaScript is transcribed.

## Native-only

The forge shells to `git`/`git-http-backend`, touches the filesystem, and
runs a loopback HTTP client. It is never part of a `core`/wasm build and
adds zero dependencies to the core crate.

## Features

Both features are scaffolded (they add the dependencies) and are not yet
wired to any code path in this crate:

| Feature | Effect |
|---|---|
| `anchoring` | Tier 3.5 Blocktrails anchoring — planned (pulls `solid-pod-rs/mrc20` + `k256`) |
| `announce` | NIP-34 discovery publication over WS — planned (pulls `solid-pod-rs-nostr` + `k256`) |

## Entry point

Framework-agnostic: `ForgeService::handle(ForgeRequest, ForgeAgent) ->
Result<ForgeResponse, ForgeError>`. The embedding server translates its
native types at the edge and gates the forge scope before dispatch (the
bundled server uses the namespace-ownership guard, not WAC).

## Licence

AGPL-3.0-only.
