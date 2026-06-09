# Ecosystem integration

solid-pod-rs is the foundation library of the DreamLab open-source
ecosystem -- five repositories federated via `did:nostr` identity.
This page explains how the pieces fit, who consumes what, and the
integration points between them.

## The stack

```
  +----------------------------------------------------------+
  |                       Solid-Apps                          |
  |  (end-user apps: forum UI, dashboards, XR clients)       |
  +----------------------------------------------------------+
                          ^
                          | HTTP (LDP + WAC + Notifications)
                          v
  +----------------------------------------------------------+
  |                    Consumer substrates                    |
  |   VisionClaw, agentbox, nostr-rust-forum,                |
  |   dreamlab-ai-website                                    |
  |   Each wires solid-pod-rs into its own runtime           |
  |   (actix/axum/CF Workers) with domain-specific concerns  |
  +----------------------------------------------------------+
                          |
                          | uses (Storage trait, WAC, auth, LDP)
                          v
  +----------------------------------------------------------+
  |                  solid-pod-rs (this crate)                |
  |   Library: WAC, LDP, Notifications, NIP-98, Solid-OIDC,  |
  |   DID:nostr, WebID, did:key                              |
  +----------------------------------------------------------+
```

## Consumers

### VisionClaw

VisionClaw is the integration substrate -- a knowledge-graph platform
with GPU physics, WebXR rendering, and a Nostr-backed actor mesh.

- **Integration point:** `src/handlers/solid_pod_handler.rs` wires
  solid-pod-rs into the actix-web runtime as an embedded pod endpoint.
- **Features used:** LDP (resource CRUD), WAC (per-resource access
  control), NIP-98 auth, WebID profile generation, DID:nostr
  resolution.
- **Dependency:** `solid-pod-rs = "0.4"` with default features plus
  `nip98-schnorr` and `did-nostr`.

Repository: [DreamLab-AI/VisionClaw](https://github.com/DreamLab-AI/VisionClaw)

### agentbox

agentbox is a Nix-based sovereign agent container that runs as a mesh
peer alongside VisionClaw and nostr-rust-forum.

- **Integration point:** the pod-bridge adapter in
  `management-api/adapters/` forwards agent state to a local Solid
  pod for durable storage and WAC-governed sharing.
- **Features used:** Storage trait (filesystem backend), WAC
  enforcement, NIP-98 auth, Solid Notifications (WebSocket channel
  for agent event streaming).
- **Dependency:** `solid-pod-rs = "0.4"` with default features.

Repository: [DreamLab-AI/agentbox](https://github.com/DreamLab-AI/agentbox)

### nostr-rust-forum (nostr-bbs-pod-worker)

nostr-rust-forum is a configurable forum kit published as 12
`nostr-bbs-*` Rust crates. The `nostr-bbs-pod-worker` crate runs on
Cloudflare Workers (wasm32 target) and consumes solid-pod-rs for
pod-backed thread storage.

- **Integration point:** `nostr-bbs-pod-worker` uses the `core`
  feature flag (no-IO subset) to compile to wasm32 without pulling
  tokio, reqwest, or filesystem dependencies.
- **Features used:** WAC evaluator, WebID parsing, NIP-98 structural
  verification (`auth::nip98::verify_at`), dotfile allowlist, LDP
  parsers (PATCH dialects, content negotiation), interop types.
- **Dependency:**
  `solid-pod-rs = { version = "0.4", default-features = false, features = ["core"] }`

Repository: [DreamLab-AI/nostr-rust-forum](https://github.com/DreamLab-AI/nostr-rust-forum)

### dreamlab-ai-website

dreamlab-ai-website is DreamLab's branded forum deployment -- a
downstream consumer of the nostr-rust-forum kit.

- **Integration point:** consumes solid-pod-rs transitively via
  `nostr-bbs-pod-worker`. Does not depend on solid-pod-rs directly.
- **Features used:** inherited from nostr-bbs-pod-worker (WAC, WebID,
  NIP-98 structural verification, LDP parsers).

Repository: [DreamLab-AI/dreamlab-ai-website](https://github.com/DreamLab-AI/dreamlab-ai-website)

## Who owns what

### solid-pod-rs (this crate)

- The `Storage` trait.
- LDP semantics (containers, Link headers, PATCH).
- WAC evaluator.
- NIP-98 + Solid-OIDC verification.
- In-memory, filesystem, and S3 backends.
- Solid Notifications 0.2 channel managers.
- DID:nostr resolution + WebID generation.
- did:key resolution (Ed25519, P-256, secp256k1).
- Platform-independent. No actix, no worker, no hosting concerns.

**Does not** own: HTTP routing, TLS, provisioning, account lifecycle,
WebFinger, NIP-05, quota, billing.

### Consumer substrates

Each consumer substrate wraps solid-pod-rs in its own runtime with
domain-specific concerns:

- **VisionClaw** -- actix-web transport, graph-aware provisioning,
  actor-mesh integration.
- **agentbox** -- management API adapter, Nix packaging,
  nostr-rs-relay mesh peering.
- **nostr-bbs-pod-worker** -- CF Workers (wasm32), thread storage,
  forum-specific ACL policies.

## Boundary contracts

### solid-pod-rs public API surface

All consumers depend on these public API surfaces:

- `storage::Storage` trait (VisionClaw, agentbox).
- `ldp::*` helpers -- link_headers, PreferHeader, content negotiation,
  PATCH (all consumers).
- `wac::evaluate_access*`, `wac_allow_header`, `StorageAclResolver`
  (VisionClaw, agentbox); `wac::AclResolver` trait alone for
  `core`-only consumers (nostr-bbs-pod-worker).
- `auth::nip98::verify` / `auth::nip98::verify_at` (all consumers).
- `oidc::*` (feature `oidc` -- VisionClaw).
- `notifications::{WebSocketChannelManager, WebhookChannelManager,
  discovery_document}` (VisionClaw, agentbox).
- `interop::did_nostr::*` (feature `did-nostr` -- VisionClaw,
  nostr-bbs-pod-worker).
- `PodError` variants for HTTP status mapping.

Anything else is an implementation detail and may change between
minor versions.

## Integration patterns

### Pattern 1 -- full server embedding (VisionClaw, agentbox)

```rust
use solid_pod_rs::{storage::fs::FsBackend, Storage};
use std::sync::Arc;

let storage: Arc<dyn Storage> = Arc::new(
    FsBackend::new("/var/lib/pods").await?
);
// Wire into your actix/axum router; see examples/embed_in_actix.rs.
```

The consumer composes HTTP routing, auth middleware, provisioning,
and metrics around the solid-pod-rs library.

### Pattern 2 -- core-only WASM embedding (nostr-bbs-pod-worker)

```rust
// Cargo.toml
// solid-pod-rs = { version = "0.4", default-features = false, features = ["core"] }

use solid_pod_rs::auth::nip98::verify_at;
use solid_pod_rs::wac::evaluate_access;

// No tokio, no filesystem -- pure logic only.
// The CF Worker runtime provides its own I/O.
```

### Pattern 3 -- transitive consumption (dreamlab-ai-website)

dreamlab-ai-website does not depend on solid-pod-rs directly.
It consumes the forum kit (`nostr-bbs-pod-worker`) which handles
all pod interactions internally. The integration contract is the
Solid Protocol itself over HTTP.

### Pattern 4 -- storage-only reuse

A consumer that needs just a storage abstraction with strong ETags +
change events could use solid-pod-rs's storage module alone, ignoring
LDP / WAC / auth. Nothing in the crate forces the full Solid stack
on you.

## Cross-repo versioning

- solid-pod-rs uses semantic versioning. Breaking changes to public
  APIs cause a major-version bump.
- VisionClaw consumes `solid-pod-rs` at the current alpha line with the
  feature set it needs for embedded pods. agentbox builds a pinned
  `solid-pod-rs-server` binary through Nix for the native pod tier.
- nostr-bbs-pod-worker pins
  `solid-pod-rs = { version = "0.4.0-alpha.16", default-features = false, features = ["core"] }`.
- The current workspace version is **0.4.0-alpha.16** across all 7
  workspace crates.

## Cross-system identity

All five repositories share `did:nostr:<64-lowercase-hex>` as the
universal identity primitive (per ADR-074). solid-pod-rs provides:

- DID document generation with `verificationMethod.type =
  SchnorrSecp256k1VerificationKey2019`.
- `@context` including `https://w3id.org/security/suites/secp256k1-2019/v1`.
- WebID profile generation with `alsoKnownAs` cross-linking to
  `did:nostr` identifiers.
- NIP-98 HTTP authentication binding pubkey to `did:nostr:{pubkey}`,
  with BIP-340 Schnorr signature verification via `verify_raw()` (raw
  32-byte event-id message, no tagged pre-hash).

NIP-26 delegation is the cross-system trust pivot for inter-substrate
operations.

## Contribution flow

When adding a feature that spans the ecosystem:

1. Land library API in solid-pod-rs with tests. Update
   `PARITY-CHECKLIST.md`.
2. Expose it in the relevant consumer substrate(s) via new endpoints
   or middleware.
3. Verify `core` feature compatibility if the feature is needed by
   wasm32 consumers (nostr-bbs-pod-worker).
4. Document in the appropriate Diataxis quadrant.

## See also

- [PARITY-CHECKLIST.md](../../PARITY-CHECKLIST.md) -- current
  feature status.
- [README.md](../../README.md) -- crate overview.
- [explanation/architecture-decisions.md](architecture-decisions.md) --
  why the library is framework-agnostic.
- [explanation/storage-abstraction.md](storage-abstraction.md) -- the
  trait shape consumers build on.
