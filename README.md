# solid-pod-rs

**A Rust-native port of [JavaScriptSolidServer](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer) (JSS)** — the reference implementation of the [Solid Protocol](https://solidproject.org/TR/protocol). solid-pod-rs is the **personal-data-sovereignty layer** of the DreamLab ecosystem: it gives every human and every agent a self-owned RDF data store — a **pod** — under their own key, with WAC access control, did:nostr identity, and a sovereign, Bitcoin-settled HTTP-402 trust ledger. Every write to a pod is a git-mark commit; high-value writes anchor to the Bitcoin chain. The exit right sits in the floor, not granted at the door. Pre-1.0, AGPL-3.0 by design.

[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](./LICENSE)
[![crates.io](https://img.shields.io/crates/v/solid-pod-rs.svg)](https://crates.io/crates/solid-pod-rs)
[![docs.rs](https://img.shields.io/docsrs/solid-pod-rs)](https://docs.rs/solid-pod-rs)
[![CI](https://github.com/DreamLab-AI/solid-pod-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/DreamLab-AI/solid-pod-rs/actions/workflows/ci.yml)
[![MSRV: 1.88](https://img.shields.io/badge/MSRV-1.88-lightgray.svg)](https://releases.rs/docs/1.88.0/)

**Maintainer**: [John O'Hare](https://github.com/jjohare) · **Upstream IP**: [Melvin Carvalho](https://github.com/melvincarvalho) ([JSS](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer), the AGPL-3.0 reference Solid pod server) · [MAINTAINERS.md](MAINTAINERS.md)

New to Solid, RDF/JSON-LD, WAC, or did:nostr? The concepts live in one place: the [Solid primer for Rust developers](crates/solid-pod-rs/docs/explanation/solid-primer.md). This README stays on what solid-pod-rs is and where it sits.

---

## Part of VisionFlow

solid-pod-rs is the sovereign data layer of [**VisionFlow**](https://github.com/DreamLab-AI/VisionFlow) — a seven-repo mesh for human–AI coordination built on one identity spine: `did:nostr` as login, WAC principal, provenance author, DID subject, and payment account, all from a single keypair. Pods are the canonical store the other components read from and write to.

| Repository | Role |
|:-----------|:-----|
| [DreamLab-AI/VisionFlow](https://github.com/DreamLab-AI/VisionFlow) | Ecosystem canon — ADRs, PRDs, the compatibility matrix, marketing site and vision report. |
| [DreamLab-AI/VisionClaw](https://github.com/DreamLab-AI/VisionClaw) | Flagship engine — ontology-grounded immersive 3D knowledge graph, OWL 2 EL + Whelk, GPU physics. |
| [DreamLab-AI/agentbox](https://github.com/DreamLab-AI/agentbox) | Sovereign agent runtime — Nix container, did:nostr agent identities, RuVector memory, Solid-pod bridge. |
| **[DreamLab-AI/solid-pod-rs](https://github.com/DreamLab-AI/solid-pod-rs)** | **The personal-data-sovereignty layer — this repo.** |
| [DreamLab-AI/nostr-rust-forum](https://github.com/DreamLab-AI/nostr-rust-forum) | Nostr-native forum + relay — the human+agent communication and governance substrate. |
| [DreamLab-AI/dreamlab-ai-website](https://github.com/DreamLab-AI/dreamlab-ai-website) | DreamLab AI company website — the commercial face. |
| [DreamLab-AI/knowledgeGraph](https://github.com/DreamLab-AI/knowledgeGraph) | narrativegoldmine.com — the published public knowledge graph, the corpus VisionClaw renders in 3D. |

In July 2026 Block (Jack Dorsey) launched [Buzz](https://github.com/block/buzz), a self-hosted, Nostr-native team-chat + AI-agent + git platform in Rust. It independently arrives at the same substrate this ecosystem has built since 2022: Nostr events as source of truth, agents as first-class signed participants with their own keypairs, and NIP-42/98 auth — industry convergence that validates the direction. What Buzz does not carry is what differentiates this ecosystem: Solid-pod data sovereignty (this repo), OWL 2 EL / KG ontology grounding, immersive 3D embodiment, and closed learning loops (sibling repos).

---

## Architecture

solid-pod-rs is a Cargo workspace of **8 crates**. The core library is framework-agnostic; sibling crates add bounded-context features and depend only on the core.

| Crate | docs.rs | Description |
|-------|---------|-------------|
| [`solid-pod-rs`](https://crates.io/crates/solid-pod-rs) | [![docs](https://img.shields.io/docsrs/solid-pod-rs)](https://docs.rs/solid-pod-rs) | Core library — LDP, WAC, WebID, auth, provenance, payments, notifications, storage |
| [`solid-pod-rs-server`](https://crates.io/crates/solid-pod-rs-server) | [![docs](https://img.shields.io/docsrs/solid-pod-rs-server)](https://docs.rs/solid-pod-rs-server) | Drop-in server binary (actix-web + CLI) |
| [`solid-pod-rs-idp`](https://crates.io/crates/solid-pod-rs-idp) | [![docs](https://img.shields.io/docsrs/solid-pod-rs-idp)](https://docs.rs/solid-pod-rs-idp) | Solid-OIDC identity provider |
| [`solid-pod-rs-activitypub`](https://crates.io/crates/solid-pod-rs-activitypub) | [![docs](https://img.shields.io/docsrs/solid-pod-rs-activitypub)](https://docs.rs/solid-pod-rs-activitypub) | ActivityPub federation + HTTP Signatures |
| [`solid-pod-rs-nostr`](https://crates.io/crates/solid-pod-rs-nostr) | [![docs](https://img.shields.io/docsrs/solid-pod-rs-nostr)](https://docs.rs/solid-pod-rs-nostr) | did:nostr resolver + NIP-01 relay |
| [`solid-pod-rs-git`](https://crates.io/crates/solid-pod-rs-git) | [![docs](https://img.shields.io/docsrs/solid-pod-rs-git)](https://docs.rs/solid-pod-rs-git) | Git HTTP smart-protocol backend (git-marks) |
| [`solid-pod-rs-forge`](https://crates.io/crates/solid-pod-rs-forge) | [![docs](https://img.shields.io/docsrs/solid-pod-rs-forge)](https://docs.rs/solid-pod-rs-forge) | Pod-native git forge — hosting, browse, issues (Phases 0–3) |
| [`solid-pod-rs-didkey`](https://crates.io/crates/solid-pod-rs-didkey) | [![docs](https://img.shields.io/docsrs/solid-pod-rs-didkey)](https://docs.rs/solid-pod-rs-didkey) | did:key + self-signed JWT verifier |

```mermaid
graph TD
    SERVER["solid-pod-rs-server (CLI + actix-web)"]
    CORE["solid-pod-rs (protocol primitives)"]
    AP["solid-pod-rs-activitypub"]
    GIT["solid-pod-rs-git"]
    FORGE["solid-pod-rs-forge"]
    IDP["solid-pod-rs-idp"]
    NOSTR["solid-pod-rs-nostr"]
    DIDKEY["solid-pod-rs-didkey"]

    SERVER --> CORE
    SERVER --> IDP
    SERVER -.->|"feature: git"| GIT
    SERVER -.->|"feature: forge"| FORGE
    AP --> CORE
    GIT --> CORE
    FORGE --> CORE
    IDP --> CORE
    NOSTR --> CORE
    DIDKEY --> CORE

    style SERVER fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style CORE fill:#2ecc71,stroke:#1a9850,color:#fff
    style AP fill:#e67e22,stroke:#bf6516,color:#fff
    style GIT fill:#e67e22,stroke:#bf6516,color:#fff
    style FORGE fill:#e67e22,stroke:#bf6516,color:#fff
    style IDP fill:#e67e22,stroke:#bf6516,color:#fff
    style NOSTR fill:#e67e22,stroke:#bf6516,color:#fff
    style DIDKEY fill:#e67e22,stroke:#bf6516,color:#fff
```

---

## Quick start

### As a server binary

```bash
cargo install solid-pod-rs-server

# Minimal config — one JSON file.
cat > config.json <<'EOF'
{
  "server": { "host": "127.0.0.1", "port": 3000 },
  "storage": { "kind": "fs", "root": "./pod-root" },
  "auth":    { "nip98": { "enabled": true } }
}
EOF

solid-pod-rs-server --config config.json
```

```bash
# Round-trip a resource.
curl -i -X PUT http://127.0.0.1:3000/notes/hello.ttl \
     -H 'Content-Type: text/turtle' \
     --data-binary '<#> <http://example.org/says> "Hello, Solid".'

curl -i http://127.0.0.1:3000/notes/hello.ttl
# 200 OK
# ETag: "sha256-..."
# Link: <.acl>; rel="acl", <http://www.w3.org/ns/ldp#Resource>; rel="type"
```

### As a library

```toml
[dependencies]
solid-pod-rs = { version = "0.5.0-alpha.6", features = ["fs-backend", "oidc"] }
```

```rust,no_run
use solid_pod_rs::storage::fs::FsBackend;
use std::path::PathBuf;

let storage = FsBackend::new(PathBuf::from("./pod-root"));
// Wire your HTTP framework of choice; see examples/embed_in_actix.rs.
```

All configuration keys accept either a JSON/TOML file entry or a `JSS_*` environment variable — names identical to JSS, so existing deployment scripts work unchanged. See [`env-vars.md`](crates/solid-pod-rs/docs/reference/env-vars.md) for the full list.

---

## What it does

Each subsystem below is a one-paragraph summary; the linked docs carry the row-level detail.

**LDP — Linked Data Platform.** Every URL is a resource (a file with RDF metadata) or a container (a directory that lists its children), addressed with standard HTTP verbs plus `COPY` and glob `GET`. Content negotiation over Turtle / JSON-LD / N-Triples, N3-Patch and SPARQL-Update PATCH, strong SHA-256 ETags, `Prefer` and `Range` headers, and `.meta` sidecars. Modules: `ldp`, `storage::*`.

**WAC — Web Access Control.** Deny by default: no ACL means no access. `.acl` sidecars specify who (by WebID, agent class, or group) may Read / Write / Append / Control, inheriting down the container tree via `acl:default`. Parser bounds cap Turtle at 1 MiB and JSON-LD depth at 32 levels (CWE-400). See [`wac-modes.md`](crates/solid-pod-rs/docs/reference/wac-modes.md) and [`debug-acl-denials.md`](crates/solid-pod-rs/docs/how-to/debug-acl-denials.md).

**Provenance & trust ledger.** A pod records who changed what, when, and on whose authority. **git-marks** (cheap, always-on) turn every write into a git commit persisted as a PROV-O sidecar. **block-trails** (opt-in) anchor a hash-chained state trail to Bitcoin taproot, batched under an epoch Merkle root so one transaction notarises an epoch of writes. Default network is `testnet4`; mainnet is an explicit operator choice. See [ADR-059](crates/solid-pod-rs/docs/adr/ADR-059-provenance-primitives-block-trails-git-marks.md) and the [provenance upgrade master plan](crates/solid-pod-rs/docs/design/provenance-upgrade-master-plan.md).

**Payments & web ledger.** solid-pod-rs inherits JSS's HTTP-402 economy: a `PaymentCondition` in a WAC ACL gates a resource behind a price, the client pays, the read succeeds. Settlement is sovereign and Bitcoin-native (sats, no EVM), sharing one verified taproot core with block-trail anchors — deposits, withdrawals, a routed order book and constant-product AMM, all through `PaymentStore` as the sole ledger I/O path, with replay protection on every settlement proof.

**Authentication.** Two paths, one `AuthContext`. **NIP-98** signs a per-request Nostr event (kind 27235) binding URL, method, and body hash — no IdP, just a keypair; see [`configure-nip98-auth.md`](crates/solid-pod-rs/docs/how-to/configure-nip98-auth.md). **Solid-OIDC** is authorization-code + PKCE with DPoP-bound tokens (RFC 9449) for interop with existing Solid clients; see [`enable-solid-oidc.md`](crates/solid-pod-rs/docs/how-to/enable-solid-oidc.md).

**Identity provider.** The `solid-pod-rs-idp` crate is a self-contained Solid-OIDC IdP — authorization-code flow with PKCE, ES256-signed DPoP tokens, dynamic client registration, JWKS publication, WebAuthn passkeys, and NIP-07 Schnorr SSO — so a pod can run without a separate identity service.

**Federation.** `solid-pod-rs-activitypub` speaks ActivityPub (Actor discovery, HTTP-Signature inbox verification, follower fan-out, SQLite persistence). `solid-pod-rs-nostr` embeds a NIP-01 relay and resolves did:nostr. Solid Notifications 0.2 ships over WebSocket, webhook (RFC 9421 Ed25519-signed), and a legacy `solid-0.1` adapter. Reachable over three transports: Tailscale private mesh, the Nostr relay mesh, and Cloudflare tunnels.

**Storage.** A pluggable `Storage` trait backs everything: `fs-backend` (POSIX, atomic rename, path-traversal guard), `memory-backend` (tests/demos), and `s3-backend` (S3/MinIO/R2/B2). Per-pod quota via `.quota.json` sidecars.

**Security.** Safe by default: `..`/null-byte path rejection on both backends, SSRF guard against RFC-1918 / loopback / link-local / cloud-metadata with per-call IP pinning against DNS-rebinding, ACL size caps, dotfile allowlist, NIP-98 token-size limit, and WAC-gated git smart-HTTP. See [`security-model.md`](crates/solid-pod-rs/docs/explanation/security-model.md) and [`SECURITY.md`](crates/solid-pod-rs/SECURITY.md).

**Git forge.** `solid-pod-rs-forge` is a clean-room Rust forge composed on the pod's own primitives (git smart-HTTP, provenance, NIP-98, did:nostr, WAC), behind a default-off `forge` feature. See Status below for exactly what is shipped versus scaffolded.

---

## Documentation

Full documentation follows the [Diátaxis](https://diataxis.fr/) framework and lives at [`crates/solid-pod-rs/docs/`](crates/solid-pod-rs/docs/README.md) (the docs index) — tutorials, how-to guides, reference, and explanation. Parity and gaps are tracked row-by-row in [`PARITY-CHECKLIST.md`](crates/solid-pod-rs/PARITY-CHECKLIST.md) and narrated in [`GAP-ANALYSIS.md`](crates/solid-pod-rs/GAP-ANALYSIS.md).

---

## Status & remaining work (2026-07-22)

Honest, pre-1.0, dated. Version pins here match `Cargo.toml` `workspace.package.version` = **`0.5.0-alpha.6`** at time of writing.

- **8 crates, not 7.** `solid-pod-rs-forge` is real and test-green: Phases 0–3 (XSS-safe content-type spine, Tier-1 git hosting + browse porcelain, Tier-2 issues over an atomic spine store, and the Tier-2.5 HMAC push-token path for podless did:nostr identities) shipped per CHANGELOG's `0.5.0-alpha.5` entry (2026-07-15). Phases 4–7 — forks/PRs, Bitcoin anchors (`forge-anchoring`), and NIP-34 discovery (`forge-announce`) — are feature-scaffolded and compiling, not implemented.
- **~96% strict JSS parity.** Ground truth is [`PARITY-CHECKLIST.md`](crates/solid-pod-rs/PARITY-CHECKLIST.md) "Current state (Sprint 16)": 207 rows tracked — 3 missing, 6 deferred as legacy/P3, 3 wontfix-in-crate. See the checklist for the working; the Rust port adds a single static binary, no Node.js dependency, lower memory footprint, deterministic RDF serialisation, and compile-time feature gating on top of that parity.
- **Provenance is git-mark-first.** git-marks are always-on; Bitcoin block-trail anchors are opt-in behind the `mrc20` feature and default to `testnet4`. The Bitcoin write side (P2TR construction, BIP-341 TapSighash, BIP-340 Schnorr) is validated against the official test vectors.
- **Security fixes landed after the last CHANGELOG entry.** git HEAD (`0.5.0-alpha.6`) closes audit criticals — deposit-oracle exploit, an SSRF cluster, CORS, and auth stubs — beyond CHANGELOG's `alpha.5` cut. Treat CHANGELOG.md as the authoritative record of shipped work; do not read more security completeness into this line than the checklist records.

---

## Lineage & licence

solid-pod-rs is a Rust port of [JavaScriptSolidServer](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer) and deliberately inherits JSS's AGPL-3.0 licence to preserve the ecosystem's network-service copyleft — the sovereignty mechanism, not an accident.

```
JavaScriptSolidServer (Node.js, AGPL-3.0)
        │  reference implementation, Melvin Carvalho
        ▼
solid-pod-rs (Rust, AGPL-3.0)   ← you are here
```

**AGPL-3.0-only.** If you operate solid-pod-rs as a network-accessible service — which, being a pod, you almost certainly will — §13 requires you to offer corresponding source to your users. See [`LICENSE`](LICENSE) and [`NOTICE`](crates/solid-pod-rs/NOTICE).

---

## Contributing

See [`CONTRIBUTING.md`](crates/solid-pod-rs/CONTRIBUTING.md). Run `cargo test --all-features` and `cargo clippy --all-targets --all-features -- -D warnings` before opening a pull request. Report security issues via [`SECURITY.md`](crates/solid-pod-rs/SECURITY.md). Maintainers: [MAINTAINERS.md](MAINTAINERS.md).
