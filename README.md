# solid-pod-rs

**A Rust-native port of [JavaScriptSolidServer](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer) (JSS)** — an extended implementation of the Solid Protocol. This crate delivers the full JSS feature surface (~96% strict parity) as a framework-agnostic Rust library and a drop-in server binary.

[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](./LICENSE)
[![crates.io](https://img.shields.io/crates/v/solid-pod-rs.svg)](https://crates.io/crates/solid-pod-rs)
[![docs.rs](https://img.shields.io/docsrs/solid-pod-rs)](https://docs.rs/solid-pod-rs)
[![CI](https://github.com/dreamlab-ai/solid-pod-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/dreamlab-ai/solid-pod-rs/actions/workflows/ci.yml)
[![MSRV: 1.85](https://img.shields.io/badge/MSRV-1.85-lightgray.svg)](https://releases.rs/docs/1.85.0/)

**Maintainer**: [John O'Hare](https://github.com/jjohare) · **Upstream IP**: [Melvin Carvalho](https://github.com/melvincarvalho) ([JSS](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer), [DID:Nostr](https://github.com/nicholasgasior/did-nostr)) · [MAINTAINERS.md](MAINTAINERS.md)

> **Upstream:** [JavaScriptSolidServer (JSS)](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer) — the AGPL-3.0 reference implementation of the [Solid Protocol](https://solidproject.org/TR/protocol), created and maintained by [Melvin Carvalho](https://github.com/melvincarvalho).
> This crate is a Rust port of JSS; see the upstream repo for the canonical feature set, issue tracker, and protocol discussion.

---

## What is Solid?

**Solid** (Social Linked Data) is a W3C specification that gives people control over their own data. Instead of scattering personal information across dozens of siloed apps, Solid stores it in a **pod** — a personal data server that the user owns or chooses. Apps ask the pod for permission to read or write data; the user decides who gets access to what.

The key ideas:

- **Your data stays in your pod.** A to-do app, a calendar, and a social feed can all read from the same storage — with your permission.
- **Apps are decoupled from storage.** You can switch apps without migrating data, because the data format (RDF) and the access rules (WAC) are standardised.
- **Identity is portable.** Your WebID is a URL you control. Log in once, use it everywhere — no platform lock-in.

Solid was incubated by Sir Tim Berners-Lee at MIT (2015–2018) and moved to the W3C Solid Community Group. The spec reached 0.9 in 2021 and 0.11 in 2023. Deployments range from academic data vaults (Flemish government's *MijnBurgerprofiel*) to personal pods on community hosts like solidcommunity.net. JSS (JavaScriptSolidServer) is the oldest open-source pod server and the reference against which conformance tests are written. **solid-pod-rs is JSS, rewritten in Rust.**

<details>
<summary><strong>JSS extensions beyond the core Solid spec</strong></summary>

JSS goes further than the base Solid Protocol in several areas. solid-pod-rs tracks all of these:

- **ActivityPub federation** — JSS can federate with Mastodon, Pleroma, and other fediverse servers. Pods can follow and be followed; posts are delivered via signed HTTP requests (draft-cavage-12 HTTP Signatures).
- **Embedded identity provider** — JSS includes a full Solid-OIDC identity provider (authorization-code flow, DPoP-bound tokens, dynamic client registration, JWKS publication) so operators don't need a separate IdP deployment.
- **Git HTTP backend** — JSS can serve Git repositories over smart HTTP, letting users store and clone code directly from their pod. solid-pod-rs additionally turns every LDP write into a git commit (git-marks, see *Provenance & trust ledger*) and WAC-gates all git routes.
- **Nostr integration** — NIP-98 HTTP authentication (Schnorr signatures over secp256k1), did:nostr DID document resolution, and an embedded NIP-01 relay.
- **Passkey and Schnorr SSO** — WebAuthn passkey authentication and NIP-07 Schnorr single sign-on as alternatives to password-based login.
- **did:key support** — Ed25519, P-256, and secp256k1 did:key documents with self-signed JWT verification (LWS 1.0 SSI profile).
- **HTTP 402 Web Ledgers + provenance** — a sovereign, Bitcoin-settled (sats; no EVM) trust ledger: PaymentCondition in WAC ACLs, per-read micropayments, routed order book + AMM with replay protection, multi-chain TXO deposits (btc/tbtc3/tbtc4/signet), and MRC20 minting/buy/withdraw with a full Bitcoin write side. The same taproot crypto anchors **block-trails** — a tamper-evident, hash-chained provenance trail — paired with always-on **git-marks**. See *Provenance & trust ledger* below and [Melvin Carvalho's Practical Guide to Solid](https://melvin.me/public/solid/) for a 10-part walkthrough of the JSS payment system.
</details>

<details>
<summary><strong>JSON-LD primer — why RDF?</strong></summary>

Solid uses **RDF** (Resource Description Framework) as its data model. Every piece of data is a triple: `subject → predicate → object`. For example:

```
<#me> <http://xmlns.com/foaf/0.1/name> "Alice" .
```

This is written in **Turtle** syntax. The same triple in **JSON-LD** looks like:

```json
{
  "@id": "#me",
  "http://xmlns.com/foaf/0.1/name": "Alice"
}
```

JSON-LD is JSON with a `@context` that maps short keys to full IRIs. Apps can consume JSON-LD as plain JSON and ignore the RDF layer entirely — or process the full graph if they need to reason across datasets.

ACL (Access Control List) documents use JSON-LD to express who can read, write, or control a resource. The WAC (Web Access Control) spec standardises the vocabulary (`acl:agent`, `acl:agentClass`, `acl:mode`, `acl:default`).
</details>

<details>
<summary><strong>DID:nostr — identity from a cryptographic keypair</strong></summary>

A **DID** (Decentralized Identifier) is a URL that resolves to a document describing a public key and how to verify signatures from it. `did:nostr` maps a Nostr public key (32-byte hex, secp256k1) to a DID document:

```
did:nostr:ab12cd34...  →  resolves to a DID Document with:
  - verificationMethod: Schnorr/secp256k1
  - alsoKnownAs: https://pod.example/profile/card#me  (cross-verified WebID)
```

This bridges the Nostr identity ecosystem with Solid's WebID system. A Nostr user can authenticate to a Solid pod using their existing keypair (NIP-98), and the pod resolves their identity through the did:nostr → WebID `alsoKnownAs` chain.

solid-pod-rs implements both Tier 1 (pubkey → DID Document) and Tier 3 (DID → WebID cross-verification via `alsoKnownAs`/`owl:sameAs`) resolution.
</details>

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
solid-pod-rs = { version = "0.5.0-alpha.4", features = ["fs-backend", "oidc"] }
```

```rust,no_run
use solid_pod_rs::storage::fs::FsBackend;
use std::path::PathBuf;

let storage = FsBackend::new(PathBuf::from("./pod-root"));
// Wire your HTTP framework of choice; see examples/embed_in_actix.rs.
```

All configuration keys accept either a JSON file entry or a `JSS_*` environment variable. See [`docs/reference/env-vars.md`](crates/solid-pod-rs/docs/reference/env-vars.md) for the full list.

---

## Crates

solid-pod-rs is a Cargo workspace of 7 crates. The core library is framework-agnostic; sibling crates add bounded-context features.

| Crate | docs.rs | Description |
|-------|---------|-------------|
| [`solid-pod-rs`](https://crates.io/crates/solid-pod-rs) | [![docs](https://img.shields.io/docsrs/solid-pod-rs)](https://docs.rs/solid-pod-rs) | Core library — LDP, WAC, WebID, auth, notifications, storage |
| [`solid-pod-rs-server`](https://crates.io/crates/solid-pod-rs-server) | [![docs](https://img.shields.io/docsrs/solid-pod-rs-server)](https://docs.rs/solid-pod-rs-server) | Drop-in server binary (actix-web + CLI) |
| [`solid-pod-rs-idp`](https://crates.io/crates/solid-pod-rs-idp) | [![docs](https://img.shields.io/docsrs/solid-pod-rs-idp)](https://docs.rs/solid-pod-rs-idp) | Solid-OIDC identity provider |
| [`solid-pod-rs-activitypub`](https://crates.io/crates/solid-pod-rs-activitypub) | [![docs](https://img.shields.io/docsrs/solid-pod-rs-activitypub)](https://docs.rs/solid-pod-rs-activitypub) | ActivityPub federation + HTTP Signatures |
| [`solid-pod-rs-nostr`](https://crates.io/crates/solid-pod-rs-nostr) | [![docs](https://img.shields.io/docsrs/solid-pod-rs-nostr)](https://docs.rs/solid-pod-rs-nostr) | did:nostr resolver + NIP-01 relay |
| [`solid-pod-rs-git`](https://crates.io/crates/solid-pod-rs-git) | [![docs](https://img.shields.io/docsrs/solid-pod-rs-git)](https://docs.rs/solid-pod-rs-git) | Git HTTP smart-protocol backend |
| [`solid-pod-rs-didkey`](https://crates.io/crates/solid-pod-rs-didkey) | [![docs](https://img.shields.io/docsrs/solid-pod-rs-didkey)](https://docs.rs/solid-pod-rs-didkey) | did:key + self-signed JWT verifier |

```mermaid
graph TD
    SERVER["solid-pod-rs-server\nCLI + actix-web transport"]
    CORE["solid-pod-rs\nProtocol primitives"]
    AP["solid-pod-rs-activitypub"]
    GIT["solid-pod-rs-git"]
    IDP["solid-pod-rs-idp"]
    NOSTR["solid-pod-rs-nostr"]
    DIDKEY["solid-pod-rs-didkey"]

    SERVER --> CORE
    SERVER --> IDP
    SERVER -.->|"feature: git"| GIT
    AP --> CORE
    GIT --> CORE
    IDP --> CORE
    NOSTR --> CORE
    DIDKEY --> CORE

    style SERVER fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style CORE fill:#2ecc71,stroke:#1a9850,color:#fff
    style AP fill:#e67e22,stroke:#bf6516,color:#fff
    style GIT fill:#e67e22,stroke:#bf6516,color:#fff
    style IDP fill:#e67e22,stroke:#bf6516,color:#fff
    style NOSTR fill:#e67e22,stroke:#bf6516,color:#fff
    style DIDKEY fill:#e67e22,stroke:#bf6516,color:#fff
```

---

## LDP — Linked Data Platform

Solid pods speak LDP. This means every URL is either a **resource** (a file with RDF metadata) or a **container** (a directory that lists its children). You interact with them using standard HTTP verbs: `GET` to read, `PUT` to create or replace, `POST` to add to a container, `PATCH` to edit in place, `DELETE` to remove, and `COPY` to duplicate resources with their ACL sidecars.

<details>
<summary><strong>Technical detail</strong></summary>

solid-pod-rs implements LDP Basic Containers per Solid Protocol §5.2–§5.3:

- **Content negotiation** — Turtle, JSON-LD, N-Triples (RDF/XML deferred per ADR-053).
- **PATCH** — N3 Patch (with `where` precondition → 412), SPARQL-Update, and JSON Patch (RFC 6902 extension).
- **`Prefer` header** — `return=minimal`, `include=containedIRIs`, `include=membership` (LDP §4.2.2, RFC 7240).
- **Conditional requests** — `If-Match` / `If-None-Match` with strong SHA-256 ETags → 304 / 412.
- **Range requests** — single-range `bytes=N-M` (RFC 7233).
- **Container membership** — `ldp:contains` with server-managed `dcterms:modified`, `stat:size`, `stat:mtime`.
- **Container creation via PUT** — `PUT` with `Link: <ldp:BasicContainer>; rel="type"` creates a container (JSS parity).
- **HTTP COPY** — `Source` header → resource + ACL sidecar duplication.
- **Glob GET** — `GET /folder/*` merges all Turtle resources into a single response (JSS parity).
- **`Updates-Via`** — GET responses include `Updates-Via` WebSocket header for live subscription discovery.
- **`.meta` sidecars** — RDF metadata that travels with the resource.

Modules: `ldp`, `storage::fs`, `storage::memory`, `storage::s3`.
</details>

---

## WAC — Web Access Control

Every resource on a Solid pod is protected by an Access Control List. The ACL specifies who (by WebID) can do what (read, write, append, control). No ACL means no access — deny by default. ACLs inherit from parent containers via `acl:default`, so you can set a policy once at the top and let it cascade.

<details>
<summary><strong>Technical detail</strong></summary>

The WAC evaluator implements the full [WAC spec](https://solidproject.org/TR/wac):

- **Modes** — `acl:Read`, `acl:Write`, `acl:Append`, `acl:Control`. `Write ⊇ Append`.
- **Agent matchers** — `acl:agent` (specific WebID), `acl:agentClass` (`foaf:Agent` = public, `acl:AuthenticatedAgent` = logged in), `acl:agentGroup` (group membership).
- **Inheritance** — walks up the path looking for `.acl` sidecars; `acl:default` propagates to descendants.
- **`acl:origin` enforcement** — feature `acl-origin`. Restricts access by request `Origin` header (WAC §4.3).
- **WAC 2.0 conditions** — `acl:ClientCondition`, `acl:IssuerCondition` with a pluggable `ConditionRegistry`.
- **Parser bounds** — 1 MiB Turtle input cap, 32-level JSON-LD depth cap (CWE-400 DoS hardening).
- **`WAC-Allow` header** — returned on 403 responses per the Solid Protocol transparency requirement.

Modules: `wac::evaluator`, `wac::resolver`, `wac::document`, `wac::origin`, `wac::conditions`.

See [`debug-acl-denials.md`](crates/solid-pod-rs/docs/how-to/debug-acl-denials.md) and [`wac-modes.md`](crates/solid-pod-rs/docs/reference/wac-modes.md).
</details>

---

## Provenance & trust ledger

A pod is not just storage — it is a record of *who changed what, when, and on whose authority*. As of `0.5.0-alpha.0` (ADR-059), solid-pod-rs makes that record first-class with two composable, cost-tiered provenance primitives. The headline value is **traceability**: every change to pod data is attributable to a commit, and high-value records carry an external, tamper-evident proof.

- **git-marks** (cheap, always-on) — every LDP write (`PUT` / `POST` / `PATCH`) becomes a git commit. The commit is captured as a `GitMark` and persisted as a [PROV-O](https://www.w3.org/TR/prov-o/) sidecar at `<resource>.prov.ttl`. You get content-addressed, append-only, tamper-evident ordering of every write for free — and a full, queryable history of who wrote each resource.
- **block-trails** (high-value, opt-in) — a Bitcoin-taproot-anchored, hash-chained, tamper-evident state trail. An anchor irreversibly timestamps a record against the Bitcoin chain, so no single party — not even the pod operator — can forge or silently rewrite it. This is one instance of a general provenance trail (the MRC20 payment token is another).

The two compose through `ProvenanceLog`: git-marks are recorded on **every** write; a Bitcoin anchor is added only when a resource's ACL carries a `ProvenanceAnchor` condition or the write is a high-value record. To keep on-chain cost amortised, an **epoch Merkle root** over a batch of git commits is anchored in a single transaction — so one Bitcoin tx notarises an entire epoch of writes. A `_prov` API resolves marks (`GET /{pod}/_prov/{commit_sha}`) and upgrades them to anchors (`POST /{pod}/_prov/anchor`).

Taken together with the payment layer below, this gives the pod a **verifiable, tamper-evident provenance** trail over its data and a **global trust ledger and value-transfer substrate** beneath it — sovereign and Bitcoin-settled, with no external trust assumptions and no chain to trust but Bitcoin.

<details>
<summary><strong>Technical detail</strong></summary>

- **`GitMark`** — `commit_sha`, `repo`, `branch` (pinned `main`), `parent` (prior commit → append-only chain). Produced by a `GitMarker` trait; the native implementation lives in `solid-pod-rs-git`, the wasm `core` build compiles a no-op marker.
- **`BlockTrailAnchor`** — `state_hash` (the JCS hash that commits to the git SHA, or an epoch Merkle root), `txid`, `vout`, derived P2TR `address`, `network`, `blockheight` (`None` until confirmed), and `state_strings` — a portable, independently-verifiable proof.
- **Crypto** — RFC-8785 JCS canonicalisation, SHA-256 state-chain linking, BIP-341 taproot key-chaining (pubkey **and** privkey), bech32m P2TR derivation. The write side (`bitcoin_tx.rs`: P2TR output construction, BIP-341 TapSighash, BIP-340 Schnorr signing, witness assembly) is byte-parity with JSS `token.js` and validated against the official BIP-340/341 test vectors. UTXO lookup and tx broadcast use the public [mempool.space](https://mempool.space/) API.
- **Default network is `testnet4`** — anchoring runs against testnet4 via the public mempool API by default; mainnet is an explicit operator choice. git-marks are always-on and cost nothing; Bitcoin anchors are opt-in and reserved for records that warrant the sats.
- **WAC condition** — `acl:ProvenanceAnchor` (`wac::anchor::ProvenanceAnchorEvaluator`) flags a resource as anchor-worthy, evaluated by the same `ConditionRegistry` as `PaymentCondition`.
- **Surface** — `ProvenanceMark` persisted as `<resource>.prov.ttl` and emitted on the `Updates-Via` notification stream. Routes: `GET /{pod}/{path}.prov.ttl`, `GET /{pod}/_prov/{commit_sha}`, `POST /{pod}/_prov/anchor` (NIP-98, payment-gated).
- **wasm-safe** — `GitMarker` / `BlockAnchorer` are `?Send` traits; all Bitcoin / mempool / process-spawning code is `#[cfg(not(target_arch = "wasm32"))]` behind feature `mrc20`.

Modules: `provenance` (`ProvenanceMark`, `GitMark`, `BlockTrailAnchor`, `ProvenanceLog`, `EpochAccumulator`, `prov_ttl`), `mrc20`, `bitcoin_tx`, `wac::anchor`. Feature: `mrc20`. See [ADR-059](crates/solid-pod-rs/docs/adr/ADR-059-provenance-primitives-block-trails-git-marks.md) and the [provenance upgrade master plan](crates/solid-pod-rs/docs/design/provenance-upgrade-master-plan.md).
</details>

---

## Payments & web ledger

solid-pod-rs inherits JSS's HTTP 402 economy and routes it end-to-end: a `PaymentCondition` in a WAC ACL gates a resource behind a price, the client pays, and the read succeeds. Settlement is **sovereign and Bitcoin-native** — sats over Bitcoin, no Ethereum or EVM. The same Bitcoin write-side that powers block-trail anchors also drives deposits, withdrawals, and the trading layer, so payments and provenance share one verified cryptographic core.

<details>
<summary><strong>Technical detail</strong></summary>

- **Web Ledger** — multi-currency CRUD, per-read micropayments, `X-Balance` / `X-Cost` / `X-Pay-Currency` headers, `/pay/.info`, `/pay/.balance`, multi-chain balance gating.
- **Deposits** — TXO and MRC20 deposit verification against real mempool UTXOs; per-user tweaked deposit addresses (`/pay/.address?user=<did>&chain=<id>`); claim / auto-detect.
- **Markets** — order book (sell / swap) and a constant-product AMM pool, both routed through `PaymentStore` as the **sole ledger I/O path**.
- **Replay protection** — every deposit passes `check_replay` / `record_replay`; double-spend of a settlement proof is rejected.
- **Anchored settlement** — settlement receipts can carry a `git_commit_sha`, `txid`, and `blockheight`, binding a payment to the code commit that approved it and the Bitcoin block that settled it.

The payment + provenance layers together form a verifiable, tamper-evident value-transfer substrate. See [Melvin Carvalho's Practical Guide to Solid](https://melvin.me/public/solid/) for a 10-part walkthrough of the JSS payment system, and the [master plan](crates/solid-pod-rs/docs/design/provenance-upgrade-master-plan.md) §1 for the full inheritance matrix.
</details>

---

## Authentication

solid-pod-rs ships two authentication paths. Both produce the same `AuthContext` (identity + granted modes), so WAC evaluation doesn't care which one the client used. You can run one, the other, or both side by side.

**NIP-98** — HTTP authentication over Nostr-signed events. The client signs a per-request event (kind 27235) binding the URL, method, and body hash. No IdP, no client registration, no token exchange — just a cryptographic keypair. This is the simplest path for sovereign-identity deployments.

**Solid-OIDC** — Standards-track Solid identity. Authorization-code flow with PKCE, DPoP-bound tokens (RFC 9449), and dynamic client registration. Use this when you need interop with existing Solid clients and identity providers.

<details>
<summary><strong>Technical detail — NIP-98</strong></summary>

- Always compiled (structural verifier). `nip98-schnorr` feature enables BIP-340 Schnorr signature verification via `VerifyingKey::verify_raw()` (raw 32-byte event-id message, no pre-hashing). This matches the BIP-340 specification and ensures interoperability with standard Nostr clients and the nostr-bbs ecosystem.
- Token: base64-encoded Nostr event in `Authorization: Nostr <token>`.
- Binds: URL (`u` tag), method (`method` tag), body hash (`payload` tag = `SHA-256(body)`).
- Timestamp tolerance: ±60 s. Max token size: 64 KB.
- Identity: pubkey → `did:nostr:{pubkey}`.

Module: `auth::nip98`. See [`configure-nip98-auth.md`](crates/solid-pod-rs/docs/how-to/configure-nip98-auth.md).
</details>

<details>
<summary><strong>Technical detail — Solid-OIDC + DPoP</strong></summary>

- Feature `oidc`. DPoP replay cache under `dpop-replay-cache`.
- DPoP proof verification: algorithm allowlist (`ES256`, `ES384`, `RS256`–`RS512`, `PS256`–`PS512`, `EdDSA`); `alg=none` and HMAC hard-rejected.
- `ath` (access-token hash) binding enforced per RFC 9449 §4.3.
- `jti` replay cache: per-process LRU, bounded, clock-aware, concurrent-safe.
- JWKS discovery: SSRF-guarded, DNS-rebinding-closed, with per-call IP pinning.
- RFC 7638 canonical JWK thumbprints (verified against appendix-A test vector).
- Issuer validation: `verify_access_token` enforces `iss == expected_issuer`.
- WebID extraction: URL-shaped WebIDs only from `webid` or `sub` claim.

Module: `oidc`. See [`enable-solid-oidc.md`](crates/solid-pod-rs/docs/how-to/enable-solid-oidc.md).
</details>

---

## Identity Provider

The `solid-pod-rs-idp` crate is a complete Solid-OIDC identity provider. It handles the full authorization-code flow with PKCE, issues DPoP-bound access tokens signed with ES256, manages dynamic client registration, and publishes JWKS. Operators can run a self-contained pod+IdP without needing a separate identity service.

<details>
<summary><strong>Technical detail</strong></summary>

- **Authorization-code flow** with PKCE (S256). Single-use auth codes. Configurable TTL.
- **DPoP token binding** — `cnf.jkt` = JWK thumbprint of the client's DPoP key. `ath` = SHA-256 of the access token.
- **ES256 signing** — Solid-OIDC mandates ES256 for DPoP. RS256 omitted to avoid pulling `rsa`.
- **Dynamic client registration** — `POST /idp/reg` returns `client_id` + `client_secret`. Client Identifier Documents fetched with SSRF guard.
- **Credentials endpoint** — email + password (argon2id hash). Rate-limited: 10/min per IP.
- **Password validation** — min 8 chars (CWE-521, matches JSS commit `1feead2`).
- **WebAuthn passkeys** — feature `passkey`. Built on `webauthn-rs` 0.5. User-verification required, `EdDSA`+`ES256`.
- **Schnorr SSO** — feature `schnorr-sso`. NIP-07-style challenge-response with 5-minute TTL.
- **Discovery** — `GET /.well-known/openid-configuration` and `GET /.well-known/jwks.json`.
- **Axum binder** — feature `axum-binder` for a pre-built Router with discovery, JWKS, registration, and credentials.

Crate: [`solid-pod-rs-idp`](https://docs.rs/solid-pod-rs-idp). See the [IdP README](crates/solid-pod-rs-idp/README.md) for the full auth-code flow diagram.
</details>

---

## Notifications

When data on a pod changes, subscribed clients need to know. Solid Notifications 0.2 defines the protocol: clients subscribe to a resource and receive events when it's created, modified, or deleted. solid-pod-rs ships three delivery mechanisms.

<details>
<summary><strong>Technical detail</strong></summary>

- **WebSocketChannel2023** — the current Solid Notifications 0.2 protocol. Subscribers `POST` a `NotificationChannel` and receive updates over a topic-bound WebSocket.
- **WebhookChannel2023** — same event model, delivered as outbound HTTP `POST` requests. RFC 9421 Ed25519 signing over `@method`, `@target-uri`, `content-type`, `content-digest`, `date`, `x-solid-notification-id`. Exponential backoff + circuit breaker.
- **Legacy `solid-0.1`** — feature `legacy-notifications`. Compatibility adapter for SolidOS data browser's older WebSocket dialect with WAC read-check on subscribe.
- Events are generated from storage-layer mutations via a `NotificationBus`. Custom backends emit events by calling `publish`.

Modules: `notifications::websocket`, `notifications::webhook`, `notifications::legacy`.
</details>

---

## ActivityPub Federation

Pods can participate in the fediverse. The `solid-pod-rs-activitypub` crate implements ActivityPub Actor discovery, inbox processing with HTTP Signature verification, outbox emission with follower fan-out, and a SQLite-backed persistence layer for followers, activities, and the delivery queue.

<details>
<summary><strong>Technical detail</strong></summary>

- **Actor documents** — Accept-negotiation between `application/activity+json` and LDP profiles.
- **Inbox** — `POST /inbox` with draft-cavage-12 HTTP Signature verification (RSA-SHA256). SHA-256 `Digest` header validation.
- **Outbox** — raw Notes auto-wrapped in `Create` activities. UUID IDs, ISO 8601 timestamps. Follower fan-out delivery.
- **Delivery** — HTTP Signature signing, exponential retry (5xx), no retry on 4xx. `enqueue_to_inboxes()` batch helper.
- **Store** — SQLite via `sqlx`. Tables: followers, following, inbox, outbox, delivery queue. Actor cache with 24-hour freshness.
- **Discovery** — NodeInfo 2.1 document emission. WebFinger JRD rendering.

Crate: [`solid-pod-rs-activitypub`](https://docs.rs/solid-pod-rs-activitypub). See the [AP README](crates/solid-pod-rs-activitypub/README.md) for the federation flow diagram.
</details>

---

## Storage Backends

The `Storage` trait abstracts the blob + metadata layer. The rest of the crate is backend-agnostic — LDP, WAC, notifications all work identically regardless of where bytes are stored.

<details>
<summary><strong>Technical detail</strong></summary>

- **`fs-backend`** (default) — POSIX filesystem. Sidecar `.meta` and `.acl` documents. Atomic rename for concurrent writers. Path traversal guard (`..` and `\0` rejection).
- **`memory-backend`** (default) — in-process `HashMap`. Tests, demos, ephemeral deployments.
- **`s3-backend`** (opt-in) — AWS S3 and S3-compatible stores (MinIO, R2, Backblaze B2). Metadata in object tags.
- **Custom backends** — implement `get`, `put`, `delete`, `list` on `ResourceMeta` + `Bytes`. See [`custom_storage.rs`](crates/solid-pod-rs/examples/custom_storage.rs).
- **Quota** — feature `quota`. Per-pod `.quota.json` sidecar with atomic writes. `JSS_DEFAULT_QUOTA` env var.

Modules: `storage::fs`, `storage::memory`, `storage::s3`, `quota`.
</details>

---

## Security

solid-pod-rs is designed to be safe by default. The library rejects paths containing `..` or null bytes, blocks SSRF against private IP ranges and cloud metadata endpoints, enforces size limits on ACL documents, and denies access when no ACL is found.

<details>
<summary><strong>Technical detail</strong></summary>

- **SSRF guard** — blocks RFC 1918, loopback, link-local, cloud metadata (169.254.169.254), and DNS resolution failures. Per-call IP pinning closes DNS-rebinding.
- **Dotfile allowlist** — only `.acl`, `.meta`, `.well-known`, `.quota.json`, `.account` are served. All other dotfiles return 404.
- **Path traversal** — both backends reject `..` and `\0` in `normalize`. Double-encoded traversal (`%252e%252e`) caught by the server middleware.
- **ACL parser bounds** — 1 MiB Turtle cap (`JSS_MAX_ACL_BYTES`), 32-level JSON-LD depth cap. Returns `PodError::PayloadTooLarge`.
- **Token size limit** — NIP-98 tokens > 64 KB rejected before parsing.
- **Password validation** — 8-char minimum (CWE-521).
- **Atomic quota writes** — temp-file + rename prevents torn `.quota.json`.
- **Webhook signing** — RFC 9421 Ed25519 over method, target-uri, content-type, content-digest, date, notification-id.
- **WAC-gated git smart-HTTP** — every git route runs `enforce_read` / `enforce_write` before reaching CGI; the anonymous-push hole is closed (ADR-059).
- **Payment replay protection** — settlement proofs pass `check_replay` / `record_replay`; `PaymentStore` is the sole ledger I/O path.

See [`SECURITY.md`](crates/solid-pod-rs/SECURITY.md) and the full [`security-model.md`](crates/solid-pod-rs/docs/explanation/security-model.md).
</details>

---

## Configuration

The server binary loads configuration in layers (lowest precedence first): compiled-in defaults → JSON/TOML config file → `JSS_*` environment variables. The variable names are identical to JSS so existing deployment scripts, Kubernetes manifests, and Docker Compose files work unchanged.

<details>
<summary><strong>Technical detail</strong></summary>

| Variable | Type | Purpose |
|----------|------|---------|
| `JSS_HOST` | string | Bind address (default `127.0.0.1`) |
| `JSS_PORT` | u16 | Listen port (default `3000`) |
| `JSS_BASE_URL` | URL | Externally visible base URL |
| `JSS_STORAGE_ROOT` | path | Filesystem root (FS backend) |
| `JSS_OIDC_ISSUER` | URL | Identity provider discovery URL |
| `JSS_WORKERS` | usize | actix-web worker count (default: CPU count) |
| `JSS_LOG_LEVEL` | string | `trace` / `debug` / `info` / `warn` / `error` |
| `JSS_MAX_ACL_BYTES` | usize | ACL document size cap (default 1 MiB) |
| `JSS_MAX_REQUEST_BODY` | string | Request body cap (e.g. `50MB`) |
| `JSS_DEFAULT_QUOTA` | string | Per-pod storage quota |

Full list: [`docs/reference/env-vars.md`](crates/solid-pod-rs/docs/reference/env-vars.md).
</details>

---

## Federation Transports

solid-pod-rs participates in all three DreamLab federation transport strata as the sovereign data layer — pods are the canonical store, and all three transports provide different paths to reach them.

### Stratum 1 — Tailscale (Private Mesh)

solid-pod-rs can be reached by agentbox containers over a [Tailscale](https://tailscale.com/) tailnet for private federation. This is an alternative to Cloudflare tunnels when the pod mesh does not need public exposure.

When solid-pod-rs runs standalone (not inside agentbox), Tailscale runs at the host level. The server binds to `0.0.0.0` and Tailscale ACLs control which nodes on the tailnet can reach it.

```bash
# On the host running solid-pod-rs:
tailscale up --hostname=solid-pods

# Server binds to all interfaces; Tailscale routes traffic:
solid-pod-rs-server --config config.json
# config.json contains:
#   "server": { "host": "0.0.0.0", "port": 8484 }
#   "server": { "base_url": "https://solid-pods.tailnet-name.ts.net:8484" }
```

Agentbox containers on the same tailnet discover the pod server via MagicDNS:

```
http://solid-pods.tailnet-name.ts.net:8484
```

<details>
<summary><strong>Security model and comparison with Cloudflare tunnels</strong></summary>

**Transport encryption.** Tailscale encrypts all traffic between nodes using WireGuard. NIP-98 bearer tokens still authenticate individual HTTP requests — the tailnet provides the encrypted channel, not the identity layer.

**ACL restriction.** Tailscale ACLs should restrict port 8484 to agentbox nodes only:

```json
{
  "acls": [
    {
      "action": "accept",
      "src": ["tag:agentbox"],
      "dst": ["tag:solid-pods:8484"]
    }
  ]
}
```

**Comparison with Cloudflare tunnel.** A Cloudflare tunnel exposes solid-pod-rs at a public HTTPS URL (e.g. `pods-native.dreamlab-ai.com`) with Cloudflare-managed TLS and DDoS protection. Tailscale provides private access restricted to tailnet members — no public endpoint. Both can coexist: Cloudflare for external clients, Tailscale for agentbox-to-pod traffic within the operator's infrastructure.

</details>

### Stratum 2 — Nostr Relays (All Components)

solid-pod-rs bridges Nostr events into pod storage via the pod-inbox bridge. The embedded NIP-01 relay accepts events authenticated with NIP-98 `did:nostr` signatures. Peer relays (agentbox instances, public Nostr relays) connect via standard WebSocket.

Pod owners receive governance events (kinds 31400-31405), direct messages, and federation notifications through the relay mesh. Events are persisted as Linked Data resources in the pod, making the Nostr relay mesh a durable delivery transport rather than an ephemeral bus.

For censorship resistance, operators can configure public relay fallbacks alongside private infrastructure relays. All events are Schnorr-signed — authentication is independent of transport.

### Stratum 3 — Cloudflare Tunnels (Edge to Local)

A Cloudflare tunnel exposes the pod server to CF Workers services (nostr-rust-forum, dreamlab-ai-website) without opening ports to the public internet. The tunnel terminates at the pod server's HTTP listener; NIP-98 signatures provide request-level authentication on top of the tunnel's transport security.

```toml
# Tunnel exposes solid-pod-rs at a public hostname
# CF Workers reach pods via: https://pods-native.dreamlab-ai.com/pods/{pubkey}/
```

Both Cloudflare tunnels (public HTTPS) and Tailscale (private WireGuard) can coexist — the pod server binds to `0.0.0.0` and accepts connections from either transport.

---

## Account Management

The server exposes the same account management endpoints as JSS, so existing Solid clients and deployment tooling work without modification. Pods are provisioned with a full directory structure: WebID profile, inbox, public/private containers, type indexes, and root ACL.

<details>
<summary><strong>Technical detail</strong></summary>

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/accounts/new` | POST | Create a new pod (username + optional display name) |
| `/pods/check/{name}` | GET | Check if a pod name is taken |
| `/login/password` | POST | Credentials login (delegates to IdP crate) |
| `/account/password/reset` | POST | Request password reset (anti-enumeration: always 200) |
| `/account/password/change` | POST | Change password with reset token |
| `/.well-known/solid` | GET | Discovery document with `api.accounts.*` URLs |

Pod provisioning creates: `/profile/card` (WebID), `/inbox/`, `/public/`, `/private/`, `/settings/`, `publicTypeIndex.jsonld`, `privateTypeIndex.jsonld`, and root `.acl`.
</details>

---

## Feature Flags

Feature flags keep the dependency surface tight. A minimal NIP-98-only build is under 200 KB of transitive deps; a full build stays under 40 MB.

| Flag | Default | Purpose |
|------|:-------:|---------|
| `fs-backend` | on | POSIX filesystem storage |
| `memory-backend` | on | In-process `HashMap` storage (tests/demos) |
| `s3-backend` | off | AWS S3 / S3-compatible object stores |
| `oidc` | off | Solid-OIDC 0.1 + DPoP |
| `dpop-replay-cache` | off | DPoP `jti` replay cache (pulls `oidc`) |
| `nip98-schnorr` | off | BIP-340 Schnorr signature verification for NIP-98 via `verify_raw()` (raw 32-byte message, no tagged pre-hash) |
| `acl-origin` | off | WAC `acl:origin` enforcement |
| `security-primitives` | off | SSRF guard + dotfile allowlist |
| `legacy-notifications` | off | `solid-0.1` WebSocket adapter (SolidOS) |
| `config-loader` | off | Layered config loader with `JSS_*` env vars |
| `webhook-signing` | off | RFC 9421 Ed25519 webhook signing |
| `did-nostr` | off | did:nostr resolver in `interop` |
| `mrc20` | off | Bitcoin block-trail anchors + taproot tx build/sign (BIP-340/341) for the provenance & payment layer |
| `rate-limit` | off | Sliding-window LRU rate limiter |
| `quota` | off | Per-pod `.quota.json` sidecar |

---

## Parity with JSS

solid-pod-rs has reached ~96% strict parity with JSS: on the 207-row tracker, 3 rows remain missing, 6 are explicitly deferred as legacy/P3, and 3 are wontfix-in-crate as consumer concerns. (This figure is derived from [`PARITY-CHECKLIST.md`](crates/solid-pod-rs/PARITY-CHECKLIST.md)'s own row counts; the earlier "~98% on the 132-row tracker" headline predates the §19–§21 row additions and the denominator recount.) The Rust port adds runtime advantages on top of feature parity: no Node.js dependency, single static binary, lower memory footprint, deterministic RDF serialisation, and compile-time feature gating.

```mermaid
timeline
    title JSS Parity Progression
    Sprint 6  : 40% strict
              : WAC 2.0 + webhook signing
    Sprint 7  : 55% strict
              : Rate limiter + CORS + middleware
    Sprint 8-9 : 66% strict
               : DPoP CVE fix + SSRF + dotfile
    Sprint 10  : 83% strict
               : Sibling crates land (AP, Git, IdP, Nostr)
    Sprint 11  : 97% strict
               : LWS 1.0 + did:key + legacy notifications
    Sprint 12  : 98% strict
               : JSS v0.0.60-v0.0.71 delta closed
    Sprint 16  : 96% strict
               : §19-21 rows added; 207-row denominator recount
```

See the full row-by-row accounting in [`PARITY-CHECKLIST.md`](crates/solid-pod-rs/PARITY-CHECKLIST.md) and the prose gap analysis in [`GAP-ANALYSIS.md`](crates/solid-pod-rs/GAP-ANALYSIS.md).

---

## Lineage and Licence

solid-pod-rs is a Rust port of [JavaScriptSolidServer](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer) and deliberately inherits JSS's AGPL-3.0 licence to preserve the ecosystem's network-service copyleft.

```
JavaScriptSolidServer (Node.js, AGPL-3.0)
        │
        ├── reference implementation
        │
solid-pod-rs (Rust, AGPL-3.0)   ← you are here
```

**AGPL-3.0-only.** If you operate solid-pod-rs as a network-accessible service — which, by the nature of a pod, you almost certainly will — §13 of the AGPL requires you to provide corresponding source to your users. See [`LICENSE`](LICENSE) and [`NOTICE`](crates/solid-pod-rs/NOTICE).

---

## Documentation

Full documentation follows the [Diataxis](https://diataxis.fr/) framework in [`crates/solid-pod-rs/docs/`](crates/solid-pod-rs/docs/):

- **Tutorials** — learning-oriented walkthroughs for new users
- **How-to guides** — goal-oriented recipes (configure auth, enable notifications, debug ACL denials)
- **Reference** — exhaustive API docs, env vars, WAC modes, agent integration guide
- **Explanation** — architecture decisions, security model, design rationale

---

## Part of VisionFlow

solid-pod-rs is the **cryptographic foundation** of the [VisionFlow](https://github.com/DreamLab-AI/VisionFlow) coordination platform — a federated architecture for human–AI intelligence built on `did:nostr` identity, OWL 2 EL reasoning, and Nostr message passing.

| Substrate | Repository | Role |
|:----------|:-----------|:-----|
| **VisionFlow** | [DreamLab-AI/VisionFlow](https://github.com/DreamLab-AI/VisionFlow) | Ecosystem guide and coordination architecture |
| **VisionClaw** | [DreamLab-AI/VisionClaw](https://github.com/DreamLab-AI/VisionClaw) | Knowledge engineering — OWL 2 EL, 92 CUDA kernels, XR |
| **Agentbox** | [DreamLab-AI/agentbox](https://github.com/DreamLab-AI/agentbox) | Harness engineering — Nix, 90+ skills, sovereign pods |
| **solid-pod-rs** | **[DreamLab-AI/solid-pod-rs](https://github.com/DreamLab-AI/solid-pod-rs)** | **Cryptographic foundation — JSS Rust port, DID:Nostr** |
| **nostr-rust-forum** | [DreamLab-AI/nostr-rust-forum](https://github.com/DreamLab-AI/nostr-rust-forum) | Forum kit — passkey auth, governance events |
| **dreamlab-ai-website** | [DreamLab-AI/dreamlab-ai-website](https://github.com/DreamLab-AI/dreamlab-ai-website) | Branded deployment — React, WASM, Cloudflare Workers |

---

## Contributing

See [`CONTRIBUTING.md`](crates/solid-pod-rs/CONTRIBUTING.md). Run `cargo test --all-features` and `cargo clippy --all-targets --all-features -- -D warnings` before opening a pull request. Security issues: follow [`SECURITY.md`](crates/solid-pod-rs/SECURITY.md).
