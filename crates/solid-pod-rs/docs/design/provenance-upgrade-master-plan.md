# Master Plan — Block-trails & Git-marks Provenance + JSS Payment Maturity

**Date:** 2026-06-13
**Status:** Ready for implementation
**Companion ADR:** [ADR-059](../archive/adr/ADR-059-provenance-primitives-block-trails-git-marks.md)
**Origin:** Produced by a 6-reader research mesh over JavaScriptSolidServer (JSS,
gh-pages v0.0.197), this crate, and the downstream VisionFlow consumers
(agentbox, nostr-rust-forum, dreamlab-ai-website, VisionClaw).

## Why

Two forces converge:

1. **JSS payment maturity.** JSS has moved well ahead on the HTTP-402 economy
   (primary/secondary markets, multi-currency conditions, chain-balance,
   deposit-address auto-detect, mint-root, withdraw). Our port has a strong,
   well-tested foundation but several capabilities are **built yet unrouted**,
   and the Bitcoin write-side (tx-building/broadcast) is absent.

2. **Provenance as a first-class concern (operator steer, 2026-06-13).**
   *"Block trails might be absolutely crucial to our provenance system for
   agents within agentbox."* This graduates the Blocktrails MRC20 mechanism
   from a token feature into a **general, Bitcoin-anchored provenance
   primitive**, and pairs it with **git-marks** (write-as-commit) as the cheap,
   always-on tier. Both land here, at the lowest level, so every downstream
   consumer inherits verifiable traceability without re-implementing crypto.

**Money model (PRD-015 v1.2, non-negotiable):** Lightning/L402/NWC + Bitcoin
sats. No Ethereum/EVM. JSS is Bitcoin-native (TXO deposits, taproot MRC20), so
it is the correct upstream.

**Pin baseline:** workspace `0.4.0-alpha.17`. Target release: `0.5.0-alpha.0`.

---

## 1. Inheritance matrix

Verdict legend — **REPLACE**: ours is behind/wrong, swap for JSS-derived logic ·
**PORT-NEW**: absent in ours, port from JSS · **KEEP**: at parity or better ·
**EXTEND**: correct foundation, missing capability.

### 1A. Payment core

| Feature | Our state | Verdict | JSS target | Our target |
|---|---|---|---|---|
| Web Ledger CRUD + multi-currency | FULLY IMPL (`payments.rs:33-176`, `trading.rs:27-123`) | KEEP | `webledger.js:83-165` | — |
| `/pay/.info` | IMPL, parity (`lib.rs:1818`) | KEEP | `pay.js:258-283` | — |
| `/pay/.balance` | body defined, **no handler** (`payments.rs:272`) | PORT-NEW | `pay.js:307-373` | `handlers/pay.rs` |
| `/pay/.deposit` (TXO) | parser only (`payments.rs:367-413`) | PORT-NEW | `pay.js:440-474` | `handlers/pay.rs`+`mempool.rs` |
| `/pay/.deposit` (MRC20) | anchor verify exists, unrouted | PORT-NEW | `pay.js:384-438`, `mrc20.js:279-335` | `handlers/pay.rs` |
| `/pay/.deposit` claim/auto-detect | MISSING | PORT-NEW | `pay.js:476-541` | `handlers/pay.rs`+`mempool.rs` |
| Per-user tweaked deposit addr `/pay/.address` | MISSING | PORT-NEW | `pay.js:286-305` | `mrc20.rs`+`handlers/pay.rs` |
| `/pay/.withdraw-sats` (TXO voucher) | MISSING | PORT-NEW | `pay.js:763-898`, `token.js:117-174` | `bitcoin_tx.rs` |
| Bitcoin TX build + Schnorr/taproot sign | MISSING (verify-only) | PORT-NEW | `token.js:117-174` | `bitcoin_tx.rs` (feat `mrc20`) |
| Mempool HTTP client | MISSING | PORT-NEW | `token.js:176-187`, `mrc20.js:315-327` | `mempool.rs` (non-wasm) |
| Replay protection wiring | DEFINED, **never called** (`payments.rs:441-442`) | REPLACE | `pay.js:106-128` | `handlers/pay.rs` |
| `PaymentStore` trait impl | orphaned; runtime uses inline `Storage::get/put` | REPLACE | — (ours is cleaner) | `StoragePaymentStore` |
| Multi-chain balance gating | NOT WIRED | PORT-NEW | `pay.js:1306-1315` | `handlers/pay.rs` |
| `X-Balance/X-Cost/X-Pay-Currency` | IMPL (`payments.rs:319-329`) | KEEP | issue #259 | — |
| Order book (sell/swap) | COMPLETE, 15 tests, **orphaned** (`trading.rs:161-314`) | EXTEND (route) | `pay.js:906-1058` | `handlers/pay.rs` |
| AMM pool | COMPLETE, 16 tests, **orphaned** (`trading.rs:320-543`) | EXTEND (route) | `pay.js:1060-1289` | `handlers/pay.rs` |

### 1B. Block-trails (MRC20 / Bitcoin anchor)

| Feature | Our state | Verdict | JSS target | Our target |
|---|---|---|---|---|
| JCS (RFC 8785) | COMPLETE (`mrc20.rs:32-63`) | KEEP | `mrc20.js:32-37` | — |
| `Mrc20State`/`Mrc20Trail` | COMPLETE (`mrc20.rs:72-122`) | KEEP | `token.js:250-260` | — |
| State link + seq verify | COMPLETE (`mrc20.rs:151-171`) | KEEP | `mrc20.js:54-72` | — |
| BIP-341 chained pubkey/privkey | COMPLETE, feat `mrc20` (`mrc20.rs:263-312`) | KEEP | `token.js:83-110` | — |
| Bech32m P2TR address | COMPLETE (`mrc20.rs:360-402`) | KEEP | `mrc20.js:241-265` | — |
| Anchor verify (crypto) | COMPLETE minus mempool (`mrc20.rs:409-449`) | EXTEND | `mrc20.js:279-335` | wire `mempool.rs` |
| Mint genesis (TX build + broadcast) | MISSING | PORT-NEW | `token.js:239-307` | `bitcoin_tx.rs` |
| Transfer (chained-key TX) | MISSING | PORT-NEW | `token.js:310-389` | `bitcoin_tx.rs` |
| Trail load/save (server) | MISSING | PORT-NEW | `token.js:198-208` | `trail_store.rs` |
| Portable proof struct | types present, not produced | EXTEND | `pay.js:647-656` | `handlers/pay.rs` |
| **General (non-token) `ProvenanceTrail`** | MISSING | PORT-NEW | (generalise `mrc20`) | `provenance.rs` |

### 1C. Git-marks (write-as-commit)

| Feature | Our state | Verdict | JSS target | Our target |
|---|---|---|---|---|
| Git smart-HTTP CGI | COMPLETE (`service.rs:194-269`) | KEEP | `git.js:190-386` | — |
| Path-traversal guard | COMPLETE (`guard.rs:68-105`) | KEEP | `git.js:31-64` | — |
| Push config (`updateInstead`) | COMPLETE per write (`config.rs:71-87`) | KEEP | `git.js:248-266` | — |
| Basic/Nostr auth bridge | COMPLETE (`auth.rs:60-171`) | KEEP | git CGI env | — |
| **WAC gating of git routes** | **BROKEN** — `handle_git` never enforces; anonymous push (`lib.rs:2986`) | REPLACE | `server.js:498-530` | `lib.rs` |
| Auto-init on first push | provisioning-time only; missing repo → 404 (`service.rs:226`) | PORT-NEW | `git.js:135-166` | `service.rs`+`init.rs` |
| Auto-init `-b main` pin | COMPLETE (`init.rs:92-115`) | KEEP | `git.js:143-149` | — |
| **Write-as-commit on LDP PUT/POST/PATCH** | **MISSING** — pure `storage.put()` (`lib.rs:885-1096`) | PORT-NEW | `updateInstead` model | `mark.rs` hook |
| Symlink/realpath hardening | MISSING both sides | EXTEND | `git.js:122-129` | `guard.rs` |

### 1D. WAC conditions

| Feature | Our state | Verdict | JSS target | Our target |
|---|---|---|---|---|
| `PaymentCondition` parse+eval (fail-closed) | COMPLETE, 12 tests (`payment.rs:21-93`) | KEEP | `checker.js:155-197` | — |
| Zero-cost gate (cost=0 → proof-of-past-deposit) | partial — does not check "has ANY ledger entry" | REPLACE | `checker.js:178-180` | `payment.rs` |
| Multi-currency PaymentCondition | NO, `cost_sats` only (`payment.rs:34`) | EXTEND | `checker.js:168` | `payment.rs` |
| Unknown-condition 422 at write | COMPLETE (`conditions.rs:337-368`) | KEEP | `checker.js:158-159` | — |

---

## 2. Provenance primitive design

Two composable, cost-tiered primitives become first-class in core:

- **git-mark** — cheap, always-on, content-addressed (git SHA-1 / Merkle),
  local. Every pod write becomes a commit.
- **block-trail anchor** — expensive, optional, Bitcoin-anchored (taproot MRC20
  UTXO). Reserved for high-value records (settlement receipts, elevation
  decisions, epoch snapshots).

### 2.1 Data model — `crates/solid-pod-rs/src/provenance.rs`

```rust
/// A provenance mark over a pod resource write. Always carries a git commit;
/// optionally upgraded with a Bitcoin block-trail anchor for high-value records.
pub struct ProvenanceMark {
    pub resource: String,                 // pod-relative path
    pub git: GitMark,                     // ALWAYS present (cheap tier)
    pub anchor: Option<BlockTrailAnchor>, // OPTIONAL (expensive tier)
    pub agent_did: String,                // did:nostr of writer (NIP-98)
    pub created: u64,
}

pub struct GitMark {
    pub commit_sha: String,   // git SHA-1 of the commit the write produced
    pub repo: String,         // pod repo slug
    pub branch: String,       // "main" (pinned, init.rs)
    pub parent: Option<String>, // prior commit (append-only chain)
}

pub struct BlockTrailAnchor {
    pub ticker: String,
    pub state_hash: String,        // sha256_hex(jcs(state)) — links into MRC20 trail
    pub txid: String,
    pub vout: u32,
    pub address: String,           // derived P2TR (mrc20.rs:bt_address)
    pub network: String,           // "testnet4" | "mainnet"
    pub blockheight: Option<u64>,  // None until confirmed
    pub state_strings: Vec<String>,// portable, independently verifiable proof
}
```

`BlockTrailAnchor` reuses existing `mrc20.rs` types (`Mrc20State`, `bt_address`,
`verify_mrc20_anchor`) — **no crypto re-implementation**.

### 2.2 Traits

```rust
/// Cheap tier. Implemented by solid-pod-rs-git. ?Send (wasm32-safe); no-op on wasm.
#[async_trait(?Send)]
pub trait GitMarker: Send + Sync {
    async fn mark_write(&self, repo: &Path, path: &str, agent_did: &str, message: &str)
        -> Result<GitMark, ProvenanceError>;
    async fn head(&self, repo: &Path) -> Result<Option<String>, ProvenanceError>;
}

/// Expensive tier. Server-side (mempool + Bitcoin TX). Behind feature `mrc20`.
#[async_trait(?Send)]
pub trait BlockAnchorer: Send + Sync {
    async fn anchor(&self, ticker: &str, state_hash: &str, network: &str)
        -> Result<BlockTrailAnchor, ProvenanceError>;
    async fn verify(&self, anchor: &BlockTrailAnchor) -> Result<bool, ProvenanceError>;
}

pub struct ProvenanceLog {
    pub marker: Arc<dyn GitMarker>,
    pub anchorer: Option<Arc<dyn BlockAnchorer>>, // None in pods that don't pay for Bitcoin
}
```

### 2.3 Composition rule (cheap-always, expensive-opt-in)

`ProvenanceLog::record(write)`:

1. **Always** `marker.mark_write()` → `GitMark` (the `updateInstead` commit the
   pod already produces; we now *capture and surface* the SHA).
2. **Conditionally** anchor when `anchorer.is_some()` AND (the resource ACL
   carries a `ProvenanceAnchor` condition OR the write is a high-value record).
   The `state_hash` placed in the trail **is** the git commit SHA (or a JCS hash
   that includes it) → the Bitcoin anchor commits to the git history, binding
   both primitives into one chain.
3. Persist `ProvenanceMark` as a PROV-O sidecar at `<resource>.prov.ttl`, and
   emit it on the `Updates-via` notification stream so subscribers see new marks.

**Why correct:** git gives tamper-evident ordering + content-addressing free on
every write (Merkle history). Bitcoin gives external, trustless, irreversible
timestamping but costs sats + a mempool round-trip per state. Anchoring the git
SHA into the MRC20 trail means **one Bitcoin tx notarises an entire epoch of git
commits** (epoch Merkle root → one anchor) — retroactive immutability without
per-write on-chain cost.

### 2.4 Server API surface

- `GET  /{pod}/{path}.prov.ttl` — provenance sidecar (PROV-O).
- `GET  /{pod}/_prov/{commit_sha}` — resolve a git-mark to resource + optional anchor.
- `POST /{pod}/_prov/anchor` (NIP-98, payment-gated) — upgrade a git-mark to a Bitcoin anchor.
- `GET  /pay/.address?user=<did>&chain=<id>` — per-user tweaked deposit address.

---

## 3. Downstream augmentation

All consumers derive provenance from the upgraded pod; settlement/receipts flow
*up*, provenance proofs flow *down*.

**agentbox (402 settlement + spend receipts).** `/pay/.deposit` proxies to the
upgraded pod doing real mempool verification → C12 moves from trusted-write to
Bitcoin-confirmed. Every `urn:agentbox:receipt:<scope>` gains
`git_commit_sha` + `blockheight` + `txid` trailers ("this payment was approved
by code commit abc123, settled at block X"). `[payments.consumer]` threshold
changes land via signed governance-repo commits; the spend gate records the
policy commit SHA into each `urn:agentbox:activity:pay-*`.

**forum / website.** Each `.acl` PUT records its git commit SHA → access
decisions auditable by commit. `txo_deposits` gain `blockheight` (min-conf
before crediting). `/api/native-pod/provision` emits a commit to a
`provisioning-audit` repo.

**VisionClaw (elevation / beads / receipts / ACSP).** Elevation PR merge commit
SHA embedded in `urn:visionclaw:concept:...#merged_at=<sha>` — completing a
five-link ancestry: `elevatedFrom` → agentbox activity URN → (BC20) →
elevation decision → PR merge commit → corpus lineage. Beads gain a
`blockheight` once settlement confirms. Crossed `urn:agentbox:activity:pay-*`
materialise as VisionClaw `execution` nodes (**requires** wiring the BC20
host-ingest gap, economy-loop.md:163). ACSP kind-31402/31403 decisions gain a
`git_commit_sha` of the decision corpus state.

---

## 4. Phased implementation

Lowest-risk highest-value first; this crate lands before any downstream;
crypto-correct primitives before I/O; routing already-built logic before new
TX-building.

- **Phase 0 — Wire orphaned logic.** Route the complete+tested trading/balance/
  deposit logic; implement `StoragePaymentStore: PaymentStore`; wire
  `check_replay`/`record_replay`. New `handlers/pay.rs`. *Done:* JSS-parity
  JSON, replay rejection, `PaymentStore` sole ledger I/O, tests green.
- **Phase 1 — WAC-gate git (security).** `handle_git` calls `enforce_read/write`;
  inject auth into `GitHttpService`. *Done:* no git path reaches CGI without
  WAC; anonymous-push hole closed.
- **Phase 2 — git-marks.** `GitMarker` trait + impl; hook `mark_write()` into
  LDP write handlers; on-demand auto-init. *Done:* every PUT/POST/PATCH yields a
  commit + PROV-O sidecar; first push auto-inits; `.git` direct access still 403.
- **Phase 3 — mempool + anchor verify (read-side).** `mempool.rs`; wire into
  `verify_mrc20_anchor` + `/pay/.deposit` MRC20/auto-detect; `BlockAnchorer::verify`.
  *Done:* anchor proofs verified against **fixture** UTXOs (no live chain in CI).
- **Phase 4 — Bitcoin TX build + broadcast (highest risk).** `bitcoin_tx.rs`
  (P2TR build, BIP-341 Schnorr/TapSighash sign, witness); mint/transfer/
  withdraw-sats; `BlockAnchorer::anchor`; `trail_store.rs`. *Done:* taproot tx
  verified on **regtest**; portable proof independently verifiable.
- **Phase 5 — Composition + sidecar API.** `ProvenanceLog::record`;
  `ProvenanceAnchor` WAC condition; epoch-Merkle-root anchoring; `_prov` routes.
  *Done:* composition enforced; epoch anchoring works; `0.5.0-alpha.0` tagged.
- **Phase 6 — Downstream pin bump + augmentation.** Bump consumers to
  `0.5.0-alpha.0`; wire §3; resolve BC20 host-ingest gap. *Done:* all consumers
  settle via upgraded pod; provenance chains end-to-end.

---

## 5. Risks & open questions

- **BIP-341 sign correctness** (`bitcoin_tx.rs`, Phase 4) is the highest-risk
  item — validate against official BIP-341 test vectors before any broadcast;
  reuse the verified `mrc20.rs` chained-key derivation rather than re-deriving.
- **JCS determinism** must be byte-identical Rust↔JS (state hashes chain across
  both) — add a cross-impl golden-fixture test.
- **No live chain in CI** — Phase 3 verify-side uses captured mempool-JSON
  fixtures; Phase 4 write-side uses bitcoind regtest.
- **wasm32 split** — `bitcoin_tx.rs`/`mempool.rs`/native `GitMarker` are
  non-wasm; `core` (wasm) compiles with a no-op `GitMarker` and
  `anchorer: None`. Gate with `#[cfg(not(target_arch = "wasm32"))]` + a wasm CI job.
- **Coordinated pin bump** — agentbox pins `0.4.0-alpha.17` exactly; bumping is a
  four-repo change (Phase 6). Additions are non-breaking, but audit forum
  `pod-worker` re-exports before bump.
- **Operator decisions:** min-confirmation policy (suggest 6 blocks); which
  records anchor (settlement receipts + elevation decisions clear; ACL writes
  epoch-only to bound cost); mainnet vs testnet4 for production; whether
  `/pay/.address` per-user addresses are publicly exposed (DID→address linkage).
