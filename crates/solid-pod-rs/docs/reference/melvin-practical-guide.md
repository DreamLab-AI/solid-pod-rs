# Reference: Melvin Carvalho's "A Practical Guide to Solid"

> **Author**: Melvin Carvalho
> **Published**: April 2026
> **URL**: <https://melvin.me/public/solid/>
> **Licence**: Published as public educational material on the author's Solid pod.

## Overview

Melvin Carvalho published a 10-part practical guide to the
JavaScript Solid Server (JSS), the upstream reference implementation
that solid-pod-rs ports to Rust. The guide covers the full lifecycle
from pod creation through WAC, authentication, payments, tokens,
multi-chain support, and programmable state anchoring.

This document maps each article to the corresponding solid-pod-rs
module and records implementation parity. For the row-level payment
gap analysis, see [`GAP-ANALYSIS.md` section C.9](../../GAP-ANALYSIS.md#c9-payments-tokens--web-ledgers).
For the row-level parity checklist, see rows 180-195 in
[`PARITY-CHECKLIST.md`](../../PARITY-CHECKLIST.md).

---

## Article Index

### Part 1 — "Your Data, Your Server" (`solid-acl.html`)

**Topic**: JSS installation, pod creation, WAC fundamentals, file
system layout.

**solid-pod-rs mapping**:

| Concept | Module | Status |
|---|---|---|
| Pod creation + directory scaffold | `provision::provision_pod` | present |
| WAC ACL evaluation | `wac::evaluate_access` | present |
| File system storage | `storage::fs::FileSystemStorage` | present |
| `.acl` sidecar convention | `wac::StorageAclResolver` | present |

All fundamentals covered by the core crate. See GAP-ANALYSIS.md
sections C.1 (LDP) and C.2 (WAC).

---

### Part 2 — "Your Nostr Key Is Your Login" (`solid-nostr.html`)

**Topic**: did:nostr identity, NIP-98 Schnorr authentication, ACL
with did:nostr agents.

**solid-pod-rs mapping**:

| Concept | Module | Status |
|---|---|---|
| NIP-98 HTTP auth (kind 27235) | `auth::nip98::verify_at` | present |
| Schnorr signature verification | `auth::nip98::verify_schnorr_signature` (feature `nip98-schnorr`) | present |
| did:nostr DID Document publication | `solid-pod-rs-nostr` crate: `render_did_document_tier1`, `render_did_document_tier3` | present |
| did:nostr <-> WebID resolver | `solid-pod-rs-nostr` crate: `NostrWebIdResolver` | present |

See GAP-ANALYSIS.md section C.3 (Authentication).

---

### Part 3 — "HTTP 402: The Missing Status Code" (`solid-402.html`)

**Topic**: PaymentCondition in WAC ACLs, membership gates, deposit
verification via the 402 status code.

**solid-pod-rs mapping**:

| Concept | Module | Status |
|---|---|---|
| `PaymentCondition` in WAC | `wac::conditions::PaymentCondition` | present |
| HTTP 402 response body | `payments::payment_required_body()` | present |
| Payment discovery endpoint | `payments::pay_info()` | present |

See GAP-ANALYSIS.md section C.9 (Payments).

---

### Part 4 — "Pay Per Read" (`solid-pay.html`)

**Topic**: Per-read micropayments, balance deduction, X-Cost and
X-Balance response headers.

**solid-pod-rs mapping**:

| Concept | Module | Status |
|---|---|---|
| Balance deduction on read | `payments::debit()` | present |
| Balance credit on deposit | `payments::credit()` | present |
| X-Cost / X-Balance headers | `payments::payment_response_headers()` | present |

---

### Part 5 — "Your Pod Is Your Bank" (`solid-balance.html`)

**Topic**: Webledger JSON format, TXO URI scheme
(`txo:chain:txid:vout`), balance endpoints.

**solid-pod-rs mapping**:

| Concept | Module | Status |
|---|---|---|
| WebLedger JSON storage | `payments::WebLedger` struct | present |
| TXO URI parsing | `payments::parse_txo_uri()` | present |
| Balance endpoint `/pay/.balance` | `payments::balance_response()` | present |

---

### Part 6 — "Anchored to Bitcoin" (`solid-blocktrails.html`)

**Topic**: BIP-341 key chaining (SHA256 tweak, scalar addition,
P2TR address derivation), the `blocktrails` npm package.

**solid-pod-rs mapping**:

| Concept | Module | Status |
|---|---|---|
| BIP-341 chained public key derivation | `mrc20::bt_derive_chained_pubkey()` | present (feature `mrc20`) |
| BIP-341 chained private key derivation | `mrc20::bt_derive_chained_privkey()` | present (feature `mrc20`) |
| P2TR address derivation | `mrc20::bt_address()` | present (feature `mrc20`) |
| Anchor verification against mempool | `mrc20::verify_mrc20_anchor()` + `MempoolHttpClient` | present (feature `mrc20`; live mempool wired 0.5.0-alpha.0) |
| Bitcoin tx build + Schnorr/taproot sign | `bitcoin_tx` (P2TR, BIP-341 TapSighash, BIP-340) | present (feature `mrc20`; byte-parity with JSS `token.js`, 0.5.0-alpha.0) |
| Generic (non-token) provenance trail | `provenance::BlockTrailAnchor`, `ProvenanceLog` | present (0.5.0-alpha.0 — MRC20 is one instance, ADR-059) |

---

### Part 7 — "Your Pod, Your Token" (`solid-tokens.html`)

**Topic**: MRC20 token minting, `/pay/.buy` and `/pay/.withdraw`
endpoints, portable MRC20 proofs.

**solid-pod-rs mapping**:

| Concept | Module | Status |
|---|---|---|
| MRC20 state machine | `mrc20::Mrc20State`, `Mrc20Op` | present |
| State validation | `mrc20::validate_mrc20_state()` | present |
| Hash chain verification | `mrc20::verify_state_link()` | present |
| Deposit verification | `mrc20::verify_mrc20_deposit()` | present |
| JCS canonicalisation (RFC 8785) | `mrc20::jcs()` | present |

---

### Part 8 — "Multi-Currency" (`solid-multi.html`)

**Topic**: Multi-chain support (btc, tbtc3, tbtc4, signet),
`/pay/.offers`, `/pay/.sell`, `/pay/.swap`.

**solid-pod-rs mapping**:

| Concept | Module | Status |
|---|---|---|
| Multi-chain config with mempool URLs | `payments::ChainConfig` (btc, tbtc3, tbtc4, signet presets) | present |
| `/pay/.offers` listing | `trading::OrderBook::list_offers()` → `handlers::pay::handle_offers` | present (routed 0.5.0-alpha.0) |
| `/pay/.sell` order placement | `trading::OrderBook::create_order()` → `handle_sell` | present (routed 0.5.0-alpha.0) |
| `/pay/.swap` atomic swap | `trading::OrderBook::execute_swap()` → `handle_swap` | present (routed 0.5.0-alpha.0) |

The multi-chain deposit and verification infrastructure is at parity. The
peer-to-peer trading surface (sell, swap, offers) is complete and **routed**
as of 0.5.0-alpha.0 — the library logic existed earlier but was orphaned;
it is now mounted on HTTP via `handlers::pay`.

---

### Part 9 — "Your Pod Is an Exchange" (`solid-amm.html`)

**Topic**: Automated market maker, constant-product `x*y=k`,
`/pay/.pool`, liquidity provision.

**solid-pod-rs mapping**:

| Concept | Module | Status |
|---|---|---|
| AMM constant-product pool | `trading::AmmPool` (`x·y=k`, `add_liquidity`/`remove_liquidity`/`swap`, 30 bps default) | present (routed 0.5.0-alpha.0) |
| `/pay/.pool` endpoint | `trading::Exchange` → `handlers::pay::handle_pool_{get,post}` | present (routed 0.5.0-alpha.0) |

The AMM is a live constant-product pool. `GET /pay/.pool` returns pool
reserves/shares (or the registry); `POST /pay/.pool` runs `swap` /
`add-liquidity` / `remove-liquidity`, settling against the same Web Ledger.

---

### Part 10 — "Beyond Tokens" (`solid-beyond.html`)

**Topic**: Programmable state anchoring — NFTs, smart contracts, git
commits via blocktrails.

**solid-pod-rs mapping**:

| Concept | Module | Status |
|---|---|---|
| Token-specific state trails | `mrc20::Mrc20Trail` | present |
| Generic state anchoring abstraction | `provenance::BlockTrailAnchor`, `BlockAnchorer`, `ProvenanceLog` | present (0.5.0-alpha.0 — ADR-059 D2: MRC20 is one instance of a general trail) |
| git-commit anchoring | `provenance::ProvenanceLog::record` (anchored `state_hash` = git commit SHA; epoch Merkle batching) | present (0.5.0-alpha.0) |
| NFT / smart contract rules engine | not implemented | **missing** (P3 — out of scope; Bitcoin-only, no VM) |

The generic state-anchoring abstraction landed in 0.5.0-alpha.0: ADR-059
lifts the trail from a token-only structure to one carrying arbitrary
JCS-canonicalised payloads (`provenance`), with the MRC20 token as one
instance. git commits are anchored via `ProvenanceLog` (the anchored
`state_hash` is the git commit SHA, with epoch Merkle-root batching). A
programmable NFT / smart-contract rules engine remains out of scope —
the model is Bitcoin-anchored provenance, not a contract VM.

---

## Summary

| Part | Title | Primary Module(s) | Parity |
|---|---|---|---|
| 1 | Your Data, Your Server | `provision`, `wac`, `storage::fs` | full |
| 2 | Your Nostr Key Is Your Login | `auth::nip98`, `solid-pod-rs-nostr` | full |
| 3 | HTTP 402: The Missing Status Code | `wac::conditions`, `payments` | full |
| 4 | Pay Per Read | `payments` | full |
| 5 | Your Pod Is Your Bank | `payments` | full |
| 6 | Anchored to Bitcoin | `mrc20`, `bitcoin_tx` (feature `mrc20`) | full |
| 7 | Your Pod, Your Token | `mrc20` | full |
| 8 | Multi-Currency | `payments::ChainConfig`, `trading::OrderBook` | full (trading surface routed 0.5.0-alpha.0) |
| 9 | Your Pod Is an Exchange | `trading::AmmPool` / `Exchange` | full (AMM routed 0.5.0-alpha.0) |
| 10 | Beyond Tokens | `provenance` (`BlockTrailAnchor`, `ProvenanceLog`) | full for generic anchoring; NFT/contract VM out of scope |

**Overall**: as of 0.5.0-alpha.0 all 10 articles' payment/token/anchoring
surfaces are implemented and routed. The core lifecycle (deposit, balance,
debit, buy, withdraw, blocktrail anchor) plus the exchange layer (sell,
swap, offers, AMM pool) and the generalised provenance trail are all
present — the previously-orphaned trading/AMM logic is now mounted on HTTP
(`handlers::pay`), and ADR-059 added the generic, non-token block-trail
abstraction. The only deliberate non-goal is a programmable NFT /
smart-contract rules engine (Bitcoin-only, no VM).
