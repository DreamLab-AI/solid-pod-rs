---
id: ADR-2007
title: Anchor against one configured explorer URL, public default, no silent fallback
date: 2026-08-31
decision_status: accepted
implementation_status: complete
activation_status: live
supersedes: []
superseded_by: []
verified_commit: e093e88
owner: jjohare
review_trigger: the LAN Bitcoin node passes its cutover checklist, or telemetry justifies a fallback chain
repo: solid-pod-rs
domain: BASELINE-solid-pod-rs.md
lineage: Distils archived ADR-061 (LAN Bitcoin node substrate — non-goals: no ordered multi-URL fallback, LAN URL is deployment config not a crate default) and ADR-059 D3 (the mempool write side the anchor consumes).
---

# ADR-2007 — Anchor against one configured explorer URL, public default, no silent fallback

## Context

Block-trail anchoring needs a mempool.space-style REST backend for UTXO lookup
and tx broadcast. A sovereign LAN node (192.168.2.27) is intended but was
unreachable at design time. The obvious convenience — an ordered LAN→public
fallback so anchoring "just works" — would let a broken LAN node hide behind a
public explorer and silently reintroduce the third-party dependency the LAN node
exists to remove.

## Decision

`MempoolHttpClient` speaks exactly one configured REST base URL and fails loudly
on it — the struct holds a single `base: String` with no fallback list
(`mempool.rs:56-72`). The shipped crate default stays the **public**
`https://mempool.space/testnet4` (`mempool.rs:48`), so a pod without LAN access
keeps working; a sovereign/LAN explorer is selected purely by
`JSS_PAY_MEMPOOL_URL` (`mempool.rs:44`) as deployment configuration, never a new
crate default. Pod code never speaks bitcoind RPC directly — the REST seam
(`MempoolLookup`/`MempoolBroadcast`) is the only substrate boundary. A failed
lookup surfaces as an error, not a failover.

## Consequences

- Forecloses LAN→public failover: a down LAN node breaks anchoring visibly
  rather than degrading to a public explorer unnoticed; revisiting needs
  explicit telemetry.
- Keeping the public testnet4 default means the stock build's settlement path
  still touches a third party — sovereignty is a deployment act, not a default.
- The single-URL client cannot straddle mainnet and testnet4 at once; a
  deployment needing both runs two configured clients.
- Speaking only REST (never RPC) keeps the node's RPC LAN-firewalled to its own
  stack, at the cost of depending on an explorer's REST schema fidelity.

## Verification

- `mempool.rs:56-60` struct has a single `base` field, no fallback collection;
  `mempool.rs:48` `DEFAULT_MEMPOOL_URL = "https://mempool.space/testnet4"`;
  `mempool.rs:44` env override `JSS_PAY_MEMPOOL_URL`.
- `mempool.rs` error paths return `PaymentError::InvalidState` on non-success
  rather than retrying another URL, verified at `e093e88`.
