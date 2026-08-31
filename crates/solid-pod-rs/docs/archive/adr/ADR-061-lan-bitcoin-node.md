# ADR-061: LAN Bitcoin node (192.168.2.27) as the anchoring + Lightning substrate

**Status**: Accepted (design); cutover **blocked on the acceptance checklist below** — the node was unreachable from the mesh at design time (2026-08-25: no ping, no open service ports from either agentbox or its host)
**Date**: 2026-08-25
**Supersedes**: the public-explorer-only posture implicit in ADR-059
**Related**: ADR-059 (block-trails/git-marks — the anchoring consumer), agentbox PRD-015 v1.2 (Lightning-first economy, C10 "resident node"), dreamlab-cumbria `infrastructure/compute` (old VM 107 `bitcoin (chain-only)` destroyed; pathway box's Core-Lightning `hsm_secret` preserved on machinelearn)

## Context

Three ecosystem threads need a Bitcoin node and today settle for less:

1. **Block-trail anchoring (this crate).** `MempoolBlockAnchorer` / `MempoolHttpClient`
   does UTXO/scriptPubKey lookup and tx broadcast against a mempool.space-style
   REST API — `JSS_PAY_MEMPOOL_URL`, default **public** `https://mempool.space/testnet4`.
   Every taproot anchor and MRC20 `/pay/.deposit`/`.buy`/`.withdraw*`/`_prov/anchor`
   round-trips a third-party explorer: an availability, privacy and
   rate-limit dependency under settlement-grade provenance.
2. **Lightning rail (agentbox PRD-015 Phase 3, C10).** The NWC real-money rail
   requires a *resident node*. The estate already holds the retired pathway
   box's Core-Lightning `hsm_secret` (backed up to machinelearn when VM 107 and
   the pathway box were decommissioned) — the node identity survives; it needs
   a host.
3. **Infrastructure succession.** VM 107 `bitcoin (chain-only)` was destroyed in
   the compute consolidation. The new node at **192.168.2.27** (trusted server
   segment) is its successor.

## Decision

192.168.2.27 is the mesh's Bitcoin substrate, expected to expose:

| Service | API | Consumer | Suggested port |
|---|---|---|---|
| bitcoind (**dual-network: mainnet + testnet4**, see below) | JSON-RPC (LAN-only) | electrs/mempool stack only — pod code never speaks RPC | 8332 (mainnet) / 48332 (testnet4) |
| **electrs/esplora or mempool.space self-host** | mempool.space-style REST (**the contract this crate needs**: `GET /api/address/:addr/utxo`, `GET /api/tx/:txid`, `POST /api/tx`, `GET /api/blocks/tip/height`) | `MempoolHttpClient` via `JSS_PAY_MEMPOOL_URL` | 3000 (electrs-mainnet) / 3001 (electrs-testnet4), or 8999/9000→`/api` (mempool) |
| Core-Lightning (restored `hsm_secret`) + NWC bridge | NIP-47 over the mesh relay | PRD-015 C10 spender/receiver | n/a (relay-mediated) |

### Dual-network posture (2026-08-25 amendment)

The node runs **both networks simultaneously**: mainnet for real-money
Lightning (PRD-015 C10) and cheap on-chain tests; testnet4 for development
and integration testing. Each network gets its own bitcoind instance, its
own electrs, and its own REST port. Consumers select by URL:

```
# Mainnet (real money — Lightning + cheap anchoring tests)
JSS_PAY_MEMPOOL_URL=http://192.168.2.27:3000

# Testnet4 (development + CI)
JSS_PAY_MEMPOOL_URL=http://192.168.2.27:3001

# Core-Lightning connects to the mainnet bitcoind for the NWC rail
```

The public `mempool.space/testnet4` default **stays the shipped default**: a pod
without LAN access must keep working. The LAN URL is deployment configuration
(agentbox `.env` / compose), not a new crate default. The `JSS_PAY_NETWORK`
env var is not needed — the URL itself selects the network.

## Non-goals / rejected

- **Ordered multi-URL fallback in `MempoolHttpClient`** (LAN → public): rejected
  for now. Silent failover to a public explorer would hide a broken LAN node
  behind working anchors and reintroduce the third-party dependency invisibly.
  Fail loudly on the configured URL; revisit only with explicit telemetry.
- **Speaking bitcoind RPC directly from pod code**: rejected — the REST seam is
  already trait-shaped (`MempoolLookup`/`MempoolBroadcast`), test-fixtured, and
  explorer-agnostic. Keep the node's RPC LAN-firewalled to its own stack.

## Acceptance checklist (gates the cutover — run when .27 is reachable)

1. **Both networks synced:**
   - `curl http://192.168.2.27:3000/api/blocks/tip/height` returns the current
     mainnet tip (within 1 block of a public explorer).
   - `curl http://192.168.2.27:3001/api/blocks/tip/height` returns the current
     testnet4 tip.
2. The four contract endpoints above respond with mempool.space-compatible
   schemas on both ports (the crate's fixture tests document the exact shapes).
3. A full anchor round-trip on **testnet4** against the LAN URL:
   `_prov/anchor` → txid → confirmed lookup, with `JSS_PAY_MEMPOOL_URL=http://192.168.2.27:3001`
   in a staging pod. Then a cheap mainnet test (balance lookup only, no spend)
   against `:3000`.
4. Firewall: REST port reachable from the agentbox/pod segment; bitcoind RPC
   and P2P **not** reachable from it.
5. Update: agentbox `.env` (+ compose env passthrough), this ADR's Status →
   "cut over", `env-vars.md` LAN note, and a `192.168.2.27` row in
   dreamlab-cumbria `infrastructure/compute/README.md`.
6. (Phase 3, separate) Core-Lightning restored from the preserved `hsm_secret`
   with NWC reachable via the mesh relay — tracked by PRD-015 C10, not this ADR.

## Consequences

- Anchoring becomes sovereign: no third-party explorer in the settlement path,
  matching the mesh's keep-content-on-LAN posture (same shape as the Loom
  decision for LLM traffic).
- The unreachability found at design time is recorded honestly: nothing in this
  ADR pretends the node was verified. The checklist is the boundary between
  "designed" and "deployed".
