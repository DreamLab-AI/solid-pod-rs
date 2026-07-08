# ADR-059: Block-trails and git-marks as first-class provenance primitives

**Status**: Accepted — the Phase-5 composition and `_prov` API shipped in `182ed31` (see Status detail, corrected 2026-07-08); two residuals remain (default-off `git` feature, no pod-wide `_prov` enumeration index)
**Date**: 2026-06-13
**Supersedes**: none
**Related**: ADR-058 (JSS drift analysis), the master plan in
[`docs/design/provenance-upgrade-master-plan.md`](../design/provenance-upgrade-master-plan.md),
agentbox PRD-015 v1.2 (Lightning-first economy) and ADR-032 (402 scheme grammar)

## Status detail (open items, 2026-07-03)

**Shipped in code** (the *verify* half): `mrc20.rs` carries RFC-8785 JCS,
SHA-256 state-chain linking, BIP-341 taproot key-chaining
(`bt_derive_chained_pubkey` / `bt_derive_chained_privkey`) and anchor
verification (`verify_mrc20_anchor`), feature-gated behind
`bip341-taproot` / `mrc20`. The `solid-pod-rs-git` smart-HTTP backend and
the server's `git_mark_write` write hook (`--features git`) also exist.

**Shipped since (corrected 2026-07-08, ADR-060 Decision 3).** The *produce*
half and the composition landed in commit `182ed31` ("feat(provenance):
ProvenanceLog composition + epoch anchoring + _prov API (ADR-059 Phase 5)",
2026-06-13; `crates/solid-pod-rs/src/provenance.rs` +770,
`crates/solid-pod-rs-server/src/handlers/prov.rs` +532), so the items below
are no longer "not built":

- **D3** `bitcoin_tx.rs` + `mempool.rs` write side — `MempoolBlockAnchorer`
  (`solid-pod-rs-server/src/mempool.rs`) produces and broadcasts the taproot
  anchor tx; `bitcoin_tx.rs` builds it byte-parity.
- **D5** epoch Merkle anchoring — `EpochAccumulator` batches marks under an
  `AnchorPolicy::Epoch` Merkle root (`handlers/prov.rs::epoch_push_and_maybe_anchor`).
- **D7** the PROV-O `.prov.ttl` sidecar and the `_prov` routes —
  `GET /{pod}/_prov/{commit_sha}` and `POST /{pod}/_prov/anchor`
  (`handlers/prov.rs`).
- The Phase-5 **`ProvenanceLog::record`** composition (git-mark always, anchor
  per policy) is the single canonical write path
  (`solid-pod-rs-server/src/lib.rs::git_mark_write` → `ProvenanceLog::record`).
- **D6 (part)** the NIP-98 **replay-protection wiring** is live
  (`NIP98_REPLAY`, `auth::replay`); WAC sidecar-enforcement and the
  `did:nostr` backlink policy were unified in `cded64f`.

**Still open.** D2 the fully generalised `ProvenanceTrail` beyond token
balances, and the WAC-gating of the raw git smart-HTTP push route (distinct
from the LDP write path, which is WAC-gated). Two residuals bound every
git-mark claim: (1) the `git` feature is **off in the default build** (see the
capability caveat below) — a default build records zero marks; and (2) there is
**no pod-wide `_prov` enumeration index** — the `_prov` API is point-lookup by
a known commit SHA plus per-resource sidecars, so "one queryable trace" over a
whole pod is not yet delivered (the REC-11 gap; contract in
[`docs/reference/provenance-trace-contract.md`](../reference/provenance-trace-contract.md)).

**Capability caveat — git-marks are off by default.** D1 below describes
the git-mark tier as "always-on", but the server's `git` feature is **off
in the default build** (the server's default feature set is empty). In a
default build `git_mark_write` is a no-op empty shim
(`#[cfg(not(feature = "git"))]`), so **default builds record zero
provenance marks**. Git-mark provenance requires building the server with
`--features git`; only then is every LDP `PUT`/`POST`/`PATCH` committed.
Read "always-on" as "on every write *when compiled with `git`*", not "on
by default".

## Context

solid-pod-rs already carries the *verify* half of the Blocktrails MRC20
mechanism (`mrc20.rs`: RFC-8785 JCS, SHA-256 state-chain linking, BIP-341
taproot key-chaining for pubkey **and** privkey, bech32m P2TR derivation, anchor
verification — 47 passing tests) and a complete git smart-HTTP backend
(`solid-pod-rs-git`: CGI, path-traversal guard, `receive.denyCurrentBranch
updateInstead`, NIP-98/Basic auth). Both, however, are bolted on rather than
woven in:

- The MRC20 code can *check* a Bitcoin-anchored state chain but cannot *produce*
  one (no tx-building, no mempool client), and it is shaped exclusively around
  **token balances** — there is no general trail that carries arbitrary payloads.
- Git is reachable only as an explicit clone/push transport. An ordinary LDP
  write (`PUT`/`POST`/`PATCH`) is a plain `storage.put()` with **no commit** —
  so there is no per-write history — and, separately, `handle_git` never calls
  the WAC enforcers, leaving an **anonymous-push hole**.

Two forces make this the moment to fix it properly:

1. **Operator steer (2026-06-13):** *"Block trails might be absolutely crucial
   to our provenance system for agents within agentbox."* Agent actions,
   receipts, credentials and governance (ACSP) decisions need a tamper-evident,
   independently-verifiable trail. The Blocktrails mechanism is exactly that —
   but only if generalised beyond tokens.

2. **JSS payment maturity.** Inheriting JSS's mature 402 economy (already
   surveyed) brings the Bitcoin write-side (tx-building, broadcast, deposit
   verification) we need anyway — the same crypto that an anchor requires.

The money model is fixed by PRD-015 v1.2: Lightning/L402/NWC + Bitcoin sats, **no
EVM**. JSS is Bitcoin-native, so it aligns.

## Decision

Introduce **two composable, cost-tiered provenance primitives** in this crate,
at the lowest level, so every downstream consumer (agentbox, forum, website,
VisionClaw) inherits verifiable traceability without re-implementing crypto.

### D1 — Two tiers, composed

- **git-mark** (cheap, on every write *when the server is built with
  `--features git`* — see the capability caveat above; **not** enabled in
  the default build): every pod write becomes a git commit. The commit SHA
  is captured and surfaced as a `GitMark` — content-addressed,
  append-only, tamper-evident ordering for free.
- **block-trail anchor** (expensive, opt-in): a Bitcoin-anchored MRC20 state
  whose taproot UTXO externally and irreversibly timestamps a record. Reserved
  for high-value records (settlement receipts, elevation/ACSP decisions, epoch
  snapshots).

A `ProvenanceMark` always carries a `GitMark` and *optionally* a
`BlockTrailAnchor`. The anchor's `state_hash` commits to the git SHA (or an
epoch Merkle root over many commits), binding the two tiers into one chain.

### D2 — Generalise the trail beyond tokens

The Blocktrails state-chain is lifted from a token-only structure to a general
`ProvenanceTrail` whose states carry arbitrary JCS-canonicalised payloads. The
MRC20 token becomes **one instance** of a provenance trail. This is what makes
block-trails usable as the agentbox agent-provenance backbone, not just a
payment feature.

### D3 — Reuse the verified crypto; add only the missing edges

No crypto is re-implemented. We add exactly:

- `bitcoin_tx.rs` (feature `mrc20`): P2TR output construction, BIP-341
  Schnorr/TapSighash signing, witness assembly — validated against official
  BIP-341 test vectors before any broadcast.
- `mempool.rs` (non-wasm): UTXO lookup + tx broadcast.

The chained-key derivation, JCS, state-link verification and bech32m already in
`mrc20.rs` are used verbatim.

### D4 — Traits are wasm32-safe; native I/O is feature-gated

`GitMarker` and `BlockAnchorer` are `?Send` traits. The wasm `core` consumer
(e.g. the forum pod-worker) compiles with a **no-op `GitMarker`** and
`anchorer: None`. All Bitcoin/mempool/process-spawning code is
`#[cfg(not(target_arch = "wasm32"))]` and behind feature `mrc20`. A wasm build
job guards against leakage.

### D5 — One Bitcoin tx notarises many commits

Per-write on-chain anchoring is rejected on cost grounds. Instead, an epoch
Merkle root over a batch of git commits is anchored in a single MRC20 state, so
the cost of external immutability is amortised. Epoch boundaries and the set of
record classes that warrant anchoring are operator policy (see Consequences).

### D6 — Close the debt the primitives expose

Landing the primitives requires fixing adjacent rot, so it is in scope:

- **WAC-gate all git routes** — `handle_git` calls `enforce_read`/`enforce_write`;
  the anonymous-push hole is closed.
- **Wire replay protection** — `check_replay`/`record_replay` (defined but never
  called) are invoked on the deposit path.
- **`PaymentStore` becomes the sole ledger I/O path** — replacing the inline
  `Storage::get/put` the runtime currently uses, so the already-built+tested
  trading/AMM logic can be routed.

### D7 — Persistence and surface

A `ProvenanceMark` is persisted as a PROV-O sidecar at `<resource>.prov.ttl` and
emitted on the existing `Updates-via` notification stream. New routes:
`GET /{pod}/{path}.prov.ttl`, `GET /{pod}/_prov/{commit_sha}`,
`POST /{pod}/_prov/anchor` (NIP-98, payment-gated).

## Considered options

- **(chosen) Two tiered primitives, git-always + Bitcoin-optional, generalised
  trail.** Cheap traceability on every write; trustless external proof only when
  a record warrants it; one mechanism serves payments *and* agent provenance.
- **Rejected: Bitcoin anchor on every write.** Correct but unaffordable — a
  mempool round-trip and sats per pod write. D5's epoch anchoring gets the same
  immutability at amortised cost.
- **Rejected: git-marks only (no Bitcoin tier).** Git history is tamper-evident
  but not externally trustless — a pod operator can rewrite local history.
  High-value records (settlement, governance decisions) need an anchor no single
  party can forge.
- **Rejected: keep MRC20 token-shaped and bolt provenance on per consumer.**
  Guarantees crypto drift across agentbox/forum/VisionClaw and re-litigates JCS
  determinism in every repo. The primitive belongs at the lowest level.
- **Rejected: EVM/L2 anchoring.** Excluded by PRD-015 v1.2; Bitcoin-only.

## Consequences

**Positive.** Every pod write is traceable to a commit; high-value records are
externally verifiable against Bitcoin; agent actions, receipts, credentials and
ACSP decisions gain a uniform provenance trail; downstream consumers inherit it
on a version bump without touching crypto; the JSS payment maturity (markets,
multi-currency, deposit verification) arrives with the same Bitcoin write-side
the anchor needs; three latent defects (anonymous git push, unwired replay,
orphaned ledger I/O) are closed.

**Negative.** BIP-341 signing is the highest-risk new code (mitigated by test
vectors + regtest, never live mainnet in CI). A coordinated four-repo pin bump
(`0.4.0-alpha.17` → `0.5.0-alpha.0`) is required to deliver the downstream
augmentation. Operator policy is now load-bearing: min-confirmation threshold,
which record classes anchor, mainnet vs testnet4, and whether per-user deposit
addresses (DID→on-chain linkage) are publicly exposed.

**Neutral.** The 402 scheme grammar (agentbox ADR-032) is unchanged — only the
*settlement backend* moves from trusted-write to Bitcoin-confirmed, so its
fixture corpus stays frozen. wasm consumers are unaffected (no-op marker).

## Status → Accepted criteria

Accepted when the master plan's Phase 5 lands: `ProvenanceLog::record`
composition enforced, epoch anchoring working, `0.5.0-alpha.0` tagged with the
provenance primitives green in both native and wasm builds.
