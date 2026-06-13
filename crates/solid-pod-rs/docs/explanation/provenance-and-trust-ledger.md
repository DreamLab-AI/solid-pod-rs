# Provenance and the trust ledger

Understanding-oriented. *Why* does a Solid pod library carry a Bitcoin
anchor and a git committer? What are the two provenance tiers, how do
they compose, and what does "independently verifiable" actually buy you?

This page explains the model. For the decision record see
[ADR-059](../adr/ADR-059-provenance-primitives-block-trails-git-marks.md);
for the full inheritance matrix and phased delivery see the
[provenance upgrade master plan](../design/provenance-upgrade-master-plan.md);
for the data-flow picture see
[diagram 09 — provenance tiers](../diagrams/src/09-provenance-tiers.mmd).

## The thesis

A pod is already the place your data lives. ADR-059 makes it also the
place your data's **history** lives — verifiably. Every write to a
git-backed pod becomes a commit; high-value records can additionally be
notarised on Bitcoin. Compose those two and you get a sovereign,
Bitcoin-settled **global trust ledger**: a substrate on which any agent's
actions, receipts, credentials, or governance decisions carry a
tamper-evident, externally-checkable trail — without any consumer
re-implementing a line of crypto.

This is deliberately **not** a crypto project. There is no token sale, no
EVM, no smart-contract VM, no L2. Settlement is Bitcoin sats over
Lightning/L402/NWC (PRD-015 v1.2); the on-chain footprint is a single
taproot UTXO whose only job is to timestamp a hash. The interesting
object is the *verifiable-provenance graph*, not a coin.

## Two tiers, by cost

The primitives live in [`provenance`](https://docs.rs/solid-pod-rs/latest/solid_pod_rs/provenance/index.html)
(pure logic, `wasm32`-safe). They are deliberately cost-asymmetric:

| Tier | Type | Cost | Cadence | Trust property |
|---|---|---|---|---|
| **git-mark** | `GitMark` | free | every write | tamper-evident *ordering* + content-addressing (Merkle DAG) — but local, so a pod operator could rewrite their own history |
| **block-trail anchor** | `BlockTrailAnchor` | sats + a mempool round-trip | opt-in (high-value / epoch) | external, irreversible timestamp no single party can forge |

You always get the cheap one. You pay for the expensive one only where a
record genuinely warrants it.

### Tier 1 — git-marks (write-as-commit)

The cheap tier exploits a fact the pod already had: a git-backed pod runs
`receive.denyCurrentBranch = updateInstead`, so the working tree *is* the
served content. ADR-059's move is to make an ordinary LDP
`PUT`/`POST`/`PATCH` *also* produce a commit, and to **capture and
surface** the resulting SHA.

- The trait is `provenance::GitMarker` (`?Send`, wasm-safe). The native
  implementor is `solid-pod-rs-git`'s **`ShellGitMarker`**, which shells
  to `git`: it records the pre-write `HEAD` (the commit's parent — the
  append-only chain link), `git add`s the written file, and commits it
  with `git -c user.name=… -c user.email=<agent_did>` so the writer's
  `did:nostr` (the NIP-98 principal) becomes the commit author. No global
  git config is touched; an idempotent re-write of identical bytes is a
  no-op that returns the current `HEAD` rather than erroring.
- The captured `GitMark { commit_sha, repo, branch, parent }` is
  persisted as a **PROV-O sidecar** at `<resource>.prov.ttl` (W3C PROV
  Turtle: the write is a `prov:Activity` that `prov:generated` the
  resource entity, `prov:wasAssociatedWith` the agent, identified by its
  `git:commit`). The sidecar write fires the existing `Updates-via`
  notification stream, so subscribers see new marks.
- It is **always-on and cheap**: no sats, no network, no feature flag on
  the read path. On `wasm32` (e.g. a Cloudflare-Workers pod) there is no
  subprocess, so the consumer compiles against a **no-op marker** and the
  tier degrades silently.

Git history is tamper-evident — you cannot alter a commit without
changing every descendant SHA — but it is not *trustless*: the operator
holds the repo and could rewrite local history. That is exactly the gap
the second tier closes.

### Tier 2 — block-trails (Bitcoin-anchored state)

The expensive tier is the generalised **Blocktrails MRC20** mechanism. A
block-trail is a JCS-canonicalised (RFC 8785), SHA-256 hash-chained
sequence of states whose head is committed to a **Bitcoin taproot UTXO**.
The crypto is the verified `mrc20` module — BIP-341 taproot key chaining
for both the public and private key, bech32m P2TR address derivation,
state-link + sequence verification — and the write-side (`bitcoin_tx`,
feature `mrc20`, non-wasm): P2TR output construction, BIP-341 TapSighash,
BIP-340 Schnorr signing, witness assembly. That tx-builder is a
**byte-for-byte** port of the JSS `token.js` taproot builder, validated
against the official BIP-340/341 test vectors and a JSS cross-impl golden
fixture so a state hash chains identically across the Rust and JS
implementations.

ADR-059's **generalisation** (D2) is the load-bearing change: the trail
is lifted from a token-only structure to one carrying *arbitrary*
JCS-canonicalised payloads. **The MRC20 token is now just one instance of
a provenance trail.** That is what makes block-trails usable as an
agent-provenance backbone (the agentbox use case) and not merely a
payment feature.

The trait is `provenance::BlockAnchorer` (`?Send`). The
read+write implementor is the server's `MempoolBlockAnchorer`, talking to
the public mempool.space testnet4 API (`JSS_PAY_MEMPOOL_URL`,
default `https://mempool.space/testnet4`) via `MempoolHttpClient` — which
implements both UTXO/scriptPubKey lookup (`mrc20::MempoolLookup`) and tx
broadcast (`bitcoin_tx::MempoolBroadcast`). On wasm the anchorer is simply
`None`.

## Composition — `ProvenanceLog` and `AnchorPolicy`

The two tiers compose in one place: `provenance::ProvenanceLog`, which
holds the always-present `marker: Arc<dyn GitMarker>` and an *optional*
`anchorer: Option<Arc<dyn BlockAnchorer>>`. `ProvenanceLog::record(write)`
implements the **cheap-always, expensive-opt-in** rule:

1. **Always** `marker.mark_write()` → a `GitMark`. A failure here is a
   hard error: the git-mark is the contract.
2. **Conditionally** `anchorer.anchor()` — only when the `AnchorPolicy`
   says this write anchors *and* an anchorer is wired. With
   `anchorer: None` (a wasm pod, or a pod that doesn't pay for Bitcoin)
   every policy degrades to git-mark-only, silently.

The binding insight: **the anchored `state_hash` is the git commit SHA**.
So the Bitcoin UTXO commits to the git history — the two primitives fuse
into a single chain. A reader who trusts the Bitcoin chain (and nobody
else) can verify that a given git commit existed at a given block height.

`AnchorPolicy` governs the expensive tier:

| Variant | Behaviour |
|---|---|
| `Never` | git-mark only — no on-chain cost. The default for ordinary writes. |
| `Always` | anchor every write (its git SHA on-chain each time). Expensive; only for trails where every state must be externally timestamped. |
| `HighValue` | anchor iff the resource is flagged anchor-worthy. Settlement receipts, elevation / ACSP decisions. |
| `Epoch` | accumulate the SHA into an `EpochAccumulator`; anchor the batch **Merkle root** once on epoch close. |

### Epoch batching — one tx notarises many commits

Per-write anchoring is rejected on cost grounds (ADR-059 D5): a mempool
round-trip and sats *per pod write* is unaffordable. The `Epoch` policy
instead accumulates commit SHAs (a per-pod batch persisted by the server),
and when the batch reaches its threshold (`JSS_PROV_EPOCH_SIZE`, default
16) computes a single SHA-256 **Merkle root** over the batch and anchors
*that* in one Bitcoin tx. Any individual commit is later proven against
the anchored root with a Merkle inclusion proof
(`EpochAccumulator::inclusion_proof` / `verify_inclusion`) — no
re-anchoring. The result is retroactive external immutability at
amortised on-chain cost: one tx, N notarised commits.

This is why "ACL writes are epoch-only" is the recommended operator
policy — frequent, low-individual-value writes get the cheap batched
guarantee; rare high-value records get an inline anchor of their own.

## Flagging anchor-worthy resources — the `ProvenanceAnchor` WAC condition

Which resources warrant the expensive tier is expressed in WAC, not in
code. `acl:ProvenanceAnchor` is a WAC 2.0 condition
(`wac::ProvenanceAnchorBody`) that — crucially — **does not gate access**.
It is a *marker*: its evaluator always returns `Satisfied`, so it can
never block a write; it only changes how the write is *recorded*. It is a
recognised condition, so it never trips the unknown-condition fail-closed
422 path that an unrecognised `@type` would.

Its one hint is `acl:anchorMode`:

- `"epoch"` (default) → `AnchorPolicy::Epoch` (batched, bounded cost);
- `"always"` / `"inline"` / `"highValue"` → `AnchorPolicy::HighValue`
  (anchored inline);

plus an optional `acl:anchorTicker` to target a specific trail. The
server's write hook reads the resource's effective ACL, maps any
`ProvenanceAnchor` it finds onto an `AnchorPolicy` (`anchor_mode_of` →
`resolve_anchor_policy`), and escalates that write from the default
`Never`. Authorisation is still decided entirely by the classic ACL triad
and any `acl:PaymentCondition` — provenance and access are orthogonal.

## The `_prov` API and independent verification

Provenance is only useful if a third party can check it **without trusting
the pod**. The server surfaces three routes (ADR-059 D7):

- `GET /{pod}/{path}.prov.ttl` — the PROV-O sidecar for a resource
  (served by the ordinary LDP read path).
- `GET /{pod}/_prov/{commit_sha}` — resolve a git-mark commit SHA back to
  the resource it wrote and its `ProvenanceMark` (inlining the sidecar, so
  any block-trail anchor comes with it). Public, the same audience as the
  sidecar.
- `POST /{pod}/_prov/anchor` — NIP-98-authenticated (the pod owner),
  payment-gated *explicit upgrade* of an existing git-mark to a Bitcoin
  anchor. Debits the caller's Web Ledger by the configured anchor price
  (`JSS_PROV_ANCHOR_PRICE_SATS`, else the pay-token rate), anchors the
  commit SHA on the pod's trail, and rewrites the resource's `.prov.ttl`
  to carry the anchor. If the on-chain anchor fails after the debit, the
  charge is refunded.

The trustless part is the `BlockTrailAnchor` itself. It carries the
**portable proof** — the issuer `pubkey` and the `state_strings` — needed
to re-derive the taproot `address` from first principles
(`mrc20::bt_address`) and then confirm a live UTXO sits at it via any
mempool endpoint. A verifier never asks the pod whether an anchor is real;
they re-derive the P2TR address from the proof and check the chain
directly (`BlockAnchorer::verify`). The pod is reduced to a *cache* of a
fact anyone can independently reconstruct. That is the whole point of a
trust ledger: the ledger, not the operator, is authoritative.

## What this is, and isn't

**Is:** a verifiable-provenance substrate. Every pod write traceable to a
commit; high-value records externally verifiable against Bitcoin; a
uniform trail for agent actions, receipts, credentials, and governance
decisions; downstream consumers inheriting all of it on a version bump,
touching no crypto. Settlement is Bitcoin sats; the global, neutral,
unforgeable clock is the Bitcoin chain.

**Isn't:** a coin, an exchange-listed token, an EVM, or an L2. The
`mrc20` token rides the *same* trail mechanism, but the mechanism's reason
to exist is provenance, not speculation. EVM/L2 anchoring was explicitly
rejected (ADR-059, PRD-015 v1.2): Bitcoin-only, because the value on offer
is an irreversible timestamp from the most neutral settlement layer
available, not programmable money.

## See also

- [Payments and the web ledger](payments-and-web-ledger.md) — the routed
  402 economy whose Bitcoin write-side this provenance tier shares.
- [Security model](security-model.md) — WAC-gated git, replay protection,
  the auth layering the `_prov` routes sit behind.
- [ADR-059](../adr/ADR-059-provenance-primitives-block-trails-git-marks.md)
  — the decision record.
- [Provenance upgrade master plan](../design/provenance-upgrade-master-plan.md)
  — the JSS inheritance matrix and phased delivery.
- [diagram 09 — provenance tiers](../diagrams/src/09-provenance-tiers.mmd).
