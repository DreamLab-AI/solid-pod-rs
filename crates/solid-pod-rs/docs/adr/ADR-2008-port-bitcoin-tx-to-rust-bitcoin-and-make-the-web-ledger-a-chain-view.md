---
id: ADR-2008
title: Port bitcoin_tx.rs and mrc20.rs to rust-bitcoin, make WebLedger a derived view over the sidestr chain, remove credit/debit from the public API and delete the TXO stand-in deposit
date: 2026-09-21
decision_status: proposed
implementation_status: none
activation_status: inactive
supersedes: []
superseded_by: []
verified_commit: 51426be8232a6ddf2d8134848b756de938ef70dd
owner: jjohare
review_trigger: the golden fixtures passing byte-identical under rust-bitcoin; the first sidestr-node read-through balance served by this crate; any proposal to reintroduce a ledger write path that is not a peg-in claim
repo: solid-pod-rs
domain: BASELINE-solid-pod-rs.md
lineage: "Implements agentbox ADR-2096 D3 (rust-bitcoin accepted estate-wide) and ADR-2099 D2/D3 (every ledger becomes a derived view; the only credit is a peg-in claim) for this crate. Extends ADR-2007's single-explorer settlement seam with a second, authoritative backend: the estate's own chain."
---

# ADR-2008 — Port bitcoin_tx.rs and mrc20.rs to rust-bitcoin, make WebLedger a derived view over the sidestr chain, remove credit/debit from the public API and delete the TXO stand-in deposit

## Context

This crate owns 100% of the estate's Bitcoin transaction construction and hand-rolls it.
`src/bitcoin_tx.rs` (1442 lines) builds BIP-341 P2TR scripts, the TapSighash and key-path
Schnorr signing on raw `k256`, with big-endian mod-n scalar arithmetic written out by hand
(`add_mod_n` `src/bitcoin_tx.rs:146-158`, `neg_mod_n` `:162-164`); its module doc states the
posture outright, "No `rust-bitcoin` / `secp256k1-sys` is introduced" (`src/bitcoin_tx.rs:24`).
`src/mrc20.rs` (1181 lines) carries the chained-key derivation (`bt_derive_chained_pubkey`
`:350`). The house crypto rule forbids hand-rolled primitives and sighashes. Separately,
`WebLedger` (`src/payments.rs:104`) is a stored number mutated by `credit` (`:144`) and `debit`
(`:158`), and the server's TXO deposit path invents value from the vout index, calling itself a
"Phase 0: deterministic stand-in" (`crates/solid-pod-rs-server/src/handlers/pay.rs:498-519`).
The owner decided on 2026-09-21 that DreamLab's own sidestr chains are the sole value
instrument and that the chain is the ledger of record (PRD-024 D0, D3, D4).

## Decision

1. **`bitcoin_tx.rs` and `mrc20.rs` port to `rust-bitcoin` plus `secp256k1`.** The k256-only,
   zero-rust-bitcoin-dependency posture asserted at `src/bitcoin_tx.rs:24` is retired here and
   estate-wide (agentbox ADR-2096 D3). Script construction, VarInt encoding, tagged hashes, the
   BIP-341 sighash and BIP-340 signing come from the libraries; `add_mod_n`, `neg_mod_n` and
   `sub` are deleted rather than kept beside them. This is the highest-priority item in the
   programme because it is the only one that removes hand-rolled crypto.
2. **The three cross-implementation golden tests are the acceptance gate.**
   `golden_case_a_full_hex_matches_jss` (`src/bitcoin_tx.rs:1113`),
   `golden_case_b_tweaked_full_hex_matches_jss` (`:1143`) and
   `golden_case_c_multi_input_matches_jss` (`:1172`), over
   `tests/fixtures/bitcoin/golden_tx.json`, must pass byte-identical before and after the port.
   The fixtures are not regenerated to fit the new code. Deterministic signing with
   `aux_rand = 0^32` is preserved, so JSS parity survives the change of library.
3. **MRC20 is retained as an anchoring primitive and retires as a token rail.**
   `bt_derive_chained_pubkey` and the chained taproot derivation port alongside and keep
   working, because block-trail anchors and the host's `AnchorConfirmer` depend on them (host
   ADR-2111). MRC20-as-token is superseded by wrapped assets on the chain (agentbox ADR-2102);
   the `.buy` / `.withdraw` MRC20 token routes retire with the ledger write API.
4. **`WebLedger` becomes a derived, height-stamped view.** `get_balance(did)`
   (`src/payments.rs:136`) reads through the `sidestr-node` HTTP surface and folds the UTXOs
   keyed by that `did:nostr`, with a bounded cache. A staleness bound is an error, never a
   slightly old number. No caller may spend, charge or gate on the view without resolving to
   the chain.
5. **`credit` and `debit` leave the public API.** `WebLedger::credit`
   (`src/payments.rs:144-156`) and `WebLedger::debit` (`:158-178`) are removed. The only credit
   is a peg-in claim on the chain; the only debit is a chain spend. `PaymentStore`
   (`src/payments.rs:438-444`) keeps `check_replay` / `record_replay` and loses
   `write_ledger` as an authority: writes become cache population. This is the one deliberately
   breaking change in the estate, and it is deliberate because leaving the pair in place leaves
   a path by which a balance can exist that the chain does not know about.
6. **The TXO stand-in deposit is deleted, not left default-off.**
   `crates/solid-pod-rs-server/src/handlers/pay.rs:498-519` credits
   `((vout as u64) + 1) * 1000` sats for any parseable TXO URI, guarded only by a replay key.
   A chain-settled estate must not keep a reachable free-money oracle. `handle_mrc20_deposit`
   loses its ledger-crediting half and keeps only anchor verification.
7. **Non-atomic payment state is fixed first.** The README's own reproduced critical finding
   (`README.md:238-247`, "do not carry value through payment routes until the findings are
   fixed") is a precondition of P2, not a follow-up. The chain must not ride on a store this
   crate's maintainers say not to carry value through.
8. **Both consumers move together.** The host repo (currently pinned `0.4.0-alpha.15`,
   `/home/devuser/workspace/project/Cargo.toml:218`) and the forum (`=0.5.0-alpha.7`,
   `/home/devuser/workspace/nostr-rust-forum/Cargo.toml:155`) adopt one post-port version in
   lockstep; closing that skew is a P1 exit criterion (agentbox ADR-2099 D4).

## Consequences

The crate gains `rust-bitcoin` and `secp256k1` and loses roughly 400 lines of
consensus-critical hand-rolled arithmetic, which is the point. Binary size and the wasm32
boundary both move, and the wasm story for transaction building must be re-measured rather
than assumed. Removing `credit` / `debit` breaks every downstream caller by design and is a
semver-major event for this crate. `docs/explanation/payments-and-web-ledger.md` needs
rewriting: its "the core operations are `get_balance`, `credit`, `debit`" paragraph and its
"the money model is fixed by PRD-015 v1.2: Lightning/L402/NWC" sentence are both superseded
(agentbox ADR-2097). The pod economy's per-read micro-debits become chain-settled or batched,
which is a latency and fee change that the acceptance test must measure rather than assert.
The order book and constant-product AMM stay as the exchange surface; sidestr's `pool` rule is
not adopted (agentbox ADR-2096 D5).

## Verification

Proposed; nothing built. Ratification evidence will be:

- The three golden tests green with output byte-identical to the pre-port run, over an
  unmodified `tests/fixtures/bitcoin/golden_tx.json`, at the porting commit.
- `grep -n "fn add_mod_n\|fn neg_mod_n" src/bitcoin_tx.rs` empty, and `cargo tree` showing
  `rust-bitcoin` and `secp256k1` present.
- `grep -n "pub fn credit\|pub fn debit" src/payments.rs` empty.
- `grep -n "Phase 0: deterministic stand-in" crates/solid-pod-rs-server/src/handlers/pay.rs`
  empty, with the route returning a refusal rather than a credit.
- `balance(did)` from this crate identical to `sidestr-node` directly for 100 random DIDs,
  and an explicit error rather than a stale figure when the node is unreachable.
- The security audit's non-atomic payment state finding closed, with the README claim updated
  in the same change.
