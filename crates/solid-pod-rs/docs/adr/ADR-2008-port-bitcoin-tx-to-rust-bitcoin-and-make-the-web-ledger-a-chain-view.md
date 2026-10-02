---
id: ADR-2008
title: Port bitcoin_tx.rs and mrc20.rs to rust-bitcoin, make WebLedger a derived view over the sidestr chain, remove credit/debit from the public API and delete the TXO stand-in deposit
date: 2026-09-21
decision_status: proposed
implementation_status: partial
activation_status: staged
supersedes: []
superseded_by: []
verified_commit: e62d028
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

D1, D2 and D6 are built and verified at `e62d028` (see *Implementation — 2026-10-02*);
D3 holds in part, and D4, D5, D7 and D8 are not built. Ratification evidence will be:

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

## Disposition — 2026-10-02

- **Suitability:** fits, needs revision
- **Priority:** P2 — next cycle (planning-cycle §3 names "solid-pod-rs `bitcoin_tx.rs` is on rust-bitcoin" as a sovereign-settlement reopening condition, so D1–D2 are its first item; D4–D6 park with agentbox ADR-2099)
- **Why:** D1 is the estate's outstanding hand-rolled-crypto port, and the house rule ranks that highest. It has not started at `6d2e5b0`: `src/bitcoin_tx.rs:24` still declares "No `rust-bitcoin` / `secp256k1-sys`", `add_mod_n`/`neg_mod_n` remain (`:146`, `:162`), and `Cargo.toml` carries only `k256`. D5 and D6 also stand: `src/payments.rs:144,158` keep `credit`/`debit` public, and the TXO stand-in remains at `crates/solid-pod-rs-server/src/handlers/pay.rs:498`. Two parts are overtaken. D8's pins are stale: this workspace is now `0.5.0-alpha.10`, the forum pins `=0.5.0-alpha.10`, and the host `0.4.0-alpha.15`. The Consequences' "the order book and constant-product AMM stay as the exchange surface; sidestr's `pool` rule is not adopted" is narrowed by agentbox ADR-2096's amendment, which parks the pod AMM in favour of upstream's pool rule (now in sidestr-rs, inactive).
- **Next:** First item of the next cycle: port D1 under D2's unmodified golden fixtures. When D2 holds, D1–D3 are ready to accept on that evidence, separately from the ledger-view decisions.

## Implementation — 2026-10-02

Owner decision 2026-10-02 (Q17) ordered the crypto items done now. Landed on `main`, unreleased:

- `7d27024`: published vectors pinned against the **pre-port** code before anything was switched over. These are
  the BIP-340 CSV (4 signing rows, 15 verification rows) and BIP-341 `keyPathSpending` (the key-path-only
  `tweakedPrivkey`, plus the `SIGHASH_DEFAULT` witness signed with `aux_rand = 0`). Also pinned: all seven
  BIP-341 `scriptPubKey`s and their BIP-350 addresses, JSS `signingKey` for golden cases A–C, and six chained-key
  rows (pubkey, privkey, both addresses, odd-Y points included). The old code passed all of them.
- `0befa5b`: **D1 done for both files.** `bitcoin` 0.32.102 (re-exporting `secp256k1` 0.29 / libsecp256k1) now
  provides serialisation, CompactSize, txid byte order, the P2TR script, the `TapSighash` (`SighashCache`), the
  key-path tweak (`TapTweakHash` + `Keypair::add_xonly_tweak`), BIP-340 signing and verification, the witness,
  the chained-key point and scalar adds, and bech32m. `add_mod_n`, `neg_mod_n`, `sub`, both `tagged_hash`
  helpers and the bech32m encoder are deleted. The `mrc20` feature swaps `dep:k256` for `dep:bitcoin`.
  **D2 holds:** the three golden tests pass byte-identical over `golden_tx.json`, unmodified since `fc56b39`.
  The BIP-341 `sigHash` vector is checked through the builder's own `SighashCache` call.
- `e62d028`: **D6 done.** The TXO stand-in branch, `AppState::deposit_txo_standin_enabled`,
  `--deposit-txo-standin` and `DEPOSIT_TXO_STANDIN_ENABLED` are deleted. A non-MRC20 deposit body gets 501 and
  writes no payment state (`txo_deposit_is_gone_and_credits_nothing`). `handle_mrc20_deposit` keeps its
  verified credit; stripping that credit waits on D4/D5.

Old-code defects the port turned into errors, each with a test: a 24–31-byte private key was left-padded by
k256 and then panicked in `copy_from_slice`; `p2tr_script` accepted an x-only key with no curve point, an
unspendable output; `verify_keypath_signature` accepted a non-32-byte sighash. No correct output changed.

**D3 in part.** The chained derivation ports and stays byte-identical. The `.buy` / `.withdraw` token routes
are still live, because their retirement belongs with D4/D5.

**Not built:** D4 (derived `WebLedger` view), D5 (`credit`/`debit` remain public), D7 (non-atomic payment
state) and D8 (lockstep consumer bump).

**Callers of the deleted deposit path.** VisionClaw's `src/handlers/pay_handler.rs` has its own `/pay/.deposit`
stub and does not call this crate's route. agentbox `management-api/routes/payments.js:332` proxies
`{txo_uri, amount_sats}` to this server's `/pay/.deposit` and, once the 501 arrives, surfaces it as an error.
nostr-rust-forum `nostr-bbs-pod-worker` imports `parse_txo_uri` (kept) for its own mempool-verified deposit.
That same forum handler has a sibling free-money path, outside this repo and not changed here. A
`{"amount_sats": N}` body with no `txo` credits `N` unverified (`crates/nostr-bbs-pod-worker/src/payments.rs`,
`pay_deposit_handler`), behind only NIP-98 and `PAY_ENABLED`, which `wrangler.toml` sets to `"false"`.

Ratification of D1–D3 is the owner's call on this evidence; `decision_status` stays `proposed` until then.

