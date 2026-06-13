//! Chain-logic integration tests for the block-trail write-side
//! (`bitcoin_tx.rs`, ADR-059 Phase 4).
//!
//! These exercise the high-level composers (`mint_token`,
//! `transfer_token_with_key`, `anchor_state`) through a **fixture**
//! `MempoolLookup` (no live chain) and assert:
//!
//! 1. mint → transfer → transfer produces a valid SHA-256 hash-chained trail
//!    whose state links verify under the Phase-1/2 `verify_state_link`
//!    (reusing the existing mrc20 chain invariants as the floor);
//! 2. every produced transaction's signature verifies offline against the
//!    derived signing x-only key;
//! 3. Phase 3's `verify_mrc20_anchor` ACCEPTS the produced states against a
//!    fixture mempool seeded with the derived addresses (the write-side and
//!    the read-side compose);
//! 4. `anchor_state` notarises a `state_hash` (e.g. a git commit SHA) and
//!    yields a spendable, chained-key anchoring UTXO.
//!
//! No network access; deterministic; gated on `feature = "mrc20"`.

#![cfg(feature = "mrc20")]

use std::collections::HashMap;

use solid_pod_rs::bitcoin_tx::{
    anchor_state, mint_token, transfer_token_with_key, verify_keypath_signature, MempoolBroadcast,
    TxoVoucher,
};
use solid_pod_rs::mrc20::{
    bt_address, jcs, sha256_hex, verify_mrc20_anchor, verify_state_link, MempoolLookup, TxInfo,
    TxOut, Utxo,
};
use solid_pod_rs::payments::PaymentError;

// ── Fixture mempool: address→UTXO map + txid→scriptPubKey map ────────────
//
// Mirrors the FixtureMempool used by the Phase-3 mrc20 anchor tests, plus a
// txid→(vout→scriptpubkey) map so `mint`/`transfer` can resolve the
// scriptPubKey of the output they spend (the write-side needs `tx()`, not
// just `address_utxos()`).

#[derive(Default, Clone)]
struct FixtureMempool {
    /// address → UTXOs (drives `verify_mrc20_anchor`).
    utxos: HashMap<String, Vec<Utxo>>,
    /// txid → ordered outputs (drives the write-side scriptPubKey fetch).
    txs: HashMap<String, Vec<TxOut>>,
    /// Captured broadcasts: txid → raw hex (assert what was sent).
    broadcasts: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
}

impl FixtureMempool {
    fn new() -> Self {
        Self::default()
    }

    /// Register an output (`txid:vout` paying `script_pubkey_hex`) so the
    /// write-side can fetch its scriptPubKey when spending it.
    fn add_output(&mut self, txid: &str, vout: u32, script_pubkey_hex: &str) {
        let outs = self.txs.entry(txid.to_string()).or_default();
        while outs.len() <= vout as usize {
            outs.push(TxOut {
                value: 0,
                scriptpubkey: None,
                scriptpubkey_address: None,
            });
        }
        outs[vout as usize] = TxOut {
            value: 0,
            scriptpubkey: Some(script_pubkey_hex.to_string()),
            scriptpubkey_address: None,
        };
    }

    /// Seed a UTXO at `address` so `verify_mrc20_anchor` finds it.
    fn add_utxo_at(&mut self, address: &str, value: u64) {
        self.utxos.entry(address.to_string()).or_default().push(Utxo {
            txid: "00".repeat(32),
            vout: 0,
            value,
            confirmed: true,
            block_height: Some(840_000),
        });
    }
}

#[async_trait::async_trait(?Send)]
impl MempoolLookup for FixtureMempool {
    async fn address_utxos(&self, address: &str) -> Result<Vec<Utxo>, PaymentError> {
        Ok(self.utxos.get(address).cloned().unwrap_or_default())
    }
    async fn tx(&self, txid: &str) -> Result<TxInfo, PaymentError> {
        Ok(TxInfo {
            txid: txid.to_string(),
            vout: self.txs.get(txid).cloned().unwrap_or_default(),
            confirmed: true,
            block_height: Some(840_000),
        })
    }
}

#[async_trait::async_trait(?Send)]
impl MempoolBroadcast for FixtureMempool {
    async fn broadcast_tx(&self, raw_hex: &str) -> Result<String, PaymentError> {
        // Fixture "broadcast": derive a synthetic txid (sha256 of the raw tx,
        // reversed-display) and record it. The real txid is the double-SHA of
        // the legacy serialisation, but for chain-walk tests any stable,
        // unique id suffices — the *crypto* correctness is asserted via the
        // golden + signature-verify gates, not via the txid value.
        let txid = sha256_hex(raw_hex);
        self.broadcasts
            .lock()
            .unwrap()
            .push((txid.clone(), raw_hex.to_string()));
        Ok(txid)
    }
}

// Issuer keypair — a fixed, arbitrary testnet key.
const ISSUER_PRIVKEY: &str = "0000000000000000000000000000000000000000000000000000000000000007";

fn issuer_pubkey_hex() -> String {
    let sk = k256::SecretKey::from_slice(&hex::decode(ISSUER_PRIVKEY).unwrap()).unwrap();
    hex::encode(sk.public_key().to_sec1_bytes())
}

/// A voucher controlled by the issuer key, funding the genesis tx. The
/// scriptPubKey of an MRC20 chained-key UTXO is `5120<xonly>`; the voucher's
/// own output is a plain key-path output of the issuer key so `needs_tweak`
/// is false (`5120<xonly(issuer)>`), exercising the untweaked sign path.
fn issuer_voucher(mempool: &mut FixtureMempool, txid: &str, amount: u64) -> TxoVoucher {
    let sk = k256::SecretKey::from_slice(&hex::decode(ISSUER_PRIVKEY).unwrap()).unwrap();
    let compressed = sk.public_key().to_sec1_bytes();
    let xonly_hex = hex::encode(&compressed[1..]);
    let spk_hex = format!("5120{xonly_hex}");
    mempool.add_output(txid, 0, &spk_hex);
    TxoVoucher {
        txid: txid.to_string(),
        vout: 0,
        amount,
        privkey: ISSUER_PRIVKEY.to_string(),
    }
}

#[tokio::test]
async fn mint_then_transfer_twice_is_a_valid_hash_chained_trail() {
    let network = "testnet4";
    let mut mempool = FixtureMempool::new();
    let voucher_txid = "11".repeat(32);
    let voucher = issuer_voucher(&mut mempool, &voucher_txid, 100_000);

    // ── MINT ──
    let mint = mint_token("PROV", Some("Provenance Token"), 1_000, &voucher, network, 300, &mempool)
        .await
        .expect("mint must build");
    // Genesis state is seq 0, prev all-zero.
    assert_eq!(mint.state.seq, 0);
    assert_eq!(mint.state.prev, "0".repeat(64));
    // The genesis output pays the genesis chained-key address.
    let genesis_addr = bt_address(&issuer_pubkey_hex(), &[mint.state_jcs.clone()], network).unwrap();
    assert_eq!(mint.address, genesis_addr);
    // The mint tx's single sig verifies offline.
    assert!(
        verify_keypath_signature(&mint.tx.signing_xonly, &mint.tx.sighashes[0], &mint.tx.signatures[0])
            .unwrap(),
        "mint signature must verify"
    );

    // Simulate broadcast + UTXO confirmation: the genesis UTXO now sits at the
    // genesis address. Register its scriptPubKey so the next transfer can spend
    // it, and set the trail's currentTxid to the broadcast id.
    let mint_txid = mempool.broadcast_tx(&mint.tx.raw_hex).await.unwrap();
    let mut trail = mint.trail.clone();
    trail.current_txid = mint_txid.clone();
    // The genesis output scriptPubKey is the chained-key P2TR; register it.
    let genesis_xonly = {
        // bt_address derives the same chained key; recover xonly from the addr
        // by re-deriving the chained pubkey for the scriptPubKey.
        let chained = solid_pod_rs::mrc20::bt_derive_chained_pubkey(
            &issuer_pubkey_hex(),
            &[mint.state_jcs.clone()],
        )
        .unwrap();
        hex::encode(&chained[1..])
    };
    mempool.add_output(&mint_txid, 0, &format!("5120{genesis_xonly}"));

    // ── TRANSFER #1: issuer → recipientA, 100 ──
    let recipient_a = "aa".repeat(32); // arbitrary recipient pubkey hex
    let t1 = transfer_token_with_key(&trail, ISSUER_PRIVKEY, None, &recipient_a, 100, 300, &mempool)
        .await
        .expect("transfer 1 must build");
    assert_eq!(t1.state.seq, 1);
    // Chain link: state1.prev == sha256(jcs(genesis)).
    assert_eq!(t1.state.prev, sha256_hex(&mint.state_jcs));
    // verify_state_link (Phase 1/2 invariant) accepts genesis → state1.
    verify_state_link(&t1.state, &mint.state).expect("state link genesis→1 must verify");
    assert!(
        verify_keypath_signature(&t1.tx.signing_xonly, &t1.tx.sighashes[0], &t1.tx.signatures[0])
            .unwrap(),
        "transfer 1 signature must verify"
    );

    // Broadcast t1; register its output for t2 to spend.
    let t1_txid = mempool.broadcast_tx(&t1.tx.raw_hex).await.unwrap();
    let mut trail = t1.trail.clone();
    trail.current_txid = t1_txid.clone();
    let t1_xonly = {
        let chained =
            solid_pod_rs::mrc20::bt_derive_chained_pubkey(&issuer_pubkey_hex(), &trail.state_strings)
                .unwrap();
        hex::encode(&chained[1..])
    };
    mempool.add_output(&t1_txid, 0, &format!("5120{t1_xonly}"));

    // ── TRANSFER #2: issuer → recipientB, 50 ──
    let recipient_b = "bb".repeat(32);
    let t2 = transfer_token_with_key(&trail, ISSUER_PRIVKEY, None, &recipient_b, 50, 300, &mempool)
        .await
        .expect("transfer 2 must build");
    assert_eq!(t2.state.seq, 2);
    assert_eq!(t2.state.prev, sha256_hex(&t1.state_jcs));
    verify_state_link(&t2.state, &t1.state).expect("state link 1→2 must verify");
    assert!(
        verify_keypath_signature(&t2.tx.signing_xonly, &t2.tx.sighashes[0], &t2.tx.signatures[0])
            .unwrap(),
        "transfer 2 signature must verify"
    );

    // ── Balances after the chain: issuer 850, A 100, B 50 (supply 1000) ──
    let final_balances = t2.state.balances.clone().unwrap();
    assert_eq!(final_balances.get(&issuer_pubkey_hex()).copied(), Some(850));
    assert_eq!(final_balances.get(&recipient_a).copied(), Some(100));
    assert_eq!(final_balances.get(&recipient_b).copied(), Some(50));
    let total: u64 = final_balances.values().sum();
    assert_eq!(total, 1_000, "conservation of supply across the chain");

    // ── The trail's state_strings are the JCS of each state, in order ──
    assert_eq!(t2.trail.state_strings.len(), 3);
    assert_eq!(t2.trail.state_strings[0], mint.state_jcs);
    assert_eq!(t2.trail.state_strings[1], t1.state_jcs);
    assert_eq!(t2.trail.state_strings[2], t2.state_jcs);
    // And each is exactly jcs(state).
    assert_eq!(
        t2.trail.state_strings[2],
        jcs(&serde_json::to_value(&t2.state).unwrap())
    );
}

#[tokio::test]
async fn verify_mrc20_anchor_accepts_a_produced_transfer_state() {
    // The write-side produces a transfer state; the Phase-3 read-side
    // (`verify_mrc20_anchor`) must ACCEPT it when the derived address has a
    // UTXO. This proves write and verify compose end-to-end.
    let network = "testnet4";
    let mut mempool = FixtureMempool::new();
    let voucher_txid = "22".repeat(32);
    let voucher = issuer_voucher(&mut mempool, &voucher_txid, 100_000);

    let mint = mint_token("ANCH", None, 1_000, &voucher, network, 300, &mempool)
        .await
        .unwrap();
    let mint_txid = mempool.broadcast_tx(&mint.tx.raw_hex).await.unwrap();
    let mut trail = mint.trail.clone();
    trail.current_txid = mint_txid.clone();
    let genesis_xonly = {
        let chained = solid_pod_rs::mrc20::bt_derive_chained_pubkey(
            &issuer_pubkey_hex(),
            &[mint.state_jcs.clone()],
        )
        .unwrap();
        hex::encode(&chained[1..])
    };
    mempool.add_output(&mint_txid, 0, &format!("5120{genesis_xonly}"));

    // Transfer 200 to a recipient address (the to-address the read-side checks).
    let recipient = "cc".repeat(32);
    let t = transfer_token_with_key(&trail, ISSUER_PRIVKEY, None, &recipient, 200, 300, &mempool)
        .await
        .unwrap();

    // Seed the derived next-address with a UTXO so the read-side finds it.
    let derived_addr = bt_address(&issuer_pubkey_hex(), &t.trail.state_strings, network).unwrap();
    assert_eq!(t.address, derived_addr);
    mempool.add_utxo_at(&derived_addr, t.output_amount);

    // verify_mrc20_anchor: state-chain + transfer-to-recipient + derived-addr +
    // UTXO-present. The transfer op targets `recipient` with amt 200.
    let result = verify_mrc20_anchor(
        &t.state,
        &mint.state,
        &recipient,
        &issuer_pubkey_hex(),
        &t.trail.state_strings,
        network,
        &mempool,
    )
    .await
    .expect("Phase-3 verify must ACCEPT the write-side-produced state");
    assert_eq!(result.amount, 200);
    assert_eq!(result.address, derived_addr);
    assert_eq!(result.ticker, "ANCH");
}

#[tokio::test]
async fn anchor_state_notarises_a_state_hash() {
    // `anchor_state` is the provenance write: it appends a state binding a
    // `state_hash` (here a synthetic git commit SHA) and builds a spendable
    // anchoring UTXO. Verify the chain link, the `anchor` field, and the sig.
    let network = "testnet4";
    let mut mempool = FixtureMempool::new();
    let voucher_txid = "33".repeat(32);
    let voucher = issuer_voucher(&mut mempool, &voucher_txid, 100_000);

    let mint = mint_token("GITP", None, 1_000, &voucher, network, 300, &mempool)
        .await
        .unwrap();
    let mint_txid = mempool.broadcast_tx(&mint.tx.raw_hex).await.unwrap();
    let mut trail = mint.trail.clone();
    trail.current_txid = mint_txid.clone();
    let genesis_xonly = {
        let chained = solid_pod_rs::mrc20::bt_derive_chained_pubkey(
            &issuer_pubkey_hex(),
            &[mint.state_jcs.clone()],
        )
        .unwrap();
        hex::encode(&chained[1..])
    };
    mempool.add_output(&mint_txid, 0, &format!("5120{genesis_xonly}"));

    // Anchor a git commit SHA (40-hex). The state binds it via `anchor`.
    let commit_sha = "a1b2c3d4e5f60718293a4b5c6d7e8f9001122334";
    let anchored =
        anchor_state(&trail, ISSUER_PRIVKEY, commit_sha, 300, &mempool).await.unwrap();

    assert_eq!(anchored.state.seq, 1);
    assert_eq!(anchored.state.prev, sha256_hex(&mint.state_jcs));
    assert_eq!(anchored.state.anchor.as_deref(), Some(commit_sha));
    assert_eq!(anchored.state.ops.len(), 1);
    assert_eq!(anchored.state.ops[0].op, "urn:mono:op:anchor");
    // Balances carried forward unchanged (anchor doesn't move tokens).
    assert_eq!(
        anchored.state.balances.clone().unwrap().get(&issuer_pubkey_hex()).copied(),
        Some(1_000)
    );
    verify_state_link(&anchored.state, &mint.state).expect("anchor state links to genesis");
    assert!(
        verify_keypath_signature(
            &anchored.tx.signing_xonly,
            &anchored.tx.sighashes[0],
            &anchored.tx.signatures[0]
        )
        .unwrap(),
        "anchor tx signature must verify"
    );
}
