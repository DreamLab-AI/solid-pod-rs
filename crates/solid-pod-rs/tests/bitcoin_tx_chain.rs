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
    anchor_state, decode_tx_info, gitmark_advance, gitmark_genesis, mint_token,
    transfer_token_with_key, verify_keypath_signature, MempoolBroadcast, TxoVoucher,
};
use solid_pod_rs::blocktrail::{
    verify_anchor_chain, verify_blocktrail, BlocktrailTxo, MarkStatus, TrailVerdict,
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
    /// address → UTXOs (drives `verify_mrc20_anchor`'s head lookup).
    utxos: HashMap<String, Vec<Utxo>>,
    /// txid → ordered outputs, for outputs registered by hand (vouchers).
    txs: HashMap<String, Vec<TxOut>>,
    /// txid → every broadcast transaction, decoded (inputs and outputs), so
    /// the per-link walk can follow each mark back to the one it spends.
    decoded: std::sync::Arc<std::sync::Mutex<HashMap<String, TxInfo>>>,
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

    /// Seed the UTXO `txid:vout` at `address` so `verify_mrc20_anchor` finds
    /// the head there.
    fn add_utxo_at(&mut self, address: &str, txid: &str, value: u64) {
        self.utxos
            .entry(address.to_string())
            .or_default()
            .push(Utxo {
                txid: txid.to_string(),
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
        if let Some(info) = self.decoded.lock().unwrap().get(txid) {
            return Ok(info.clone());
        }
        match self.txs.get(txid) {
            Some(vout) => Ok(TxInfo {
                txid: txid.to_string(),
                vin: vec![],
                vout: vout.clone(),
                confirmed: true,
                block_height: Some(840_000),
            }),
            None => Err(PaymentError::InvalidState(format!("tx {txid} not found"))),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl MempoolBroadcast for FixtureMempool {
    async fn broadcast_tx(&self, raw_hex: &str) -> Result<String, PaymentError> {
        // Fixture "broadcast": decode the transaction, keep it (confirmed at a
        // fixed height) under its real txid, and return that txid.
        let mut info = decode_tx_info(raw_hex)?;
        info.confirmed = true;
        info.block_height = Some(840_001);
        let txid = info.txid.clone();
        self.decoded.lock().unwrap().insert(txid.clone(), info);
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
    let mint = mint_token(
        "PROV",
        Some("Provenance Token"),
        1_000,
        &voucher,
        network,
        300,
        &mempool,
    )
    .await
    .expect("mint must build");
    // Genesis state is seq 0, prev all-zero.
    assert_eq!(mint.state.seq, 0);
    assert_eq!(mint.state.prev, "0".repeat(64));
    // The genesis output pays the genesis chained-key address.
    let genesis_addr = bt_address(
        &issuer_pubkey_hex(),
        std::slice::from_ref(&mint.state_jcs),
        network,
    )
    .unwrap();
    assert_eq!(mint.address, genesis_addr);
    // The mint tx's single sig verifies offline.
    assert!(
        verify_keypath_signature(
            &mint.tx.signing_xonly,
            &mint.tx.sighashes[0],
            &mint.tx.signatures[0]
        )
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
            std::slice::from_ref(&mint.state_jcs),
        )
        .unwrap();
        hex::encode(&chained[1..])
    };
    mempool.add_output(&mint_txid, 0, &format!("5120{genesis_xonly}"));

    // ── TRANSFER #1: issuer → recipientA, 100 ──
    let recipient_a = "aa".repeat(32); // arbitrary recipient pubkey hex
    let t1 = transfer_token_with_key(
        &trail,
        ISSUER_PRIVKEY,
        None,
        &recipient_a,
        100,
        300,
        &mempool,
    )
    .await
    .expect("transfer 1 must build");
    assert_eq!(t1.state.seq, 1);
    // Chain link: state1.prev == sha256(jcs(genesis)).
    assert_eq!(t1.state.prev, sha256_hex(&mint.state_jcs));
    // verify_state_link (Phase 1/2 invariant) accepts genesis → state1.
    verify_state_link(&t1.state, &mint.state).expect("state link genesis→1 must verify");
    assert!(
        verify_keypath_signature(
            &t1.tx.signing_xonly,
            &t1.tx.sighashes[0],
            &t1.tx.signatures[0]
        )
        .unwrap(),
        "transfer 1 signature must verify"
    );

    // Broadcast t1; register its output for t2 to spend.
    let t1_txid = mempool.broadcast_tx(&t1.tx.raw_hex).await.unwrap();
    let mut trail = t1.trail.clone();
    trail.current_txid = t1_txid.clone();
    let t1_xonly = {
        let chained = solid_pod_rs::mrc20::bt_derive_chained_pubkey(
            &issuer_pubkey_hex(),
            &trail.state_strings,
        )
        .unwrap();
        hex::encode(&chained[1..])
    };
    mempool.add_output(&t1_txid, 0, &format!("5120{t1_xonly}"));

    // ── TRANSFER #2: issuer → recipientB, 50 ──
    let recipient_b = "bb".repeat(32);
    let t2 = transfer_token_with_key(
        &trail,
        ISSUER_PRIVKEY,
        None,
        &recipient_b,
        50,
        300,
        &mempool,
    )
    .await
    .expect("transfer 2 must build");
    assert_eq!(t2.state.seq, 2);
    assert_eq!(t2.state.prev, sha256_hex(&t1.state_jcs));
    verify_state_link(&t2.state, &t1.state).expect("state link 1→2 must verify");
    assert!(
        verify_keypath_signature(
            &t2.tx.signing_xonly,
            &t2.tx.sighashes[0],
            &t2.tx.signatures[0]
        )
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
            std::slice::from_ref(&mint.state_jcs),
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

    // Broadcast the transfer and seed its output as the UTXO at the derived
    // head address, so the read-side finds the head and walks back from it.
    let derived_addr = bt_address(&issuer_pubkey_hex(), &t.trail.state_strings, network).unwrap();
    assert_eq!(t.address, derived_addr);
    let t_txid = mempool.broadcast_tx(&t.tx.raw_hex).await.unwrap();
    assert_eq!(t_txid, t.tx.txid, "BuiltTx::txid is the broadcast txid");
    mempool.add_utxo_at(&derived_addr, &t_txid, t.output_amount);

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
    // every link walked: the genesis mark and the transfer mark both commit
    assert_eq!(result.report.marks.len(), 2);
    assert_eq!(result.report.marks[0].txid, mint_txid);
    assert_eq!(result.report.verdict, TrailVerdict::Verified);

    // A head that is the right key is not enough: when the genesis mark
    // behind it is not the key the genesis state derives, the walk refuses.
    let mut forged = mempool.clone();
    {
        let mut decoded = forged.decoded.lock().unwrap().clone();
        let genesis = decoded.get_mut(&mint_txid).unwrap();
        genesis.vout[0].scriptpubkey = Some(format!("5120{}", "11".repeat(32)));
        forged.decoded = std::sync::Arc::new(std::sync::Mutex::new(decoded));
    }
    let err = verify_mrc20_anchor(
        &t.state,
        &mint.state,
        &recipient,
        &issuer_pubkey_hex(),
        &t.trail.state_strings,
        network,
        &forged,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("mark 0") && err.contains("wrong key"), "{err}");
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
            std::slice::from_ref(&mint.state_jcs),
        )
        .unwrap();
        hex::encode(&chained[1..])
    };
    mempool.add_output(&mint_txid, 0, &format!("5120{genesis_xonly}"));

    // Anchor a git commit SHA (40-hex). The state binds it via `anchor`.
    let commit_sha = "a1b2c3d4e5f60718293a4b5c6d7e8f9001122334";
    let anchored = anchor_state(&trail, ISSUER_PRIVKEY, commit_sha, 300, &mempool)
        .await
        .unwrap();

    assert_eq!(anchored.state.seq, 1);
    assert_eq!(anchored.state.prev, sha256_hex(&mint.state_jcs));
    assert_eq!(anchored.state.anchor.as_deref(), Some(commit_sha));
    assert_eq!(anchored.state.ops.len(), 1);
    assert_eq!(anchored.state.ops[0].op, "urn:mono:op:anchor");
    // Balances carried forward unchanged (anchor doesn't move tokens).
    assert_eq!(
        anchored
            .state
            .balances
            .clone()
            .unwrap()
            .get(&issuer_pubkey_hex())
            .copied(),
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

// ── git-mark trails: the profile new trails use ──────────────────────────

const COMMITS: [&str; 3] = [
    "0123456789abcdef0123456789abcdef01234567",
    "cf97baba489e88c1ffbe6758c0fe8c18ff83d17d",
    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
];

#[tokio::test]
async fn gitmark_genesis_and_advance_build_a_trail_that_verifies_link_by_link() {
    let network = "testnet4";
    let mut mempool = FixtureMempool::new();
    let voucher = issuer_voucher(&mut mempool, &"44".repeat(32), 100_000);

    let g = gitmark_genesis(&voucher, COMMITS[0], network, 300, &mempool)
        .await
        .unwrap();
    assert_eq!(
        g.trail.pubkey_base.as_deref(),
        Some(issuer_pubkey_hex().as_str())
    );
    assert_eq!(g.trail.chain.as_deref(), Some("tbtc4"));
    assert_eq!(g.txo.commit.as_deref(), Some(COMMITS[0]));
    assert_eq!(g.output_amount, 99_700);
    // the state is the commit as text, with no MRC20 wrapper
    assert_eq!(
        g.trail.state_strings().unwrap(),
        vec![COMMITS[0].to_string()]
    );
    assert_eq!(
        g.address,
        bt_address(&issuer_pubkey_hex(), &[COMMITS[0].to_string()], network).unwrap()
    );
    assert_eq!(
        mempool.broadcast_tx(&g.tx.raw_hex).await.unwrap(),
        g.txo.txid
    );

    let mut trail = g.trail;
    for commit in &COMMITS[1..] {
        let a = gitmark_advance(&trail, ISSUER_PRIVKEY, commit, 300, &mempool)
            .await
            .unwrap();
        assert!(verify_keypath_signature(
            &a.tx.signing_xonly,
            &a.tx.sighashes[0],
            &a.tx.signatures[0]
        )
        .unwrap());
        assert_eq!(
            mempool.broadcast_tx(&a.tx.raw_hex).await.unwrap(),
            a.txo.txid
        );
        trail = a.trail;
    }
    assert_eq!(trail.txo.len(), 3);
    assert_eq!(
        trail
            .txo
            .iter()
            .map(|t| t.amount.unwrap())
            .collect::<Vec<_>>(),
        vec![99_700, 99_400, 99_100]
    );

    // blocktrails/verify's walk over the trail as published
    let report = verify_blocktrail(&trail, &mempool).await;
    assert_eq!(report.verdict, TrailVerdict::Verified, "{report:?}");
    assert!(report
        .marks
        .iter()
        .all(|m| m.status == MarkStatus::Verified));
    // and the same trail walked back from its head alone
    let head = trail.txo.last().unwrap();
    let back = verify_anchor_chain(
        &issuer_pubkey_hex(),
        &trail.state_strings().unwrap(),
        &head.txid,
        head.vout,
        &mempool,
    )
    .await
    .unwrap();
    // the same marks and verdict; only the recorded amounts are not known
    // to a walk from the head
    let mut without_amounts = report.clone();
    for m in &mut without_amounts.marks {
        m.amount = None;
    }
    assert_eq!(back, without_amounts);

    // two states swapped: every link from the swap on refuses
    let mut swapped = trail.clone();
    swapped.states.swap(1, 2);
    let report = verify_blocktrail(&swapped, &mempool).await;
    assert_eq!(report.verdict, TrailVerdict::Partial);
    assert_eq!(report.marks[0].status, MarkStatus::Verified);
    assert_eq!(report.marks[1].status, MarkStatus::WrongKey);
    assert_eq!(report.marks[2].status, MarkStatus::WrongKey);
}

#[tokio::test]
async fn gitmark_advance_refuses_what_it_must_not_extend() {
    let network = "testnet4";
    let mut mempool = FixtureMempool::new();
    let voucher = issuer_voucher(&mut mempool, &"55".repeat(32), 100_000);
    let g = gitmark_genesis(&voucher, COMMITS[0], network, 300, &mempool)
        .await
        .unwrap();
    mempool.broadcast_tx(&g.tx.raw_hex).await.unwrap();

    // not a commit
    for bad in [
        "CF97BABA489E88C1FFBE6758C0FE8C18FF83D17D",
        "cf97baba",
        "\"cf97\"",
    ] {
        assert!(
            gitmark_advance(&g.trail, ISSUER_PRIVKEY, bad, 300, &mempool)
                .await
                .is_err()
        );
        assert!(gitmark_genesis(&voucher, bad, network, 300, &mempool)
            .await
            .is_err());
    }
    // another secret than the base key's
    let other = "0000000000000000000000000000000000000000000000000000000000000009";
    let err = gitmark_advance(&g.trail, other, COMMITS[1], 300, &mempool)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("not the trail's base key"), "{err}");
    // a trail whose states do not derive its newest mark is never extended
    let mut tampered = g.trail.clone();
    tampered.states = vec![serde_json::Value::String(COMMITS[2].into())];
    let err = gitmark_advance(&tampered, ISSUER_PRIVKEY, COMMITS[1], 300, &mempool)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("refusing to extend"), "{err}");
    // a trail that lists no states takes them from its marks, and writes them out
    let mut bare = g.trail.clone();
    bare.states.clear();
    let a = gitmark_advance(&bare, ISSUER_PRIVKEY, COMMITS[1], 300, &mempool)
        .await
        .unwrap();
    assert_eq!(a.trail.states.len(), 2);
    // a mark with no chain cannot be advanced from
    let mut chainless = g.trail.clone();
    chainless.chain = None;
    chainless.txo = vec![BlocktrailTxo {
        chain: None,
        ..g.txo.clone()
    }];
    assert!(
        gitmark_advance(&chainless, ISSUER_PRIVKEY, COMMITS[1], 300, &mempool)
            .await
            .is_err()
    );
}
