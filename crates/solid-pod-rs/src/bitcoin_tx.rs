//! Bitcoin taproot transaction building — the **write-side** of block-trails.
//!
//! This is the Rust port of JSS `src/token.js` `buildTransaction`
//! (lines 117-174): a BIP-341 key-path taproot transaction builder with
//! BIP-340 Schnorr signing. It produces broadcastable raw transactions for
//! MRC20 mint/transfer and for anchoring an arbitrary block-trail state, plus
//! the high-level [`mint_token`](crate::bitcoin_tx::mint_token),
//! [`transfer_token_with_key`](crate::bitcoin_tx::transfer_token_with_key)
//! and [`anchor_state`](crate::bitcoin_tx::anchor_state) composers that the
//! server's `BlockAnchorer::anchor` and the `/pay/.buy` / `/pay/.withdraw`
//! routes call, and the git-mark composers
//! [`gitmark_genesis`](crate::bitcoin_tx::gitmark_genesis) /
//! [`gitmark_advance`](crate::bitcoin_tx::gitmark_advance) (each state the
//! commit as text, blocktrails/git-mark b852d7d) that new trails use.
//!
//! # Crypto provenance — nothing hand-rolled
//!
//! Every Bitcoin primitive comes from [`bitcoin`] (rust-bitcoin) and the
//! libsecp256k1 binding it re-exports (ADR-2008 D1): transaction and
//! CompactSize serialisation, txid byte order, P2TR script construction, the
//! BIP-341 `TapTweak` and `TapSighash` tagged hashes, the key-path tweak of
//! the secret key, and BIP-340 signing and verification. This module only
//! decides *what* to build. The chained-key derivation and JCS live in
//! [`crate::mrc20`] and are reused (`bt_derive_chained_pubkey`,
//! `bt_derive_chained_privkey`, `bt_address`, [`jcs`](crate::mrc20::jcs),
//! [`sha256_hex`](crate::mrc20::sha256_hex)).
//!
//! The port is held byte-identical to the previous hand-rolled builder by the
//! cross-implementation golden fixture (`tests/fixtures/bitcoin/golden_tx.json`,
//! generated from JSS) and by the published BIP-340 and BIP-341 test vectors.
//!
//! ## Signature determinism (cross-impl golden)
//!
//! JSS `schnorr.sign(sighash, key)` (`token.js:156`) supplies **no** aux_rand,
//! so `@noble/curves` injects `randomBytes(32)` — production JSS tx hex is
//! non-deterministic. BIP-340, however, is fully deterministic when
//! `aux_rand = 0^32`. We sign with `aux_rand = 0^32`, which makes our output
//! reproducible *and* byte-for-byte identical to JSS when JSS is pinned to
//! `aux_rand = 0` (the cross-impl golden fixture is generated that way).
//! libsecp256k1 performs the BIP-340 even-Y negation of the secret
//! internally, exactly as `@noble` does.
//!
//! ## wasm32 boundary
//!
//! The module is gated `#[cfg(not(target_arch = "wasm32"))]` (and behind
//! feature `mrc20`) per ADR-059 D4: the write-side is a native, server-only
//! concern and must **not** leak into the wasm `core` surface. The
//! [`MempoolBroadcast`](crate::bitcoin_tx::MempoolBroadcast) trait itself is
//! pure (`?Send`, no I/O) — the concrete reqwest implementation lives
//! server-side in `solid-pod-rs-server::mempool`, mirroring Phase 3's
//! [`MempoolLookup`](crate::mrc20::MempoolLookup).

#![cfg(all(feature = "mrc20", not(target_arch = "wasm32")))]
#![warn(missing_docs)]

use std::str::FromStr;

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak, TweakedPublicKey};
use bitcoin::secp256k1::{rand, schnorr, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use serde_json::json;

use crate::blocktrail::{
    is_gitmark_commit, network_for_txo_chain, txo_chain_for_network, Blocktrail, BlocktrailTxo,
};
use crate::mrc20::{
    bt_address, bt_base_point, bt_derive_chained_privkey, bt_derive_chained_pubkey, jcs,
    sha256_hex, MempoolLookup, Mrc20Op, Mrc20State, Mrc20Trail, TxIn as TxInView, TxInfo,
    TxOut as TxOutView, MRC20_PROFILE, TRANSFER_OP,
};
use crate::payments::PaymentError;

/// Default fee in sats (JSS `token.js:278,369`).
pub const DEFAULT_FEE_SATS: u64 = 300;
/// Dust threshold in sats — an output at or below this is uneconomical
/// (JSS `token.js:280,371`).
pub const DUST_LIMIT_SATS: u64 = 546;

/// nSequence on every input: `0xfffffffd`, replace-by-fee signalled and no
/// relative lock-time (JSS `token.js`).
const INPUT_SEQUENCE: Sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;

fn invalid(msg: impl std::fmt::Display) -> PaymentError {
    PaymentError::InvalidState(msg.to_string())
}

/// Parse a 32-byte x-only public key, as BIP-340/341 define it.
fn parse_xonly(xonly: &[u8]) -> Result<XOnlyPublicKey, PaymentError> {
    if xonly.len() != 32 {
        return Err(invalid(format!(
            "x-only pubkey must be 32 bytes, got {}",
            xonly.len()
        )));
    }
    XOnlyPublicKey::from_slice(xonly).map_err(|e| invalid(format!("bad x-only pubkey: {e}")))
}

/// Parse a 32-byte secret key. Exactly 32 bytes are required: shorter
/// slices are refused rather than left-padded.
fn parse_secret(privkey: &[u8]) -> Result<SecretKey, PaymentError> {
    if privkey.len() != 32 {
        return Err(invalid(format!(
            "privkey must be 32 bytes, got {}",
            privkey.len()
        )));
    }
    SecretKey::from_slice(privkey).map_err(|e| invalid(format!("bad privkey: {e}")))
}

// ── P2TR output script (token.js:112-114) ───────────────────────────────

/// Build a P2TR (pay-to-taproot) output script, `OP_1 PUSH32 <x-only key>`
/// (`5120…`, JSS `token.js:112-114`), for an output key that is already the
/// final (tweaked or chained) key.
///
/// `xonly` must be 32 bytes and a valid secp256k1 x coordinate: an output to
/// a non-point can never be spent, so it is refused.
pub fn p2tr_script(xonly: &[u8]) -> Result<Vec<u8>, PaymentError> {
    let key = parse_xonly(xonly)?;
    Ok(ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(key)).into_bytes())
}

/// The x-only public key of `privkey`.
fn xonly_of(privkey: &[u8]) -> Result<[u8; 32], PaymentError> {
    let secp = Secp256k1::signing_only();
    let sk = parse_secret(privkey)?;
    Ok(sk.x_only_public_key(&secp).0.serialize())
}

// ── Transaction input / output value types ──────────────────────────────

/// A transaction input spending a previous taproot output.
///
/// `scriptPubKey` is the **full** `scriptPubKey` of the output being spent
/// (`5120<xonly>` for taproot) — needed for the BIP-341 sighash and to decide
/// whether the default TapTweak must be applied (JSS `token.js:120`).
#[derive(Debug, Clone)]
pub struct TxInput {
    /// Big-endian (display order) txid hex (64 chars) of the funding output.
    pub txid: String,
    /// Output index within `txid`.
    pub vout: u32,
    /// Value of the output being spent, in sats (BIP-341 commits to amounts).
    pub amount: u64,
    /// Full `scriptPubKey` bytes of the output being spent.
    pub script_pubkey: Vec<u8>,
}

/// A transaction output paying `amount` sats to `script_pubkey`.
#[derive(Debug, Clone)]
pub struct TxOutput {
    /// Output value in sats.
    pub amount: u64,
    /// `scriptPubKey` bytes (use [`p2tr_script`] for a taproot output).
    pub script_pubkey: Vec<u8>,
}

/// The result of [`build_transaction`].
///
/// Carries the broadcastable `raw_hex` plus the per-input `sighashes` and the
/// `signing_xonly` (x-only pubkey the signatures verify against). The latter
/// two are what the offline correctness gate checks: every signature must
/// verify against `signing_xonly`, and the `sighashes`/`unsigned_hex` must
/// match JSS byte-for-byte even when nonces differ.
#[derive(Debug, Clone)]
pub struct BuiltTx {
    /// The transaction id (display order, 64 hex), as a broadcast returns it.
    pub txid: String,
    /// Fully-signed, broadcastable transaction (segwit-serialised) as hex.
    pub raw_hex: String,
    /// Unsigned (legacy, witness-stripped) serialisation as hex — the
    /// deterministic skeleton, independent of the Schnorr nonce.
    pub unsigned_hex: String,
    /// BIP-341 TapSighash (hex) for each input, in input order.
    pub sighashes: Vec<String>,
    /// 64-byte Schnorr signatures (hex) for each input, in input order.
    pub signatures: Vec<String>,
    /// x-only pubkey (hex) the signatures verify against — i.e. the BIP-340
    /// public key of the effective signing scalar (post even-Y normalisation,
    /// post tweak). Used by the offline verification gate.
    pub signing_xonly: String,
}

/// The secret scalar a key-path spend signs with (JSS `token.js:118-129`).
///
/// Untweaked: `privkey` itself. Tweaked: the BIP-341 key-path-only tweak
/// `(negate_if_odd_y(d) + TapTweak(xonly(d))) mod n`, computed by
/// rust-bitcoin's [`TapTweak`] for [`Keypair`]. The result is *not* further
/// normalised to even Y: that happens inside BIP-340 signing.
fn keypath_signing_secret(privkey: &[u8], needs_tweak: bool) -> Result<[u8; 32], PaymentError> {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &parse_secret(privkey)?);
    if !needs_tweak {
        return Ok(keypair.secret_bytes());
    }
    // `TapTweak::tap_tweak` for `Keypair` expects on an out-of-range tweak
    // (probability ~2^-128); this is the same computation, made fallible.
    let (internal, _parity) = keypair.x_only_public_key();
    let tweak = bitcoin::taproot::TapTweakHash::from_key_and_tweak(internal, None).to_scalar();
    let tweaked = keypair
        .add_xonly_tweak(&secp, &tweak)
        .map_err(|e| invalid(format!("taproot tweak failed: {e}")))?;
    debug_assert_eq!(
        tweaked.x_only_public_key().0,
        internal.tap_tweak(&secp, None).0.to_x_only_public_key(),
        "secret and public tweak must agree"
    );
    Ok(tweaked.secret_bytes())
}

/// BIP-340 sign a 32-byte message with `aux_rand = 0^32`.
fn schnorr_sign_zero_aux(secret: &[u8; 32], msg: &[u8; 32]) -> Result<[u8; 64], PaymentError> {
    let secp = Secp256k1::signing_only();
    let keypair = Keypair::from_seckey_slice(&secp, secret)
        .map_err(|e| invalid(format!("invalid signing scalar: {e}")))?;
    let sig = secp.sign_schnorr_with_aux_rand(&Message::from_digest(*msg), &keypair, &[0u8; 32]);
    Ok(*sig.as_ref())
}

// ── Core: BIP-341 key-path taproot tx builder ───────────────────────────

/// Build and key-path-sign a taproot transaction (JSS `token.js:117-174`).
///
/// All inputs are signed with `privkey` (the JSS builder signs every input
/// with one key — callers group UTXOs by key/tweak before calling, exactly
/// as `pay.js` withdraw-sats does). The transaction is version 2, locktime
/// 0, sequence `0xfffffffd` on every input, empty `scriptSig`s, and one
/// 64-byte `SIGHASH_DEFAULT` key-path signature per witness.
///
/// 1. `needs_tweak` is `true` unless the first input's `scriptPubKey` is
///    precisely `5120<xonly(privkey)>` — i.e. the output pays the
///    **untweaked** internal key. MRC20 chained-key spends are untweaked (the
///    chaining tweaks are already baked into `privkey`); externally-funded
///    vouchers are tweaked (BIP-341 default/key-path-only TapTweak).
///    (`token.js:118-129`)
/// 2. Each input's BIP-341 `TapSighash` (`SIGHASH_DEFAULT`, committing to
///    every prevout, amount and `scriptPubKey`) comes from rust-bitcoin's
///    [`SighashCache`].
/// 3. The sighash is signed with `aux_rand = 0` for deterministic BIP-340.
///
/// # Errors
///
/// [`PaymentError::InvalidState`] when there are no inputs, `privkey` is not
/// a valid 32-byte secret key, a txid is not 64 hex characters, or an
/// amount exceeds the 21-million-BTC money range.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "mrc20")] {
/// use solid_pod_rs::bitcoin_tx::{
///     build_transaction, p2tr_script, verify_keypath_signature, TxInput, TxOutput,
/// };
///
/// let mut privkey = [0u8; 32];
/// privkey[31] = 1; // secret key 1, internal key = G
/// let g_x = hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
///
/// let built = build_transaction(
///     &[TxInput {
///         txid: "aa".repeat(32),
///         vout: 0,
///         amount: 10_000,
///         script_pubkey: p2tr_script(&g_x).unwrap(), // pays the untweaked key
///     }],
///     &[TxOutput { amount: 9_700, script_pubkey: p2tr_script(&g_x).unwrap() }],
///     &privkey,
/// )
/// .unwrap();
///
/// assert!(built.raw_hex.starts_with("02000000000101")); // v2, segwit marker, 1 input
/// assert!(verify_keypath_signature(&built.signing_xonly, &built.sighashes[0], &built.signatures[0]).unwrap());
/// # }
/// ```
pub fn build_transaction(
    inputs: &[TxInput],
    outputs: &[TxOutput],
    privkey: &[u8],
) -> Result<BuiltTx, PaymentError> {
    if inputs.is_empty() {
        return Err(invalid("transaction has no inputs"));
    }

    // ── Effective signing scalar (token.js:118-129) ──
    let untweaked_spk = p2tr_script(&xonly_of(privkey)?)?; // 5120<internal xonly>
    let needs_tweak = inputs[0].script_pubkey != untweaked_spk;
    let signing_secret = keypath_signing_secret(privkey, needs_tweak)?;
    let secp = Secp256k1::signing_only();
    let signing_xonly = Keypair::from_seckey_slice(&secp, &signing_secret)
        .map_err(|e| invalid(format!("invalid signing scalar: {e}")))?
        .x_only_public_key()
        .0
        .serialize();

    // ── Unsigned transaction (token.js:131-144) ──
    let mut tx_inputs = Vec::with_capacity(inputs.len());
    let mut spent = Vec::with_capacity(inputs.len());
    for i in inputs {
        let txid = Txid::from_str(&i.txid).map_err(|e| invalid(format!("bad txid hex: {e}")))?;
        tx_inputs.push(TxIn {
            previous_output: OutPoint::new(txid, i.vout),
            script_sig: ScriptBuf::new(),
            sequence: INPUT_SEQUENCE,
            witness: Witness::new(),
        });
        spent.push(TxOut {
            value: amount(i.amount)?,
            script_pubkey: ScriptBuf::from_bytes(i.script_pubkey.clone()),
        });
    }
    let tx_outputs = outputs
        .iter()
        .map(|o| {
            Ok(TxOut {
                value: amount(o.amount)?,
                script_pubkey: ScriptBuf::from_bytes(o.script_pubkey.clone()),
            })
        })
        .collect::<Result<Vec<_>, PaymentError>>()?;
    let mut tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: tx_inputs,
        output: tx_outputs,
    };
    // With every witness empty this is the legacy (witness-stripped) encoding.
    let unsigned_hex = serialize_hex(&tx);

    // ── Per-input BIP-341 sighash + BIP-340 sign (token.js:146-157) ──
    let prevouts = Prevouts::All(&spent);
    let mut sighashes = Vec::with_capacity(inputs.len());
    let mut signatures = Vec::with_capacity(inputs.len());
    {
        let mut cache = SighashCache::new(&tx);
        for index in 0..inputs.len() {
            let sighash = cache
                .taproot_key_spend_signature_hash(index, &prevouts, TapSighashType::Default)
                .map_err(|e| invalid(format!("taproot sighash: {e}")))?
                .to_byte_array();
            signatures.push(schnorr_sign_zero_aux(&signing_secret, &sighash)?);
            sighashes.push(sighash);
        }
    }

    // ── Witnesses: one 64-byte SIGHASH_DEFAULT signature each (token.js:159-173) ──
    for (txin, sig) in tx.input.iter_mut().zip(&signatures) {
        let signature = schnorr::Signature::from_slice(sig)
            .map_err(|e| invalid(format!("bad signature: {e}")))?;
        txin.witness = Witness::p2tr_key_spend(&bitcoin::taproot::Signature {
            signature,
            sighash_type: TapSighashType::Default,
        });
    }

    Ok(BuiltTx {
        txid: tx.compute_txid().to_string(),
        raw_hex: serialize_hex(&tx),
        unsigned_hex,
        sighashes: sighashes.iter().map(hex::encode).collect(),
        signatures: signatures.iter().map(hex::encode).collect(),
        signing_xonly: hex::encode(signing_xonly),
    })
}

/// A sats amount, checked against the Bitcoin money range.
fn amount(sats: u64) -> Result<Amount, PaymentError> {
    let a = Amount::from_sat(sats);
    if a > Amount::MAX_MONEY {
        return Err(invalid(format!("{sats} sats exceeds the money range")));
    }
    Ok(a)
}

/// Verify a 64-byte key-path Schnorr signature against an x-only pubkey and a
/// 32-byte TapSighash — the offline correctness gate ("every signature our
/// builder produces must verify"). BIP-340 verification by libsecp256k1.
///
/// Returns `Ok(false)` for a well-formed signature that does not verify, and
/// an error when any argument is malformed: bad hex, a key that is not a
/// valid x-only point, a sighash that is not 32 bytes, or a signature that is
/// not 64 bytes.
pub fn verify_keypath_signature(
    xonly_hex: &str,
    sighash_hex: &str,
    sig_hex: &str,
) -> Result<bool, PaymentError> {
    let xonly = hex::decode(xonly_hex).map_err(|e| invalid(format!("bad xonly hex: {e}")))?;
    let sighash = hex::decode(sighash_hex).map_err(|e| invalid(format!("bad sighash hex: {e}")))?;
    let sig_bytes = hex::decode(sig_hex).map_err(|e| invalid(format!("bad sig hex: {e}")))?;
    let key = parse_xonly(&xonly)?;
    let msg = Message::from_digest_slice(&sighash)
        .map_err(|e| invalid(format!("sighash must be 32 bytes: {e}")))?;
    let sig = schnorr::Signature::from_slice(&sig_bytes)
        .map_err(|e| invalid(format!("bad signature: {e}")))?;
    Ok(Secp256k1::verification_only()
        .verify_schnorr(&sig, &msg, &key)
        .is_ok())
}

// ── TXO voucher parsing (token.js:226-236) ──────────────────────────────

/// A parsed TXO **voucher** — a self-contained spendable output carrying the
/// private key that controls it. This is the JSS `parseTxoUri` form
/// (`token.js:226-236`): `txo:<chain>:<txid>:<vout>?amount=<sats>&key=<hex>`.
///
/// This is intentionally distinct from [`crate::payments::TxoDeposit`]
/// (`payments::parse_txo_uri`), which parses a bare *output reference*
/// (`txid:vout`, no key). A voucher additionally carries the spending
/// `privkey` + `amount` and is what mint / withdraw-sats consume. The two are different concepts; keeping the names distinct avoids
/// a same-name/different-shape collision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxoVoucher {
    /// Funding txid (64-char hex).
    pub txid: String,
    /// Output index within `txid`.
    pub vout: u32,
    /// Output value in sats.
    pub amount: u64,
    /// 32-byte private key (64-char hex) controlling the output.
    pub privkey: String,
}

/// Parse a TXO voucher URI (JSS `token.js:226-236`). Accepts an optional
/// `txo:<chain>:` prefix; the chain segment is ignored (the explorer is
/// chosen separately), matching the JSS regex which captures only
/// `txid:vout?amount=…&key=…`.
pub fn parse_txo_voucher(uri: &str) -> Result<TxoVoucher, PaymentError> {
    let s = uri.trim();
    // Strip an optional `txo:<chain>:` prefix down to `…txid:vout?...`.
    // JSS regex: /(?:txo:btc:)?([0-9a-f]{64}):(\d+)\?amount=(\d+)&key=([0-9a-f]{64})/i
    // We accept any chain token (not just `btc`) to match the broader
    // `txo:<chain>:` forms produced by withdraw-sats (`txo:tbtc4:…`).
    let body = if let Some(rest) = s.strip_prefix("txo:") {
        // rest = "<chain>:<txid>:<vout>?..."; drop the chain segment.
        match rest.split_once(':') {
            Some((_chain, after)) => after,
            None => rest,
        }
    } else {
        s
    };

    let (txid, tail) = body
        .split_once(':')
        .ok_or_else(|| PaymentError::InvalidTxo("voucher: missing ':vout'".into()))?;
    let (vout_str, query) = tail
        .split_once('?')
        .ok_or_else(|| PaymentError::InvalidTxo("voucher: missing '?amount='".into()))?;

    if txid.len() != 64 || !txid.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(PaymentError::InvalidTxo(
            "voucher: txid must be 64 hex chars".into(),
        ));
    }
    let vout: u32 = vout_str
        .parse()
        .map_err(|_| PaymentError::InvalidTxo("voucher: bad vout".into()))?;

    let mut amount: Option<u64> = None;
    let mut privkey: Option<String> = None;
    for kv in query.split('&') {
        if let Some(v) = kv.strip_prefix("amount=") {
            amount = Some(
                v.parse()
                    .map_err(|_| PaymentError::InvalidTxo("voucher: bad amount".into()))?,
            );
        } else if let Some(v) = kv.strip_prefix("key=") {
            if v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(PaymentError::InvalidTxo(
                    "voucher: key must be 64 hex chars".into(),
                ));
            }
            privkey = Some(v.to_string());
        }
    }

    Ok(TxoVoucher {
        txid: txid.to_string(),
        vout,
        amount: amount.ok_or_else(|| PaymentError::InvalidTxo("voucher: missing amount".into()))?,
        privkey: privkey.ok_or_else(|| PaymentError::InvalidTxo("voucher: missing key".into()))?,
    })
}

// ── Mempool broadcast abstraction (token.js:176-187) ────────────────────

/// Broadcast a raw transaction to a Bitcoin mempool, returning the txid.
///
/// Pure abstraction mirroring Phase 3's [`MempoolLookup`]: the trait drags in
/// no I/O and is `?Send`, so it compiles to wasm and a single-threaded
/// executor can implement it. The concrete `reqwest`-backed implementation
/// (POST `{base}/api/tx`, JSS `token.js:176-187`) lives server-side in
/// `solid-pod-rs-server::mempool::MempoolHttpClient`. A fixture HTTP origin
/// (or an in-memory stub) drives it in tests — never a live network in CI.
#[async_trait::async_trait(?Send)]
pub trait MempoolBroadcast {
    /// POST `raw_hex` to the mempool's broadcast endpoint; return the txid.
    async fn broadcast_tx(&self, raw_hex: &str) -> Result<String, PaymentError>;
}

// ── High-level composers: mint / transfer / anchor ──────────────────────

/// Outcome of a mint or transfer: the broadcastable tx plus the updated trail
/// and the new state / derived address (JSS `token.js` mint/transfer returns).
#[derive(Debug, Clone)]
pub struct TrailUpdate {
    /// The fully-built, signed transaction.
    pub tx: BuiltTx,
    /// The new trail (genesis trail for mint; appended trail for transfer).
    pub trail: Mrc20Trail,
    /// The state appended in this operation (genesis state for mint).
    pub state: Mrc20State,
    /// JCS of `state`.
    pub state_jcs: String,
    /// The taproot address the new UTXO pays (the next chained-key address).
    pub address: String,
    /// The transaction's single output amount (sats).
    pub output_amount: u64,
}

/// Mint a genesis MRC20 token (JSS `token.js:239-307`).
///
/// Builds the genesis state, JCS-canonicalises it, derives the genesis
/// chained-key taproot output script + address (reusing `mrc20.rs`), fetches
/// the voucher's `scriptPubKey` via the injected [`MempoolLookup`], builds the
/// genesis tx spending the voucher into the genesis output, and returns the
/// raw tx + the freshly-created trail. **Broadcast is the caller's**: the raw
/// tx and the trail are returned so the route can broadcast then persist (the
/// server route wires [`MempoolBroadcast`]).
///
/// `pubkey_base_hex` is the voucher key's compressed pubkey (the issuer
/// identity); balances are keyed on it (`token.js:258`).
pub async fn mint_token(
    ticker: &str,
    name: Option<&str>,
    supply: u64,
    voucher: &TxoVoucher,
    network: &str,
    fee_sats: u64,
    mempool: &dyn MempoolLookup,
) -> Result<TrailUpdate, PaymentError> {
    let privkey = hex::decode(&voucher.privkey)
        .map_err(|e| PaymentError::InvalidState(format!("bad voucher key: {e}")))?;
    let sk = parse_secret(&privkey)?;
    let pubkey_base_hex = hex::encode(sk.public_key(&Secp256k1::signing_only()).serialize());

    // Genesis MRC20 state (token.js:250-260).
    let mut balances = std::collections::BTreeMap::new();
    balances.insert(pubkey_base_hex.clone(), supply);
    let genesis = Mrc20State {
        profile: MRC20_PROFILE.into(),
        prev: "0".repeat(64),
        seq: 0,
        ticker: Some(ticker.to_string()),
        name: Some(name.unwrap_or(ticker).to_string()),
        decimals: Some(0),
        supply: Some(supply),
        balances: Some(balances),
        ops: vec![],
        anchor: None,
    };
    let genesis_jcs = jcs(&serde_json::to_value(&genesis).map_err(serde_err)?);

    // Derive genesis chained-key output script + address (token.js:264-267).
    let genesis_strings = std::slice::from_ref(&genesis_jcs);
    let genesis_xonly = chained_xonly(&pubkey_base_hex, genesis_strings)?;
    let genesis_script = p2tr_script(&genesis_xonly)?;
    let genesis_addr = bt_address(&pubkey_base_hex, genesis_strings, network)?;

    // Fetch the voucher's scriptPubKey (token.js:270-275).
    let script_pubkey = fetch_output_spk(mempool, &voucher.txid, voucher.vout).await?;

    // Build the genesis tx (token.js:278-286).
    let output_amount = checked_output(voucher.amount, fee_sats)?;
    let tx = build_transaction(
        &[TxInput {
            txid: voucher.txid.clone(),
            vout: voucher.vout,
            amount: voucher.amount,
            script_pubkey,
        }],
        &[TxOutput {
            amount: output_amount,
            script_pubkey: genesis_script,
        }],
        &privkey,
    )?;

    // The trail's currentTxid is filled by the caller after broadcast; we
    // return the tx + trail skeleton (token.js:290-303) and let the route set
    // currentTxid from the broadcast result (it equals the tx's own txid).
    let trail = Mrc20Trail {
        ticker: ticker.to_string(),
        name: name.unwrap_or(ticker).to_string(),
        supply,
        pubkey_base: pubkey_base_hex,
        states: vec![genesis.clone()],
        state_strings: vec![genesis_jcs.clone()],
        current_txid: String::new(), // set post-broadcast
        current_vout: 0,
        current_amount: output_amount,
        network: network.to_string(),
        date_created: String::new(), // set by caller (wasm-safe: no chrono here)
    };

    Ok(TrailUpdate {
        tx,
        trail,
        state: genesis,
        state_jcs: genesis_jcs,
        address: genesis_addr,
        output_amount,
    })
}

/// Transfer tokens within an existing trail (JSS `token.js:310-389`).
///
/// Computes the new balance map, builds the transfer state (hash-chained to
/// the current state), derives the next chained-key output + address, fetches
/// the current UTXO's `scriptPubKey`, derives the chained **private** key for
/// signing (reusing `mrc20.rs`), and builds the transfer tx spending the
/// current UTXO into the new output. Returns the raw tx + the appended trail.
/// Broadcast + `currentTxid` update are the caller's.
///
/// `from` defaults to the issuer (`trail.pubkey_base`) when `None`
/// (`token.js:322`).
///
/// The issuer's signing key is taken explicitly (`issuer_privkey_hex`) because
/// the public [`Mrc20Trail`] type deliberately does **not** carry the privkey
/// in memory — the server's trail file (`trail_store.rs`) holds it and supplies
/// it here. (JSS's `transferToken` reads `trail.privkey` straight off the
/// persisted JSON; we keep that secret off the shared type.)
pub async fn transfer_token_with_key(
    trail: &Mrc20Trail,
    issuer_privkey_hex: &str,
    from: Option<&str>,
    to: &str,
    amount: u64,
    fee_sats: u64,
    mempool: &dyn MempoolLookup,
) -> Result<TrailUpdate, PaymentError> {
    let current_state = trail
        .states
        .last()
        .ok_or_else(|| PaymentError::InvalidState("trail has no states".into()))?;
    let mut balances = current_state.balances.clone().unwrap_or_default();

    let sender = from.unwrap_or(&trail.pubkey_base).to_string();
    let sender_balance = balances.get(&sender).copied().unwrap_or(0);
    if sender_balance < amount {
        return Err(PaymentError::InsufficientBalance {
            balance: sender_balance,
            cost: amount,
        });
    }
    balances.insert(sender.clone(), sender_balance - amount);
    let to_balance = balances.get(to).copied().unwrap_or(0);
    balances.insert(to.to_string(), to_balance + amount);
    balances.retain(|_, v| *v != 0);

    let prev_jcs = trail
        .state_strings
        .last()
        .ok_or_else(|| PaymentError::InvalidState("trail has no state strings".into()))?;
    let new_state = Mrc20State {
        profile: MRC20_PROFILE.into(),
        prev: sha256_hex(prev_jcs),
        seq: current_state.seq + 1,
        ticker: trail.states.first().and_then(|s| s.ticker.clone()),
        name: Some(trail.name.clone()),
        decimals: Some(0),
        supply: Some(trail.supply),
        balances: Some(balances),
        ops: vec![Mrc20Op {
            op: TRANSFER_OP.into(),
            from: Some(sender),
            to: Some(to.to_string()),
            amt: Some(amount),
        }],
        anchor: None,
    };
    let new_jcs = jcs(&serde_json::to_value(&new_state).map_err(serde_err)?);

    let mut all_strings = trail.state_strings.clone();
    all_strings.push(new_jcs.clone());
    let new_xonly = chained_xonly(&trail.pubkey_base, &all_strings)?;
    let new_script = p2tr_script(&new_xonly)?;
    let new_addr = bt_address(&trail.pubkey_base, &all_strings, &trail.network)?;

    let script_pubkey = fetch_output_spk(mempool, &trail.current_txid, trail.current_vout).await?;

    // Chained privkey controlling the *current* UTXO chains over the strings
    // BEFORE the new state (token.js:366).
    let chained_priv = bt_derive_chained_privkey(issuer_privkey_hex, &trail.state_strings)?;

    let output_amount = checked_output(trail.current_amount, fee_sats)?;
    let tx = build_transaction(
        &[TxInput {
            txid: trail.current_txid.clone(),
            vout: trail.current_vout,
            amount: trail.current_amount,
            script_pubkey,
        }],
        &[TxOutput {
            amount: output_amount,
            script_pubkey: new_script,
        }],
        &chained_priv,
    )?;

    // Append to the trail (token.js:381-385). currentTxid set post-broadcast.
    let mut updated = trail.clone();
    updated.states.push(new_state.clone());
    updated.state_strings.push(new_jcs.clone());
    updated.current_txid = String::new();
    updated.current_vout = 0;
    updated.current_amount = output_amount;

    Ok(TrailUpdate {
        tx,
        trail: updated,
        state: new_state,
        state_jcs: new_jcs,
        address: new_addr,
        output_amount,
    })
}

/// Append a single MRC20 state that anchors `state_hash` and build the
/// anchoring tx. This is the provenance-primitive write the design hinges on
/// (`BlockAnchorer::anchor`): unlike a token transfer it carries no balance
/// change — its `ops` record an anchor op binding `state_hash` (a git commit
/// SHA or an epoch Merkle root) into the trail, and the new chained-key UTXO
/// externally timestamps it on Bitcoin.
///
/// Returns the built tx + the appended trail + the derived address. The server
/// `BlockAnchorer::anchor` broadcasts the tx, sets `current_txid`, and returns
/// a `BlockTrailAnchor`.
pub async fn anchor_state(
    trail: &Mrc20Trail,
    issuer_privkey_hex: &str,
    state_hash: &str,
    fee_sats: u64,
    mempool: &dyn MempoolLookup,
) -> Result<TrailUpdate, PaymentError> {
    let current_state = trail
        .states
        .last()
        .ok_or_else(|| PaymentError::InvalidState("trail has no states".into()))?;

    let prev_jcs = trail
        .state_strings
        .last()
        .ok_or_else(|| PaymentError::InvalidState("trail has no state strings".into()))?;

    // Anchor state: balances carried forward unchanged, a single anchor op
    // binding `state_hash`, and the `anchor` field set to `state_hash` so the
    // portable proof self-describes what was notarised.
    let new_state = Mrc20State {
        profile: MRC20_PROFILE.into(),
        prev: sha256_hex(prev_jcs),
        seq: current_state.seq + 1,
        ticker: trail.states.first().and_then(|s| s.ticker.clone()),
        name: Some(trail.name.clone()),
        decimals: Some(0),
        supply: Some(trail.supply),
        balances: current_state.balances.clone(),
        ops: vec![Mrc20Op {
            op: "urn:mono:op:anchor".into(),
            from: None,
            to: None,
            amt: None,
        }],
        anchor: Some(state_hash.to_string()),
    };
    let new_jcs = jcs(&serde_json::to_value(&new_state).map_err(serde_err)?);

    let mut all_strings = trail.state_strings.clone();
    all_strings.push(new_jcs.clone());
    let new_xonly = chained_xonly(&trail.pubkey_base, &all_strings)?;
    let new_script = p2tr_script(&new_xonly)?;
    let new_addr = bt_address(&trail.pubkey_base, &all_strings, &trail.network)?;

    let script_pubkey = fetch_output_spk(mempool, &trail.current_txid, trail.current_vout).await?;
    let chained_priv = bt_derive_chained_privkey(issuer_privkey_hex, &trail.state_strings)?;

    let output_amount = checked_output(trail.current_amount, fee_sats)?;
    let tx = build_transaction(
        &[TxInput {
            txid: trail.current_txid.clone(),
            vout: trail.current_vout,
            amount: trail.current_amount,
            script_pubkey,
        }],
        &[TxOutput {
            amount: output_amount,
            script_pubkey: new_script,
        }],
        &chained_priv,
    )?;

    let mut updated = trail.clone();
    updated.states.push(new_state.clone());
    updated.state_strings.push(new_jcs.clone());
    updated.current_txid = String::new();
    updated.current_vout = 0;
    updated.current_amount = output_amount;

    Ok(TrailUpdate {
        tx,
        trail: updated,
        state: new_state,
        state_jcs: new_jcs,
        address: new_addr,
        output_amount,
    })
}

// ── git-mark trails (blocktrails/git-mark b852d7d) ──────────────────────

/// Outcome of a git-mark genesis or advance: the transaction to broadcast and
/// the trail with its new mark.
#[derive(Debug, Clone)]
pub struct GitmarkUpdate {
    /// The signed transaction creating the new mark.
    pub tx: BuiltTx,
    /// The trail with the new commit and mark appended (its `txo` entry names
    /// [`BuiltTx::txid`]).
    pub trail: Blocktrail,
    /// The new mark.
    pub txo: BlocktrailTxo,
    /// The new mark's address on the trail's network.
    pub address: String,
    /// The new mark's value in sats.
    pub output_amount: u64,
}

fn check_commit(commit: &str) -> Result<(), PaymentError> {
    if is_gitmark_commit(commit) {
        Ok(())
    } else {
        Err(invalid(
            "a git-mark state is a commit hash: 40 (or 64) lowercase hex characters",
        ))
    }
}

/// Start a git-mark trail: spend `voucher` to the first mark, the voucher
/// key's point tweaked by `commit` (blocktrails/git-mark b852d7d `genesis`).
///
/// The voucher's key is the trail's base key: its full compressed point is the
/// trail's `pubkeyBase`, and it is never an output itself. The genesis mark
/// carries the first commit, as git-mark's does; the state is the commit as
/// text, with no MRC20 wrapper. `network` is this crate's network name
/// (`testnet4`, `mainnet`, `gitmark`, …); the trail records the matching TXO
/// chain token ([`txo_chain_for_network`]). Broadcasting is the caller's.
///
/// # Errors
///
/// [`PaymentError::InvalidState`] for a commit that is not 40 (or 64)
/// lowercase hex, a bad voucher key, an unreadable voucher output, or a
/// voucher too small for the fee.
pub async fn gitmark_genesis(
    voucher: &TxoVoucher,
    commit: &str,
    network: &str,
    fee_sats: u64,
    mempool: &dyn MempoolLookup,
) -> Result<GitmarkUpdate, PaymentError> {
    check_commit(commit)?;
    let privkey = hex::decode(&voucher.privkey)
        .map_err(|e| PaymentError::InvalidState(format!("bad voucher key: {e}")))?;
    let sk = parse_secret(&privkey)?;
    let base = hex::encode(sk.public_key(&Secp256k1::signing_only()).serialize());
    let commits = vec![commit.to_string()];

    let script_pubkey = fetch_output_spk(mempool, &voucher.txid, voucher.vout).await?;
    let output_amount = checked_output(voucher.amount, fee_sats)?;
    let tx = build_transaction(
        &[TxInput {
            txid: voucher.txid.clone(),
            vout: voucher.vout,
            amount: voucher.amount,
            script_pubkey,
        }],
        &[TxOutput {
            amount: output_amount,
            script_pubkey: p2tr_script(&chained_xonly(&base, &commits)?)?,
        }],
        &privkey,
    )?;

    let chain = txo_chain_for_network(network);
    let txo = BlocktrailTxo::new(chain.clone(), tx.txid.clone(), 0)
        .with_amount(output_amount)
        .with_commit(commit);
    Ok(GitmarkUpdate {
        address: bt_address(&base, &commits, network)?,
        trail: Blocktrail::gitmark(base, chain, commits, vec![txo.clone()]),
        txo,
        tx,
        output_amount,
    })
}

/// Advance a git-mark trail by one commit: spend its newest mark to the next
/// one, `P' = P + TapTweak(x(P) || sha256(commit as text))·G` on the full point
/// (blocktrails/git-mark b852d7d `advance`).
///
/// `privkey_hex` is the base key's secret, the one whose point is the trail's
/// `pubkeyBase`; the newest mark is spent with that secret plus every tweak so
/// far. Before building anything the newest mark's output on-chain is checked
/// against the key the trail's states derive, so a trail that does not commit
/// to its own states is never extended. The new mark pays to output 0 and
/// carries `commit`; broadcasting is the caller's.
///
/// # Errors
///
/// [`PaymentError::InvalidState`] for a bad commit, a trail with no base key,
/// no marks, or states that do not match its marks, a secret that is not the
/// base key's, a newest mark whose output is not the derived key, or an
/// output too small for the fee.
pub async fn gitmark_advance(
    trail: &Blocktrail,
    privkey_hex: &str,
    commit: &str,
    fee_sats: u64,
    mempool: &dyn MempoolLookup,
) -> Result<GitmarkUpdate, PaymentError> {
    check_commit(commit)?;
    let base = trail
        .pubkey_base
        .as_deref()
        .ok_or_else(|| invalid("the trail has no base key (pubkeyBase)"))?;
    let base_point = bt_base_point(base)?;
    let privkey = hex::decode(privkey_hex).map_err(|e| invalid(format!("bad privkey hex: {e}")))?;
    let own = parse_secret(&privkey)?
        .public_key(&Secp256k1::signing_only())
        .serialize();
    if own != base_point {
        return Err(invalid("the secret is not the trail's base key"));
    }
    let head = trail
        .txo
        .last()
        .ok_or_else(|| invalid("the trail has no marks: start it with gitmark_genesis"))?;
    let commits = trail.state_strings().map_err(invalid)?;
    let chain = trail
        .chain
        .clone()
        .or_else(|| head.chain.clone())
        .ok_or_else(|| invalid("the trail names no chain"))?;
    let network = network_for_txo_chain(&chain);

    // The newest mark must be the key the states so far derive.
    let script_pubkey = fetch_output_spk(mempool, &head.txid, head.vout).await?;
    if script_pubkey != p2tr_script(&chained_xonly(base, &commits)?)? {
        return Err(invalid(format!(
            "mark {} ({}) is not the key the trail's states derive: refusing to extend it",
            commits.len() - 1,
            head.outpoint()
        )));
    }
    let input_amount = match head.amount {
        Some(a) => a,
        None => mempool
            .tx(&head.txid)
            .await?
            .vout
            .get(head.vout as usize)
            .map(|o| o.value)
            .ok_or_else(|| invalid(format!("output {} not found", head.outpoint())))?,
    };

    let mut next = commits.clone();
    next.push(commit.to_string());
    let output_amount = checked_output(input_amount, fee_sats)?;
    let tx = build_transaction(
        &[TxInput {
            txid: head.txid.clone(),
            vout: head.vout,
            amount: input_amount,
            script_pubkey,
        }],
        &[TxOutput {
            amount: output_amount,
            script_pubkey: p2tr_script(&chained_xonly(base, &next)?)?,
        }],
        &bt_derive_chained_privkey(privkey_hex, &commits)?,
    )?;

    let txo = BlocktrailTxo::new(chain, tx.txid.clone(), 0)
        .with_amount(output_amount)
        .with_commit(commit);
    let mut updated = trail.clone();
    // A trail that listed no states took them from its marks: write them out.
    updated.states = next
        .iter()
        .cloned()
        .map(serde_json::Value::String)
        .collect();
    updated.txo.push(txo.clone());
    Ok(GitmarkUpdate {
        address: bt_address(base, &next, &network)?,
        trail: updated,
        txo,
        tx,
        output_amount,
    })
}

/// Read a raw transaction (hex, as [`BuiltTx::raw_hex`] or a node gives it)
/// into the [`TxInfo`] view a [`MempoolLookup`] returns, unconfirmed.
///
/// For an in-memory chain (tests, an offline verifier fed raw transactions):
/// the txid, every input's spent outpoint and every output's value and
/// `scriptPubKey`, decoded by rust-bitcoin.
///
/// # Errors
///
/// [`PaymentError::InvalidState`] when the hex is not a transaction.
pub fn decode_tx_info(raw_hex: &str) -> Result<TxInfo, PaymentError> {
    let bytes = hex::decode(raw_hex).map_err(|e| invalid(format!("bad tx hex: {e}")))?;
    let tx: Transaction = bitcoin::consensus::deserialize(&bytes)
        .map_err(|e| invalid(format!("not a transaction: {e}")))?;
    Ok(TxInfo {
        txid: tx.compute_txid().to_string(),
        vin: tx
            .input
            .iter()
            .map(|i| TxInView {
                txid: i.previous_output.txid.to_string(),
                vout: i.previous_output.vout,
            })
            .collect(),
        vout: tx
            .output
            .iter()
            .map(|o| TxOutView {
                value: o.value.to_sat(),
                scriptpubkey: Some(hex::encode(o.script_pubkey.as_bytes())),
                scriptpubkey_address: None,
            })
            .collect(),
        confirmed: false,
        block_height: None,
    })
}

// ── internal helpers ────────────────────────────────────────────────────

fn serde_err(e: serde_json::Error) -> PaymentError {
    PaymentError::InvalidState(format!("serialize: {e}"))
}

/// Derive the x-only pubkey at the end of a chained-key derivation (reuses
/// `mrc20::bt_derive_chained_pubkey`, then drops the compressed prefix byte).
fn chained_xonly(
    pubkey_base_hex: &str,
    state_strings: &[String],
) -> Result<[u8; 32], PaymentError> {
    let chained = bt_derive_chained_pubkey(pubkey_base_hex, state_strings)?;
    if chained.len() != 33 {
        return Err(PaymentError::InvalidState(format!(
            "expected 33-byte compressed chained key, got {}",
            chained.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&chained[1..]);
    Ok(out)
}

/// `voucher.amount - fee`, rejecting dust (token.js:279-280,370-371).
fn checked_output(input_amount: u64, fee_sats: u64) -> Result<u64, PaymentError> {
    let out = input_amount
        .checked_sub(fee_sats)
        .ok_or_else(|| PaymentError::InvalidState("input too small for fee".into()))?;
    if out <= DUST_LIMIT_SATS {
        return Err(PaymentError::InvalidState(format!(
            "output {out} at/below dust limit {DUST_LIMIT_SATS}"
        )));
    }
    Ok(out)
}

/// Fetch the `scriptPubKey` bytes of output `vout` of transaction `txid`
/// through a [`MempoolLookup`] (token.js:270-275,358-363).
async fn fetch_output_spk(
    mempool: &dyn MempoolLookup,
    txid: &str,
    vout: u32,
) -> Result<Vec<u8>, PaymentError> {
    let tx = mempool.tx(txid).await?;
    let out = tx
        .vout
        .get(vout as usize)
        .ok_or_else(|| PaymentError::InvalidState(format!("output {vout} not found in {txid}")))?;
    let spk_hex = out
        .scriptpubkey
        .as_ref()
        .ok_or_else(|| PaymentError::InvalidState("output missing scriptpubkey".into()))?;
    hex::decode(spk_hex)
        .map_err(|e| PaymentError::InvalidState(format!("bad scriptpubkey hex: {e}")))
}

/// Result of [`build_withdraw_voucher`]: the broadcastable tx plus the
/// freshly-minted voucher URI controlling the withdrawn output.
#[derive(Debug, Clone)]
pub struct WithdrawVoucher {
    /// The signed, broadcastable transaction.
    pub tx: BuiltTx,
    /// `txo:<chain>:<txid placeholder>:0?amount=<sats>&key=<hex>` — the txid is
    /// filled by the caller after broadcast (the voucher pays output 0).
    pub voucher_privkey_hex: String,
    /// The withdrawn amount (sats) the voucher's output carries.
    pub amount: u64,
    /// Change amount paid back to the funding key (0 when below dust).
    pub change: u64,
}

/// Build a withdraw-sats voucher tx (JSS `pay.js:842-892`, `token.js`): spend
/// the `funding` voucher into (a) a fresh-key voucher output paying `amount`
/// and (b) change back to the funding key. Returns the signed tx + the fresh
/// voucher private key; the caller broadcasts and assembles the
/// `txo:<chain>:<txid>:0?amount=…&key=…` URI from the broadcast txid.
///
/// `funding_spk_hex` is the funding output's `scriptPubKey` hex (fetched via
/// the mempool by the caller). The fresh voucher key is generated with the OS
/// RNG.
pub fn build_withdraw_voucher(
    funding: &TxoVoucher,
    funding_spk_hex: &str,
    amount: u64,
    fee_sats: u64,
) -> Result<WithdrawVoucher, PaymentError> {
    let funding_spk = hex::decode(funding_spk_hex)
        .map_err(|e| PaymentError::InvalidState(format!("bad funding scriptPubKey hex: {e}")))?;
    let needed = amount
        .checked_add(fee_sats)
        .ok_or_else(|| PaymentError::InvalidState("amount + fee overflow".into()))?;
    if funding.amount < needed {
        return Err(PaymentError::InvalidState(format!(
            "funding {} < needed {needed}",
            funding.amount
        )));
    }

    // Fresh voucher recipient key (JSS `pay.js:848-851`).
    let voucher_sk = SecretKey::new(&mut rand::thread_rng());
    let voucher_priv_hex = hex::encode(voucher_sk.secret_bytes());
    let voucher_xonly = xonly_of(&voucher_sk.secret_bytes())?;
    let voucher_script = p2tr_script(&voucher_xonly)?;

    // Change back to the funding key (JSS `pay.js:854-859`).
    let funding_privkey = hex::decode(&funding.privkey)
        .map_err(|e| PaymentError::InvalidTxo(format!("bad funding key: {e}")))?;
    let funding_xonly = xonly_of(&funding_privkey)?;

    let mut outputs = vec![TxOutput {
        amount,
        script_pubkey: voucher_script,
    }];
    let change = funding.amount - amount - fee_sats;
    if change > DUST_LIMIT_SATS {
        outputs.push(TxOutput {
            amount: change,
            script_pubkey: p2tr_script(&funding_xonly)?,
        });
    }

    let tx = build_transaction(
        &[TxInput {
            txid: funding.txid.clone(),
            vout: funding.vout,
            amount: funding.amount,
            script_pubkey: funding_spk,
        }],
        &outputs,
        &funding_privkey,
    )?;

    Ok(WithdrawVoucher {
        tx,
        voucher_privkey_hex: voucher_priv_hex,
        amount,
        change: if change > DUST_LIMIT_SATS { change } else { 0 },
    })
}

/// Build the proof JSON a route returns alongside a transfer/anchor — the
/// portable, independently-verifiable anchor (JSS `pay.js:647-656`).
pub fn anchor_proof_json(trail: &Mrc20Trail) -> serde_json::Value {
    json!({
        "pubkey": trail.pubkey_base,
        "stateStrings": trail.state_strings,
        "network": trail.network,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── golden fixture (generated by /tmp/gen_golden.mjs via @noble, aux=0) ──
    const GOLDEN: &str = include_str!("../tests/fixtures/bitcoin/golden_tx.json");

    fn golden() -> serde_json::Value {
        serde_json::from_str(GOLDEN).unwrap()
    }

    // ── p2tr_script ──────────────────────────────────────────────────────

    #[test]
    fn p2tr_script_shape() {
        // x of the generator G.
        let xonly: [u8; 32] =
            hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap()
                .try_into()
                .unwrap();
        let s = p2tr_script(&xonly).unwrap();
        assert_eq!(s.len(), 34);
        assert_eq!(s[0], 0x51);
        assert_eq!(s[1], 0x20);
        assert_eq!(&s[2..], &xonly);
    }

    #[test]
    fn p2tr_script_rejects_wrong_length() {
        assert!(p2tr_script(&[0u8; 31]).is_err());
        assert!(p2tr_script(&[0u8; 33]).is_err());
    }

    // ── CROSS-IMPL GOLDEN: case A (untweaked MRC20 chained-key spend) ─────

    #[test]
    fn golden_case_a_full_hex_matches_jss() {
        let g = golden();
        let a = &g["caseA"];
        let input = TxInput {
            txid: a["input"]["txid"].as_str().unwrap().into(),
            vout: a["input"]["vout"].as_u64().unwrap() as u32,
            amount: a["input"]["amount"].as_u64().unwrap(),
            script_pubkey: hex::decode(a["input"]["scriptPubKey"].as_str().unwrap()).unwrap(),
        };
        let output = TxOutput {
            amount: a["output"]["amount"].as_u64().unwrap(),
            script_pubkey: hex::decode(a["output"]["scriptPubKey"].as_str().unwrap()).unwrap(),
        };
        let privkey = hex::decode(a["priv"].as_str().unwrap()).unwrap();
        let built = build_transaction(&[input], &[output], &privkey).unwrap();

        // The strongest check: deterministic full hex matches JSS byte-for-byte.
        assert_eq!(
            built.raw_hex,
            a["raw"].as_str().unwrap(),
            "case A raw tx hex must match JSS token.js (aux_rand=0)"
        );
        assert_eq!(built.sighashes[0], a["sighashes"][0].as_str().unwrap());
        assert_eq!(built.signatures[0], a["sigs"][0].as_str().unwrap());
        assert_eq!(built.unsigned_hex, a["unsigned"].as_str().unwrap());
    }

    // ── CROSS-IMPL GOLDEN: case B (tweaked external voucher) ─────────────

    #[test]
    fn golden_case_b_tweaked_full_hex_matches_jss() {
        let g = golden();
        let b = &g["caseB"];
        let input = TxInput {
            txid: b["input"]["txid"].as_str().unwrap().into(),
            vout: b["input"]["vout"].as_u64().unwrap() as u32,
            amount: b["input"]["amount"].as_u64().unwrap(),
            script_pubkey: hex::decode(b["input"]["scriptPubKey"].as_str().unwrap()).unwrap(),
        };
        let output = TxOutput {
            amount: b["output"]["amount"].as_u64().unwrap(),
            script_pubkey: hex::decode(b["output"]["scriptPubKey"].as_str().unwrap()).unwrap(),
        };
        let privkey = hex::decode(b["priv"].as_str().unwrap()).unwrap();
        let built = build_transaction(&[input], &[output], &privkey).unwrap();

        // The tweak path: signingKey scalar must match JSS, then full hex.
        assert_eq!(
            built.raw_hex,
            b["raw"].as_str().unwrap(),
            "case B (needsTweak) raw tx hex must match JSS"
        );
        assert_eq!(built.sighashes[0], b["sighashes"][0].as_str().unwrap());
        assert_eq!(built.signatures[0], b["sigs"][0].as_str().unwrap());
    }

    // ── CROSS-IMPL GOLDEN: case C (multi-input, withdraw-sats style) ─────

    #[test]
    fn golden_case_c_multi_input_matches_jss() {
        let g = golden();
        let c = &g["caseC"];
        let inputs: Vec<TxInput> = c["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| TxInput {
                txid: i["txid"].as_str().unwrap().into(),
                vout: i["vout"].as_u64().unwrap() as u32,
                amount: i["amount"].as_u64().unwrap(),
                script_pubkey: hex::decode(i["scriptPubKey"].as_str().unwrap()).unwrap(),
            })
            .collect();
        let outputs: Vec<TxOutput> = c["outputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| TxOutput {
                amount: o["amount"].as_u64().unwrap(),
                script_pubkey: hex::decode(o["scriptPubKey"].as_str().unwrap()).unwrap(),
            })
            .collect();
        let privkey = hex::decode(c["priv"].as_str().unwrap()).unwrap();
        let built = build_transaction(&inputs, &outputs, &privkey).unwrap();

        assert_eq!(
            built.raw_hex,
            c["raw"].as_str().unwrap(),
            "case C raw tx hex must match JSS"
        );
        assert_eq!(
            built.sighashes,
            vec![
                c["sighashes"][0].as_str().unwrap().to_string(),
                c["sighashes"][1].as_str().unwrap().to_string(),
            ]
        );
    }

    // ── OFFLINE SIGNATURE VERIFICATION (every sig must verify) ───────────

    #[test]
    fn every_golden_signature_verifies() {
        let g = golden();
        for case in ["caseA", "caseB", "caseC"] {
            let c = &g[case];
            // Rebuild to get our own signing_xonly + sigs, then verify each.
            let (inputs, outputs, privkey) = case_inputs(c);
            let built = build_transaction(&inputs, &outputs, &privkey).unwrap();
            for (i, (sighash, sig)) in built
                .sighashes
                .iter()
                .zip(built.signatures.iter())
                .enumerate()
            {
                assert!(
                    verify_keypath_signature(&built.signing_xonly, sighash, sig).unwrap(),
                    "{case} input {i}: signature must verify against signing_xonly"
                );
            }
        }
    }

    /// Helper: build inputs/outputs/privkey from a golden case (handles both
    /// single-input `input`/`output` and multi `inputs`/`outputs`).
    fn case_inputs(c: &serde_json::Value) -> (Vec<TxInput>, Vec<TxOutput>, Vec<u8>) {
        let privkey = hex::decode(c["priv"].as_str().unwrap()).unwrap();
        let inputs = if let Some(arr) = c["inputs"].as_array() {
            arr.iter()
                .map(|i| TxInput {
                    txid: i["txid"].as_str().unwrap().into(),
                    vout: i["vout"].as_u64().unwrap() as u32,
                    amount: i["amount"].as_u64().unwrap(),
                    script_pubkey: hex::decode(i["scriptPubKey"].as_str().unwrap()).unwrap(),
                })
                .collect()
        } else {
            vec![TxInput {
                txid: c["input"]["txid"].as_str().unwrap().into(),
                vout: c["input"]["vout"].as_u64().unwrap() as u32,
                amount: c["input"]["amount"].as_u64().unwrap(),
                script_pubkey: hex::decode(c["input"]["scriptPubKey"].as_str().unwrap()).unwrap(),
            }]
        };
        let outputs = if let Some(arr) = c["outputs"].as_array() {
            arr.iter()
                .map(|o| TxOutput {
                    amount: o["amount"].as_u64().unwrap(),
                    script_pubkey: hex::decode(o["scriptPubKey"].as_str().unwrap()).unwrap(),
                })
                .collect()
        } else {
            vec![TxOutput {
                amount: c["output"]["amount"].as_u64().unwrap(),
                script_pubkey: hex::decode(c["output"]["scriptPubKey"].as_str().unwrap()).unwrap(),
            }]
        };
        (inputs, outputs, privkey)
    }

    // ── BIP-340 OFFICIAL TEST VECTORS (the whole published CSV) ──────────
    //
    // `tests/fixtures/bitcoin/bip340_test_vectors.csv` is a copy of
    // https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
    // (CRLF line endings normalised to LF; content unchanged).
    // Every row with a secret key must sign byte-for-byte (with the row's
    // aux_rand) and every row must verify or fail exactly as published. Rows
    // 15-18 use non-32-byte messages; a key-path sighash is always 32 bytes,
    // so the key-path verifier is checked on rows 0-14 only.

    const BIP340_CSV: &str = include_str!("../tests/fixtures/bitcoin/bip340_test_vectors.csv");

    #[test]
    fn bip340_official_vectors_sign_and_verify() {
        let mut signed = 0;
        let mut checked = 0;
        for line in BIP340_CSV.lines().skip(1) {
            let f: Vec<&str> = line.split(',').collect();
            let (idx, sk, pk, aux, msg, sig, ok) = (f[0], f[1], f[2], f[3], f[4], f[5], f[6]);
            if msg.len() != 64 {
                continue;
            }
            let expected = ok == "TRUE";
            if !sk.is_empty() {
                let secret: [u8; 32] = hex::decode(sk).unwrap().try_into().unwrap();
                let aux: [u8; 32] = hex::decode(aux).unwrap().try_into().unwrap();
                let msg_b: [u8; 32] = hex::decode(msg).unwrap().try_into().unwrap();
                let secp = Secp256k1::new();
                let key = Keypair::from_seckey_slice(&secp, &secret).unwrap();
                assert_eq!(
                    hex::encode_upper(key.x_only_public_key().0.serialize()),
                    pk,
                    "vector {idx}: public key"
                );
                let ours = *secp
                    .sign_schnorr_with_aux_rand(&Message::from_digest(msg_b), &key, &aux)
                    .as_ref();
                assert_eq!(hex::encode_upper(ours), sig, "vector {idx}: signature");
                signed += 1;
            }
            let verdict = verify_keypath_signature(
                &pk.to_lowercase(),
                &msg.to_lowercase(),
                &sig.to_lowercase(),
            )
            .unwrap_or(false);
            assert_eq!(verdict, expected, "vector {idx}: verification result");
            checked += 1;
        }
        assert_eq!((signed, checked), (4, 15), "vector coverage changed");
    }

    // ── BIP-341 OFFICIAL KEY-PATH SPENDING VECTORS ───────────────────────
    //
    // `tests/fixtures/bitcoin/bip341_wallet_test_vectors.json` is a verbatim
    // copy of https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json.

    const BIP341_JSON: &str =
        include_str!("../tests/fixtures/bitcoin/bip341_wallet_test_vectors.json");

    fn bip341() -> serde_json::Value {
        serde_json::from_str(BIP341_JSON).unwrap()
    }

    /// Input 0 of `keyPathSpending` has no script tree (`merkleRoot: null`):
    /// exactly the key-path-only tweak `build_transaction` applies. Its
    /// published `tweakedPrivkey` pins the tweak arithmetic, including the
    /// even-Y negation of the internal secret.
    #[test]
    fn bip341_keypath_tweaked_privkey_vector() {
        let v = bip341();
        let inputs = v["keyPathSpending"][0]["inputSpending"].as_array().unwrap();
        let mut seen = 0;
        for inp in inputs {
            if !inp["given"]["merkleRoot"].is_null() {
                continue;
            }
            let privkey = hex::decode(inp["given"]["internalPrivkey"].as_str().unwrap()).unwrap();
            let tweaked = keypath_signing_secret(&privkey, true).unwrap();
            assert_eq!(
                hex::encode(tweaked),
                inp["intermediary"]["tweakedPrivkey"].as_str().unwrap(),
                "BIP-341 tweakedPrivkey"
            );
            seen += 1;
        }
        assert_eq!(seen, 1, "expected exactly one key-path-only input");
    }

    /// Every `SIGHASH_DEFAULT` input in `keyPathSpending`: signing the published
    /// `sigHash` with the published `tweakedPrivkey` and `aux_rand = 0` gives
    /// the published 64-byte witness signature.
    #[test]
    fn bip341_keypath_default_signature_vector() {
        let v = bip341();
        let inputs = v["keyPathSpending"][0]["inputSpending"].as_array().unwrap();
        let mut seen = 0;
        for inp in inputs {
            if inp["given"]["hashType"].as_u64().unwrap() != 0 {
                continue;
            }
            let secret: [u8; 32] =
                hex::decode(inp["intermediary"]["tweakedPrivkey"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap();
            let sighash: [u8; 32] = hex::decode(inp["intermediary"]["sigHash"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let sig = schnorr_sign_zero_aux(&secret, &sighash).unwrap();
            assert_eq!(
                hex::encode(sig),
                inp["expected"]["witness"][0].as_str().unwrap(),
                "BIP-341 SIGHASH_DEFAULT witness"
            );
            seen += 1;
        }
        assert_eq!(seen, 1, "expected exactly one SIGHASH_DEFAULT input");
    }

    /// Every BIP-341 `scriptPubKey` vector: the P2TR script for the published
    /// tweaked output key is the published `scriptPubKey`.
    #[test]
    fn bip341_scriptpubkey_vectors() {
        let v = bip341();
        let cases = v["scriptPubKey"].as_array().unwrap();
        assert_eq!(cases.len(), 7);
        for (i, c) in cases.iter().enumerate() {
            let q = hex::decode(c["intermediary"]["tweakedPubkey"].as_str().unwrap()).unwrap();
            assert_eq!(
                hex::encode(p2tr_script(&q).unwrap()),
                c["expected"]["scriptPubKey"].as_str().unwrap(),
                "scriptPubKey vector {i}"
            );
        }
    }

    /// The golden fixture records JSS's effective `signingKey` per case: the
    /// tweak (case B) and the pass-through (cases A, C) must match it.
    #[test]
    fn golden_signing_key_matches_jss() {
        let g = golden();
        for case in ["caseA", "caseB", "caseC"] {
            let c = &g[case];
            let (inputs, _, privkey) = case_inputs(c);
            let internal = p2tr_script(&xonly_of(&privkey).unwrap()).unwrap();
            let needs_tweak = inputs[0].script_pubkey != internal;
            let secret = keypath_signing_secret(&privkey, needs_tweak).unwrap();
            assert_eq!(
                hex::encode(secret),
                c["signingKey"].as_str().unwrap(),
                "{case} signingKey"
            );
        }
    }

    // ── BIP-341 OFFICIAL OUTPUT-KEY VECTOR (TapTweak correctness) ────────
    //
    // From the BIP-341 spec's `wallet-test-vectors.json`
    // ("scriptPubKey" → key-path-only output, no script tree): the internal
    // x-only key `d6889cb0…` tweaked with the key-path-only `TapTweak`
    // (hashing ONLY the internal key) yields the published output key
    // `53a1f6e4…`. This is the public-key side of the tweak whose secret-key
    // side `keypath_signing_secret` applies.
    #[test]
    fn bip341_official_output_key_vector() {
        let internal = parse_xonly(
            &hex::decode("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d")
                .unwrap(),
        )
        .unwrap();
        let (output, _parity) = internal.tap_tweak(&Secp256k1::verification_only(), None);
        assert_eq!(
            hex::encode(output.to_x_only_public_key().serialize()),
            "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343",
            "BIP-341 official output-key vector"
        );
    }

    // ── BIP-341 OFFICIAL SIGHASH VECTOR (SIGHASH_DEFAULT, key path) ──────
    //
    // `keyPathSpending[0]` publishes an unsigned transaction, the outputs it
    // spends and, per input, the expected `sigHash`. The SIGHASH_DEFAULT
    // input must produce the published `sigHash` through the same
    // `SighashCache` call `build_transaction` makes.
    #[test]
    fn bip341_keypath_default_sighash_vector() {
        use bitcoin::consensus::encode::deserialize;
        let v = bip341();
        let kps = &v["keyPathSpending"][0];
        let tx: Transaction =
            deserialize(&hex::decode(kps["given"]["rawUnsignedTx"].as_str().unwrap()).unwrap())
                .unwrap();
        let spent: Vec<TxOut> = kps["given"]["utxosSpent"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u| TxOut {
                value: Amount::from_sat(u["amountSats"].as_u64().unwrap()),
                script_pubkey: ScriptBuf::from_bytes(
                    hex::decode(u["scriptPubKey"].as_str().unwrap()).unwrap(),
                ),
            })
            .collect();
        let mut cache = SighashCache::new(&tx);
        let mut seen = 0;
        for inp in kps["inputSpending"].as_array().unwrap() {
            if inp["given"]["hashType"].as_u64().unwrap() != 0 {
                continue;
            }
            let index = inp["given"]["txinIndex"].as_u64().unwrap() as usize;
            let sighash = cache
                .taproot_key_spend_signature_hash(
                    index,
                    &Prevouts::All(&spent),
                    TapSighashType::Default,
                )
                .unwrap();
            assert_eq!(
                hex::encode(sighash.to_byte_array()),
                inp["intermediary"]["sigHash"].as_str().unwrap(),
                "BIP-341 sigHash for input {index}"
            );
            seen += 1;
        }
        assert_eq!(seen, 1);
    }

    // ── Port-specific behaviour (ADR-2008) ───────────────────────────────

    /// The pre-port builder left-padded a 24-31-byte key through k256 and
    /// then panicked copying it into a 32-byte buffer. It is now an error.
    #[test]
    fn build_rejects_short_privkey_without_panicking() {
        let input = TxInput {
            txid: "aa".repeat(32),
            vout: 0,
            amount: 10_000,
            script_pubkey: vec![0x51, 0x20],
        };
        let mut short = vec![0u8; 31];
        short[30] = 1;
        assert!(build_transaction(&[input], &[], &short).is_err());
    }

    /// An output to an x coordinate with no curve point can never be spent;
    /// the pre-port `p2tr_script` accepted any 32 bytes.
    #[test]
    fn p2tr_script_rejects_non_point() {
        // x = 5 is not the x coordinate of any secp256k1 point (5^3 + 7 = 132
        // is a quadratic non-residue mod p), which rejects it.
        let mut x = [0u8; 32];
        x[31] = 5;
        assert!(p2tr_script(&x).is_err());
    }

    /// Upper-case txid hex is accepted, as before, and serialises identically.
    #[test]
    fn txid_hex_case_is_insignificant() {
        let g = golden();
        let (mut inputs, outputs, privkey) = case_inputs(&g["caseA"]);
        let lower = build_transaction(&inputs, &outputs, &privkey).unwrap();
        inputs[0].txid = inputs[0].txid.to_uppercase();
        let upper = build_transaction(&inputs, &outputs, &privkey).unwrap();
        assert_eq!(lower.raw_hex, upper.raw_hex);
    }

    /// A key-path sighash is 32 bytes; anything else is a malformed argument.
    #[test]
    fn verify_rejects_non_32_byte_sighash() {
        for line in BIP340_CSV.lines().skip(1) {
            let f: Vec<&str> = line.split(',').collect();
            if f[4].len() == 64 {
                continue;
            }
            assert!(verify_keypath_signature(
                &f[2].to_lowercase(),
                &f[4].to_lowercase(),
                &f[5].to_lowercase()
            )
            .is_err());
        }
    }

    /// The signed transaction round-trips through rust-bitcoin's decoder and
    /// its txid is the hash of the witness-stripped serialisation.
    #[test]
    fn golden_raw_decodes_and_txid_matches_unsigned_hash() {
        use bitcoin::consensus::encode::deserialize;
        let g = golden();
        for case in ["caseA", "caseB", "caseC"] {
            let c = &g[case];
            let raw = hex::decode(c["raw"].as_str().unwrap()).unwrap();
            let tx: Transaction = deserialize(&raw).unwrap();
            let unsigned = hex::decode(c["unsigned"].as_str().unwrap()).unwrap();
            let double = bitcoin::hashes::sha256d::Hash::hash(&unsigned);
            assert_eq!(
                tx.compute_txid().to_byte_array(),
                double.to_byte_array(),
                "{case}"
            );
            assert!(tx
                .input
                .iter()
                .all(|i| i.witness.len() == 1 && i.witness[0].len() == 64));
        }
    }

    // ── parse_txo_voucher ────────────────────────────────────────────────

    #[test]
    fn parse_voucher_full_form() {
        let txid = "a".repeat(64);
        let key = "1".repeat(64);
        let uri = format!("txo:tbtc4:{txid}:2?amount=9700&key={key}");
        let v = parse_txo_voucher(&uri).unwrap();
        assert_eq!(v.txid, txid);
        assert_eq!(v.vout, 2);
        assert_eq!(v.amount, 9700);
        assert_eq!(v.privkey, key);
    }

    #[test]
    fn parse_voucher_no_chain_prefix() {
        let txid = "b".repeat(64);
        let key = "2".repeat(64);
        let uri = format!("{txid}:0?amount=5000&key={key}");
        let v = parse_txo_voucher(&uri).unwrap();
        assert_eq!(v.txid, txid);
        assert_eq!(v.amount, 5000);
    }

    #[test]
    fn parse_voucher_rejects_bad_key() {
        let txid = "c".repeat(64);
        let uri = format!("txo:btc:{txid}:0?amount=5000&key=deadbeef");
        assert!(parse_txo_voucher(&uri).is_err());
    }

    #[test]
    fn parse_voucher_rejects_missing_amount() {
        let txid = "d".repeat(64);
        let key = "3".repeat(64);
        let uri = format!("txo:btc:{txid}:0?key={key}");
        assert!(parse_txo_voucher(&uri).is_err());
    }

    // ── build_transaction guards ─────────────────────────────────────────

    #[test]
    fn build_rejects_empty_inputs() {
        assert!(build_transaction(&[], &[], &[1u8; 32]).is_err());
    }

    #[test]
    fn checked_output_rejects_dust() {
        assert!(checked_output(800, 300).is_err()); // 500 <= 546 dust
        assert!(checked_output(200, 300).is_err()); // underflow
        assert_eq!(checked_output(10_000, 300).unwrap(), 9_700);
    }
}
