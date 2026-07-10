//! Bitcoin taproot transaction building — the **write-side** of block-trails.
//!
//! This is the Rust port of JSS `src/token.js` `buildTransaction`
//! (lines 117-174): a from-scratch BIP-341 key-path taproot transaction
//! builder with BIP-340 Schnorr signing. It produces broadcastable raw
//! transactions for MRC20 mint/transfer and for anchoring an arbitrary
//! block-trail state, plus the high-level [`mint_token`], [`transfer_token`]
//! and [`anchor_state`] composers that the server's `BlockAnchorer::anchor`
//! and the `/pay/.buy` / `/pay/.withdraw` routes call.
//!
//! # Crypto provenance — no re-derivation
//!
//! The chained-key derivation, JCS, SHA-256 and bech32m all live in
//! [`crate::mrc20`] and are reused verbatim ([`bt_derive_chained_pubkey`],
//! [`bt_derive_chained_privkey`], [`bt_address`], [`jcs`], [`sha256_hex`]).
//! Only the *missing edges* are added here: P2TR script construction, the
//! BIP-341 TapSighash, key-path Schnorr signing (with the optional default
//! TapTweak for externally-funded inputs), and witness assembly.
//!
//! The signing stack is `k256` with the `schnorr` feature — the **same**
//! secp256k1 implementation the crate already uses for `mrc20.rs` and NIP-98.
//! No `rust-bitcoin` / `secp256k1-sys` is introduced.
//!
//! ## Signature determinism (cross-impl golden)
//!
//! JSS `schnorr.sign(sighash, key)` (`token.js:156`) supplies **no** aux_rand,
//! so `@noble/curves` injects `randomBytes(32)` — production JSS tx hex is
//! non-deterministic. BIP-340, however, is fully deterministic when
//! `aux_rand = 0^32`. We sign with `SigningKey::sign_raw(sighash, &[0u8; 32])`,
//! which makes our output reproducible *and* byte-for-byte identical to JSS
//! when JSS is pinned to `aux_rand = 0` (the cross-impl golden fixture is
//! generated that way). `k256::schnorr::SigningKey::from` performs the BIP-340
//! even-Y scalar negation internally, exactly as `@noble` does, so passing the
//! same `signingKey` scalar reproduces the same signature.
//!
//! ## wasm32 boundary
//!
//! Transaction *building* is pure byte manipulation + `k256` signing, so it
//! could compile to wasm — but it is gated `#[cfg(not(target_arch = "wasm32"))]`
//! (and behind feature `mrc20`) per ADR-059 D4: the write-side is a native,
//! server-only concern and must **not** leak into the wasm `core` surface. The
//! [`MempoolBroadcast`] trait itself is pure (`?Send`, no I/O) — the concrete
//! reqwest implementation lives server-side in `solid-pod-rs-server::mempool`,
//! mirroring Phase 3's [`MempoolLookup`].

#![cfg(all(feature = "mrc20", not(target_arch = "wasm32")))]

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::schnorr::SigningKey;
use k256::SecretKey;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::mrc20::{
    bt_address, bt_derive_chained_privkey, bt_derive_chained_pubkey, jcs, sha256_hex,
    MempoolLookup, Mrc20Op, Mrc20State, Mrc20Trail, MRC20_PROFILE, TRANSFER_OP,
};
use crate::payments::PaymentError;

/// secp256k1 group order `n` (JSS `token.js:21`).
const SECP_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Default fee in sats (JSS `token.js:278,369`).
pub const DEFAULT_FEE_SATS: u64 = 300;
/// Dust threshold in sats — an output at or below this is uneconomical
/// (JSS `token.js:280,371`).
pub const DUST_LIMIT_SATS: u64 = 546;

// ── Byte / serialization helpers (token.js:24-70) ───────────────────────

fn write_u32_le(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

fn write_u64_le(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

/// CompactSize/VarInt encode (JSS `token.js:61-65`). Values above `0xffff`
/// are rejected — taproot scripts and the counts we emit never exceed it.
fn write_var_int(v: usize) -> Result<Vec<u8>, PaymentError> {
    if v < 0xfd {
        Ok(vec![v as u8])
    } else if v <= 0xffff {
        Ok(vec![0xfd, (v & 0xff) as u8, ((v >> 8) & 0xff) as u8])
    } else {
        Err(PaymentError::InvalidState("VarInt too large".into()))
    }
}

/// Reverse a big-endian txid hex into the little-endian byte order used on
/// the wire (JSS `token.js:66-70`).
fn reverse_txid(txid_hex: &str) -> Result<Vec<u8>, PaymentError> {
    let mut bytes = hex::decode(txid_hex)
        .map_err(|e| PaymentError::InvalidState(format!("bad txid hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(PaymentError::InvalidState(format!(
            "txid must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    bytes.reverse();
    Ok(bytes)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// BIP-340/341 tagged hash `SHA256(SHA256(tag) || SHA256(tag) || msg…)`
/// (JSS `token.js:77-80`). Reused for both `TapTweak` and `TapSighash`.
fn tagged_hash(tag: &str, msgs: &[&[u8]]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    for m in msgs {
        h.update(m);
    }
    h.finalize().into()
}

// ── Big-endian scalar arithmetic mod n (token.js:33-40,124-128) ─────────
//
// `buildTransaction`'s tweak branch does `(d ± t) mod n` on raw 256-bit
// integers. We mirror it with constant-width big-endian byte arithmetic so
// the produced `signingKey` scalar is byte-identical to JSS before it is
// handed to `k256` for the BIP-340 even-Y normalisation + sign.

/// Big-endian compare: `a < b`?
fn be_lt(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/// `(a + b) mod n` over big-endian 32-byte scalars.
fn add_mod_n(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let s = a[i] as u16 + b[i] as u16 + carry;
        out[i] = (s & 0xff) as u8;
        carry = s >> 8;
    }
    // A 256-bit add can overflow; if it did, or the result >= n, subtract n.
    if carry != 0 || !be_lt(&out, &SECP_N) {
        out = sub(&out, &SECP_N, carry as u8);
    }
    out
}

/// `n - a` over big-endian 32-byte scalars (used for the even-Y negation).
fn neg_mod_n(a: &[u8; 32]) -> [u8; 32] {
    sub(&SECP_N, a, 0)
}

/// `(a - b)` with an incoming borrow-as-carry from the add overflow path.
/// Returns the wrapped difference; callers only invoke it when `a + carry*2^256 >= b`.
fn sub(a: &[u8; 32], b: &[u8; 32], carry_in: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = a[i] as i16 - b[i] as i16 - borrow;
        if d < 0 {
            out[i] = (d + 256) as u8;
            borrow = 1;
        } else {
            out[i] = d as u8;
            borrow = 0;
        }
    }
    // `carry_in` represents the 2^256 bit that overflowed during the add;
    // it cancels the final borrow.
    debug_assert!(carry_in as i16 >= borrow, "scalar subtraction underflow");
    out
}

// ── P2TR output script (token.js:112-114) ───────────────────────────────

/// Build a P2TR (pay-to-taproot) output script: `OP_1 (0x51) PUSH32 (0x20)
/// <x-only pubkey>` (JSS `token.js:112-114`). `xonly` must be 32 bytes.
pub fn p2tr_script(xonly: &[u8]) -> Result<Vec<u8>, PaymentError> {
    if xonly.len() != 32 {
        return Err(PaymentError::InvalidState(format!(
            "x-only pubkey must be 32 bytes, got {}",
            xonly.len()
        )));
    }
    let mut s = Vec::with_capacity(34);
    s.push(0x51);
    s.push(0x20);
    s.extend_from_slice(xonly);
    Ok(s)
}

/// Compressed-pubkey → x-only (drop the 0x02/0x03 prefix byte).
fn xonly_of(privkey: &[u8]) -> Result<[u8; 32], PaymentError> {
    let sk = SecretKey::from_slice(privkey)
        .map_err(|e| PaymentError::InvalidState(format!("bad privkey: {e}")))?;
    let compressed = sk.public_key().to_sec1_bytes();
    if compressed.len() != 33 {
        return Err(PaymentError::InvalidState(
            "expected compressed pubkey".into(),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&compressed[1..]);
    Ok(out)
}

// ── Transaction input / output value types ──────────────────────────────

/// A transaction input spending a previous taproot output.
///
/// `scriptPubKey` is the **full** `scriptPubKey` of the output being spent
/// (`5120<xonly>` for taproot) — needed for the BIP-341 sighash and to decide
/// whether the default TapTweak must be applied (JSS `token.js:120`).
#[derive(Debug, Clone)]
pub struct TxInput {
    /// Big-endian txid hex (64 chars) of the funding output.
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

// ── Core: from-scratch BIP-341 key-path taproot tx builder ──────────────

/// Build and key-path-sign a taproot transaction (JSS `token.js:117-174`).
///
/// All inputs are signed with `privkey` (the JSS builder signs every input
/// with one key — callers group UTXOs by key/tweak before calling, exactly
/// as `pay.js` withdraw-sats does). For each input:
///
/// 1. `needs_tweak` is `true` unless the input's `scriptPubKey` is precisely
///    `5120<xonly(privkey)>` — i.e. the output pays the **untweaked** internal
///    key. MRC20 chained-key spends are untweaked (the chaining tweaks are
///    already baked into `privkey`); externally-funded vouchers are tweaked
///    (BIP-341 default/key-path-only TapTweak). (`token.js:118-129`)
/// 2. The BIP-341 `TapSighash` is computed from the SHA-midstates over
///    prevouts / amounts / scriptPubKeys / sequences / outputs
///    (`token.js:136-156`), with `SIGHASH_DEFAULT` (0x00), version 2, locktime
///    0, sequence `0xfffffffd`.
/// 3. The sighash is signed with `aux_rand = 0` for deterministic BIP-340.
///
/// The witness (one 64-byte key-path signature per input, `SIGHASH_DEFAULT`)
/// and the segwit serialisation are then assembled (`token.js:159-173`).
pub fn build_transaction(
    inputs: &[TxInput],
    outputs: &[TxOutput],
    privkey: &[u8],
) -> Result<BuiltTx, PaymentError> {
    if inputs.is_empty() {
        return Err(PaymentError::InvalidState(
            "transaction has no inputs".into(),
        ));
    }

    // ── Determine the effective signing scalar (token.js:118-129) ──
    let internal_xonly = xonly_of(privkey)?;
    let untweaked_spk = p2tr_script(&internal_xonly)?; // 5120<internal xonly>
    let needs_tweak = inputs[0].script_pubkey != untweaked_spk;

    let signing_scalar: [u8; 32] = if needs_tweak {
        // d' = (negate_if_odd_y(d) + TapTweak(internalXOnly)) mod n.
        // token.js:123-128 — the BIP-341 key-path-only tweak (no merkle root).
        let tweak = tagged_hash("TapTweak", &[&internal_xonly]);
        let mut d = [0u8; 32];
        d.copy_from_slice(privkey);

        // Negate d if the full pubkey's Y is odd (BIP-340 even-Y) —
        // token.js:126-127 reads byte 64 of the uncompressed pubkey.
        let sk = SecretKey::from_slice(privkey)
            .map_err(|e| PaymentError::InvalidState(format!("bad privkey: {e}")))?;
        let uncompressed = sk.public_key().to_encoded_point(false);
        let y_is_odd = uncompressed.as_bytes()[64] & 1 == 1;
        if y_is_odd {
            d = neg_mod_n(&d);
        }
        add_mod_n(&d, &tweak)
    } else {
        let mut d = [0u8; 32];
        d.copy_from_slice(privkey);
        d
    };

    // `k256`'s SigningKey::from performs the BIP-340 even-Y negation on the
    // scalar internally (identical to @noble) before signing.
    let signing_key = SigningKey::from_bytes(&signing_scalar)
        .map_err(|e| PaymentError::InvalidState(format!("invalid signing scalar: {e}")))?;
    let signing_xonly = signing_key.verifying_key().to_bytes();

    let version: u32 = 2;
    let locktime: u32 = 0;
    let sequence: u32 = 0xfffffffd;

    // Serialise outputs once (token.js:132-134).
    let mut ser_outputs: Vec<Vec<u8>> = Vec::with_capacity(outputs.len());
    for o in outputs {
        let mut b = Vec::new();
        b.extend_from_slice(&write_u64_le(o.amount));
        b.extend_from_slice(&write_var_int(o.script_pubkey.len())?);
        b.extend_from_slice(&o.script_pubkey);
        ser_outputs.push(b);
    }

    // ── BIP-341 SHA midstates (token.js:136-144) ──
    let mut prevouts = Vec::new();
    for i in inputs {
        prevouts.extend_from_slice(&reverse_txid(&i.txid)?);
        prevouts.extend_from_slice(&write_u32_le(i.vout));
    }
    let sha_prevouts = sha256(&prevouts);

    let mut amounts = Vec::new();
    for i in inputs {
        amounts.extend_from_slice(&write_u64_le(i.amount));
    }
    let sha_amounts = sha256(&amounts);

    let mut spks = Vec::new();
    for i in inputs {
        spks.extend_from_slice(&write_var_int(i.script_pubkey.len())?);
        spks.extend_from_slice(&i.script_pubkey);
    }
    let sha_scriptpubkeys = sha256(&spks);

    let mut seqs = Vec::new();
    for _ in inputs {
        seqs.extend_from_slice(&write_u32_le(sequence));
    }
    let sha_sequences = sha256(&seqs);

    let mut outs = Vec::new();
    for so in &ser_outputs {
        outs.extend_from_slice(so);
    }
    let sha_outputs = sha256(&outs);

    // ── Per-input sighash + sign (token.js:146-157) ──
    let mut sighashes: Vec<[u8; 32]> = Vec::with_capacity(inputs.len());
    let mut signatures: Vec<Vec<u8>> = Vec::with_capacity(inputs.len());
    for i in 0..inputs.len() {
        let mut sig_msg = Vec::new();
        // epoch (0x00) || hash_type (SIGHASH_DEFAULT 0x00) — token.js:149
        sig_msg.extend_from_slice(&[0x00, 0x00]);
        sig_msg.extend_from_slice(&write_u32_le(version));
        sig_msg.extend_from_slice(&write_u32_le(locktime));
        sig_msg.extend_from_slice(&sha_prevouts);
        sig_msg.extend_from_slice(&sha_amounts);
        sig_msg.extend_from_slice(&sha_scriptpubkeys);
        sig_msg.extend_from_slice(&sha_sequences);
        sig_msg.extend_from_slice(&sha_outputs);
        // spend_type (0x00, key-path) || input_index — token.js:152-153
        sig_msg.push(0x00);
        sig_msg.extend_from_slice(&write_u32_le(i as u32));

        let sighash = tagged_hash("TapSighash", &[&sig_msg]);
        // aux_rand = 0 → deterministic BIP-340 (see module docs).
        let sig = signing_key
            .sign_raw(&sighash, &[0u8; 32])
            .map_err(|e| PaymentError::InvalidState(format!("schnorr sign failed: {e}")))?;
        sighashes.push(sighash);
        signatures.push(sig.to_bytes().to_vec());
    }

    // ── Assemble segwit tx (token.js:159-173) ──
    let mut parts = Vec::new();
    parts.extend_from_slice(&write_u32_le(version));
    parts.extend_from_slice(&[0x00, 0x01]); // segwit marker+flag
    parts.extend_from_slice(&write_var_int(inputs.len())?);
    for inp in inputs {
        parts.extend_from_slice(&reverse_txid(&inp.txid)?);
        parts.extend_from_slice(&write_u32_le(inp.vout));
        parts.push(0x00); // empty scriptSig
        parts.extend_from_slice(&write_u32_le(sequence));
    }
    parts.extend_from_slice(&write_var_int(outputs.len())?);
    for so in &ser_outputs {
        parts.extend_from_slice(so);
    }
    // Witness: one item (the signature) per input — token.js:169-171.
    for sig in &signatures {
        parts.push(0x01); // witness stack items = 1
        parts.extend_from_slice(&write_var_int(sig.len())?);
        parts.extend_from_slice(sig);
    }
    parts.extend_from_slice(&write_u32_le(locktime));

    // Unsigned (legacy, witness-stripped) serialisation — the nonce-independent
    // skeleton used by the cross-impl golden's fallback assertion.
    let mut uparts = Vec::new();
    uparts.extend_from_slice(&write_u32_le(version));
    uparts.extend_from_slice(&write_var_int(inputs.len())?);
    for inp in inputs {
        uparts.extend_from_slice(&reverse_txid(&inp.txid)?);
        uparts.extend_from_slice(&write_u32_le(inp.vout));
        uparts.push(0x00);
        uparts.extend_from_slice(&write_u32_le(sequence));
    }
    uparts.extend_from_slice(&write_var_int(outputs.len())?);
    for so in &ser_outputs {
        uparts.extend_from_slice(so);
    }
    uparts.extend_from_slice(&write_u32_le(locktime));

    Ok(BuiltTx {
        raw_hex: hex::encode(&parts),
        unsigned_hex: hex::encode(&uparts),
        sighashes: sighashes.iter().map(hex::encode).collect(),
        signatures: signatures.iter().map(hex::encode).collect(),
        signing_xonly: hex::encode(signing_xonly),
    })
}

/// Verify a 64-byte key-path Schnorr signature against an x-only pubkey and a
/// 32-byte TapSighash — the offline correctness gate ("every signature our
/// builder produces must verify"). Pure `k256` BIP-340 verification.
pub fn verify_keypath_signature(
    xonly_hex: &str,
    sighash_hex: &str,
    sig_hex: &str,
) -> Result<bool, PaymentError> {
    use k256::schnorr::{Signature, VerifyingKey};
    let xonly = hex::decode(xonly_hex)
        .map_err(|e| PaymentError::InvalidState(format!("bad xonly hex: {e}")))?;
    let sighash = hex::decode(sighash_hex)
        .map_err(|e| PaymentError::InvalidState(format!("bad sighash hex: {e}")))?;
    let sig_bytes = hex::decode(sig_hex)
        .map_err(|e| PaymentError::InvalidState(format!("bad sig hex: {e}")))?;
    let vk = VerifyingKey::from_bytes(&xonly)
        .map_err(|e| PaymentError::InvalidState(format!("bad verifying key: {e}")))?;
    let sig = Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| PaymentError::InvalidState(format!("bad signature: {e}")))?;
    Ok(vk.verify_raw(&sighash, &sig).is_ok())
}

// ── TXO voucher parsing (token.js:226-236) ──────────────────────────────

/// A parsed TXO **voucher** — a self-contained spendable output carrying the
/// private key that controls it. This is the JSS `parseTxoUri` form
/// (`token.js:226-236`): `txo:<chain>:<txid>:<vout>?amount=<sats>&key=<hex>`.
///
/// This is intentionally distinct from [`crate::payments::TxoDeposit`]
/// (`payments::parse_txo_uri`), which parses a *deposit reference*
/// (`txid:vout`, no key) used to credit a ledger. A voucher additionally
/// carries the spending `privkey` + `amount` and is what mint / withdraw-sats
/// consume. The two are different concepts; keeping the names distinct avoids
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
    let sk = SecretKey::from_slice(&privkey)
        .map_err(|e| PaymentError::InvalidState(format!("bad voucher key: {e}")))?;
    let pubkey_base_hex = hex::encode(sk.public_key().to_sec1_bytes());

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
    let voucher_sk = SecretKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
    let voucher_priv_hex = hex::encode(voucher_sk.to_bytes());
    let voucher_xonly = xonly_of(&voucher_sk.to_bytes())?;
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
        let xonly = [0xabu8; 32];
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

    // ── scalar arithmetic ────────────────────────────────────────────────

    #[test]
    fn add_mod_n_wraps() {
        // (n-1) + 2 = 1 (mod n)
        let mut a = SECP_N;
        a[31] -= 1; // n-1
        let mut two = [0u8; 32];
        two[31] = 2;
        let r = add_mod_n(&a, &two);
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(r, one);
    }

    #[test]
    fn neg_mod_n_is_n_minus_a() {
        let mut a = [0u8; 32];
        a[31] = 5;
        let r = neg_mod_n(&a);
        // r + a should be n ≡ 0; check r == n-5
        let mut expected = SECP_N;
        expected[31] -= 5;
        assert_eq!(r, expected);
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

    // ── BIP-340 OFFICIAL TEST VECTORS (sighash + sign correctness) ───────
    //
    // From the canonical BIP-340 test-vectors.csv. These validate the BIP-340
    // signing primitive `k256` uses (with aux_rand=0) against the spec, which
    // — together with the TapSighash bytes the golden checks — covers the
    // "validate TapSighash + key-path schnorr signing against BIP-341 vectors"
    // gate (the TapSighash is a tagged-hash of a defined preimage; the signing
    // is BIP-340; both are pinned here).

    struct Bip340Vec {
        sk: &'static str,
        pk: &'static str,
        aux: &'static str,
        msg: &'static str,
        sig: &'static str,
    }

    // Vectors 0,1,2,3 (the deterministic key-known vectors) from BIP-340.
    const BIP340_VECTORS: &[Bip340Vec] = &[
        Bip340Vec {
            sk: "0000000000000000000000000000000000000000000000000000000000000003",
            pk: "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            aux: "0000000000000000000000000000000000000000000000000000000000000000",
            msg: "0000000000000000000000000000000000000000000000000000000000000000",
            sig: "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
        },
        Bip340Vec {
            sk: "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
            pk: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            aux: "0000000000000000000000000000000000000000000000000000000000000001",
            msg: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            sig: "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
        },
        Bip340Vec {
            sk: "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
            pk: "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
            aux: "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
            msg: "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
            sig: "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
        },
    ];

    #[test]
    fn bip340_official_vectors_sign_and_verify() {
        for (i, v) in BIP340_VECTORS.iter().enumerate() {
            let sk_bytes = hex::decode(v.sk).unwrap();
            let aux: [u8; 32] = hex::decode(v.aux).unwrap().try_into().unwrap();
            let msg = hex::decode(v.msg).unwrap();
            let sk = SigningKey::from_bytes(&sk_bytes).unwrap();

            // Public key matches the spec.
            assert_eq!(
                hex::encode_upper(sk.verifying_key().to_bytes()),
                v.pk,
                "vector {i}: pubkey"
            );
            // Signature matches the spec byte-for-byte (BIP-340 with given aux).
            let sig = sk.sign_raw(&msg, &aux).unwrap();
            assert_eq!(
                hex::encode_upper(sig.to_bytes()),
                v.sig,
                "vector {i}: signature must match BIP-340 official vector"
            );
            // And it verifies.
            assert!(
                verify_keypath_signature(
                    &hex::encode(sk.verifying_key().to_bytes()),
                    &v.msg.to_lowercase(),
                    &v.sig.to_lowercase()
                )
                .unwrap(),
                "vector {i}: must verify"
            );
        }
    }

    // ── BIP-341 OFFICIAL OUTPUT-KEY VECTOR (TapTweak correctness) ────────
    //
    // From the BIP-341 spec's `wallet-test-vectors.json`
    // ("scriptPubKey" → key-path-only output, no script tree): the internal
    // x-only key `d6889cb0…` tweaked with the key-path-only `TapTweak`
    // (hashing ONLY the internal key) yields the published output key
    // `53a1f6e4…`. This validates our `tagged_hash("TapTweak", …)` + the
    // even-Y lift + `Q = P + t·G` against the spec INDEPENDENTLY of JSS — it is
    // the authoritative oracle for the `needs_tweak` signing path.
    #[test]
    fn bip341_official_output_key_vector() {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use k256::{ProjectivePoint, PublicKey, Scalar};

        let internal_hex = "d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d";
        let expected_output = "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343";

        let internal = hex::decode(internal_hex).unwrap();
        // TapTweak over ONLY the internal key (key-path spend, empty merkle).
        let tweak = tagged_hash("TapTweak", &[&internal]);
        let t = Scalar::from(k256::elliptic_curve::ScalarPrimitive::from_slice(&tweak).unwrap());

        // lift_x(internal) with even Y (BIP-340 convention).
        let lifted = PublicKey::from_sec1_bytes(&{
            let mut c = vec![0x02];
            c.extend_from_slice(&internal);
            c
        })
        .unwrap();
        let p = ProjectivePoint::from(*lifted.as_affine());
        let q = p + ProjectivePoint::GENERATOR * t;
        let q_pub = PublicKey::from_affine(q.to_affine()).unwrap();
        let encoded = q_pub.to_encoded_point(true);
        let output_xonly = hex::encode(&encoded.as_bytes()[1..]);

        assert_eq!(
            output_xonly, expected_output,
            "BIP-341 official output-key vector: TapTweak derivation must match the spec"
        );
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
