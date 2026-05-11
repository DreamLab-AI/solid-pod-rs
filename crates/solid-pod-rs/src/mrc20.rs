//! MRC20 token state chain verification and BIP-341 anchor derivation.
//!
//! Implements the Blocktrails MRC20 profile (`mono.mrc20.v0.1`):
//! - RFC 8785 JSON Canonicalization Scheme (JCS) for deterministic hashing.
//! - SHA-256 hash-chained state transitions with sequence enforcement.
//! - Transfer operation extraction and deposit verification.
//!
//! When the `mrc20` feature is enabled, also provides:
//! - BIP-341 taproot key chaining for per-state P2TR address derivation.
//! - Bech32m encoding for taproot addresses.
//! - Full anchor verification against mempool UTXOs.
//!
//! @see <https://blocktrails.org/>
//! @see JSS `src/mrc20.js`, `src/token.js`

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::payments::PaymentError;

pub const MRC20_PROFILE: &str = "mono.mrc20.v0.1";
pub const TRANSFER_OP: &str = "urn:mono:op:transfer";

// ── RFC 8785 JSON Canonicalization Scheme ────────────────────────────

/// Produce a deterministic JSON string per RFC 8785 (JCS).
///
/// Object keys are sorted lexicographically; no whitespace between
/// tokens; strings and numbers use `JSON.stringify` semantics.
pub fn jcs(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(b) => if *b { "true" } else { "false" }.into(),
        Value::Number(n) => {
            // RFC 8785 §3.2.2.3: integers render without fraction;
            // floats use shortest representation. serde_json's Display
            // already follows these rules for i64/u64/f64.
            n.to_string()
        }
        Value::String(_) => {
            // Delegate escaping to serde_json which handles RFC 8785 §3.2.2.2.
            serde_json::to_string(value).unwrap_or_else(|_| "\"\"".into())
        }
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(jcs).collect();
            format!("[{}]", items.join(","))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let pairs: Vec<String> = keys
                .iter()
                .map(|k| {
                    let key_json = serde_json::to_string(*k).unwrap_or_default();
                    format!("{}:{}", key_json, jcs(&map[*k]))
                })
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
    }
}

/// SHA-256 hex digest of a string.
pub fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

// ── MRC20 state types ───────────────────────────────────────────────

/// Full MRC20 token state in the hash chain.
///
/// Each state links to its predecessor via `prev = SHA-256(JCS(prev_state))`.
/// The genesis state has `prev = "0" * 64` and `seq = 0`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mrc20State {
    pub profile: String,
    pub prev: String,
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticker: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decimals: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supply: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balances: Option<BTreeMap<String, u64>>,
    pub ops: Vec<Mrc20Op>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<String>,
}

/// A single MRC20 operation within a state transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mrc20Op {
    pub op: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amt: Option<u64>,
}

/// Persistent trail for a token's full state chain history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mrc20Trail {
    pub ticker: String,
    pub name: String,
    pub supply: u64,
    pub pubkey_base: String,
    pub states: Vec<Mrc20State>,
    pub state_strings: Vec<String>,
    pub current_txid: String,
    pub current_vout: u32,
    pub current_amount: u64,
    pub network: String,
    pub date_created: String,
}

/// Result of MRC20 deposit verification.
#[derive(Debug, Clone)]
pub struct Mrc20DepositResult {
    pub amount: u64,
    pub ticker: String,
}

// ── State chain verification ────────────────────────────────────────

/// Validate that a state object conforms to MRC20 profile.
pub fn validate_mrc20_state(state: &Mrc20State) -> Result<(), PaymentError> {
    if state.profile != MRC20_PROFILE {
        return Err(PaymentError::InvalidState(format!(
            "invalid profile: expected {MRC20_PROFILE}, got {}",
            state.profile
        )));
    }
    if state.prev.is_empty() {
        return Err(PaymentError::InvalidState("missing prev hash".into()));
    }
    Ok(())
}

/// Verify state chain link: `state.prev` must equal `SHA-256(JCS(prev_state))`.
///
/// Uses RFC 8785 JCS for deterministic serialization — **not**
/// `serde_json::to_string` which does not guarantee key ordering.
pub fn verify_state_link(state: &Mrc20State, prev_state: &Mrc20State) -> Result<(), PaymentError> {
    let prev_value = serde_json::to_value(prev_state)
        .map_err(|e| PaymentError::InvalidState(format!("serialize: {e}")))?;
    let prev_jcs = jcs(&prev_value);
    let expected = sha256_hex(&prev_jcs);

    if state.prev != expected {
        return Err(PaymentError::InvalidState(format!(
            "chain break: expected prev {expected}, got {}",
            state.prev
        )));
    }
    if state.seq != prev_state.seq + 1 {
        return Err(PaymentError::InvalidState(format!(
            "sequence mismatch: expected {}, got {}",
            prev_state.seq + 1,
            state.seq
        )));
    }
    Ok(())
}

/// Extract transfer operations targeting a specific address.
pub fn extract_transfers_to<'a>(state: &'a Mrc20State, to_address: &str) -> Vec<&'a Mrc20Op> {
    state
        .ops
        .iter()
        .filter(|op| {
            op.op == TRANSFER_OP
                && op.to.as_deref() == Some(to_address)
                && op.amt.map_or(false, |a| a > 0)
        })
        .collect()
}

/// Total amount transferred to `to_address` in a given state.
pub fn total_transferred_to(state: &Mrc20State, to_address: &str) -> u64 {
    extract_transfers_to(state, to_address)
        .iter()
        .filter_map(|op| op.amt)
        .sum()
}

/// Verify an MRC20 deposit: validate state chain integrity and extract
/// the transfer amount to the pod's address.
pub fn verify_mrc20_deposit(
    state: &Mrc20State,
    prev_state: &Mrc20State,
    to_address: &str,
) -> Result<Mrc20DepositResult, PaymentError> {
    validate_mrc20_state(state)?;
    validate_mrc20_state(prev_state)?;
    verify_state_link(state, prev_state)?;

    let amount = total_transferred_to(state, to_address);
    if amount == 0 {
        return Err(PaymentError::InvalidState(format!(
            "no transfers to {to_address} in state ops"
        )));
    }

    Ok(Mrc20DepositResult {
        amount,
        ticker: state.ticker.clone().unwrap_or_else(|| "UNKNOWN".into()),
    })
}

// ── BIP-341 key chaining (feature: mrc20) ───────────────────────────

#[cfg(feature = "mrc20")]
mod anchor {
    use super::*;
    use k256::elliptic_curve::ff::PrimeField;
    use k256::ProjectivePoint;
    use k256::Scalar;
    use k256::SecretKey;

    fn tagged_hash(tag: &str, msgs: &[&[u8]]) -> [u8; 32] {
        let tag_hash = Sha256::digest(tag.as_bytes());
        let mut hasher = Sha256::new();
        hasher.update(&tag_hash);
        hasher.update(&tag_hash);
        for msg in msgs {
            hasher.update(msg);
        }
        hasher.finalize().into()
    }

    fn bytes_to_scalar(bytes: &[u8; 32]) -> Option<Scalar> {
        let wide = k256::FieldBytes::from_slice(bytes);
        Option::from(Scalar::from_repr(*wide))
    }

    /// Compute the BIP-341 TapTweak scalar for a compressed pubkey and state string.
    ///
    /// `scalar = SHA-256_tagged("TapTweak", x_only || SHA-256(state)) mod N`
    fn bt_scalar(pubkey_compressed: &[u8], state_jcs: &str) -> Option<Scalar> {
        let x_only = if pubkey_compressed.len() == 33 {
            &pubkey_compressed[1..]
        } else if pubkey_compressed.len() == 32 {
            pubkey_compressed
        } else {
            return None;
        };
        let state_hash = Sha256::digest(state_jcs.as_bytes());
        let tweak_bytes = tagged_hash("TapTweak", &[x_only, &state_hash]);
        bytes_to_scalar(&tweak_bytes)
    }

    /// Iteratively derive a chained public key through a sequence of state strings.
    ///
    /// For each state, tweaks the current point by `G * bt_scalar(current, state)`.
    pub fn bt_derive_chained_pubkey(
        pubkey_base_hex: &str,
        state_strings: &[String],
    ) -> Result<Vec<u8>, PaymentError> {
        let pubkey_bytes = hex::decode(pubkey_base_hex)
            .map_err(|e| PaymentError::InvalidState(format!("bad pubkey hex: {e}")))?;

        let point = k256::PublicKey::from_sec1_bytes(&pubkey_bytes)
            .map_err(|e| PaymentError::InvalidState(format!("bad pubkey: {e}")))?;
        let mut p = ProjectivePoint::from(point.as_affine().clone());
        let mut current_compressed = pubkey_bytes;

        for state_jcs in state_strings {
            let t = bt_scalar(&current_compressed, state_jcs)
                .ok_or_else(|| PaymentError::InvalidState("scalar derivation failed".into()))?;
            p = p + (ProjectivePoint::GENERATOR * t);
            let affine = p.to_affine();
            let encoded = k256::PublicKey::from_affine(affine)
                .map_err(|e| PaymentError::InvalidState(format!("point at infinity: {e}")))?;
            current_compressed = encoded.to_sec1_bytes().to_vec();
        }

        Ok(current_compressed)
    }

    /// Derive a chained private key through a sequence of state strings.
    pub fn bt_derive_chained_privkey(
        privkey_hex: &str,
        state_strings: &[String],
    ) -> Result<Vec<u8>, PaymentError> {
        let privkey_bytes = hex::decode(privkey_hex)
            .map_err(|e| PaymentError::InvalidState(format!("bad privkey hex: {e}")))?;

        let sk = SecretKey::from_slice(&privkey_bytes)
            .map_err(|e| PaymentError::InvalidState(format!("bad privkey: {e}")))?;
        let mut d = *sk.to_nonzero_scalar().as_ref();

        let pubkey = sk.public_key();
        let mut current_compressed = pubkey.to_sec1_bytes().to_vec();

        for state_jcs in state_strings {
            let t = bt_scalar(&current_compressed, state_jcs)
                .ok_or_else(|| PaymentError::InvalidState("scalar derivation failed".into()))?;
            d = d + t;
            let new_sk = SecretKey::new(d.into());
            current_compressed = new_sk.public_key().to_sec1_bytes().to_vec();
        }

        Ok(d.to_bytes().to_vec())
    }

    // ── Bech32m encoding ────────────────────────────────────────────

    const BECH32_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    const BECH32M_CONST: u32 = 0x2bc830a3;

    fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Vec<u8> {
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        let maxv = (1u32 << to) - 1;
        let mut ret = Vec::new();
        for &v in data {
            acc = (acc << from) | (v as u32);
            bits += from;
            while bits >= to {
                bits -= to;
                ret.push(((acc >> bits) & maxv) as u8);
            }
        }
        if pad && bits > 0 {
            ret.push(((acc << (to - bits)) & maxv) as u8);
        }
        ret
    }

    fn hrp_expand(hrp: &str) -> Vec<u8> {
        let mut r: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
        r.push(0);
        r.extend(hrp.bytes().map(|b| b & 31));
        r
    }

    fn polymod(values: &[u8]) -> u32 {
        const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        let mut chk: u32 = 1;
        for &v in values {
            let b = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ (v as u32);
            for i in 0..5 {
                if (b >> i) & 1 != 0 {
                    chk ^= GEN[i];
                }
            }
        }
        chk
    }

    fn bech32m_encode(hrp: &str, version: u8, program: &[u8]) -> String {
        let conv = convert_bits(program, 8, 5, true);
        let mut values = vec![version];
        values.extend_from_slice(&conv);

        let mut enc = hrp_expand(hrp);
        enc.extend_from_slice(&values);
        enc.extend_from_slice(&[0, 0, 0, 0, 0, 0]);

        let plm = polymod(&enc) ^ BECH32M_CONST;
        let checksum: Vec<u8> = (0..6)
            .map(|i| ((plm >> (5 * (5 - i))) & 31) as u8)
            .collect();

        let mut result = String::with_capacity(hrp.len() + 1 + values.len() + 6);
        result.push_str(hrp);
        result.push('1');
        for &v in values.iter().chain(checksum.iter()) {
            result.push(BECH32_CHARSET[v as usize] as char);
        }
        result
    }

    /// Derive the taproot (P2TR) address for a state chain.
    ///
    /// Takes the issuer's compressed pubkey (66-char hex), the full
    /// sequence of JCS-encoded state strings, and the network.
    pub fn bt_address(
        pubkey_hex: &str,
        state_strings: &[String],
        network: &str,
    ) -> Result<String, PaymentError> {
        let chained = bt_derive_chained_pubkey(pubkey_hex, state_strings)?;
        let x_only = if chained.len() == 33 {
            &chained[1..]
        } else if chained.len() == 32 {
            &chained[..]
        } else {
            return Err(PaymentError::InvalidState("unexpected key length".into()));
        };
        let hrp = if network == "mainnet" { "bc" } else { "tb" };
        Ok(bech32m_encode(hrp, 1, x_only))
    }

    /// Verify an MRC20 deposit is anchored to a Bitcoin UTXO.
    ///
    /// Combines state chain verification with taproot address derivation.
    /// The actual mempool UTXO lookup is left to the caller (transport-layer
    /// concern — HTTP fetch in Workers, reqwest on native).
    pub fn verify_mrc20_anchor(
        state: &Mrc20State,
        prev_state: &Mrc20State,
        to_address: &str,
        pubkey_hex: &str,
        state_strings: &[String],
        network: &str,
    ) -> Result<Mrc20AnchorResult, PaymentError> {
        let deposit = verify_mrc20_deposit(state, prev_state, to_address)?;

        if state_strings.is_empty() {
            return Err(PaymentError::InvalidState(
                "stateStrings required for anchor verification".into(),
            ));
        }
        if pubkey_hex.len() != 66 {
            return Err(PaymentError::InvalidState(
                "pubkey must be a 66-char compressed pubkey hex".into(),
            ));
        }

        // Verify last state string matches current state JCS
        let current_value = serde_json::to_value(state)
            .map_err(|e| PaymentError::InvalidState(format!("serialize: {e}")))?;
        let current_jcs = jcs(&current_value);
        if let Some(last) = state_strings.last() {
            if *last != current_jcs {
                return Err(PaymentError::InvalidState(
                    "last stateString does not match JCS(state)".into(),
                ));
            }
        }

        let address = bt_address(pubkey_hex, state_strings, network)?;

        Ok(Mrc20AnchorResult {
            amount: deposit.amount,
            ticker: deposit.ticker,
            address,
        })
    }

    /// Result of anchor verification — includes derived taproot address
    /// for the caller to check against mempool UTXOs.
    #[derive(Debug, Clone)]
    pub struct Mrc20AnchorResult {
        pub amount: u64,
        pub ticker: String,
        pub address: String,
    }
}

#[cfg(feature = "mrc20")]
pub use anchor::*;

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── JCS ──────────────────────────────────────────────────────────

    #[test]
    fn jcs_sorts_keys() {
        let val = json!({"z": 1, "a": 2, "m": 3});
        assert_eq!(jcs(&val), r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn jcs_nested_objects() {
        let val = json!({"b": {"d": 1, "c": 2}, "a": 3});
        assert_eq!(jcs(&val), r#"{"a":3,"b":{"c":2,"d":1}}"#);
    }

    #[test]
    fn jcs_array() {
        let val = json!([3, 1, 2]);
        assert_eq!(jcs(&val), "[3,1,2]");
    }

    #[test]
    fn jcs_string_escaping() {
        let val = json!({"key": "hello \"world\""});
        assert_eq!(jcs(&val), r#"{"key":"hello \"world\""}"#);
    }

    #[test]
    fn jcs_null_bool() {
        assert_eq!(jcs(&json!(null)), "null");
        assert_eq!(jcs(&json!(true)), "true");
        assert_eq!(jcs(&json!(false)), "false");
    }

    #[test]
    fn jcs_empty_object_and_array() {
        assert_eq!(jcs(&json!({})), "{}");
        assert_eq!(jcs(&json!([])), "[]");
    }

    #[test]
    fn jcs_deterministic() {
        let val = json!({"profile": "mono.mrc20.v0.1", "prev": "abc", "seq": 0, "ops": []});
        let a = jcs(&val);
        let b = jcs(&val);
        assert_eq!(a, b);
    }

    // ── SHA-256 ──────────────────────────────────────────────────────

    #[test]
    fn sha256_hex_known_vector() {
        assert_eq!(
            sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_hex_deterministic() {
        let a = sha256_hex("hello");
        let b = sha256_hex("hello");
        assert_eq!(a, b);
    }

    // ── State validation ─────────────────────────────────────────────

    fn genesis_state() -> Mrc20State {
        Mrc20State {
            profile: MRC20_PROFILE.into(),
            prev: "0".repeat(64),
            seq: 0,
            ticker: Some("TEST".into()),
            name: Some("Test Token".into()),
            decimals: Some(0),
            supply: Some(1000),
            balances: Some(BTreeMap::from([("issuer".into(), 1000)])),
            ops: vec![],
            anchor: None,
        }
    }

    fn transfer_state(prev_jcs_hash: &str) -> Mrc20State {
        Mrc20State {
            profile: MRC20_PROFILE.into(),
            prev: prev_jcs_hash.into(),
            seq: 1,
            ticker: Some("TEST".into()),
            name: Some("Test Token".into()),
            decimals: Some(0),
            supply: Some(1000),
            balances: Some(BTreeMap::from([
                ("issuer".into(), 900),
                ("recipient".into(), 100),
            ])),
            ops: vec![Mrc20Op {
                op: TRANSFER_OP.into(),
                from: Some("issuer".into()),
                to: Some("recipient".into()),
                amt: Some(100),
            }],
            anchor: None,
        }
    }

    #[test]
    fn validate_valid_state() {
        assert!(validate_mrc20_state(&genesis_state()).is_ok());
    }

    #[test]
    fn validate_rejects_wrong_profile() {
        let mut state = genesis_state();
        state.profile = "wrong".into();
        assert!(validate_mrc20_state(&state).is_err());
    }

    #[test]
    fn validate_rejects_empty_prev() {
        let mut state = genesis_state();
        state.prev = String::new();
        assert!(validate_mrc20_state(&state).is_err());
    }

    // ── State chain linking ──────────────────────────────────────────

    #[test]
    fn verify_state_link_valid_chain() {
        let genesis = genesis_state();
        let genesis_value = serde_json::to_value(&genesis).unwrap();
        let genesis_hash = sha256_hex(&jcs(&genesis_value));
        let next = transfer_state(&genesis_hash);

        assert!(verify_state_link(&next, &genesis).is_ok());
    }

    #[test]
    fn verify_state_link_detects_break() {
        let genesis = genesis_state();
        let next = transfer_state("wrong_hash");

        assert!(verify_state_link(&next, &genesis).is_err());
    }

    #[test]
    fn verify_state_link_detects_sequence_gap() {
        let genesis = genesis_state();
        let genesis_value = serde_json::to_value(&genesis).unwrap();
        let genesis_hash = sha256_hex(&jcs(&genesis_value));
        let mut next = transfer_state(&genesis_hash);
        next.seq = 5;

        let err = verify_state_link(&next, &genesis);
        assert!(err.is_err());
    }

    // ── Transfer extraction ──────────────────────────────────────────

    #[test]
    fn extract_transfers_finds_matching() {
        let genesis = genesis_state();
        let genesis_value = serde_json::to_value(&genesis).unwrap();
        let genesis_hash = sha256_hex(&jcs(&genesis_value));
        let state = transfer_state(&genesis_hash);

        let transfers = extract_transfers_to(&state, "recipient");
        assert_eq!(transfers.len(), 1);
        assert_eq!(transfers[0].amt, Some(100));
    }

    #[test]
    fn extract_transfers_ignores_wrong_recipient() {
        let genesis = genesis_state();
        let genesis_value = serde_json::to_value(&genesis).unwrap();
        let genesis_hash = sha256_hex(&jcs(&genesis_value));
        let state = transfer_state(&genesis_hash);

        let transfers = extract_transfers_to(&state, "nobody");
        assert!(transfers.is_empty());
    }

    #[test]
    fn extract_transfers_ignores_zero_amount() {
        let state = Mrc20State {
            profile: MRC20_PROFILE.into(),
            prev: "0".repeat(64),
            seq: 0,
            ticker: None,
            name: None,
            decimals: None,
            supply: None,
            balances: None,
            ops: vec![Mrc20Op {
                op: TRANSFER_OP.into(),
                from: Some("a".into()),
                to: Some("b".into()),
                amt: Some(0),
            }],
            anchor: None,
        };
        assert!(extract_transfers_to(&state, "b").is_empty());
    }

    #[test]
    fn total_transferred_sums_multiple_ops() {
        let state = Mrc20State {
            profile: MRC20_PROFILE.into(),
            prev: "0".repeat(64),
            seq: 0,
            ticker: None,
            name: None,
            decimals: None,
            supply: None,
            balances: None,
            ops: vec![
                Mrc20Op {
                    op: TRANSFER_OP.into(),
                    from: Some("a".into()),
                    to: Some("pod".into()),
                    amt: Some(50),
                },
                Mrc20Op {
                    op: TRANSFER_OP.into(),
                    from: Some("b".into()),
                    to: Some("pod".into()),
                    amt: Some(30),
                },
                Mrc20Op {
                    op: TRANSFER_OP.into(),
                    from: Some("c".into()),
                    to: Some("other".into()),
                    amt: Some(20),
                },
            ],
            anchor: None,
        };
        assert_eq!(total_transferred_to(&state, "pod"), 80);
    }

    // ── Full deposit verification ────────────────────────────────────

    #[test]
    fn verify_deposit_success() {
        let genesis = genesis_state();
        let genesis_value = serde_json::to_value(&genesis).unwrap();
        let genesis_hash = sha256_hex(&jcs(&genesis_value));
        let next = transfer_state(&genesis_hash);

        let result = verify_mrc20_deposit(&next, &genesis, "recipient").unwrap();
        assert_eq!(result.amount, 100);
        assert_eq!(result.ticker, "TEST");
    }

    #[test]
    fn verify_deposit_fails_no_transfers() {
        let genesis = genesis_state();
        let genesis_value = serde_json::to_value(&genesis).unwrap();
        let genesis_hash = sha256_hex(&jcs(&genesis_value));
        let next = transfer_state(&genesis_hash);

        let err = verify_mrc20_deposit(&next, &genesis, "nobody");
        assert!(err.is_err());
    }

    #[test]
    fn verify_deposit_fails_chain_break() {
        let genesis = genesis_state();
        let next = transfer_state("bad_hash");

        let err = verify_mrc20_deposit(&next, &genesis, "recipient");
        assert!(err.is_err());
    }

    // ── Trail serialization ──────────────────────────────────────────

    #[test]
    fn trail_roundtrip() {
        let trail = Mrc20Trail {
            ticker: "TEST".into(),
            name: "Test".into(),
            supply: 1000,
            pubkey_base: "02".to_string() + &"ab".repeat(32),
            states: vec![genesis_state()],
            state_strings: vec![jcs(&serde_json::to_value(&genesis_state()).unwrap())],
            current_txid: "a".repeat(64),
            current_vout: 0,
            current_amount: 9700,
            network: "testnet4".into(),
            date_created: "2026-05-11T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&trail).unwrap();
        let parsed: Mrc20Trail = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.ticker, "TEST");
        assert_eq!(parsed.supply, 1000);
        assert_eq!(parsed.states.len(), 1);
    }

    // ── JCS ↔ serde_json interop ─────────────────────────────────────

    #[test]
    fn jcs_state_is_deterministic_across_serializations() {
        let state = genesis_state();
        let v1 = serde_json::to_value(&state).unwrap();
        let v2 = serde_json::to_value(&state).unwrap();
        assert_eq!(jcs(&v1), jcs(&v2));
    }

    // ── BIP-341 anchor tests (feature: mrc20) ───────────────────────

    #[cfg(feature = "mrc20")]
    mod anchor_tests {
        use super::*;

        // k256 test keypair (arbitrary).
        const TEST_PRIVKEY: &str =
            "0000000000000000000000000000000000000000000000000000000000000001";

        fn test_pubkey_compressed() -> String {
            let sk = k256::SecretKey::from_slice(&hex::decode(TEST_PRIVKEY).unwrap()).unwrap();
            hex::encode(sk.public_key().to_sec1_bytes())
        }

        #[test]
        fn bt_derive_chained_pubkey_single_state() {
            let pubkey = test_pubkey_compressed();
            let states = vec!["genesis_state".into()];
            let result = bt_derive_chained_pubkey(&pubkey, &states);
            assert!(result.is_ok());
            let chained = result.unwrap();
            assert_eq!(chained.len(), 33);
            assert!(chained[0] == 0x02 || chained[0] == 0x03);
        }

        #[test]
        fn bt_derive_chained_pubkey_multiple_states() {
            let pubkey = test_pubkey_compressed();
            let states = vec!["state0".into(), "state1".into(), "state2".into()];
            let result = bt_derive_chained_pubkey(&pubkey, &states);
            assert!(result.is_ok());
        }

        #[test]
        fn bt_derive_chained_pubkey_deterministic() {
            let pubkey = test_pubkey_compressed();
            let states = vec!["s1".into(), "s2".into()];
            let a = bt_derive_chained_pubkey(&pubkey, &states).unwrap();
            let b = bt_derive_chained_pubkey(&pubkey, &states).unwrap();
            assert_eq!(a, b);
        }

        #[test]
        fn bt_derive_chained_pubkey_differs_per_state() {
            let pubkey = test_pubkey_compressed();
            let a = bt_derive_chained_pubkey(&pubkey, &["s1".into()]).unwrap();
            let b = bt_derive_chained_pubkey(&pubkey, &["s2".into()]).unwrap();
            assert_ne!(a, b);
        }

        #[test]
        fn bt_derive_chained_privkey_roundtrip() {
            let pubkey = test_pubkey_compressed();
            let states = vec!["state1".into()];

            let chained_priv = bt_derive_chained_privkey(TEST_PRIVKEY, &states).unwrap();
            let chained_sk = k256::SecretKey::from_slice(&chained_priv).unwrap();
            let chained_pub_from_priv = hex::encode(chained_sk.public_key().to_sec1_bytes());

            let chained_pub = hex::encode(bt_derive_chained_pubkey(&pubkey, &states).unwrap());
            assert_eq!(chained_pub_from_priv, chained_pub);
        }

        #[test]
        fn bt_address_testnet_format() {
            let pubkey = test_pubkey_compressed();
            let states = vec!["genesis".into()];
            let addr = bt_address(&pubkey, &states, "testnet4").unwrap();
            assert!(
                addr.starts_with("tb1p"),
                "expected tb1p prefix, got: {addr}"
            );
        }

        #[test]
        fn bt_address_mainnet_format() {
            let pubkey = test_pubkey_compressed();
            let states = vec!["genesis".into()];
            let addr = bt_address(&pubkey, &states, "mainnet").unwrap();
            assert!(
                addr.starts_with("bc1p"),
                "expected bc1p prefix, got: {addr}"
            );
        }

        #[test]
        fn bt_address_deterministic() {
            let pubkey = test_pubkey_compressed();
            let states = vec!["s1".into(), "s2".into()];
            let a = bt_address(&pubkey, &states, "testnet4").unwrap();
            let b = bt_address(&pubkey, &states, "testnet4").unwrap();
            assert_eq!(a, b);
        }

        #[test]
        fn bt_address_differs_per_network() {
            let pubkey = test_pubkey_compressed();
            let states = vec!["s1".into()];
            let testnet = bt_address(&pubkey, &states, "testnet4").unwrap();
            let mainnet = bt_address(&pubkey, &states, "mainnet").unwrap();
            assert_ne!(testnet, mainnet);
            assert!(testnet.starts_with("tb1p"));
            assert!(mainnet.starts_with("bc1p"));
        }

        #[test]
        fn verify_anchor_rejects_empty_state_strings() {
            let genesis = genesis_state();
            let genesis_val = serde_json::to_value(&genesis).unwrap();
            let genesis_hash = sha256_hex(&jcs(&genesis_val));
            let next = transfer_state(&genesis_hash);
            let pubkey = test_pubkey_compressed();

            let result =
                verify_mrc20_anchor(&next, &genesis, "recipient", &pubkey, &[], "testnet4");
            assert!(result.is_err());
        }

        #[test]
        fn verify_anchor_rejects_bad_pubkey_length() {
            let genesis = genesis_state();
            let genesis_val = serde_json::to_value(&genesis).unwrap();
            let genesis_hash = sha256_hex(&jcs(&genesis_val));
            let next = transfer_state(&genesis_hash);

            let result = verify_mrc20_anchor(
                &next,
                &genesis,
                "recipient",
                "short",
                &["s1".into()],
                "testnet4",
            );
            assert!(result.is_err());
        }
    }
}
