//! MRC20 token state chain verification and BIP-341 anchor derivation.
//!
//! Implements the Blocktrails MRC20 profile (`mono.mrc20.v0.1`):
//! - RFC 8785 JSON Canonicalization Scheme (JCS) for deterministic hashing.
//! - SHA-256 hash-chained state transitions with sequence enforcement.
//! - Transfer operation extraction and deposit verification.
//!
//! When the `mrc20` feature is enabled, also provides:
//! - BIP-341 taproot key chaining for per-state P2TR address derivation.
//! - Bech32m (BIP-350) taproot addresses, via rust-bitcoin.
//! - Full anchor verification against mempool UTXOs.
//!
//! @see <https://blocktrails.org/>
//! @see JSS `src/mrc20.js`, `src/token.js`

#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::payments::PaymentError;

/// The Blocktrails MRC20 profile identifier every state carries in `profile`.
pub const MRC20_PROFILE: &str = "mono.mrc20.v0.1";
/// The `op` value of a token transfer operation.
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
    /// Profile identifier; must equal [`MRC20_PROFILE`].
    pub profile: String,
    /// Hex SHA-256 of the previous state's JCS, or 64 zeros for genesis.
    pub prev: String,
    /// Sequence number: 0 at genesis, +1 per state.
    pub seq: u64,
    /// Token ticker symbol.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticker: Option<String>,
    /// Human-readable token name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Decimal places of the token amount.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decimals: Option<u32>,
    /// Total token supply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supply: Option<u64>,
    /// Balances after this state, keyed by holder (compressed pubkey hex or DID).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balances: Option<BTreeMap<String, u64>>,
    /// Operations this state applies.
    pub ops: Vec<Mrc20Op>,
    /// State hash this state notarises (anchor states only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<String>,
}

/// A single MRC20 operation within a state transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mrc20Op {
    /// Operation URN, e.g. [`TRANSFER_OP`].
    pub op: String,
    /// Sending holder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Receiving holder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// Amount moved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amt: Option<u64>,
}

/// Persistent trail for a token's full state chain history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mrc20Trail {
    /// Token ticker symbol.
    pub ticker: String,
    /// Human-readable token name.
    pub name: String,
    /// Total token supply.
    pub supply: u64,
    /// Issuer's compressed pubkey hex: the base of the chained-key derivation.
    pub pubkey_base: String,
    /// Every state from genesis to the head.
    pub states: Vec<Mrc20State>,
    /// JCS of each state, in order; the chained-key derivation hashes these.
    pub state_strings: Vec<String>,
    /// Txid of the UTXO currently anchoring the head.
    pub current_txid: String,
    /// Output index of that UTXO.
    pub current_vout: u32,
    /// Value of that UTXO, in sats.
    pub current_amount: u64,
    /// Network name; `"mainnet"` selects `bc` addresses, anything else `tb`.
    pub network: String,
    /// Creation timestamp, set by the caller.
    pub date_created: String,
}

/// Result of MRC20 deposit verification.
#[derive(Debug, Clone)]
pub struct Mrc20DepositResult {
    /// Total amount transferred to the deposit address.
    pub amount: u64,
    /// Ticker of the token transferred.
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
                && op.amt.is_some_and(|a| a > 0)
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

// ── Mempool lookup abstraction (pure, wasm-safe) ────────────────────
//
// The anchor *crypto* (taproot derivation) lives behind feature `mrc20`,
// but the lookup boundary is pure: a small trait plus minimal value types
// that compile for `wasm32-unknown-unknown` with no HTTP, no tokio. The
// concrete `MempoolHttpClient` (reqwest over the mempool.space REST API)
// is server-side only (`solid-pod-rs-server::mempool`). This mirrors the
// crate's existing `?Send` pattern (`PaymentStore`, `provenance::GitMarker`)
// so a single-threaded wasm executor can implement it.

/// A minimal unspent-output record returned by a [`MempoolLookup`].
///
/// Shape mirrors the mempool.space `GET /api/address/{addr}/utxo` element
/// (JSS `mrc20.js:315-327`, `token.js:176-187`): `txid`, `vout`, `value`
/// (sats), and the `status.confirmed`/`status.block_height` confirmation
/// fields flattened to `confirmed` + `block_height`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Utxo {
    /// Transaction id funding this output (64-char hex).
    pub txid: String,
    /// Output index within `txid`.
    pub vout: u32,
    /// Output value in satoshis.
    pub value: u64,
    /// Whether the funding tx is confirmed in a block (mempool vs chain).
    #[serde(default)]
    pub confirmed: bool,
    /// Confirmation height; `None` while unconfirmed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u64>,
}

/// A single transaction output as returned inside [`TxInfo::vout`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOut {
    /// Output value in satoshis.
    #[serde(default)]
    pub value: u64,
    /// Hex-encoded `scriptPubKey` of this output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scriptpubkey: Option<String>,
    /// Decoded address the output pays, when the indexer provides one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scriptpubkey_address: Option<String>,
}

/// Minimal view of a transaction returned by [`MempoolLookup::tx`].
///
/// Mirrors mempool.space `GET /api/tx/{txid}` (JSS `token.js:270-275`):
/// the `vout` array (for `scriptpubkey` lookup) and the confirmation
/// `status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxInfo {
    /// Transaction id (64-char hex).
    pub txid: String,
    /// The transaction's outputs, indexed by `vout`.
    #[serde(default)]
    pub vout: Vec<TxOut>,
    /// Whether the tx is confirmed in a block.
    #[serde(default)]
    pub confirmed: bool,
    /// Confirmation height; `None` while unconfirmed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u64>,
}

/// Read-only Bitcoin mempool/chain lookup used by anchor verification.
///
/// Pure abstraction: implementors fetch UTXO sets and transactions from
/// whatever transport is appropriate (reqwest on native, `fetch` in a
/// Worker). The trait itself drags in no I/O, so it — and the value types
/// above — compile to `wasm32`. `?Send` to match the crate's existing
/// single-threaded-executor-friendly traits.
#[async_trait::async_trait(?Send)]
pub trait MempoolLookup {
    /// Return every UTXO currently at `address` (confirmed or in-mempool).
    ///
    /// An empty vec means "no UTXO" (not an error). A transport failure is
    /// surfaced as [`PaymentError::InvalidState`] so anchor verification can
    /// fail-closed without a bespoke error variant.
    async fn address_utxos(&self, address: &str) -> Result<Vec<Utxo>, PaymentError>;

    /// Fetch a transaction by id (for `scriptPubKey` / confirmation reads).
    async fn tx(&self, txid: &str) -> Result<TxInfo, PaymentError>;
}

// ── BIP-341 key chaining (feature: mrc20) ───────────────────────────

#[cfg(feature = "mrc20")]
mod anchor {
    use super::*;
    use bitcoin::hashes::{sha256, Hash, HashEngine};
    use bitcoin::key::TweakedPublicKey;
    use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
    use bitcoin::taproot::TapTweakHash;
    use bitcoin::{Address, KnownHrp};

    /// The chaining scalar for one state:
    /// `TaggedHash("TapTweak", x_only(current) || SHA-256(state)) mod n`.
    ///
    /// This is BIP-341's `TapTweak` tagged hash with `SHA-256(state)` in the
    /// place of a script-tree root, computed with rust-bitcoin's
    /// [`TapTweakHash`] engine. Unlike a BIP-341 output tweak it is added to
    /// the full point `P` (its Y parity unchanged), not to `lift_x(x(P))`.
    /// `current` must be a 33-byte compressed key; a hash at or above the
    /// group order yields `None`.
    fn bt_scalar(current_compressed: &[u8], state_jcs: &str) -> Option<Scalar> {
        if current_compressed.len() != 33 {
            return None;
        }
        let state_hash = sha256::Hash::hash(state_jcs.as_bytes());
        let mut engine = TapTweakHash::engine();
        engine.input(&current_compressed[1..]);
        engine.input(state_hash.as_byte_array());
        Scalar::from_be_bytes(TapTweakHash::from_engine(engine).to_byte_array()).ok()
    }

    /// Iteratively derive a chained public key through a sequence of state strings.
    ///
    /// For each state, tweaks the current point by `G * bt_scalar(current, state)`
    /// and returns the final compressed (33-byte) key. With no states, the
    /// base key's own bytes come back unchanged.
    pub fn bt_derive_chained_pubkey(
        pubkey_base_hex: &str,
        state_strings: &[String],
    ) -> Result<Vec<u8>, PaymentError> {
        let pubkey_bytes = hex::decode(pubkey_base_hex)
            .map_err(|e| PaymentError::InvalidState(format!("bad pubkey hex: {e}")))?;
        let mut point = PublicKey::from_slice(&pubkey_bytes)
            .map_err(|e| PaymentError::InvalidState(format!("bad pubkey: {e}")))?;
        let secp = Secp256k1::verification_only();
        let mut current_compressed = pubkey_bytes;

        for state_jcs in state_strings {
            let t = bt_scalar(&current_compressed, state_jcs)
                .ok_or_else(|| PaymentError::InvalidState("scalar derivation failed".into()))?;
            point = point
                .add_exp_tweak(&secp, &t)
                .map_err(|e| PaymentError::InvalidState(format!("point at infinity: {e}")))?;
            current_compressed = point.serialize().to_vec();
        }

        Ok(current_compressed)
    }

    /// Derive a chained private key through a sequence of state strings.
    ///
    /// The secret-key counterpart of [`bt_derive_chained_pubkey`]: each
    /// state adds the same scalar mod n. `privkey_hex` must be exactly 32
    /// bytes of hex.
    pub fn bt_derive_chained_privkey(
        privkey_hex: &str,
        state_strings: &[String],
    ) -> Result<Vec<u8>, PaymentError> {
        let privkey_bytes = hex::decode(privkey_hex)
            .map_err(|e| PaymentError::InvalidState(format!("bad privkey hex: {e}")))?;
        let mut d = SecretKey::from_slice(&privkey_bytes)
            .map_err(|e| PaymentError::InvalidState(format!("bad privkey: {e}")))?;
        let secp = Secp256k1::signing_only();

        for state_jcs in state_strings {
            let current_compressed = d.public_key(&secp).serialize();
            let t = bt_scalar(&current_compressed, state_jcs)
                .ok_or_else(|| PaymentError::InvalidState("scalar derivation failed".into()))?;
            d = d
                .add_tweak(&t)
                .map_err(|e| PaymentError::InvalidState(format!("zero chained key: {e}")))?;
        }

        Ok(d.secret_bytes().to_vec())
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
        if chained.len() != 33 {
            return Err(PaymentError::InvalidState("unexpected key length".into()));
        }
        taproot_address(&chained[1..], network)
    }

    /// Encode the BIP-350 (bech32m) P2TR address paying `x_only` directly as
    /// the output key: `bc` on `"mainnet"`, `tb` for every other network name.
    fn taproot_address(x_only: &[u8], network: &str) -> Result<String, PaymentError> {
        let key = XOnlyPublicKey::from_slice(x_only)
            .map_err(|e| PaymentError::InvalidState(format!("bad x-only key: {e}")))?;
        let hrp = if network == "mainnet" {
            KnownHrp::Mainnet
        } else {
            KnownHrp::Testnets
        };
        // The chained key is the final output key: no further BIP-341 tweak.
        let output_key = TweakedPublicKey::dangerous_assume_tweaked(key);
        Ok(Address::p2tr_tweaked(output_key, hrp).to_string())
    }

    #[cfg(test)]
    mod vector_tests {
        use super::*;

        /// Every BIP-341 `scriptPubKey` vector carries the BIP-350 (bech32m)
        /// mainnet address of its output key. Fixture: verbatim copy of
        /// https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json.
        #[test]
        fn bip350_address_vectors() {
            let v: Value = serde_json::from_str(include_str!(
                "../tests/fixtures/bitcoin/bip341_wallet_test_vectors.json"
            ))
            .unwrap();
            let cases = v["scriptPubKey"].as_array().unwrap();
            assert_eq!(cases.len(), 7);
            for (i, c) in cases.iter().enumerate() {
                let q = hex::decode(c["intermediary"]["tweakedPubkey"].as_str().unwrap()).unwrap();
                assert_eq!(
                    taproot_address(&q, "mainnet").unwrap(),
                    c["expected"]["bip350Address"].as_str().unwrap(),
                    "bip350Address vector {i}"
                );
            }
        }
    }

    /// Verify an MRC20 deposit is anchored to a confirmed/in-mempool Bitcoin UTXO.
    ///
    /// This is the full, independently-verifiable anchor check (JSS
    /// `mrc20.js:279-335`): it composes
    ///
    /// 1. state-chain integrity + transfer extraction ([`verify_mrc20_deposit`]),
    /// 2. `stateStrings`/pubkey shape validation and the last-string↔`JCS(state)` bind,
    /// 3. taproot address re-derivation ([`bt_address`]) from the *portable*
    ///    proof (`pubkey` + `state_strings`), then
    /// 4. a **mempool UTXO lookup** at that derived address via the supplied
    ///    [`MempoolLookup`].
    ///
    /// The earlier shape, which returned the derived address and left the
    /// UTXO lookup "to the caller", is replaced: the lookup is now part of
    /// verification, so a verified result genuinely means *anchored on
    /// Bitcoin*. Pass a server-side `MempoolHttpClient` on native, or a
    /// fixture implementation in tests — the crypto and the chain read
    /// compose in one place.
    pub async fn verify_mrc20_anchor(
        state: &Mrc20State,
        prev_state: &Mrc20State,
        to_address: &str,
        pubkey_hex: &str,
        state_strings: &[String],
        network: &str,
        mempool: &dyn MempoolLookup,
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

        // Mempool lookup: the anchor is only valid if a UTXO actually
        // exists at the derived taproot address (JSS `mrc20.js:315-327`).
        let utxos = mempool.address_utxos(&address).await?;
        if utxos.is_empty() {
            return Err(PaymentError::InvalidState(format!(
                "no UTXO at derived address {address}"
            )));
        }

        Ok(Mrc20AnchorResult {
            amount: deposit.amount,
            ticker: deposit.ticker,
            address,
            utxos,
        })
    }

    /// Result of anchor verification.
    ///
    /// Carries the verified transfer amount/ticker, the derived taproot
    /// `address`, and the `utxos` found there (so callers can inspect
    /// confirmation depth without a second round-trip).
    #[derive(Debug, Clone)]
    pub struct Mrc20AnchorResult {
        /// Total amount transferred to the deposit address.
        pub amount: u64,
        /// Ticker of the token transferred.
        pub ticker: String,
        /// Taproot address re-derived from the portable proof.
        pub address: String,
        /// UTXOs found at `address`.
        pub utxos: Vec<Utxo>,
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
            state_strings: vec![jcs(&serde_json::to_value(genesis_state()).unwrap())],
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
        use std::collections::HashMap;

        // k256 test keypair (arbitrary).
        const TEST_PRIVKEY: &str =
            "0000000000000000000000000000000000000000000000000000000000000001";

        fn test_pubkey_compressed() -> String {
            let sk = k256::SecretKey::from_slice(&hex::decode(TEST_PRIVKEY).unwrap()).unwrap();
            hex::encode(sk.public_key().to_sec1_bytes())
        }

        /// Fixture [`MempoolLookup`] backed by an in-memory address→UTXO map
        /// — NO network. Lets the anchor crypto + lookup be exercised
        /// deterministically (any UTXO present ⇒ anchored; absent ⇒ not).
        struct FixtureMempool {
            utxos: HashMap<String, Vec<Utxo>>,
        }
        impl FixtureMempool {
            fn empty() -> Self {
                Self {
                    utxos: HashMap::new(),
                }
            }
            /// Register one UTXO at `address` (value/vout arbitrary but plausible).
            fn with_utxo_at(address: &str) -> Self {
                let mut utxos = HashMap::new();
                utxos.insert(
                    address.to_string(),
                    vec![Utxo {
                        txid: "ab".repeat(32),
                        vout: 0,
                        value: 9700,
                        confirmed: true,
                        block_height: Some(840_000),
                    }],
                );
                Self { utxos }
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
                    vout: vec![],
                    confirmed: true,
                    block_height: Some(840_000),
                })
            }
        }

        /// Drive an async future to completion on a single-thread runtime —
        /// the verify path is now async; this keeps the unit tests `#[test]`.
        fn block_on<F: std::future::Future>(f: F) -> F::Output {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(f)
        }

        /// Build a valid genesis→transfer chain plus its `state_strings`,
        /// returning `(prev, next, state_strings)` ready for anchor verify.
        fn valid_chain() -> (Mrc20State, Mrc20State, Vec<String>) {
            let genesis = genesis_state();
            let genesis_val = serde_json::to_value(&genesis).unwrap();
            let genesis_jcs = jcs(&genesis_val);
            let genesis_hash = sha256_hex(&genesis_jcs);
            let next = transfer_state(&genesis_hash);
            let next_jcs = jcs(&serde_json::to_value(&next).unwrap());
            (genesis, next, vec![genesis_jcs, next_jcs])
        }

        /// One pinned chained-derivation row (see [`CHAINED_GOLDEN`]).
        type ChainedRow = (
            &'static str,
            &'static [&'static str],
            &'static str,
            &'static str,
            &'static str,
            &'static str,
        );

        /// Chained-key outputs pinned from the pre-rust-bitcoin implementation
        /// (k256 point/scalar arithmetic + hand-written bech32m, commit
        /// 7a98bc0). The chained derivation is this project's construction,
        /// so no published vector exists; these rows hold the port to
        /// byte-identical output. Bases 1·G, 3·G and the BIP-340 vector-1 key;
        /// the 3-state chain from 3·G passes through odd-Y points.
        /// Columns: privkey, states, chained pubkey, chained privkey,
        /// testnet address, mainnet address.
        const CHAINED_GOLDEN: &[ChainedRow] = &[
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                &[],
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47zagq",
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                &["s1"],
                "02188885c94d9dac1636becb4891e6a0f045f4dcade83a35dc82f67965d1c07c69",
                "10d0d33688460987d4bcbbd95947c6fa408fec969dfad92ee50d7c84a7b66666",
                "tb1przygtj2dnkkpvd47edyfre4q7pzlfh9daqarthyz7eukt5wq035s9q3x6e",
                "bc1przygtj2dnkkpvd47edyfre4q7pzlfh9daqarthyz7eukt5wq035sjg8fqk",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                &["s1", "s2", "s3"],
                "023a471eb4a085454baf581f53a4c0a4bb1226b609ae98c39a910aa7ff9aa9a460",
                "8d50bb21b9e521b229c751dce1ed5720ff3b0cb0a21afba14a94c46bfc8bd482",
                "tb1p8fr3ad9qs4z5ht6craf6fs9yhvfzddsf46vv8x53p2nllx4f53sqlg6upc",
                "bc1p8fr3ad9qs4z5ht6craf6fs9yhvfzddsf46vv8x53p2nllx4f53sqgqvnmh",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000003",
                &["s1"],
                "02587dcc33ef72f579de94e3046d2ae09e9cd2740bac64918a327b702d51964d92",
                "ceaa29cc897a2ab6e94751c5bd66cf2297aff0611a941eeb351b3afd5f662f3f",
                "tb1ptp7ucvl0wt6hnh55uvzx62hqn6wdyaqt43jfrz3j0dcz65vkfkfqskp92l",
                "bc1ptp7ucvl0wt6hnh55uvzx62hqn6wdyaqt43jfrz3j0dcz65vkfkfq87h2ss",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000003",
                &["s1", "s2", "s3"],
                "03894f27c061c57dc7b6791c42b9c38faa826d3f3a2785ceac707db887db38c0a0",
                "a1e277eac1517681cc9c394d3e43e18b7efd1f377dbf387461bdc4764d3e6d66",
                "tb1p398j0srpc47u0dner3ptnsu042px60e6y7zuatrs0kug0kecczsqvv3cjm",
                "bc1p398j0srpc47u0dner3ptnsu042px60e6y7zuatrs0kug0kecczsqmy8hg5",
            ),
            (
                "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef",
                &["s1", "s2", "s3"],
                "02f283242cfe1a63c445c2a809a08068dffeb6d3220951136786e140808ee87307",
                "4793128a0984fd7ec9eec4649530c3a59c47851eef73daf6a547f819fae097df",
                "tb1p72pjgt87rf3ug3wz4qy6pqrgmlltd5ezp9g3xeuxu9qgprhgwvrss46m8z",
                "bc1p72pjgt87rf3ug3wz4qy6pqrgmlltd5ezp9g3xeuxu9qgprhgwvrs8av5ad",
            ),
        ];

        /// The same derivation over the real genesis→transfer JCS chain.
        const CHAINED_GOLDEN_JCS: &[(&str, &str, &str, &str)] = &[
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "02e5c6ad36a3a79979a71f7879fa3b07454a1ef5883ba1695c89d1a7fc0e70f6dc",
                "bbcb1e87c393cdcff150fd58245c29d011b0b41f7312b88148ec3b9d28cf3205",
                "tb1puhr26d4r57vhnfcl0pul5wc8g49paavg8wskjhyf6xnlcrns7mwqj0wjc4",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000003",
                "03ae5d99603a017fd8e09699bb9ff122df512d3109a1490427664855edca72516b",
                "ad7eced080c43f4c1f31a829adadeeeeab2005a0576c04fba1ba86700d97e4ac",
                "tb1p4ewejcp6q9la3cyknxaelufzmagj6vgf59ysgfmxfp27mjnj294sf6ur8c",
            ),
        ];

        fn compressed_pub(priv_hex: &str) -> String {
            let sk = k256::SecretKey::from_slice(&hex::decode(priv_hex).unwrap()).unwrap();
            hex::encode(sk.public_key().to_sec1_bytes())
        }

        #[test]
        fn chained_derivation_matches_pinned_golden() {
            for (priv_hex, states, pubk, privk, tb, bc) in CHAINED_GOLDEN {
                let states: Vec<String> = states.iter().map(|s| s.to_string()).collect();
                let base = compressed_pub(priv_hex);
                let ctx = format!("{priv_hex} over {} states", states.len());
                assert_eq!(
                    hex::encode(bt_derive_chained_pubkey(&base, &states).unwrap()),
                    *pubk,
                    "pubkey: {ctx}"
                );
                assert_eq!(
                    hex::encode(bt_derive_chained_privkey(priv_hex, &states).unwrap()),
                    *privk,
                    "privkey: {ctx}"
                );
                assert_eq!(
                    bt_address(&base, &states, "testnet4").unwrap(),
                    *tb,
                    "testnet: {ctx}"
                );
                assert_eq!(
                    bt_address(&base, &states, "mainnet").unwrap(),
                    *bc,
                    "mainnet: {ctx}"
                );
            }
            let (_, _, chain) = valid_chain();
            for (priv_hex, pubk, privk, tb) in CHAINED_GOLDEN_JCS {
                let base = compressed_pub(priv_hex);
                assert_eq!(
                    hex::encode(bt_derive_chained_pubkey(&base, &chain).unwrap()),
                    *pubk
                );
                assert_eq!(
                    hex::encode(bt_derive_chained_privkey(priv_hex, &chain).unwrap()),
                    *privk
                );
                assert_eq!(bt_address(&base, &chain, "testnet4").unwrap(), *tb);
            }
        }

        /// Every network name other than `"mainnet"` encodes with the `tb` HRP.
        #[test]
        fn bt_address_non_mainnet_uses_tb() {
            let base = compressed_pub(TEST_PRIVKEY);
            let states = vec!["s1".to_string()];
            let tb = bt_address(&base, &states, "testnet4").unwrap();
            for net in ["testnet", "signet", "regtest", "anything"] {
                assert_eq!(bt_address(&base, &states, net).unwrap(), tb, "{net}");
            }
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
            let mp = FixtureMempool::empty();

            let result = block_on(verify_mrc20_anchor(
                &next,
                &genesis,
                "recipient",
                &pubkey,
                &[],
                "testnet4",
                &mp,
            ));
            assert!(result.is_err());
        }

        #[test]
        fn verify_anchor_rejects_bad_pubkey_length() {
            let genesis = genesis_state();
            let genesis_val = serde_json::to_value(&genesis).unwrap();
            let genesis_hash = sha256_hex(&jcs(&genesis_val));
            let next = transfer_state(&genesis_hash);
            let mp = FixtureMempool::empty();

            let result = block_on(verify_mrc20_anchor(
                &next,
                &genesis,
                "recipient",
                "short",
                &["s1".into()],
                "testnet4",
                &mp,
            ));
            assert!(result.is_err());
        }

        // ── Mempool-composed verification (fixture, no live chain) ──────

        /// TRUE path: a UTXO exists at the derived taproot address ⇒ the
        /// anchor verifies and reports the transfer amount.
        #[test]
        fn verify_anchor_true_when_utxo_present() {
            let (genesis, next, state_strings) = valid_chain();
            let pubkey = test_pubkey_compressed();
            // Derive the SAME address the verifier will, and seed it.
            let address = bt_address(&pubkey, &state_strings, "testnet4").unwrap();
            let mp = FixtureMempool::with_utxo_at(&address);

            let result = block_on(verify_mrc20_anchor(
                &next,
                &genesis,
                "recipient",
                &pubkey,
                &state_strings,
                "testnet4",
                &mp,
            ))
            .expect("anchor with a present UTXO must verify");
            assert_eq!(result.amount, 100);
            assert_eq!(result.ticker, "TEST");
            assert_eq!(result.address, address);
            assert_eq!(result.utxos.len(), 1);
            assert!(result.utxos[0].confirmed);
        }

        /// FALSE path: crypto is valid but NO UTXO sits at the derived
        /// address ⇒ verification fails closed.
        #[test]
        fn verify_anchor_false_when_utxo_absent() {
            let (genesis, next, state_strings) = valid_chain();
            let pubkey = test_pubkey_compressed();
            let mp = FixtureMempool::empty(); // nothing anywhere

            let err = block_on(verify_mrc20_anchor(
                &next,
                &genesis,
                "recipient",
                &pubkey,
                &state_strings,
                "testnet4",
                &mp,
            ))
            .unwrap_err();
            match err {
                PaymentError::InvalidState(m) => assert!(m.contains("no UTXO")),
                other => panic!("expected no-UTXO InvalidState, got {other:?}"),
            }
        }

        /// MISMATCH path: a UTXO exists, but at a DIFFERENT address (e.g. a
        /// UTXO for some other state chain) ⇒ verification still fails,
        /// because the lookup is keyed on the *derived* address.
        #[test]
        fn verify_anchor_false_when_utxo_at_wrong_address() {
            let (genesis, next, state_strings) = valid_chain();
            let pubkey = test_pubkey_compressed();
            let mp = FixtureMempool::with_utxo_at("tb1pdecoy0000000000000000000000000000");

            let result = block_on(verify_mrc20_anchor(
                &next,
                &genesis,
                "recipient",
                &pubkey,
                &state_strings,
                "testnet4",
                &mp,
            ));
            assert!(
                result.is_err(),
                "UTXO at a non-derived address must not verify"
            );
        }
    }
}
