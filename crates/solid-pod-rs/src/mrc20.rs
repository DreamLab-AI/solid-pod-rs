//! MRC20 token state chain verification and BIP-341 anchor derivation.
//!
//! Implements the Blocktrails MRC20 profile (`mono.mrc20.v0.1`):
//! - RFC 8785 JSON Canonicalization Scheme (JCS) for deterministic hashing.
//! - SHA-256 hash-chained state transitions with sequence enforcement.
//! - Transfer operation extraction and deposit verification.
//!
//! When the `mrc20` feature is enabled, also provides:
//! - Blocktrails key chaining for per-state P2TR address derivation, the rule
//!   blocktrails/spec ef54a08 states ("the rule as it is"): the tweak is BIP
//!   341's `TapTweak` hash of `x(P) || sha256(state)`, added to the full point
//!   `P` (never its even-y lift), and each output key is `x(P)` itself.
//! - Reading a base key as a compressed point, a bare x (the even-y point) or
//!   a did:nostr identifier (`bt_base_point`), and the per-link walk
//!   blocktrails/verify checks a trail with (`bt_trail_outputs`,
//!   `bt_verify_trail_outputs`).
//! - Bech32m (BIP-350) taproot addresses, via rust-bitcoin.
//! - Anchor verification against the chain, every link of the trail walked
//!   back from the head UTXO ([`crate::blocktrail`]).
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

/// The string a Blocktrails state is hashed as when it is chained: a string
/// state is its own text, any other JSON value its JCS ([`jcs`]).
///
/// This is blocktrails/verify's `stateHash` (043e7af): a string state hashes
/// as its UTF-8 text, never as `JSON.stringify` of it (which would quote it),
/// so a git-mark commit is its 40 lowercase hex characters; an object state,
/// such as an [`Mrc20State`], hashes as its JCS. The MRC20 trails this crate
/// keeps already store each state's JCS in `state_strings`, which is the same
/// string this function gives for the state as an object.
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// use solid_pod_rs::mrc20::bt_state_string;
///
/// let commit = "9adc596cfd1100333393a12f2f41b2d820f16d0b";
/// assert_eq!(bt_state_string(&json!(commit)), commit);
/// assert_eq!(bt_state_string(&json!({"b": 1, "a": [true, null]})), r#"{"a":[true,null],"b":1}"#);
/// ```
pub fn bt_state_string(state: &Value) -> String {
    match state {
        Value::String(text) => text.clone(),
        other => jcs(other),
    }
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

/// One input of a transaction returned inside [`TxInfo::vin`]: the output it
/// spends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxIn {
    /// Transaction id of the output spent (64-char hex).
    pub txid: String,
    /// Index of the output spent within `txid`.
    pub vout: u32,
}

/// Minimal view of a transaction returned by [`MempoolLookup::tx`].
///
/// Mirrors mempool.space `GET /api/tx/{txid}` (JSS `token.js:270-275`):
/// the `vin` array (the outputs it spends, which is how a verifier checks
/// that a mark spends the one before it), the `vout` array (for
/// `scriptpubkey` lookup) and the confirmation `status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxInfo {
    /// Transaction id (64-char hex).
    pub txid: String,
    /// The outputs this transaction spends, in input order.
    #[serde(default)]
    pub vin: Vec<TxIn>,
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

    // The derivation is Blocktrails Core as blocktrails/spec ef54a08 states it
    // ("the rule as it is"), and as blocktrails/verify 043e7af and
    // blocktrails/git-mark b852d7d compute it with sidestr/spec `keys.mjs`:
    //
    //   t_i = int(TaggedHash("TapTweak", x(P_{i-1}) || sha256(state_i))) mod n, t_i != 0
    //   P_i = P_{i-1} + t_i·G      on the full point, never its even-y lift
    //   d_i = d_{i-1} + t_i mod n  so d_i·G = P_i exactly, whatever the parities
    //   output_i = x(P_i)          a raw taproot key (`rawtr()`), no further tweak
    //
    // The hash is BIP 341's; the derivation is not (BIP 341 lifts before every
    // tweak). The x-only form appears only at the output and inside BIP 340
    // signing.

    /// `int(h) mod n` for a 32-byte hash `h`, refusing zero: the scalar rule of
    /// blocktrails/spec (`t = int(t) mod n`, a zero `t` rejects the state) and
    /// of sidestr/spec `keys.mjs` `taggedScalar`.
    ///
    /// A hash at or above the group order (probability about 2^-128) is reduced
    /// rather than refused: `h = (h - 2^255) + 2^255`, both terms below `n`, and
    /// libsecp256k1 adds them mod `n`. The only such `h` that reduces to zero is
    /// `n` itself, which `add_tweak` refuses.
    fn scalar_mod_n(h: [u8; 32]) -> Option<Scalar> {
        if let Ok(s) = Scalar::from_be_bytes(h) {
            return (s != Scalar::ZERO).then_some(s);
        }
        let mut low = h;
        low[0] &= 0x7f;
        let mut high = [0u8; 32];
        high[0] = 0x80;
        let sum = SecretKey::from_slice(&low)
            .ok()?
            .add_tweak(&Scalar::from_be_bytes(high).ok()?)
            .ok()?;
        Scalar::from_be_bytes(sum.secret_bytes()).ok()
    }

    /// The chaining scalar for one state:
    /// `TaggedHash("TapTweak", x(current) || SHA-256(state)) mod n`, never zero.
    ///
    /// This is BIP-341's `TapTweak` tagged hash with `SHA-256(state)` in the
    /// place of a script-tree root, computed with rust-bitcoin's
    /// [`TapTweakHash`] engine. Unlike a BIP-341 output tweak it is added to
    /// the full point `P` (its Y parity unchanged), not to `lift_x(x(P))`.
    /// `None` means the state must be refused (`t = 0`).
    fn bt_scalar(current: &PublicKey, state_string: &str) -> Option<Scalar> {
        let state_hash = sha256::Hash::hash(state_string.as_bytes());
        let mut engine = TapTweakHash::engine();
        engine.input(&current.serialize()[1..]);
        engine.input(state_hash.as_byte_array());
        scalar_mod_n(TapTweakHash::from_engine(engine).to_byte_array())
    }

    fn refused_state() -> PaymentError {
        PaymentError::InvalidState("the tweak is zero: refuse this state".into())
    }

    /// Parse a base key into its full point (see [`bt_base_point`]).
    fn base_point(id: &str) -> Result<PublicKey, PaymentError> {
        let s = id.trim().to_ascii_lowercase();
        let is_hex = |h: &str| h.bytes().all(|b| b.is_ascii_hexdigit());
        let is_point = |h: &str| h.len() == 66 && (h.starts_with("02") || h.starts_with("03"));
        let bare = s.strip_prefix("did:nostr:").unwrap_or(&s);
        let compressed = if bare.len() == 64 && is_hex(bare) {
            format!("02{bare}")
        } else if let Some(mk) = s.strip_prefix("fe701").filter(|m| is_point(m) && is_hex(m)) {
            mk.to_string()
        } else if is_point(&s) && is_hex(&s) {
            s.clone()
        } else {
            return Err(PaymentError::InvalidState(
                "bad pubkey: not a compressed point (02/03 + x), a bare x, a did:nostr \
                 identifier or a did:nostr Multikey"
                    .into(),
            ));
        };
        let bytes = hex::decode(&compressed)
            .map_err(|e| PaymentError::InvalidState(format!("bad pubkey hex: {e}")))?;
        PublicKey::from_slice(&bytes)
            .map_err(|e| PaymentError::InvalidState(format!("bad pubkey: not on the curve: {e}")))
    }

    /// Walk the chain from `base`, returning every chained point `P_1..P_k`.
    fn walk_points(
        base: PublicKey,
        state_strings: &[String],
    ) -> Result<Vec<PublicKey>, PaymentError> {
        let secp = Secp256k1::verification_only();
        let mut point = base;
        let mut points = Vec::with_capacity(state_strings.len());
        for state in state_strings {
            let t = bt_scalar(&point, state).ok_or_else(refused_state)?;
            point = point
                .add_exp_tweak(&secp, &t)
                .map_err(|e| PaymentError::InvalidState(format!("point at infinity: {e}")))?;
            points.push(point);
        }
        Ok(points)
    }

    /// Read a trail's base key as the full point it names, compressed
    /// (33 bytes), as sidestr/spec `keys.mjs` `basePoint` does: the rule
    /// blocktrails/spec ef54a08 states and blocktrails/verify applies to a
    /// trail's `pubkeyBase`.
    ///
    /// - A compressed point, `02`/`03` + x (66 hex): that point, parity kept.
    ///   A trail publishes its base this way, so a verifier has nothing to guess.
    /// - A bare x-only key (64 hex) or `did:nostr:<x>`: the even-y point `02` + x.
    /// - A did:nostr Multikey, `fe701` + compressed point: that point.
    ///
    /// Input is trimmed and read case-insensitively; anything else, and any x
    /// that is not on the curve, is refused. A bare x names the even-y point
    /// whatever the parity of its holder's key, so the holder normalises the
    /// secret once with [`bt_normalize_privkey`] before deriving chained
    /// secrets from it.
    ///
    /// # Examples
    ///
    /// ```
    /// use solid_pod_rs::mrc20::bt_base_point;
    ///
    /// let x = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    /// let even = format!("02{x}");
    /// assert_eq!(hex::encode(bt_base_point(x).unwrap()), even);
    /// assert_eq!(hex::encode(bt_base_point(&format!("did:nostr:{x}")).unwrap()), even);
    /// // a full point keeps its parity
    /// let odd = format!("03{x}");
    /// assert_eq!(hex::encode(bt_base_point(&odd).unwrap()), odd);
    /// assert!(bt_base_point("not a key").is_err());
    /// ```
    pub fn bt_base_point(pubkey_base: &str) -> Result<[u8; 33], PaymentError> {
        Ok(base_point(pubkey_base)?.serialize())
    }

    /// Iteratively derive a chained public key through a sequence of state strings.
    ///
    /// For each state, tweaks the current point by `G * t` with
    /// `t = TaggedHash("TapTweak", x(current) || SHA-256(state)) mod n`, on the
    /// full point (never its even-y lift), and returns the final compressed
    /// (33-byte) key. With no states, the base point comes back unchanged.
    ///
    /// `pubkey_base_hex` is read by [`bt_base_point`]: a compressed point as
    /// every stored trail has it, or a bare x (read as `02` + x), a
    /// `did:nostr:` identifier or a Multikey.
    ///
    /// Each state string is hashed as its UTF-8 bytes, which is
    /// blocktrails/verify's `stateHash`: an object state is passed as its JCS
    /// (see [`jcs`] and [`bt_state_string`]), a string state as its text with
    /// no JSON quoting (a git-mark commit is its 40 lowercase hex characters).
    /// A state whose tweak is zero is refused.
    ///
    /// # Examples
    ///
    /// ```
    /// use solid_pod_rs::mrc20::bt_derive_chained_pubkey;
    ///
    /// // base 1·G over the states "s1", "s2", "s3"
    /// let g = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    /// let states: Vec<String> = ["s1", "s2", "s3"].map(String::from).to_vec();
    /// let head = bt_derive_chained_pubkey(g, &states).unwrap();
    /// assert_eq!(
    ///     hex::encode(&head),
    ///     "023a471eb4a085454baf581f53a4c0a4bb1226b609ae98c39a910aa7ff9aa9a460"
    /// );
    /// // the same base as a bare x: 1·G is even-y, so the 02 reading agrees
    /// assert_eq!(bt_derive_chained_pubkey(&g[2..], &states).unwrap(), head);
    /// ```
    pub fn bt_derive_chained_pubkey(
        pubkey_base_hex: &str,
        state_strings: &[String],
    ) -> Result<Vec<u8>, PaymentError> {
        let base = base_point(pubkey_base_hex)?;
        let points = walk_points(base, state_strings)?;
        Ok(points.last().unwrap_or(&base).serialize().to_vec())
    }

    /// The x-only output key of every link of a trail: `x(P_1) .. x(P_k)`, one
    /// per state, from the base key and the states.
    ///
    /// This is the walk blocktrails/verify runs to check a trail's commitment:
    /// its result is compared, mark by mark, with the output each mark's
    /// transaction carries on-chain (see [`bt_verify_trail_outputs`]). The base
    /// is read by [`bt_base_point`], each state string as in
    /// [`bt_derive_chained_pubkey`].
    ///
    /// # Examples
    ///
    /// ```
    /// use solid_pod_rs::mrc20::bt_trail_outputs;
    ///
    /// // blocktrails/git-mark's live trail: the commits are the states, as text
    /// let base = "0273c7f6cf0f135a63bc95a2e676bcf0a592c8b508fae8697e43f778c74e232b24";
    /// let commits = vec!["9adc596cfd1100333393a12f2f41b2d820f16d0b".to_string()];
    /// let outputs = bt_trail_outputs(base, &commits).unwrap();
    /// assert_eq!(
    ///     hex::encode(outputs[0]),
    ///     "e403de73c97cb7ca2efddab823493a7b949085e40087ac97fe6884db12cc77df"
    /// );
    /// ```
    pub fn bt_trail_outputs(
        pubkey_base: &str,
        state_strings: &[String],
    ) -> Result<Vec<[u8; 32]>, PaymentError> {
        let points = walk_points(base_point(pubkey_base)?, state_strings)?;
        Ok(points
            .iter()
            .map(|p| p.x_only_public_key().0.serialize())
            .collect())
    }

    /// Check every link of a trail, not the head alone: recompute each mark's
    /// output key from the base key and the states ([`bt_trail_outputs`]) and
    /// compare it with the x-only output key found on-chain for that mark.
    ///
    /// `onchain_outputs[i]` is the 32-byte witness program of mark `i`'s
    /// output (the `<x>` of its `OP_1 <x>` script). There must be exactly one
    /// state per mark. The error names the first mark that does not match,
    /// as blocktrails/git-mark's `verify` does (`mismatch at index i`).
    ///
    /// # Examples
    ///
    /// ```
    /// use solid_pod_rs::mrc20::{bt_trail_outputs, bt_verify_trail_outputs};
    ///
    /// let base = "0273c7f6cf0f135a63bc95a2e676bcf0a592c8b508fae8697e43f778c74e232b24";
    /// let states: Vec<String> = ["a", "b", "c"].map(String::from).to_vec();
    /// let onchain = bt_trail_outputs(base, &states).unwrap();
    /// assert!(bt_verify_trail_outputs(base, &states, &onchain).is_ok());
    /// // the same states in another order commit to other outputs
    /// let swapped: Vec<String> = ["a", "c", "b"].map(String::from).to_vec();
    /// let err = bt_verify_trail_outputs(base, &swapped, &onchain).unwrap_err();
    /// assert!(err.to_string().contains("mismatch at index 1"));
    /// ```
    pub fn bt_verify_trail_outputs(
        pubkey_base: &str,
        state_strings: &[String],
        onchain_outputs: &[[u8; 32]],
    ) -> Result<(), PaymentError> {
        if state_strings.len() != onchain_outputs.len() {
            return Err(PaymentError::InvalidState(format!(
                "the trail has {} marks and {} states",
                onchain_outputs.len(),
                state_strings.len()
            )));
        }
        let expected = bt_trail_outputs(pubkey_base, state_strings)?;
        match expected
            .iter()
            .zip(onchain_outputs)
            .position(|(want, got)| want != got)
        {
            None => Ok(()),
            Some(i) => Err(PaymentError::InvalidState(format!(
                "mismatch at index {i}: expected output {}, found {}",
                hex::encode(expected[i]),
                hex::encode(onchain_outputs[i])
            ))),
        }
    }

    /// Normalise a holder's secret once to the secret of the even-y point with
    /// the same x: `d` itself when `d·G` has even y, otherwise `n - d`
    /// (sidestr/spec `keys.mjs` `normalize`).
    ///
    /// Use it when a trail's base was published as a bare x (or a
    /// `did:nostr:` identifier), which names the even-y point: the normalised
    /// secret is then exactly the base point's, and
    /// [`bt_derive_chained_privkey`] from it gives the secret of every chained
    /// point. Never apply it between steps, and never to a trail whose base is
    /// stored as a full compressed point: there the secret as stored already
    /// matches the base.
    ///
    /// # Examples
    ///
    /// ```
    /// use solid_pod_rs::mrc20::bt_normalize_privkey;
    ///
    /// // 1·G has even y: unchanged
    /// let one = format!("{:064x}", 1);
    /// assert_eq!(hex::encode(bt_normalize_privkey(&one).unwrap()), one);
    /// // 10·G has odd y: n - 10
    /// let ten = format!("{:064x}", 10);
    /// assert_eq!(
    ///     hex::encode(bt_normalize_privkey(&ten).unwrap()),
    ///     "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364137"
    /// );
    /// ```
    pub fn bt_normalize_privkey(privkey_hex: &str) -> Result<Vec<u8>, PaymentError> {
        let d = parse_privkey(privkey_hex)?;
        let (_, parity) = d.x_only_public_key(&Secp256k1::signing_only());
        let d = if parity == bitcoin::secp256k1::Parity::Odd {
            d.negate()
        } else {
            d
        };
        Ok(d.secret_bytes().to_vec())
    }

    fn parse_privkey(privkey_hex: &str) -> Result<SecretKey, PaymentError> {
        let privkey_bytes = hex::decode(privkey_hex)
            .map_err(|e| PaymentError::InvalidState(format!("bad privkey hex: {e}")))?;
        SecretKey::from_slice(&privkey_bytes)
            .map_err(|e| PaymentError::InvalidState(format!("bad privkey: {e}")))
    }

    /// Derive a chained private key through a sequence of state strings.
    ///
    /// The secret-key counterpart of [`bt_derive_chained_pubkey`]: each
    /// state adds the same scalar mod n, so the result's point is exactly the
    /// chained point from `privkey_hex`'s own full point (its parity kept).
    /// `privkey_hex` must be exactly 32 bytes of hex. For a base published as
    /// a bare x, pass the secret through [`bt_normalize_privkey`] first.
    ///
    /// # Examples
    ///
    /// ```
    /// use solid_pod_rs::mrc20::{bt_derive_chained_privkey, bt_derive_chained_pubkey};
    ///
    /// let one = format!("{:064x}", 1);
    /// let g = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    /// let states = vec!["s1".to_string()];
    /// let d = bt_derive_chained_privkey(&one, &states).unwrap();
    /// assert_eq!(
    ///     hex::encode(&d),
    ///     "10d0d33688460987d4bcbbd95947c6fa408fec969dfad92ee50d7c84a7b66666"
    /// );
    /// assert_eq!(
    ///     hex::encode(bt_derive_chained_pubkey(g, &states).unwrap()),
    ///     "02188885c94d9dac1636becb4891e6a0f045f4dcade83a35dc82f67965d1c07c69"
    /// );
    /// ```
    pub fn bt_derive_chained_privkey(
        privkey_hex: &str,
        state_strings: &[String],
    ) -> Result<Vec<u8>, PaymentError> {
        let mut d = parse_privkey(privkey_hex)?;
        let secp = Secp256k1::signing_only();

        for state in state_strings {
            let t = bt_scalar(&d.public_key(&secp), state).ok_or_else(refused_state)?;
            d = d
                .add_tweak(&t)
                .map_err(|e| PaymentError::InvalidState(format!("zero chained key: {e}")))?;
        }

        Ok(d.secret_bytes().to_vec())
    }

    /// Derive the taproot (P2TR) address for a state chain.
    ///
    /// Takes the issuer's base key (a 66-char compressed point as stored
    /// trails carry it, or any form [`bt_base_point`] reads), the full
    /// sequence of state strings (JCS for MRC20 states, the commit as text
    /// for a git-mark trail), and the network. The output key is `x(P_k)`
    /// itself, with no further BIP-341 tweak. The human-readable part is `bc`
    /// on `"mainnet"`, `gm` on `"gitmark"` (the sidestr git-mark chain, as
    /// blocktrails/git-mark b852d7d `NETWORK_HRP` has it), and `tb` for every
    /// other network name.
    ///
    /// # Examples
    ///
    /// ```
    /// use solid_pod_rs::mrc20::bt_address;
    ///
    /// let g = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    /// let states = vec!["s1".to_string()];
    /// assert_eq!(
    ///     bt_address(g, &states, "testnet4").unwrap(),
    ///     "tb1przygtj2dnkkpvd47edyfre4q7pzlfh9daqarthyz7eukt5wq035s9q3x6e"
    /// );
    /// assert!(bt_address(g, &states, "gitmark").unwrap().starts_with("gm1p"));
    /// ```
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
    /// the output key: `bc` on `"mainnet"`, `gm` on `"gitmark"`, `tb` for
    /// every other network name.
    fn taproot_address(x_only: &[u8], network: &str) -> Result<String, PaymentError> {
        let key = XOnlyPublicKey::from_slice(x_only)
            .map_err(|e| PaymentError::InvalidState(format!("bad x-only key: {e}")))?;
        if network == crate::blocktrail::GITMARK_NETWORK {
            // Not a Bitcoin network, so not one of rust-bitcoin's known HRPs:
            // the same witness-v1 program under the `gm` HRP, encoded by the
            // bech32 crate rust-bitcoin itself uses.
            let hrp = bitcoin::bech32::Hrp::parse("gm")
                .map_err(|e| PaymentError::InvalidState(format!("bad hrp: {e}")))?;
            return bitcoin::bech32::segwit::encode_v1(hrp, &key.serialize())
                .map_err(|e| PaymentError::InvalidState(format!("bech32m: {e}")));
        }
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

        const N_HEX: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

        fn h32(h: &str) -> [u8; 32] {
            hex::decode(h).unwrap().try_into().unwrap()
        }

        /// `int(h) mod n`, zero refused: below `n` unchanged, `n` itself
        /// refused (it reduces to zero), above `n` reduced. Known answers:
        /// `n + 1 -> 1` and `2^256 - 1 -> 2^256 - 1 - n`
        /// (`2^256 - n = 0x14551231950b75fc4402da1732fc9bebf`).
        #[test]
        fn scalar_mod_n_reduces_and_refuses_zero() {
            let scal = |h: &str| scalar_mod_n(h32(h)).map(|s| hex::encode(s.to_be_bytes()));
            assert_eq!(scal(&"0".repeat(64)), None);
            let one = format!("{:064x}", 1);
            assert_eq!(scal(&one).as_deref(), Some(one.as_str()));
            let n_minus_1 = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";
            assert_eq!(scal(n_minus_1).as_deref(), Some(n_minus_1));
            assert_eq!(scal(N_HEX), None);
            let n_plus_1 = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142";
            assert_eq!(scal(n_plus_1).as_deref(), Some(one.as_str()));
            assert_eq!(
                scal(&"f".repeat(64)).as_deref(),
                Some("000000000000000000000000000000014551231950b75fc4402da1732fc9bebe")
            );
        }

        /// blocktrails/git-mark b852d7d: the `gitmark` network encodes with
        /// the `gm` HRP, the same witness program as `tb` and `bc`. Its own
        /// trail (base, commits, addresses) and the live outputs under `gm`,
        /// from `tests/fixtures/blocktrails/verify-trail-vectors.json`.
        #[test]
        fn bt_address_gitmark_uses_gm() {
            let v: Value = serde_json::from_str(include_str!(
                "../tests/fixtures/blocktrails/verify-trail-vectors.json"
            ))
            .unwrap();
            for (network, ours) in [
                ("gitmark", "gitmark"),
                ("tbtc4", "testnet4"),
                ("mainnet", "mainnet"),
            ] {
                let net = &v["gitMark"]["networks"][network];
                let base = net["pubkeyBase"].as_str().unwrap();
                let commits: Vec<String> = net["commits"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|c| c.as_str().unwrap().to_string())
                    .collect();
                for (i, want) in net["addresses"].as_array().unwrap().iter().enumerate() {
                    assert_eq!(
                        bt_address(base, &commits[..=i], ours).unwrap(),
                        want.as_str().unwrap(),
                        "{network} mark {i}"
                    );
                }
            }
            let live: Vec<[u8; 32]> = v["gitMark"]["liveVerify"]["expected"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| h32(x.as_str().unwrap()))
                .collect();
            let gm = v["gitMark"]["liveGm"].as_array().unwrap();
            assert_eq!(gm.len(), live.len());
            for (i, want) in gm.iter().enumerate() {
                let want = want.as_str().unwrap();
                assert!(want.starts_with("gm1p"));
                assert_eq!(taproot_address(&live[i], "gitmark").unwrap(), want);
            }
            // bc and tb are untouched
            let x = live[0];
            assert!(taproot_address(&x, "mainnet").unwrap().starts_with("bc1p"));
            assert_eq!(
                taproot_address(&x, "testnet4").unwrap(),
                v["gitMark"]["liveTb"][0].as_str().unwrap()
            );
        }

        /// `int(h) mod n` for hashes at and above the group order, against
        /// sidestr/spec `keys.mjs` `taggedScalar` (e8deb63) run with its tagged
        /// hash replaced by `h`, so the reduction is the reference's own
        /// (`tests/fixtures/blocktrails/verify-trail-vectors.json`).
        #[test]
        fn scalar_mod_n_matches_keys_mjs() {
            let v: Value = serde_json::from_str(include_str!(
                "../tests/fixtures/blocktrails/verify-trail-vectors.json"
            ))
            .unwrap();
            let cases = v["scalarModN"].as_array().unwrap();
            assert!(cases
                .iter()
                .any(|c| c["hash"].as_str().unwrap() > N_HEX && !c["scalar"].is_null()));
            for c in cases {
                let h = c["hash"].as_str().unwrap();
                let want = c["scalar"].as_str();
                let got = scalar_mod_n(h32(h)).map(|s| hex::encode(s.to_be_bytes()));
                assert_eq!(got.as_deref(), want, "int({h}) mod n");
            }
        }

        /// The base-key forms of sidestr/spec `keys.mjs` `basePoint`.
        #[test]
        fn base_point_forms() {
            let x = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
            let even = format!("02{x}");
            let odd = format!("03{x}");
            for id in [
                x.to_string(),
                x.to_uppercase(),
                format!("  {x}\n"),
                format!("did:nostr:{x}"),
                format!("fe701{even}"),
                even.clone(),
            ] {
                assert_eq!(hex::encode(bt_base_point(&id).unwrap()), even, "{id:?}");
            }
            assert_eq!(hex::encode(bt_base_point(&odd).unwrap()), odd);
            assert_eq!(
                hex::encode(bt_base_point(&format!("fe701{odd}")).unwrap()),
                odd
            );
            // x = 5 is not on secp256k1 (5^3 + 7 = 132 is not a square mod p)
            let off_curve = format!("{:064x}", 5);
            for bad in [
                off_curve.clone(),
                format!("02{off_curve}"),
                format!("04{x}"),
                format!("did:nostr:{even}"),
                format!("fe7010{x}"),
                x[..62].to_string(),
                format!("{}zz", &x[..62]),
                String::new(),
            ] {
                assert!(bt_base_point(&bad).is_err(), "{bad:?} accepted");
            }
        }

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

    /// Verify an MRC20 deposit is anchored on Bitcoin, every link of its trail
    /// checked.
    ///
    /// The independently-verifiable anchor check (JSS `mrc20.js:279-335`),
    /// with the head-only UTXO lookup replaced by the per-link walk of
    /// blocktrails/verify 043e7af. It composes
    ///
    /// 1. state-chain integrity + transfer extraction ([`verify_mrc20_deposit`]),
    /// 2. `stateStrings`/pubkey shape validation and the last-string↔`JCS(state)` bind,
    /// 3. taproot address re-derivation ([`bt_address`]) from the *portable*
    ///    proof (`pubkey` + `state_strings`),
    /// 4. a **mempool UTXO lookup** at that derived address via the supplied
    ///    [`MempoolLookup`], which finds the head mark, and then
    /// 5. the walk back from that head
    ///    ([`verify_anchor_chain`](crate::blocktrail::verify_anchor_chain)):
    ///    every earlier mark's output must be the key its prefix of states
    ///    derives, and each mark must spend the one before it.
    ///
    /// Step 5 is what the head alone cannot show: a UTXO at the head address
    /// proves only that the head key was paid, not that each earlier state was
    /// committed by its own mark, in order, before it.
    ///
    /// As before, a head still in the mempool is accepted: the result carries
    /// the full [`TrailReport`](crate::blocktrail::TrailReport) (per-mark
    /// confirmation and block heights) for a caller that wants
    /// [`is_verified`](crate::blocktrail::TrailReport::is_verified) rather
    /// than [`is_intact`](crate::blocktrail::TrailReport::is_intact). Pass a
    /// server-side `MempoolHttpClient` on native, or a fixture implementation
    /// in tests.
    ///
    /// # Errors
    ///
    /// [`PaymentError::InvalidState`] for a broken state chain, no transfer to
    /// `to_address`, a malformed proof, no UTXO at the derived address, or a
    /// trail whose walk from every UTXO there finds a mark that is missing,
    /// does not commit to its state, or does not spend its predecessor.
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

        // Mempool lookup: the head mark is a UTXO at the derived taproot
        // address (JSS `mrc20.js:315-327`).
        let utxos = mempool.address_utxos(&address).await?;
        if utxos.is_empty() {
            return Err(PaymentError::InvalidState(format!(
                "no UTXO at derived address {address}"
            )));
        }

        // Every link: walk back from a UTXO at the head address. Any one whose
        // whole chain holds anchors the deposit.
        let mut failure = None;
        for utxo in &utxos {
            let report = crate::blocktrail::verify_anchor_chain(
                pubkey_hex,
                state_strings,
                &utxo.txid,
                utxo.vout,
                mempool,
            )
            .await?;
            if report.is_intact() {
                return Ok(Mrc20AnchorResult {
                    amount: deposit.amount,
                    ticker: deposit.ticker,
                    address,
                    utxos,
                    report,
                });
            }
            if failure.is_none() {
                failure = report.first_failure().map(|m| {
                    format!(
                        "mark {} ({}): {}",
                        m.index,
                        if m.txid.is_empty() {
                            "unreached"
                        } else {
                            &m.txid
                        },
                        m.status
                    )
                });
            }
        }
        Err(PaymentError::InvalidState(format!(
            "the anchor's trail does not verify link by link: {}",
            failure.unwrap_or_else(|| "no mark reached".into())
        )))
    }

    /// Result of anchor verification.
    ///
    /// Carries the verified transfer amount/ticker, the derived taproot
    /// `address`, the `utxos` found there, and the per-link `report` of the
    /// trail walked back from the UTXO that verified (so callers can inspect
    /// every mark's confirmation without a second round-trip).
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
        /// The trail, mark by mark, walked back from the head UTXO.
        pub report: crate::blocktrail::TrailReport,
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

        /// Fixture [`MempoolLookup`] backed by in-memory address→UTXO and
        /// txid→transaction maps — NO network. Lets the anchor crypto, the
        /// head lookup and the per-link walk be exercised deterministically.
        struct FixtureMempool {
            utxos: HashMap<String, Vec<Utxo>>,
            txs: HashMap<String, TxInfo>,
        }
        impl FixtureMempool {
            fn empty() -> Self {
                Self {
                    utxos: HashMap::new(),
                    txs: HashMap::new(),
                }
            }
            /// Register one UTXO at `address` with no transaction behind it.
            fn with_utxo_at(address: &str) -> Self {
                let mut me = Self::empty();
                me.utxos.insert(
                    address.to_string(),
                    vec![Utxo {
                        txid: "ab".repeat(32),
                        vout: 0,
                        value: 9700,
                        confirmed: true,
                        block_height: Some(840_000),
                    }],
                );
                me
            }
            /// A whole trail on-chain: one transaction per state, each paying
            /// the key its prefix of states derives and spending the one
            /// before; the head's output is the UTXO at the derived address.
            fn with_chain(pubkey: &str, state_strings: &[String]) -> Self {
                let mut me = Self::empty();
                let outputs = bt_trail_outputs(pubkey, state_strings).unwrap();
                let mut prev = "ff".repeat(32);
                for (i, x) in outputs.iter().enumerate() {
                    let txid = sha256_hex(&format!("mark {i}"));
                    me.txs.insert(
                        txid.clone(),
                        TxInfo {
                            txid: txid.clone(),
                            vin: vec![TxIn {
                                txid: prev,
                                vout: 0,
                            }],
                            vout: vec![TxOut {
                                value: 9700 - 300 * i as u64,
                                scriptpubkey: Some(format!("5120{}", hex::encode(x))),
                                scriptpubkey_address: None,
                            }],
                            confirmed: true,
                            block_height: Some(840_000 + i as u64),
                        },
                    );
                    prev = txid;
                }
                me.utxos.insert(
                    bt_address(pubkey, state_strings, "testnet4").unwrap(),
                    vec![Utxo {
                        txid: prev,
                        vout: 0,
                        value: 9700,
                        confirmed: true,
                        block_height: Some(840_001),
                    }],
                );
                me
            }
        }
        #[async_trait::async_trait(?Send)]
        impl MempoolLookup for FixtureMempool {
            async fn address_utxos(&self, address: &str) -> Result<Vec<Utxo>, PaymentError> {
                Ok(self.utxos.get(address).cloned().unwrap_or_default())
            }
            async fn tx(&self, txid: &str) -> Result<TxInfo, PaymentError> {
                self.txs
                    .get(txid)
                    .cloned()
                    .ok_or_else(|| PaymentError::InvalidState(format!("tx {txid} not found")))
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

        /// blocktrails/git-mark b852d7d `test/gitmark.test.js`, "the live rule,
        /// pinned by the first three marks of an on-chain trail (1 Oct 2026)":
        /// base key, commits (each state is the commit as text) and the x-only
        /// outputs the chain carries. These are the git-mark profile on
        /// tbtc4; the trails this crate keeps are MRC20 on testnet4, so the
        /// pin proves the shared arithmetic (TapTweak hash, full-point
        /// addition, x-only output), not the profile.
        const GITMARK_BASE: &str =
            "0273c7f6cf0f135a63bc95a2e676bcf0a592c8b508fae8697e43f778c74e232b24";
        const GITMARK_COMMITS: [&str; 3] = [
            "9adc596cfd1100333393a12f2f41b2d820f16d0b",
            "4490c4c39e145915c59c0964b6dcd8dc720c9d2e",
            "699ee3a3ea9332cc9ec435acf8fd8cd07eecf940",
        ];
        const GITMARK_OUTPUTS: [&str; 3] = [
            "e403de73c97cb7ca2efddab823493a7b949085e40087ac97fe6884db12cc77df",
            "3ef39ed4fc2a739d8d67f59db78da7b06ac4224d9919b05f963889086e3f58f6",
            "d7abfea9a395ab2218d4a68558186ade4be4f632125f8520485e62443b3e59cf",
        ];

        fn gitmark_onchain() -> Vec<[u8; 32]> {
            GITMARK_OUTPUTS
                .iter()
                .map(|o| hex::decode(o).unwrap().try_into().unwrap())
                .collect()
        }

        #[test]
        fn gitmark_live_trail_pin() {
            let commits: Vec<String> = GITMARK_COMMITS.iter().map(|c| c.to_string()).collect();
            // each prefix's head is the mark's output (x-only of the intermediate point)
            for i in 0..commits.len() {
                let head = bt_derive_chained_pubkey(GITMARK_BASE, &commits[..=i]).unwrap();
                assert_eq!(hex::encode(&head[1..]), GITMARK_OUTPUTS[i], "mark {i}");
            }
            // a commit is hashed as its text: bt_state_string gives it back unquoted
            for c in &commits {
                assert_eq!(bt_state_string(&Value::String(c.clone())), *c);
            }
            let onchain = gitmark_onchain();
            assert_eq!(bt_trail_outputs(GITMARK_BASE, &commits).unwrap(), onchain);
            bt_verify_trail_outputs(GITMARK_BASE, &commits, &onchain).unwrap();
            // the base as a bare x reads as the 02 point; this base is 02, so it agrees
            bt_verify_trail_outputs(&GITMARK_BASE[2..], &commits, &onchain).unwrap();
            // a JSON-quoted commit is not the state: no trail was made that way
            let quoted: Vec<String> = commits.iter().map(|c| format!("\"{c}\"")).collect();
            assert!(bt_verify_trail_outputs(GITMARK_BASE, &quoted, &onchain).is_err());
        }

        /// git-mark's "every link is checked: two commits swapped ... are
        /// refused": commits 2 and 3 swapped do not give the live outputs, and
        /// the walk names the first mark that differs.
        #[test]
        fn gitmark_swapped_commits_refused() {
            let swapped: Vec<String> = [GITMARK_COMMITS[0], GITMARK_COMMITS[2], GITMARK_COMMITS[1]]
                .iter()
                .map(|c| c.to_string())
                .collect();
            let outputs = bt_trail_outputs(GITMARK_BASE, &swapped).unwrap();
            assert_eq!(hex::encode(outputs[0]), GITMARK_OUTPUTS[0]);
            assert_ne!(hex::encode(outputs[1]), GITMARK_OUTPUTS[1]);
            assert_ne!(hex::encode(outputs[2]), GITMARK_OUTPUTS[2]);
            let err = bt_verify_trail_outputs(GITMARK_BASE, &swapped, &gitmark_onchain())
                .unwrap_err()
                .to_string();
            assert!(err.contains("mismatch at index 1"), "{err}");
            // one state per mark
            let short = &swapped[..2];
            let err = bt_verify_trail_outputs(GITMARK_BASE, short, &gitmark_onchain())
                .unwrap_err()
                .to_string();
            assert!(err.contains("3 marks and 2 states"), "{err}");
        }

        /// Every network name other than `"mainnet"` and `"gitmark"` encodes
        /// with the `tb` HRP.
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

        /// TRUE path: the head UTXO sits at the derived taproot address and
        /// every mark behind it commits to its state ⇒ the anchor verifies and
        /// reports the transfer amount.
        #[test]
        fn verify_anchor_true_when_utxo_present() {
            let (genesis, next, state_strings) = valid_chain();
            let pubkey = test_pubkey_compressed();
            // Derive the SAME address the verifier will; the chain ends there.
            let address = bt_address(&pubkey, &state_strings, "testnet4").unwrap();
            let mp = FixtureMempool::with_chain(&pubkey, &state_strings);

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
            assert!(result.report.is_verified());
            assert_eq!(result.report.marks.len(), 2);
        }

        /// A UTXO at the head address with no trail behind it (the head was
        /// the only thing the earlier check looked at) no longer verifies.
        #[test]
        fn verify_anchor_false_when_head_has_no_history() {
            let (genesis, next, state_strings) = valid_chain();
            let pubkey = test_pubkey_compressed();
            let address = bt_address(&pubkey, &state_strings, "testnet4").unwrap();
            let mp = FixtureMempool::with_utxo_at(&address);
            let err = block_on(verify_mrc20_anchor(
                &next,
                &genesis,
                "recipient",
                &pubkey,
                &state_strings,
                "testnet4",
                &mp,
            ))
            .unwrap_err()
            .to_string();
            assert!(err.contains("link by link"), "{err}");
        }

        /// An intermediate mark that is not the key its state derives is
        /// refused, though the head is right.
        #[test]
        fn verify_anchor_false_when_an_earlier_mark_does_not_commit() {
            let (genesis, next, state_strings) = valid_chain();
            let pubkey = test_pubkey_compressed();
            let mut mp = FixtureMempool::with_chain(&pubkey, &state_strings);
            let genesis_txid = sha256_hex("mark 0");
            mp.txs.get_mut(&genesis_txid).unwrap().vout[0].scriptpubkey =
                Some(format!("5120{}", "22".repeat(32)));
            let err = block_on(verify_mrc20_anchor(
                &next,
                &genesis,
                "recipient",
                &pubkey,
                &state_strings,
                "testnet4",
                &mp,
            ))
            .unwrap_err()
            .to_string();
            assert!(err.contains("mark 0") && err.contains("wrong key"), "{err}");
        }

        /// A head still in the mempool is accepted, as before; its report says
        /// so (intact, not yet verified).
        #[test]
        fn verify_anchor_accepts_a_pending_head() {
            let (genesis, next, state_strings) = valid_chain();
            let pubkey = test_pubkey_compressed();
            let mut mp = FixtureMempool::with_chain(&pubkey, &state_strings);
            let head = sha256_hex("mark 1");
            mp.txs.get_mut(&head).unwrap().confirmed = false;
            let result = block_on(verify_mrc20_anchor(
                &next,
                &genesis,
                "recipient",
                &pubkey,
                &state_strings,
                "testnet4",
                &mp,
            ))
            .unwrap();
            assert!(result.report.is_intact());
            assert!(!result.report.is_verified());
            assert_eq!(
                result.report.marks[1].status,
                crate::blocktrail::MarkStatus::Unconfirmed
            );
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
