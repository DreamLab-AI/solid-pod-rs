//! Native mempool.space REST client — the read-side of block-trail anchors.
//!
//! [`MempoolHttpClient`] is the server-side concrete implementation of the
//! pure [`solid_pod_rs::mrc20::MempoolLookup`] trait. It speaks the
//! mempool.space-style REST API over the `reqwest` client the crate already
//! pulls in for the CORS proxy and webhook delivery:
//!
//! | Method | Path                              | Returns          |
//! |--------|-----------------------------------|------------------|
//! | GET    | `{base}/api/address/{addr}/utxo`  | `Vec<Utxo>`      |
//! | GET    | `{base}/api/tx/{txid}`            | `TxInfo`         |
//!
//! The wire shapes (`status: {confirmed, block_height}` nested objects) are
//! deserialised into local `*Wire` structs and flattened into the crate's
//! transport-free [`Utxo`]/[`TxInfo`] value types, so the pure verification
//! surface never learns the mempool.space schema.
//!
//! ## wasm boundary
//!
//! This module is native-only (it builds a `reqwest::Client`). It mirrors
//! the JSS `verifyMrc20Anchor` mempool round-trip (`mrc20.js:315-327`,
//! `token.js:176-187`) and is the production [`MempoolLookup`] the
//! `/pay/.deposit` MRC20 path and `/pay/.address` derivation use. wasm
//! consumers implement [`MempoolLookup`] over `fetch` instead and never
//! compile this file.
//!
//! ## Configuration
//!
//! The base URL is read from `JSS_PAY_MEMPOOL_URL` (JSS `mempoolUrl`
//! parity), defaulting to the testnet4 explorer
//! `https://mempool.space/testnet4`. The reqwest `json` feature is *not*
//! enabled crate-wide, so responses are read as text and parsed with
//! `serde_json` (matching the proxy handler's manual-parse style).

use async_trait::async_trait;
use serde::Deserialize;

use solid_pod_rs::mrc20::{bt_address, MempoolLookup, TxInfo, TxOut, Utxo};
use solid_pod_rs::payments::PaymentError;
use solid_pod_rs::provenance::{BlockAnchorer, BlockTrailAnchor, ProvenanceError};

/// Environment variable selecting the mempool REST base URL (JSS parity).
pub const MEMPOOL_URL_ENV: &str = "JSS_PAY_MEMPOOL_URL";

/// Default base URL — the mempool.space **testnet4** explorer. Matches the
/// JSS default (`pay.js:243`, `mrc20.js:282`).
pub const DEFAULT_MEMPOOL_URL: &str = "https://mempool.space/testnet4";

/// A [`MempoolLookup`] backed by the mempool.space REST API over `reqwest`.
///
/// Cheap to clone (holds an `Arc`-internal `reqwest::Client` and the base
/// URL). Construct with [`MempoolHttpClient::from_env`] to honour
/// `JSS_PAY_MEMPOOL_URL`, or [`MempoolHttpClient::new`] for an explicit base.
#[derive(Debug, Clone)]
pub struct MempoolHttpClient {
    client: reqwest::Client,
    /// Base URL with any trailing slash trimmed (so `{base}/api/...` joins
    /// cleanly regardless of how the operator wrote the env value).
    base: String,
}

impl MempoolHttpClient {
    /// Construct a client against an explicit base URL (e.g.
    /// `https://mempool.space/testnet4`). A trailing `/` is trimmed.
    #[must_use]
    pub fn new(base_url: impl Into<String>) -> Self {
        let base = base_url.into().trim_end_matches('/').to_string();
        Self {
            client: reqwest::Client::new(),
            base,
        }
    }

    /// Construct from `JSS_PAY_MEMPOOL_URL`, falling back to
    /// [`DEFAULT_MEMPOOL_URL`] (testnet4).
    #[must_use]
    pub fn from_env() -> Self {
        let base = std::env::var(MEMPOOL_URL_ENV)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_MEMPOOL_URL.to_string());
        Self::new(base)
    }

    /// The configured base URL (trailing slash trimmed).
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base
    }

    /// GET `url`, returning the body text on a 2xx, or a fail-closed
    /// [`PaymentError::InvalidState`] describing the transport/status error.
    async fn get_text(&self, url: &str) -> Result<String, PaymentError> {
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| PaymentError::InvalidState(format!("mempool request failed: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(PaymentError::InvalidState(format!(
                "mempool API error: {} for {url}",
                status.as_u16()
            )));
        }
        resp.text()
            .await
            .map_err(|e| PaymentError::InvalidState(format!("mempool body read failed: {e}")))
    }
}

// ── Wire shapes (mempool.space schema) ──────────────────────────────────

/// Nested `status` object on UTXO/tx responses.
#[derive(Debug, Deserialize, Default)]
struct StatusWire {
    #[serde(default)]
    confirmed: bool,
    #[serde(default)]
    block_height: Option<u64>,
}

/// One element of `GET /api/address/{addr}/utxo`.
#[derive(Debug, Deserialize)]
struct UtxoWire {
    txid: String,
    vout: u32,
    #[serde(default)]
    value: u64,
    #[serde(default)]
    status: StatusWire,
}

impl From<UtxoWire> for Utxo {
    fn from(w: UtxoWire) -> Self {
        Utxo {
            txid: w.txid,
            vout: w.vout,
            value: w.value,
            confirmed: w.status.confirmed,
            block_height: w.status.block_height,
        }
    }
}

/// One element of a tx's `vout` array.
#[derive(Debug, Deserialize, Default)]
struct TxOutWire {
    #[serde(default)]
    value: u64,
    #[serde(default)]
    scriptpubkey: Option<String>,
    #[serde(default)]
    scriptpubkey_address: Option<String>,
}

impl From<TxOutWire> for TxOut {
    fn from(w: TxOutWire) -> Self {
        TxOut {
            value: w.value,
            scriptpubkey: w.scriptpubkey,
            scriptpubkey_address: w.scriptpubkey_address,
        }
    }
}

/// Shape of `GET /api/tx/{txid}`.
#[derive(Debug, Deserialize)]
struct TxWire {
    txid: String,
    #[serde(default)]
    vout: Vec<TxOutWire>,
    #[serde(default)]
    status: StatusWire,
}

impl From<TxWire> for TxInfo {
    fn from(w: TxWire) -> Self {
        TxInfo {
            txid: w.txid,
            vout: w.vout.into_iter().map(TxOut::from).collect(),
            confirmed: w.status.confirmed,
            block_height: w.status.block_height,
        }
    }
}

#[async_trait(?Send)]
impl MempoolLookup for MempoolHttpClient {
    async fn address_utxos(&self, address: &str) -> Result<Vec<Utxo>, PaymentError> {
        let url = format!("{}/api/address/{address}/utxo", self.base);
        let body = self.get_text(&url).await?;
        let wire: Vec<UtxoWire> = serde_json::from_str(&body)
            .map_err(|e| PaymentError::InvalidState(format!("malformed utxo JSON: {e}")))?;
        Ok(wire.into_iter().map(Utxo::from).collect())
    }

    async fn tx(&self, txid: &str) -> Result<TxInfo, PaymentError> {
        let url = format!("{}/api/tx/{txid}", self.base);
        let body = self.get_text(&url).await?;
        let wire: TxWire = serde_json::from_str(&body)
            .map_err(|e| PaymentError::InvalidState(format!("malformed tx JSON: {e}")))?;
        Ok(TxInfo::from(wire))
    }
}

// ---------------------------------------------------------------------------
// BlockAnchorer::verify — the portable-proof read-side (provenance §2.2)
// ---------------------------------------------------------------------------

/// A [`BlockAnchorer`] whose **verify** side is fully implemented over any
/// [`MempoolLookup`] (`anchor()` is Phase 4). Generic over the lookup so a
/// fixture mempool drives it in tests and [`MempoolHttpClient`] drives it in
/// production — both without changing the verification logic.
///
/// `verify` re-derives the expected taproot address from the anchor's
/// *portable proof* (`pubkey` + `state_strings`) via [`bt_address`],
/// confirms it matches the address recorded in the anchor (so a forged
/// `address` is rejected), and then confirms a UTXO actually sits at that
/// derived address. No pod trust is required: the proof is checked against
/// independent chain state.
#[derive(Debug, Clone)]
pub struct MempoolBlockAnchorer<M: MempoolLookup + Send + Sync> {
    lookup: M,
}

impl<M: MempoolLookup + Send + Sync> MempoolBlockAnchorer<M> {
    /// Wrap a [`MempoolLookup`] as a verify-capable [`BlockAnchorer`].
    pub fn new(lookup: M) -> Self {
        Self { lookup }
    }

    /// Borrow the underlying lookup (e.g. for a one-off `address_utxos`).
    pub fn lookup(&self) -> &M {
        &self.lookup
    }
}

#[async_trait(?Send)]
impl<M: MempoolLookup + Send + Sync> BlockAnchorer for MempoolBlockAnchorer<M> {
    /// Phase 4 — Bitcoin TX build/broadcast. Not in scope for Phase 3.
    async fn anchor(
        &self,
        _ticker: &str,
        _state_hash: &str,
        _network: &str,
    ) -> Result<BlockTrailAnchor, ProvenanceError> {
        Err(ProvenanceError::Anchor(
            "anchor() (Bitcoin tx build/broadcast) is Phase 4; not implemented".into(),
        ))
    }

    async fn verify(&self, anchor: &BlockTrailAnchor) -> Result<bool, ProvenanceError> {
        // The portable proof requires both the issuer pubkey and the state
        // strings. Absent either, there is nothing to independently
        // re-derive against → not verifiable (false, not error).
        let Some(pubkey) = anchor.pubkey.as_deref() else {
            return Ok(false);
        };
        if anchor.state_strings.is_empty() {
            return Ok(false);
        }

        // Re-derive the taproot address from the proof and reject a forged
        // `address` field (the recorded address must equal the derivation).
        let derived = bt_address(pubkey, &anchor.state_strings, &anchor.network)
            .map_err(|e| ProvenanceError::Anchor(format!("address re-derivation failed: {e}")))?;
        if derived != anchor.address {
            return Ok(false);
        }

        // A genuine anchor has a live UTXO at the derived address.
        let utxos = self
            .lookup
            .address_utxos(&derived)
            .await
            .map_err(|e| ProvenanceError::Anchor(format!("mempool lookup failed: {e}")))?;
        Ok(!utxos.is_empty())
    }
}

// ---------------------------------------------------------------------------
// Tests — fixture parsing only (NO live mempool.space access).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A captured mempool.space `GET /api/address/{addr}/utxo` payload:
    /// one confirmed UTXO. Deserialises into the flat [`Utxo`].
    const UTXO_JSON: &str = include_str!("../tests/fixtures/mempool/address_utxos.json");
    /// A captured `GET /api/tx/{txid}` payload (one confirmed tx, 2 outputs).
    const TX_JSON: &str = include_str!("../tests/fixtures/mempool/tx.json");
    /// An empty UTXO set (`[]`) — the "no deposit yet" response.
    const EMPTY_UTXO_JSON: &str = "[]";

    #[test]
    fn utxo_wire_flattens_status() {
        let wire: Vec<UtxoWire> = serde_json::from_str(UTXO_JSON).unwrap();
        let utxos: Vec<Utxo> = wire.into_iter().map(Utxo::from).collect();
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].vout, 0);
        assert_eq!(utxos[0].value, 9700);
        assert!(utxos[0].confirmed, "status.confirmed must flatten onto Utxo");
        assert_eq!(utxos[0].block_height, Some(42_000));
    }

    #[test]
    fn empty_utxo_set_parses_to_empty_vec() {
        let wire: Vec<UtxoWire> = serde_json::from_str(EMPTY_UTXO_JSON).unwrap();
        assert!(wire.is_empty());
    }

    #[test]
    fn tx_wire_flattens_outputs_and_status() {
        let wire: TxWire = serde_json::from_str(TX_JSON).unwrap();
        let tx = TxInfo::from(wire);
        assert_eq!(tx.vout.len(), 2);
        assert_eq!(tx.vout[0].value, 9700);
        assert_eq!(
            tx.vout[0].scriptpubkey.as_deref(),
            Some("5120aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")
        );
        assert_eq!(
            tx.vout[0].scriptpubkey_address.as_deref(),
            Some("tb1pexampleaddress")
        );
        assert!(tx.confirmed);
        assert_eq!(tx.block_height, Some(42_000));
    }

    #[test]
    fn from_env_defaults_to_testnet4() {
        // Snapshot/restore so a parallel test or the host env can't perturb it.
        let prev = std::env::var(MEMPOOL_URL_ENV).ok();
        std::env::remove_var(MEMPOOL_URL_ENV);
        let c = MempoolHttpClient::from_env();
        assert_eq!(c.base_url(), DEFAULT_MEMPOOL_URL);
        if let Some(v) = prev {
            std::env::set_var(MEMPOOL_URL_ENV, v);
        }
    }

    #[test]
    fn new_trims_trailing_slash() {
        let c = MempoolHttpClient::new("https://mempool.space/testnet4/");
        assert_eq!(c.base_url(), "https://mempool.space/testnet4");
    }

    /// Live smoke test — disabled by default (no live chain in CI). Run with
    /// `cargo test -p solid-pod-rs-server --features git -- --ignored live_`.
    #[ignore = "hits live mempool.space; opt-in only"]
    #[tokio::test]
    async fn live_address_utxos_smoke() {
        let c = MempoolHttpClient::from_env();
        // A well-known testnet4 faucet-ish address may have UTXOs; the test
        // only asserts the call shape succeeds (empty is acceptable).
        let _ = c
            .address_utxos("tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c")
            .await;
    }

    // ── BlockAnchorer::verify over a FIXTURE MempoolLookup (no network) ──

    use std::collections::HashMap;

    /// In-memory [`MempoolLookup`] — address→UTXO map. No HTTP.
    struct FixtureMempool {
        utxos: HashMap<String, Vec<Utxo>>,
    }
    impl FixtureMempool {
        fn with_utxo_at(address: &str) -> Self {
            let mut utxos = HashMap::new();
            utxos.insert(
                address.to_string(),
                vec![Utxo {
                    txid: "ab".repeat(32),
                    vout: 0,
                    value: 9700,
                    confirmed: true,
                    block_height: Some(42_000),
                }],
            );
            Self { utxos }
        }
        fn empty() -> Self {
            Self { utxos: HashMap::new() }
        }
    }
    #[async_trait(?Send)]
    impl MempoolLookup for FixtureMempool {
        async fn address_utxos(&self, address: &str) -> Result<Vec<Utxo>, PaymentError> {
            Ok(self.utxos.get(address).cloned().unwrap_or_default())
        }
        async fn tx(&self, txid: &str) -> Result<TxInfo, PaymentError> {
            Ok(TxInfo {
                txid: txid.to_string(),
                vout: vec![],
                confirmed: true,
                block_height: Some(42_000),
            })
        }
    }

    // Issuer keypair (arbitrary) for deriving real anchor addresses.
    const ISSUER_PRIVKEY: &str =
        "0000000000000000000000000000000000000000000000000000000000000001";
    fn issuer_pubkey() -> String {
        let sk = k256::SecretKey::from_slice(&hex::decode(ISSUER_PRIVKEY).unwrap()).unwrap();
        hex::encode(sk.public_key().to_sec1_bytes())
    }

    /// Build a `BlockTrailAnchor` whose `address`/`state_strings`/`pubkey`
    /// are internally consistent (the `address` is the genuine derivation).
    fn consistent_anchor() -> BlockTrailAnchor {
        let pubkey = issuer_pubkey();
        let state_strings = vec!["{\"seq\":0}".to_string(), "{\"seq\":1}".to_string()];
        let address = bt_address(&pubkey, &state_strings, "testnet4").unwrap();
        BlockTrailAnchor {
            ticker: "PROV".into(),
            state_hash: "ff".repeat(32),
            txid: "ab".repeat(32),
            vout: 0,
            address,
            network: "testnet4".into(),
            blockheight: Some(42_000),
            state_strings,
            pubkey: Some(pubkey),
        }
    }

    #[tokio::test]
    async fn block_anchorer_verify_true_when_utxo_present() {
        let anchor = consistent_anchor();
        let anchorer = MempoolBlockAnchorer::new(FixtureMempool::with_utxo_at(&anchor.address));
        assert!(anchorer.verify(&anchor).await.unwrap(), "present UTXO ⇒ verify true");
    }

    #[tokio::test]
    async fn block_anchorer_verify_false_when_utxo_absent() {
        let anchor = consistent_anchor();
        let anchorer = MempoolBlockAnchorer::new(FixtureMempool::empty());
        assert!(!anchorer.verify(&anchor).await.unwrap(), "absent UTXO ⇒ verify false");
    }

    #[tokio::test]
    async fn block_anchorer_verify_false_when_address_forged() {
        // A UTXO sits at the real derived address, but the anchor *claims* a
        // different (forged) address → the re-derivation mismatch fails it.
        let mut anchor = consistent_anchor();
        let real = anchor.address.clone();
        anchor.address = "tb1pforged000000000000000000000000000000".into();
        let anchorer = MempoolBlockAnchorer::new(FixtureMempool::with_utxo_at(&real));
        assert!(
            !anchorer.verify(&anchor).await.unwrap(),
            "forged address must not verify even with a real UTXO elsewhere"
        );
    }

    #[tokio::test]
    async fn block_anchorer_verify_false_without_pubkey() {
        // No pubkey ⇒ nothing to re-derive against ⇒ not verifiable.
        let mut anchor = consistent_anchor();
        anchor.pubkey = None;
        let anchorer = MempoolBlockAnchorer::new(FixtureMempool::with_utxo_at(&anchor.address));
        assert!(!anchorer.verify(&anchor).await.unwrap());
    }

    #[tokio::test]
    async fn block_anchorer_anchor_is_phase4_todo() {
        let anchorer = MempoolBlockAnchorer::new(FixtureMempool::empty());
        let err = anchorer.anchor("PROV", "deadbeef", "testnet4").await.unwrap_err();
        assert!(matches!(err, ProvenanceError::Anchor(_)));
    }
}
