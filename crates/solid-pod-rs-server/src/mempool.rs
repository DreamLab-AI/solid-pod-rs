//! Native mempool.space REST client — the read-side of block-trail anchors.
//!
//! [`MempoolHttpClient`](crate::mempool::MempoolHttpClient) is the server-side concrete implementation of the
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
//! transport-free [`Utxo`](solid_pod_rs::mrc20::Utxo)/[`TxInfo`](solid_pod_rs::mrc20::TxInfo) value types, so the pure verification
//! surface never learns the mempool.space schema.
//!
//! ## wasm boundary
//!
//! This module is native-only (it builds a `reqwest::Client`). It mirrors
//! the JSS `verifyMrc20Anchor` mempool round-trip (`mrc20.js:315-327`,
//! `token.js:176-187`) and is the production [`MempoolLookup`](solid_pod_rs::mrc20::MempoolLookup) the
//! `/pay/.deposit` MRC20 path and `/pay/.address` derivation use. wasm
//! consumers implement [`MempoolLookup`](solid_pod_rs::mrc20::MempoolLookup) over `fetch` instead and never
//! compile this file.
//!
//! ## Configuration
//!
//! The base URL is read from `JSS_PAY_MEMPOOL_URL` (JSS `mempoolUrl`
//! parity), defaulting to the testnet4 explorer
//! `https://mempool.space/testnet4`. The reqwest `json` feature is *not*
//! enabled crate-wide, so responses are read as text and parsed with
//! `serde_json` (matching the proxy handler's manual-parse style).
//!
//! The endpoint choice is not silent: [`select_mempool_endpoint`] resolves the
//! base URL, [`infer_network`] classifies the Bitcoin network it serves, and
//! [`log_mempool_selection`] records both (plus whether the URL was
//! operator-supplied or defaulted) in the startup log — with a warning when the
//! pod would otherwise be anchoring against an unchosen or unclassifiable
//! chain. [`MempoolSelection::to_manifest_json`] renders the same facts for a
//! manifest (ADR-2007).

use async_trait::async_trait;
use serde::Deserialize;

use solid_pod_rs::bitcoin_tx::{anchor_state, MempoolBroadcast};
use solid_pod_rs::mrc20::{bt_address, MempoolLookup, TxInfo, TxOut, Utxo};
use solid_pod_rs::payments::PaymentError;
use solid_pod_rs::provenance::{BlockAnchorer, BlockTrailAnchor, ProvenanceError};

/// Environment variable selecting the mempool REST base URL (JSS parity).
pub const MEMPOOL_URL_ENV: &str = "JSS_PAY_MEMPOOL_URL";

/// Default base URL — the mempool.space **testnet4** explorer. Matches the
/// JSS default (`pay.js:243`, `mrc20.js:282`).
pub const DEFAULT_MEMPOOL_URL: &str = "https://mempool.space/testnet4";

// ---------------------------------------------------------------------------
// Endpoint selection (ADR-2007) — pure, no I/O
// ---------------------------------------------------------------------------
//
// The base URL alone does not tell an operator *why* the pod is pointed where
// it is, nor which Bitcoin network that endpoint serves. A silent fall back to
// the built-in testnet4 default could otherwise have the pod anchoring and
// verifying against a chain nobody chose. The types below make the choice
// explicit, classifiable and loggable without performing any I/O, so the
// startup path can record it in the log and in a manifest.

/// Where the mempool base URL came from.
///
/// [`MempoolConfigSource::Explicit`] means an operator supplied it (via
/// [`MEMPOOL_URL_ENV`] or [`MempoolHttpClient::new`]);
/// [`MempoolConfigSource::Default`] means nothing was configured and the
/// built-in [`DEFAULT_MEMPOOL_URL`] was used. The distinction matters because a
/// defaulted endpoint is an *unchosen* chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MempoolConfigSource {
    /// The operator supplied the base URL.
    Explicit,
    /// Nothing was configured; [`DEFAULT_MEMPOOL_URL`] was used.
    Default,
}

impl MempoolConfigSource {
    /// Lower-case wire name (`"explicit"` / `"default"`) used in logs and the
    /// manifest JSON.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::Default => "default",
        }
    }
}

impl std::fmt::Display for MempoolConfigSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The Bitcoin network a mempool endpoint is understood to serve.
///
/// [`BitcoinNetwork::Unknown`] is deliberate: an unrecognised operator-supplied
/// explorer is *not* assumed to be mainnet (or anything else). Guessing here
/// would reintroduce exactly the silent-wrong-chain risk this type exists to
/// remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinNetwork {
    /// Bitcoin mainnet.
    Mainnet,
    /// The legacy testnet3 network (`/testnet` or `/testnet3`).
    Testnet3,
    /// The testnet4 network (the crate default).
    Testnet4,
    /// The signet test network.
    Signet,
    /// A local regtest node (loopback host with no network in the path).
    Regtest,
    /// Not classifiable from the URL — treat as unverified.
    Unknown,
}

impl BitcoinNetwork {
    /// Lower-case wire name used in logs and the manifest JSON.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet3 => "testnet3",
            Self::Testnet4 => "testnet4",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for BitcoinNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Classify the Bitcoin network a mempool base URL serves, purely from the URL.
///
/// The trailing path segment is matched case-insensitively against the
/// mempool.space layout:
///
/// | Base URL                         | Network    |
/// |----------------------------------|------------|
/// | `https://mempool.space`          | `Mainnet`  |
/// | `https://mempool.space/testnet4` | `Testnet4` |
/// | `https://mempool.space/testnet`  | `Testnet3` |
/// | `https://mempool.space/testnet3` | `Testnet3` |
/// | `https://mempool.space/signet`   | `Signet`   |
/// | `http://127.0.0.1:3006`          | `Regtest`  |
/// | anything else                    | `Unknown`  |
///
/// A loopback host is taken to be a local regtest node *unless* its path names a
/// network explicitly (`http://localhost:3006/signet` is `Signet`). Anything
/// unrecognised is [`BitcoinNetwork::Unknown`] — never a guess.
#[must_use]
pub fn infer_network(base_url: &str) -> BitcoinNetwork {
    let trimmed = base_url.trim().trim_end_matches('/');

    // Split scheme / authority / path by hand: the base may legitimately be
    // scheme-relative in a fixture, and a full URL parser would reject it.
    let after_scheme = match trimmed.find("://") {
        Some(i) => &trimmed[i + 3..],
        None => trimmed,
    };
    let (authority, path) = match after_scheme.find('/') {
        Some(i) => (&after_scheme[..i], &after_scheme[i + 1..]),
        None => (after_scheme, ""),
    };

    // Last non-empty path segment, ignoring any query/fragment tail.
    let path = path
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .trim_end_matches('/');
    let last_segment = path.rsplit('/').find(|seg| !seg.is_empty()).unwrap_or("");

    match last_segment.to_ascii_lowercase().as_str() {
        "testnet4" => return BitcoinNetwork::Testnet4,
        "testnet" | "testnet3" => return BitcoinNetwork::Testnet3,
        "signet" => return BitcoinNetwork::Signet,
        "regtest" => return BitcoinNetwork::Regtest,
        "mainnet" | "bitcoin" => return BitcoinNetwork::Mainnet,
        _ => {}
    }

    // Host (minus any userinfo / port) drives the remaining cases.
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = if let Some(rest) = host.strip_prefix('[') {
        // Bracketed IPv6 literal: keep the address, drop the port.
        rest.split(']').next().unwrap_or(rest)
    } else {
        host.split(':').next().unwrap_or(host)
    };
    let host_lower = host.to_ascii_lowercase();

    let is_loopback = host_lower == "localhost"
        || host_lower == "::1"
        || host_lower.starts_with("127.")
        || host_lower.ends_with(".localhost");
    if is_loopback {
        // A local node with no network in the path is a regtest node.
        return BitcoinNetwork::Regtest;
    }

    // A bare mempool.space-style host with no network path is mainnet.
    if path.is_empty() && (host_lower == "mempool.space" || host_lower.ends_with(".mempool.space"))
    {
        return BitcoinNetwork::Mainnet;
    }

    BitcoinNetwork::Unknown
}

/// The resolved mempool endpoint: which URL, which chain, and why.
///
/// Produced by [`select_mempool_endpoint`] /
/// [`select_mempool_endpoint_from_env`] and carried on [`MempoolHttpClient`] so
/// the choice can be logged at startup ([`log_mempool_selection`]) and surfaced
/// in a manifest ([`MempoolSelection::to_manifest_json`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MempoolSelection {
    /// The base URL actually in use, trailing slash trimmed.
    pub base_url: String,
    /// The Bitcoin network inferred from `base_url`.
    pub network: BitcoinNetwork,
    /// Whether `base_url` was operator-supplied or the built-in default.
    pub source: MempoolConfigSource,
}

impl MempoolSelection {
    /// Render the selection as manifest JSON:
    /// `{"base_url": …, "network": …, "source": "explicit"|"default"}`.
    #[must_use]
    pub fn to_manifest_json(&self) -> serde_json::Value {
        serde_json::json!({
            "base_url": self.base_url,
            "network": self.network.as_str(),
            "source": self.source.as_str(),
        })
    }
}

/// Resolve the mempool endpoint from an optional configured value.
///
/// A `configured` value that is `None`, empty or whitespace-only is treated as
/// absent (matching the historical `JSS_PAY_MEMPOOL_URL` filter), yielding
/// [`DEFAULT_MEMPOOL_URL`] with [`MempoolConfigSource::Default`]. Any trailing
/// `/` is trimmed so `{base}/api/...` joins cleanly. Pure — no environment or
/// network access.
#[must_use]
pub fn select_mempool_endpoint(configured: Option<&str>) -> MempoolSelection {
    let (raw, source) = match configured.map(str::trim).filter(|v| !v.is_empty()) {
        Some(v) => (v, MempoolConfigSource::Explicit),
        None => (DEFAULT_MEMPOOL_URL, MempoolConfigSource::Default),
    };
    let base_url = raw.trim_end_matches('/').to_string();
    let network = infer_network(&base_url);
    MempoolSelection {
        base_url,
        network,
        source,
    }
}

/// Resolve the mempool endpoint from [`MEMPOOL_URL_ENV`], delegating the (pure)
/// decision to [`select_mempool_endpoint`].
#[must_use]
pub fn select_mempool_endpoint_from_env() -> MempoolSelection {
    let configured = std::env::var(MEMPOOL_URL_ENV).ok();
    select_mempool_endpoint(configured.as_deref())
}

/// Record the selected endpoint in the startup log.
///
/// Emits exactly one `INFO` on target `solid_pod_rs_server::mempool` carrying
/// the structured fields `base_url`, `network` and `source`, so an operator can
/// tell from the log which chain the pod anchors and verifies against. When the
/// network could not be classified, or the endpoint was defaulted rather than
/// chosen, an additional `WARN` names [`MEMPOOL_URL_ENV`] as the fix.
pub fn log_mempool_selection(sel: &MempoolSelection) {
    tracing::info!(
        target: "solid_pod_rs_server::mempool",
        base_url = %sel.base_url,
        network = sel.network.as_str(),
        source = sel.source.as_str(),
        "mempool endpoint selected"
    );
    if sel.network == BitcoinNetwork::Unknown || sel.source == MempoolConfigSource::Default {
        tracing::warn!(
            target: "solid_pod_rs_server::mempool",
            base_url = %sel.base_url,
            network = sel.network.as_str(),
            source = sel.source.as_str(),
            env_var = MEMPOOL_URL_ENV,
            "pod is using an unverified or defaulted Bitcoin endpoint; anchors may be \
             written to or verified against an unintended chain — set {} to pin the \
             explorer, and therefore the network, explicitly",
            MEMPOOL_URL_ENV
        );
    }
}

/// Emit [`log_mempool_selection`] at most once for the lifetime of the
/// process.
///
/// `MempoolHttpClient::from_env` is called per request on the payment and
/// provenance routes, so logging unconditionally there would repeat the
/// startup record on every request. The selection is process-global (it comes
/// from an environment variable), so one record is exactly the right number:
/// it lands in the startup log the first time the endpoint is resolved, and
/// `solid-pod-rs-server`'s `main` calls this explicitly at boot so the record
/// appears even on a pod that never serves a payment route.
///
/// Callers that want the value rather than the log should read
/// [`MempoolHttpClient::selection`] or call [`select_mempool_endpoint`].
pub fn log_mempool_selection_once(sel: &MempoolSelection) {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| log_mempool_selection(sel));
}

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
    /// The resolved endpoint choice — URL, inferred network, and where the URL
    /// came from — so the selection is recordable rather than an invisible
    /// default (ADR-2007).
    selection: MempoolSelection,
}

impl MempoolHttpClient {
    /// Construct a client against an explicit base URL (e.g.
    /// `https://mempool.space/testnet4`). A trailing `/` is trimmed.
    #[must_use]
    pub fn new(base_url: impl Into<String>) -> Self {
        let raw = base_url.into();
        let base = raw.trim_end_matches('/').to_string();
        // An explicit constructor argument is operator-chosen by definition,
        // even when it happens to equal DEFAULT_MEMPOOL_URL.
        let selection = MempoolSelection {
            network: infer_network(&base),
            base_url: base,
            source: MempoolConfigSource::Explicit,
        };
        Self::from_selection(selection)
    }

    /// Construct from an already-resolved [`MempoolSelection`]. Does not log —
    /// the caller owns whether this choice is recorded (see
    /// [`log_mempool_selection`]).
    #[must_use]
    pub fn from_selection(selection: MempoolSelection) -> Self {
        Self {
            client: reqwest::Client::new(),
            base: selection.base_url.clone(),
            selection,
        }
    }

    /// Construct from `JSS_PAY_MEMPOOL_URL`, falling back to
    /// [`DEFAULT_MEMPOOL_URL`] (testnet4).
    ///
    /// The resolved endpoint is logged exactly once via
    /// [`log_mempool_selection`], so the startup log always records which
    /// explorer — and therefore which Bitcoin network — the pod is using, with
    /// a warning when that endpoint was defaulted or is unclassifiable.
    #[must_use]
    pub fn from_env() -> Self {
        let selection = select_mempool_endpoint_from_env();
        log_mempool_selection_once(&selection);
        Self::from_selection(selection)
    }

    /// The configured base URL (trailing slash trimmed).
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base
    }

    /// The resolved endpoint selection: base URL, inferred Bitcoin network, and
    /// whether the URL was operator-supplied or defaulted.
    #[must_use]
    pub fn selection(&self) -> &MempoolSelection {
        &self.selection
    }

    /// Check whether a transaction is known without collapsing an HTTP 404
    /// into the same result as an ambiguous transport/server failure. Payment
    /// intent recovery may compensate a debit only for `Ok(false)`.
    pub async fn transaction_exists(&self, txid: &str) -> Result<bool, PaymentError> {
        let url = format!("{}/api/tx/{txid}", self.base);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| PaymentError::InvalidState(format!("mempool request failed: {e}")))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        if !resp.status().is_success() {
            return Err(PaymentError::InvalidState(format!(
                "mempool API error: {} for {url}",
                resp.status().as_u16()
            )));
        }
        Ok(true)
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

    /// POST `body` as `text/plain` to `url`, returning the response body on a
    /// 2xx (the txid, for `/api/tx`) or a fail-closed
    /// [`PaymentError::InvalidState`]. Mirrors JSS `broadcastTx`
    /// (`token.js:176-187`).
    async fn post_text(&self, url: &str, body: &str) -> Result<String, PaymentError> {
        let resp = self
            .client
            .post(url)
            .header("Content-Type", "text/plain")
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| PaymentError::InvalidState(format!("mempool broadcast failed: {e}")))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| PaymentError::InvalidState(format!("mempool body read failed: {e}")))?;
        if !status.is_success() {
            return Err(PaymentError::InvalidState(format!(
                "broadcast rejected ({}): {text}",
                status.as_u16()
            )));
        }
        Ok(text.trim().to_string())
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

#[async_trait(?Send)]
impl MempoolBroadcast for MempoolHttpClient {
    async fn broadcast_tx(&self, raw_hex: &str) -> Result<String, PaymentError> {
        let url = format!("{}/api/tx", self.base);
        self.post_text(&url, raw_hex).await
    }
}

// ---------------------------------------------------------------------------
// BlockAnchorer::verify — the portable-proof read-side (provenance §2.2)
// ---------------------------------------------------------------------------

/// A [`BlockAnchorer`] implementing **both** sides over a transport that can
/// look up UTXOs ([`MempoolLookup`]) and broadcast transactions
/// ([`MempoolBroadcast`]). Generic over that transport so a fixture drives it
/// in tests and [`MempoolHttpClient`] drives it in production — without
/// changing the logic.
///
/// - `verify` (Phase 3) re-derives the expected taproot address from the
///   anchor's *portable proof* (`pubkey` + `state_strings`) via [`bt_address`],
///   rejects a forged `address`, and confirms a UTXO sits at the derived
///   address. No pod trust required.
/// - `anchor` (Phase 4) loads the named trail from storage, appends an MRC20
///   state notarising `state_hash` (via
///   [`anchor_state`], broadcasts the
///   anchoring tx, persists the updated trail, and returns the
///   [`BlockTrailAnchor`] (txid/vout/address/state_strings/pubkey). It requires
///   a `storage` handle (set via [`MempoolBlockAnchorer::with_storage`]); the
///   verify-only constructor [`MempoolBlockAnchorer::new`] leaves it `None` and
///   `anchor()` then errors with a clear message.
#[derive(Clone)]
pub struct MempoolBlockAnchorer<M: MempoolLookup + MempoolBroadcast + Send + Sync> {
    lookup: M,
    storage: Option<std::sync::Arc<dyn solid_pod_rs::storage::Storage>>,
}

impl<M: MempoolLookup + MempoolBroadcast + Send + Sync> MempoolBlockAnchorer<M> {
    /// Wrap a transport as a **verify-capable** [`BlockAnchorer`]. `anchor()`
    /// is unavailable (no storage) and returns an error explaining that
    /// [`with_storage`](Self::with_storage) is required.
    pub fn new(lookup: M) -> Self {
        Self {
            lookup,
            storage: None,
        }
    }

    /// Wrap a transport + pod storage as a **fully-capable** [`BlockAnchorer`]
    /// (both `verify` and `anchor`). The `storage` backs the trail load/save at
    /// `/.well-known/token/{ticker}.json`.
    pub fn with_storage(
        lookup: M,
        storage: std::sync::Arc<dyn solid_pod_rs::storage::Storage>,
    ) -> Self {
        Self {
            lookup,
            storage: Some(storage),
        }
    }

    /// Borrow the underlying transport (e.g. for a one-off `address_utxos`).
    pub fn lookup(&self) -> &M {
        &self.lookup
    }
}

#[async_trait(?Send)]
impl<M: MempoolLookup + MempoolBroadcast + Send + Sync> BlockAnchorer for MempoolBlockAnchorer<M> {
    /// Append one MRC20 state anchoring `state_hash` under `ticker`, build +
    /// broadcast the anchoring tx, persist the updated trail, and return the
    /// produced [`BlockTrailAnchor`]. This is the expensive-tier write the
    /// provenance design hinges on (ADR-059 §2.2, master-plan Phase 4).
    ///
    /// `network` is honoured as a guard: it must match the trail's own network
    /// (the trail's chained-key addresses are network-bound). The returned
    /// anchor's `vout` is `0` (the anchoring tx pays the next chained-key UTXO
    /// at output 0); `blockheight` is `None` until the tx confirms.
    async fn anchor(
        &self,
        ticker: &str,
        state_hash: &str,
        network: &str,
    ) -> Result<BlockTrailAnchor, ProvenanceError> {
        use crate::trail_store::{load_trail, save_trail};
        use solid_pod_rs::bitcoin_tx::DEFAULT_FEE_SATS;

        let storage = self.storage.as_ref().ok_or_else(|| {
            ProvenanceError::Anchor(
                "anchor() requires storage; construct with MempoolBlockAnchorer::with_storage"
                    .into(),
            )
        })?;

        // Load the trail that will carry the anchor (JSS `loadTrail`).
        let mut stored = load_trail(storage, ticker)
            .await
            .map_err(|e| ProvenanceError::Anchor(format!("load trail {ticker}: {e}")))?
            .ok_or_else(|| {
                ProvenanceError::Anchor(format!("trail {ticker} not minted on this pod"))
            })?;

        if stored.network != network {
            return Err(ProvenanceError::Anchor(format!(
                "network mismatch: trail is {}, requested {network}",
                stored.network
            )));
        }

        // Build the anchoring tx (appends a state notarising `state_hash`).
        let public = stored.to_public();
        let update = anchor_state(
            &public,
            &stored.privkey,
            state_hash,
            DEFAULT_FEE_SATS,
            &self.lookup,
        )
        .await
        .map_err(|e| ProvenanceError::Anchor(format!("build anchoring tx: {e}")))?;

        // Broadcast (JSS `broadcastTx`). The returned txid IS the anchoring tx.
        let txid = self
            .lookup
            .broadcast_tx(&update.tx.raw_hex)
            .await
            .map_err(|e| ProvenanceError::Anchor(format!("broadcast anchoring tx: {e}")))?;

        // Persist the appended trail with the broadcast txid as the new
        // currentTxid (so the next anchor/transfer spends this output).
        let mut appended = update.trail.clone();
        appended.current_txid = txid.clone();
        stored.merge_public(&appended);
        stored.current_txid = txid.clone();
        stored.current_vout = 0;
        save_trail(storage, &stored)
            .await
            .map_err(|e| ProvenanceError::Anchor(format!("save trail: {e}")))?;

        Ok(BlockTrailAnchor {
            ticker: ticker.to_string(),
            state_hash: state_hash.to_string(),
            txid,
            vout: 0,
            address: update.address,
            network: network.to_string(),
            blockheight: None,
            state_strings: appended.state_strings,
            pubkey: Some(stored.pubkey_base),
        })
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
        assert!(
            utxos[0].confirmed,
            "status.confirmed must flatten onto Utxo"
        );
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

    /// In-memory [`MempoolLookup`] + [`MempoolBroadcast`] — address→UTXO and
    /// txid→outputs maps. No HTTP. Interior mutability so the broadcast side
    /// can record raw txs and the anchor round-trip can register the spent
    /// output's scriptPubKey.
    #[derive(Clone, Default)]
    struct FixtureMempool {
        utxos: std::sync::Arc<std::sync::Mutex<HashMap<String, Vec<Utxo>>>>,
        txs: std::sync::Arc<std::sync::Mutex<HashMap<String, Vec<TxOut>>>>,
        broadcasts: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }
    impl FixtureMempool {
        fn with_utxo_at(address: &str) -> Self {
            let me = Self::default();
            me.utxos.lock().unwrap().insert(
                address.to_string(),
                vec![Utxo {
                    txid: "ab".repeat(32),
                    vout: 0,
                    value: 9700,
                    confirmed: true,
                    block_height: Some(42_000),
                }],
            );
            me
        }
        fn empty() -> Self {
            Self::default()
        }
        fn add_output(&self, txid: &str, vout: u32, spk_hex: &str) {
            let mut txs = self.txs.lock().unwrap();
            let outs = txs.entry(txid.to_string()).or_default();
            while outs.len() <= vout as usize {
                outs.push(TxOut {
                    value: 0,
                    scriptpubkey: None,
                    scriptpubkey_address: None,
                });
            }
            outs[vout as usize] = TxOut {
                value: 0,
                scriptpubkey: Some(spk_hex.to_string()),
                scriptpubkey_address: None,
            };
        }
    }
    #[async_trait(?Send)]
    impl MempoolLookup for FixtureMempool {
        async fn address_utxos(&self, address: &str) -> Result<Vec<Utxo>, PaymentError> {
            Ok(self
                .utxos
                .lock()
                .unwrap()
                .get(address)
                .cloned()
                .unwrap_or_default())
        }
        async fn tx(&self, txid: &str) -> Result<TxInfo, PaymentError> {
            Ok(TxInfo {
                txid: txid.to_string(),
                vout: self
                    .txs
                    .lock()
                    .unwrap()
                    .get(txid)
                    .cloned()
                    .unwrap_or_default(),
                confirmed: true,
                block_height: Some(42_000),
            })
        }
    }
    #[async_trait(?Send)]
    impl MempoolBroadcast for FixtureMempool {
        async fn broadcast_tx(&self, raw_hex: &str) -> Result<String, PaymentError> {
            // Synthetic, stable txid (sha256 of raw hex) — crypto correctness
            // is asserted elsewhere; the chain-walk only needs uniqueness.
            let txid = solid_pod_rs::mrc20::sha256_hex(raw_hex);
            self.broadcasts.lock().unwrap().push(raw_hex.to_string());
            Ok(txid)
        }
    }

    // Issuer keypair (arbitrary) for deriving real anchor addresses.
    const ISSUER_PRIVKEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
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
        assert!(
            anchorer.verify(&anchor).await.unwrap(),
            "present UTXO ⇒ verify true"
        );
    }

    #[tokio::test]
    async fn block_anchorer_verify_false_when_utxo_absent() {
        let anchor = consistent_anchor();
        let anchorer = MempoolBlockAnchorer::new(FixtureMempool::empty());
        assert!(
            !anchorer.verify(&anchor).await.unwrap(),
            "absent UTXO ⇒ verify false"
        );
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
    async fn block_anchorer_anchor_requires_storage() {
        // The verify-only constructor leaves storage None ⇒ anchor() errors
        // with a clear message rather than panicking.
        let anchorer = MempoolBlockAnchorer::new(FixtureMempool::empty());
        let err = anchorer
            .anchor("PROV", "deadbeef", "testnet4")
            .await
            .unwrap_err();
        match err {
            ProvenanceError::Anchor(m) => assert!(m.contains("with_storage")),
            other => panic!("expected Anchor(requires storage), got {other:?}"),
        }
    }

    // ── Phase 4: full anchor() round-trip (mint → store → anchor → verify) ──

    use crate::trail_store::{load_trail, save_trail, StoredTrail};
    use solid_pod_rs::bitcoin_tx::mint_token;
    use solid_pod_rs::storage::memory::MemoryBackend;
    use solid_pod_rs::storage::Storage;

    /// Mint a genesis trail through the write-side, persist it (with the
    /// issuer secret), and register the genesis UTXO's scriptPubKey so a
    /// subsequent anchor can spend it. Returns `(storage, mempool, ticker)`.
    async fn mint_and_store(ticker: &str) -> (std::sync::Arc<dyn Storage>, FixtureMempool, String) {
        let mempool = FixtureMempool::empty();
        let storage: std::sync::Arc<dyn Storage> = std::sync::Arc::new(MemoryBackend::new());

        // Fund the genesis from an issuer-key voucher (untweaked path).
        let sk = k256::SecretKey::from_slice(&hex::decode(ISSUER_PRIVKEY).unwrap()).unwrap();
        let compressed = sk.public_key().to_sec1_bytes();
        let xonly_hex = hex::encode(&compressed[1..]);
        let voucher_txid = "11".repeat(32);
        mempool.add_output(&voucher_txid, 0, &format!("5120{xonly_hex}"));

        let voucher = solid_pod_rs::bitcoin_tx::TxoVoucher {
            txid: voucher_txid,
            vout: 0,
            amount: 100_000,
            privkey: ISSUER_PRIVKEY.to_string(),
        };
        let mint = mint_token(ticker, None, 1_000, &voucher, "testnet4", 300, &mempool)
            .await
            .unwrap();
        let mint_txid = mempool.broadcast_tx(&mint.tx.raw_hex).await.unwrap();

        // Persist the trail with the issuer secret + the broadcast txid.
        let mut stored = StoredTrail {
            ticker: mint.trail.ticker.clone(),
            name: mint.trail.name.clone(),
            supply: mint.trail.supply,
            privkey: ISSUER_PRIVKEY.to_string(),
            pubkey_base: mint.trail.pubkey_base.clone(),
            states: mint.trail.states.clone(),
            state_strings: mint.trail.state_strings.clone(),
            current_txid: mint_txid.clone(),
            current_vout: 0,
            current_amount: mint.trail.current_amount,
            network: mint.trail.network.clone(),
            date_created: "2026-06-13T00:00:00Z".into(),
        };
        stored.current_txid = mint_txid.clone();
        save_trail(&storage, &stored).await.unwrap();

        // Register the genesis output scriptPubKey so anchor() can spend it.
        let genesis_xonly = {
            let chained = solid_pod_rs::mrc20::bt_derive_chained_pubkey(
                &issuer_pubkey(),
                std::slice::from_ref(&mint.state_jcs),
            )
            .unwrap();
            hex::encode(&chained[1..])
        };
        mempool.add_output(&mint_txid, 0, &format!("5120{genesis_xonly}"));

        (storage, mempool, ticker.to_string())
    }

    #[tokio::test]
    async fn block_anchorer_anchor_round_trip_and_self_verifies() {
        let (storage, mempool, ticker) = mint_and_store("ANCH").await;
        let anchorer = MempoolBlockAnchorer::with_storage(mempool.clone(), storage.clone());

        // Anchor a git commit SHA (the provenance write).
        let commit_sha = "a1b2c3d4e5f60718293a4b5c6d7e8f9001122334";
        let anchor = anchorer
            .anchor(&ticker, commit_sha, "testnet4")
            .await
            .expect("anchor() must build + broadcast + persist");

        assert_eq!(anchor.ticker, "ANCH");
        assert_eq!(anchor.state_hash, commit_sha);
        assert_eq!(anchor.vout, 0);
        assert!(anchor.blockheight.is_none());
        assert_eq!(anchor.network, "testnet4");
        assert!(anchor.pubkey.is_some());
        // The portable proof carries genesis + anchor state strings.
        assert_eq!(anchor.state_strings.len(), 2);
        // The recorded address is the genuine derivation from the proof.
        let derived = bt_address(
            anchor.pubkey.as_deref().unwrap(),
            &anchor.state_strings,
            "testnet4",
        )
        .unwrap();
        assert_eq!(anchor.address, derived);

        // The trail was persisted with the new state appended + new txid.
        let reloaded = load_trail(&storage, "ANCH").await.unwrap().unwrap();
        assert_eq!(reloaded.states.len(), 2);
        assert_eq!(reloaded.current_txid, anchor.txid);
        assert_eq!(reloaded.states[1].anchor.as_deref(), Some(commit_sha));

        // verify() ACCEPTS the produced anchor once a UTXO sits at its address.
        mempool.utxos.lock().unwrap().insert(
            anchor.address.clone(),
            vec![Utxo {
                txid: anchor.txid.clone(),
                vout: 0,
                value: 9_400,
                confirmed: false,
                block_height: None,
            }],
        );
        assert!(
            anchorer.verify(&anchor).await.unwrap(),
            "the anchor we just produced must verify against its own UTXO"
        );
    }

    #[tokio::test]
    async fn block_anchorer_anchor_rejects_unminted_ticker() {
        let storage: std::sync::Arc<dyn Storage> = std::sync::Arc::new(MemoryBackend::new());
        let anchorer = MempoolBlockAnchorer::with_storage(FixtureMempool::empty(), storage);
        let err = anchorer
            .anchor("GHOST", "deadbeef", "testnet4")
            .await
            .unwrap_err();
        match err {
            ProvenanceError::Anchor(m) => assert!(m.contains("not minted")),
            other => panic!("expected not-minted error, got {other:?}"),
        }
    }
}
