//! Payment routing — wires the orphaned `solid-pod-rs` payment core onto
//! actix-web routes with JSS-parity request/response JSON.
//!
//! The order book ([`solid_pod_rs::trading::OrderBook`]), AMM pool
//! ([`solid_pod_rs::trading::AmmPool`]), and Web-Ledger balance/deposit
//! logic ([`solid_pod_rs::payments`]) are complete and unit-tested in the
//! library but were never reachable over HTTP. This module is Phase 0 of
//! the provenance/payment upgrade (see
//! `docs/design/provenance-upgrade-master-plan.md`, §"Phase 0"): it
//! *routes* that logic without re-implementing any of it.
//!
//! ## Storage abstraction
//!
//! All ledger reads/writes for these handlers flow through
//! [`StoragePaymentStore`], the server's `Arc<dyn Storage>`-backed
//! [`PaymentStore`] implementation — replacing the inline
//! `Storage::get`/`put` ledger plumbing that the WAC enforcement path
//! uses. The store also wires the previously-defined-but-never-called
//! replay protection (`check_replay`/`record_replay`) so a TXO deposit
//! cannot be credited twice.
//!
//! ## Mirrored JSS routes (`JavaScriptSolidServer/src/handlers/pay.js`)
//!
//! | Method | Route          | JSS source        |
//! |--------|----------------|-------------------|
//! | GET    | `/pay/.balance`| `pay.js:307-373`  |
//! | POST   | `/pay/.deposit`| `pay.js:440-474`  |
//! | GET    | `/pay/.offers` | `pay.js:1176-…`   |
//! | POST   | `/pay/.sell`   | `pay.js:906-961`  |
//! | POST   | `/pay/.swap`   | `pay.js:964-1058` |
//! | GET    | `/pay/.pool`   | `pay.js:1060-…`   |
//! | POST   | `/pay/.pool`   | `pay.js:1080-1289`|
//!
//! ## Scope (Phase 0)
//!
//! TXO deposits are **parse + credit + replay-guard only** — no mempool
//! verification (Phase 3) and no Bitcoin TX build/broadcast (Phase 4).
//! The order-book / AMM model is the library's richer currency-pair
//! variant rather than JSS's single-MRC20-token model, so `.sell` /
//! `.swap` / `.pool` carry explicit currency fields.

use actix_web::{web, Error as ActixError, HttpRequest, HttpResponse};
use async_trait::async_trait;
use bytes::Bytes;
use serde::Deserialize;

use solid_pod_rs::bitcoin_tx::{
    anchor_proof_json, build_withdraw_voucher, parse_txo_voucher, transfer_token_with_key,
    MempoolBroadcast, DEFAULT_FEE_SATS,
};
use solid_pod_rs::mrc20::{bt_address, verify_mrc20_anchor, Mrc20State};
use solid_pod_rs::payments::{
    balance_response, parse_txo_uri, payment_required_body, PaymentError, PaymentStore, WebLedger,
};
use solid_pod_rs::storage::Storage;
use solid_pod_rs::trading::{AmmPool, Exchange};

use crate::mempool::MempoolHttpClient;
use crate::trail_store::{load_trail, save_trail};
use crate::{agent_uri, extract_pubkey, AppState, WEBLEDGER_PATH};

// ---------------------------------------------------------------------------
// Chain → Bitcoin network mapping (JSS parity — pay.js:295, 489)
// ---------------------------------------------------------------------------

/// Map a chain id to the BIP-341 network string used by `mrc20::bt_address`.
/// Mirrors JSS: `btc`→`mainnet`, `tbtc3`→`testnet`, everything else
/// (`tbtc4`, `signet`, unknown) → `testnet4`.
fn network_for_chain(chain: &str) -> &'static str {
    match chain {
        "btc" => "mainnet",
        "tbtc3" => "testnet",
        _ => "testnet4",
    }
}

// ---------------------------------------------------------------------------
// Canonical storage paths (JSS parity — PAY.md "Storage layout")
// ---------------------------------------------------------------------------

/// Seen TXO / MRC20 replay keys. JSS: `replay.json`.
const REPLAY_PATH: &str = "/.well-known/webledgers/replay.json";
/// Open sell orders (secondary market). JSS: `offers.json`.
const OFFERS_PATH: &str = "/.well-known/webledgers/offers.json";
/// AMM pool registry (reserves, LP shares, k). JSS: `pool.json`.
const POOL_PATH: &str = "/.well-known/webledgers/pool.json";

// ---------------------------------------------------------------------------
// StoragePaymentStore — the PaymentStore impl over Arc<dyn Storage>
// ---------------------------------------------------------------------------

/// [`PaymentStore`] backed by the server's [`Storage`] trait object.
///
/// This is the SOLE ledger read/write path for the payment handlers: it
/// reads/writes the Web Ledger at [`WEBLEDGER_PATH`] and maintains the
/// replay set at [`REPLAY_PATH`]. A missing ledger document is treated as
/// an empty ledger (so the first deposit provisions it); a missing replay
/// document is treated as an empty set.
pub struct StoragePaymentStore<'a> {
    storage: &'a dyn Storage,
    ledger_name: String,
}

impl<'a> StoragePaymentStore<'a> {
    pub fn new(storage: &'a dyn Storage) -> Self {
        Self {
            storage,
            ledger_name: "Pod Credits".to_string(),
        }
    }

    async fn read_replay_set(&self) -> Result<Vec<String>, PaymentError> {
        match self.storage.get(REPLAY_PATH).await {
            Ok((bytes, _meta)) => serde_json::from_slice::<Vec<String>>(&bytes)
                .map_err(|e| PaymentError::Store(format!("malformed replay set: {e}"))),
            // No replay document yet → empty set.
            Err(_) => Ok(Vec::new()),
        }
    }

    async fn write_replay_set(&self, set: &[String]) -> Result<(), PaymentError> {
        let body = serde_json::to_vec(set)
            .map_err(|e| PaymentError::Store(format!("serialise replay set: {e}")))?;
        self.storage
            .put(REPLAY_PATH, Bytes::from(body), "application/json")
            .await
            .map_err(|e| PaymentError::Store(e.to_string()))?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl<'a> PaymentStore for StoragePaymentStore<'a> {
    async fn read_ledger(&self) -> Result<WebLedger, PaymentError> {
        match self.storage.get(WEBLEDGER_PATH).await {
            Ok((bytes, _meta)) => serde_json::from_slice::<WebLedger>(&bytes)
                .map_err(|e| PaymentError::Store(format!("malformed ledger: {e}"))),
            // No ledger provisioned yet → fresh, empty ledger.
            Err(_) => Ok(WebLedger::new(&self.ledger_name)),
        }
    }

    async fn write_ledger(&self, ledger: &WebLedger) -> Result<(), PaymentError> {
        let body = serde_json::to_vec(ledger)
            .map_err(|e| PaymentError::Store(format!("serialise ledger: {e}")))?;
        self.storage
            .put(WEBLEDGER_PATH, Bytes::from(body), "application/json")
            .await
            .map_err(|e| PaymentError::Store(e.to_string()))?;
        Ok(())
    }

    async fn check_replay(&self, key: &str) -> Result<bool, PaymentError> {
        let set = self.read_replay_set().await?;
        Ok(set.iter().any(|k| k == key))
    }

    async fn record_replay(&self, key: &str) -> Result<(), PaymentError> {
        let mut set = self.read_replay_set().await?;
        if !set.iter().any(|k| k == key) {
            set.push(key.to_string());
            self.write_replay_set(&set).await?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Exchange persistence helpers (order book + AMM pools)
// ---------------------------------------------------------------------------

/// Load the order book from [`OFFERS_PATH`], or a fresh one if absent.
async fn load_order_book(
    storage: &dyn Storage,
) -> Result<solid_pod_rs::trading::OrderBook, ActixError> {
    match storage.get(OFFERS_PATH).await {
        Ok((bytes, _meta)) => serde_json::from_slice(&bytes).map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!("malformed offers: {e}"))
        }),
        Err(_) => Ok(solid_pod_rs::trading::OrderBook::new()),
    }
}

async fn save_order_book(
    storage: &dyn Storage,
    book: &solid_pod_rs::trading::OrderBook,
) -> Result<(), ActixError> {
    let body = serde_json::to_vec(book).map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("serialise offers: {e}"))
    })?;
    storage
        .put(OFFERS_PATH, Bytes::from(body), "application/json")
        .await
        .map_err(crate::to_actix)?;
    Ok(())
}

/// Load the AMM pool registry from [`POOL_PATH`], or a fresh one if absent.
async fn load_exchange(storage: &dyn Storage) -> Result<Exchange, ActixError> {
    match storage.get(POOL_PATH).await {
        Ok((bytes, _meta)) => serde_json::from_slice(&bytes).map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!("malformed pool: {e}"))
        }),
        Err(_) => Ok(Exchange::new()),
    }
}

async fn save_exchange(storage: &dyn Storage, exchange: &Exchange) -> Result<(), ActixError> {
    let body = serde_json::to_vec(exchange)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("serialise pool: {e}")))?;
    storage
        .put(POOL_PATH, Bytes::from(body), "application/json")
        .await
        .map_err(crate::to_actix)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared auth + error helpers
// ---------------------------------------------------------------------------

/// JSS parity: every `/pay/*` route except `.info` and `.offers` requires
/// NIP-98 auth. Returns the authenticated `did:nostr:<pubkey>` or a 401
/// response body matching JSS (`pay.js:54`, `pay.js:122`).
async fn require_did(req: &HttpRequest) -> Result<String, HttpResponse> {
    let pubkey = extract_pubkey(req).await;
    match agent_uri(pubkey.as_ref()) {
        Some(did) => Ok(did),
        None => Err(HttpResponse::Unauthorized()
            .json(serde_json::json!({ "error": "NIP-98 authentication required" }))),
    }
}

/// Map a [`PaymentError`] onto a JSS-shaped 4xx JSON response.
fn payment_error_response(err: PaymentError) -> HttpResponse {
    match err {
        PaymentError::InsufficientBalance { balance, cost } => {
            HttpResponse::PaymentRequired().json(payment_required_body(balance, cost))
        }
        PaymentError::Replay(msg) => HttpResponse::BadRequest()
            .json(serde_json::json!({ "error": format!("Replay: {msg}") })),
        PaymentError::InvalidTxo(msg) | PaymentError::InvalidState(msg) => {
            HttpResponse::BadRequest().json(serde_json::json!({ "error": msg }))
        }
        PaymentError::Store(msg) => HttpResponse::InternalServerError()
            .json(serde_json::json!({ "error": format!("payment store: {msg}") })),
    }
}

// ---------------------------------------------------------------------------
// GET /pay/.balance  (pay.js:307-373)
// ---------------------------------------------------------------------------

/// NIP-98 → `did:nostr` → Web-Ledger balance. JSON `{did, balance, cost, unit}`.
async fn handle_balance(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ActixError> {
    let did = match require_did(&req).await {
        Ok(d) => d,
        Err(rsp) => return Ok(rsp),
    };

    let store = StoragePaymentStore::new(&*state.storage);
    let ledger = match store.read_ledger().await {
        Ok(l) => l,
        Err(e) => return Ok(payment_error_response(e)),
    };
    let balance = ledger.get_balance(&did);

    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .json(balance_response(&did, balance, state.pay_config.cost_sats)))
}

// ---------------------------------------------------------------------------
// POST /pay/.deposit  (TXO path only — pay.js:440-474)
// ---------------------------------------------------------------------------

/// JSON or text/plain deposit body. JSS accepts a bare `"<txid>:<vout>"`
/// string or `{"txo": "<txid>:<vout>"}`.
#[derive(Debug, Deserialize)]
struct DepositBody {
    txo: String,
}

/// The `anchor` block of an MRC20 deposit — the portable proof needed to
/// re-derive the taproot address and check the chain (JSS `pay.js:402-411`).
#[derive(Debug, Deserialize)]
struct Mrc20AnchorBody {
    pubkey: String,
    #[serde(rename = "stateStrings")]
    state_strings: Vec<String>,
    #[serde(default)]
    network: Option<String>,
}

/// An MRC20 token deposit body: `{type:"mrc20", state, prevState, anchor}`
/// (JSS `pay.js:384-438`). `state`/`prevState` are full MRC20 states; the
/// `anchor` carries the issuer pubkey + state-string proof.
#[derive(Debug, Deserialize)]
struct Mrc20DepositBody {
    #[allow(dead_code)]
    #[serde(rename = "type")]
    kind: String,
    state: Mrc20State,
    #[serde(rename = "prevState")]
    prev_state: Mrc20State,
    anchor: Mrc20AnchorBody,
}

/// `POST /pay/.deposit`. Two paths, discriminated by body:
///
/// * **MRC20** (`Content-Type: application/json`, `{type:"mrc20", …}`) —
///   verify the block-trail anchor against live mempool state via
///   [`verify_mrc20_anchor`] + [`MempoolHttpClient`], replay-guard on the
///   `JCS(state)` hash, then credit the verified transfer amount (Phase 3,
///   JSS `pay.js:384-438`).
/// * **TXO** (text/plain or `{"txo":…}`) — the Phase-0 path, unchanged.
///
/// The TXO path remains a deterministic stand-in for the mempool-read sat
/// value (`(vout + 1) * 1000`); its real mempool valuation is a later step.
/// The MRC20 path is the one that genuinely round-trips to the chain here.
async fn handle_deposit(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: Bytes,
) -> Result<HttpResponse, ActixError> {
    let did = match require_did(&req).await {
        Ok(d) => d,
        Err(rsp) => return Ok(rsp),
    };

    // MRC20 path: a JSON body tagged `type: "mrc20"`. Probe cheaply for the
    // tag before committing to full deserialisation so a TXO JSON body
    // (`{"txo":…}`) still falls through to the Phase-0 path.
    if body_is_mrc20(&body) {
        return handle_mrc20_deposit(&did, &state, &body).await;
    }

    // Accept either a bare TXO URI (text/plain) or {"txo": "..."} (JSON).
    let raw = String::from_utf8_lossy(&body);
    let txo_uri = match serde_json::from_slice::<DepositBody>(&body) {
        Ok(b) => b.txo,
        Err(_) => raw.trim().to_string(),
    };

    let txo = match parse_txo_uri(&txo_uri) {
        Ok(t) => t,
        Err(e) => return Ok(payment_error_response(e)),
    };

    // Replay key: txid:vout — one credit per output, ever.
    let replay_key = format!("{}:{}", txo.txid, txo.vout);
    let store = StoragePaymentStore::new(&*state.storage);

    match store.check_replay(&replay_key).await {
        Ok(true) => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Replay: this output has already been used for a deposit",
                "txid": txo.txid,
                "vout": txo.vout,
            })));
        }
        Ok(false) => {}
        Err(e) => return Ok(payment_error_response(e)),
    }

    // Phase 0: deterministic stand-in for the mempool-read UTXO value.
    let amount: u64 = ((txo.vout as u64) + 1) * 1000;

    // Credit via the PaymentStore (sole ledger I/O path), then record the
    // replay key so a re-POST of the same TXO is rejected above.
    let mut ledger = match store.read_ledger().await {
        Ok(l) => l,
        Err(e) => return Ok(payment_error_response(e)),
    };
    ledger.credit(&did, amount);
    if let Err(e) = store.write_ledger(&ledger).await {
        return Ok(payment_error_response(e));
    }
    if let Err(e) = store.record_replay(&replay_key).await {
        return Ok(payment_error_response(e));
    }

    let balance = ledger.get_balance(&did);
    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .json(serde_json::json!({
            "did": did,
            "deposited": amount,
            "balance": balance,
            "unit": "sat",
            "txid": txo.txid,
            "vout": txo.vout,
        })))
}

// ---------------------------------------------------------------------------
// POST /pay/.deposit  (MRC20 path — pay.js:384-438, mrc20.js:279-335)
// ---------------------------------------------------------------------------

/// Cheap discriminator: does the body deserialise to an object whose
/// `type` is `"mrc20"`? Avoids committing to full `Mrc20DepositBody`
/// parsing for a TXO body. Any non-JSON / non-tagged body returns `false`.
fn body_is_mrc20(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("type")
                .and_then(|t| t.as_str())
                .map(|s| s.eq_ignore_ascii_case("mrc20"))
        })
        .unwrap_or(false)
}

/// The pod's issuer pubkey (66-char hex) — the key that anchors derive
/// against. Sourced from `pay_config.token.issuer`. `None` means MRC20
/// deposits / `/pay/.address` are not configured for this pod.
fn pod_issuer_pubkey(state: &AppState) -> Option<String> {
    state
        .pay_config
        .token
        .as_ref()
        .map(|t| t.issuer.clone())
        .filter(|p| !p.is_empty())
}

/// Verify an MRC20 token deposit and credit the verified transfer amount.
///
/// Flow (JSS `pay.js:384-438`):
/// 1. require an issuer pubkey configured on the pod (`payAddress` parity);
/// 2. derive the pod's generic deposit address `bt_address(issuer, [], net)`
///    — the `toAddress` transfers must target;
/// 3. **replay-guard** on `JCS(state)` (reuse the Phase-0 replay set) so a
///    state can't be credited twice;
/// 4. [`verify_mrc20_anchor`] — state-chain integrity + taproot re-derivation
///    + a live mempool UTXO check via [`MempoolHttpClient`];
/// 5. credit the verified amount via the [`PaymentStore`].
async fn handle_mrc20_deposit(
    did: &str,
    state: &AppState,
    body: &[u8],
) -> Result<HttpResponse, ActixError> {
    let deposit: Mrc20DepositBody = match serde_json::from_slice(body) {
        Ok(d) => d,
        Err(e) => {
            return Ok(HttpResponse::BadRequest()
                .json(serde_json::json!({ "error": format!("malformed mrc20 deposit: {e}") })))
        }
    };

    // (1) Issuer pubkey — the pod must be configured to accept MRC20.
    let issuer = match pod_issuer_pubkey(state) {
        Some(p) => p,
        None => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "MRC20 deposits not configured (no token issuer set)"
            })))
        }
    };

    let network = deposit
        .anchor
        .network
        .clone()
        .unwrap_or_else(|| "testnet4".to_string());

    // (2) The pod's generic deposit address — transfers must target it.
    let to_address = match bt_address(&issuer, &[], &network) {
        Ok(a) => a,
        Err(e) => return Ok(payment_error_response(e)),
    };

    // (3) Replay guard on the canonical state hash. Reuses the Phase-0
    // replay set; keyed `mrc20:<sha256(JCS(state))>` so it can't collide
    // with a TXO `txid:vout` key.
    let state_value = match serde_json::to_value(&deposit.state) {
        Ok(v) => v,
        Err(e) => {
            return Ok(HttpResponse::BadRequest()
                .json(serde_json::json!({ "error": format!("serialize state: {e}") })))
        }
    };
    let state_hash = solid_pod_rs::mrc20::sha256_hex(&solid_pod_rs::mrc20::jcs(&state_value));
    let replay_key = format!("mrc20:{state_hash}");
    let store = StoragePaymentStore::new(&*state.storage);
    match store.check_replay(&replay_key).await {
        Ok(true) => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Replay: this state has already been used for a deposit",
                "state_hash": state_hash,
            })))
        }
        Ok(false) => {}
        Err(e) => return Ok(payment_error_response(e)),
    }

    // (4) Anchor verification against live mempool state. An explicit
    // `mempool_url` (tests → local fixture server) overrides the env-driven
    // default so the route never reaches mempool.space in CI.
    let mempool = match &state.mempool_url {
        Some(url) => MempoolHttpClient::new(url.clone()),
        None => MempoolHttpClient::from_env(),
    };
    let result = match verify_mrc20_anchor(
        &deposit.state,
        &deposit.prev_state,
        &to_address,
        &deposit.anchor.pubkey,
        &deposit.anchor.state_strings,
        &network,
        &mempool,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return Ok(payment_error_response(e)),
    };

    // (5) Credit the verified amount, then record the replay key.
    let mut ledger = match store.read_ledger().await {
        Ok(l) => l,
        Err(e) => return Ok(payment_error_response(e)),
    };
    ledger.credit(did, result.amount);
    if let Err(e) = store.write_ledger(&ledger).await {
        return Ok(payment_error_response(e));
    }
    if let Err(e) = store.record_replay(&replay_key).await {
        return Ok(payment_error_response(e));
    }

    let balance = ledger.get_balance(did);
    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .json(serde_json::json!({
            "did": did,
            "deposited": result.amount,
            "ticker": result.ticker,
            "balance": balance,
            "unit": "token",
            "anchor": result.address,
        })))
}

// ---------------------------------------------------------------------------
// GET /pay/.address  (per-user tweaked deposit address — pay.js:286-305)
// ---------------------------------------------------------------------------

/// `?user=<did:nostr:…>&chain=<id>`. Both optional: without `user` the
/// generic pod deposit address is returned; without `chain` the first
/// configured chain (or `tbtc4`) is used.
#[derive(Debug, Deserialize)]
pub struct AddressQuery {
    user: Option<String>,
    chain: Option<String>,
}

/// Derive a deposit address (JSS `pay.js:286-305`). Public, no auth — it
/// returns only a derived address + the pod's issuer pubkey, never a
/// secret. The per-user address tweaks the issuer key by the user's DID
/// (`bt_address(issuer, [did], net)`), so funds sent there are
/// attributable to that user on the `/pay/.balance` auto-detect scan.
async fn handle_address(
    state: web::Data<AppState>,
    query: web::Query<AddressQuery>,
) -> Result<HttpResponse, ActixError> {
    let issuer = match pod_issuer_pubkey(&state) {
        Some(p) => p,
        None => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Deposit addresses not configured (no token issuer set)"
            })))
        }
    };

    // Chain: explicit query, else first configured chain, else tbtc4.
    let chain = query
        .chain
        .clone()
        .or_else(|| state.pay_config.chains.first().map(|c| c.id.clone()))
        .unwrap_or_else(|| "tbtc4".to_string());

    // If chains are configured, the requested chain must be among them.
    if !state.pay_config.chains.is_empty() && !state.pay_config.chains.iter().any(|c| c.id == chain)
    {
        let enabled: Vec<&str> = state
            .pay_config
            .chains
            .iter()
            .map(|c| c.id.as_str())
            .collect();
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Chain not enabled: {chain}"),
            "enabledChains": enabled,
        })));
    }

    let network = network_for_chain(&chain);

    // Optional per-user tweak. Validate the DID shape (JSS regex parity).
    let user = query.user.as_ref().map(|u| u.trim().to_lowercase());
    if let Some(u) = &user {
        if !is_valid_did_nostr(u) {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid user DID. Expected: did:nostr:<64-hex>"
            })));
        }
    }

    let states: Vec<String> = match &user {
        Some(u) => vec![u.clone()],
        None => vec![],
    };
    let address = match bt_address(&issuer, &states, network) {
        Ok(a) => a,
        Err(e) => return Ok(payment_error_response(e)),
    };

    let mut response = serde_json::json!({
        "address": address,
        "chain": chain,
        "pubkey": issuer,
    });
    if let Some(u) = &user {
        response["user"] = serde_json::Value::String(u.clone());
    }
    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .json(response))
}

/// JSS parity (`pay.js:297`): `^did:nostr:[0-9a-f]{64}$`.
fn is_valid_did_nostr(did: &str) -> bool {
    if let Some(hex) = did.strip_prefix("did:nostr:") {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// GET /pay/.offers  (public — pay.js:1176-…)
// ---------------------------------------------------------------------------

/// Public list of open sell orders. Optional `?sell=<cur>&buy=<cur>` filter.
#[derive(Debug, Deserialize)]
pub struct OffersQuery {
    sell: Option<String>,
    buy: Option<String>,
}

async fn handle_offers(
    state: web::Data<AppState>,
    query: web::Query<OffersQuery>,
) -> Result<HttpResponse, ActixError> {
    let book = load_order_book(&*state.storage).await?;
    let pair = match (query.sell.as_deref(), query.buy.as_deref()) {
        (Some(s), Some(b)) => Some((s, b)),
        _ => None,
    };
    let offers = book.list_offers(pair);
    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .json(offers))
}

// ---------------------------------------------------------------------------
// POST /pay/.sell  (create a sell order — pay.js:906-961)
// ---------------------------------------------------------------------------

/// Create-order request. The library's order book is currency-pair-based
/// (richer than JSS's single-token model), so the seller names both
/// currencies explicitly.
#[derive(Debug, Deserialize)]
struct SellBody {
    sell_currency: String,
    sell_amount: u64,
    buy_currency: String,
    price: u64,
}

async fn handle_sell(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<SellBody>,
) -> Result<HttpResponse, ActixError> {
    let seller = match require_did(&req).await {
        Ok(d) => d,
        Err(rsp) => return Ok(rsp),
    };

    if body.sell_amount == 0 || body.price == 0 {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Specify sell_amount (>0) and price (>0)"
        })));
    }

    let mut book = load_order_book(&*state.storage).await?;
    let order = book.create_order(
        &seller,
        &body.sell_currency,
        body.sell_amount,
        &body.buy_currency,
        body.price,
    );
    save_order_book(&*state.storage, &book).await?;

    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .json(order))
}

// ---------------------------------------------------------------------------
// POST /pay/.swap  (execute against an open order — pay.js:964-1058)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct SwapBody {
    id: String,
}

async fn handle_swap(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<SwapBody>,
) -> Result<HttpResponse, ActixError> {
    let buyer = match require_did(&req).await {
        Ok(d) => d,
        Err(rsp) => return Ok(rsp),
    };

    let store = StoragePaymentStore::new(&*state.storage);
    let mut ledger = match store.read_ledger().await {
        Ok(l) => l,
        Err(e) => return Ok(payment_error_response(e)),
    };
    let mut book = load_order_book(&*state.storage).await?;

    let result = match book.execute_swap(&body.id, &buyer, &mut ledger) {
        Ok(r) => r,
        Err(e) => return Ok(payment_error_response(e)),
    };

    // Persist the mutated ledger (via the PaymentStore) and the order book.
    if let Err(e) = store.write_ledger(&ledger).await {
        return Ok(payment_error_response(e));
    }
    save_order_book(&*state.storage, &book).await?;

    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .json(serde_json::json!({
            "swapped": result.amount_out,
            "paid": result.amount_in,
            "fee": result.fee,
            "buyer": buyer,
            "new_balance_in": result.new_balance_in,
            "new_balance_out": result.new_balance_out,
        })))
}

// ---------------------------------------------------------------------------
// GET /pay/.pool  (public AMM state — pay.js:1060-…)
// ---------------------------------------------------------------------------

/// Optional `?a=<cur>&b=<cur>` selects a specific pool. Without it, returns
/// the registry of all pools.
#[derive(Debug, Deserialize)]
pub struct PoolQuery {
    a: Option<String>,
    b: Option<String>,
}

async fn handle_pool_get(
    state: web::Data<AppState>,
    query: web::Query<PoolQuery>,
) -> Result<HttpResponse, ActixError> {
    let exchange = load_exchange(&*state.storage).await?;
    match (query.a.as_deref(), query.b.as_deref()) {
        (Some(a), Some(b)) => match exchange.get_pool(a, b) {
            Some(pool) => Ok(HttpResponse::Ok()
                .content_type("application/json")
                .json(pool.pool_info())),
            None => Ok(HttpResponse::Ok().content_type("application/json").json(
                serde_json::json!({ "currency_a": a, "currency_b": b, "reserve_a": 0, "reserve_b": 0, "total_shares": 0 }),
            )),
        },
        _ => {
            let infos: Vec<serde_json::Value> =
                exchange.pools.values().map(|p| p.pool_info()).collect();
            Ok(HttpResponse::Ok()
                .content_type("application/json")
                .json(infos))
        }
    }
}

// ---------------------------------------------------------------------------
// POST /pay/.pool  (AMM ops — pay.js:1080-1289)
// ---------------------------------------------------------------------------

/// AMM operation. `action` is one of `swap`, `add-liquidity`,
/// `remove-liquidity`. The currency pair is always explicit (library's
/// multi-pool model).
#[derive(Debug, Deserialize)]
struct PoolOpBody {
    action: String,
    currency_a: String,
    currency_b: String,
    #[serde(default)]
    amount_a: u64,
    #[serde(default)]
    amount_b: u64,
    #[serde(default)]
    shares: u64,
    #[serde(default)]
    from_currency: Option<String>,
    #[serde(default)]
    amount_in: u64,
    #[serde(default)]
    fee_bps: Option<u64>,
}

async fn handle_pool_post(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<PoolOpBody>,
) -> Result<HttpResponse, ActixError> {
    let provider = match require_did(&req).await {
        Ok(d) => d,
        Err(rsp) => return Ok(rsp),
    };

    let store = StoragePaymentStore::new(&*state.storage);
    let mut ledger = match store.read_ledger().await {
        Ok(l) => l,
        Err(e) => return Ok(payment_error_response(e)),
    };
    let mut exchange = load_exchange(&*state.storage).await?;
    let fee_bps = body.fee_bps.unwrap_or(AmmPool::DEFAULT_FEE_BPS);

    let response = match body.action.as_str() {
        "add-liquidity" => {
            let pool = exchange.get_or_create_pool(&body.currency_a, &body.currency_b, fee_bps);
            match pool.add_liquidity(&provider, body.amount_a, body.amount_b, &mut ledger) {
                Ok(issued) => {
                    let mut deposited = serde_json::Map::new();
                    deposited.insert(body.currency_a.clone(), body.amount_a.into());
                    deposited.insert(body.currency_b.clone(), body.amount_b.into());
                    serde_json::json!({
                        "action": "add-liquidity",
                        "shares": issued,
                        "deposited": deposited,
                        "total_shares": pool.total_shares,
                        "reserve_a": pool.reserve_a,
                        "reserve_b": pool.reserve_b,
                    })
                }
                Err(e) => return Ok(payment_error_response(e)),
            }
        }
        "remove-liquidity" => {
            let pool = match exchange.get_pool(&body.currency_a, &body.currency_b) {
                Some(_) => exchange.get_or_create_pool(&body.currency_a, &body.currency_b, fee_bps),
                None => {
                    return Ok(HttpResponse::BadRequest()
                        .json(serde_json::json!({ "error": "Pool has no liquidity" })))
                }
            };
            match pool.remove_liquidity(&provider, body.shares, &mut ledger) {
                Ok((got_a, got_b)) => {
                    let mut withdrawn = serde_json::Map::new();
                    withdrawn.insert(body.currency_a.clone(), got_a.into());
                    withdrawn.insert(body.currency_b.clone(), got_b.into());
                    serde_json::json!({
                        "action": "remove-liquidity",
                        "withdrawn": withdrawn,
                        "total_shares": pool.total_shares,
                        "reserve_a": pool.reserve_a,
                        "reserve_b": pool.reserve_b,
                    })
                }
                Err(e) => return Ok(payment_error_response(e)),
            }
        }
        "swap" => {
            let from = match body.from_currency.as_deref() {
                Some(f) => f.to_string(),
                None => {
                    return Ok(HttpResponse::BadRequest().json(
                        serde_json::json!({ "error": "Specify from_currency for a pool swap" }),
                    ))
                }
            };
            let pool = match exchange.get_pool(&body.currency_a, &body.currency_b) {
                Some(_) => exchange.get_or_create_pool(&body.currency_a, &body.currency_b, fee_bps),
                None => {
                    return Ok(HttpResponse::BadRequest()
                        .json(serde_json::json!({ "error": "Pool has no liquidity" })))
                }
            };
            match pool.swap(&provider, &from, body.amount_in, &mut ledger) {
                Ok(result) => serde_json::json!({
                    "action": "swap",
                    "amount_in": result.amount_in,
                    "amount_out": result.amount_out,
                    "fee": result.fee,
                    "new_balance_in": result.new_balance_in,
                    "new_balance_out": result.new_balance_out,
                    "reserve_a": pool.reserve_a,
                    "reserve_b": pool.reserve_b,
                }),
                Err(e) => return Ok(payment_error_response(e)),
            }
        }
        other => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Unknown action '{other}' (want swap | add-liquidity | remove-liquidity)")
            })));
        }
    };

    // Persist mutated ledger (via PaymentStore) + pool registry.
    if let Err(e) = store.write_ledger(&ledger).await {
        return Ok(payment_error_response(e));
    }
    save_exchange(&*state.storage, &exchange).await?;

    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .json(response))
}

// ---------------------------------------------------------------------------
// Phase 4 — Bitcoin write-side routes: /pay/.buy, /pay/.withdraw,
// /pay/.withdraw-sats (JSS pay.js:553-898, token.js mint/transfer/build).
// ---------------------------------------------------------------------------

/// Build the mempool transport: the test override (`state.mempool_url`,
/// pointing at a fixture HTTP origin) or the env-driven testnet4 default.
/// `MempoolHttpClient` implements both [`solid_pod_rs::mrc20::MempoolLookup`]
/// (UTXO/scriptPubKey reads) and [`MempoolBroadcast`] (tx broadcast).
fn mempool_client(state: &AppState) -> MempoolHttpClient {
    match &state.mempool_url {
        Some(url) => MempoolHttpClient::new(url.clone()),
        None => MempoolHttpClient::from_env(),
    }
}

/// The portable anchor proof returned alongside a `.buy` / `.withdraw`
/// transfer (JSS `pay.js:647-656`): the state, the prev state, and the
/// `{pubkey, stateStrings, network}` anchor needed to independently verify the
/// derived taproot address against the chain.
fn transfer_proof_json(
    state: &Mrc20State,
    prev_state: &Mrc20State,
    trail: &solid_pod_rs::mrc20::Mrc20Trail,
) -> serde_json::Value {
    serde_json::json!({
        "state": state,
        "prevState": prev_state,
        "anchor": anchor_proof_json(trail),
    })
}

/// Shared `.buy` / `.withdraw` body — both move `payToken` tokens to the
/// authenticated buyer/withdrawer against their sat balance, differing only in
/// how the token amount is derived (buy: `amount`/`sats`; withdraw:
/// `tokens`/`sats`/`all`).
#[derive(Debug, Deserialize, Default)]
struct TokenMoveBody {
    #[serde(default)]
    ticker: Option<String>,
    #[serde(default)]
    amount: Option<u64>,
    #[serde(default)]
    sats: Option<u64>,
    #[serde(default)]
    tokens: Option<u64>,
    #[serde(default)]
    all: Option<bool>,
}

/// Execute the token transfer + ledger debit shared by `.buy`/`.withdraw`.
///
/// Loads the trail, runs [`transfer_token_with_key`] (reusing the chained-key
/// crypto), broadcasts the tx, persists the appended trail, debits `sat_cost`
/// from the user's ledger entry, and returns `(txid, proof, new_balance)`.
/// Fail-closed: if the broadcast or persistence fails the ledger is NOT
/// debited (debit happens only after a successful broadcast, matching JSS
/// ordering at `pay.js:636-637,740-741`).
async fn execute_token_transfer(
    state: &AppState,
    ticker: &str,
    buyer_pubkey: &str,
    did: &str,
    token_amount: u64,
    sat_cost: u64,
) -> Result<(String, serde_json::Value, u64), HttpResponse> {
    let storage = &state.storage;

    // Load the trail (must be minted on this pod).
    let mut stored = match load_trail(storage, ticker).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            return Err(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Token {ticker} not minted on this pod")
            })));
        }
        Err(e) => return Err(payment_error_response(e)),
    };

    let mempool = mempool_client(state);
    let public = stored.to_public();
    let prev_state = match public.states.last() {
        Some(s) => s.clone(),
        None => {
            return Err(HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Trail has no states"})));
        }
    };

    // Build the transfer (issuer → buyer pubkey). The issuer secret comes from
    // the stored trail file (never the public type).
    let update = match transfer_token_with_key(
        &public,
        &stored.privkey,
        None,
        buyer_pubkey,
        token_amount,
        DEFAULT_FEE_SATS,
        &mempool,
    )
    .await
    {
        Ok(u) => u,
        Err(e) => {
            return Err(HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": format!("Transfer failed: {e}")})));
        }
    };

    // Broadcast, then (only on success) persist + debit.
    let txid = match mempool.broadcast_tx(&update.tx.raw_hex).await {
        Ok(t) => t,
        Err(e) => {
            return Err(HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": format!("Broadcast failed: {e}")})));
        }
    };

    let mut appended = update.trail.clone();
    appended.current_txid = txid.clone();
    stored.merge_public(&appended);
    stored.current_txid = txid.clone();
    stored.current_vout = 0;
    if let Err(e) = save_trail(storage, &stored).await {
        return Err(payment_error_response(e));
    }

    // Debit the user's sat balance (JSS `debit` then `writeLedger`).
    let store = StoragePaymentStore::new(&**storage);
    let mut ledger = match store.read_ledger().await {
        Ok(l) => l,
        Err(e) => return Err(payment_error_response(e)),
    };
    if let Err(e) = ledger.debit(did, sat_cost) {
        return Err(payment_error_response(e));
    }
    if let Err(e) = store.write_ledger(&ledger).await {
        return Err(payment_error_response(e));
    }
    let new_balance = ledger.get_balance(did);

    let proof = transfer_proof_json(&update.state, &prev_state, &appended);
    Ok((txid, proof, new_balance))
}

/// POST `/pay/.buy` — primary market: buy `payToken` tokens with sats
/// (JSS `pay.js:553-657`).
async fn handle_buy(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: Bytes,
) -> Result<HttpResponse, ActixError> {
    let did = match require_did(&req).await {
        Ok(d) => d,
        Err(rsp) => return Ok(rsp),
    };
    let buyer_pubkey = match did.strip_prefix("did:nostr:") {
        Some(pk) => pk.to_string(),
        None => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "NIP-98 authentication required"
            })))
        }
    };

    let token_cfg = match &state.pay_config.token {
        Some(t) => t.clone(),
        None => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Primary market not configured (no pay-token set)"
            })));
        }
    };
    let pay_token = token_cfg.ticker.clone();
    let pay_rate = token_cfg.rate.max(1);

    let req_body: TokenMoveBody = serde_json::from_slice(&body).unwrap_or_default();
    let ticker = req_body.ticker.clone().unwrap_or_else(|| pay_token.clone());
    if ticker != pay_token {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("This pod only sells {pay_token}")
        })));
    }

    // amount (tokens to buy) or sats (sats to spend) — JSS `pay.js:580-592`.
    let (token_amount, sat_cost) = if let Some(a) = req_body.amount {
        (a, a * pay_rate)
    } else if let Some(s) = req_body.sats {
        (s / pay_rate, s)
    } else {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Specify amount (tokens to buy) or sats (sats to spend)",
            "rate": pay_rate, "unit": "sat/token"
        })));
    };
    if token_amount == 0 {
        return Ok(HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "Amount must be positive"})));
    }

    // Balance check (JSS `pay.js:602-614`).
    let store = StoragePaymentStore::new(&*state.storage);
    let balance = match store.read_ledger().await {
        Ok(l) => l.get_balance(&did),
        Err(e) => return Ok(payment_error_response(e)),
    };
    if balance < sat_cost {
        return Ok(HttpResponse::PaymentRequired().json(serde_json::json!({
            "error": "Insufficient sat balance",
            "balance": balance, "cost": sat_cost, "rate": pay_rate,
            "deposit": "/pay/.deposit"
        })));
    }

    match execute_token_transfer(
        &state,
        &pay_token,
        &buyer_pubkey,
        &did,
        token_amount,
        sat_cost,
    )
    .await
    {
        Ok((txid, proof, new_balance)) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "bought": token_amount, "ticker": pay_token, "cost": sat_cost,
            "rate": pay_rate, "balance": new_balance, "unit": "sat",
            "txid": txid, "proof": proof
        }))),
        Err(rsp) => Ok(rsp),
    }
}

/// POST `/pay/.withdraw` — withdraw a sat balance as portable `payToken`
/// tokens with an MRC20 proof (JSS `pay.js:659-761`).
async fn handle_withdraw(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: Bytes,
) -> Result<HttpResponse, ActixError> {
    let did = match require_did(&req).await {
        Ok(d) => d,
        Err(rsp) => return Ok(rsp),
    };
    let user_pubkey = match did.strip_prefix("did:nostr:") {
        Some(pk) => pk.to_string(),
        None => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "NIP-98 authentication required"
            })))
        }
    };

    let token_cfg = match &state.pay_config.token {
        Some(t) => t.clone(),
        None => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Withdrawal not configured (no pay-token set)"
            })));
        }
    };
    let pay_token = token_cfg.ticker.clone();
    let pay_rate = token_cfg.rate.max(1);

    let req_body: TokenMoveBody = serde_json::from_slice(&body).unwrap_or_default();

    let store = StoragePaymentStore::new(&*state.storage);
    let balance = match store.read_ledger().await {
        Ok(l) => l.get_balance(&did),
        Err(e) => return Ok(payment_error_response(e)),
    };

    // all / sats / tokens — JSS `pay.js:688-705`.
    let (token_amount, sat_cost) = if req_body.all.unwrap_or(false) {
        (balance / pay_rate, balance)
    } else if let Some(s) = req_body.sats {
        (s / pay_rate, s)
    } else if let Some(t) = req_body.tokens {
        (t, t * pay_rate)
    } else {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Specify tokens, sats, or all: true",
            "balance": balance, "rate": pay_rate, "unit": "sat/token"
        })));
    };
    if token_amount == 0 {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Nothing to withdraw", "balance": balance, "rate": pay_rate
        })));
    }
    if balance < sat_cost {
        return Ok(HttpResponse::PaymentRequired().json(serde_json::json!({
            "error": "Insufficient balance", "balance": balance,
            "cost": sat_cost, "rate": pay_rate
        })));
    }

    match execute_token_transfer(
        &state,
        &pay_token,
        &user_pubkey,
        &did,
        token_amount,
        sat_cost,
    )
    .await
    {
        Ok((txid, proof, new_balance)) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "withdrawn": token_amount, "ticker": pay_token, "cost": sat_cost,
            "rate": pay_rate, "balance": new_balance, "unit": "sat",
            "txid": txid, "proof": proof
        }))),
        Err(rsp) => Ok(rsp),
    }
}

/// `/pay/.withdraw-sats` request body — withdraw `amount` sats as a fresh TXO
/// voucher, funded by a pod-supplied funding voucher (JSS `pay.js:763-898`).
///
/// JSS draws funding from a pod-side UTXO pool (`loadUtxos`/`saveUtxos`). This
/// crate has no such pool, so the operator supplies the funding output as a
/// `txo:` voucher in `funding` (the pod's sat reserve), and the handler emits a
/// new voucher paying `amount` to a freshly-generated key, with change back to
/// the pod key. The crypto deliverable — voucher-tx build + new voucher minting
/// — is identical to JSS `token.js`.
#[derive(Debug, Deserialize)]
struct WithdrawSatsBody {
    amount: u64,
    #[serde(default)]
    chain: Option<String>,
    /// Funding voucher (`txo:<chain>:<txid>:<vout>?amount=<sats>&key=<hex>`)
    /// controlling the pod's sat reserve to spend from.
    funding: String,
}

/// POST `/pay/.withdraw-sats` — withdraw sats as a TXO voucher (JSS
/// `pay.js:763-898`, `token.js` voucher build).
async fn handle_withdraw_sats(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: Bytes,
) -> Result<HttpResponse, ActixError> {
    let did = match require_did(&req).await {
        Ok(d) => d,
        Err(rsp) => return Ok(rsp),
    };

    let req_body: WithdrawSatsBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(_) => {
            return Ok(
                HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid JSON body"}))
            );
        }
    };
    if req_body.amount == 0 {
        return Ok(HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "Specify amount to withdraw"})));
    }

    // Chain selection (JSS `pay.js:779-790`).
    let chain_id = req_body
        .chain
        .clone()
        .or_else(|| state.pay_config.chains.first().map(|c| c.id.clone()))
        .unwrap_or_else(|| "tbtc4".to_string());
    if !state.pay_config.chains.is_empty()
        && !state.pay_config.chains.iter().any(|c| c.id == chain_id)
    {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Chain '{chain_id}' not enabled")
        })));
    }

    // Balance check (JSS `pay.js:793-798`).
    let store = StoragePaymentStore::new(&*state.storage);
    let balance = match store.read_ledger().await {
        Ok(l) => l.get_balance(&did),
        Err(e) => return Ok(payment_error_response(e)),
    };
    if balance < req_body.amount {
        return Ok(HttpResponse::PaymentRequired().json(serde_json::json!({
            "error": "Insufficient balance", "balance": balance,
            "requested": req_body.amount
        })));
    }

    // Parse the funding voucher (the pod sat reserve to spend).
    let funding = match parse_txo_voucher(&req_body.funding) {
        Ok(v) => v,
        Err(e) => return Ok(payment_error_response(e)),
    };

    // Fetch the funding output's scriptPubKey (hex).
    let mempool = mempool_client(&state);
    use solid_pod_rs::mrc20::MempoolLookup;
    let funding_spk_hex = match mempool.tx(&funding.txid).await {
        Ok(tx) => match tx
            .vout
            .get(funding.vout as usize)
            .and_then(|o| o.scriptpubkey.clone())
        {
            Some(spk) => spk,
            None => {
                return Ok(HttpResponse::BadRequest()
                    .json(serde_json::json!({"error": "Funding output not found"})));
            }
        },
        Err(e) => return Ok(payment_error_response(e)),
    };

    // Build the voucher tx (fresh-key voucher output + change) — the crypto
    // lives in `bitcoin_tx::build_withdraw_voucher` (JSS `pay.js:842-869`).
    let voucher = match build_withdraw_voucher(
        &funding,
        &funding_spk_hex,
        req_body.amount,
        DEFAULT_FEE_SATS,
    ) {
        Ok(v) => v,
        Err(PaymentError::InvalidState(m)) if m.contains("funding") && m.contains("needed") => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Not enough funding-voucher value for withdrawal + fee",
                "available": funding.amount, "needed": req_body.amount + DEFAULT_FEE_SATS
            })));
        }
        Err(e) => return Ok(payment_error_response(e)),
    };

    let txid = match mempool.broadcast_tx(&voucher.tx.raw_hex).await {
        Ok(t) => t,
        Err(e) => {
            return Ok(HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": format!("Broadcast failed: {e}")})));
        }
    };

    // Debit the user's balance only after a successful broadcast.
    let mut ledger = match store.read_ledger().await {
        Ok(l) => l,
        Err(e) => return Ok(payment_error_response(e)),
    };
    if let Err(e) = ledger.debit(&did, req_body.amount) {
        return Ok(payment_error_response(e));
    }
    if let Err(e) = store.write_ledger(&ledger).await {
        return Ok(payment_error_response(e));
    }

    // Return the new voucher URI (JSS `pay.js:890-892`).
    let voucher_uri = format!(
        "txo:{chain_id}:{txid}:0?amount={}&key={}",
        req_body.amount, voucher.voucher_privkey_hex
    );
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "voucher": voucher_uri,
        "amount": req_body.amount,
        "chain": chain_id,
        "txid": txid,
        "balance": ledger.get_balance(&did),
    })))
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

/// Register all Phase-0 payment routes. Mounted unconditionally next to
/// the existing `/pay/.info` route (which is itself always-on) so the
/// gating matches exactly — there is no payments feature flag.
pub fn register(app: &mut web::ServiceConfig) {
    app.route("/pay/.balance", web::get().to(handle_balance))
        .route("/pay/.deposit", web::post().to(handle_deposit))
        .route("/pay/.address", web::get().to(handle_address))
        .route("/pay/.offers", web::get().to(handle_offers))
        .route("/pay/.sell", web::post().to(handle_sell))
        .route("/pay/.swap", web::post().to(handle_swap))
        .route("/pay/.pool", web::get().to(handle_pool_get))
        .route("/pay/.pool", web::post().to(handle_pool_post))
        // Phase 4 — Bitcoin write-side (token mint/transfer + voucher).
        .route("/pay/.buy", web::post().to(handle_buy))
        .route("/pay/.withdraw", web::post().to(handle_withdraw))
        .route("/pay/.withdraw-sats", web::post().to(handle_withdraw_sats));
}
