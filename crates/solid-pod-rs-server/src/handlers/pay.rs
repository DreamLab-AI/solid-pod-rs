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

use solid_pod_rs::payments::{
    balance_response, parse_txo_uri, payment_required_body, PaymentError, PaymentStore, WebLedger,
};
use solid_pod_rs::storage::Storage;
use solid_pod_rs::trading::{AmmPool, Exchange};

use crate::{agent_uri, extract_pubkey, AppState, WEBLEDGER_PATH};

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
        Ok((bytes, _meta)) => serde_json::from_slice(&bytes)
            .map_err(|e| actix_web::error::ErrorInternalServerError(format!("malformed offers: {e}"))),
        Err(_) => Ok(solid_pod_rs::trading::OrderBook::new()),
    }
}

async fn save_order_book(
    storage: &dyn Storage,
    book: &solid_pod_rs::trading::OrderBook,
) -> Result<(), ActixError> {
    let body = serde_json::to_vec(book)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("serialise offers: {e}")))?;
    storage
        .put(OFFERS_PATH, Bytes::from(body), "application/json")
        .await
        .map_err(crate::to_actix)?;
    Ok(())
}

/// Load the AMM pool registry from [`POOL_PATH`], or a fresh one if absent.
async fn load_exchange(storage: &dyn Storage) -> Result<Exchange, ActixError> {
    match storage.get(POOL_PATH).await {
        Ok((bytes, _meta)) => serde_json::from_slice(&bytes)
            .map_err(|e| actix_web::error::ErrorInternalServerError(format!("malformed pool: {e}"))),
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
        PaymentError::InsufficientBalance { balance, cost } => HttpResponse::PaymentRequired()
            .json(payment_required_body(balance, cost)),
        PaymentError::Replay(msg) => {
            HttpResponse::BadRequest().json(serde_json::json!({ "error": format!("Replay: {msg}") }))
        }
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

/// Phase 0 TXO deposit: parse the URI, derive the sat amount, credit the
/// caller — guarded by replay protection keyed on `txid:vout` so the same
/// output can never be credited twice.
///
/// **Out of scope (Phase 3+):** mempool verification of the UTXO value.
/// Until then the credited amount is derived deterministically from the
/// vout (`(vout + 1) * 1000` sats) so the route is exercisable end-to-end
/// without a live chain. This is replaced by the real mempool-read value
/// in Phase 3; the replay guard wired here remains unchanged.
async fn handle_deposit(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: Bytes,
) -> Result<HttpResponse, ActixError> {
    let did = match require_did(&req).await {
        Ok(d) => d,
        Err(rsp) => return Ok(rsp),
    };

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
    Ok(HttpResponse::Ok().content_type("application/json").json(serde_json::json!({
        "did": did,
        "deposited": amount,
        "balance": balance,
        "unit": "sat",
        "txid": txo.txid,
        "vout": txo.vout,
    })))
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

    Ok(HttpResponse::Ok().content_type("application/json").json(order))
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

    Ok(HttpResponse::Ok().content_type("application/json").json(serde_json::json!({
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
// Route registration
// ---------------------------------------------------------------------------

/// Register all Phase-0 payment routes. Mounted unconditionally next to
/// the existing `/pay/.info` route (which is itself always-on) so the
/// gating matches exactly — there is no payments feature flag.
pub fn register(app: &mut web::ServiceConfig) {
    app.route("/pay/.balance", web::get().to(handle_balance))
        .route("/pay/.deposit", web::post().to(handle_deposit))
        .route("/pay/.offers", web::get().to(handle_offers))
        .route("/pay/.sell", web::post().to(handle_sell))
        .route("/pay/.swap", web::post().to(handle_swap))
        .route("/pay/.pool", web::get().to(handle_pool_get))
        .route("/pay/.pool", web::post().to(handle_pool_post));
}
