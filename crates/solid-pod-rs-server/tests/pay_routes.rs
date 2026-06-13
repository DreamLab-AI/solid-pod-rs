//! Integration tests for the Phase-0 payment routes (`handlers/pay.rs`).
//!
//! These exercise the routes wired in `build_app` end-to-end via
//! `actix_web::test`, using the in-memory storage backend so they are
//! fully deterministic with no network access:
//!
//! * `GET  /pay/.balance` — authed `did:nostr` resolves a ledger balance.
//! * `POST /pay/.deposit` — a TXO URI credits the balance.
//! * **Replay** — a second deposit of the SAME `txid:vout` is rejected and
//!   does NOT double-credit (the headline Phase-0 guarantee).
//! * `POST /pay/.sell` + `GET /pay/.offers` + `POST /pay/.swap` — an
//!   order-book round-trip settling against the Web Ledger.
//! * `POST /pay/.pool` — an AMM add-liquidity then swap.
//!
//! The richer per-currency order-book / AMM *logic* is already covered by
//! the library unit tests in `trading.rs` (15 order-book + 16 AMM cases);
//! these tests verify only the HTTP routing + persistence + ledger wiring
//! on top of that logic.

use std::sync::Arc;

use actix_web::http::header;
use actix_web::test;
use serde_json::Value;
use solid_pod_rs::auth::nip98;
use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::{build_app, AppState};

// A fixed 32-byte secret key (64 hex). Deterministic — the derived pubkey
// is stable across runs so balances/orders key consistently.
const SK_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn state() -> AppState {
    AppState::new(Arc::new(MemoryBackend::new()))
}

/// Mint a NIP-98 `Authorization` header for `method`+`path`. The handler
/// reconstructs the signed URL from the actix `connection_info`, which in
/// the test harness is `http://localhost:8080`. Mirrors that exactly so
/// strict URL binding passes. Returns `(header_value, did:nostr)`.
fn nip98_auth(method: &str, path: &str) -> (String, String) {
    let url = format!("http://localhost:8080{path}");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = nip98::mint(&url, method, SK_HEX, now)
        .expect("nip98-schnorr is enabled in the workspace test build");
    // Derive the did the server will compute from the same key.
    let sk = hex::decode(SK_HEX).unwrap();
    let signing = k256::schnorr::SigningKey::from_bytes(&sk).unwrap();
    let pubkey = hex::encode(signing.verifying_key().to_bytes());
    (format!("Nostr {token}"), format!("did:nostr:{pubkey}"))
}

// ---------------------------------------------------------------------------
// Balance
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn balance_requires_auth() {
    let app = test::init_service(build_app(state())).await;
    let req = test::TestRequest::get().uri("/pay/.balance").to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(rsp.status().as_u16(), 401, "no NIP-98 → 401");
}

#[actix_web::test]
async fn balance_for_authed_did_zero_then_credited() {
    let st = state();
    let storage = st.storage.clone();
    let app = test::init_service(build_app(st)).await;

    let (auth, did) = nip98_auth("GET", "/pay/.balance");

    // Pre-seed the ledger with a known balance for this did.
    let mut ledger = solid_pod_rs::payments::WebLedger::new("Pod Credits");
    ledger.credit(&did, 4242);
    let body = serde_json::to_vec(&ledger).unwrap();
    storage
        .put(
            "/.well-known/webledgers/webledgers.json",
            body.into(),
            "application/json",
        )
        .await
        .unwrap();

    let req = test::TestRequest::get()
        .uri("/pay/.balance")
        .insert_header((header::AUTHORIZATION, auth))
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(rsp.status().as_u16(), 200);
    let json: Value = test::read_body_json(rsp).await;
    assert_eq!(json["did"], did);
    assert_eq!(json["balance"], 4242);
    assert_eq!(json["unit"], "sat");
}

// ---------------------------------------------------------------------------
// Deposit + replay
// ---------------------------------------------------------------------------

async fn read_balance(storage: &dyn Storage, did: &str) -> u64 {
    let (bytes, _) = storage
        .get("/.well-known/webledgers/webledgers.json")
        .await
        .unwrap();
    let ledger: solid_pod_rs::payments::WebLedger = serde_json::from_slice(&bytes).unwrap();
    ledger.get_balance(did)
}

#[actix_web::test]
async fn deposit_credits_balance() {
    let st = state();
    let storage = st.storage.clone();
    let app = test::init_service(build_app(st)).await;

    let (auth, did) = nip98_auth("POST", "/pay/.deposit");
    let txid = "a".repeat(64);
    let txo = format!("{txid}:0"); // vout 0 → (0+1)*1000 = 1000 sats

    let req = test::TestRequest::post()
        .uri("/pay/.deposit")
        .insert_header((header::AUTHORIZATION, auth))
        .insert_header((header::CONTENT_TYPE, "text/plain"))
        .set_payload(txo)
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(rsp.status().as_u16(), 200);
    let json: Value = test::read_body_json(rsp).await;
    assert_eq!(json["deposited"], 1000);
    assert_eq!(json["balance"], 1000);
    assert_eq!(read_balance(storage.as_ref(), &did).await, 1000);
}

/// Headline Phase-0 guarantee: a second deposit of the SAME txid:vout is
/// rejected and the balance is NOT credited twice.
#[actix_web::test]
async fn deposit_replay_is_rejected_and_does_not_double_credit() {
    let st = state();
    let storage = st.storage.clone();
    let app = test::init_service(build_app(st)).await;

    let txid = "b".repeat(64);
    let txo = format!("{txid}:1"); // vout 1 → 2000 sats

    // First deposit — succeeds.
    let (auth1, did) = nip98_auth("POST", "/pay/.deposit");
    let req = test::TestRequest::post()
        .uri("/pay/.deposit")
        .insert_header((header::AUTHORIZATION, auth1))
        .insert_header((header::CONTENT_TYPE, "text/plain"))
        .set_payload(txo.clone())
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(rsp.status().as_u16(), 200);
    assert_eq!(read_balance(storage.as_ref(), &did).await, 2000);

    // Second deposit of the SAME output — rejected (400), balance unchanged.
    let (auth2, _) = nip98_auth("POST", "/pay/.deposit");
    let req = test::TestRequest::post()
        .uri("/pay/.deposit")
        .insert_header((header::AUTHORIZATION, auth2))
        .insert_header((header::CONTENT_TYPE, "text/plain"))
        .set_payload(txo)
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(
        rsp.status().as_u16(),
        400,
        "duplicate txid:vout must be rejected (replay guard)"
    );
    let json: Value = test::read_body_json(rsp).await;
    assert!(
        json["error"].as_str().unwrap_or("").contains("Replay"),
        "expected a replay error, got: {json}"
    );
    assert_eq!(
        read_balance(storage.as_ref(), &did).await,
        2000,
        "replayed deposit must NOT double-credit"
    );
}

// ---------------------------------------------------------------------------
// Order book round-trip: sell → offers → swap
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn offers_sell_swap_round_trip() {
    let st = state();
    let storage = st.storage.clone();

    // Seed two principals with currency balances so the swap can settle.
    // The seller is the NIP-98 key (did derived below); the buyer is a
    // distinct did we fund directly.
    let (_, seller_did) = nip98_auth("POST", "/pay/.sell");
    let buyer_did = "did:nostr:buyer";

    let mut ledger = solid_pod_rs::payments::WebLedger::new("Pod Credits");
    ledger.credit_currency(&seller_did, "tbtc4", 1_000);
    ledger.credit_currency(buyer_did, "tbtc3", 1_000);
    storage
        .put(
            "/.well-known/webledgers/webledgers.json",
            serde_json::to_vec(&ledger).unwrap().into(),
            "application/json",
        )
        .await
        .unwrap();

    let app = test::init_service(build_app(st)).await;

    // 1. Seller lists 100 tbtc4 at price 2 tbtc3 each (buyer pays 200 tbtc3).
    let (sell_auth, _) = nip98_auth("POST", "/pay/.sell");
    let req = test::TestRequest::post()
        .uri("/pay/.sell")
        .insert_header((header::AUTHORIZATION, sell_auth))
        .set_json(serde_json::json!({
            "sell_currency": "tbtc4",
            "sell_amount": 100,
            "buy_currency": "tbtc3",
            "price": 2
        }))
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(rsp.status().as_u16(), 200);
    let order: Value = test::read_body_json(rsp).await;
    let order_id = order["id"].as_str().unwrap().to_string();
    assert_eq!(order["seller"], seller_did);

    // 2. Offers (public) lists the order.
    let req = test::TestRequest::get().uri("/pay/.offers").to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(rsp.status().as_u16(), 200);
    let offers: Value = test::read_body_json(rsp).await;
    assert_eq!(offers.as_array().unwrap().len(), 1);

    // 3. Buyer swaps against the order. We must auth as the buyer — but
    //    the NIP-98 key is the seller's, so instead seed a buyer-keyed
    //    swap by funding the seller's own did as buyer is not possible
    //    (cannot self-swap is not enforced here). To keep a single signing
    //    key we let the SELLER buy back from a SECOND order is overkill;
    //    instead fund the seller-did as the buyer and place the order from
    //    the buyer side. Simpler: place the order as seller, then have the
    //    SAME did execute the swap is rejected by no rule — execute_swap
    //    does not forbid self-trade, so we drive the swap with the signing
    //    did acting as buyer against a buyer-funded balance.
    //
    //    Re-seed: give the signing did enough tbtc3 to buy its own order.
    let (bytes, _) = storage
        .get("/.well-known/webledgers/webledgers.json")
        .await
        .unwrap();
    let mut ledger: solid_pod_rs::payments::WebLedger =
        serde_json::from_slice(&bytes).unwrap();
    ledger.credit_currency(&seller_did, "tbtc3", 1_000);
    storage
        .put(
            "/.well-known/webledgers/webledgers.json",
            serde_json::to_vec(&ledger).unwrap().into(),
            "application/json",
        )
        .await
        .unwrap();

    let (swap_auth, _) = nip98_auth("POST", "/pay/.swap");
    let req = test::TestRequest::post()
        .uri("/pay/.swap")
        .insert_header((header::AUTHORIZATION, swap_auth))
        .set_json(serde_json::json!({ "id": order_id }))
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(rsp.status().as_u16(), 200, "swap should settle");
    let result: Value = test::read_body_json(rsp).await;
    assert_eq!(result["swapped"], 100);
    assert_eq!(result["paid"], 200);

    // 4. The order is consumed — offers now empty.
    let req = test::TestRequest::get().uri("/pay/.offers").to_request();
    let rsp = test::call_service(&app, req).await;
    let offers: Value = test::read_body_json(rsp).await;
    assert_eq!(offers.as_array().unwrap().len(), 0);
}

// ---------------------------------------------------------------------------
// AMM pool: add-liquidity then swap
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn pool_add_liquidity_then_swap() {
    let st = state();
    let storage = st.storage.clone();

    let (_, did) = nip98_auth("POST", "/pay/.pool");
    let mut ledger = solid_pod_rs::payments::WebLedger::new("Pod Credits");
    ledger.credit_currency(&did, "tbtc4", 10_000);
    ledger.credit_currency(&did, "tbtc3", 10_000);
    storage
        .put(
            "/.well-known/webledgers/webledgers.json",
            serde_json::to_vec(&ledger).unwrap().into(),
            "application/json",
        )
        .await
        .unwrap();

    let app = test::init_service(build_app(st)).await;

    // Add liquidity 5000/5000.
    let (auth, _) = nip98_auth("POST", "/pay/.pool");
    let req = test::TestRequest::post()
        .uri("/pay/.pool")
        .insert_header((header::AUTHORIZATION, auth))
        .set_json(serde_json::json!({
            "action": "add-liquidity",
            "currency_a": "tbtc4",
            "currency_b": "tbtc3",
            "amount_a": 5000,
            "amount_b": 5000,
            "fee_bps": 0
        }))
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(rsp.status().as_u16(), 200);
    let json: Value = test::read_body_json(rsp).await;
    assert_eq!(json["action"], "add-liquidity");
    assert!(json["shares"].as_u64().unwrap() > 0);

    // Swap 1000 tbtc4 → tbtc3 (zero fee → 833 out, per trading.rs unit test).
    let (auth, _) = nip98_auth("POST", "/pay/.pool");
    let req = test::TestRequest::post()
        .uri("/pay/.pool")
        .insert_header((header::AUTHORIZATION, auth))
        .set_json(serde_json::json!({
            "action": "swap",
            "currency_a": "tbtc4",
            "currency_b": "tbtc3",
            "from_currency": "tbtc4",
            "amount_in": 1000,
            "fee_bps": 0
        }))
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(rsp.status().as_u16(), 200, "pool swap should succeed");
    let json: Value = test::read_body_json(rsp).await;
    assert_eq!(json["action"], "swap");
    assert_eq!(json["amount_out"], 833);
}
