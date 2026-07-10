//! Integration tests for the Phase-4 Bitcoin write-side routes
//! (`handlers/pay.rs`): `POST /pay/.buy`, `/pay/.withdraw`,
//! `/pay/.withdraw-sats`.
//!
//! No live chain: a throwaway `actix_web::HttpServer` on an ephemeral port
//! serves a fixture mempool — `GET /api/tx/{txid}` (returns the spent output's
//! scriptPubKey), `GET /api/address/{addr}/utxo`, and `POST /api/tx`
//! (broadcast → returns a synthetic txid). `AppState::mempool_url` points the
//! handlers at it, so the `MempoolHttpClient` HTTP path (lookup **and**
//! broadcast) is genuinely exercised.
//!
//! These assert the routes wire the verified `bitcoin_tx` crypto end-to-end:
//! buy/withdraw move tokens (debiting sats, appending the trail, returning a
//! portable proof); withdraw-sats mints a fresh TXO voucher from a funding
//! voucher.

use std::sync::Arc;

use actix_web::http::header;
use actix_web::{test, web, App, HttpResponse};
use serde_json::{json, Value};
use solid_pod_rs::auth::nip98;
use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::trail_store::{save_trail, StoredTrail};
use solid_pod_rs_server::{build_app, AppState};

const NETWORK: &str = "testnet4";
// Issuer (pod) key — controls the trail.
const ISSUER_PRIVKEY: &str = "0000000000000000000000000000000000000000000000000000000000000007";
// Buyer/withdrawer NIP-98 key.
const USER_SK: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn issuer_pubkey() -> String {
    let sk = k256::SecretKey::from_slice(&hex::decode(ISSUER_PRIVKEY).unwrap()).unwrap();
    hex::encode(sk.public_key().to_sec1_bytes())
}

fn issuer_xonly_hex() -> String {
    let sk = k256::SecretKey::from_slice(&hex::decode(ISSUER_PRIVKEY).unwrap()).unwrap();
    let c = sk.public_key().to_sec1_bytes();
    hex::encode(&c[1..])
}

fn user_pubkey() -> String {
    let sk = hex::decode(USER_SK).unwrap();
    let sk = k256::schnorr::SigningKey::from_bytes(&sk).unwrap();
    // NIP-98 uses the x-only pubkey as the did:nostr identity.
    hex::encode(sk.verifying_key().to_bytes())
}

fn nip98_auth(method: &str, path: &str) -> (String, String) {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;
    // Each token MUST be a distinct NIP-98 event: the server's single-use replay
    // guard (`NIP98_REPLAY`, a process-global `LazyLock`) rejects a repeated
    // event_id with 401, and tokens minted in the same second with the same
    // key/url/method are otherwise identical. Anchor `created_at` to a base
    // captured once (30s in the past) + a monotonic per-call counter — strictly
    // unique regardless of wall-clock drift, within the ±60s tolerance window.
    static BASE: OnceLock<u64> = OnceLock::new();
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let base = *BASE.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(30)
    });
    let now = base + SEQ.fetch_add(1, Ordering::Relaxed);
    let url = format!("http://localhost:8080{path}");
    let token = nip98::mint(&url, method, USER_SK, now).expect("nip98 mint");
    (
        format!("Nostr {token}"),
        format!("did:nostr:{}", user_pubkey()),
    )
}

/// `AppState` with a configured pay-token (the issuer's) + a sat balance for
/// the user, and a minted trail persisted at `/.well-known/token/test.json`.
async fn state_with_minted_trail(
    mempool_url: String,
    user_balance: u64,
) -> (AppState, Arc<dyn Storage>) {
    let st = AppState::new(Arc::new(MemoryBackend::new()));
    let storage = st.storage.clone();

    // Pay-token config (ticker TEST, rate 1 sat/token).
    let mut st = st;
    st.pay_config.token = Some(solid_pod_rs::payments::TokenConfig {
        ticker: "TEST".into(),
        rate: 1,
        supply: 1000,
        issuer: issuer_pubkey(),
    });
    st.mempool_url = Some(mempool_url);

    // Seed the user's ledger balance (idiomatic: WebLedger + credit).
    let did = format!("did:nostr:{}", user_pubkey());
    let mut ledger = solid_pod_rs::payments::WebLedger::new("Pod Credits");
    ledger.credit(&did, user_balance);
    storage
        .put(
            "/.well-known/webledgers/webledgers.json",
            bytes::Bytes::from(serde_json::to_vec(&ledger).unwrap()),
            "application/json",
        )
        .await
        .unwrap();

    // Mint a genesis trail (seq 0) controlled by the issuer key. The genesis
    // state must match what `transfer_token_with_key` expects: profile, prev,
    // ticker, name, decimals, supply, balances keyed on issuer pubkey.
    use solid_pod_rs::mrc20::{jcs, Mrc20State, MRC20_PROFILE};
    let genesis = Mrc20State {
        profile: MRC20_PROFILE.into(),
        prev: "0".repeat(64),
        seq: 0,
        ticker: Some("TEST".into()),
        name: Some("Test Token".into()),
        decimals: Some(0),
        supply: Some(1000),
        balances: Some(std::collections::BTreeMap::from([(issuer_pubkey(), 1000)])),
        ops: vec![],
        anchor: None,
    };
    let genesis_jcs = jcs(&serde_json::to_value(&genesis).unwrap());

    let stored = StoredTrail {
        ticker: "TEST".into(),
        name: "Test Token".into(),
        supply: 1000,
        privkey: ISSUER_PRIVKEY.into(),
        pubkey_base: issuer_pubkey(),
        states: vec![genesis],
        state_strings: vec![genesis_jcs],
        current_txid: "aa".repeat(32),
        current_vout: 0,
        current_amount: 50_000,
        network: NETWORK.into(),
        date_created: "2026-06-13T00:00:00Z".into(),
    };
    save_trail(&storage, &stored).await.unwrap();

    (st, storage)
}

/// Fixture mempool: `GET /api/tx/{txid}` returns a tx whose vout[0] pays the
/// genesis chained-key scriptPubKey (so the transfer can spend the trail
/// UTXO), `GET /api/address/{addr}/utxo` returns `[]`, and `POST /api/tx`
/// echoes a synthetic txid (sha256 of the raw body, hex). The genesis
/// scriptPubKey is `5120<chained-xonly>` for the single-state chain.
async fn spawn_fixture(genesis_spk_hex: String) -> (String, actix_web::dev::ServerHandle) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let spk = web::Data::new(genesis_spk_hex);

    let server = actix_web::HttpServer::new(move || {
        App::new()
            .app_data(spk.clone())
            .route(
                "/api/tx/{txid}",
                web::get().to(|_p: web::Path<String>, spk: web::Data<String>| async move {
                    let body = json!({
                        "txid": "aa".repeat(32),
                        "vout": [ { "value": 50000, "scriptpubkey": spk.get_ref() } ],
                        "status": { "confirmed": true, "block_height": 42000 }
                    });
                    HttpResponse::Ok()
                        .content_type("application/json")
                        .body(body.to_string())
                }),
            )
            .route(
                "/api/address/{addr}/utxo",
                web::get().to(|_p: web::Path<String>| async {
                    HttpResponse::Ok()
                        .content_type("application/json")
                        .body("[]")
                }),
            )
            .route(
                "/api/tx",
                web::post().to(|body: bytes::Bytes| async move {
                    let raw = String::from_utf8_lossy(&body);
                    let txid = solid_pod_rs::mrc20::sha256_hex(&raw);
                    HttpResponse::Ok().content_type("text/plain").body(txid)
                }),
            )
    })
    .listen(listener)
    .unwrap()
    .workers(1)
    .run();

    let handle = server.handle();
    tokio::spawn(server);
    (format!("http://127.0.0.1:{port}"), handle)
}

/// Genesis chained-key scriptPubKey (`5120<xonly>`) for the single-state TEST
/// trail — what the trail's current UTXO pays, so the transfer spends it
/// untweaked.
fn genesis_spk_hex() -> String {
    use solid_pod_rs::mrc20::{bt_derive_chained_pubkey, jcs, Mrc20State, MRC20_PROFILE};
    let genesis = Mrc20State {
        profile: MRC20_PROFILE.into(),
        prev: "0".repeat(64),
        seq: 0,
        ticker: Some("TEST".into()),
        name: Some("Test Token".into()),
        decimals: Some(0),
        supply: Some(1000),
        balances: Some(std::collections::BTreeMap::from([(issuer_pubkey(), 1000)])),
        ops: vec![],
        anchor: None,
    };
    let genesis_jcs = jcs(&serde_json::to_value(&genesis).unwrap());
    let chained = bt_derive_chained_pubkey(&issuer_pubkey(), &[genesis_jcs]).unwrap();
    format!("5120{}", hex::encode(&chained[1..]))
}

// ── /pay/.buy ────────────────────────────────────────────────────────────

#[actix_web::test]
async fn buy_moves_tokens_and_debits_sats() {
    let (mempool_url, handle) = spawn_fixture(genesis_spk_hex()).await;
    let (st, storage) = state_with_minted_trail(mempool_url, 500).await;
    let app = test::init_service(build_app(st)).await;

    let (auth, _did) = nip98_auth("POST", "/pay/.buy");
    let req = test::TestRequest::post()
        .uri("/pay/.buy")
        .insert_header((header::AUTHORIZATION, auth))
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload(json!({ "amount": 100 }).to_string())
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "buy must succeed");
    let body: Value = test::read_body_json(resp).await;

    assert_eq!(body["bought"], 100);
    assert_eq!(body["ticker"], "TEST");
    assert_eq!(body["cost"], 100);
    assert_eq!(body["balance"], 400, "500 - 100 sats");
    assert!(body["txid"].is_string());
    // Portable proof present (state + prevState + anchor).
    assert!(body["proof"]["state"].is_object());
    assert!(body["proof"]["prevState"].is_object());
    assert_eq!(body["proof"]["anchor"]["pubkey"], issuer_pubkey());
    assert_eq!(body["proof"]["anchor"]["network"], NETWORK);

    // The trail was appended (seq-1 transfer state persisted).
    let (bytes, _) = storage.get("/.well-known/token/test.json").await.unwrap();
    let stored: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(stored["states"].as_array().unwrap().len(), 2);
    assert_eq!(stored["states"][1]["seq"], 1);

    let _ = issuer_xonly_hex(); // silence unused in some cfgs
    handle.stop(false).await;
}

#[actix_web::test]
async fn buy_rejects_insufficient_balance() {
    let (mempool_url, handle) = spawn_fixture(genesis_spk_hex()).await;
    let (st, _storage) = state_with_minted_trail(mempool_url, 10).await; // only 10 sats
    let app = test::init_service(build_app(st)).await;

    let (auth, _did) = nip98_auth("POST", "/pay/.buy");
    let req = test::TestRequest::post()
        .uri("/pay/.buy")
        .insert_header((header::AUTHORIZATION, auth))
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload(json!({ "amount": 100 }).to_string())
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 402, "insufficient balance ⇒ 402");
    handle.stop(false).await;
}

#[actix_web::test]
async fn buy_requires_nip98() {
    let (mempool_url, handle) = spawn_fixture(genesis_spk_hex()).await;
    let (st, _storage) = state_with_minted_trail(mempool_url, 500).await;
    let app = test::init_service(build_app(st)).await;

    let req = test::TestRequest::post()
        .uri("/pay/.buy")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload(json!({ "amount": 100 }).to_string())
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401, "no NIP-98 ⇒ 401");
    handle.stop(false).await;
}

// ── /pay/.withdraw ───────────────────────────────────────────────────────

#[actix_web::test]
async fn withdraw_all_moves_tokens_and_zeroes_balance() {
    let (mempool_url, handle) = spawn_fixture(genesis_spk_hex()).await;
    let (st, _storage) = state_with_minted_trail(mempool_url, 250).await;
    let app = test::init_service(build_app(st)).await;

    let (auth, _did) = nip98_auth("POST", "/pay/.withdraw");
    let req = test::TestRequest::post()
        .uri("/pay/.withdraw")
        .insert_header((header::AUTHORIZATION, auth))
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload(json!({ "all": true }).to_string())
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "withdraw all must succeed");
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["withdrawn"], 250, "250 sats / rate 1 = 250 tokens");
    assert_eq!(body["cost"], 250);
    assert_eq!(body["balance"], 0);
    assert!(body["proof"]["anchor"]["stateStrings"].is_array());
    handle.stop(false).await;
}

// ── /pay/.withdraw-sats ──────────────────────────────────────────────────

#[actix_web::test]
async fn withdraw_sats_mints_a_voucher() {
    // The funding voucher: a fresh key controlling a 20000-sat output. The
    // fixture `/api/tx` returns its scriptPubKey (untweaked key-path output of
    // the funding key) so the build signs the untweaked path.
    let funding_sk = "0000000000000000000000000000000000000000000000000000000000000009";
    let fsk = k256::SecretKey::from_slice(&hex::decode(funding_sk).unwrap()).unwrap();
    let funding_xonly = hex::encode(&fsk.public_key().to_sec1_bytes()[1..]);
    let funding_spk = format!("5120{funding_xonly}");
    let funding_txid = "ff".repeat(32);

    // Fixture that returns the FUNDING output's scriptPubKey for /api/tx.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let spk = web::Data::new(funding_spk.clone());
    let server = actix_web::HttpServer::new(move || {
        App::new()
            .app_data(spk.clone())
            .route(
                "/api/tx/{txid}",
                web::get().to(|_p: web::Path<String>, spk: web::Data<String>| async move {
                    let body = json!({
                        "txid": "ff".repeat(32),
                        "vout": [ { "value": 20000, "scriptpubkey": spk.get_ref() } ],
                        "status": { "confirmed": true, "block_height": 42000 }
                    });
                    HttpResponse::Ok()
                        .content_type("application/json")
                        .body(body.to_string())
                }),
            )
            .route(
                "/api/tx",
                web::post().to(|body: bytes::Bytes| async move {
                    let txid = solid_pod_rs::mrc20::sha256_hex(&String::from_utf8_lossy(&body));
                    HttpResponse::Ok().content_type("text/plain").body(txid)
                }),
            )
    })
    .listen(listener)
    .unwrap()
    .workers(1)
    .run();
    let handle = server.handle();
    tokio::spawn(server);
    let mempool_url = format!("http://127.0.0.1:{port}");

    let (st, _storage) = state_with_minted_trail(mempool_url, 50_000).await;
    let app = test::init_service(build_app(st)).await;

    let funding_uri = format!("txo:tbtc4:{funding_txid}:0?amount=20000&key={funding_sk}");
    let (auth, _did) = nip98_auth("POST", "/pay/.withdraw-sats");
    let req = test::TestRequest::post()
        .uri("/pay/.withdraw-sats")
        .insert_header((header::AUTHORIZATION, auth))
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload(
            json!({ "amount": 10000, "chain": "tbtc4", "funding": funding_uri }).to_string(),
        )
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "withdraw-sats must mint a voucher");
    let body: Value = test::read_body_json(resp).await;

    let voucher = body["voucher"].as_str().expect("voucher URI present");
    assert!(voucher.starts_with("txo:tbtc4:"), "voucher: {voucher}");
    assert!(voucher.contains("?amount=10000&key="));
    assert_eq!(body["amount"], 10000);
    assert_eq!(body["balance"], 40_000, "50000 - 10000 withdrawn");

    // The minted voucher is parseable and carries a valid fresh key.
    let parsed = solid_pod_rs::bitcoin_tx::parse_txo_voucher(voucher).unwrap();
    assert_eq!(parsed.amount, 10000);
    assert_eq!(parsed.privkey.len(), 64);
    handle.stop(false).await;
}

#[actix_web::test]
async fn withdraw_sats_rejects_insufficient_funding() {
    let funding_sk = "0000000000000000000000000000000000000000000000000000000000000009";
    let funding_txid = "ff".repeat(32);
    let fsk = k256::SecretKey::from_slice(&hex::decode(funding_sk).unwrap()).unwrap();
    let funding_xonly = hex::encode(&fsk.public_key().to_sec1_bytes()[1..]);
    let funding_spk = format!("5120{funding_xonly}");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let spk = web::Data::new(funding_spk);
    let server = actix_web::HttpServer::new(move || {
        App::new().app_data(spk.clone()).route(
            "/api/tx/{txid}",
            web::get().to(|_p: web::Path<String>, spk: web::Data<String>| async move {
                let body = json!({
                    "txid": "ff".repeat(32),
                    "vout": [ { "value": 500, "scriptpubkey": spk.get_ref() } ],
                    "status": { "confirmed": true, "block_height": 42000 }
                });
                HttpResponse::Ok()
                    .content_type("application/json")
                    .body(body.to_string())
            }),
        )
    })
    .listen(listener)
    .unwrap()
    .workers(1)
    .run();
    let handle = server.handle();
    tokio::spawn(server);
    let mempool_url = format!("http://127.0.0.1:{port}");

    let (st, _storage) = state_with_minted_trail(mempool_url, 50_000).await;
    let app = test::init_service(build_app(st)).await;

    // Funding voucher claims 500 sats — too small for 10000 + fee.
    let funding_uri = format!("txo:tbtc4:{funding_txid}:0?amount=500&key={funding_sk}");
    let (auth, _did) = nip98_auth("POST", "/pay/.withdraw-sats");
    let req = test::TestRequest::post()
        .uri("/pay/.withdraw-sats")
        .insert_header((header::AUTHORIZATION, auth))
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload(
            json!({ "amount": 10000, "chain": "tbtc4", "funding": funding_uri }).to_string(),
        )
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400, "insufficient funding ⇒ 400");
    handle.stop(false).await;
}
