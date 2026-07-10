//! Integration tests for the Phase-3 MRC20 deposit + per-user deposit
//! address routes (`handlers/pay.rs`), the provenance-upgrade read-side.
//!
//! These exercise:
//!
//! * `POST /pay/.deposit` (MRC20 JSON path) — a block-trail anchor proof is
//!   verified against **mempool state** and the verified token amount is
//!   credited. The mempool is a LOCAL fixture HTTP server (no mempool.space):
//!   - credits when a UTXO exists at the derived taproot address;
//!   - rejects (no credit) when the derived address has no UTXO;
//!   - replay-guards a second POST of the same state hash.
//! * `GET /pay/.address` — per-user tweaked address derivation is
//!   deterministic and DID-validated; the generic pod address differs from a
//!   per-user one.
//!
//! No network: a throwaway `actix_web::HttpServer` bound to an ephemeral
//! port serves the captured mempool JSON, and `AppState::mempool_url` points
//! the deposit handler at it. The `MempoolHttpClient` HTTP path is therefore
//! genuinely exercised, just against a fixture origin.

use std::sync::Arc;

use actix_web::http::header;
use actix_web::{test, web, App, HttpResponse};
use serde_json::{json, Value};
use solid_pod_rs::auth::nip98;
use solid_pod_rs::mrc20::{bt_address, jcs, Mrc20Op, Mrc20State, TRANSFER_OP};
use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs_server::{build_app, AppState};

const SK_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const NETWORK: &str = "testnet4";

/// The issuer keypair the pod is configured with. Deterministic — the
/// derived addresses are stable across runs.
const ISSUER_PRIVKEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";

fn issuer_pubkey() -> String {
    let sk = k256::SecretKey::from_slice(&hex::decode(ISSUER_PRIVKEY).unwrap()).unwrap();
    hex::encode(sk.public_key().to_sec1_bytes())
}

/// Build an `AppState` whose `pay_config.token.issuer` is the test issuer,
/// so `/pay/.address` and the MRC20 deposit have a key to derive against.
fn state_with_issuer(mempool_url: Option<String>) -> AppState {
    let mut st = AppState::new(Arc::new(MemoryBackend::new()));
    st.pay_config.token = Some(solid_pod_rs::payments::TokenConfig {
        ticker: "TEST".into(),
        rate: 1,
        supply: 1000,
        issuer: issuer_pubkey(),
    });
    st.mempool_url = mempool_url;
    st
}

fn nip98_auth(method: &str, path: &str) -> (String, String) {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;
    // Each minted token MUST be a distinct NIP-98 event. The server's single-use
    // replay guard (`NIP98_REPLAY`) is a process-global `LazyLock`, so two tokens
    // sharing key/url/method/created_at collide on event_id and the second is
    // replay-rejected (401) — a test-isolation flake across tests in one process.
    // Anchor `created_at` to a base captured ONCE (30s in the past) and add a
    // monotonic per-call counter: values are strictly increasing and unique
    // regardless of wall-clock drift (so they never collide the way a
    // `now - counter` scheme can when the clock advances), and stay comfortably
    // inside the ±60s `TIMESTAMP_TOLERANCE` window.
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
    let token = nip98::mint(&url, method, SK_HEX, now).expect("nip98 mint");
    let sk = hex::decode(SK_HEX).unwrap();
    let signing = k256::schnorr::SigningKey::from_bytes(&sk).unwrap();
    let pubkey = hex::encode(signing.verifying_key().to_bytes());
    (format!("Nostr {token}"), format!("did:nostr:{pubkey}"))
}

// ---------------------------------------------------------------------------
// Fixture mempool HTTP server (no mempool.space)
// ---------------------------------------------------------------------------

/// Spawn a local HTTP server that answers `GET /api/address/{addr}/utxo`.
/// If `addr == utxo_address` it returns a one-element UTXO list; otherwise
/// (and for any other address) an empty list `[]`. Returns the base URL.
async fn spawn_fixture_mempool(
    utxo_address: Option<String>,
) -> (String, actix_web::dev::ServerHandle) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let utxo_address = web::Data::new(utxo_address);

    let server = actix_web::HttpServer::new(move || {
        App::new().app_data(utxo_address.clone()).route(
            "/api/address/{addr}/utxo",
            web::get().to(
                |path: web::Path<String>, want: web::Data<Option<String>>| async move {
                    let addr = path.into_inner();
                    let matches = want
                        .get_ref()
                        .as_deref()
                        .map(|w| w == addr)
                        .unwrap_or(false);
                    if matches {
                        HttpResponse::Ok().content_type("application/json").body(
                            r#"[{"txid":"abababababababababababababababababababababababababababababababab","vout":0,"value":9700,"status":{"confirmed":true,"block_height":42000}}]"#,
                        )
                    } else {
                        HttpResponse::Ok().content_type("application/json").body("[]")
                    }
                },
            ),
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

// ---------------------------------------------------------------------------
// MRC20 state-chain fixture builder
// ---------------------------------------------------------------------------

/// Build a `(genesis, transfer, state_strings, anchor_address, pod_address)`
/// fixture: a genesis MRC20 state and a transfer state that sends `amount`
/// tokens to the pod's generic deposit address. `anchor_address` is where
/// the UTXO must sit for verification to pass.
fn build_mrc20_fixture(amount: u64) -> (Mrc20State, Mrc20State, Vec<String>, String, String) {
    let issuer = issuer_pubkey();
    // The pod's generic deposit address (no tweak) — transfers target it.
    let pod_address = bt_address(&issuer, &[], NETWORK).unwrap();

    let genesis = Mrc20State {
        profile: solid_pod_rs::mrc20::MRC20_PROFILE.into(),
        prev: "0".repeat(64),
        seq: 0,
        ticker: Some("TEST".into()),
        name: Some("Test Token".into()),
        decimals: Some(0),
        supply: Some(1000),
        balances: Some(std::collections::BTreeMap::from([(issuer.clone(), 1000)])),
        ops: vec![],
        anchor: None,
    };
    let genesis_jcs = jcs(&serde_json::to_value(&genesis).unwrap());
    let genesis_hash = solid_pod_rs::mrc20::sha256_hex(&genesis_jcs);

    let transfer = Mrc20State {
        profile: solid_pod_rs::mrc20::MRC20_PROFILE.into(),
        prev: genesis_hash,
        seq: 1,
        ticker: Some("TEST".into()),
        name: Some("Test Token".into()),
        decimals: Some(0),
        supply: Some(1000),
        balances: Some(std::collections::BTreeMap::from([
            (issuer.clone(), 1000 - amount),
            (pod_address.clone(), amount),
        ])),
        ops: vec![Mrc20Op {
            op: TRANSFER_OP.into(),
            from: Some(issuer.clone()),
            to: Some(pod_address.clone()),
            amt: Some(amount),
        }],
        anchor: None,
    };
    let transfer_jcs = jcs(&serde_json::to_value(&transfer).unwrap());

    let state_strings = vec![genesis_jcs, transfer_jcs];
    // Where the anchoring UTXO must live (full chain → derived address).
    let anchor_address = bt_address(&issuer, &state_strings, NETWORK).unwrap();

    (
        genesis,
        transfer,
        state_strings,
        anchor_address,
        pod_address,
    )
}

fn mrc20_deposit_body(state: &Mrc20State, prev: &Mrc20State, state_strings: &[String]) -> Value {
    json!({
        "type": "mrc20",
        "state": state,
        "prevState": prev,
        "anchor": {
            "pubkey": issuer_pubkey(),
            "stateStrings": state_strings,
            "network": NETWORK,
        }
    })
}

// ---------------------------------------------------------------------------
// MRC20 deposit — credit on found UTXO
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn mrc20_deposit_credits_when_utxo_present() {
    let (genesis, transfer, state_strings, anchor_address, _pod) = build_mrc20_fixture(100);
    // Fixture mempool returns a UTXO at the derived anchor address.
    let (mempool_url, handle) = spawn_fixture_mempool(Some(anchor_address)).await;

    let st = state_with_issuer(Some(mempool_url));
    let storage = st.storage.clone();
    let app = test::init_service(build_app(st)).await;

    let (auth, did) = nip98_auth("POST", "/pay/.deposit");
    let body = mrc20_deposit_body(&transfer, &genesis, &state_strings);

    let req = test::TestRequest::post()
        .uri("/pay/.deposit")
        .insert_header((header::AUTHORIZATION, auth))
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload(serde_json::to_vec(&body).unwrap())
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(
        rsp.status().as_u16(),
        200,
        "anchor with present UTXO should credit"
    );
    let j: Value = test::read_body_json(rsp).await;
    assert_eq!(j["deposited"], 100);
    assert_eq!(j["balance"], 100);
    assert_eq!(j["unit"], "token");
    assert_eq!(j["ticker"], "TEST");

    // Ledger actually credited.
    let (bytes, _) = storage
        .get("/.well-known/webledgers/webledgers.json")
        .await
        .unwrap();
    let ledger: solid_pod_rs::payments::WebLedger = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(ledger.get_balance(&did), 100);

    handle.stop(false).await;
}

#[actix_web::test]
async fn mrc20_deposit_rejected_when_no_utxo() {
    let (genesis, transfer, state_strings, _anchor, _pod) = build_mrc20_fixture(100);
    // Fixture mempool has NOTHING at any address → anchor unverifiable.
    let (mempool_url, handle) = spawn_fixture_mempool(None).await;

    let st = state_with_issuer(Some(mempool_url));
    let storage = st.storage.clone();
    let app = test::init_service(build_app(st)).await;

    let (auth, did) = nip98_auth("POST", "/pay/.deposit");
    let body = mrc20_deposit_body(&transfer, &genesis, &state_strings);

    let req = test::TestRequest::post()
        .uri("/pay/.deposit")
        .insert_header((header::AUTHORIZATION, auth))
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload(serde_json::to_vec(&body).unwrap())
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(rsp.status().as_u16(), 400, "no UTXO ⇒ deposit rejected");
    let j: Value = test::read_body_json(rsp).await;
    assert!(
        j["error"].as_str().unwrap_or("").contains("no UTXO"),
        "expected a no-UTXO error, got: {j}"
    );

    // No ledger was written (nothing credited).
    let credited = match storage.get("/.well-known/webledgers/webledgers.json").await {
        Ok((bytes, _)) => {
            let l: solid_pod_rs::payments::WebLedger = serde_json::from_slice(&bytes).unwrap();
            l.get_balance(&did)
        }
        Err(_) => 0,
    };
    assert_eq!(credited, 0, "a failed anchor must not credit");

    handle.stop(false).await;
}

#[actix_web::test]
async fn mrc20_deposit_replay_is_rejected() {
    let (genesis, transfer, state_strings, anchor_address, _pod) = build_mrc20_fixture(100);
    let (mempool_url, handle) = spawn_fixture_mempool(Some(anchor_address)).await;

    let st = state_with_issuer(Some(mempool_url));
    let storage = st.storage.clone();
    let app = test::init_service(build_app(st)).await;

    let body = mrc20_deposit_body(&transfer, &genesis, &state_strings);
    let payload = serde_json::to_vec(&body).unwrap();

    // First deposit — credited.
    let (auth1, did) = nip98_auth("POST", "/pay/.deposit");
    let req = test::TestRequest::post()
        .uri("/pay/.deposit")
        .insert_header((header::AUTHORIZATION, auth1))
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload(payload.clone())
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(rsp.status().as_u16(), 200);

    // Second deposit of the SAME state — replay-rejected, no double-credit.
    let (auth2, _) = nip98_auth("POST", "/pay/.deposit");
    let req = test::TestRequest::post()
        .uri("/pay/.deposit")
        .insert_header((header::AUTHORIZATION, auth2))
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload(payload)
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(
        rsp.status().as_u16(),
        400,
        "replayed state must be rejected"
    );
    let j: Value = test::read_body_json(rsp).await;
    assert!(j["error"].as_str().unwrap_or("").contains("Replay"));

    let (bytes, _) = storage
        .get("/.well-known/webledgers/webledgers.json")
        .await
        .unwrap();
    let ledger: solid_pod_rs::payments::WebLedger = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        ledger.get_balance(&did),
        100,
        "replay must not double-credit"
    );

    handle.stop(false).await;
}

// ---------------------------------------------------------------------------
// GET /pay/.address — per-user tweaked deposit address
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn address_generic_and_per_user_are_deterministic_and_distinct() {
    let st = state_with_issuer(None);
    let app = test::init_service(build_app(st)).await;

    // Generic pod address (no user).
    let req = test::TestRequest::get()
        .uri("/pay/.address?chain=tbtc4")
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(rsp.status().as_u16(), 200);
    let generic: Value = test::read_body_json(rsp).await;
    let generic_addr = generic["address"].as_str().unwrap().to_string();
    assert!(
        generic_addr.starts_with("tb1p"),
        "testnet4 P2TR, got {generic_addr}"
    );
    assert_eq!(generic["pubkey"], issuer_pubkey());
    assert!(generic.get("user").is_none());

    // Per-user tweaked address.
    let user = format!("did:nostr:{}", "a".repeat(64));
    let req = test::TestRequest::get()
        .uri(&format!("/pay/.address?chain=tbtc4&user={user}"))
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(rsp.status().as_u16(), 200);
    let per_user: Value = test::read_body_json(rsp).await;
    let user_addr = per_user["address"].as_str().unwrap().to_string();
    assert_eq!(per_user["user"], user);

    // Distinct from the generic address, and determinism: a second call
    // yields the identical address.
    assert_ne!(
        user_addr, generic_addr,
        "tweaked address must differ from generic"
    );

    let req = test::TestRequest::get()
        .uri(&format!("/pay/.address?chain=tbtc4&user={user}"))
        .to_request();
    let rsp = test::call_service(&app, req).await;
    let per_user2: Value = test::read_body_json(rsp).await;
    assert_eq!(
        per_user2["address"].as_str().unwrap(),
        user_addr,
        "per-user derivation must be deterministic"
    );

    // Cross-check the server's derivation against the library directly.
    let expected = bt_address(&issuer_pubkey(), std::slice::from_ref(&user), "testnet4").unwrap();
    assert_eq!(user_addr, expected);
}

#[actix_web::test]
async fn address_rejects_malformed_did() {
    let st = state_with_issuer(None);
    let app = test::init_service(build_app(st)).await;

    let req = test::TestRequest::get()
        .uri("/pay/.address?chain=tbtc4&user=not-a-did")
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(rsp.status().as_u16(), 400, "malformed DID must be rejected");
    let j: Value = test::read_body_json(rsp).await;
    assert!(j["error"]
        .as_str()
        .unwrap_or("")
        .contains("Invalid user DID"));
}

#[actix_web::test]
async fn address_mainnet_chain_yields_bc1p() {
    let st = state_with_issuer(None);
    let app = test::init_service(build_app(st)).await;

    let req = test::TestRequest::get()
        .uri("/pay/.address?chain=btc")
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(rsp.status().as_u16(), 200);
    let j: Value = test::read_body_json(rsp).await;
    assert!(
        j["address"].as_str().unwrap().starts_with("bc1p"),
        "btc chain ⇒ mainnet P2TR"
    );
    assert_eq!(j["chain"], "btc");
}
