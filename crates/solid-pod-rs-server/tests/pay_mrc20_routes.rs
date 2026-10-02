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
        accepted_issuers: Vec::new(),
    });
    st.mempool_url = mempool_url;
    st
}

fn nip98_auth(method: &str, path: &str, body: Option<&[u8]>) -> (String, String) {
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
    let token = nip98::mint_with_payload(&url, method, body, SK_HEX, now).expect("nip98 mint");
    let sk = hex::decode(SK_HEX).unwrap();
    let signing = k256::schnorr::SigningKey::from_bytes(&sk).unwrap();
    let pubkey = hex::encode(signing.verifying_key().to_bytes());
    (format!("Nostr {token}"), format!("did:nostr:{pubkey}"))
}

// ---------------------------------------------------------------------------
// Fixture mempool HTTP server (no mempool.space)
// ---------------------------------------------------------------------------

/// The on-chain side of a fixture trail: one transaction per state, each
/// paying the key its prefix of states derives and spending the one before.
#[derive(Clone)]
struct ChainFixture {
    /// The head mark's txid (its output 0 is the UTXO at the trail address).
    head: String,
    /// mempool.space `GET /api/tx/{txid}` bodies for every mark.
    txs: Vec<(String, Value)>,
}

/// Every trail [`build_trail_fixture`] built, by its anchor address, so the
/// fixture mempool can serve the whole chain behind an address.
fn chains() -> &'static std::sync::Mutex<std::collections::HashMap<String, ChainFixture>> {
    static CHAINS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, ChainFixture>>,
    > = std::sync::OnceLock::new();
    CHAINS.get_or_init(Default::default)
}

fn register_chain(issuer: &str, state_strings: &[String], address: &str) {
    let outputs = solid_pod_rs::mrc20::bt_trail_outputs(issuer, state_strings).unwrap();
    let mut prev = "ff".repeat(32);
    let mut txs = Vec::new();
    for (i, x) in outputs.iter().enumerate() {
        let txid = solid_pod_rs::mrc20::sha256_hex(&format!("{address} mark {i}"));
        txs.push((
            txid.clone(),
            json!({
                "txid": txid,
                "vin": [{"txid": prev, "vout": 0}],
                "vout": [{"scriptpubkey": format!("5120{}", hex::encode(x)), "value": 9700}],
                "status": {"confirmed": true, "block_height": 42000 + i},
            }),
        ));
        prev = txid;
    }
    chains()
        .lock()
        .unwrap()
        .insert(address.to_string(), ChainFixture { head: prev, txs });
}

/// Spawn a local HTTP server that answers `GET /api/address/{addr}/utxo` and
/// `GET /api/tx/{txid}`: each address in `utxo_addresses` holds the head mark
/// of the trail built for it, and every mark of those trails is served, so
/// the deposit's per-link walk finds the whole chain. Any other address has
/// no UTXO. Returns the base URL.
async fn spawn_fixture_mempool(
    utxo_addresses: Vec<String>,
) -> (String, actix_web::dev::ServerHandle) {
    let pairs = utxo_addresses.into_iter().map(|a| (a.clone(), a)).collect();
    spawn_fixture_mempool_with(pairs).await
}

/// [`spawn_fixture_mempool`] where each `(address, trail_address)` pair puts
/// the head mark of the trail built for `trail_address` at `address`.
async fn spawn_fixture_mempool_with(
    utxos: Vec<(String, String)>,
) -> (String, actix_web::dev::ServerHandle) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let registry = chains().lock().unwrap().clone();
    let mut heads = std::collections::HashMap::new();
    let mut txs = std::collections::HashMap::new();
    for (address, trail) in utxos {
        let chain = registry
            .get(&trail)
            .expect("trail built by build_trail_fixture");
        heads.insert(address, chain.head.clone());
        txs.extend(chain.txs.iter().cloned());
    }
    let heads = web::Data::new(heads);
    let txs = web::Data::new(txs);

    let server = actix_web::HttpServer::new(move || {
        App::new()
            .app_data(heads.clone())
            .app_data(txs.clone())
            .route(
                "/api/address/{addr}/utxo",
                web::get().to(
                    |path: web::Path<String>,
                     heads: web::Data<std::collections::HashMap<String, String>>| async move {
                        let body = match heads.get(&path.into_inner()) {
                            Some(txid) => json!([{
                                "txid": txid, "vout": 0, "value": 9700,
                                "status": {"confirmed": true, "block_height": 42000},
                            }])
                            .to_string(),
                            None => "[]".to_string(),
                        };
                        HttpResponse::Ok().content_type("application/json").body(body)
                    },
                ),
            )
            .route(
                "/api/tx/{txid}",
                web::get().to(
                    |path: web::Path<String>,
                     txs: web::Data<std::collections::HashMap<String, Value>>| async move {
                        match txs.get(&path.into_inner()) {
                            Some(tx) => HttpResponse::Ok()
                                .content_type("application/json")
                                .body(tx.to_string()),
                            None => HttpResponse::NotFound().body("Transaction not found"),
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
    build_trail_fixture(&issuer_pubkey(), "TEST", amount)
}

/// [`build_mrc20_fixture`] for a trail issued by `issuer` (any key) under
/// `ticker`, still transferring to the POD's deposit address.
fn build_trail_fixture(
    issuer: &str,
    ticker: &str,
    amount: u64,
) -> (Mrc20State, Mrc20State, Vec<String>, String, String) {
    let issuer = issuer.to_string();
    // The pod's generic deposit address (no tweak) — transfers target it.
    let pod_address = bt_address(&issuer_pubkey(), &[], NETWORK).unwrap();

    let genesis = Mrc20State {
        profile: solid_pod_rs::mrc20::MRC20_PROFILE.into(),
        prev: "0".repeat(64),
        seq: 0,
        ticker: Some(ticker.into()),
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
        ticker: Some(ticker.into()),
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
    register_chain(&issuer, &state_strings, &anchor_address);

    (
        genesis,
        transfer,
        state_strings,
        anchor_address,
        pod_address,
    )
}

fn mrc20_deposit_body(state: &Mrc20State, prev: &Mrc20State, state_strings: &[String]) -> Value {
    mrc20_deposit_body_by(&issuer_pubkey(), state, prev, state_strings)
}

fn mrc20_deposit_body_by(
    anchor_pubkey: &str,
    state: &Mrc20State,
    prev: &Mrc20State,
    state_strings: &[String],
) -> Value {
    json!({
        "type": "mrc20",
        "state": state,
        "prevState": prev,
        "anchor": {
            "pubkey": anchor_pubkey,
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
    let head = chains().lock().unwrap()[&anchor_address].head.clone();
    let (mempool_url, handle) = spawn_fixture_mempool(vec![anchor_address]).await;

    let st = state_with_issuer(Some(mempool_url));
    let storage = st.storage.clone();
    let app = test::init_service(build_app(st)).await;

    let body = mrc20_deposit_body(&transfer, &genesis, &state_strings);
    let payload = serde_json::to_vec(&body).unwrap();
    let (auth, did) = nip98_auth("POST", "/pay/.deposit", Some(&payload));

    let req = test::TestRequest::post()
        .uri("/pay/.deposit")
        .insert_header((header::AUTHORIZATION, auth))
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload(payload)
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
    assert_eq!(j["outpoint"], format!("{head}:0"));

    // Ledger actually credited — in the TEST balance, never in sats — with
    // the anchor outpoint as the deposit's receipt.
    let ledger = read_ledger(&storage).await;
    assert_eq!(ledger.get_currency_balance(&did, "TEST"), 100);
    assert_eq!(
        ledger.get_balance(&did),
        0,
        "a token deposit never credits sats"
    );
    assert_eq!(ledger.deposits().len(), 1);
    assert_eq!(ledger.deposits()[0].outpoint, format!("{head}:0"));
    assert_eq!(ledger.deposits()[0].currency.as_deref(), Some("TEST"));

    // A fresh ledger is born with teller's genesis identity, operator the
    // pod issuer: id = urn:webledgers:sha256(JCS(genesis)).
    let genesis = ledger.genesis().expect("fresh ledger carries a genesis");
    assert_eq!(
        genesis.operator,
        format!("did:nostr:{}", &issuer_pubkey()[2..])
    );
    assert_eq!(ledger.hash(), Some(genesis.hash().as_str()));
    assert_eq!(
        ledger.id(),
        Some(format!("urn:webledgers:{}", genesis.hash()).as_str())
    );
    ledger.check_genesis().unwrap();

    handle.stop(false).await;
}

#[actix_web::test]
async fn mrc20_deposit_rejected_when_no_utxo() {
    let (genesis, transfer, state_strings, _anchor, _pod) = build_mrc20_fixture(100);
    // Fixture mempool has NOTHING at any address → anchor unverifiable.
    let (mempool_url, handle) = spawn_fixture_mempool(vec![]).await;

    let st = state_with_issuer(Some(mempool_url));
    let storage = st.storage.clone();
    let app = test::init_service(build_app(st)).await;

    let body = mrc20_deposit_body(&transfer, &genesis, &state_strings);
    let payload = serde_json::to_vec(&body).unwrap();
    let (auth, did) = nip98_auth("POST", "/pay/.deposit", Some(&payload));

    let req = test::TestRequest::post()
        .uri("/pay/.deposit")
        .insert_header((header::AUTHORIZATION, auth))
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload(payload)
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
            l.get_balance(&did) + l.get_currency_balance(&did, "TEST")
        }
        Err(_) => 0,
    };
    assert_eq!(credited, 0, "a failed anchor must not credit");

    handle.stop(false).await;
}

#[actix_web::test]
async fn mrc20_deposit_replay_is_rejected() {
    let (genesis, transfer, state_strings, anchor_address, _pod) = build_mrc20_fixture(100);
    let (mempool_url, handle) = spawn_fixture_mempool(vec![anchor_address]).await;

    let st = state_with_issuer(Some(mempool_url));
    let storage = st.storage.clone();
    let app = test::init_service(build_app(st)).await;

    let body = mrc20_deposit_body(&transfer, &genesis, &state_strings);
    let payload = serde_json::to_vec(&body).unwrap();

    // First deposit — credited.
    let (auth1, did) = nip98_auth("POST", "/pay/.deposit", Some(&payload));
    let req = test::TestRequest::post()
        .uri("/pay/.deposit")
        .insert_header((header::AUTHORIZATION, auth1))
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload(payload.clone())
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(rsp.status().as_u16(), 200);

    // Second deposit of the SAME state — replay-rejected, no double-credit.
    let (auth2, _) = nip98_auth("POST", "/pay/.deposit", Some(&payload));
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

    let ledger = read_ledger(&storage).await;
    assert_eq!(
        ledger.get_currency_balance(&did, "TEST"),
        100,
        "replay must not double-credit"
    );

    handle.stop(false).await;
}

/// The authoritative ledger (`state.json`).
async fn read_ledger(
    storage: &Arc<dyn solid_pod_rs::storage::Storage>,
) -> solid_pod_rs::payments::WebLedger {
    let (bytes, _) = storage
        .get("/.well-known/webledgers/state.json")
        .await
        .unwrap();
    let state: Value = serde_json::from_slice(&bytes).unwrap();
    serde_json::from_value(state["ledger"].clone()).unwrap()
}

/// POST a deposit body as the test caller; returns `(status, json, did)`.
async fn post_deposit<S, B>(app: &S, body: &Value) -> (u16, Value, String)
where
    S: actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse<B>,
        Error = actix_web::Error,
    >,
    B: actix_web::body::MessageBody,
{
    let payload = serde_json::to_vec(body).unwrap();
    let (auth, did) = nip98_auth("POST", "/pay/.deposit", Some(&payload));
    let req = test::TestRequest::post()
        .uri("/pay/.deposit")
        .insert_header((header::AUTHORIZATION, auth))
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload(payload)
        .to_request();
    let rsp = test::call_service(app, req).await;
    let status = rsp.status().as_u16();
    let j: Value = test::read_body_json(rsp).await;
    (status, j, did)
}

// ---------------------------------------------------------------------------
// MRC20 deposit — issuer and ticker binding, per-ticker credit, outpoint replay
// ---------------------------------------------------------------------------

/// A second key, standing in for anyone who mints their own trail.
fn other_pubkey() -> String {
    let sk = k256::SecretKey::from_slice(
        &hex::decode("0000000000000000000000000000000000000000000000000000000000000002").unwrap(),
    )
    .unwrap();
    hex::encode(sk.public_key().to_sec1_bytes())
}

#[actix_web::test]
async fn mrc20_self_issued_trail_is_refused() {
    // A trail with the pod's ticker, transferring to the pod's address, but
    // issued (anchored) on someone else's key: a different token.
    let other = other_pubkey();
    let (genesis, transfer, state_strings, anchor_address, _pod) =
        build_trail_fixture(&other, "TEST", 100);
    let (mempool_url, handle) = spawn_fixture_mempool(vec![anchor_address]).await;
    let st = state_with_issuer(Some(mempool_url));
    let storage = st.storage.clone();
    let app = test::init_service(build_app(st)).await;

    let body = mrc20_deposit_body_by(&other, &transfer, &genesis, &state_strings);
    let (status, j, _did) = post_deposit(&app, &body).await;
    assert_eq!(status, 403, "self-issued trail must be refused: {j}");
    assert!(j["error"].as_str().unwrap().contains("issuer"));
    assert!(
        storage
            .get("/.well-known/webledgers/state.json")
            .await
            .is_err(),
        "nothing was committed"
    );
    handle.stop(false).await;
}

#[actix_web::test]
async fn mrc20_self_issued_trail_from_an_accepted_issuer_is_credited() {
    let other = other_pubkey();
    let (genesis, transfer, state_strings, anchor_address, _pod) =
        build_trail_fixture(&other, "TEST", 100);
    let (mempool_url, handle) = spawn_fixture_mempool(vec![anchor_address]).await;
    let mut st = state_with_issuer(Some(mempool_url));
    st.pay_config
        .token
        .as_mut()
        .unwrap()
        .accepted_issuers
        .push(other.to_uppercase());
    let app = test::init_service(build_app(st)).await;

    let body = mrc20_deposit_body_by(&other, &transfer, &genesis, &state_strings);
    let (status, j, _did) = post_deposit(&app, &body).await;
    assert_eq!(status, 200, "accepted issuer: {j}");
    assert_eq!(j["balance"], 100);
    handle.stop(false).await;
}

#[actix_web::test]
async fn mrc20_wrong_ticker_is_refused() {
    let (genesis, transfer, state_strings, anchor_address, _pod) =
        build_trail_fixture(&issuer_pubkey(), "ELSE", 100);
    let (mempool_url, handle) = spawn_fixture_mempool(vec![anchor_address]).await;
    let st = state_with_issuer(Some(mempool_url));
    let storage = st.storage.clone();
    let app = test::init_service(build_app(st)).await;

    let body = mrc20_deposit_body(&transfer, &genesis, &state_strings);
    let (status, j, _did) = post_deposit(&app, &body).await;
    assert_eq!(status, 400, "another ticker must be refused: {j}");
    assert!(j["error"].as_str().unwrap().contains("TEST"));
    assert!(storage
        .get("/.well-known/webledgers/state.json")
        .await
        .is_err());
    handle.stop(false).await;
}

#[actix_web::test]
async fn mrc20_credit_leaves_the_sat_balance_unchanged() {
    let (genesis, transfer, state_strings, anchor_address, _pod) = build_mrc20_fixture(100);
    let (mempool_url, handle) = spawn_fixture_mempool(vec![anchor_address]).await;
    let st = state_with_issuer(Some(mempool_url));
    let storage = st.storage.clone();

    // The caller already holds 777 sats (a receipted sat deposit).
    let (_, did) = nip98_auth("GET", "/pay/.balance", None);
    let mut seeded = solid_pod_rs::payments::WebLedger::new("Pod Credits");
    seeded
        .credit_by_outpoint(&did, "satoshi", &"cd".repeat(32), 1, 777)
        .unwrap();
    storage
        .put(
            "/.well-known/webledgers/webledgers.json",
            serde_json::to_vec(&seeded).unwrap().into(),
            "application/json",
        )
        .await
        .unwrap();
    let app = test::init_service(build_app(st)).await;

    let body = mrc20_deposit_body(&transfer, &genesis, &state_strings);
    let (status, j, did) = post_deposit(&app, &body).await;
    assert_eq!(status, 200, "{j}");
    let ledger = read_ledger(&storage).await;
    assert_eq!(ledger.get_balance(&did), 777, "sats untouched");
    assert_eq!(ledger.get_currency_balance(&did, "TEST"), 100);
    assert_eq!(ledger.deposits().len(), 2);
    assert!(
        ledger.genesis().is_none(),
        "a ledger holding balances keeps its shape; no identity is rewritten under it"
    );
    handle.stop(false).await;
}

#[actix_web::test]
async fn mrc20_same_anchor_outpoint_twice_credits_once() {
    // Two different states (different state hashes, different anchor
    // addresses) whose anchors the mempool shows holding the SAME coin. The
    // per-link walk already refuses the second: that coin is the first
    // trail's mark, not a key the second trail's states derive.
    let (g1, t1, s1, a1, _) = build_mrc20_fixture(100);
    let (g2, t2, s2, a2, _) = build_mrc20_fixture(60);
    assert_ne!(a1, a2);
    let (mempool_url, handle) =
        spawn_fixture_mempool_with(vec![(a1.clone(), a1.clone()), (a2, a1)]).await;
    let st = state_with_issuer(Some(mempool_url));
    let storage = st.storage.clone();
    let app = test::init_service(build_app(st)).await;

    let (status, j, did) = post_deposit(&app, &mrc20_deposit_body(&t1, &g1, &s1)).await;
    assert_eq!(status, 200, "{j}");

    let (status, j, _) = post_deposit(&app, &mrc20_deposit_body(&t2, &g2, &s2)).await;
    assert_eq!(status, 400, "a used outpoint must be refused: {j}");
    let error = j["error"].as_str().unwrap();
    assert!(
        (error.contains("Replay") && error.contains("outpoint")) || error.contains("link by link"),
        "{error}"
    );

    let ledger = read_ledger(&storage).await;
    assert_eq!(
        ledger.get_currency_balance(&did, "TEST"),
        100,
        "credited once"
    );
    assert_eq!(ledger.deposits().len(), 1);
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
