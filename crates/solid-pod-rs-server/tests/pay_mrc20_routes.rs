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
    // Each minted token MUST be a distinct NIP-98 event. The server's single-use
    // replay guard (`NIP98_REPLAY`) is a process-global `LazyLock`, so two tokens
    // sharing key/url/method/created_at collide on event_id and the second is
    // replay-rejected (401) — a test-isolation flake across tests in one process.
    // Anchor `created_at` to a base captured ONCE (30s in the past) and add a
    // monotonic per-call counter: values are strictly increasing and unique
    // regardless of wall-clock drift (so they never collide the way a
    // `now - counter` scheme can when the clock advances), and stay comfortably
    // inside the ±60s `TIMESTAMP_TOLERANCE` window.
    // `created_at` must track the wall clock: the server refuses a NIP-98 event
    // more than 60 s from its own time, so a base fixed at first use goes stale
    // whenever the process runs slowly (coverage instrumentation). Distinct
    // events need distinct seconds (replay protection), so never reuse one.
    static LAST: std::sync::Mutex<u64> = std::sync::Mutex::new(0);
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let now = {
        let mut last = LAST.lock().unwrap();
        *last = wall.max(*last + 1);
        *last
    };
    let url = format!("http://localhost:8080{path}");
    let token = nip98::mint_with_payload(&url, method, body, SK_HEX, now).expect("nip98 mint");
    let sk = hex::decode(SK_HEX).unwrap();
    let signing = k256::schnorr::SigningKey::from_slice(&sk).unwrap();
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
    spawn_fixture_mempool_decoyed(utxos, Vec::new()).await
}

/// [`spawn_fixture_mempool_with`] where each `(address, txid)` in `decoys`
/// also lists a coin at `address`, listed BEFORE the real one, whose
/// transaction the mempool does not know: anyone can send dust to an address.
async fn spawn_fixture_mempool_decoyed(
    utxos: Vec<(String, String)>,
    decoys: Vec<(String, String)>,
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
    let heads: std::collections::HashMap<String, Vec<String>> = heads
        .into_iter()
        .map(|(address, head)| {
            let mut coins: Vec<String> = decoys
                .iter()
                .filter(|(a, _)| *a == address)
                .map(|(_, t)| t.clone())
                .collect();
            coins.push(head);
            (address, coins)
        })
        .collect();
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
                     heads: web::Data<std::collections::HashMap<String, Vec<String>>>| async move {
                        let body = match heads.get(&path.into_inner()) {
                            Some(coins) => Value::Array(
                                coins
                                    .iter()
                                    .map(|txid| {
                                        json!({
                                            "txid": txid, "vout": 0, "value": 9700,
                                            "status": {"confirmed": true, "block_height": 42000},
                                        })
                                    })
                                    .collect(),
                            )
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
    build_trail_fixture_ext(issuer, ticker, amount, amount, true)
}

/// [`build_trail_fixture`] with the knobs a forger turns: `op_amt` is what the
/// transfer op claims, `balance_amt` what the state's balances actually move,
/// and `full == false` ships only the tip's state string (a one-string proof).
fn build_trail_fixture_ext(
    issuer: &str,
    ticker: &str,
    op_amt: u64,
    balance_amt: u64,
    full: bool,
) -> (Mrc20State, Mrc20State, Vec<String>, String, String) {
    build_ops_fixture(issuer, ticker, full, |issuer, pod| {
        (
            vec![(issuer.to_string(), 1000)],
            vec![Mrc20Op {
                op: TRANSFER_OP.into(),
                from: Some(issuer.to_string()),
                to: Some(pod.to_string()),
                amt: Some(op_amt),
            }],
            vec![
                (issuer.to_string(), 1000 - balance_amt),
                (pod.to_string(), balance_amt),
            ],
        )
    })
}

/// A genesis and a tip whose balances and ops the caller writes, given the
/// issuer key and the caller's pod address: `plan` returns
/// `(genesis balances, tip ops, tip balances)`.
fn build_ops_fixture(
    issuer: &str,
    ticker: &str,
    full: bool,
    plan: impl FnOnce(&str, &str) -> (Vec<(String, u64)>, Vec<Mrc20Op>, Vec<(String, u64)>),
) -> (Mrc20State, Mrc20State, Vec<String>, String, String) {
    let issuer = issuer.to_string();
    // The transfer beneficiary is cryptographically bound to the caller DID.
    let sk = hex::decode(SK_HEX).unwrap();
    let signer = k256::schnorr::SigningKey::from_slice(&sk).unwrap();
    let did = format!(
        "did:nostr:{}",
        hex::encode(signer.verifying_key().to_bytes())
    );
    let pod_address = bt_address(&issuer_pubkey(), &[did], NETWORK).unwrap();
    let (genesis_balances, tip_ops, tip_balances) = plan(&issuer, &pod_address);

    let genesis = Mrc20State {
        profile: solid_pod_rs::mrc20::MRC20_PROFILE.into(),
        prev: "0".repeat(64),
        seq: 0,
        ticker: Some(ticker.into()),
        name: Some("Test Token".into()),
        decimals: Some(0),
        supply: Some(1000),
        balances: Some(genesis_balances.into_iter().collect()),
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
        balances: Some(tip_balances.into_iter().filter(|(_, v)| *v != 0).collect()),
        ops: tip_ops,
        anchor: None,
    };
    let transfer_jcs = jcs(&serde_json::to_value(&transfer).unwrap());

    let state_strings = if full {
        vec![genesis_jcs, transfer_jcs]
    } else {
        vec![transfer_jcs]
    };
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

    // Public proof bytes must not let another principal steal the credit.
    let thief_key = "22".repeat(32);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let thief = nip98::mint_with_payload(
        "http://localhost:8080/pay/.deposit",
        "POST",
        Some(&payload),
        &thief_key,
        timestamp,
    )
    .unwrap();
    let request = test::TestRequest::post()
        .uri("/pay/.deposit")
        .insert_header((header::AUTHORIZATION, format!("Nostr {thief}")))
        .set_payload(payload.clone())
        .to_request();
    let response = test::call_service(&app, request).await;
    assert_ne!(
        response.status().as_u16(),
        200,
        "a proof is not a bearer credit claim"
    );

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

// ---------------------------------------------------------------------------
// SP-07.17 — the proof must be the full trail, and the credit the proven amount
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn mrc20_one_string_proof_is_rejected() {
    // Anyone can derive the address of a one-string trail and fund it: with
    // nothing before the mark there is nothing the issuer ever signed.
    let (genesis, transfer, state_strings, anchor_address, _pod) =
        build_trail_fixture_ext(&issuer_pubkey(), "TEST", 100, 100, false);
    assert_eq!(state_strings.len(), 1);
    let (mempool_url, handle) = spawn_fixture_mempool(vec![anchor_address]).await;
    let st = state_with_issuer(Some(mempool_url));
    let storage = st.storage.clone();
    let app = test::init_service(build_app(st)).await;

    let body = mrc20_deposit_body(&transfer, &genesis, &state_strings);
    let (status, j, _did) = post_deposit(&app, &body).await;
    assert_eq!(status, 400, "a k=1 proof must be refused: {j}");
    assert!(
        j["error"].as_str().unwrap().contains("at least 2"),
        "refused for the short trail, not something else: {j}"
    );
    assert!(
        storage
            .get("/.well-known/webledgers/state.json")
            .await
            .is_err(),
        "a refused proof must not touch the ledger"
    );
    handle.stop(false).await;
}

#[actix_web::test]
async fn mrc20_inflated_amount_is_rejected_and_not_credited() {
    // The op claims 500 tokens while the committed balances move only 100.
    let (genesis, transfer, state_strings, anchor_address, _pod) =
        build_trail_fixture_ext(&issuer_pubkey(), "TEST", 500, 100, true);
    let (mempool_url, handle) = spawn_fixture_mempool(vec![anchor_address]).await;
    let st = state_with_issuer(Some(mempool_url));
    let storage = st.storage.clone();
    let app = test::init_service(build_app(st)).await;

    let body = mrc20_deposit_body(&transfer, &genesis, &state_strings);
    let (status, j, _did) = post_deposit(&app, &body).await;
    assert_eq!(status, 400, "an inflated claim must be refused: {j}");
    assert!(
        j["error"]
            .as_str()
            .unwrap()
            .contains("do not reproduce its committed balances"),
        "refused for the balance mismatch: {j}"
    );
    assert!(
        storage
            .get("/.well-known/webledgers/state.json")
            .await
            .is_err(),
        "an inflated claim must not credit anything"
    );
    handle.stop(false).await;
}

/// Run a deposit built from `plan` and return `(status, body)` plus the
/// storage, for the net-balance tests.
async fn deposit_ops(
    plan: impl FnOnce(&str, &str) -> (Vec<(String, u64)>, Vec<Mrc20Op>, Vec<(String, u64)>),
) -> (u16, Value, Arc<dyn solid_pod_rs::storage::Storage>) {
    let (genesis, transfer, state_strings, anchor_address, _pod) =
        build_ops_fixture(&issuer_pubkey(), "TEST", true, plan);
    let (mempool_url, handle) = spawn_fixture_mempool(vec![anchor_address]).await;
    let st = state_with_issuer(Some(mempool_url));
    let storage = st.storage.clone();
    let app = test::init_service(build_app(st)).await;
    let body = mrc20_deposit_body(&transfer, &genesis, &state_strings);
    let (status, j, _did) = post_deposit(&app, &body).await;
    handle.stop(false).await;
    (status, j, storage)
}

fn transfer(from: &str, to: &str, amt: u64) -> Mrc20Op {
    Mrc20Op {
        op: TRANSFER_OP.into(),
        from: Some(from.into()),
        to: Some(to.into()),
        amt: Some(amt),
    }
}

#[actix_web::test]
async fn mrc20_self_transfer_credits_nothing() {
    // The pod address already holds 100 and sends them to itself: gross 100,
    // net 0.
    let (status, j, storage) = deposit_ops(|issuer, pod| {
        (
            vec![(issuer.into(), 900), (pod.into(), 100)],
            vec![transfer(pod, pod, 100)],
            vec![(issuer.into(), 900), (pod.into(), 100)],
        )
    })
    .await;
    assert_eq!(status, 400, "a self-transfer is not a deposit: {j}");
    assert!(j["error"].as_str().unwrap().contains("net"), "{j}");
    assert!(storage
        .get("/.well-known/webledgers/state.json")
        .await
        .is_err());
}

#[actix_web::test]
async fn mrc20_round_trip_credits_nothing() {
    // issuer -> pod 100, then pod -> issuer 100: the pod ends where it began.
    let (status, j, storage) = deposit_ops(|issuer, pod| {
        (
            vec![(issuer.into(), 1000)],
            vec![transfer(issuer, pod, 100), transfer(pod, issuer, 100)],
            vec![(issuer.into(), 1000)],
        )
    })
    .await;
    assert_eq!(status, 400, "a round trip is not a deposit: {j}");
    assert!(j["error"].as_str().unwrap().contains("net"), "{j}");
    assert!(storage
        .get("/.well-known/webledgers/state.json")
        .await
        .is_err());
}

#[actix_web::test]
async fn mrc20_credit_is_the_net_balance_change() {
    // Gross inbound 150, outbound 50: the pod gains 100 and is credited 100.
    let (status, j, _s) = deposit_ops(|issuer, pod| {
        (
            vec![(issuer.into(), 1000)],
            vec![transfer(issuer, pod, 150), transfer(pod, issuer, 50)],
            vec![(issuer.into(), 900), (pod.into(), 100)],
        )
    })
    .await;
    assert_eq!(status, 200, "{j}");
    assert_eq!(j["deposited"], 100);
}

#[actix_web::test]
async fn mrc20_receipt_is_the_verified_utxo_not_a_decoy() {
    // Someone sends dust to the derived address; its txid sorts below the
    // real head's. The credit's receipt must be the coin that was verified.
    let (genesis, transfer, state_strings, anchor_address, _pod) = build_mrc20_fixture(100);
    let head = chains().lock().unwrap()[&anchor_address].head.clone();
    let decoy = "00".repeat(32);
    assert!(decoy < head);
    let (mempool_url, handle) = spawn_fixture_mempool_decoyed(
        vec![(anchor_address.clone(), anchor_address.clone())],
        vec![(anchor_address, decoy.clone())],
    )
    .await;
    let st = state_with_issuer(Some(mempool_url));
    let storage = st.storage.clone();
    let app = test::init_service(build_app(st)).await;
    let body = mrc20_deposit_body(&transfer, &genesis, &state_strings);
    let (status, j, _did) = post_deposit(&app, &body).await;
    assert_eq!(status, 200, "{j}");
    assert_eq!(j["outpoint"], format!("{head}:0"));
    let ledger = read_ledger(&storage).await;
    assert_eq!(ledger.deposits().len(), 1);
    assert_eq!(ledger.deposits()[0].outpoint, format!("{head}:0"));
    handle.stop(false).await;
}

/// `body` with the depositor's named anchor outpoint added.
fn with_outpoint(mut body: Value, outpoint: &str) -> Value {
    body["anchor"]["outpoint"] = json!(outpoint);
    body
}

#[actix_web::test]
async fn mrc20_dust_cannot_crowd_out_the_named_anchor() {
    // Six dust coins sit at the public address, all listed before the real
    // head, which the depositor names. The walk reads that coin only.
    let (genesis, transfer, state_strings, anchor_address, _pod) = build_mrc20_fixture(100);
    let head = chains().lock().unwrap()[&anchor_address].head.clone();
    let decoys: Vec<(String, String)> = (0..6)
        .map(|i| {
            (
                anchor_address.clone(),
                solid_pod_rs::mrc20::sha256_hex(&format!("dust {i}")),
            )
        })
        .collect();
    let (mempool_url, handle) = spawn_fixture_mempool_decoyed(
        vec![(anchor_address.clone(), anchor_address.clone())],
        decoys,
    )
    .await;
    let st = state_with_issuer(Some(mempool_url));
    let storage = st.storage.clone();
    let app = test::init_service(build_app(st)).await;
    let body = with_outpoint(
        mrc20_deposit_body(&transfer, &genesis, &state_strings),
        &format!("{head}:0"),
    );
    let (status, j, _did) = post_deposit(&app, &body).await;
    assert_eq!(status, 200, "a named anchor beats any amount of dust: {j}");
    assert_eq!(j["outpoint"], format!("{head}:0"));
    let ledger = read_ledger(&storage).await;
    assert_eq!(ledger.deposits()[0].outpoint, format!("{head}:0"));
    handle.stop(false).await;
}

#[actix_web::test]
async fn mrc20_named_anchor_must_be_a_coin_at_the_address() {
    let (genesis, transfer, state_strings, anchor_address, _pod) = build_mrc20_fixture(100);
    let (mempool_url, handle) = spawn_fixture_mempool(vec![anchor_address]).await;
    let st = state_with_issuer(Some(mempool_url));
    let storage = st.storage.clone();
    let app = test::init_service(build_app(st)).await;
    for bad in [
        format!("{}:0", "ab".repeat(32)),
        "not-an-outpoint".to_string(),
    ] {
        let body = with_outpoint(
            mrc20_deposit_body(&transfer, &genesis, &state_strings),
            &bad,
        );
        let (status, j, _did) = post_deposit(&app, &body).await;
        assert_eq!(status, 400, "{bad}: {j}");
        assert!(j["error"].as_str().unwrap().contains("outpoint"), "{j}");
    }
    assert!(storage
        .get("/.well-known/webledgers/state.json")
        .await
        .is_err());
    handle.stop(false).await;
}
