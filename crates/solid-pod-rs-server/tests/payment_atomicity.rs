use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use actix_web::{http::header, test};
use solid_pod_rs::auth::nip98;
use solid_pod_rs::storage::{memory::MemoryBackend, Storage};
use solid_pod_rs_server::{build_app, AppState};

const SECRET: &str = "5555555555555555555555555555555555555555555555555555555555555555";

fn auth(body: &[u8], offset: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .saturating_sub(10)
        + offset;
    let token = nip98::mint_with_payload(
        "http://localhost:8080/pay/.deposit",
        "POST",
        Some(body),
        SECRET,
        now,
    )
    .unwrap();
    format!("Nostr {token}")
}

#[actix_web::test]
async fn concurrent_duplicate_deposits_credit_exactly_once() {
    let storage = Arc::new(MemoryBackend::new());
    let mut state = AppState::new(storage.clone());
    state.deposit_txo_standin_enabled = true;
    let app = test::init_service(build_app(state)).await;
    let body = format!("{}:0", "a".repeat(64));

    let first = test::TestRequest::post()
        .uri("/pay/.deposit")
        .insert_header((header::AUTHORIZATION, auth(body.as_bytes(), 0)))
        .set_payload(body.clone())
        .to_request();
    let second = test::TestRequest::post()
        .uri("/pay/.deposit")
        .insert_header((header::AUTHORIZATION, auth(body.as_bytes(), 1)))
        .set_payload(body)
        .to_request();
    let (first, second) = futures_util::future::join(
        test::call_service(&app, first),
        test::call_service(&app, second),
    )
    .await;
    let mut statuses = [first.status().as_u16(), second.status().as_u16()];
    statuses.sort_unstable();
    assert_eq!(statuses, [200, 400]);

    let (bytes, _) = storage
        .get("/.well-known/webledgers/webledgers.json")
        .await
        .unwrap();
    let ledger: solid_pod_rs::payments::WebLedger = serde_json::from_slice(&bytes).unwrap();
    let key = k256::schnorr::SigningKey::from_bytes(&hex::decode(SECRET).unwrap()).unwrap();
    let did = format!("did:nostr:{}", hex::encode(key.verifying_key().to_bytes()));
    assert_eq!(ledger.get_balance(&did), 1_000);
}
