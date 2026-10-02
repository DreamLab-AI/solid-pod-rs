//! Payment-state atomicity: concurrent writers to the shared payment state
//! (`/.well-known/webledgers/state.json`) are serialised by
//! `PAYMENT_STATE_LOCK`, so no read-modify-write loses another's update.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use actix_web::{http::header, test};
use async_trait::async_trait;
use bytes::Bytes;
use serde_json::Value;
use solid_pod_rs::auth::nip98;
use solid_pod_rs::error::PodError;
use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::{ResourceMeta, Storage, StorageEvent};
use solid_pod_rs_server::{build_app, AppState};

/// The in-memory backend completes every call without suspending, so two
/// handlers on one executor would never interleave and a missing lock would
/// go unnoticed. This wrapper yields before each read, which lets a second
/// request read the state between the first one's read and its commit.
struct YieldingStorage(MemoryBackend);

#[async_trait]
impl Storage for YieldingStorage {
    async fn get(&self, path: &str) -> Result<(Bytes, ResourceMeta), PodError> {
        tokio::task::yield_now().await;
        self.0.get(path).await
    }
    async fn put(&self, path: &str, body: Bytes, ct: &str) -> Result<ResourceMeta, PodError> {
        self.0.put(path, body, ct).await
    }
    async fn delete(&self, path: &str) -> Result<(), PodError> {
        self.0.delete(path).await
    }
    async fn list(&self, container: &str) -> Result<Vec<String>, PodError> {
        self.0.list(container).await
    }
    async fn head(&self, path: &str) -> Result<ResourceMeta, PodError> {
        self.0.head(path).await
    }
    async fn exists(&self, path: &str) -> Result<bool, PodError> {
        self.0.exists(path).await
    }
    async fn watch(
        &self,
        path: &str,
    ) -> Result<tokio::sync::mpsc::Receiver<StorageEvent>, PodError> {
        self.0.watch(path).await
    }
}

const SECRET: &str = "5555555555555555555555555555555555555555555555555555555555555555";

fn auth(body: &[u8], offset: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .saturating_sub(10)
        + offset;
    let token = nip98::mint_with_payload(
        "http://localhost:8080/pay/.sell",
        "POST",
        Some(body),
        SECRET,
        now,
    )
    .unwrap();
    format!("Nostr {token}")
}

/// Two orders placed at the same instant both land in the order book. An
/// unserialised read-modify-write would let the second commit overwrite the
/// first, leaving one order.
#[actix_web::test]
async fn concurrent_payment_state_writes_lose_no_update() {
    let storage = Arc::new(YieldingStorage(MemoryBackend::new()));
    let app = test::init_service(build_app(AppState::new(storage))).await;

    let sell = |price: u64, offset: u64| {
        let body = format!(
            r#"{{"sell_currency":"tbtc3","sell_amount":10,"buy_currency":"sat","price":{price}}}"#
        );
        test::TestRequest::post()
            .uri("/pay/.sell")
            .insert_header((header::AUTHORIZATION, auth(body.as_bytes(), offset)))
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .set_payload(body)
            .to_request()
    };
    let (first, second) = futures_util::future::join(
        test::call_service(&app, sell(100, 0)),
        test::call_service(&app, sell(200, 1)),
    )
    .await;
    assert_eq!(first.status().as_u16(), 200);
    assert_eq!(second.status().as_u16(), 200);

    let offers = test::call_service(
        &app,
        test::TestRequest::get().uri("/pay/.offers").to_request(),
    )
    .await;
    let offers: Value = test::read_body_json(offers).await;
    let mut prices: Vec<u64> = offers
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["price"].as_u64().unwrap())
        .collect();
    prices.sort_unstable();
    assert_eq!(prices, [100, 200], "both concurrent orders must persist");
}
