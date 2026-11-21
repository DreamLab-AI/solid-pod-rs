//! Review A4: the outbound clients that pin a vetted address must connect to
//! it directly. reqwest honours `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` by
//! default (`auto_sys_proxy`, reqwest 0.12.28 `async_impl/client.rs`), and
//! through a proxy the pinned address is never used: the proxy resolves and
//! connects. This file is its own test binary because it sets those variables
//! for the whole process.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use solid_pod_rs_activitypub::{
    generate_actor_keypair, DeliveryConfig, DeliveryOutcome, DeliveryWorker, HttpActorKeyResolver,
    SsrfGuard, Store,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Property: with proxy variables set, the actor-document fetch and the
/// delivery POST both reach the pinned origin directly, and the proxy sees
/// no connection.
#[tokio::test]
async fn pinned_clients_ignore_proxy_environment_variables() {
    let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = seen.clone();
    std::thread::spawn(move || {
        while let Ok((s, _)) = proxy.accept() {
            counter.fetch_add(1, Ordering::SeqCst);
            drop(s);
        }
    });
    for k in ["NO_PROXY", "no_proxy"] {
        std::env::remove_var(k);
    }
    for k in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        std::env::set_var(k, format!("http://{proxy_addr}"));
    }

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": "x"})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(202))
        .mount(&server)
        .await;

    let resolver =
        HttpActorKeyResolver::default().with_guard(SsrfGuard::permit_loopback_for_tests());
    let doc = resolver
        .fetch_document(&format!("{}/actor", server.uri()))
        .await
        .expect("actor fetch must bypass the proxy");
    assert_eq!(doc["id"], "x");

    let dir = tempfile::tempdir().unwrap();
    let store = Store::connect(&format!(
        "sqlite://{}?mode=rwc",
        dir.path().join("ap.db").display()
    ))
    .await
    .unwrap();
    let me = "https://pod.example/profile/card.jsonld#me";
    let id = store
        .record_outbox(me, &serde_json::json!({"id": "urn:a:1", "type": "Create"}))
        .await
        .unwrap();
    store
        .enqueue_delivery(&id, &format!("{}/inbox", server.uri()))
        .await
        .unwrap();
    let (private_key_pem, _) = generate_actor_keypair().unwrap();
    let worker = DeliveryWorker::new(
        store,
        DeliveryConfig {
            private_key_pem,
            key_id: format!("{me}-key"),
        },
    )
    .with_guard(SsrfGuard::permit_loopback_for_tests());
    let outcome = worker.drain_once().await.unwrap();
    assert_eq!(
        outcome,
        DeliveryOutcome::Delivered,
        "delivery must bypass the proxy"
    );

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(seen.load(Ordering::SeqCst), 0, "the proxy saw a connection");
}
