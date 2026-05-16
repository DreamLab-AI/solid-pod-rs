//! End-to-end integration test for the JSS v0.0.190 Phase 1
//! pod-resident NIP-05 endpoint (parity row 197, issue #437).
//!
//! Mounts the full actix app via `build_app` and exercises
//! `GET /.well-known/nostr.json?name=<local>` against an in-memory
//! pod whose `/profile/card` has been seeded with a `nostr:pubkey`
//! triple.

#![cfg(feature = "nip05-endpoint")]

use std::sync::Arc;

use actix_web::test;
use bytes::Bytes;

use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::{build_app, AppState};

const SAMPLE_PUBKEY: &str = "deadbeefcafebabe000000000000000000000000000000000000000000000001";

async fn seed_pod_with_nostr_pubkey(storage: &dyn Storage, profile_path: &str, pubkey: &str) {
    // Minimal profile/card carrying the `nostr:pubkey` triple. The
    // production flow patches a real WebID via `provision_pod_keys`;
    // for this route test we go straight to the smallest valid HTML
    // that satisfies the extractor.
    let html = format!(
        r#"<!DOCTYPE html><html><head>
<script type="application/ld+json">
{{
  "@context": {{ "nostr": "https://nostr.org/ns#" }},
  "@id": "https://pod.example/profile/card#me",
  "nostr:pubkey": "{pubkey}"
}}
</script>
</head><body></body></html>"#
    );
    storage
        .put(profile_path, Bytes::from(html.into_bytes()), "text/html")
        .await
        .unwrap();
}

#[actix_web::test]
async fn nip05_endpoint_returns_pubkey_for_underscore_name() {
    let storage = Arc::new(MemoryBackend::new());
    seed_pod_with_nostr_pubkey(storage.as_ref(), "/profile/card", SAMPLE_PUBKEY).await;
    let state = AppState::new(storage);
    let app = test::init_service(build_app(state)).await;

    let req = test::TestRequest::get()
        .uri("/.well-known/nostr.json?name=_")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body = test::read_body(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["names"]["_"], SAMPLE_PUBKEY);
}

#[actix_web::test]
async fn nip05_endpoint_returns_pubkey_for_named_user() {
    let storage = Arc::new(MemoryBackend::new());
    seed_pod_with_nostr_pubkey(storage.as_ref(), "/alice/profile/card", SAMPLE_PUBKEY).await;
    let state = AppState::new(storage);
    let app = test::init_service(build_app(state)).await;

    let req = test::TestRequest::get()
        .uri("/.well-known/nostr.json?name=alice")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body = test::read_body(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["names"]["alice"], SAMPLE_PUBKEY);
}

#[actix_web::test]
async fn nip05_endpoint_returns_empty_names_for_missing_user() {
    let storage = Arc::new(MemoryBackend::new());
    let state = AppState::new(storage);
    let app = test::init_service(build_app(state)).await;

    let req = test::TestRequest::get()
        .uri("/.well-known/nostr.json?name=ghost")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body = test::read_body(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["names"]
            .as_object()
            .map(|m| m.is_empty())
            .unwrap_or(false),
        "missing user must yield empty names map: {json}"
    );
}

#[actix_web::test]
async fn nip05_endpoint_rejects_invalid_local_part() {
    let storage = Arc::new(MemoryBackend::new());
    let state = AppState::new(storage);
    let app = test::init_service(build_app(state)).await;

    let req = test::TestRequest::get()
        .uri("/.well-known/nostr.json?name=alice@invalid")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_web::test]
async fn nip05_endpoint_emits_cors_origin_star() {
    let storage = Arc::new(MemoryBackend::new());
    seed_pod_with_nostr_pubkey(storage.as_ref(), "/profile/card", SAMPLE_PUBKEY).await;
    let state = AppState::new(storage);
    let app = test::init_service(build_app(state)).await;

    let req = test::TestRequest::get()
        .uri("/.well-known/nostr.json?name=_")
        .to_request();
    let resp = test::call_service(&app, req).await;
    let acao = resp
        .headers()
        .get("Access-Control-Allow-Origin")
        .map(|v| v.to_str().unwrap_or_default().to_string());
    assert_eq!(acao.as_deref(), Some("*"));
}
