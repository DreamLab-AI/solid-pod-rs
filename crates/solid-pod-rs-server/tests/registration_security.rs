//! Regression coverage for the public pod-provisioning policy boundary.

use std::sync::Arc;

use actix_web::test;
use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs_server::{build_app, AppState};

fn state() -> AppState {
    AppState::new(Arc::new(MemoryBackend::new()))
}

#[actix_web::test]
async fn public_provisioning_is_closed_by_default_on_both_routes() {
    let app = test::init_service(build_app(state())).await;

    let pod = test::TestRequest::post()
        .uri("/.pods")
        .set_json(serde_json::json!({"name": "alice"}))
        .to_request();
    assert_eq!(test::call_service(&app, pod).await.status().as_u16(), 403);

    let account = test::TestRequest::post()
        .uri("/api/accounts/new")
        .set_json(serde_json::json!({"username": "alice"}))
        .to_request();
    assert_eq!(
        test::call_service(&app, account).await.status().as_u16(),
        403
    );
}

#[actix_web::test]
async fn account_route_validates_names_before_touching_storage() {
    let mut state = state();
    state.nodeinfo.open_registrations = true;
    let storage = state.storage.clone();
    let app = test::init_service(build_app(state)).await;

    let request = test::TestRequest::post()
        .uri("/api/accounts/new")
        .set_json(serde_json::json!({"username": "../escape"}))
        .to_request();
    assert_eq!(
        test::call_service(&app, request).await.status().as_u16(),
        400
    );
    assert!(!storage.exists("/escape/profile/card").await.unwrap());
}

#[actix_web::test]
async fn both_routes_share_the_same_per_ip_rate_limit() {
    let mut state = state();
    state.nodeinfo.open_registrations = true;
    let app = test::init_service(build_app(state)).await;

    let pod = test::TestRequest::post()
        .uri("/.pods")
        .set_json(serde_json::json!({"name": "alice"}))
        .to_request();
    assert_eq!(test::call_service(&app, pod).await.status().as_u16(), 201);

    let account = test::TestRequest::post()
        .uri("/api/accounts/new")
        .set_json(serde_json::json!({"username": "bob"}))
        .to_request();
    assert_eq!(
        test::call_service(&app, account).await.status().as_u16(),
        429
    );
}

#[actix_web::test]
async fn admin_key_overrides_closed_registration_without_root_pollution() {
    let mut state = state();
    state.admin_key = Some("operator-secret".into());
    let storage = state.storage.clone();
    let app = test::init_service(build_app(state)).await;

    let account = test::TestRequest::post()
        .uri("/api/accounts/new")
        .insert_header(("x-pod-admin-key", "operator-secret"))
        .set_json(serde_json::json!({"username": "alice", "name": "Alice"}))
        .to_request();
    assert_eq!(
        test::call_service(&app, account).await.status().as_u16(),
        201
    );
    assert!(storage.exists("/alice/profile/card").await.unwrap());
    assert!(!storage.exists("/profile/card").await.unwrap());
}
