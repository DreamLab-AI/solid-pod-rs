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

/// JSS `validateInvite`: with registration closed, a valid invite opens it for
/// exactly as many uses as the invite allows.
#[actix_web::test]
async fn a_valid_invite_opens_closed_registration_for_its_allowed_uses() {
    use solid_pod_rs_idp::{Invite, InviteStore};
    use solid_pod_rs_server::cli::FileInviteStore;

    let root = tempfile::tempdir().unwrap();
    FileInviteStore::new(root.path())
        .insert(Invite {
            token: "welcome-token".into(),
            max_uses: Some(1),
            expires_at: None,
        })
        .await
        .unwrap();
    let mut state = state();
    state.data_root = Some(root.path().to_path_buf());
    let app = test::init_service(build_app(state)).await;

    // The per-IP limiter counts every attempt that reaches it, so each request
    // here comes from its own address.
    let next_ip = std::cell::Cell::new(10u8);
    let with = |name: &str, token: &str| {
        let n = next_ip.get();
        next_ip.set(n + 1);
        test::TestRequest::post()
            .uri("/.pods")
            .peer_addr(std::net::SocketAddr::from(([203, 0, 113, n], 4000)))
            .insert_header(("X-Invite-Token", token.to_string()))
            .set_json(serde_json::json!({ "name": name }))
            .to_request()
    };

    // no invite and an unknown invite are both refused
    let none = test::TestRequest::post()
        .uri("/.pods")
        .set_json(serde_json::json!({"name": "carol"}))
        .to_request();
    assert_eq!(test::call_service(&app, none).await.status().as_u16(), 403);
    assert_eq!(
        test::call_service(&app, with("carol", "nope"))
            .await
            .status()
            .as_u16(),
        403
    );

    // the valid invite works once...
    let ok = test::call_service(&app, with("alice", "welcome-token")).await;
    assert!(ok.status().is_success(), "{}", ok.status());
    // ...and then is spent
    let spent = test::call_service(&app, with("bob", "welcome-token")).await;
    assert_eq!(spent.status().as_u16(), 403);
    let body = test::read_body(spent).await;
    assert!(String::from_utf8_lossy(&body).contains("invite has been used"));
}

#[actix_web::test]
async fn an_invite_does_nothing_without_a_data_root() {
    let app = test::init_service(build_app(state())).await;
    let req = test::TestRequest::post()
        .uri("/.pods")
        .insert_header(("X-Invite-Token", "anything"))
        .set_json(serde_json::json!({"name": "alice"}))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 403);
}
