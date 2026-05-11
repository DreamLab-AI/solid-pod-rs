//! Integration tests for `ClientStore` and `register_client` — dynamic
//! client registration (RFC 7591) and Client Identifier Document handling.
//!
//! These tests exercise the public API from an integration boundary.
//! CID-document tests that require HTTP are limited to cases that do
//! NOT hit the SSRF pre-flight (using `allow_unsafe_urls_for_testing`)
//! or that deliberately trigger it.

use solid_pod_rs_idp::registration::{
    register_client, ClientDocument, ClientStore, RegError, RegistrationRequest,
};

// ---------------------------------------------------------------------------
// Opaque registration (RFC 7591 path)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_client_assigns_client_prefix_id() {
    let store = ClientStore::new();
    let req = RegistrationRequest {
        redirect_uris: vec!["https://app.example/cb".into()],
        ..Default::default()
    };
    let doc = register_client(&store, req).await.unwrap();
    assert!(
        doc.client_id.starts_with("client_"),
        "opaque client id must start with 'client_', got: {}",
        doc.client_id
    );
}

#[tokio::test]
async fn register_client_preserves_redirect_uris() {
    let store = ClientStore::new();
    let req = RegistrationRequest {
        redirect_uris: vec![
            "https://app.example/cb".into(),
            "https://app.example/cb2".into(),
        ],
        ..Default::default()
    };
    let doc = register_client(&store, req).await.unwrap();
    assert_eq!(doc.redirect_uris.len(), 2);
    assert!(doc
        .redirect_uris
        .contains(&"https://app.example/cb".to_string()));
    assert!(doc
        .redirect_uris
        .contains(&"https://app.example/cb2".to_string()));
}

#[tokio::test]
async fn register_client_without_redirect_uris_is_rejected() {
    let store = ClientStore::new();
    let req = RegistrationRequest::default();
    let err = register_client(&store, req).await.unwrap_err();
    assert!(
        matches!(err, RegError::InvalidRequest(_)),
        "expected InvalidRequest, got {err:?}"
    );
}

#[tokio::test]
async fn register_client_public_has_no_secret() {
    let store = ClientStore::new();
    let req = RegistrationRequest {
        redirect_uris: vec!["https://app/cb".into()],
        token_endpoint_auth_method: Some("none".into()),
        ..Default::default()
    };
    let doc = register_client(&store, req).await.unwrap();
    assert!(
        doc.client_secret.is_none(),
        "public client (auth_method=none) must not have a secret"
    );
}

#[tokio::test]
async fn register_client_confidential_gets_secret() {
    let store = ClientStore::new();
    let req = RegistrationRequest {
        redirect_uris: vec!["https://app/cb".into()],
        token_endpoint_auth_method: Some("client_secret_basic".into()),
        ..Default::default()
    };
    let doc = register_client(&store, req).await.unwrap();
    assert!(
        doc.client_secret.is_some(),
        "confidential client must receive a secret"
    );
    assert!(doc.client_secret.unwrap().starts_with("secret-"));
}

#[tokio::test]
async fn register_client_defaults_grant_and_response_types() {
    let store = ClientStore::new();
    let req = RegistrationRequest {
        redirect_uris: vec!["https://app/cb".into()],
        ..Default::default()
    };
    let doc = register_client(&store, req).await.unwrap();
    assert!(doc.grant_types.contains(&"authorization_code".to_string()));
    assert!(doc.grant_types.contains(&"refresh_token".to_string()));
    assert!(doc.response_types.contains(&"code".to_string()));
}

#[tokio::test]
async fn register_client_preserves_custom_grant_types() {
    let store = ClientStore::new();
    let req = RegistrationRequest {
        redirect_uris: vec!["https://app/cb".into()],
        grant_types: vec!["authorization_code".into()],
        response_types: vec!["code".into()],
        ..Default::default()
    };
    let doc = register_client(&store, req).await.unwrap();
    assert_eq!(doc.grant_types, vec!["authorization_code".to_string()]);
    assert_eq!(doc.response_types, vec!["code".to_string()]);
}

#[tokio::test]
async fn register_client_defaults_scope_to_openid_webid() {
    let store = ClientStore::new();
    let req = RegistrationRequest {
        redirect_uris: vec!["https://app/cb".into()],
        ..Default::default()
    };
    let doc = register_client(&store, req).await.unwrap();
    assert_eq!(doc.scope.as_deref(), Some("openid webid"));
}

#[tokio::test]
async fn register_client_preserves_custom_scope() {
    let store = ClientStore::new();
    let req = RegistrationRequest {
        redirect_uris: vec!["https://app/cb".into()],
        scope: Some("openid webid profile".into()),
        ..Default::default()
    };
    let doc = register_client(&store, req).await.unwrap();
    assert_eq!(doc.scope.as_deref(), Some("openid webid profile"));
}

#[tokio::test]
async fn register_client_sets_application_type_default() {
    let store = ClientStore::new();
    let req = RegistrationRequest {
        redirect_uris: vec!["https://app/cb".into()],
        ..Default::default()
    };
    let doc = register_client(&store, req).await.unwrap();
    assert_eq!(doc.application_type.as_deref(), Some("web"));
}

#[tokio::test]
async fn register_client_preserves_custom_application_type() {
    let store = ClientStore::new();
    let req = RegistrationRequest {
        redirect_uris: vec!["https://app/cb".into()],
        application_type: Some("native".into()),
        ..Default::default()
    };
    let doc = register_client(&store, req).await.unwrap();
    assert_eq!(doc.application_type.as_deref(), Some("native"));
}

// ---------------------------------------------------------------------------
// ClientStore: find
// ---------------------------------------------------------------------------

#[tokio::test]
async fn find_registered_client_returns_correct_data() {
    let store = ClientStore::new();
    let req = RegistrationRequest {
        redirect_uris: vec!["https://app.example/cb".into()],
        client_name: Some("MyApp".into()),
        ..Default::default()
    };
    let doc = register_client(&store, req).await.unwrap();
    let found = store.find(&doc.client_id).await.unwrap().unwrap();
    assert_eq!(found.client_id, doc.client_id);
    assert_eq!(found.client_name.as_deref(), Some("MyApp"));
}

#[tokio::test]
async fn find_nonexistent_opaque_client_returns_none() {
    let store = ClientStore::new();
    let result = store.find("nonexistent-client-id").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn insert_then_find_round_trips() {
    let store = ClientStore::new();
    let doc = ClientDocument {
        client_id: "test-direct-insert".into(),
        client_secret: None,
        client_id_issued_at: 1700000000,
        redirect_uris: vec!["https://app/cb".into()],
        client_name: Some("Direct".into()),
        grant_types: vec!["authorization_code".into()],
        response_types: vec!["code".into()],
        token_endpoint_auth_method: "none".into(),
        application_type: Some("web".into()),
        scope: Some("openid webid".into()),
        client_id_document_url: None,
    };
    store.insert(doc.clone());
    let found = store.find("test-direct-insert").await.unwrap().unwrap();
    assert_eq!(found.client_name.as_deref(), Some("Direct"));
    assert_eq!(found.redirect_uris, vec!["https://app/cb".to_string()]);
}

// ---------------------------------------------------------------------------
// ClientStore: SSRF protection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn find_url_client_id_triggers_ssrf_guard_for_private_ip() {
    let store = ClientStore::new(); // SSRF enabled (production mode).
    let err = store.find("http://127.0.0.1/client").await.unwrap_err();
    assert!(
        matches!(err, RegError::Ssrf(_)),
        "private IP must be blocked by SSRF guard, got {err:?}"
    );
}

#[tokio::test]
async fn find_url_client_id_blocks_192_168_range() {
    let store = ClientStore::new();
    let err = store.find("http://192.168.1.1/client").await.unwrap_err();
    assert!(
        matches!(err, RegError::Ssrf(_)),
        "192.168.x.x must be SSRF-blocked, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// allow_unsafe_urls_for_testing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn allow_unsafe_urls_skips_ssrf_precheck() {
    // With unsafe URLs allowed but no wiremock server running on the
    // target, the request will fail at the HTTP level (connection
    // refused), NOT at the SSRF pre-flight. This proves the SSRF
    // guard was bypassed.
    let store = ClientStore::new().allow_unsafe_urls_for_testing();
    let err = store
        .find("http://127.0.0.1:1/nonexistent-client")
        .await
        .unwrap_err();
    // The error must be a Fetch (connection refused), not Ssrf.
    assert!(
        matches!(err, RegError::Fetch(_)),
        "with unsafe URLs allowed, error should be Fetch not Ssrf, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Multiple registrations produce unique ids
// ---------------------------------------------------------------------------

#[tokio::test]
async fn multiple_registrations_produce_distinct_client_ids() {
    let store = ClientStore::new();
    let mut ids = Vec::new();
    for _ in 0..10 {
        let req = RegistrationRequest {
            redirect_uris: vec!["https://app/cb".into()],
            ..Default::default()
        };
        let doc = register_client(&store, req).await.unwrap();
        ids.push(doc.client_id);
    }
    let unique: std::collections::HashSet<_> = ids.iter().collect();
    assert_eq!(
        unique.len(),
        10,
        "10 registrations must produce 10 distinct ids"
    );
}

// ---------------------------------------------------------------------------
// ClientDocument: client_id_issued_at is recent
// ---------------------------------------------------------------------------

#[tokio::test]
async fn registered_client_has_recent_issued_at() {
    let store = ClientStore::new();
    let req = RegistrationRequest {
        redirect_uris: vec!["https://app/cb".into()],
        ..Default::default()
    };
    let doc = register_client(&store, req).await.unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // issued_at should be within 5 seconds of now.
    assert!(
        doc.client_id_issued_at <= now && doc.client_id_issued_at >= now - 5,
        "client_id_issued_at should be recent, got {} vs now {}",
        doc.client_id_issued_at,
        now
    );
}

// ---------------------------------------------------------------------------
// ClientDocument: opaque registration has no document URL
// ---------------------------------------------------------------------------

#[tokio::test]
async fn opaque_registration_has_no_document_url() {
    let store = ClientStore::new();
    let req = RegistrationRequest {
        redirect_uris: vec!["https://app/cb".into()],
        ..Default::default()
    };
    let doc = register_client(&store, req).await.unwrap();
    assert!(
        doc.client_id_document_url.is_none(),
        "opaque registration should not set client_id_document_url"
    );
}
