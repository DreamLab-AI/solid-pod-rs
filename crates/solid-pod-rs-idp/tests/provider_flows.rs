//! Integration tests for `Provider` — OIDC authorization-code flows,
//! discovery document generation, and error paths.
//!
//! These tests exercise the provider from an integration boundary,
//! treating it as a black box. The `token` and `userinfo` endpoints
//! require valid DPoP proofs which are non-trivial to construct outside
//! the crate (the HS256 `kty=oct` test path used in the inline tests is
//! an internal detail). We focus on the `/auth` surface and the
//! discovery document here, plus structural validation of the provider
//! API.

use std::sync::Arc;

use solid_pod_rs_idp::discovery::build_discovery;
use solid_pod_rs_idp::error::ProviderError;
use solid_pod_rs_idp::jwks::Jwks;
use solid_pod_rs_idp::provider::{AuthorizeRequest, AuthorizeResponse, Provider, ProviderConfig};
use solid_pod_rs_idp::registration::{register_client, ClientStore, RegistrationRequest};
use solid_pod_rs_idp::session::SessionStore;
use solid_pod_rs_idp::user_store::{InMemoryUserStore, UserStore};

/// Construct a Provider with a registered client and a seeded user.
/// Returns (provider, client_id, pkce_verifier).
async fn build_provider() -> (Provider, String, String) {
    let user_store = Arc::new(InMemoryUserStore::new());
    user_store
        .insert_user(
            "acct-1",
            "alice@example.com",
            "https://alice.example/profile#me",
            Some("Alice".into()),
            "hunter2!",
        )
        .unwrap();

    let jwks = Jwks::generate_es256().unwrap();
    let clients = ClientStore::new();
    let client = register_client(
        &clients,
        RegistrationRequest {
            redirect_uris: vec!["https://app.example/cb".into()],
            client_name: Some("TestApp".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let sessions = SessionStore::new();
    let cfg = ProviderConfig::new("https://pod.example");
    let provider = Provider::new(
        cfg,
        clients,
        sessions,
        user_store as Arc<dyn UserStore>,
        jwks,
    );

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    (provider, client.client_id, verifier.to_string())
}

fn s256(verifier: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine;
    use sha2::{Digest, Sha256};
    B64.encode(Sha256::digest(verifier.as_bytes()))
}

// ---------------------------------------------------------------------------
// Provider construction + accessors
// ---------------------------------------------------------------------------

#[tokio::test]
async fn provider_construction_succeeds() {
    let (p, _, _) = build_provider().await;
    // Slash-normalised at construction (JSS #524 — see
    // `provider_config_new_sets_defaults`).
    assert_eq!(p.config().issuer, "https://pod.example/");
    assert_eq!(p.config().access_token_ttl_secs, 3600);
    assert_eq!(p.config().dpop_skew_secs, 60);
}

#[tokio::test]
async fn provider_exposes_jwks() {
    let (p, _, _) = build_provider().await;
    let doc = p.jwks().public_document();
    assert!(!doc.keys.is_empty(), "JWKS must have at least one key");
    assert_eq!(doc.keys[0].alg, "ES256");
}

#[tokio::test]
async fn provider_exposes_session_store() {
    let (p, _, _) = build_provider().await;
    let sess = p.session_store();
    let id = sess.create_session("test-acct");
    let rec = sess.lookup(&id).unwrap();
    assert_eq!(rec.account_id, "test-acct");
}

#[tokio::test]
async fn provider_exposes_client_store() {
    let (p, client_id, _) = build_provider().await;
    let found = p.client_store().find(&client_id).await.unwrap();
    assert!(found.is_some());
}

// ---------------------------------------------------------------------------
// Discovery document
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_document_from_provider_has_correct_issuer() {
    let (p, _, _) = build_provider().await;
    let doc = p.discovery_document();
    assert_eq!(doc.issuer, "https://pod.example/");
}

#[test]
fn discovery_document_contains_all_required_endpoints() {
    let doc = build_discovery("https://pod.example");
    assert_eq!(doc.authorization_endpoint, "https://pod.example/idp/auth");
    assert_eq!(doc.token_endpoint, "https://pod.example/idp/token");
    assert_eq!(doc.userinfo_endpoint, "https://pod.example/idp/me");
    assert_eq!(doc.jwks_uri, "https://pod.example/.well-known/jwks.json");
    assert_eq!(doc.registration_endpoint, "https://pod.example/idp/reg");
    assert_eq!(
        doc.end_session_endpoint,
        "https://pod.example/idp/session/end"
    );
    assert_eq!(
        doc.introspection_endpoint,
        "https://pod.example/idp/token/introspection"
    );
    assert_eq!(
        doc.revocation_endpoint,
        "https://pod.example/idp/token/revocation"
    );
}

#[test]
fn discovery_document_advertises_solid_oidc_profile() {
    let doc = build_discovery("https://pod.example");
    assert!(doc.solid_oidc_supported.contains("solid-oidc"));
    assert!(doc.authorization_response_iss_parameter_supported);
}

#[test]
fn discovery_document_advertises_dpop_es256() {
    let doc = build_discovery("https://pod.example");
    assert!(doc
        .dpop_signing_alg_values_supported
        .contains(&"ES256".to_string()));
}

#[test]
fn discovery_document_advertises_pkce_s256() {
    let doc = build_discovery("https://pod.example");
    assert!(doc
        .code_challenge_methods_supported
        .contains(&"S256".to_string()));
}

#[test]
fn discovery_document_supports_webid_scope() {
    let doc = build_discovery("https://pod.example");
    assert!(doc.scopes_supported.contains(&"webid".to_string()));
    assert!(doc.scopes_supported.contains(&"openid".to_string()));
}

#[test]
fn discovery_normalises_trailing_slash() {
    let a = build_discovery("https://pod.example");
    let b = build_discovery("https://pod.example/");
    assert_eq!(a.issuer, b.issuer);
    assert_eq!(a, b);
}

#[test]
fn discovery_endpoints_never_have_double_slash() {
    let doc = build_discovery("https://pod.example/");
    assert!(!doc.authorization_endpoint.contains("//idp"));
    assert!(!doc.token_endpoint.contains("//idp"));
    assert!(!doc.jwks_uri.contains("//.well-known"));
}

#[test]
fn discovery_document_serialises_to_json() {
    let doc = build_discovery("https://pod.example");
    let json = serde_json::to_value(&doc).unwrap();
    assert_eq!(json["issuer"], "https://pod.example/");
    assert!(json["scopes_supported"].is_array());
    assert!(json["authorization_response_iss_parameter_supported"]
        .as_bool()
        .unwrap());
}

// ---------------------------------------------------------------------------
// /auth — authorize endpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn authorize_without_session_returns_needs_login() {
    let (p, client_id, verifier) = build_provider().await;
    let req = AuthorizeRequest {
        client_id,
        response_type: "code".into(),
        redirect_uri: "https://app.example/cb".into(),
        state: Some("state-1".into()),
        code_challenge: Some(s256(&verifier)),
        code_challenge_method: Some("S256".into()),
        scope: Some("openid webid".into()),
        session_account_id: None,
    };
    match p.authorize(req).await.unwrap() {
        AuthorizeResponse::NeedsLogin {
            client_id, state, ..
        } => {
            assert!(client_id.starts_with("client_"));
            assert_eq!(state.as_deref(), Some("state-1"));
        }
        other => panic!("expected NeedsLogin, got {other:?}"),
    }
}

#[tokio::test]
async fn authorize_with_session_returns_redirect_with_code() {
    let (p, client_id, verifier) = build_provider().await;
    let challenge = s256(&verifier);
    let req = AuthorizeRequest {
        client_id: client_id.clone(),
        response_type: "code".into(),
        redirect_uri: "https://app.example/cb".into(),
        state: Some("state-2".into()),
        code_challenge: Some(challenge),
        code_challenge_method: Some("S256".into()),
        scope: Some("openid webid".into()),
        session_account_id: Some("acct-1".into()),
    };
    match p.authorize(req).await.unwrap() {
        AuthorizeResponse::Redirect {
            redirect_uri,
            code,
            state,
            iss,
        } => {
            assert_eq!(redirect_uri, "https://app.example/cb");
            assert!(!code.is_empty());
            assert_eq!(code.len(), 64, "code should be 32 bytes hex");
            assert_eq!(state.as_deref(), Some("state-2"));
            assert!(iss.contains("pod.example"));
        }
        other => panic!("expected Redirect, got {other:?}"),
    }
}

#[tokio::test]
async fn authorize_rejects_unknown_client() {
    let (p, _, verifier) = build_provider().await;
    let req = AuthorizeRequest {
        client_id: "nonexistent-client".into(),
        response_type: "code".into(),
        redirect_uri: "https://app.example/cb".into(),
        state: None,
        code_challenge: Some(s256(&verifier)),
        code_challenge_method: Some("S256".into()),
        scope: None,
        session_account_id: Some("acct-1".into()),
    };
    let err = p.authorize(req).await.unwrap_err();
    assert!(
        matches!(err, ProviderError::InvalidClient(_)),
        "expected InvalidClient, got {err:?}"
    );
}

#[tokio::test]
async fn authorize_rejects_unregistered_redirect_uri() {
    let (p, client_id, verifier) = build_provider().await;
    let req = AuthorizeRequest {
        client_id,
        response_type: "code".into(),
        redirect_uri: "https://evil.example/steal".into(),
        state: None,
        code_challenge: Some(s256(&verifier)),
        code_challenge_method: Some("S256".into()),
        scope: None,
        session_account_id: Some("acct-1".into()),
    };
    let err = p.authorize(req).await.unwrap_err();
    assert!(
        matches!(err, ProviderError::InvalidRequest(_)),
        "expected InvalidRequest for bad redirect_uri, got {err:?}"
    );
}

#[tokio::test]
async fn authorize_rejects_response_type_token() {
    let (p, client_id, verifier) = build_provider().await;
    let req = AuthorizeRequest {
        client_id,
        response_type: "token".into(),
        redirect_uri: "https://app.example/cb".into(),
        state: None,
        code_challenge: Some(s256(&verifier)),
        code_challenge_method: Some("S256".into()),
        scope: None,
        session_account_id: Some("acct-1".into()),
    };
    let err = p.authorize(req).await.unwrap_err();
    assert!(
        matches!(err, ProviderError::InvalidRequest(_)),
        "response_type=token must be rejected, got {err:?}"
    );
}

#[tokio::test]
async fn authorize_rejects_missing_pkce() {
    let (p, client_id, _) = build_provider().await;
    let req = AuthorizeRequest {
        client_id,
        response_type: "code".into(),
        redirect_uri: "https://app.example/cb".into(),
        state: None,
        code_challenge: None,
        code_challenge_method: None,
        scope: None,
        session_account_id: Some("acct-1".into()),
    };
    let err = p.authorize(req).await.unwrap_err();
    assert!(
        matches!(err, ProviderError::InvalidRequest(_)),
        "missing PKCE must be rejected, got {err:?}"
    );
}

#[tokio::test]
async fn authorize_rejects_pkce_plain_method() {
    let (p, client_id, verifier) = build_provider().await;
    let req = AuthorizeRequest {
        client_id,
        response_type: "code".into(),
        redirect_uri: "https://app.example/cb".into(),
        state: None,
        code_challenge: Some(verifier.clone()),
        code_challenge_method: Some("plain".into()),
        scope: None,
        session_account_id: Some("acct-1".into()),
    };
    let err = p.authorize(req).await.unwrap_err();
    assert!(
        matches!(err, ProviderError::InvalidRequest(_)),
        "PKCE plain method must be rejected (S256 only), got {err:?}"
    );
}

#[tokio::test]
async fn authorize_echoes_state_back() {
    let (p, client_id, verifier) = build_provider().await;
    let req = AuthorizeRequest {
        client_id,
        response_type: "code".into(),
        redirect_uri: "https://app.example/cb".into(),
        state: Some("my-opaque-state-value".into()),
        code_challenge: Some(s256(&verifier)),
        code_challenge_method: Some("S256".into()),
        scope: Some("openid".into()),
        session_account_id: Some("acct-1".into()),
    };
    match p.authorize(req).await.unwrap() {
        AuthorizeResponse::Redirect { state, .. } => {
            assert_eq!(state.as_deref(), Some("my-opaque-state-value"));
        }
        other => panic!("expected Redirect, got {other:?}"),
    }
}

#[tokio::test]
async fn authorize_with_no_state_echoes_none() {
    let (p, client_id, verifier) = build_provider().await;
    let req = AuthorizeRequest {
        client_id,
        response_type: "code".into(),
        redirect_uri: "https://app.example/cb".into(),
        state: None,
        code_challenge: Some(s256(&verifier)),
        code_challenge_method: Some("S256".into()),
        scope: None,
        session_account_id: Some("acct-1".into()),
    };
    match p.authorize(req).await.unwrap() {
        AuthorizeResponse::Redirect { state, .. } => {
            assert!(state.is_none());
        }
        other => panic!("expected Redirect, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// ProviderError: code() method
// ---------------------------------------------------------------------------

#[test]
fn provider_error_code_mapping() {
    assert_eq!(
        ProviderError::InvalidRequest("x".into()).code(),
        "invalid_request"
    );
    assert_eq!(
        ProviderError::InvalidGrant("x".into()).code(),
        "invalid_grant"
    );
    assert_eq!(
        ProviderError::InvalidClient("x".into()).code(),
        "invalid_client"
    );
    assert_eq!(
        ProviderError::InvalidDpop("x".into()).code(),
        "invalid_dpop_proof"
    );
    assert_eq!(
        ProviderError::ClientDocument("x".into()).code(),
        "invalid_client"
    );
    assert_eq!(
        ProviderError::PasswordTooShort { min_length: 8 }.code(),
        "invalid_request"
    );
    assert_eq!(
        ProviderError::RateLimited {
            retry_after_secs: 60
        }
        .code(),
        "rate_limited"
    );
    assert_eq!(ProviderError::UserStore("x".into()).code(), "server_error");
    assert_eq!(ProviderError::Crypto("x".into()).code(), "server_error");
    assert_eq!(ProviderError::Session("x".into()).code(), "server_error");
    assert_eq!(ProviderError::Internal("x".into()).code(), "server_error");
}

// ---------------------------------------------------------------------------
// ProviderConfig
// ---------------------------------------------------------------------------

#[test]
fn provider_config_new_sets_defaults() {
    // JSS #524: the issuer is slash-normalised at construction so the
    // discovery `issuer`, RFC 9207 `iss` param, and token `iss` claim are
    // byte-identical regardless of how the operator wrote the config.
    let cfg = ProviderConfig::new("https://my-pod.example");
    assert_eq!(cfg.issuer, "https://my-pod.example/");
    assert_eq!(cfg.access_token_ttl_secs, 3600);
    assert_eq!(cfg.dpop_skew_secs, 60);
    // Already-normalised input is untouched (idempotent).
    assert_eq!(
        ProviderConfig::new("https://my-pod.example/").issuer,
        "https://my-pod.example/"
    );
}

#[test]
fn discovery_issuer_matches_token_iss_byte_for_byte() {
    // The RFC 9207 invariant JSS #524 fixed: a strict client compares the
    // discovery document's `issuer` against the authorization response
    // `iss` and the token `iss` claim byte-for-byte.
    let cfg = ProviderConfig::new("https://pod.example");
    let discovery = solid_pod_rs_idp::discovery::build_discovery(&cfg.issuer);
    assert_eq!(discovery.issuer, cfg.issuer);
}
