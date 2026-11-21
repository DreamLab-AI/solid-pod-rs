//! The token endpoint spends a DPoP `jti` only after the authorisation code
//! has been accepted (AW1-05 follow-up).
//!
//! A DPoP proof is signed with a key the client invents, so an anonymous
//! caller can mint any number of valid proofs. If `/token` recorded each
//! `jti` before checking the code, a flood of cheap proofs would fill the
//! bounded replay cache and lock out every real exchange.

use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

use solid_pod_rs::oidc::DpopReplayCache;
use solid_pod_rs_idp::error::ProviderError;
use solid_pod_rs_idp::jwks::Jwks;
use solid_pod_rs_idp::provider::{Provider, ProviderConfig, TokenRequest};
use solid_pod_rs_idp::registration::{register_client, ClientStore, RegistrationRequest};
use solid_pod_rs_idp::session::SessionStore;
use solid_pod_rs_idp::user_store::{InMemoryUserStore, UserStore};

const NOW: u64 = 1_700_000_000;
const REDIRECT: &str = "https://app.example/cb";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const TOKEN_URL: &str = "https://pod.example/idp/token";

struct Fixture {
    provider: Provider,
    cache: DpopReplayCache,
    client_id: String,
}

async fn fixture(capacity: usize) -> Fixture {
    let users = Arc::new(InMemoryUserStore::new());
    users
        .insert_user(
            "acct-1",
            "alice@example.com",
            "https://alice.example/profile#me",
            Some("Alice".into()),
            "hunter2!",
        )
        .unwrap();
    let clients = ClientStore::new();
    let client = register_client(
        &clients,
        RegistrationRequest {
            redirect_uris: vec![REDIRECT.into()],
            client_name: Some("TestApp".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let cache = DpopReplayCache::with_config(Duration::from_secs(122), capacity);
    let provider = Provider::new(
        ProviderConfig::new("https://pod.example"),
        clients,
        SessionStore::new(),
        users as Arc<dyn UserStore>,
        Jwks::generate_es256().unwrap(),
    )
    .with_dpop_replay_cache(cache.clone());
    Fixture {
        provider,
        cache,
        client_id: client.client_id,
    }
}

fn challenge() -> String {
    B64.encode(Sha256::digest(VERIFIER.as_bytes()))
}

fn fresh_code(f: &Fixture) -> String {
    f.provider
        .session_store()
        .issue_code(&f.client_id, "acct-1", REDIRECT, Some(challenge()), None)
        .code
}

/// A valid ES256 proof signed with a throwaway key derived from `jti`, as any
/// anonymous client can mint.
fn proof(jti: &str) -> String {
    let seed: [u8; 32] = Sha256::digest(jti.as_bytes()).into();
    let key = SigningKey::from_bytes(&seed.into()).expect("valid scalar");
    let point = key.verifying_key().to_sec1_point(false);
    let bytes = point.as_bytes();
    let jwk = serde_json::json!({
        "kty": "EC", "crv": "P-256",
        "x": B64.encode(&bytes[1..33]), "y": B64.encode(&bytes[33..65]),
    });
    let header = serde_json::json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk});
    let claims = serde_json::json!({"htu": TOKEN_URL, "htm": "POST", "iat": NOW, "jti": jti});
    let input = format!(
        "{}.{}",
        B64.encode(header.to_string()),
        B64.encode(claims.to_string())
    );
    let sig: Signature = key.sign(input.as_bytes());
    format!("{input}.{}", B64.encode(sig.to_bytes()))
}

async fn exchange(f: &Fixture, code: &str, dpop: &str) -> Result<(), ProviderError> {
    f.provider
        .token(TokenRequest {
            grant_type: "authorization_code".into(),
            code,
            redirect_uri: REDIRECT.into(),
            client_id: f.client_id.clone(),
            code_verifier: Some(VERIFIER),
            dpop_proof: Some(dpop),
            now_unix: NOW,
        })
        .await
        .map(|_| ())
}

#[tokio::test]
async fn a_flood_of_valid_proofs_with_bad_codes_takes_no_cache_capacity() {
    let f = fixture(4).await;
    for i in 0..50 {
        let err = exchange(&f, "not-a-code", &proof(&format!("flood-{i}")))
            .await
            .unwrap_err();
        assert!(matches!(err, ProviderError::InvalidGrant(_)), "{err:?}");
    }
    assert_eq!(
        f.cache.len().await,
        0,
        "no jti recorded without a valid code"
    );

    // A real exchange still works afterwards.
    let code = fresh_code(&f);
    exchange(&f, &code, &proof("real-1")).await.unwrap();
    assert_eq!(f.cache.len().await, 1);
}

#[tokio::test]
async fn a_valid_code_with_a_failed_grant_check_records_nothing() {
    let f = fixture(4).await;
    // Right code, wrong PKCE verifier.
    let code = fresh_code(&f);
    let err = f
        .provider
        .token(TokenRequest {
            grant_type: "authorization_code".into(),
            code: &code,
            redirect_uri: REDIRECT.into(),
            client_id: f.client_id.clone(),
            code_verifier: Some("wrong-verifier"),
            dpop_proof: Some(&proof("pkce-1")),
            now_unix: NOW,
        })
        .await
        .unwrap_err();
    assert!(matches!(err, ProviderError::InvalidGrant(_)), "{err:?}");
    assert_eq!(f.cache.len().await, 0);
}

#[tokio::test]
async fn a_replayed_proof_with_a_fresh_valid_code_is_refused_and_issues_no_token() {
    let f = fixture(4).await;
    let p = proof("once");
    let first = fresh_code(&f);
    exchange(&f, &first, &p).await.unwrap();

    let second = fresh_code(&f);
    let err = exchange(&f, &second, &p).await.unwrap_err();
    assert!(matches!(err, ProviderError::InvalidDpop(_)), "{err:?}");
    // The code was consumed by the refused exchange: it cannot be retried.
    assert!(f.provider.session_store().take_code(&second).is_none());
}

#[tokio::test]
async fn replay_and_full_cache_refusals_are_indistinguishable() {
    let f = fixture(1).await;
    let p = proof("fills-the-cache");
    let c1 = fresh_code(&f);
    exchange(&f, &c1, &p).await.unwrap();

    // Replay: same jti, valid code.
    let c2 = fresh_code(&f);
    let replay = exchange(&f, &c2, &p).await.unwrap_err();
    // Full: a new jti, valid code, cache of one live entry.
    let c3 = fresh_code(&f);
    let full = exchange(&f, &c3, &proof("a-different-jti"))
        .await
        .unwrap_err();

    assert_eq!(replay.to_string(), full.to_string());
    assert_eq!(replay.code(), full.code());
    let text = full.to_string().to_ascii_lowercase();
    for leak in ["capacity", "ttl", "122", "10000", "full", "already"] {
        assert!(!text.contains(leak), "message leaks {leak:?}: {text}");
    }
}
