//! Integration tests for invite management (`invites.rs`) and access
//! token issuance/verification (`tokens.rs`, `jwks.rs`).
//!
//! Exercises the public API from the integration boundary:
//! - `mint_token` uniqueness and format
//! - `parse_duration` edge cases
//! - `InMemoryInviteStore` CRUD
//! - `issue_access_token` claim integrity
//! - JWKS key rotation + PEM round-trip
//! - `ath_hash` correctness
//! - `InMemoryUserStore` + credential flow integration
//! - `validate_password_length` boundary checks

use std::collections::HashSet;
use std::time::Duration;

use solid_pod_rs_idp::credentials::validate_password_length;
use solid_pod_rs_idp::invites::{
    mint_token, parse_duration, InMemoryInviteStore, Invite, InviteStore,
};
use solid_pod_rs_idp::jwks::{Jwks, SigningKey};
use solid_pod_rs_idp::tokens::{ath_hash, issue_access_token};
use solid_pod_rs_idp::user_store::InMemoryUserStore;

// ===========================================================================
// mint_token
// ===========================================================================

#[test]
fn mint_token_produces_43_char_base64url() {
    let t = mint_token();
    // 32 raw bytes -> 43 base64url chars (no padding).
    assert_eq!(t.len(), 43);
    assert!(
        t.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "token must be URL-safe base64, got: {t}"
    );
}

#[test]
fn mint_token_is_unique_across_100_calls() {
    let tokens: HashSet<String> = (0..100).map(|_| mint_token()).collect();
    assert_eq!(tokens.len(), 100);
}

// ===========================================================================
// parse_duration
// ===========================================================================

#[test]
fn parse_duration_seconds() {
    assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
    assert_eq!(parse_duration("1s").unwrap(), Duration::from_secs(1));
    assert_eq!(parse_duration("0s").unwrap(), Duration::from_secs(0));
}

#[test]
fn parse_duration_minutes() {
    assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
    assert_eq!(parse_duration("1m").unwrap(), Duration::from_secs(60));
}

#[test]
fn parse_duration_hours() {
    assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
    assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
    assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(86400));
}

#[test]
fn parse_duration_days() {
    assert_eq!(parse_duration("7d").unwrap(), Duration::from_secs(604_800));
    assert_eq!(parse_duration("1d").unwrap(), Duration::from_secs(86_400));
    assert_eq!(
        parse_duration("30d").unwrap(),
        Duration::from_secs(2_592_000)
    );
}

#[test]
fn parse_duration_weeks() {
    assert_eq!(parse_duration("1w").unwrap(), Duration::from_secs(604_800));
    assert_eq!(
        parse_duration("2w").unwrap(),
        Duration::from_secs(1_209_600)
    );
}

#[test]
fn parse_duration_plain_integer_is_seconds() {
    assert_eq!(parse_duration("60").unwrap(), Duration::from_secs(60));
    assert_eq!(parse_duration("3600").unwrap(), Duration::from_secs(3600));
    assert_eq!(parse_duration("0").unwrap(), Duration::from_secs(0));
}

#[test]
fn parse_duration_rejects_empty_string() {
    assert!(parse_duration("").is_err());
}

#[test]
fn parse_duration_rejects_unknown_unit() {
    assert!(parse_duration("1y").is_err());
    assert!(parse_duration("5x").is_err());
}

#[test]
fn parse_duration_rejects_non_numeric() {
    assert!(parse_duration("abc").is_err());
}

#[test]
fn parse_duration_handles_whitespace() {
    // Trimmed input.
    assert_eq!(parse_duration("  5m  ").unwrap(), Duration::from_secs(300));
}

// ===========================================================================
// InMemoryInviteStore
// ===========================================================================

#[tokio::test]
async fn invite_store_insert_and_get_round_trip() {
    let store = InMemoryInviteStore::new();
    let inv = Invite {
        token: "test-token-1".into(),
        max_uses: Some(5),
        expires_at: None,
    };
    store.insert(inv.clone()).await.unwrap();
    let got = store.get("test-token-1").await.unwrap().unwrap();
    assert_eq!(got, inv);
}

#[tokio::test]
async fn invite_store_get_missing_returns_none() {
    let store = InMemoryInviteStore::new();
    assert!(store.get("nonexistent").await.unwrap().is_none());
}

#[tokio::test]
async fn invite_store_insert_is_idempotent() {
    let store = InMemoryInviteStore::new();
    let inv1 = Invite {
        token: "idem-token".into(),
        max_uses: Some(3),
        expires_at: None,
    };
    let inv2 = Invite {
        token: "idem-token".into(),
        max_uses: Some(99), // different max_uses
        expires_at: None,
    };
    store.insert(inv1.clone()).await.unwrap();
    store.insert(inv2).await.unwrap();
    // First insert wins (entry API uses or_insert).
    let got = store.get("idem-token").await.unwrap().unwrap();
    assert_eq!(got.max_uses, Some(3));
}

#[tokio::test]
async fn invite_store_snapshot_returns_all_invites() {
    let store = InMemoryInviteStore::new();
    for i in 0..5 {
        store
            .insert(Invite {
                token: format!("tok-{i}"),
                max_uses: None,
                expires_at: None,
            })
            .await
            .unwrap();
    }
    let snap = store.snapshot();
    assert_eq!(snap.len(), 5);
}

#[tokio::test]
async fn invite_store_with_expiry() {
    let store = InMemoryInviteStore::new();
    let expires = chrono::Utc::now() + chrono::Duration::hours(1);
    let inv = Invite {
        token: "expiring-token".into(),
        max_uses: Some(1),
        expires_at: Some(expires),
    };
    store.insert(inv.clone()).await.unwrap();
    let got = store.get("expiring-token").await.unwrap().unwrap();
    assert_eq!(got.expires_at, Some(expires));
    assert_eq!(got.max_uses, Some(1));
}

#[tokio::test]
async fn invite_store_unlimited_uses() {
    let store = InMemoryInviteStore::new();
    let inv = Invite {
        token: "unlimited".into(),
        max_uses: None,
        expires_at: None,
    };
    store.insert(inv.clone()).await.unwrap();
    let got = store.get("unlimited").await.unwrap().unwrap();
    assert!(got.max_uses.is_none());
}

// ===========================================================================
// issue_access_token
// ===========================================================================

#[test]
fn issue_access_token_produces_three_segment_jwt() {
    let jwks = Jwks::generate_es256().unwrap();
    let key = jwks.active_key();
    let token = issue_access_token(
        &key,
        "https://pod.example/",
        "https://alice.example/profile#me",
        "acct-1",
        "client-xyz",
        "openid webid",
        Some("dpop-jkt-value"),
        1_700_000_000,
        3600,
    )
    .unwrap();
    assert_eq!(
        token.jwt.matches('.').count(),
        2,
        "JWT must have 3 segments"
    );
}

#[test]
fn issue_access_token_populates_all_payload_fields() {
    let jwks = Jwks::generate_es256().unwrap();
    let key = jwks.active_key();
    let token = issue_access_token(
        &key,
        "https://pod.example/",
        "https://alice.example/me",
        "acct-1",
        "client-1",
        "openid webid profile",
        Some("jkt-hash"),
        1_700_000_000,
        7200,
    )
    .unwrap();
    let p = &token.payload;
    assert_eq!(p.iss, "https://pod.example/");
    assert_eq!(p.sub, "acct-1");
    assert_eq!(p.aud, "solid");
    assert_eq!(p.webid, "https://alice.example/me");
    assert_eq!(p.iat, 1_700_000_000);
    assert_eq!(p.exp, 1_700_000_000 + 7200);
    assert_eq!(p.client_id, "client-1");
    assert_eq!(p.scope, "openid webid profile");
    assert!(!p.jti.is_empty());
    assert_eq!(p.cnf.as_ref().unwrap().jkt, "jkt-hash");
}

#[test]
fn issue_access_token_without_dpop_has_no_cnf() {
    let jwks = Jwks::generate_es256().unwrap();
    let key = jwks.active_key();
    let token = issue_access_token(
        &key,
        "https://pod.example/",
        "https://a/me",
        "a",
        "c",
        "openid",
        None,
        0,
        60,
    )
    .unwrap();
    assert!(token.payload.cnf.is_none());
}

#[test]
fn issue_access_token_jti_is_unique() {
    let jwks = Jwks::generate_es256().unwrap();
    let key = jwks.active_key();
    let t1 = issue_access_token(&key, "i", "w", "a", "c", "s", None, 0, 60).unwrap();
    let t2 = issue_access_token(&key, "i", "w", "a", "c", "s", None, 0, 60).unwrap();
    assert_ne!(
        t1.payload.jti, t2.payload.jti,
        "jti must be unique per token"
    );
}

// ===========================================================================
// ath_hash
// ===========================================================================

#[test]
fn ath_hash_known_value() {
    // SHA-256("foo") base64url-noPad
    assert_eq!(
        ath_hash("foo"),
        "LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564"
    );
}

#[test]
fn ath_hash_empty_input() {
    // SHA-256("") = 47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU
    let h = ath_hash("");
    assert!(!h.is_empty());
    assert_eq!(h, "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU");
}

#[test]
fn ath_hash_different_inputs_differ() {
    assert_ne!(ath_hash("token-a"), ath_hash("token-b"));
}

// ===========================================================================
// JWKS key rotation
// ===========================================================================

#[test]
fn jwks_generate_produces_single_key() {
    let jwks = Jwks::generate_es256().unwrap();
    let doc = jwks.public_document();
    assert_eq!(doc.keys.len(), 1);
    assert_eq!(doc.keys[0].kty, "EC");
    assert_eq!(doc.keys[0].crv, "P-256");
}

#[test]
fn jwks_rotate_adds_retired_key() {
    let jwks = Jwks::generate_es256().unwrap();
    let kid1 = jwks.active_key().kid.clone();
    let new_key = jwks.rotate().unwrap();
    assert_ne!(new_key.kid, kid1);
    let doc = jwks.public_document();
    assert_eq!(doc.keys.len(), 2, "active + 1 retired");
    assert!(doc.keys.iter().any(|k| k.kid == kid1));
    assert!(doc.keys.iter().any(|k| k.kid == new_key.kid));
}

#[test]
fn jwks_double_rotate_keeps_all_retired_keys() {
    let jwks = Jwks::generate_es256().unwrap();
    let kid0 = jwks.active_key().kid.clone();
    let kid1 = jwks.rotate().unwrap().kid;
    let kid2 = jwks.rotate().unwrap().kid;
    let doc = jwks.public_document();
    assert_eq!(doc.keys.len(), 3);
    assert!(doc.keys.iter().any(|k| k.kid == kid0));
    assert!(doc.keys.iter().any(|k| k.kid == kid1));
    assert!(doc.keys.iter().any(|k| k.kid == kid2));
}

#[test]
fn jwks_prune_removes_expired_retired_keys() {
    let jwks = Jwks::generate_es256()
        .unwrap()
        .with_retention(Duration::from_millis(1));
    jwks.rotate().unwrap();
    std::thread::sleep(Duration::from_millis(20));
    jwks.prune_expired();
    let doc = jwks.public_document();
    assert_eq!(doc.keys.len(), 1, "pruned: only active key remains");
}

#[test]
fn jwks_insert_signing_key_replaces_active() {
    let jwks = Jwks::generate_es256().unwrap();
    let kid_old = jwks.active_key().kid.clone();
    let new_key = SigningKey::generate_es256().unwrap();
    let kid_new = new_key.kid.clone();
    jwks.insert_signing_key(new_key);
    assert_eq!(jwks.active_key().kid, kid_new);
    let doc = jwks.public_document();
    assert!(doc.keys.iter().any(|k| k.kid == kid_old));
}

#[test]
fn signing_key_pem_round_trip() {
    let original = SigningKey::generate_es256().unwrap();
    let restored = SigningKey::from_pem(&original.kid, &original.private_pem).unwrap();
    assert_eq!(original.public_jwk.x, restored.public_jwk.x);
    assert_eq!(original.public_jwk.y, restored.public_jwk.y);
    assert_eq!(restored.alg, "ES256");
}

#[test]
fn signing_key_kid_starts_with_es256_prefix() {
    let key = SigningKey::generate_es256().unwrap();
    assert!(key.kid.starts_with("es256-"));
}

// ===========================================================================
// UserStore integration
// ===========================================================================

#[tokio::test]
async fn user_store_case_insensitive_email_lookup() {
    let store = InMemoryUserStore::new();
    store
        .insert_user(
            "u-1",
            "Alice@Example.COM",
            "https://alice.example/me",
            None,
            "password123",
        )
        .unwrap();
    use solid_pod_rs_idp::user_store::UserStore;
    let found = store.find_by_email("alice@example.com").await.unwrap();
    assert!(found.is_some());
    let found_upper = store.find_by_email("ALICE@EXAMPLE.COM").await.unwrap();
    assert!(found_upper.is_some());
}

#[tokio::test]
async fn user_store_find_by_id_works() {
    let store = InMemoryUserStore::new();
    store
        .insert_user(
            "u-id-test",
            "test@example.com",
            "https://test.example/me",
            Some("Test User".into()),
            "secure-password",
        )
        .unwrap();
    use solid_pod_rs_idp::user_store::UserStore;
    let found = store.find_by_id("u-id-test").await.unwrap().unwrap();
    assert_eq!(found.email, "test@example.com");
    assert_eq!(found.name.as_deref(), Some("Test User"));
}

#[tokio::test]
async fn user_store_verify_password_works() {
    let store = InMemoryUserStore::new();
    let user = store
        .insert_user(
            "u-pw",
            "pw@example.com",
            "https://pw.example/me",
            None,
            "correct-horse-battery-staple",
        )
        .unwrap();
    use solid_pod_rs_idp::user_store::UserStore;
    assert!(store
        .verify_password(&user, "correct-horse-battery-staple")
        .await
        .unwrap());
    assert!(!store
        .verify_password(&user, "wrong-password")
        .await
        .unwrap());
}

// ===========================================================================
// validate_password_length
// ===========================================================================

#[test]
fn validate_password_7_chars_fails() {
    assert!(validate_password_length("1234567").is_err());
}

#[test]
fn validate_password_8_chars_succeeds() {
    assert!(validate_password_length("12345678").is_ok());
}

#[test]
fn validate_password_empty_fails() {
    assert!(validate_password_length("").is_err());
}

#[test]
fn validate_password_long_succeeds() {
    assert!(validate_password_length("a-very-long-and-secure-passphrase").is_ok());
}
