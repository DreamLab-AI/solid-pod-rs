//! Sprint 11 row 80 — `WebauthnPasskey` integration smoke tests.
//!
//! webauthn-rs does not ship a public in-process authenticator as of
//! 0.5.4 (the test harness lives in its private test module), so a
//! fully E2E register-then-auth-through-the-wire roundtrip would
//! require reproducing ~400 LOC of CBOR attestation fixtures. That is
//! over-scope for this sprint.
//!
//! Instead we exercise the full wrapper path that matters:
//!
//! 1. Construction succeeds with reasonable defaults.
//! 2. `registration_options` produces a non-empty challenge and
//!    stores per-user state.
//! 3. Multiple users are isolated — one user's state cannot leak
//!    into another's ceremony.
//! 4. A replayed (already-consumed) registration token is rejected.
//! 5. `authentication_options` refuses users with no registered
//!    credentials.
//!
//! Together those cover the failure modes an integrator actually
//! hits in practice (mis-wiring, races, replay). True attestation /
//! assertion parsing is covered upstream by webauthn-rs' own test
//! suite, which we deliberately do not duplicate.

#![cfg(feature = "passkey")]

use solid_pod_rs_idp::passkey::{
    PasskeyBackend, PasskeyError, RegistrationResponse, WebauthnPasskey,
};
use url::Url;

fn backend() -> WebauthnPasskey {
    let origin = Url::parse("https://idp.example.com").unwrap();
    WebauthnPasskey::new("idp.example.com", "Example IdP", &origin)
        .expect("WebauthnPasskey::new with defaults should succeed")
}

#[tokio::test]
async fn passkey_registration_happy_path_via_webauthn_rs_wrapper() {
    let pk = backend();
    let opts = pk
        .registration_options("alice@example.com")
        .await
        .expect("start registration");
    let raw = opts.raw;
    // webauthn-rs embeds the challenge under publicKey.challenge as
    // a base64url string.
    let challenge = raw
        .pointer("/publicKey/challenge")
        .and_then(|v| v.as_str())
        .expect("publicKey.challenge present");
    assert!(!challenge.is_empty(), "challenge should be non-empty");
    // User handle should round-trip our account id (display name).
    let user_name = raw
        .pointer("/publicKey/user/name")
        .and_then(|v| v.as_str())
        .expect("publicKey.user.name present");
    assert_eq!(user_name, "alice@example.com");
}

#[tokio::test]
async fn passkey_rejects_replayed_challenge() {
    let pk = backend();
    // Start a ceremony, then attempt to verify twice. The first
    // consumption removes state; the second must fail with
    // NoCeremony. We don't need a valid attestation — the state
    // lookup runs before any crypto.
    pk.registration_options("alice").await.unwrap();
    // Simulate "finish then replay": we call registration_verify
    // once (will fail on parse since we pass a dummy response — the
    // point is that the state MUST be consumed on first attempt).
    let dummy = RegistrationResponse {
        id: "abc".into(),
        raw: serde_json::json!({}),
    };
    let first = pk.registration_verify("alice", dummy.clone()).await;
    assert!(
        first.is_err(),
        "first verify fails (no real attestation) but must consume state"
    );
    let second = pk.registration_verify("alice", dummy).await.unwrap_err();
    assert!(
        matches!(second, PasskeyError::NoCeremony(_)),
        "replay rejected as NoCeremony, got {second:?}"
    );
}

#[tokio::test]
async fn passkey_multiple_users_isolated() {
    let pk = backend();
    pk.registration_options("alice").await.unwrap();
    pk.registration_options("bob").await.unwrap();
    pk.registration_options("carol").await.unwrap();
    // Consuming bob's state must not affect alice or carol.
    let _ = pk
        .registration_verify(
            "bob",
            RegistrationResponse {
                id: "x".into(),
                raw: serde_json::json!({}),
            },
        )
        .await;
    let alice_again = pk
        .registration_verify(
            "alice",
            RegistrationResponse {
                id: "x".into(),
                raw: serde_json::json!({}),
            },
        )
        .await;
    // alice still had state → the error is parse/verification, NOT
    // NoCeremony. That proves bob's replay-consume didn't touch her.
    assert!(
        !matches!(alice_again, Err(PasskeyError::NoCeremony(_))),
        "alice's state was not consumed by bob's verify: {alice_again:?}"
    );
    // carol's state also untouched.
    let carol_again = pk
        .registration_verify(
            "carol",
            RegistrationResponse {
                id: "x".into(),
                raw: serde_json::json!({}),
            },
        )
        .await;
    assert!(
        !matches!(carol_again, Err(PasskeyError::NoCeremony(_))),
        "carol's state was not consumed: {carol_again:?}"
    );
}

#[tokio::test]
async fn passkey_authentication_without_registered_credentials_fails_fast() {
    let pk = backend();
    let err = pk
        .authentication_options("stranger")
        .await
        .expect_err("should fail");
    assert!(
        matches!(err, PasskeyError::NoCeremony(_)),
        "no credentials ⇒ NoCeremony, got {err:?}"
    );
}
