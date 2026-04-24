//! Sprint 11 row 81 — `Nip07SchnorrSso` integration tests.
//!
//! Covers:
//!
//! 1. Challenge issuance produces 32 random bytes, hex-encoded.
//! 2. Challenges are bound to a specific user id.
//! 3. A valid Schnorr signature is accepted.
//! 4. A tampered challenge (or tampered digest) is rejected.
//! 5. Expired challenges are rejected.
//! 6. A successfully-verified challenge cannot be replayed.

#![cfg(feature = "schnorr-sso")]

use std::time::Duration;

use k256::schnorr::{signature::Signer, Signature, SigningKey};
use solid_pod_rs_idp::schnorr::{Nip07SchnorrSso, SchnorrError, SchnorrSso};

/// Deterministic key — seed 0x42 is known to produce a valid
/// BIP-340 signing key (secp256k1 acceptance is ~99.9%).
fn test_key() -> (SigningKey, String) {
    let seed = [0x42u8; 32];
    let sk = SigningKey::from_bytes(&seed).expect("valid Schnorr key");
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());
    (sk, pk_hex)
}

fn sign(sk: &SigningKey, digest: &[u8; 32]) -> String {
    let sig: Signature = sk.sign(digest);
    hex::encode(sig.to_bytes())
}

#[tokio::test]
async fn schnorr_challenge_issued_is_32_random_bytes_hex() {
    let sso = Nip07SchnorrSso::default();
    let c1 = sso.issue_challenge("alice").await.unwrap();
    let c2 = sso.issue_challenge("alice").await.unwrap();
    // 32 bytes → 64 hex chars.
    assert_eq!(c1.token.len(), 64, "32 bytes hex-encoded");
    // All lowercase hex.
    assert!(
        c1.token.chars().all(|c| c.is_ascii_hexdigit()),
        "token is hex"
    );
    // Consecutive challenges differ (re-issuing overwrites but the
    // token content is freshly random each call).
    assert_ne!(c1.token, c2.token, "freshly random tokens");
    assert_eq!(c1.user_id, "alice");
}

#[tokio::test]
async fn schnorr_challenge_bound_to_user() {
    let sso = Nip07SchnorrSso::default();
    let (sk, pk_hex) = test_key();
    let alice = sso.issue_challenge("alice").await.unwrap();
    // Sign Alice's challenge but try to verify as Bob → no challenge
    // for Bob, so the response is rejected at lookup.
    let digest = Nip07SchnorrSso::canonical_digest(&alice.token, "alice", &pk_hex);
    let sig_hex = sign(&sk, &digest);
    let err = sso
        .verify_response("bob", &pk_hex, &sig_hex)
        .await
        .unwrap_err();
    assert!(
        matches!(err, SchnorrError::Challenge(_)),
        "bob has no challenge, got {err:?}"
    );
    // Alice can still verify — her challenge is untouched.
    sso.verify_response("alice", &pk_hex, &sig_hex)
        .await
        .expect("alice verifies with her own challenge");
}

#[tokio::test]
async fn schnorr_verify_accepts_valid_sig() {
    let sso = Nip07SchnorrSso::default();
    let (sk, pk_hex) = test_key();
    let challenge = sso.issue_challenge("alice").await.unwrap();
    let digest = Nip07SchnorrSso::canonical_digest(&challenge.token, "alice", &pk_hex);
    let sig_hex = sign(&sk, &digest);
    let assertion = sso
        .verify_response("alice", &pk_hex, &sig_hex)
        .await
        .expect("valid signature accepted");
    assert_eq!(assertion.user_id, "alice");
    assert_eq!(assertion.pubkey, pk_hex);
}

#[tokio::test]
async fn schnorr_verify_rejects_tampered_challenge() {
    let sso = Nip07SchnorrSso::default();
    let (sk, pk_hex) = test_key();
    let challenge = sso.issue_challenge("alice").await.unwrap();
    // Sign an alternate token (as if MITM rewrote the challenge).
    let bogus = "ff".repeat(32);
    let digest = Nip07SchnorrSso::canonical_digest(&bogus, "alice", &pk_hex);
    let sig_hex = sign(&sk, &digest);
    let err = sso
        .verify_response("alice", &pk_hex, &sig_hex)
        .await
        .unwrap_err();
    assert!(
        matches!(err, SchnorrError::InvalidSignature(_)),
        "tampered challenge rejected, got {err:?}"
    );
    // And the legitimate challenge has been consumed — no retry.
    let (_, pk_hex2) = test_key();
    let digest_real = Nip07SchnorrSso::canonical_digest(&challenge.token, "alice", &pk_hex2);
    let sig2 = sign(&sk, &digest_real);
    let err2 = sso
        .verify_response("alice", &pk_hex2, &sig2)
        .await
        .unwrap_err();
    assert!(
        matches!(err2, SchnorrError::Challenge(_)),
        "one-shot consumption: second attempt sees no challenge, got {err2:?}"
    );
}

#[tokio::test]
async fn schnorr_verify_rejects_expired_challenge() {
    // TTL of 1ms — any real-world delay trips it.
    let sso = Nip07SchnorrSso::new(Duration::from_millis(1));
    let (sk, pk_hex) = test_key();
    let challenge = sso.issue_challenge("alice").await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let digest = Nip07SchnorrSso::canonical_digest(&challenge.token, "alice", &pk_hex);
    let sig_hex = sign(&sk, &digest);
    let err = sso
        .verify_response("alice", &pk_hex, &sig_hex)
        .await
        .unwrap_err();
    assert!(
        matches!(err, SchnorrError::Challenge(ref msg) if msg.contains("expired")),
        "expired challenge surfaced as Challenge(expired), got {err:?}"
    );
}

#[tokio::test]
async fn schnorr_verify_is_one_shot_rejects_reuse() {
    let sso = Nip07SchnorrSso::default();
    let (sk, pk_hex) = test_key();
    let challenge = sso.issue_challenge("alice").await.unwrap();
    let digest = Nip07SchnorrSso::canonical_digest(&challenge.token, "alice", &pk_hex);
    let sig_hex = sign(&sk, &digest);
    // First use succeeds.
    sso.verify_response("alice", &pk_hex, &sig_hex)
        .await
        .expect("first use accepted");
    // Replay — the same (user_id, sig) pair must now fail because
    // the challenge has been consumed.
    let err = sso
        .verify_response("alice", &pk_hex, &sig_hex)
        .await
        .unwrap_err();
    assert!(
        matches!(err, SchnorrError::Challenge(_)),
        "replay rejected, got {err:?}"
    );
}
