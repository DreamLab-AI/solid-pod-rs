//! Sprint 6 C — RFC 9421 HTTP Message Signatures for outgoing
//! webhook deliveries. Red-first TDD coverage of
//! [`solid_pod_rs::notifications::signing`].
//!
//! The tests exercise the signer / verifier pair directly so they run
//! without a network. Integration with [`WebhookChannelManager`] is
//! covered in `tests/webhook_retry.rs`.

#![cfg(feature = "webhook-signing")]

use ed25519_dalek::SigningKey;

use solid_pod_rs::notifications::signing::{
    sign_request, verify_signed_request, SignatureError, SignerConfig,
};

fn key_from_seed(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// A request signed with key A and verified with the matching public
/// key must validate.
#[test]
fn webhook_rfc9421_signature_verifies() {
    let sk_a = key_from_seed(1);
    let vk_a = sk_a.verifying_key();
    let cfg = SignerConfig {
        keyid: "chan-a".into(),
        key: sk_a,
    };
    let body = br#"{"@context":"https://www.w3.org/ns/activitystreams","type":"Create"}"#;
    let signed = sign_request(
        &cfg,
        "POST",
        "https://receiver.example/hook",
        "application/ld+json",
        body,
        "urn:uuid:11111111-1111-1111-1111-111111111111",
        1_713_600_000,
    );

    // Signature header carries the expected RFC 9421 shape.
    let sig_input = signed
        .headers
        .iter()
        .find(|(n, _)| n == "signature-input")
        .expect("signature-input header must be present")
        .1
        .as_str();
    assert!(sig_input.starts_with("sig1=("));
    assert!(sig_input.contains("alg=\"ed25519\""));
    assert!(sig_input.contains("keyid=\"chan-a\""));

    verify_signed_request(
        &vk_a,
        "chan-a",
        &signed.headers,
        "POST",
        "https://receiver.example/hook",
        body,
    )
    .expect("signed request must verify under its own key");
}

/// Mutating the body after signing must be detected — either by the
/// `Content-Digest` guard or the signature itself.
#[test]
fn webhook_rfc9421_signature_tamper_detected() {
    let sk = key_from_seed(2);
    let vk = sk.verifying_key();
    let cfg = SignerConfig {
        keyid: "chan-b".into(),
        key: sk,
    };
    let original = b"{\"type\":\"Create\"}";
    let signed = sign_request(
        &cfg,
        "POST",
        "https://receiver.example/hook",
        "application/ld+json",
        original,
        "urn:uuid:22222222-2222-2222-2222-222222222222",
        1_713_600_100,
    );
    // Tamper: flip the last byte.
    let mut tampered = original.to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;

    let err = verify_signed_request(
        &vk,
        "chan-b",
        &signed.headers,
        "POST",
        "https://receiver.example/hook",
        &tampered,
    )
    .expect_err("tampered body must fail verification");
    assert!(
        matches!(err, SignatureError::DigestMismatch | SignatureError::BadSignature),
        "expected DigestMismatch or BadSignature, got {:?}",
        err
    );
}

/// The `Content-Digest` header must be present in the RFC 9530 form
/// `sha-256=:<base64>:` on every signed request.
#[test]
fn webhook_rfc9421_content_digest_present() {
    let sk = key_from_seed(3);
    let cfg = SignerConfig {
        keyid: "chan-c".into(),
        key: sk,
    };
    let signed = sign_request(
        &cfg,
        "POST",
        "https://receiver.example/hook",
        "application/ld+json",
        b"{}",
        "urn:uuid:33333333-3333-3333-3333-333333333333",
        1_713_600_200,
    );
    let digest = signed
        .headers
        .iter()
        .find(|(n, _)| n == "content-digest")
        .expect("content-digest header must be present")
        .1
        .as_str();
    assert!(
        digest.starts_with("sha-256=:") && digest.ends_with(':'),
        "expected RFC 9530 sha-256=:…: form, got {digest}"
    );
}
