//! P0-1 — DPoP proof signature verification.
//!
//! Pre-Sprint-5 `verify_dpop_proof_core` decoded the JWT body directly
//! without ever verifying the JWS signature. Any attacker who observed
//! a DPoP-bearing request could rewrite the `jti` (or any claim) and
//! resubmit it, because the server never checked that the bytes were
//! signed by the `jwk` they claimed to come from.
//!
//! These tests lock in the required behaviour:
//!
//! 1. A proof whose signature does not match `header.jwk` MUST be
//!    rejected.
//! 2. `alg=none` MUST NEVER authenticate — no exceptions.
//! 3. A valid ES256 proof (real signature) MUST authenticate.
//!
//! Run with:
//! ```bash
//! cargo test -p solid-pod-rs --features oidc,dpop-replay-cache --test oidc_dpop_signature
//! ```

#![cfg(feature = "oidc")]

use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL;
use base64::Engine;
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    pkcs8::EncodePrivateKey,
};
use solid_pod_rs::error::PodError;
use solid_pod_rs::oidc::{DpopClaims, Jwk};

/// Produce a real ES256 keypair + matching DPoP `jwk` header fragment.
///
/// Returns (SigningKey, Jwk-for-header).
fn ec_p256_jwk_keypair() -> (SigningKey, Jwk) {
    // Deterministic key for reproducible failure output. A fixed 32-byte
    // scalar is fine — we are not using this for production secrecy.
    let seed: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    let signing_key = SigningKey::from_bytes(&seed.into()).expect("valid scalar");
    let verifying = signing_key.verifying_key();
    let point = verifying.to_encoded_point(false);
    // Uncompressed: 0x04 || x(32) || y(32). Skip the 0x04 tag.
    let bytes = point.as_bytes();
    assert_eq!(bytes[0], 0x04);
    let x = BASE64_URL.encode(&bytes[1..33]);
    let y = BASE64_URL.encode(&bytes[33..65]);
    let jwk = Jwk {
        kty: "EC".into(),
        alg: Some("ES256".into()),
        kid: None,
        use_: None,
        crv: Some("P-256".into()),
        x: Some(x),
        y: Some(y),
        n: None,
        e: None,
        k: None,
    };
    (signing_key, jwk)
}

/// Build the header+body parts of a DPoP JWT with ES256 alg and
/// the provided jwk header (already serialisable).
fn dpop_parts(jwk: &Jwk, alg: &str, claims: &DpopClaims) -> (String, String, String) {
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": alg,
        "jwk": jwk,
    });
    let header_b64 = BASE64_URL.encode(serde_json::to_string(&header).unwrap());
    let body_b64 = BASE64_URL.encode(serde_json::to_string(claims).unwrap());
    let signing_input = format!("{header_b64}.{body_b64}");
    (header_b64, body_b64, signing_input)
}

fn sign_es256(signing_key: &SigningKey, signing_input: &str) -> String {
    let sig: Signature = signing_key.sign(signing_input.as_bytes());
    let bytes = sig.to_bytes();
    BASE64_URL.encode(bytes)
}

// ---------------------------------------------------------------------------
// Test 1 — tampered signature rejected.
// ---------------------------------------------------------------------------

#[cfg(feature = "dpop-replay-cache")]
#[tokio::test]
async fn oidc_dpop_rejects_unsigned_proof() {
    let (_sk, jwk) = ec_p256_jwk_keypair();
    let now = 1_700_000_000u64;
    let claims = DpopClaims {
        htu: "https://pod.example/resource".into(),
        htm: "GET".into(),
        iat: now,
        jti: "attacker-tampered".into(),
        ath: None,
    };
    let (h, b, _) = dpop_parts(&jwk, "ES256", &claims);
    // Signature is the RIGHT shape (64 bytes base64url) but is all
    // zeros — cryptographically invalid for any real key.
    let bad_sig = BASE64_URL.encode([0u8; 64]);
    let proof = format!("{h}.{b}.{bad_sig}");

    let err = solid_pod_rs::oidc::verify_dpop_proof(
        &proof,
        "https://pod.example/resource",
        "GET",
        now,
        60,
        None,
    )
    .await
    .expect_err("unsigned/tampered DPoP proof MUST be rejected");
    match err {
        PodError::Nip98(msg) => {
            let low = msg.to_lowercase();
            assert!(
                low.contains("signature") || low.contains("sig"),
                "error must identify the signature failure, got: {msg}",
            );
        }
        other => panic!("unexpected error kind: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Test 2 — alg=none never authenticates.
// ---------------------------------------------------------------------------

#[cfg(feature = "dpop-replay-cache")]
#[tokio::test]
async fn oidc_dpop_alg_none_is_rejected() {
    let (_sk, jwk) = ec_p256_jwk_keypair();
    let now = 1_700_000_000u64;
    let claims = DpopClaims {
        htu: "https://pod.example/resource".into(),
        htm: "GET".into(),
        iat: now,
        jti: "alg-none-attack".into(),
        ath: None,
    };
    let (h, b, _) = dpop_parts(&jwk, "none", &claims);
    let proof = format!("{h}.{b}.");

    let err = solid_pod_rs::oidc::verify_dpop_proof(
        &proof,
        "https://pod.example/resource",
        "GET",
        now,
        60,
        None,
    )
    .await
    .expect_err("alg=none DPoP proof MUST be rejected");
    assert!(matches!(err, PodError::Nip98(_)));
}

// ---------------------------------------------------------------------------
// Test 3 — happy path: real ES256 signature verifies.
// ---------------------------------------------------------------------------

#[cfg(feature = "dpop-replay-cache")]
#[tokio::test]
async fn oidc_dpop_es256_valid_proof_authenticates() {
    let (sk, jwk) = ec_p256_jwk_keypair();
    let expected_jkt = jwk.thumbprint().expect("thumbprint");
    let now = 1_700_000_000u64;
    let claims = DpopClaims {
        htu: "https://pod.example/resource".into(),
        htm: "GET".into(),
        iat: now,
        jti: "valid-es256-0001".into(),
        ath: None,
    };
    let (h, b, signing_input) = dpop_parts(&jwk, "ES256", &claims);
    let sig_b64 = sign_es256(&sk, &signing_input);
    let proof = format!("{h}.{b}.{sig_b64}");

    let verified = solid_pod_rs::oidc::verify_dpop_proof(
        &proof,
        "https://pod.example/resource",
        "GET",
        now,
        60,
        None,
    )
    .await
    .expect("valid ES256 DPoP proof must authenticate");
    assert_eq!(verified.jkt, expected_jkt);
    assert_eq!(verified.htm, "GET");
    assert_eq!(verified.jti, "valid-es256-0001");
}

// ---------------------------------------------------------------------------
// Test 4 — HS256 with an asymmetric JWK is rejected (alg confusion).
// ---------------------------------------------------------------------------

#[cfg(feature = "dpop-replay-cache")]
#[tokio::test]
async fn oidc_dpop_rejects_hs256_with_ec_jwk() {
    // Classic alg-confusion: attacker takes a genuine EC public key,
    // advertises `alg=HS256` on the header, and signs the proof with
    // HMAC using the EC key's public bytes as the shared secret. If
    // the verifier switches on `alg` without cross-checking the JWK's
    // kty, it will treat the public key as an HMAC secret and accept.
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let (_sk, jwk) = ec_p256_jwk_keypair();
    let now = 1_700_000_000u64;
    let claims = DpopClaims {
        htu: "https://pod.example/resource".into(),
        htm: "GET".into(),
        iat: now,
        jti: "alg-confusion-attack".into(),
        ath: None,
    };
    let (h, b, signing_input) = dpop_parts(&jwk, "HS256", &claims);

    // Sign using the JWK's `x` coordinate as a fake shared secret —
    // that is what an alg-confusion attacker would do.
    let x_bytes = BASE64_URL
        .decode(jwk.x.as_deref().expect("jwk.x"))
        .expect("x decodes");
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&x_bytes).expect("hmac key");
    mac.update(signing_input.as_bytes());
    let sig = BASE64_URL.encode(mac.finalize().into_bytes());
    let proof = format!("{h}.{b}.{sig}");

    let err = solid_pod_rs::oidc::verify_dpop_proof(
        &proof,
        "https://pod.example/resource",
        "GET",
        now,
        60,
        None,
    )
    .await
    .expect_err("HS256 + EC jwk MUST be rejected");
    match err {
        PodError::Nip98(msg) => {
            let low = msg.to_lowercase();
            assert!(
                low.contains("hs")
                    || low.contains("permitted")
                    || low.contains("symmetric")
                    || low.contains("alg"),
                "error must call out the alg-confusion rejection, got: {msg}",
            );
        }
        other => panic!("unexpected error kind: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Test 5 — happy path: real Ed25519 (EdDSA) signature verifies.
// ---------------------------------------------------------------------------

#[cfg(all(feature = "dpop-replay-cache", feature = "webhook-signing"))]
#[tokio::test]
async fn oidc_dpop_eddsa_valid_proof_authenticates() {
    use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey};
    use rand::rngs::OsRng;

    let ed_sk = EdSigningKey::generate(&mut OsRng);
    let ed_pk = ed_sk.verifying_key();
    let jwk = Jwk {
        kty: "OKP".into(),
        alg: Some("EdDSA".into()),
        kid: None,
        use_: None,
        crv: Some("Ed25519".into()),
        x: Some(BASE64_URL.encode(ed_pk.to_bytes())),
        y: None,
        n: None,
        e: None,
        k: None,
    };
    let expected_jkt = jwk.thumbprint().expect("thumbprint");
    let now = 1_700_000_000u64;
    let claims = DpopClaims {
        htu: "https://pod.example/resource".into(),
        htm: "POST".into(),
        iat: now,
        jti: "valid-eddsa-0001".into(),
        ath: None,
    };
    let (h, b, signing_input) = dpop_parts(&jwk, "EdDSA", &claims);
    let sig = ed_sk.sign(signing_input.as_bytes());
    let sig_b64 = BASE64_URL.encode(sig.to_bytes());
    let proof = format!("{h}.{b}.{sig_b64}");

    let verified = solid_pod_rs::oidc::verify_dpop_proof(
        &proof,
        "https://pod.example/resource",
        "POST",
        now,
        60,
        None,
    )
    .await
    .expect("valid EdDSA DPoP proof must authenticate");
    assert_eq!(verified.jkt, expected_jkt);
    assert_eq!(verified.htm, "POST");
    assert_eq!(verified.jti, "valid-eddsa-0001");
}

// ---------------------------------------------------------------------------
// Test 6 — ath binding enforced against access-token hash.
// ---------------------------------------------------------------------------

#[cfg(feature = "dpop-replay-cache")]
#[tokio::test]
async fn oidc_dpop_ath_binding_enforced() {
    use sha2::{Digest, Sha256};

    let (sk, jwk) = ec_p256_jwk_keypair();
    let now = 1_700_000_000u64;

    // Real access token bytes + the hash the RFC requires.
    let access_token = "opaque-access-token-payload";
    let ath_hash = BASE64_URL.encode(Sha256::digest(access_token.as_bytes()));

    let good_claims = DpopClaims {
        htu: "https://pod.example/resource".into(),
        htm: "GET".into(),
        iat: now,
        jti: "ath-ok-0001".into(),
        ath: Some(ath_hash.clone()),
    };
    let (h, b, signing_input) = dpop_parts(&jwk, "ES256", &good_claims);
    let sig_b64 = sign_es256(&sk, &signing_input);
    let proof = format!("{h}.{b}.{sig_b64}");

    // 1. Correct hash passes.
    let verified = solid_pod_rs::oidc::verify_dpop_proof_with_ath(
        &proof,
        "https://pod.example/resource",
        "GET",
        now,
        60,
        Some(&ath_hash),
        None,
    )
    .await
    .expect("matching ath must authenticate");
    assert_eq!(verified.ath.as_deref(), Some(ath_hash.as_str()));

    // 2. Wrong hash fails.
    let err = solid_pod_rs::oidc::verify_dpop_proof_with_ath(
        &proof,
        "https://pod.example/resource",
        "GET",
        now,
        60,
        Some("DEADBEEF-not-the-real-hash"),
        None,
    )
    .await
    .expect_err("ath mismatch must reject");
    assert!(matches!(err, PodError::Nip98(_)));

    // 3. Missing `ath` on proof but required by caller fails.
    let bare_claims = DpopClaims {
        htu: "https://pod.example/resource".into(),
        htm: "GET".into(),
        iat: now,
        jti: "ath-missing-0001".into(),
        ath: None,
    };
    let (h2, b2, si2) = dpop_parts(&jwk, "ES256", &bare_claims);
    let sig2 = sign_es256(&sk, &si2);
    let proof2 = format!("{h2}.{b2}.{sig2}");
    let err2 = solid_pod_rs::oidc::verify_dpop_proof_with_ath(
        &proof2,
        "https://pod.example/resource",
        "GET",
        now,
        60,
        Some(&ath_hash),
        None,
    )
    .await
    .expect_err("missing ath when expected must reject");
    assert!(matches!(err2, PodError::Nip98(_)));
}

// Silence unused-dep warning in the rare case where neither async test
// pulls these symbols in during a cross-feature build.
#[allow(dead_code)]
fn _force_link_pkcs8() -> Option<()> {
    let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let _pem = sk
        .to_pkcs8_pem(pkcs8::LineEnding::LF)
        .ok()?
        .to_string();
    Some(())
}
