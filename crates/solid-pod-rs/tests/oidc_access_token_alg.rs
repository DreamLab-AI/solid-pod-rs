//! P0-4 part A — `verify_access_token` dispatches on the JWT `alg`
//! header rather than hard-coding HS256.
//!
//! Pre-Sprint-5 the function called
//! `Validation::new(Algorithm::HS256)` unconditionally. This meant:
//!
//! - A real IdP-issued RS256 token could never be verified (so the
//!   code was effectively dead in production).
//! - Worse, the key-type-vs-algorithm confusion that HS256 enables
//!   against asymmetric keys was not even detectable — there was no
//!   dispatch to confuse.
//!
//! These tests lock in:
//!
//! 1. When the server is configured with only a symmetric test key,
//!    an RS256 token MUST be rejected (no cross-alg acceptance).
//! 2. `alg=none` MUST be rejected regardless of configuration.
//! 3. An ES256 token MUST verify when the matching public key is
//!    present in the configured JwkSet.
//!
//! Run with:
//! ```bash
//! cargo test -p solid-pod-rs --features oidc --test oidc_access_token_alg
//! ```

#![cfg(feature = "oidc")]

use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL;
use base64::Engine;
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, EllipticCurve, EllipticCurveKeyParameters,
    EllipticCurveKeyType, Jwk as JwtJwk, JwkSet, KeyAlgorithm, PublicKeyUse,
};
use p256::{
    ecdsa::{signature::Signer, Signature as EcSignature, SigningKey},
};
use serde::{Deserialize, Serialize};
use solid_pod_rs::error::PodError;
use solid_pod_rs::oidc::{
    verify_access_token, AccessTokenVerified, CnfClaim, TokenVerifyKey,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccessTokenClaims {
    iss: String,
    sub: String,
    aud: serde_json::Value,
    exp: u64,
    iat: u64,
    webid: Option<String>,
    client_id: Option<String>,
    cnf: Option<CnfClaim>,
    scope: Option<String>,
}

fn ec_keypair() -> (SigningKey, JwtJwk, String) {
    let seed: [u8; 32] = [
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    ];
    let sk = SigningKey::from_bytes(&seed.into()).unwrap();
    let vk = sk.verifying_key();
    let pt = vk.to_encoded_point(false);
    let raw = pt.as_bytes();
    let x = BASE64_URL.encode(&raw[1..33]);
    let y = BASE64_URL.encode(&raw[33..65]);
    let kid = "test-es256-kid".to_string();
    let jwk = JwtJwk {
        common: CommonParameters {
            public_key_use: Some(PublicKeyUse::Signature),
            key_operations: None,
            key_algorithm: Some(KeyAlgorithm::ES256),
            key_id: Some(kid.clone()),
            x509_url: None,
            x509_chain: None,
            x509_sha1_fingerprint: None,
            x509_sha256_fingerprint: None,
        },
        algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
            key_type: EllipticCurveKeyType::EC,
            curve: EllipticCurve::P256,
            x,
            y,
        }),
    };
    (sk, jwk, kid)
}

fn sign_es256_jwt(sk: &SigningKey, kid: &str, claims: &AccessTokenClaims) -> String {
    let header = serde_json::json!({
        "typ": "JWT",
        "alg": "ES256",
        "kid": kid,
    });
    let h = BASE64_URL.encode(serde_json::to_string(&header).unwrap());
    let b = BASE64_URL.encode(serde_json::to_string(claims).unwrap());
    let si = format!("{h}.{b}");
    let sig: EcSignature = sk.sign(si.as_bytes());
    let s = BASE64_URL.encode(sig.to_bytes());
    format!("{si}.{s}")
}

/// Forge a "JWT" with alg=none and empty signature.
fn forge_alg_none_token(claims: &AccessTokenClaims) -> String {
    let header = serde_json::json!({
        "typ": "JWT",
        "alg": "none",
    });
    let h = BASE64_URL.encode(serde_json::to_string(&header).unwrap());
    let b = BASE64_URL.encode(serde_json::to_string(claims).unwrap());
    format!("{h}.{b}.")
}

/// Build a well-formed RS256-looking JWT without a valid signature.
/// The signature bytes are arbitrary; the point of this test is that
/// the dispatch must REJECT before it even gets to verify, because
/// the configured key is symmetric-only.
fn forge_rs256_lookalike(claims: &AccessTokenClaims) -> String {
    let header = serde_json::json!({
        "typ": "JWT",
        "alg": "RS256",
        "kid": "attacker-kid",
    });
    let h = BASE64_URL.encode(serde_json::to_string(&header).unwrap());
    let b = BASE64_URL.encode(serde_json::to_string(claims).unwrap());
    let s = BASE64_URL.encode([0u8; 256]);
    format!("{h}.{b}.{s}")
}

// ---------------------------------------------------------------------------
// Test 1 — RS256 token rejected when only a symmetric key is configured.
// ---------------------------------------------------------------------------

#[test]
fn oidc_access_token_rs256_rejected_when_hs256_only_configured() {
    let claims = AccessTokenClaims {
        iss: "https://op".into(),
        sub: "https://me.example/profile#me".into(),
        aud: serde_json::json!("solid"),
        exp: 9_999_999_999,
        iat: 1_700_000_000,
        webid: Some("https://me.example/profile#me".into()),
        client_id: Some("c".into()),
        cnf: Some(CnfClaim { jkt: "THUMB".into() }),
        scope: Some("openid".into()),
    };
    let tok = forge_rs256_lookalike(&claims);
    let keyset = TokenVerifyKey::Symmetric(b"test-secret".to_vec());

    let err = verify_access_token(&tok, &keyset, "https://op", "THUMB", 1_700_000_000)
        .expect_err("RS256 token must not be accepted under symmetric-only config");
    match err {
        PodError::Nip98(msg) => {
            assert!(
                msg.to_lowercase().contains("hs256")
                    || msg.to_lowercase().contains("asymmetric")
                    || msg.to_lowercase().contains("not permitted")
                    || msg.to_lowercase().contains("rs256"),
                "error should identify the alg mismatch, got: {msg}",
            );
        }
        other => panic!("unexpected error kind: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Test 2 — alg=none is never accepted, whatever the keyset.
// ---------------------------------------------------------------------------

#[test]
fn oidc_access_token_alg_none_rejected() {
    let claims = AccessTokenClaims {
        iss: "https://op".into(),
        sub: "https://me.example/profile#me".into(),
        aud: serde_json::json!("solid"),
        exp: 9_999_999_999,
        iat: 1_700_000_000,
        webid: Some("https://me.example/profile#me".into()),
        client_id: None,
        cnf: Some(CnfClaim { jkt: "THUMB".into() }),
        scope: None,
    };
    let tok = forge_alg_none_token(&claims);
    // Try both keyset shapes — neither must admit alg=none.
    let sym = TokenVerifyKey::Symmetric(b"x".to_vec());
    assert!(
        verify_access_token(&tok, &sym, "https://op", "THUMB", 1_700_000_000).is_err(),
        "alg=none must fail with symmetric keyset",
    );

    let (_sk, jwk, _kid) = ec_keypair();
    let set = JwkSet { keys: vec![jwk] };
    let asym = TokenVerifyKey::Asymmetric(set);
    assert!(
        verify_access_token(&tok, &asym, "https://op", "THUMB", 1_700_000_000).is_err(),
        "alg=none must fail with asymmetric keyset",
    );
}

// ---------------------------------------------------------------------------
// Test 3 — ES256 happy path via JwkSet.
// ---------------------------------------------------------------------------

#[test]
fn oidc_access_token_dispatches_es256_against_jwks() {
    let (sk, jwk, kid) = ec_keypair();
    let set = JwkSet { keys: vec![jwk] };
    let keyset = TokenVerifyKey::Asymmetric(set);

    let claims = AccessTokenClaims {
        iss: "https://op".into(),
        sub: "https://me.example/profile#me".into(),
        aud: serde_json::json!("solid"),
        exp: 9_999_999_999,
        iat: 1_700_000_000,
        webid: Some("https://me.example/profile#me".into()),
        client_id: Some("c".into()),
        cnf: Some(CnfClaim { jkt: "THUMB".into() }),
        scope: Some("openid webid".into()),
    };
    let tok = sign_es256_jwt(&sk, &kid, &claims);

    let v: AccessTokenVerified =
        verify_access_token(&tok, &keyset, "https://op", "THUMB", 1_700_000_000)
            .expect("ES256 token with matching JWK must verify");
    assert_eq!(v.webid, "https://me.example/profile#me");
    assert_eq!(v.jkt, "THUMB");
    assert_eq!(v.client_id.as_deref(), Some("c"));
}
