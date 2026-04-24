//! Self-signed JWT verification tests with real keypairs.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;

use solid_pod_rs_didkey::{
    encode_did_key, verify_self_signed_jwt, DidKeyError, DidKeyPubkey,
};

use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

fn ed25519_from_seed(seed: u64) -> Ed25519SigningKey {
    let mut rng = StdRng::seed_from_u64(seed);
    let secret: [u8; 32] = rng.gen();
    Ed25519SigningKey::from_bytes(&secret)
}

fn b64(s: impl AsRef<[u8]>) -> String {
    B64URL.encode(s)
}

struct Jwt {
    compact: String,
    did: String,
}

fn build_ed25519_jwt(htu: &str, htm: &str, iat: u64, tamper_sig: bool) -> Jwt {
    let sk = ed25519_from_seed(1);
    let pk_bytes = sk.verifying_key().to_bytes();
    let pk = DidKeyPubkey::Ed25519(pk_bytes);
    let did = encode_did_key(&pk);
    let kid = format!("{did}#{}", did.trim_start_matches("did:key:"));

    let header = serde_json::json!({ "alg": "EdDSA", "typ": "JWT", "kid": kid });
    let payload = serde_json::json!({
        "htu": htu, "htm": htm, "iat": iat,
        "sub": "https://me.example/profile#me",
    });

    let h_b64 = b64(serde_json::to_vec(&header).unwrap());
    let p_b64 = b64(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{h_b64}.{p_b64}");
    let sig = sk.sign(signing_input.as_bytes());
    let mut sig_bytes = sig.to_bytes().to_vec();
    if tamper_sig {
        sig_bytes[0] ^= 0xff;
    }
    let s_b64 = b64(sig_bytes);
    Jwt {
        compact: format!("{signing_input}.{s_b64}"),
        did,
    }
}

fn build_p256_jwt(htu: &str, htm: &str, iat: u64) -> Jwt {
    let mut rng = StdRng::seed_from_u64(2);
    let sk = P256SigningKey::random(&mut rng);
    let vk = *sk.verifying_key();
    // `to_sec1_bytes()` defaults to uncompressed (65 bytes). We need
    // the compressed form for did:key (33 bytes, 0x02/0x03 prefix).
    let sec1 = vk.to_encoded_point(true).as_bytes().to_vec();
    let pk = DidKeyPubkey::P256(sec1);
    let did = encode_did_key(&pk);

    let header = serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": did.clone() });
    let payload = serde_json::json!({
        "htu": htu, "htm": htm, "iat": iat,
    });
    let h_b64 = b64(serde_json::to_vec(&header).unwrap());
    let p_b64 = b64(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{h_b64}.{p_b64}");
    let sig: P256Signature = sk.sign(signing_input.as_bytes());
    let sig_bytes = sig.to_bytes().to_vec();
    let s_b64 = b64(sig_bytes);
    Jwt {
        compact: format!("{signing_input}.{s_b64}"),
        did,
    }
}

fn build_ed25519_jwt_with_embedded_jwk(htu: &str, htm: &str, iat: u64) -> Jwt {
    let sk = ed25519_from_seed(3);
    let pk_bytes = sk.verifying_key().to_bytes();
    let pk = DidKeyPubkey::Ed25519(pk_bytes);
    let did = encode_did_key(&pk);

    let jwk = serde_json::json!({
        "kty": "OKP", "crv": "Ed25519", "x": B64URL.encode(pk_bytes),
    });
    let header = serde_json::json!({ "alg": "EdDSA", "typ": "JWT", "jwk": jwk });
    let payload = serde_json::json!({ "htu": htu, "htm": htm, "iat": iat });

    let h_b64 = b64(serde_json::to_vec(&header).unwrap());
    let p_b64 = b64(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{h_b64}.{p_b64}");
    let sig = sk.sign(signing_input.as_bytes());
    let s_b64 = b64(sig.to_bytes());
    Jwt {
        compact: format!("{signing_input}.{s_b64}"),
        did,
    }
}

#[test]
fn verify_valid_ed25519_self_signed_jwt() {
    let now = 1_700_000_000u64;
    let jwt = build_ed25519_jwt("https://pod.example/r", "POST", now, false);
    let v = verify_self_signed_jwt(&jwt.compact, "https://pod.example/r", "POST", now, 60).unwrap();
    assert_eq!(v.did, jwt.did);
    assert_eq!(v.htm, "POST");
    assert_eq!(v.iat, now);
}

#[test]
fn verify_valid_p256_self_signed_jwt() {
    let now = 1_700_000_000u64;
    let jwt = build_p256_jwt("https://pod.example/r", "GET", now);
    let v = verify_self_signed_jwt(&jwt.compact, "https://pod.example/r", "GET", now, 60).unwrap();
    assert_eq!(v.did, jwt.did);
}

#[test]
fn verify_ed25519_with_embedded_jwk() {
    let now = 1_700_000_000u64;
    let jwt = build_ed25519_jwt_with_embedded_jwk("https://pod.example/r", "GET", now);
    let v = verify_self_signed_jwt(&jwt.compact, "https://pod.example/r", "GET", now, 60).unwrap();
    assert_eq!(v.did, jwt.did);
    // verification_method equals the did when derived from jwk.
    assert_eq!(v.verification_method, jwt.did);
}

#[test]
fn reject_tampered_ed25519_jwt() {
    let now = 1_700_000_000u64;
    let jwt = build_ed25519_jwt("https://pod.example/r", "GET", now, true);
    let err = verify_self_signed_jwt(&jwt.compact, "https://pod.example/r", "GET", now, 60)
        .unwrap_err();
    assert!(
        matches!(err, DidKeyError::BadSignature(_)),
        "got {err:?}"
    );
}

#[test]
fn reject_wrong_htu() {
    let now = 1_700_000_000u64;
    let jwt = build_ed25519_jwt("https://pod.example/r", "GET", now, false);
    let err = verify_self_signed_jwt(&jwt.compact, "https://evil.example/r", "GET", now, 60)
        .unwrap_err();
    assert!(matches!(err, DidKeyError::InvalidClaims(_)));
}

#[test]
fn reject_wrong_htm() {
    let now = 1_700_000_000u64;
    let jwt = build_ed25519_jwt("https://pod.example/r", "GET", now, false);
    let err = verify_self_signed_jwt(&jwt.compact, "https://pod.example/r", "POST", now, 60)
        .unwrap_err();
    assert!(matches!(err, DidKeyError::InvalidClaims(_)));
}

#[test]
fn reject_expired_iat() {
    // iat 10 minutes ago, skew only 60s.
    let now = 1_700_000_000u64;
    let jwt = build_ed25519_jwt("https://pod.example/r", "GET", now - 600, false);
    let err = verify_self_signed_jwt(&jwt.compact, "https://pod.example/r", "GET", now, 60)
        .unwrap_err();
    assert!(matches!(err, DidKeyError::InvalidClaims(_)));
}

#[test]
fn reject_alg_mismatch_between_header_and_did() {
    // Hand-craft a JWT whose header claims ES256 but the kid is an
    // Ed25519 did:key. The alg-confusion gate must refuse.
    let sk = ed25519_from_seed(9);
    let pk = DidKeyPubkey::Ed25519(sk.verifying_key().to_bytes());
    let did = encode_did_key(&pk);

    let header = serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": did });
    let payload =
        serde_json::json!({ "htu": "https://pod.example/r", "htm": "GET", "iat": 0u64 });
    let h_b64 = b64(serde_json::to_vec(&header).unwrap());
    let p_b64 = b64(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{h_b64}.{p_b64}");
    let sig = sk.sign(signing_input.as_bytes());
    let s_b64 = b64(sig.to_bytes());
    let jwt = format!("{signing_input}.{s_b64}");

    let err = verify_self_signed_jwt(&jwt, "https://pod.example/r", "GET", 0, 60).unwrap_err();
    assert!(matches!(err, DidKeyError::InvalidHeader(_)), "got {err:?}");
}

#[test]
fn reject_malformed_jwt_structure() {
    let err = verify_self_signed_jwt("not.a.jwt.toomany", "https://p", "GET", 0, 60).unwrap_err();
    assert!(matches!(err, DidKeyError::MalformedJwt(_)));
}
