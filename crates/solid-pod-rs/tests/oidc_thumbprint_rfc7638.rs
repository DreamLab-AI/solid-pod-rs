//! P0-4 part B — canonical RFC 7638 JWK thumbprint.
//!
//! Pre-Sprint-5 the `Jwk::thumbprint` implementation hand-rolled a
//! `format!()` JSON literal. That produced output that LOOKED canonical
//! but was not guaranteed to match RFC 7638 §3.1 — every caller that
//! round-tripped the JWK through serde got a different thumbprint
//! depending on field order. This test suite locks the implementation
//! to the real RFC canonicalisation.
//!
//! Run with:
//! ```bash
//! cargo test -p solid-pod-rs --features oidc --test oidc_thumbprint_rfc7638
//! ```

#![cfg(feature = "oidc")]

use solid_pod_rs::oidc::Jwk;

/// RFC 7638 §3.1 worked example. The RSA JWK given in the RFC produces
/// exactly this thumbprint; any deviation means the canonicalisation
/// is wrong.
const RFC7638_EXPECTED_THUMBPRINT: &str =
    "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

/// RFC 7638 §3.1 vector — the `n` parameter is base64url-encoded.
const RFC7638_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

#[test]
fn oidc_jwk_thumbprint_matches_rfc7638_test_vector() {
    // Note: RFC 7638 explicitly ignores `alg`/`kid` for the
    // thumbprint computation — only the required members go in.
    let jwk = Jwk {
        kty: "RSA".into(),
        alg: Some("RS256".into()),
        kid: Some("2011-04-29".into()),
        use_: None,
        crv: None,
        x: None,
        y: None,
        n: Some(RFC7638_N.into()),
        e: Some("AQAB".into()),
        k: None,
    };
    let tp = jwk.thumbprint().expect("RSA thumbprint must succeed");
    assert_eq!(
        tp, RFC7638_EXPECTED_THUMBPRINT,
        "RFC 7638 §3.1 RSA thumbprint mismatch — canonicalisation is wrong",
    );
}

#[test]
fn oidc_jwk_thumbprint_field_order_invariant() {
    // Same logical key, two different field-population orders on our
    // struct. Because RFC 7638 requires sorted canonical JSON, the
    // thumbprint MUST be identical regardless of source ordering.
    let a = Jwk {
        kty: "RSA".into(),
        alg: None,
        kid: None,
        use_: None,
        crv: None,
        x: None,
        y: None,
        n: Some(RFC7638_N.into()),
        e: Some("AQAB".into()),
        k: None,
    };
    // Build "b" from a round-trip through JSON with keys deliberately
    // in a different order. If the canonicalisation naively formatted
    // fields in struct order, the wire-JSON order of the SOURCE would
    // leak into the thumbprint; RFC 7638 forbids this.
    let json_shuffled = serde_json::json!({
        "n": RFC7638_N,
        "kty": "RSA",
        "e": "AQAB",
    });
    let b: Jwk = serde_json::from_value(json_shuffled).expect("shuffled JWK parse");
    assert_eq!(
        a.thumbprint().unwrap(),
        b.thumbprint().unwrap(),
        "thumbprint must be independent of source field order",
    );
}

#[test]
fn oidc_jwk_thumbprint_ec_is_canonical() {
    // EC canonical form per RFC 7638 §3.2 is {"crv":...,"kty":"EC","x":...,"y":...}.
    // This locks the EC path separately from the RSA path above.
    let jwk = Jwk {
        kty: "EC".into(),
        alg: None,
        kid: None,
        use_: None,
        crv: Some("P-256".into()),
        x: Some("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU".into()),
        y: Some("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0".into()),
        n: None,
        e: None,
        k: None,
    };
    let tp = jwk.thumbprint().expect("EC thumbprint must succeed");
    // Deterministic — we re-computed this offline using the canonical
    // JSON form {"crv":"P-256","kty":"EC","x":"...","y":"..."}.
    // If the implementation deviates (extra fields, wrong order, or
    // pretty-printing whitespace), this assertion catches it.
    let expected = {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
        use base64::Engine;
        use sha2::{Digest, Sha256};
        let canonical = r#"{"crv":"P-256","kty":"EC","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;
        B64.encode(Sha256::digest(canonical.as_bytes()))
    };
    assert_eq!(tp, expected);
}
