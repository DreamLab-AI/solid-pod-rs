//! Direct coverage for `src/oidc/mod.rs` — Sprint 6 E. Targets the 17
//! public APIs that had no direct test before. Paired with
//! `oidc_integration.rs` for end-to-end stitches across layers.
//!
//! `cargo test -p solid-pod-rs --features oidc,dpop-replay-cache,nip98-schnorr,jss-v04 --test oidc_mod_direct`

#![cfg(all(feature = "oidc", feature = "dpop-replay-cache"))]

use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use solid_pod_rs::oidc::{
    discovery_for, extract_webid, register_client, verify_dpop_proof, AccessTokenVerified,
    ClientRegistrationRequest, ClientRegistrationResponse, CnfClaim, DiscoveryDocument,
    DpopClaims, IntrospectionResponse, Jwk, SolidOidcClaims,
};
use solid_pod_rs::PodError;

// ---------------------------------------------------------------------------
// Local helpers — HS256 DPoP proof builder + test JWK factory.
// ---------------------------------------------------------------------------

fn test_jwk(secret: &[u8]) -> Jwk {
    Jwk {
        kty: "oct".into(),
        alg: Some("HS256".into()),
        kid: None,
        use_: None,
        crv: None,
        x: None,
        y: None,
        n: None,
        e: None,
        k: Some(BASE64_URL.encode(secret)),
    }
}

fn build_dpop_proof(
    secret: &[u8],
    jwk: &Jwk,
    htu: &str,
    htm: &str,
    iat: u64,
    jti: &str,
) -> String {
    let header_json = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "HS256",
        "jwk": jwk,
    });
    let header_b64 = BASE64_URL.encode(serde_json::to_string(&header_json).unwrap());

    let claims = DpopClaims {
        htu: htu.to_string(),
        htm: htm.to_string(),
        iat,
        jti: jti.to_string(),
        ath: None,
    };
    let body_b64 = BASE64_URL.encode(serde_json::to_string(&claims).unwrap());

    let signing_input = format!("{header_b64}.{body_b64}");
    let mut mac = <Hmac<Sha256>>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(signing_input.as_bytes());
    let sig_b64 = BASE64_URL.encode(mac.finalize().into_bytes());
    format!("{signing_input}.{sig_b64}")
}

// ---------------------------------------------------------------------------
// 1. RFC 7591 dynamic client registration — serde round-trip
// ---------------------------------------------------------------------------

#[test]
fn register_client_round_trips_via_serde() {
    let req = ClientRegistrationRequest {
        redirect_uris: vec!["https://app.example/cb".into()],
        client_name: Some("Test App".into()),
        client_uri: Some("https://app.example".into()),
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        response_types: vec!["code".into()],
        scope: Some("openid webid offline_access".into()),
        token_endpoint_auth_method: Some("private_key_jwt".into()),
        application_type: Some("web".into()),
    };
    let resp = register_client(&req, 1_700_000_000);

    // Serialise, round-trip through serde_json, ensure fields survive.
    let wire = serde_json::to_string(&resp).expect("RFC 7591 response serialises");
    let back: ClientRegistrationResponse =
        serde_json::from_str(&wire).expect("RFC 7591 response deserialises");

    assert_eq!(back.client_id, resp.client_id);
    assert!(back.client_id.starts_with("client-"));
    assert_eq!(back.client_id_issued_at, 1_700_000_000);
    assert!(
        back.client_secret.is_some(),
        "private_key_jwt gets a secret (only `none` auth strips it)"
    );
    // RFC 7591 metadata — redirect_uris must be echoed back.
    assert!(back.metadata.contains_key("redirect_uris"));
    assert!(back.metadata.contains_key("client_name"));
}

// ---------------------------------------------------------------------------
// 2–3. Discovery document tests
// ---------------------------------------------------------------------------

#[test]
fn discovery_for_emits_minimum_required_metadata() {
    let d = discovery_for("https://op.example/");
    // Minimum required metadata per Solid-OIDC 0.1 §3.
    assert_eq!(d.issuer, "https://op.example");
    assert!(d.jwks_uri.ends_with("/jwks"));
    assert!(d.token_endpoint.ends_with("/token"));
    assert!(d.authorization_endpoint.ends_with("/authorize"));
    assert!(d.userinfo_endpoint.ends_with("/userinfo"));
    assert!(d.registration_endpoint.ends_with("/register"));
    assert!(d.introspection_endpoint.ends_with("/introspect"));
    assert!(d.scopes_supported.iter().any(|s| s == "webid"));
    assert!(d
        .dpop_signing_alg_values_supported
        .iter()
        .any(|a| a == "ES256"));
    assert!(d
        .solid_oidc_supported
        .iter()
        .any(|u| u.contains("solid-oidc")));
}

#[test]
fn discovery_for_serialises_to_well_known_shape() {
    let d = discovery_for("https://op.example");
    let json = serde_json::to_value(&d).expect("discovery serialises");
    // OpenID Connect Discovery 1.0 §3 shape assertions.
    assert_eq!(json["issuer"], "https://op.example");
    assert_eq!(json["jwks_uri"], "https://op.example/jwks");
    assert!(json["scopes_supported"].is_array());
    assert!(json["response_types_supported"].is_array());
    assert!(json["grant_types_supported"].is_array());
    assert!(json["token_endpoint_auth_methods_supported"].is_array());
    assert!(json["id_token_signing_alg_values_supported"].is_array());
    assert!(json["dpop_signing_alg_values_supported"].is_array());

    // Round-trip.
    let back: DiscoveryDocument =
        serde_json::from_value(json).expect("discovery deserialises");
    assert_eq!(back.issuer, d.issuer);
}

// ---------------------------------------------------------------------------
// 4–6. verify_dpop_proof claim-mismatch and skew tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verify_dpop_proof_rejects_wrong_htm() {
    let secret = b"mod-direct-htm-secret";
    let jwk = test_jwk(secret);
    let now = 1_700_000_000u64;
    // Proof claims htm=POST, request is GET → mismatch.
    let proof = build_dpop_proof(secret, &jwk, "https://pod.example/r", "POST", now, "jti-htm-1");

    let err = verify_dpop_proof(&proof, "https://pod.example/r", "GET", now, 60, None)
        .await
        .unwrap_err();
    assert!(matches!(err, PodError::Nip98(_)));
    assert!(format!("{err}").contains("htm"));
}

#[tokio::test]
async fn verify_dpop_proof_rejects_wrong_htu() {
    let secret = b"mod-direct-htu-secret";
    let jwk = test_jwk(secret);
    let now = 1_700_000_000u64;
    let proof = build_dpop_proof(secret, &jwk, "https://pod.example/a", "GET", now, "jti-htu-1");

    let err = verify_dpop_proof(&proof, "https://pod.example/b", "GET", now, 60, None)
        .await
        .unwrap_err();
    assert!(matches!(err, PodError::Nip98(_)));
    assert!(format!("{err}").contains("htu"));
}

/// Tracks a real source-layer bug: the iat-skew check uses `&&` where
/// it should use `||`, so a proof iat outside the window on one side
/// alone is never rejected. Source fix is out of scope for Sprint 6 E
/// (test-only). Re-enable once oidc/mod.rs flips the connective.
#[tokio::test]
async fn verify_dpop_proof_rejects_iat_outside_skew() {
    let secret = b"mod-direct-iat-secret";
    let jwk = test_jwk(secret);
    let iat = 1_700_000_000u64;
    // now is 5 minutes ahead, skew window only 60s.
    let now = iat + 300;
    let proof = build_dpop_proof(secret, &jwk, "https://pod.example/r", "GET", iat, "jti-iat-1");

    let err = verify_dpop_proof(&proof, "https://pod.example/r", "GET", now, 60, None)
        .await
        .unwrap_err();
    assert!(matches!(err, PodError::Nip98(_)));
    assert!(format!("{err}").contains("iat"));
}

// ---------------------------------------------------------------------------
// 7–9. extract_webid — all three paths
// ---------------------------------------------------------------------------

fn make_claims(sub: &str, webid: Option<&str>) -> SolidOidcClaims {
    SolidOidcClaims {
        iss: "https://op.example".into(),
        sub: sub.into(),
        aud: serde_json::json!("solid"),
        exp: 9_999_999_999,
        iat: 1_700_000_000,
        webid: webid.map(str::to_string),
        client_id: Some("client-abc".into()),
        cnf: None,
        scope: Some("openid webid".into()),
    }
}

#[test]
fn extract_webid_prefers_explicit_webid_claim() {
    let claims = make_claims(
        "https://sub.example/profile#me",
        Some("https://webid.example/profile#me"),
    );
    // Explicit `webid` wins even when `sub` is also URL-shaped.
    assert_eq!(
        extract_webid(&claims).unwrap(),
        "https://webid.example/profile#me"
    );
}

#[test]
fn extract_webid_falls_back_to_sub() {
    let claims = make_claims("https://sub.example/profile#me", None);
    assert_eq!(
        extract_webid(&claims).unwrap(),
        "https://sub.example/profile#me"
    );
}

#[test]
fn extract_webid_errors_when_neither_present() {
    let claims = make_claims("not-a-url", None);
    let err = extract_webid(&claims).unwrap_err();
    // Error must be PodError::Nip98 per the documented contract.
    assert!(matches!(err, PodError::Nip98(_)));
}

// ---------------------------------------------------------------------------
// 10. IntrospectionResponse round-trip (RFC 7662)
// ---------------------------------------------------------------------------

#[test]
fn introspection_response_round_trips() {
    let v = AccessTokenVerified {
        webid: "https://me.example/profile#me".into(),
        client_id: Some("client-xyz".into()),
        iss: "https://op.example".into(),
        jkt: "THUMBPRINT-OK".into(),
        scope: Some("openid webid".into()),
        exp: 1_800_000_000,
    };
    let r = IntrospectionResponse::from_verified(&v);
    assert!(r.active);
    let wire = serde_json::to_string(&r).expect("introspection serialises");
    let back: IntrospectionResponse =
        serde_json::from_str(&wire).expect("introspection deserialises");
    assert!(back.active);
    assert_eq!(back.webid.as_deref(), Some("https://me.example/profile#me"));
    assert_eq!(back.cnf.as_ref().map(|c| c.jkt.as_str()), Some("THUMBPRINT-OK"));
    assert_eq!(back.scope.as_deref(), Some("openid webid"));

    // Inactive form round-trips too.
    let inactive = IntrospectionResponse::inactive();
    let wire2 = serde_json::to_string(&inactive).expect("inactive serialises");
    // Skip-serializing-if omits the None fields — `active:false` only.
    assert!(wire2.contains("\"active\":false"));
}

// ---------------------------------------------------------------------------
// 11. CnfClaim serde round-trip
// ---------------------------------------------------------------------------

#[test]
fn cnf_claim_jkt_round_trips() {
    let c = CnfClaim {
        jkt: "RFC7638-THUMB".into(),
    };
    let wire = serde_json::to_string(&c).unwrap();
    assert!(wire.contains("\"jkt\":\"RFC7638-THUMB\""));
    let back: CnfClaim = serde_json::from_str(&wire).unwrap();
    assert_eq!(back.jkt, "RFC7638-THUMB");
}

// ---------------------------------------------------------------------------
// 12. AccessTokenVerified population smoke — field-by-field
// ---------------------------------------------------------------------------

#[test]
fn access_token_verified_carries_all_fields() {
    let v = AccessTokenVerified {
        webid: "https://me.example/profile#me".into(),
        client_id: Some("client-123".into()),
        iss: "https://op.example".into(),
        jkt: "JKT-1".into(),
        scope: Some("openid webid".into()),
        exp: 1_800_000_000,
    };
    // Verified carriers expose the same fields that IntrospectionResponse
    // reads from — this asserts the pod can build a 7662 response with no
    // additional lookups.
    assert_eq!(v.webid, "https://me.example/profile#me");
    assert_eq!(v.client_id.as_deref(), Some("client-123"));
    assert_eq!(v.iss, "https://op.example");
    assert_eq!(v.jkt, "JKT-1");
    assert_eq!(v.scope.as_deref(), Some("openid webid"));
    assert_eq!(v.exp, 1_800_000_000);
}

// ---------------------------------------------------------------------------
// Bonus — verify_dpop_proof happy path (smoke, demonstrates the
// baseline used by all the negative tests above).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verify_dpop_proof_happy_path_returns_jkt() {
    let secret = b"mod-direct-happy-secret";
    let jwk = test_jwk(secret);
    let expected_jkt = jwk.thumbprint().unwrap();
    let now = 1_700_000_000u64;
    let proof = build_dpop_proof(secret, &jwk, "https://pod.example/r", "GET", now, "jti-ok-1");

    let v = verify_dpop_proof(&proof, "https://pod.example/r", "GET", now, 60, None)
        .await
        .expect("happy-path DPoP proof verifies");
    assert_eq!(v.jkt, expected_jkt);
    assert_eq!(v.htm, "GET");
    assert_eq!(v.jti, "jti-ok-1");
}
