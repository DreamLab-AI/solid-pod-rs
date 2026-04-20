//! Sprint 6 E — OIDC-layer end-to-end stitches (QE addendum §3.3).
//!
//! 1. RFC 7591 register_client → HS256 verify_access_token.
//! 2. DiscoveryDocument → verify_access_token → wac::evaluate_access.
//! 3. NIP-98 verify → did:nostr:<pubkey> → wac::evaluate_access.
//! 4. AclDocument → serialize_turtle_acl → parse_turtle_acl → identical verdict.
//! 5. verify_dpop_proof + DpopReplayCache blocks the second use.
//!
//! `cargo test -p solid-pod-rs --features oidc,dpop-replay-cache,nip98-schnorr,acl-origin,jss-v04 --test oidc_integration`

#![cfg(all(feature = "oidc", feature = "dpop-replay-cache"))]

use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL;
use base64::Engine;
use hmac::{Hmac, Mac};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use solid_pod_rs::oidc::{
    discovery_for, register_client, replay::DpopReplayCache, verify_access_token,
    verify_dpop_proof, ClientRegistrationRequest, CnfClaim, DpopClaims, Jwk, TokenVerifyKey,
};
use solid_pod_rs::wac::{
    evaluate_access, parse_turtle_acl, serialize_turtle_acl, AccessMode, AclAuthorization,
    AclDocument, IdOrIds, IdRef,
};

// Local token + DPoP helpers.

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenClaims {
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

fn issue_hs256_token(
    secret: &[u8],
    issuer: &str,
    webid: &str,
    client_id: &str,
    jkt: &str,
    exp: u64,
) -> String {
    let claims = TokenClaims {
        iss: issuer.into(),
        sub: webid.into(),
        aud: serde_json::json!("solid"),
        exp,
        iat: exp.saturating_sub(3600),
        webid: Some(webid.into()),
        client_id: Some(client_id.into()),
        cnf: Some(CnfClaim { jkt: jkt.into() }),
        scope: Some("openid webid".into()),
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .expect("HS256 token encodes")
}

fn oct_jwk(secret: &[u8]) -> Jwk {
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
        htu: htu.into(),
        htm: htm.into(),
        iat,
        jti: jti.into(),
        ath: None,
    };
    let body_b64 = BASE64_URL.encode(serde_json::to_string(&claims).unwrap());
    let signing_input = format!("{header_b64}.{body_b64}");
    let mut mac = <Hmac<Sha256>>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(signing_input.as_bytes());
    let sig_b64 = BASE64_URL.encode(mac.finalize().into_bytes());
    format!("{signing_input}.{sig_b64}")
}

fn id(s: &str) -> IdOrIds {
    IdOrIds::Single(IdRef { id: s.to_string() })
}

fn acl_single(
    agent_uri: Option<&str>,
    agent_class: Option<&str>,
    access_to: &str,
    mode: &str,
) -> AclDocument {
    AclDocument {
        context: None,
        graph: Some(vec![AclAuthorization {
            id: Some("#rule".into()),
            r#type: Some("acl:Authorization".into()),
            agent: agent_uri.map(id),
            agent_class: agent_class.map(id),
            agent_group: None,
            origin: None,
            access_to: Some(id(access_to)),
            default: None,
            mode: Some(id(mode)),
            condition: None,
        }]),
    }
}

// 1. RFC 7591 register_client → HS256 verify_access_token.
//    Demonstrates the registered client_id survives into the token.

#[test]
fn oidc_e2e_dynamic_registration_round_trip() {
    let req = ClientRegistrationRequest {
        redirect_uris: vec!["https://app.example/cb".into()],
        client_name: Some("Round Trip App".into()),
        client_uri: None,
        grant_types: vec!["authorization_code".into()],
        response_types: vec!["code".into()],
        scope: Some("openid webid".into()),
        token_endpoint_auth_method: Some("client_secret_basic".into()),
        application_type: Some("web".into()),
    };
    let now = 1_700_000_000u64;
    let client = register_client(&req, now);
    assert!(client.client_id.starts_with("client-"));

    // The pod now mints an HS256 token for this client (test-only secret).
    let secret = b"e2e-registration-secret";
    let issuer = "https://op.example";
    let webid = "https://me.example/profile#me";
    let jkt = "JKT-E2E-1";
    let token = issue_hs256_token(secret, issuer, webid, &client.client_id, jkt, now + 3600);

    let ks = TokenVerifyKey::Symmetric(secret.to_vec());
    let verified = verify_access_token(&token, &ks, issuer, jkt, now)
        .expect("HS256 token verifies against symmetric key");

    // The client_id registered in step 1 flowed all the way through.
    assert_eq!(verified.client_id.as_deref(), Some(client.client_id.as_str()));
    assert_eq!(verified.webid, webid);
    assert_eq!(verified.jkt, jkt);
    assert_eq!(verified.iss, issuer);
}

// 2. Discovery → TokenVerifyKey::Symmetric → verify_access_token →
//    feed AccessTokenVerified.webid into wac::evaluate_access. Proves
//    the layers are pluggable.

#[test]
fn oidc_e2e_discovery_to_evaluate() {
    let issuer = "https://op.example";
    let disc = discovery_for(issuer);
    assert_eq!(disc.issuer, issuer);
    // (jwks_uri would be fetched in production — here we short-circuit
    // with an in-test symmetric keyset to exercise the pluggable path.)

    let secret = b"e2e-discovery-secret";
    let ks = TokenVerifyKey::Symmetric(secret.to_vec());
    let webid = "https://me.example/profile#me";
    let jkt = "JKT-E2E-2";
    let now = 1_700_000_000u64;
    let token = issue_hs256_token(secret, &disc.issuer, webid, "client-a", jkt, now + 3600);

    let verified = verify_access_token(&token, &ks, &disc.issuer, jkt, now)
        .expect("discovery-wired verify succeeds");

    // Feed the WebID into a WAC evaluation. ACL grants Read on /n
    // exactly to `webid`.
    let acl = acl_single(Some(webid), None, "/n", "acl:Read");
    let allowed = evaluate_access(
        Some(&acl),
        Some(verified.webid.as_str()),
        "/n",
        AccessMode::Read,
        None,
    );
    assert!(allowed, "the full 3-hop pipeline grants Read to the WebID");

    // And a negative sanity: a different agent is denied.
    let denied = evaluate_access(
        Some(&acl),
        Some("https://mallory.example/profile#me"),
        "/n",
        AccessMode::Read,
        None,
    );
    assert!(!denied);
}

// 3. NIP-98 verify → did:nostr:<pubkey> as WAC agent URI.
//    Feature-gated on `nip98-schnorr` so the real Schnorr path runs.

#[cfg(feature = "nip98-schnorr")]
#[test]
fn nip98_to_wac_bridge() {
    use k256::schnorr::signature::Signer;
    use solid_pod_rs::auth::nip98::{compute_event_id, verify_at, Nip98Event};

    // Deterministic Schnorr keypair — same seed as the in-module tests.
    let sk = k256::schnorr::SigningKey::from_bytes(&[0x42u8; 32]).unwrap();
    let pubkey = hex::encode(sk.verifying_key().to_bytes());

    // Build and sign a NIP-98 event.
    let ts = 1_700_000_000u64;
    let url = "https://pod.example/note";
    let tags = vec![
        vec!["u".to_string(), url.to_string()],
        vec!["method".to_string(), "GET".to_string()],
    ];
    let skeleton = Nip98Event {
        id: String::new(),
        pubkey: pubkey.clone(),
        created_at: ts,
        kind: 27235,
        tags: tags.clone(),
        content: String::new(),
        sig: String::new(),
    };
    let id = compute_event_id(&skeleton);
    let id_bytes: Vec<u8> = hex::decode(&id).unwrap();
    let sig: k256::schnorr::Signature = sk.sign(&id_bytes);
    let ev = serde_json::json!({
        "id": id,
        "pubkey": pubkey,
        "created_at": ts,
        "kind": 27235,
        "tags": tags,
        "content": "",
        "sig": hex::encode(sig.to_bytes()),
    });
    let hdr = format!(
        "Nostr {}",
        BASE64_STANDARD.encode(serde_json::to_string(&ev).unwrap().as_bytes())
    );
    let verified = verify_at(&hdr, url, "GET", None, ts).expect("NIP-98 verifies");
    assert_eq!(verified.pubkey, pubkey);

    // Bridge: use did:nostr:<pubkey> as the WAC agent URI.
    let agent = format!("did:nostr:{pubkey}");
    let acl = acl_single(Some(&agent), None, "/note", "acl:Read");
    assert!(evaluate_access(Some(&acl), Some(&agent), "/note", AccessMode::Read, None));
    // A different pubkey must not inherit the grant.
    assert!(!evaluate_access(
        Some(&acl), Some("did:nostr:deadbeef"), "/note", AccessMode::Read, None,
    ));
}

// 4. ACL → Turtle → parse → evaluate. The programmatic document and
//    the re-parsed document must agree on the verdict.

#[test]
fn acl_serialise_round_trip_evaluates_identically() {
    let webid = "https://me.example/profile#me";
    let original = acl_single(Some(webid), None, "/r", "acl:Read");

    let turtle = serialize_turtle_acl(&original);
    // Shape check — the serialiser always emits both prefixes.
    assert!(turtle.contains("@prefix acl:"));
    assert!(turtle.contains("acl:Authorization"));
    assert!(turtle.contains("acl:accessTo"));

    let parsed = parse_turtle_acl(&turtle).expect("Turtle re-parses");

    // Verdicts must agree across the full access-mode matrix.
    for mode in [AccessMode::Read, AccessMode::Write, AccessMode::Append, AccessMode::Control] {
        let a = evaluate_access(Some(&original), Some(webid), "/r", mode, None);
        let b = evaluate_access(Some(&parsed), Some(webid), "/r", mode, None);
        assert_eq!(a, b, "verdict drift for mode {mode:?}");
    }
    // Positive case survives the round trip.
    assert!(evaluate_access(Some(&parsed), Some(webid), "/r", AccessMode::Read, None));
}

// 5. verify_dpop_proof with a DpopReplayCache — second call is blocked.

#[tokio::test]
async fn oidc_dpop_proof_replay_cache_blocks_second_use() {
    let secret = b"e2e-replay-secret";
    let jwk = oct_jwk(secret);
    let htu = "https://pod.example/r";
    let now = 1_700_000_000u64;
    let proof = build_dpop_proof(secret, &jwk, htu, "GET", now, "jti-e2e-replay");

    let cache = DpopReplayCache::with_config(Duration::from_secs(60), 64);

    // First submission: OK.
    let first = verify_dpop_proof(&proof, htu, "GET", now, 60, Some(&cache))
        .await
        .expect("first submission accepted");
    assert_eq!(first.jti, "jti-e2e-replay");

    // Replay: rejected.
    let err = verify_dpop_proof(&proof, htu, "GET", now, 60, Some(&cache))
        .await
        .expect_err("replay must be blocked");
    assert!(format!("{err}").to_lowercase().contains("replay"));

    // Backwards-compat guarantee: same proof with `None` cache is
    // accepted (replay detection is strictly opt-in).
    verify_dpop_proof(&proof, htu, "GET", now, 60, None)
        .await
        .expect("None cache disables replay detection");
}
