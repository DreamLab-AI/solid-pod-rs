//! Integration tests for HTTP Signature signing and verification.
//!
//! These tests exercise the draft-cavage-http-signatures-12
//! implementation used for ActivityPub federation: RSA-SHA256 signing,
//! Digest header computation, round-trip sign-then-verify, and
//! rejection of tampered or mismatched signatures.

use async_trait::async_trait;
use solid_pod_rs_activitypub::{
    actor::generate_actor_keypair,
    digest_header,
    error::SigError,
    http_sig::{
        sign_request, verify_request_signature, ActorKeyResolver, OutboundRequest, SignedRequest,
        VerifiedActor,
    },
};

// ---------------------------------------------------------------------------
// Test resolver: returns a static public key for any keyId
// ---------------------------------------------------------------------------

struct StaticResolver {
    pem: String,
}

#[async_trait]
impl ActorKeyResolver for StaticResolver {
    async fn resolve(&self, key_id: &str) -> Result<VerifiedActor, SigError> {
        Ok(VerifiedActor {
            key_id: key_id.to_string(),
            actor_url: key_id
                .split_once('#')
                .map(|(u, _)| u.to_string())
                .unwrap_or_else(|| key_id.to_string()),
            inbox_url: None,
            public_key_pem: self.pem.clone(),
        })
    }
}

/// Build a properly signed inbound request using the raw crypto
/// primitives, matching the production `sign_request` flow but
/// constructing a `SignedRequest` for the verifier.
fn build_signed_inbound(
    method: &str,
    path: &str,
    body: &[u8],
    priv_pem: &str,
    key_id: &str,
) -> SignedRequest {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::RsaPrivateKey;
    use sha2::Sha256;

    let host = "pod.example";
    let date = httpdate::fmt_http_date(std::time::SystemTime::now());
    let digest = digest_header(body);
    let base = format!(
        "(request-target): {} {}\nhost: {}\ndate: {}\ndigest: {}",
        method.to_ascii_lowercase(),
        path,
        host,
        date,
        digest
    );
    let sk = RsaPrivateKey::from_pkcs8_pem(priv_pem).unwrap();
    let signer = SigningKey::<Sha256>::new(sk);
    let sig: rsa::pkcs1v15::Signature = signer.sign(base.as_bytes());
    let sig_b64 = B64.encode(sig.to_bytes());
    let sig_header = format!(
        "keyId=\"{key_id}\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date digest\",signature=\"{sig_b64}\""
    );

    SignedRequest::new(method, path, body.to_vec())
        .with_header("host", host)
        .with_header("date", date)
        .with_header("digest", digest)
        .with_header("signature", sig_header)
}

// ===========================================================================
// Digest computation
// ===========================================================================

#[test]
fn digest_header_sha256_format() {
    let d = digest_header(b"hello world");
    assert!(
        d.starts_with("SHA-256="),
        "digest should start with SHA-256=, got: {d}"
    );
}

#[test]
fn digest_header_empty_body() {
    let d = digest_header(b"");
    assert!(d.starts_with("SHA-256="));
    // SHA-256 of empty string is well-known.
    assert_eq!(d, "SHA-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
}

#[test]
fn digest_header_deterministic() {
    let a = digest_header(b"same content");
    let b = digest_header(b"same content");
    assert_eq!(a, b);
}

#[test]
fn digest_header_differs_for_different_content() {
    let a = digest_header(b"content-a");
    let b = digest_header(b"content-b");
    assert_ne!(a, b);
}

// ===========================================================================
// Sign + Verify round-trip
// ===========================================================================

#[tokio::test]
async fn sign_then_verify_roundtrip() {
    let (priv_pem, pub_pem) = generate_actor_keypair().unwrap();
    let key_id = "https://pod.example/profile/card.jsonld#main-key";
    let body = br#"{"type":"Create","object":{"type":"Note","content":"test"}}"#.to_vec();

    let mut out = OutboundRequest {
        method: "POST".into(),
        url: "https://remote.example/inbox".into(),
        headers: vec![("Content-Type".into(), "application/activity+json".into())],
        body: body.clone(),
    };
    sign_request(&mut out, &priv_pem, key_id).unwrap();

    // Verify the outbound now carries Host, Date, Digest, Signature.
    let header_names: Vec<String> = out
        .headers
        .iter()
        .map(|(k, _)| k.to_ascii_lowercase())
        .collect();
    assert!(header_names.contains(&"host".to_string()));
    assert!(header_names.contains(&"date".to_string()));
    assert!(header_names.contains(&"digest".to_string()));
    assert!(header_names.contains(&"signature".to_string()));

    // Convert to inbound shape and verify.
    let url = url::Url::parse(&out.url).unwrap();
    let path = url.path().to_string();
    let mut inbound = SignedRequest::new("POST", &path, body);
    for (k, v) in &out.headers {
        inbound.headers.insert(k.to_ascii_lowercase(), v.clone());
    }
    let resolver = StaticResolver { pem: pub_pem };
    let actor = verify_request_signature(&inbound, &resolver).await.unwrap();
    assert_eq!(actor.key_id, key_id);
    assert_eq!(actor.actor_url, "https://pod.example/profile/card.jsonld");
}

// ===========================================================================
// Verification failures
// ===========================================================================

#[tokio::test]
async fn verify_rejects_tampered_body() {
    let (priv_pem, pub_pem) = generate_actor_keypair().unwrap();
    let key_id = "https://remote.example/actor#main-key";
    let mut req = build_signed_inbound("POST", "/inbox", b"{}", &priv_pem, key_id);
    // Tamper the body after signing.
    req.body = b"{\"tampered\":true}".to_vec();
    let resolver = StaticResolver { pem: pub_pem };
    let result = verify_request_signature(&req, &resolver).await;
    assert!(
        matches!(result, Err(SigError::DigestMismatch)),
        "expected DigestMismatch, got {result:?}"
    );
}

#[tokio::test]
async fn verify_rejects_tampered_header_stale_date() {
    let (priv_pem, pub_pem) = generate_actor_keypair().unwrap();
    let key_id = "https://remote.example/actor#main-key";
    let mut req = build_signed_inbound("POST", "/inbox", b"{}", &priv_pem, key_id);
    // Tamper the Date header to a very old value — this is now caught
    // by the Date freshness check (P0-07) before signature verification.
    req.headers.insert(
        "date".to_string(),
        "Sat, 01 Jan 2000 00:00:00 GMT".to_string(),
    );
    let resolver = StaticResolver { pem: pub_pem };
    let result = verify_request_signature(&req, &resolver).await;
    assert!(
        matches!(result, Err(SigError::DateNotFresh(_))),
        "expected DateNotFresh for year-2000 Date, got {result:?}"
    );
}

#[tokio::test]
async fn verify_rejects_tampered_header_fresh_date() {
    let (priv_pem, pub_pem) = generate_actor_keypair().unwrap();
    let key_id = "https://remote.example/actor#main-key";
    let mut req = build_signed_inbound("POST", "/inbox", b"{}", &priv_pem, key_id);
    // Tamper the Date header to a fresh but different value — passes
    // the freshness check but invalidates the signature base string.
    let slightly_off = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
    req.headers
        .insert("date".to_string(), httpdate::fmt_http_date(slightly_off));
    let resolver = StaticResolver { pem: pub_pem };
    let result = verify_request_signature(&req, &resolver).await;
    assert!(
        matches!(result, Err(SigError::VerifyFailed(_))),
        "expected VerifyFailed for fresh-but-tampered Date, got {result:?}"
    );
}

#[tokio::test]
async fn verify_rejects_wrong_public_key() {
    let (priv_pem, _pub_pem) = generate_actor_keypair().unwrap();
    let (_other_priv, other_pub) = generate_actor_keypair().unwrap();
    let key_id = "https://remote.example/actor#main-key";
    let req = build_signed_inbound("POST", "/inbox", b"{}", &priv_pem, key_id);
    let resolver = StaticResolver { pem: other_pub };
    let result = verify_request_signature(&req, &resolver).await;
    assert!(
        matches!(result, Err(SigError::VerifyFailed(_))),
        "expected VerifyFailed, got {result:?}"
    );
}

#[tokio::test]
async fn verify_rejects_missing_signature_header() {
    let req = SignedRequest::new("POST", "/inbox", b"{}".to_vec())
        .with_header("host", "pod.example")
        .with_header("date", "Mon, 06 May 2026 12:00:00 GMT");
    let (_priv_pem, pub_pem) = generate_actor_keypair().unwrap();
    let resolver = StaticResolver { pem: pub_pem };
    let result = verify_request_signature(&req, &resolver).await;
    assert!(
        matches!(result, Err(SigError::MissingHeader("signature"))),
        "expected MissingHeader(signature), got {result:?}"
    );
}

// ===========================================================================
// sign_request header mechanics
// ===========================================================================

#[test]
fn sign_request_adds_four_headers() {
    let (priv_pem, _pub_pem) = generate_actor_keypair().unwrap();
    let key_id = "https://pod.example/key#main-key";
    let mut req = OutboundRequest {
        method: "POST".into(),
        url: "https://remote.example/inbox".into(),
        headers: vec![("Content-Type".into(), "application/activity+json".into())],
        body: b"{}".to_vec(),
    };
    sign_request(&mut req, &priv_pem, key_id).unwrap();

    let names: Vec<String> = req.headers.iter().map(|(k, _)| k.clone()).collect();
    assert!(names.contains(&"Host".to_string()));
    assert!(names.contains(&"Date".to_string()));
    assert!(names.contains(&"Digest".to_string()));
    assert!(names.contains(&"Signature".to_string()));
    // Content-Type should still be present.
    assert!(names.contains(&"Content-Type".to_string()));
}

#[test]
fn sign_request_deduplicates_existing_headers() {
    let (priv_pem, _pub_pem) = generate_actor_keypair().unwrap();
    let key_id = "https://pod.example/key#main-key";
    let mut req = OutboundRequest {
        method: "POST".into(),
        url: "https://remote.example/inbox".into(),
        headers: vec![
            ("Host".into(), "old-host".into()),
            ("Date".into(), "old-date".into()),
            ("Digest".into(), "old-digest".into()),
            ("Signature".into(), "old-sig".into()),
        ],
        body: b"{}".to_vec(),
    };
    sign_request(&mut req, &priv_pem, key_id).unwrap();

    // Each of Host, Date, Digest, Signature should appear exactly once.
    for name in &["Host", "Date", "Digest", "Signature"] {
        let count = req
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .count();
        assert_eq!(count, 1, "{name} should appear exactly once, found {count}");
    }
}

#[test]
fn sign_request_host_matches_url() {
    let (priv_pem, _pub_pem) = generate_actor_keypair().unwrap();
    let key_id = "https://pod.example/key#main-key";
    let mut req = OutboundRequest {
        method: "POST".into(),
        url: "https://specific-host.example:8443/inbox".into(),
        headers: vec![],
        body: b"{}".to_vec(),
    };
    sign_request(&mut req, &priv_pem, key_id).unwrap();

    let host = req
        .headers
        .iter()
        .find(|(k, _)| k == "Host")
        .map(|(_, v)| v.as_str())
        .unwrap();
    assert_eq!(host, "specific-host.example");
}

#[test]
fn sign_request_digest_matches_body() {
    let (priv_pem, _pub_pem) = generate_actor_keypair().unwrap();
    let key_id = "https://pod.example/key#main-key";
    let body = b"{\"type\":\"Follow\"}";
    let mut req = OutboundRequest {
        method: "POST".into(),
        url: "https://remote.example/inbox".into(),
        headers: vec![],
        body: body.to_vec(),
    };
    sign_request(&mut req, &priv_pem, key_id).unwrap();

    let digest_val = req
        .headers
        .iter()
        .find(|(k, _)| k == "Digest")
        .map(|(_, v)| v.clone())
        .unwrap();
    let expected = digest_header(body);
    assert_eq!(digest_val, expected);
}

#[test]
fn sign_request_signature_header_contains_key_id() {
    let (priv_pem, _pub_pem) = generate_actor_keypair().unwrap();
    let key_id = "https://pod.example/profile/card.jsonld#main-key";
    let mut req = OutboundRequest {
        method: "POST".into(),
        url: "https://remote.example/inbox".into(),
        headers: vec![],
        body: b"{}".to_vec(),
    };
    sign_request(&mut req, &priv_pem, key_id).unwrap();

    let sig_header = req
        .headers
        .iter()
        .find(|(k, _)| k == "Signature")
        .map(|(_, v)| v.clone())
        .unwrap();
    assert!(
        sig_header.contains(key_id),
        "Signature header should contain the keyId"
    );
    assert!(sig_header.contains("algorithm=\"rsa-sha256\""));
    assert!(sig_header.contains("headers=\"(request-target) host date digest\""));
}

#[test]
fn sign_request_rejects_invalid_url() {
    let (priv_pem, _pub_pem) = generate_actor_keypair().unwrap();
    let key_id = "https://pod.example/key#main-key";
    let mut req = OutboundRequest {
        method: "POST".into(),
        url: "not-a-valid-url".into(),
        headers: vec![],
        body: b"{}".to_vec(),
    };
    let result = sign_request(&mut req, &priv_pem, key_id);
    assert!(
        matches!(result, Err(SigError::Url(_))),
        "expected Url error, got {result:?}"
    );
}

// ===========================================================================
// Verify with different body sizes
// ===========================================================================

#[tokio::test]
async fn sign_verify_large_body() {
    let (priv_pem, pub_pem) = generate_actor_keypair().unwrap();
    let key_id = "https://pod.example/key#main-key";
    // 10 KB body.
    let body = vec![b'x'; 10_000];
    let mut out = OutboundRequest {
        method: "POST".into(),
        url: "https://remote.example/inbox".into(),
        headers: vec![],
        body: body.clone(),
    };
    sign_request(&mut out, &priv_pem, key_id).unwrap();

    let url = url::Url::parse(&out.url).unwrap();
    let mut inbound = SignedRequest::new("POST", url.path(), body);
    for (k, v) in &out.headers {
        inbound.headers.insert(k.to_ascii_lowercase(), v.clone());
    }
    let resolver = StaticResolver { pem: pub_pem };
    let actor = verify_request_signature(&inbound, &resolver).await.unwrap();
    assert_eq!(actor.key_id, key_id);
}
