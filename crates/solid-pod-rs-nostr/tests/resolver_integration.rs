//! Integration tests for the bidirectional `did:nostr` ↔ WebID resolver.
//!
//! These exercise the live HTTP path using `wiremock` as a mock server.
//! The default SSRF policy refuses loopback/private hosts, so the tests
//! inject a permissive `SsrfCheck` for the mock origin while a separate
//! test verifies that the real default policy still blocks private IPs.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;
use solid_pod_rs_nostr::{NostrPubkey, NostrWebIdResolver, SsrfCheck};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PK: &str = "2222222222222222222222222222222222222222222222222222222222222222";

struct AllowAllSsrf;

#[async_trait]
impl SsrfCheck for AllowAllSsrf {
    async fn verify_host(&self, _host: &str) -> Result<(), String> {
        Ok(())
    }
}

#[tokio::test]
async fn resolver_maps_webid_to_nostr_via_also_known_as() {
    let server = MockServer::start().await;
    let body = json!({
        "@id": "http://alice.example/profile#me",
        "sameAs": format!("did:nostr:{PK}")
    });
    Mock::given(method("GET"))
        .and(path("/profile"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/ld+json")
                .set_body_json(&body),
        )
        .mount(&server)
        .await;

    let resolver = NostrWebIdResolver::with_ssrf(Arc::new(AllowAllSsrf));
    let webid = format!("{}/profile", server.uri());
    let pk = resolver
        .resolve_webid_to_nostr(&webid)
        .await
        .expect("resolver call succeeds")
        .expect("pubkey resolved");
    assert_eq!(pk.to_hex(), PK);
}

#[tokio::test]
async fn resolver_maps_nostr_to_webid_via_did_document() {
    let server = MockServer::start().await;
    let webid = "https://alice.example/profile#me";
    let doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": format!("did:nostr:{PK}"),
        "alsoKnownAs": [webid]
    });
    Mock::given(method("GET"))
        .and(path(format!("/.well-known/did/nostr/{PK}.json")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/did+json")
                .set_body_json(&doc),
        )
        .mount(&server)
        .await;

    let resolver = NostrWebIdResolver::with_ssrf(Arc::new(AllowAllSsrf));
    let pk = NostrPubkey::from_hex(PK).unwrap();
    let resolved = resolver
        .resolve_nostr_to_webid(&server.uri(), &pk)
        .await
        .expect("resolver succeeds")
        .expect("webid present");
    assert_eq!(resolved, webid);
}

#[tokio::test]
async fn resolver_returns_malformed_when_did_id_mismatches() {
    let server = MockServer::start().await;
    let doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": "did:nostr:deadbeef",
        "alsoKnownAs": ["https://alice.example/profile"]
    });
    Mock::given(method("GET"))
        .and(path(format!("/.well-known/did/nostr/{PK}.json")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/did+json")
                .set_body_json(&doc),
        )
        .mount(&server)
        .await;

    let resolver = NostrWebIdResolver::with_ssrf(Arc::new(AllowAllSsrf));
    let pk = NostrPubkey::from_hex(PK).unwrap();
    let err = resolver
        .resolve_nostr_to_webid(&server.uri(), &pk)
        .await
        .expect_err("should be malformed");
    let msg = err.to_string();
    assert!(msg.contains("id mismatch") || msg.contains("malformed"));
}

#[tokio::test]
async fn resolver_rejects_private_ip_host_by_default() {
    // Default resolver uses the restrictive solid_pod_rs SSRF guard.
    // Hitting 127.0.0.1 must be refused without issuing the request.
    let resolver = NostrWebIdResolver::new();
    let webid = "http://127.0.0.1:1/profile";
    let err = resolver
        .resolve_webid_to_nostr(webid)
        .await
        .expect_err("loopback must be refused");
    let msg = err.to_string();
    assert!(msg.contains("ssrf") || msg.contains("Loopback") || msg.contains("blocked"));
}

#[tokio::test]
async fn resolver_rejects_metadata_hostname() {
    let resolver = NostrWebIdResolver::new();
    let webid = "http://metadata.google.internal/computeMetadata/v1/";
    let err = resolver
        .resolve_webid_to_nostr(webid)
        .await
        .expect_err("metadata.google.internal must be refused");
    let msg = err.to_string();
    assert!(msg.contains("ssrf") || msg.contains("Reserved") || msg.contains("blocked"));
}
