//! Sprint 6 D: `did:nostr` resolver — RED phase tests.
//!
//! Exercises [`solid_pod_rs::interop::did_nostr`]. These tests are
//! written before the final implementation settles and must pass once
//! the module is in place.
//!
//! Coverage:
//!
//! 1. `did_nostr_well_known_url_format` — pure URL composition.
//! 2. `did_nostr_document_emits_minimal_schema` — doc shape +
//!    `NostrSchnorrKey2024` verification method entry.
//! 3. `did_nostr_resolver_returns_webid_when_backlink_present` — happy
//!    path: DID Doc with one `alsoKnownAs`, WebID profile carries
//!    `owl:sameAs` back-link → `Some(web_id)`.
//! 4. `did_nostr_resolver_rejects_missing_backlink` — WebID profile has
//!    no back-link → `None`.
//! 5. `did_nostr_resolver_caches_negative_result` — first call returns
//!    `None` on 404; second call within the failure TTL does not hit
//!    the network (wiremock `expect(1)` passes).
//! 6. `did_nostr_resolver_blocks_metadata_origin` — origin
//!    `http://169.254.169.254/` is rejected by the default SSRF policy
//!    with no HTTP traffic emitted.

#![cfg(feature = "did-nostr")]

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use solid_pod_rs::interop::did_nostr::{
    did_nostr_document, did_nostr_well_known_url, DidNostrResolver,
};
use solid_pod_rs::security::ssrf::SsrfPolicy;

const TEST_PUBKEY: &str = "abcd000000000000000000000000000000000000000000000000000000000001";

// --- test-1 --------------------------------------------------------------

#[test]
fn did_nostr_well_known_url_format() {
    let url = did_nostr_well_known_url("https://nostr.social", TEST_PUBKEY);
    assert_eq!(
        url,
        format!("https://nostr.social/.well-known/did/nostr/{TEST_PUBKEY}.json")
    );

    // Trailing-slash normalisation: origin may be given with or
    // without a trailing `/`; URL composition is identical either way.
    let url2 = did_nostr_well_known_url("https://nostr.social/", TEST_PUBKEY);
    assert_eq!(url, url2);
}

// --- test-2 --------------------------------------------------------------

#[test]
fn did_nostr_document_emits_minimal_schema() {
    let also = vec!["https://alice.example/me#i".to_string()];
    let doc = did_nostr_document(TEST_PUBKEY, &also);

    assert_eq!(doc["id"], format!("did:nostr:{TEST_PUBKEY}"));
    assert_eq!(doc["alsoKnownAs"][0], "https://alice.example/me#i");

    let vm = &doc["verificationMethod"][0];
    assert_eq!(vm["type"], "NostrSchnorrKey2024");
    assert_eq!(vm["controller"], format!("did:nostr:{TEST_PUBKEY}"));
    assert_eq!(vm["publicKeyHex"], TEST_PUBKEY);
    assert_eq!(vm["id"], format!("did:nostr:{TEST_PUBKEY}#nostr-schnorr"));
}

// --- test-3 --------------------------------------------------------------

/// Happy path: DID Doc lists a WebID whose profile carries an
/// `owl:sameAs` back-link to the same `did:nostr:<pubkey>`.
#[tokio::test]
async fn did_nostr_resolver_returns_webid_when_backlink_present() {
    let server = MockServer::start().await;
    let origin = server.uri();
    let web_id = format!("{origin}/alice#me");

    // Mock 1: DID Doc.
    let doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": format!("did:nostr:{TEST_PUBKEY}"),
        "alsoKnownAs": [web_id],
    });
    Mock::given(method("GET"))
        .and(path(format!("/.well-known/did/nostr/{TEST_PUBKEY}.json")))
        .respond_with(ResponseTemplate::new(200).set_body_json(doc))
        .mount(&server)
        .await;

    // Mock 2: WebID profile with back-link (Turtle-flavoured).
    let backlink_body = format!(
        "@prefix owl: <http://www.w3.org/2002/07/owl#> .\n\
         <#me> owl:sameAs <did:nostr:{TEST_PUBKEY}> .\n"
    );
    Mock::given(method("GET"))
        .and(path("/alice"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/turtle")
                .set_body_string(backlink_body),
        )
        .mount(&server)
        .await;

    let ssrf = Arc::new(SsrfPolicy::new().with_allow_loopback(true));
    let resolver = DidNostrResolver::new(ssrf);
    let out = resolver.resolve(&server.uri(), TEST_PUBKEY).await;
    assert_eq!(
        out.as_deref(),
        Some(format!("{origin}/alice#me").as_str()),
        "resolver must return verified WebID"
    );
}

// --- test-4 --------------------------------------------------------------

/// WebID profile references a different identifier (no back-link to
/// the expected DID). Resolver must return `None`.
#[tokio::test]
async fn did_nostr_resolver_rejects_missing_backlink() {
    let server = MockServer::start().await;
    let origin = server.uri();
    let web_id = format!("{origin}/bob#me");

    let doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": format!("did:nostr:{TEST_PUBKEY}"),
        "alsoKnownAs": [web_id],
    });
    Mock::given(method("GET"))
        .and(path(format!("/.well-known/did/nostr/{TEST_PUBKEY}.json")))
        .respond_with(ResponseTemplate::new(200).set_body_json(doc))
        .mount(&server)
        .await;

    // Profile body has a sameAs predicate but it points at someone
    // else, not the expected DID. The DID literal is absent.
    let other_pubkey = "ffff000000000000000000000000000000000000000000000000000000000000";
    let body = format!(
        "@prefix owl: <http://www.w3.org/2002/07/owl#> .\n\
         <#me> owl:sameAs <did:nostr:{other_pubkey}> .\n"
    );
    Mock::given(method("GET"))
        .and(path("/bob"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/turtle")
                .set_body_string(body),
        )
        .mount(&server)
        .await;

    let ssrf = Arc::new(SsrfPolicy::new().with_allow_loopback(true));
    let resolver = DidNostrResolver::new(ssrf);
    let out = resolver.resolve(&server.uri(), TEST_PUBKEY).await;
    assert!(out.is_none(), "missing back-link must yield None");
}

// --- test-5 --------------------------------------------------------------

/// Negative-result caching: a 404 on the DID Doc is cached for the
/// failure TTL, so a second call in the same window does not hit the
/// mock. `expect(1)` on the wiremock stub is the assertion.
#[tokio::test]
async fn did_nostr_resolver_caches_negative_result() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(format!("/.well-known/did/nostr/{TEST_PUBKEY}.json")))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;

    let ssrf = Arc::new(SsrfPolicy::new().with_allow_loopback(true));
    let resolver = DidNostrResolver::new(ssrf)
        .with_ttls(Duration::from_secs(300), Duration::from_secs(60));

    let first = resolver.resolve(&server.uri(), TEST_PUBKEY).await;
    assert!(first.is_none(), "404 must resolve to None");

    let second = resolver.resolve(&server.uri(), TEST_PUBKEY).await;
    assert!(second.is_none(), "cached 404 must still be None");

    // wiremock's Drop will assert expect(1) — exactly one network hit.
}

// --- test-6 --------------------------------------------------------------

/// Default SSRF policy denies link-local / cloud-metadata origins
/// before any I/O. Resolver must return `None` without contacting the
/// network (no mock is needed; the check fires pre-flight).
#[tokio::test]
async fn did_nostr_resolver_blocks_metadata_origin() {
    let ssrf = Arc::new(SsrfPolicy::new()); // default: deny non-public
    let resolver = DidNostrResolver::new(ssrf);
    let out = resolver
        .resolve("http://169.254.169.254/", TEST_PUBKEY)
        .await;
    assert!(out.is_none(), "metadata origin must be blocked pre-flight");
}
