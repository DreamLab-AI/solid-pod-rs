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
//!    `SchnorrSecp256k1VerificationKey2019` verification method entry (per ADR-074 D1).
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
fn did_nostr_document_emits_canonical_schema() {
    // ADR-125: canonical DIDNostr / Multikey form. The pre-pivot 2019-suite
    // + publicKeyHex + z-base58 shape is superseded.
    let also = vec!["https://alice.example/me#i".to_string()];
    let doc = did_nostr_document(TEST_PUBKEY, &also);
    let did = format!("did:nostr:{TEST_PUBKEY}");

    assert_eq!(doc["id"], did);
    assert_eq!(doc["type"], "DIDNostr");
    // alsoKnownAs is an agentbox extension (C4), surfaced when supplied.
    assert_eq!(doc["alsoKnownAs"][0], "https://alice.example/me#i");

    let vm = &doc["verificationMethod"][0];
    assert_eq!(vm["type"], "Multikey");
    assert_eq!(vm["controller"], did);
    assert_eq!(vm["id"], format!("{did}#key1"));
    // The 2019 suite + publicKeyHex are GONE; publicKeyMultibase is canonical.
    assert!(vm.get("publicKeyHex").is_none(), "publicKeyHex must be dropped");
    let mb = vm["publicKeyMultibase"].as_str().expect("publicKeyMultibase");
    assert_eq!(mb, format!("fe70102{TEST_PUBKEY}"), "fe70102 + x-only hex (I2)");
    assert_eq!(mb.len(), 71);
    assert_eq!(mb, mb.to_lowercase(), "lowercase hex (C3)");
    // I2: multibase body round-trips to the DID body.
    assert_eq!(&mb[7..], TEST_PUBKEY);

    // Canonical contexts (ADR-125 §2).
    let contexts = doc["@context"].as_array().expect("@context array");
    assert_eq!(contexts[0], "https://w3id.org/did");
    assert_eq!(contexts[1], "https://w3id.org/nostr/context");

    // Fragment-only auth/assertion; canonical service:[] (unset by extension
    // here because alsoKnownAs is the only extension supplied).
    assert_eq!(doc["authentication"][0], "#key1");
    assert_eq!(doc["assertionMethod"][0], "#key1");
    assert!(doc["service"].as_array().unwrap().is_empty());
}

// --- test-2b (D-1 regression) --------------------------------------------

/// D-1 (ADR-124 §7 / I2): malformed hex MUST NOT yield a keyless `Multikey`.
///
/// A pubkey that does not parse as 32-byte x-only hex cannot produce the
/// `fe70102` framing. The fallback path must emit an EMPTY
/// `verificationMethod` (and empty `authentication`/`assertionMethod`), never
/// a `Multikey` VM lacking `publicKeyMultibase`. The canonical envelope
/// (context/id/type/service) is still preserved.
#[test]
fn did_nostr_document_rejects_keyless_multikey_for_malformed_hex() {
    // Not 64 hex chars → cannot frame as fe70102 + x-only.
    let malformed = "not-a-valid-pubkey";
    let doc = did_nostr_document(malformed, &[]);

    // Canonical envelope preserved.
    assert_eq!(doc["id"], format!("did:nostr:{malformed}"));
    assert_eq!(doc["type"], "DIDNostr");
    assert_eq!(doc["@context"][0], "https://w3id.org/did");
    assert_eq!(doc["@context"][1], "https://w3id.org/nostr/context");

    // The critical I2 guarantee: verificationMethod is EMPTY, not a keyless
    // Multikey.
    let vms = doc["verificationMethod"].as_array().expect("vm array");
    assert!(
        vms.is_empty(),
        "malformed hex must yield verificationMethod:[] (no keyless Multikey)"
    );
    // No Multikey without a publicKeyMultibase anywhere in the doc.
    for vm in vms {
        assert!(
            !(vm["type"] == "Multikey" && vm.get("publicKeyMultibase").is_none()),
            "keyless Multikey VM is an I2 violation"
        );
    }
    // Auth/assertion references dropped in lockstep (no dangling #key1).
    assert!(doc["authentication"].as_array().unwrap().is_empty());
    assert!(doc["assertionMethod"].as_array().unwrap().is_empty());
    assert!(doc["service"].as_array().unwrap().is_empty());
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
    let resolver =
        DidNostrResolver::new(ssrf).with_ttls(Duration::from_secs(300), Duration::from_secs(60));

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
