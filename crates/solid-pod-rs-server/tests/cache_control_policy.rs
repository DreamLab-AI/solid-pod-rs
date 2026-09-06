//! ADR-2002 acceptance corpus — response cache-control policy.
//!
//! The gap these tests close: `Cache-Control` was decided from the response's
//! **media type** alone. RDF variants got `private, no-cache, must-revalidate`;
//! everything else — a private JPEG, a PDF, a JSON blob in an authenticated
//! container — went out with **no `Cache-Control` header at all**. Under
//! RFC 9111 §4.2.2 a response with no explicit freshness information may be
//! heuristically cached, and with no `private` directive a *shared* cache is
//! free to store it and re-serve it to a different user. A private response
//! was therefore advertised as publicly cacheable.
//!
//! The fix keys the policy on the response's **audience** — could an anonymous
//! client have received this same body? — rather than on its media type.
//!
//! Everything here runs through `build_app` + `actix_web::test` against the
//! in-memory backend, so the whole middleware and handler chain is exercised.

use std::sync::Arc;

use actix_web::http::header;
use actix_web::test;
use bytes::Bytes;
use solid_pod_rs::auth::nip98;
use solid_pod_rs::ldp::{CACHE_CONTROL_PRIVATE, CACHE_CONTROL_RDF};
use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::{build_app, AppState};

const SK_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn did_for_key() -> String {
    let sk = hex::decode(SK_HEX).unwrap();
    let signing = k256::schnorr::SigningKey::from_bytes(&sk).unwrap();
    format!(
        "did:nostr:{}",
        hex::encode(signing.verifying_key().to_bytes())
    )
}

/// Mint a NIP-98 `Authorization` header, with a distinct event id per call so
/// the server's single-use replay guard does not reject the second request.
fn nip98_auth(method: &str, path: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;
    static BASE: OnceLock<u64> = OnceLock::new();
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let base = *BASE.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(30)
    });
    let now = base + SEQ.fetch_add(1, Ordering::Relaxed);
    let url = format!("http://localhost:8080{path}");
    let token = nip98::mint_with_payload(&url, method, None, SK_HEX, now)
        .expect("nip98-schnorr is enabled in the workspace test build");
    format!("Nostr {token}")
}

/// A pod seeded with a public tree and a private one.
async fn seeded_state() -> AppState {
    let storage = Arc::new(MemoryBackend::new());

    // `/public/` — world-readable.
    let public_acl = r#"{
        "@graph": [{
            "@type": "acl:Authorization",
            "acl:agentClass": {"@id": "foaf:Agent"},
            "acl:accessTo": {"@id": "/public/"},
            "acl:default": {"@id": "/public/"},
            "acl:mode": {"@id": "acl:Read"}
        }]
    }"#;
    // `/private/` — only the test key's WebID.
    let private_acl = format!(
        r#"{{
        "@graph": [{{
            "@type": "acl:Authorization",
            "acl:agent": {{"@id": "{did}"}},
            "acl:accessTo": {{"@id": "/private/"}},
            "acl:default": {{"@id": "/private/"}},
            "acl:mode": [{{"@id": "acl:Read"}}, {{"@id": "acl:Control"}}]
        }}]
    }}"#,
        did = did_for_key()
    );

    for (path, body, ct) in [
        ("/public.acl", public_acl.to_string(), "application/ld+json"),
        ("/private.acl", private_acl, "application/ld+json"),
        (
            "/public/photo.png",
            "\u{89}PNG-not-really".to_string(),
            "image/png",
        ),
        (
            "/public/graph.ttl",
            "<#a> <#b> <#c> .".to_string(),
            "text/turtle",
        ),
        (
            "/private/photo.png",
            "\u{89}PNG-secret".to_string(),
            "image/png",
        ),
        (
            "/private/graph.ttl",
            "<#s> <#p> <#o> .".to_string(),
            "text/turtle",
        ),
        (
            "/private/report.pdf",
            "%PDF-1.7 secret".to_string(),
            "application/pdf",
        ),
    ] {
        storage
            .put(path, Bytes::from(body), ct)
            .await
            .expect("seed write");
    }

    AppState::new(storage)
}

fn cache_control<B>(rsp: &actix_web::dev::ServiceResponse<B>) -> Option<String> {
    rsp.headers()
        .get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn vary<B>(rsp: &actix_web::dev::ServiceResponse<B>) -> String {
    rsp.headers()
        .get(header::VARY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// A response is safe for a shared cache to store only if it says nothing
/// about privacy AND the body is genuinely public. This asserts the negative
/// we actually care about: the header must forbid shared caching.
fn assert_not_shared_cacheable<B>(rsp: &actix_web::dev::ServiceResponse<B>, what: &str) {
    let cc = cache_control(rsp).unwrap_or_else(|| {
        panic!("{what}: a private response MUST carry Cache-Control; it had none")
    });
    let lower = cc.to_ascii_lowercase();
    assert!(
        lower.contains("private") || lower.contains("no-store"),
        "{what}: Cache-Control {cc:?} does not forbid shared caching"
    );
}

// ---------------------------------------------------------------------------
// The finding: private NON-RDF responses carried no Cache-Control at all.
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn private_binary_response_is_not_publicly_cacheable() {
    let app = test::init_service(build_app(seeded_state().await)).await;
    let req = test::TestRequest::get()
        .uri("/private/photo.png")
        .insert_header((
            header::AUTHORIZATION,
            nip98_auth("GET", "/private/photo.png"),
        ))
        .to_request();
    let rsp = test::call_service(&app, req).await;

    assert_eq!(rsp.status().as_u16(), 200, "the owner may read it");
    // REGRESSION GUARD: this is the exact response that previously went out
    // with no Cache-Control header — an image/png is not RDF, so the
    // media-type-only policy returned None.
    assert_not_shared_cacheable(&rsp, "private image/png");
    assert_eq!(cache_control(&rsp).as_deref(), Some(CACHE_CONTROL_PRIVATE));
}

#[actix_web::test]
async fn private_pdf_response_is_not_publicly_cacheable() {
    let app = test::init_service(build_app(seeded_state().await)).await;
    let req = test::TestRequest::get()
        .uri("/private/report.pdf")
        .insert_header((
            header::AUTHORIZATION,
            nip98_auth("GET", "/private/report.pdf"),
        ))
        .to_request();
    let rsp = test::call_service(&app, req).await;

    assert_eq!(rsp.status().as_u16(), 200);
    assert_not_shared_cacheable(&rsp, "private application/pdf");
}

#[actix_web::test]
async fn private_rdf_response_is_no_store_not_merely_no_cache() {
    // RDF already got `private, no-cache, must-revalidate`, which forbids
    // re-use without revalidation but still permits STORAGE. A private
    // resource should not be written to an intermediary's disk at all.
    let app = test::init_service(build_app(seeded_state().await)).await;
    let req = test::TestRequest::get()
        .uri("/private/graph.ttl")
        .insert_header((
            header::AUTHORIZATION,
            nip98_auth("GET", "/private/graph.ttl"),
        ))
        .to_request();
    let rsp = test::call_service(&app, req).await;

    assert_eq!(rsp.status().as_u16(), 200);
    assert_eq!(cache_control(&rsp).as_deref(), Some(CACHE_CONTROL_PRIVATE));
    assert!(cache_control(&rsp).unwrap().contains("no-store"));
}

#[actix_web::test]
async fn private_responses_vary_on_authorization() {
    // A cache keyed on the request must not fuse an authenticated response
    // with the anonymous 403 for the same URL.
    let app = test::init_service(build_app(seeded_state().await)).await;
    let req = test::TestRequest::get()
        .uri("/private/photo.png")
        .insert_header((
            header::AUTHORIZATION,
            nip98_auth("GET", "/private/photo.png"),
        ))
        .to_request();
    let rsp = test::call_service(&app, req).await;

    assert!(
        vary(&rsp)
            .split(',')
            .any(|f| f.trim().eq_ignore_ascii_case("Authorization")),
        "expected Vary to include Authorization, got {:?}",
        vary(&rsp)
    );
}

// ---------------------------------------------------------------------------
// Public responses keep their existing, useful caching posture.
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn public_rdf_keeps_the_rdf_policy() {
    let app = test::init_service(build_app(seeded_state().await)).await;
    let req = test::TestRequest::get()
        .uri("/public/graph.ttl")
        .to_request();
    let rsp = test::call_service(&app, req).await;

    assert_eq!(rsp.status().as_u16(), 200);
    assert_eq!(
        cache_control(&rsp).as_deref(),
        Some(CACHE_CONTROL_RDF),
        "a world-readable RDF resource must keep the cheap-revalidation policy"
    );
}

#[actix_web::test]
async fn public_binary_is_left_to_ordinary_caching() {
    // The fix must not make every public asset uncacheable — that would be a
    // performance regression dressed up as a security fix.
    let app = test::init_service(build_app(seeded_state().await)).await;
    let req = test::TestRequest::get()
        .uri("/public/photo.png")
        .to_request();
    let rsp = test::call_service(&app, req).await;

    assert_eq!(rsp.status().as_u16(), 200);
    let cc = cache_control(&rsp);
    assert!(
        cc.is_none() || !cc.as_deref().unwrap().contains("no-store"),
        "a world-readable image must not be forced uncacheable, got {cc:?}"
    );
}

#[actix_web::test]
async fn an_authenticated_read_of_a_public_resource_stays_public() {
    // Presenting credentials does not make a world-readable body private:
    // an anonymous client would have received exactly the same bytes. Being
    // conservative here would needlessly defeat caching for logged-in users.
    let app = test::init_service(build_app(seeded_state().await)).await;
    let req = test::TestRequest::get()
        .uri("/public/graph.ttl")
        .insert_header((
            header::AUTHORIZATION,
            nip98_auth("GET", "/public/graph.ttl"),
        ))
        .to_request();
    let rsp = test::call_service(&app, req).await;

    assert_eq!(rsp.status().as_u16(), 200);
    assert_eq!(cache_control(&rsp).as_deref(), Some(CACHE_CONTROL_RDF));
}

// ---------------------------------------------------------------------------
// Containers and sidecars.
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn a_private_container_listing_is_not_publicly_cacheable() {
    // The listing discloses child names, so it is as sensitive as the bodies.
    let app = test::init_service(build_app(seeded_state().await)).await;
    let req = test::TestRequest::get()
        .uri("/private/")
        .insert_header((header::AUTHORIZATION, nip98_auth("GET", "/private/")))
        .to_request();
    let rsp = test::call_service(&app, req).await;

    assert_eq!(rsp.status().as_u16(), 200);
    assert_not_shared_cacheable(&rsp, "private container listing");
}

#[actix_web::test]
async fn an_acl_sidecar_read_is_always_private() {
    // Reading a `.acl` is elevated to Control and discloses the whole
    // authorisation graph, so it can never be treated as public — even if the
    // ACL itself grants public Read on the governed resource.
    let app = test::init_service(build_app(seeded_state().await)).await;
    let req = test::TestRequest::get()
        .uri("/public.acl")
        .insert_header((header::AUTHORIZATION, nip98_auth("GET", "/public.acl")))
        .to_request();
    let rsp = test::call_service(&app, req).await;

    // The test key holds no Control on `/public`, so this is denied — which is
    // itself correct. What must never happen is a 200 that is publicly
    // cacheable.
    if rsp.status().as_u16() == 200 {
        assert_not_shared_cacheable(&rsp, "ACL sidecar body");
    } else {
        assert!(
            rsp.status().is_client_error(),
            "an ACL read without Control must be denied, got {}",
            rsp.status().as_u16()
        );
    }
}

// ---------------------------------------------------------------------------
// The pure policy function, pinned directly.
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn the_policy_function_never_leaves_a_private_response_unmarked() {
    use solid_pod_rs::ldp::{cache_control_for_response, ResponseAudience};

    for ct in [
        "text/turtle",
        "application/ld+json",
        "image/png",
        "application/pdf",
        "application/octet-stream",
        "video/mp4",
        "",
    ] {
        assert_eq!(
            cache_control_for_response(ct, ResponseAudience::Private),
            Some(CACHE_CONTROL_PRIVATE),
            "a private {ct:?} response must always be marked"
        );
    }

    // Public keeps the media-type policy.
    assert_eq!(
        cache_control_for_response("text/turtle", ResponseAudience::Public),
        Some(CACHE_CONTROL_RDF)
    );
    assert_eq!(
        cache_control_for_response("image/png", ResponseAudience::Public),
        None
    );
}
