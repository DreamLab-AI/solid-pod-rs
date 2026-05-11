//! Container `index.html` content negotiation tests (khive ef97a6d1).
//!
//! When a GET request hits a container path and the `Accept` header
//! includes `text/html`, the server checks if an `index.html` resource
//! exists in the container. If yes, it serves that content with
//! `Content-Type: text/html`. If no, it falls through to the standard
//! LDP container listing (JSON-LD / Turtle).
//!
//! Solid clients requesting `text/turtle` or `application/ld+json`
//! always get the RDF container listing, regardless of whether
//! `index.html` exists.

use std::sync::Arc;

use actix_web::http::StatusCode;
use actix_web::test;
use bytes::Bytes;
use solid_pod_rs::security::DotfileAllowlist;
use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::{build_app, AppState, NodeInfoMeta};

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

async fn make_state() -> AppState {
    let backend = Arc::new(MemoryBackend::new());

    // Root ACL granting public access.
    let ttl = r#"
        @prefix acl: <http://www.w3.org/ns/auth/acl#> .
        @prefix foaf: <http://xmlns.com/foaf/0.1/> .
        <#public> a acl:Authorization ;
            acl:agentClass foaf:Agent ;
            acl:accessTo </> ;
            acl:default </> ;
            acl:mode acl:Read, acl:Write, acl:Append, acl:Control .
    "#;
    backend
        .put(
            "/.acl",
            Bytes::copy_from_slice(ttl.as_bytes()),
            "text/turtle",
        )
        .await
        .unwrap();

    // Seed a container with a .meta marker.
    backend
        .put(
            "/site/.meta",
            Bytes::from_static(b"# container marker"),
            "text/plain",
        )
        .await
        .unwrap();

    AppState {
        storage: backend,
        dotfiles: Arc::new(DotfileAllowlist::with_defaults()),
        body_cap: 10_000_000,
        nodeinfo: NodeInfoMeta {
            software_name: "solid-pod-rs-server".into(),
            software_version: "0.4.0".into(),
            open_registrations: false,
            total_users: 0,
            base_url: "https://pod.example".into(),
        },
        mashlib: solid_pod_rs::MashlibConfig::default(),
        mashlib_cdn: None,
        pay_config: solid_pod_rs::payments::PayConfig::default(),
    }
}

// ---------------------------------------------------------------------------
// Test: Accept text/html + index.html exists => serve index.html
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn container_get_html_with_index_serves_index_html() {
    let state = make_state().await;
    let storage = state.storage.clone();

    // Seed an index.html in the container.
    let html_content = b"<html><body>Hello from index</body></html>";
    storage
        .put(
            "/site/index.html",
            Bytes::copy_from_slice(html_content),
            "text/html",
        )
        .await
        .unwrap();

    let app = test::init_service(build_app(state)).await;

    let req = test::TestRequest::get()
        .uri("/site/")
        .insert_header(("accept", "text/html"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        ct.contains("text/html"),
        "content-type should be text/html, got: {ct}"
    );

    let body = test::read_body(resp).await;
    assert_eq!(&body[..], html_content);
}

// ---------------------------------------------------------------------------
// Test: Accept text/turtle => always get container listing, even when
//       index.html exists
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn container_get_turtle_ignores_index_html() {
    let state = make_state().await;
    let storage = state.storage.clone();

    // Seed an index.html.
    storage
        .put(
            "/site/index.html",
            Bytes::from_static(b"<html>ignored</html>"),
            "text/html",
        )
        .await
        .unwrap();

    let app = test::init_service(build_app(state)).await;

    let req = test::TestRequest::get()
        .uri("/site/")
        .insert_header(("accept", "text/turtle"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    // Should be JSON-LD (the default container representation), not text/html.
    assert!(
        ct.contains("application/ld+json"),
        "expected RDF container listing content-type, got: {ct}"
    );
}

// ---------------------------------------------------------------------------
// Test: Accept text/html but no index.html => fall through to RDF listing
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn container_get_html_without_index_falls_through_to_rdf() {
    let state = make_state().await;
    // No index.html seeded in /site/.

    let app = test::init_service(build_app(state)).await;

    let req = test::TestRequest::get()
        .uri("/site/")
        .insert_header(("accept", "text/html"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    // With mashlib disabled, should fall through to JSON-LD.
    assert!(
        ct.contains("application/ld+json"),
        "expected RDF container listing (mashlib off), got: {ct}"
    );
}

// ---------------------------------------------------------------------------
// Test: Accept application/ld+json => always get RDF, even with index.html
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn container_get_jsonld_ignores_index_html() {
    let state = make_state().await;
    let storage = state.storage.clone();

    storage
        .put(
            "/site/index.html",
            Bytes::from_static(b"<html>nope</html>"),
            "text/html",
        )
        .await
        .unwrap();

    let app = test::init_service(build_app(state)).await;

    let req = test::TestRequest::get()
        .uri("/site/")
        .insert_header(("accept", "application/ld+json"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        ct.contains("application/ld+json"),
        "Solid client should get JSON-LD, got: {ct}"
    );
}

// ---------------------------------------------------------------------------
// Test: Browser Accept header with multiple types including text/html
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn container_get_browser_accept_with_index_serves_html() {
    let state = make_state().await;
    let storage = state.storage.clone();

    let html = b"<html><body>Browser view</body></html>";
    storage
        .put(
            "/site/index.html",
            Bytes::copy_from_slice(html),
            "text/html",
        )
        .await
        .unwrap();

    let app = test::init_service(build_app(state)).await;

    // Typical browser Accept header.
    let req = test::TestRequest::get()
        .uri("/site/")
        .insert_header((
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.contains("text/html"));

    let body = test::read_body(resp).await;
    assert_eq!(&body[..], html);
}
