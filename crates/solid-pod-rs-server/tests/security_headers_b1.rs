//! B1 — stored-content hardening regression tests.
//!
//! A user who can write a world-readable resource must not be able to have
//! the pod serve it as inline, executable markup in the pod origin. Two
//! controls are asserted here:
//!
//! - `X-Content-Type-Options: nosniff` is present on every response
//!   (defeats MIME-sniffing of mis-typed uploads).
//! - `Content-Disposition: attachment` is present when a stored resource is
//!   *declared* an active type (text/html, SVG, JS, …) so it downloads
//!   instead of rendering; ordinary media (image/png, text/plain) stays
//!   inline.

use std::sync::Arc;

use actix_web::test;
use bytes::Bytes;

use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::{build_app, AppState};

const PUBLIC_RW_ACL: &str = r#"
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<#public> a acl:Authorization ;
    acl:agentClass foaf:Agent ;
    acl:accessTo </> ;
    acl:default </> ;
    acl:mode acl:Read, acl:Write, acl:Append .
"#;

async fn seed(storage: &dyn Storage, path: &str, body: &str, ct: &str) {
    storage
        .put("/.acl", Bytes::from(PUBLIC_RW_ACL), "text/turtle")
        .await
        .unwrap();
    storage
        .put(path, Bytes::from(body.to_string()), ct)
        .await
        .unwrap();
}

fn header<'a, B>(resp: &'a actix_web::dev::ServiceResponse<B>, name: &str) -> Option<&'a str> {
    resp.headers().get(name).and_then(|v| v.to_str().ok())
}

#[actix_web::test]
async fn stored_html_is_served_as_attachment_with_nosniff() {
    let storage = Arc::new(MemoryBackend::new());
    seed(
        storage.as_ref(),
        "/public/evil.html",
        "<script>alert(document.domain)</script>",
        "text/html",
    )
    .await;
    let app = test::init_service(build_app(AppState::new(storage))).await;

    let req = test::TestRequest::get()
        .uri("/public/evil.html")
        .insert_header(("accept", "*/*"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        header(&resp, "x-content-type-options"),
        Some("nosniff"),
        "every response must carry nosniff"
    );
    assert_eq!(
        header(&resp, "content-disposition"),
        Some("attachment"),
        "stored text/html must be served as an attachment"
    );
}

#[actix_web::test]
async fn stored_svg_is_served_as_attachment() {
    let storage = Arc::new(MemoryBackend::new());
    seed(
        storage.as_ref(),
        "/public/x.svg",
        r#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"#,
        "image/svg+xml",
    )
    .await;
    let app = test::init_service(build_app(AppState::new(storage))).await;

    let req = test::TestRequest::get()
        .uri("/public/x.svg")
        .insert_header(("accept", "*/*"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        header(&resp, "content-disposition"),
        Some("attachment"),
        "SVG can carry script and must download"
    );
}

#[actix_web::test]
async fn stored_image_stays_inline_but_keeps_nosniff() {
    let storage = Arc::new(MemoryBackend::new());
    seed(storage.as_ref(), "/public/pic.png", "not-really-png", "image/png").await;
    let app = test::init_service(build_app(AppState::new(storage))).await;

    let req = test::TestRequest::get()
        .uri("/public/pic.png")
        .insert_header(("accept", "*/*"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        header(&resp, "x-content-type-options"),
        Some("nosniff"),
        "nosniff applies to inline media too"
    );
    assert!(
        header(&resp, "content-disposition").is_none(),
        "ordinary media must remain inline (no forced download)"
    );
}

#[actix_web::test]
async fn nosniff_present_even_on_404() {
    let storage = Arc::new(MemoryBackend::new());
    let app = test::init_service(build_app(AppState::new(storage))).await;

    let req = test::TestRequest::get().uri("/nope").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(
        header(&resp, "x-content-type-options"),
        Some("nosniff"),
        "middleware must cover responses short-circuited before a handler"
    );
}
