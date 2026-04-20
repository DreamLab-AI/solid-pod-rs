//! Sprint 7 D — server route table integration tests.
//!
//! Drives the actix-web `App` that the `solid-pod-rs-server` binary
//! serves through `actix_web::test::init_service`, asserting JSS-parity
//! behaviour for every route the binary mounts.
//!
//! Tests are ordered by surface: container POST with Slug, PATCH
//! dialect dispatch, OPTIONS envelope, and the four `.well-known/*`
//! discovery endpoints.

use std::sync::Arc;

use actix_web::http::StatusCode;
use actix_web::test;
use bytes::Bytes;
use solid_pod_rs::security::DotfileAllowlist;
use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::{build_app, AppState, NodeInfoMeta};

// ---------------------------------------------------------------------------
// Test harness — in-memory storage, permissive ACL, deterministic base URL.
// ---------------------------------------------------------------------------

async fn make_state() -> AppState {
    let backend = Arc::new(MemoryBackend::new());

    // Seed a root ACL that grants Read+Write+Append+Control to the
    // public so WAC enforcement does not block the happy-path tests.
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
        .put("/.acl", Bytes::copy_from_slice(ttl.as_bytes()), "text/turtle")
        .await
        .unwrap();

    // Seed the POST target container so the storage list lookup has
    // something to anchor to.
    backend
        .put(
            "/photos/.meta",
            Bytes::from_static(b"# empty"),
            "text/plain",
        )
        .await
        .unwrap();

    let mut state = AppState {
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
        mashlib_cdn: None,
    };
    state.nodeinfo.base_url = "https://pod.example".into();
    state
}

// ---------------------------------------------------------------------------
// Container POST with Slug
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn server_post_to_container_creates_child_with_slug() {
    let state = make_state().await;
    let storage = state.storage.clone();
    let app = test::init_service(build_app(state)).await;

    let req = test::TestRequest::post()
        .uri("/photos/")
        .insert_header(("slug", "cat.jpg"))
        .insert_header(("content-type", "image/jpeg"))
        .set_payload(Bytes::from_static(b"FAKEJPG"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED, "status = {:?}", resp.status());

    let (body, _meta) = storage.get("/photos/cat.jpg").await.unwrap();
    assert_eq!(&body[..], b"FAKEJPG");
}

#[actix_web::test]
async fn server_post_to_container_returns_201_with_location() {
    let state = make_state().await;
    let app = test::init_service(build_app(state)).await;

    let req = test::TestRequest::post()
        .uri("/photos/")
        .insert_header(("slug", "dog.png"))
        .insert_header(("content-type", "image/png"))
        .set_payload(Bytes::from_static(b"FAKEPNG"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(loc, "/photos/dog.png");
}

#[actix_web::test]
async fn server_post_with_invalid_slug_returns_400() {
    let state = make_state().await;
    let app = test::init_service(build_app(state)).await;

    let req = test::TestRequest::post()
        .uri("/photos/")
        .insert_header(("slug", "../escape"))
        .insert_header(("content-type", "text/plain"))
        .set_payload(Bytes::from_static(b"x"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// PATCH dialect dispatcher
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn server_patch_n3_mutates_existing_resource() {
    let state = make_state().await;
    let storage = state.storage.clone();
    // Seed an existing Turtle resource.
    storage
        .put(
            "/notes/a",
            Bytes::from_static(b"# empty\n"),
            "text/turtle",
        )
        .await
        .unwrap();

    let app = test::init_service(build_app(state)).await;

    let n3 = r#"
        @prefix solid: <http://www.w3.org/ns/solid/terms#> .
        _:rename a solid:InsertDeletePatch ;
            solid:inserts { <#a> <p> <o> . } .
    "#;
    let req = test::TestRequest::patch()
        .uri("/notes/a")
        .insert_header(("content-type", "text/n3"))
        .set_payload(Bytes::copy_from_slice(n3.as_bytes()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "status = {:?}",
        resp.status()
    );
}

#[actix_web::test]
async fn server_patch_sparql_inserts_into_empty_resource_returns_201() {
    let state = make_state().await;
    let app = test::init_service(build_app(state)).await;

    let sparql = "INSERT DATA { <http://s> <http://p> <http://o> }";
    let req = test::TestRequest::patch()
        .uri("/notes/brand-new")
        .insert_header(("content-type", "application/sparql-update"))
        .set_payload(Bytes::copy_from_slice(sparql.as_bytes()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "status = {:?}",
        resp.status()
    );
}

#[actix_web::test]
async fn server_patch_unknown_dialect_returns_415() {
    let state = make_state().await;
    let storage = state.storage.clone();
    storage
        .put("/notes/b", Bytes::from_static(b"# empty"), "text/turtle")
        .await
        .unwrap();

    let app = test::init_service(build_app(state)).await;

    let req = test::TestRequest::patch()
        .uri("/notes/b")
        .insert_header(("content-type", "application/toml-patch"))
        .set_payload(Bytes::from_static(b"foo = 1"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

// ---------------------------------------------------------------------------
// OPTIONS
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn server_options_container_advertises_accept_post_and_accept_patch() {
    let state = make_state().await;
    let app = test::init_service(build_app(state)).await;

    let req = test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/photos/")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success() || resp.status() == StatusCode::NO_CONTENT);
    assert!(resp.headers().contains_key("accept-post"));
    assert!(resp.headers().contains_key("accept-patch"));
    let allow = resp
        .headers()
        .get("allow")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(allow.contains("POST"));
}

#[actix_web::test]
async fn server_options_resource_omits_accept_post() {
    let state = make_state().await;
    let storage = state.storage.clone();
    storage
        .put("/notes/c", Bytes::from_static(b"x"), "text/plain")
        .await
        .unwrap();

    let app = test::init_service(build_app(state)).await;

    let req = test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/notes/c")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(!resp.headers().contains_key("accept-post"));
    assert!(resp.headers().contains_key("accept-patch"));
    let allow = resp
        .headers()
        .get("allow")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(allow.contains("PATCH"));
    assert!(allow.contains("PUT"));
}

// ---------------------------------------------------------------------------
// Well-known discovery routes
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn server_well_known_solid_returns_jsonld() {
    let state = make_state().await;
    let app = test::init_service(build_app(state)).await;
    let req = test::TestRequest::get()
        .uri("/.well-known/solid")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.starts_with("application/ld+json"), "got {ct}");

    let body = test::read_body(resp).await;
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v.get("storage").is_some(), "body = {v}");
}

#[actix_web::test]
async fn server_well_known_webfinger_returns_jrd() {
    let state = make_state().await;
    let app = test::init_service(build_app(state)).await;
    let req = test::TestRequest::get()
        .uri("/.well-known/webfinger?resource=acct:alice@pod.example")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.starts_with("application/jrd+json"), "got {ct}");
}

#[actix_web::test]
async fn server_well_known_nodeinfo_advertises_2_1() {
    let state = make_state().await;
    let app = test::init_service(build_app(state)).await;
    let req = test::TestRequest::get()
        .uri("/.well-known/nodeinfo")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let links = v.get("links").and_then(|l| l.as_array()).unwrap();
    assert!(links.iter().any(|link| link
        .get("rel")
        .and_then(|r| r.as_str())
        == Some("http://nodeinfo.diaspora.software/ns/schema/2.1")));
}

#[actix_web::test]
async fn server_well_known_nodeinfo_2_1_includes_solid_and_activitypub() {
    let state = make_state().await;
    let app = test::init_service(build_app(state)).await;
    let req = test::TestRequest::get()
        .uri("/.well-known/nodeinfo/2.1")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let protos = v.get("protocols").and_then(|p| p.as_array()).unwrap();
    assert!(protos.iter().any(|p| p.as_str() == Some("solid")));
    assert!(protos.iter().any(|p| p.as_str() == Some("activitypub")));
}
