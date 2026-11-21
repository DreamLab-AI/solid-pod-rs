//! SP-PAR-277: a stored JSON-LD document (including a top-level `@graph`)
//! is served as Turtle when the client asks for `text/turtle`.
//!
//! Before, only an N-Triples-stored body was transcoded; stored JSON-LD went
//! out as JSON-LD whatever `Accept` said.

use std::sync::Arc;

use actix_web::test;
use bytes::Bytes;

use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::{build_app, AppState};

const PUBLIC_READ_ACL: &str = r#"
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .
<#p> a acl:Authorization ; acl:agentClass foaf:Agent ;
    acl:accessTo </> ; acl:default </> ; acl:mode acl:Read .
"#;

const GRAPH_DOC: &str = r#"{
  "@context": {"name": "http://xmlns.com/foaf/0.1/name",
               "knows": {"@id": "http://xmlns.com/foaf/0.1/knows", "@type": "@id"}},
  "@graph": [
    {"@id": "http://example.org/alice", "name": "Alice", "knows": "http://example.org/bob"},
    {"@id": "http://example.org/bob", "name": "Bob"}
  ]
}"#;

async fn get(stored: &str, ct: &str, accept: &str) -> (u16, String, String) {
    let storage = Arc::new(MemoryBackend::new());
    storage
        .put("/.acl", Bytes::from(PUBLIC_READ_ACL), "text/turtle")
        .await
        .unwrap();
    storage
        .put("/kg/doc", Bytes::from(stored.to_string()), ct)
        .await
        .unwrap();
    let app = test::init_service(build_app(AppState::new(storage))).await;
    let req = test::TestRequest::get()
        .uri("/kg/doc")
        .insert_header(("accept", accept))
        .to_request();
    let rsp = test::call_service(&app, req).await;
    let status = rsp.status().as_u16();
    let ct = rsp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = String::from_utf8_lossy(&test::read_body(rsp).await).into_owned();
    (status, ct, body)
}

#[actix_web::test]
async fn stored_jsonld_graph_is_served_as_turtle() {
    let (status, ct, body) = get(GRAPH_DOC, "application/ld+json", "text/turtle").await;
    assert_eq!(status, 200);
    assert!(ct.starts_with("text/turtle"), "{ct}");
    for expected in [
        "<http://example.org/alice> <http://xmlns.com/foaf/0.1/name> \"Alice\"",
        "<http://example.org/alice> <http://xmlns.com/foaf/0.1/knows> <http://example.org/bob>",
        "<http://example.org/bob> <http://xmlns.com/foaf/0.1/name> \"Bob\"",
    ] {
        assert!(body.contains(expected), "missing {expected:?} in {body}");
    }
}

#[actix_web::test]
async fn stored_jsonld_is_served_as_ntriples_too() {
    let (status, ct, body) = get(GRAPH_DOC, "application/ld+json", "application/n-triples").await;
    assert_eq!(status, 200);
    assert!(ct.starts_with("application/n-triples"), "{ct}");
    assert!(body.contains("\"Bob\""), "{body}");
}

#[actix_web::test]
async fn unreadable_jsonld_falls_back_to_verbatim() {
    // A remote context is never fetched, and broken JSON is never guessed at:
    // the stored bytes go out unchanged.
    for stored in [
        r#"{"@context": "https://remote.example/ctx", "@id": "http://example.org/a", "http://example.org/p": "v"}"#,
        "{ not json",
    ] {
        let (status, ct, body) = get(stored, "application/ld+json", "text/turtle").await;
        assert_eq!(status, 200);
        assert!(ct.starts_with("application/ld+json"), "{ct}");
        assert_eq!(body, stored);
    }
}

#[actix_web::test]
async fn jsonld_with_a_named_graph_is_not_flattened() {
    // A named graph cannot be shown as Turtle without losing its name: verbatim.
    let stored = r#"{"@id": "http://example.org/g", "@graph": [{"@id": "http://example.org/a", "http://example.org/p": "v"}]}"#;
    let (_, ct, body) = get(stored, "application/ld+json", "text/turtle").await;
    assert!(ct.starts_with("application/ld+json"), "{ct}");
    assert_eq!(body, stored);
}

#[actix_web::test]
async fn jsonld_requested_as_jsonld_is_unchanged() {
    let (_, ct, body) = get(GRAPH_DOC, "application/ld+json", "application/ld+json").await;
    assert!(ct.starts_with("application/ld+json"), "{ct}");
    assert_eq!(body, GRAPH_DOC);
}
