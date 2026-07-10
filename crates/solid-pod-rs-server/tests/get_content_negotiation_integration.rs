//! Integration tests for RDF content negotiation on GET (PRD-014 Seam C
//! / C4). KG resources persist as N-Triples (see the PATCH handler); an
//! agent or extractor must be able to GET the same graph as Turtle,
//! N-Triples, or JSON-LD by setting `Accept`. Requests that name no
//! concrete RDF type (browsers send `*/*`) and non-RDF resources MUST be
//! served verbatim — negotiation only transcodes when explicitly asked.

use std::sync::Arc;

use actix_web::test;
use bytes::Bytes;

use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::{build_app, AppState};

const RESOURCE: &str = "/kg/concepts";

const EXISTING_NTRIPLES: &str = concat!(
    "<http://example.org/alice> <http://example.org/knows> <http://example.org/bob> .\n",
    "<http://example.org/alice> <http://example.org/name> \"Alice\" .\n",
);

const PUBLIC_RW_ACL: &str = r#"
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<#public> a acl:Authorization ;
    acl:agentClass foaf:Agent ;
    acl:accessTo </> ;
    acl:default </> ;
    acl:mode acl:Read, acl:Write, acl:Append .
"#;

async fn seed(storage: &dyn Storage, resource_body: &str, resource_ct: &str) {
    storage
        .put("/.acl", Bytes::from(PUBLIC_RW_ACL), "text/turtle")
        .await
        .unwrap();
    storage
        .put(
            RESOURCE,
            Bytes::from(resource_body.to_string()),
            resource_ct,
        )
        .await
        .unwrap();
}

fn content_type<B>(resp: &actix_web::dev::ServiceResponse<B>) -> String {
    resp.headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

#[actix_web::test]
async fn get_transcodes_ntriples_to_jsonld() {
    let storage = Arc::new(MemoryBackend::new());
    seed(storage.as_ref(), EXISTING_NTRIPLES, "application/n-triples").await;
    let state = AppState::new(storage);
    let app = test::init_service(build_app(state)).await;

    let req = test::TestRequest::get()
        .uri(RESOURCE)
        .insert_header(("accept", "application/ld+json"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "GET should be 200");
    assert!(
        content_type(&resp).starts_with("application/ld+json"),
        "expected JSON-LD content-type, got {}",
        content_type(&resp)
    );
    assert_eq!(
        resp.headers()
            .get("vary")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        "Accept",
        "negotiated response must carry Vary: Accept"
    );

    let body = test::read_body(resp).await;
    let json: serde_json::Value =
        serde_json::from_slice(&body).expect("negotiated body must be valid JSON-LD");
    assert!(
        json.is_array(),
        "JSON-LD expanded form is an array of nodes"
    );
    let text = json.to_string();
    assert!(
        text.contains("http://example.org/bob"),
        "knows/bob triple missing from JSON-LD: {text}"
    );
    assert!(
        text.contains("Alice"),
        "name/Alice triple missing from JSON-LD: {text}"
    );
}

#[actix_web::test]
async fn get_transcodes_ntriples_to_turtle() {
    let storage = Arc::new(MemoryBackend::new());
    seed(storage.as_ref(), EXISTING_NTRIPLES, "application/n-triples").await;
    let state = AppState::new(storage);
    let app = test::init_service(build_app(state)).await;

    let req = test::TestRequest::get()
        .uri(RESOURCE)
        .insert_header(("accept", "text/turtle"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "GET should be 200");
    assert!(
        content_type(&resp).starts_with("text/turtle"),
        "expected Turtle content-type, got {}",
        content_type(&resp)
    );
    let body = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
    assert!(
        body.contains("<http://example.org/bob>") && body.contains("\"Alice\""),
        "Turtle body must contain the stored triples: {body}"
    );
}

#[actix_web::test]
async fn get_serves_verbatim_for_wildcard_accept() {
    // A browser-style `*/*` Accept names no concrete RDF type, so the
    // resource is returned verbatim in its stored serialisation.
    let storage = Arc::new(MemoryBackend::new());
    seed(storage.as_ref(), EXISTING_NTRIPLES, "application/n-triples").await;
    let state = AppState::new(storage);
    let app = test::init_service(build_app(state)).await;

    let req = test::TestRequest::get()
        .uri(RESOURCE)
        .insert_header(("accept", "*/*"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "GET should be 200");
    assert!(
        content_type(&resp).starts_with("application/n-triples"),
        "wildcard Accept must yield the stored content-type verbatim, got {}",
        content_type(&resp)
    );
}

#[actix_web::test]
async fn get_serves_verbatim_for_non_rdf_resource() {
    // A non-RDF resource (JSON) is never transcoded, regardless of Accept.
    let storage = Arc::new(MemoryBackend::new());
    let original = r#"{"not":"rdf"}"#;
    seed(storage.as_ref(), original, "application/json").await;
    let state = AppState::new(storage);
    let app = test::init_service(build_app(state)).await;

    let req = test::TestRequest::get()
        .uri(RESOURCE)
        .insert_header(("accept", "text/turtle"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "GET should be 200");
    assert!(
        content_type(&resp).starts_with("application/json"),
        "non-RDF resource must be served verbatim, got {}",
        content_type(&resp)
    );
    let body = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
    assert_eq!(body, original, "non-RDF body must be byte-identical");
}
