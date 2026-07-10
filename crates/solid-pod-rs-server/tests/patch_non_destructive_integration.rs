//! Regression test for the PATCH data-loss bug (PRD-014 Seam C,
//! DDD-012 A2 non-destructive-write invariant).
//!
//! Before the fix, `handle_patch` seeded the working graph with an
//! empty `Graph::new()` and applied the incoming N3/SPARQL mutation on
//! top of it, then wrote the result back — silently discarding every
//! pre-existing triple on each incremental write. An agent appending one
//! triple to its personal knowledge graph would wipe the rest.
//!
//! These tests mount the full actix app via `build_app` and assert that
//! an N3 / SPARQL-Update PATCH inserting one triple PRESERVES all triples
//! already stored in the resource, and that a resource whose body the
//! patch engine cannot read back is REFUSED (409) rather than destroyed.

use std::sync::Arc;

use actix_web::test;
use bytes::Bytes;

use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::{build_app, AppState};

const RESOURCE: &str = "/kg/concepts";

// Two N-Triples already living in the resource before the PATCH.
const EXISTING_NTRIPLES: &str = concat!(
    "<http://example.org/alice> <http://example.org/knows> <http://example.org/bob> .\n",
    "<http://example.org/alice> <http://example.org/name> \"Alice\" .\n",
);

/// Public read+write ACL inheriting to every child via `acl:default </>`.
/// `acl:agentClass foaf:Agent` grants anonymous access, so the PATCH does
/// not need to carry NIP-98 auth — `enforce_write` resolves a grant for an
/// absent web_id and returns before the 401 branch.
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

#[actix_web::test]
async fn sparql_patch_preserves_existing_triples() {
    let storage = Arc::new(MemoryBackend::new());
    seed(storage.as_ref(), EXISTING_NTRIPLES, "text/turtle").await;
    let state = AppState::new(storage);
    let app = test::init_service(build_app(state)).await;

    let update = r#"INSERT DATA { <http://example.org/alice> <http://example.org/knows> <http://example.org/carol> . }"#;
    let req = test::TestRequest::patch()
        .uri(RESOURCE)
        .insert_header(("content-type", "application/sparql-update"))
        .set_payload(update)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        204,
        "PATCH should succeed with 204 No Content"
    );

    let get = test::TestRequest::get().uri(RESOURCE).to_request();
    let get_resp = test::call_service(&app, get).await;
    assert_eq!(get_resp.status().as_u16(), 200, "GET should be 200");
    let body = String::from_utf8(test::read_body(get_resp).await.to_vec()).unwrap();
    // The newly inserted triple is present...
    assert!(
        body.contains("<http://example.org/carol>"),
        "inserted triple missing after PATCH: {body}"
    );
    // ...AND the two pre-existing triples survived (the regression).
    assert!(
        body.contains("<http://example.org/bob>"),
        "pre-existing knows/bob triple was destroyed by PATCH: {body}"
    );
    assert!(
        body.contains("\"Alice\""),
        "pre-existing name/Alice triple was destroyed by PATCH: {body}"
    );
}

#[actix_web::test]
async fn n3_patch_preserves_existing_triples() {
    let storage = Arc::new(MemoryBackend::new());
    seed(storage.as_ref(), EXISTING_NTRIPLES, "text/turtle").await;
    let state = AppState::new(storage);
    let app = test::init_service(build_app(state)).await;

    let patch = r#"
        _:add a solid:InsertDeletePatch ;
          solid:inserts {
            <http://example.org/alice> <http://example.org/knows> <http://example.org/dave> .
          } .
    "#;
    let req = test::TestRequest::patch()
        .uri(RESOURCE)
        .insert_header(("content-type", "text/n3"))
        .set_payload(patch)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 204, "N3 PATCH should return 204");

    let get = test::TestRequest::get().uri(RESOURCE).to_request();
    let get_resp = test::call_service(&app, get).await;
    assert_eq!(get_resp.status().as_u16(), 200, "GET should be 200");
    let body = String::from_utf8(test::read_body(get_resp).await.to_vec()).unwrap();
    assert!(
        body.contains("<http://example.org/dave>"),
        "inserted triple missing after N3 PATCH: {body}"
    );
    assert!(
        body.contains("<http://example.org/bob>"),
        "pre-existing knows/bob triple was destroyed by N3 PATCH: {body}"
    );
    assert!(
        body.contains("\"Alice\""),
        "pre-existing name/Alice triple was destroyed by N3 PATCH: {body}"
    );
}

#[actix_web::test]
async fn patch_refuses_unparseable_body_rather_than_destroying_it() {
    // A resource whose stored body is NOT N-Triples (here, JSON). The
    // patch engine cannot read it back, so an RDF PATCH must fail closed
    // (409 Conflict) instead of overwriting it with just the new triple.
    let storage = Arc::new(MemoryBackend::new());
    let original = r#"{"not":"ntriples"}"#;
    seed(storage.as_ref(), original, "application/json").await;
    let state = AppState::new(storage.clone());
    let app = test::init_service(build_app(state)).await;

    let update = r#"INSERT DATA { <http://example.org/alice> <http://example.org/knows> <http://example.org/eve> . }"#;
    let req = test::TestRequest::patch()
        .uri(RESOURCE)
        .insert_header(("content-type", "application/sparql-update"))
        .set_payload(update)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        409,
        "RDF PATCH against a non-N-Triples resource must fail closed with 409"
    );

    // The original body is untouched on storage.
    let (body, _meta) = storage.get(RESOURCE).await.unwrap();
    assert_eq!(
        String::from_utf8(body.to_vec()).unwrap(),
        original,
        "non-RDF resource body must be left intact when PATCH is refused"
    );
}
