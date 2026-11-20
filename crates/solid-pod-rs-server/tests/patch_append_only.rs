//! SP-PAR-273: a PATCH that provably inserts and deletes nothing is
//! authorised as `acl:Append`; anything else still needs `acl:Write`.
//!
//! The pod root grants the anonymous class `acl:Append` only (no Read, no
//! Write), so every allowed PATCH here passed the Append check alone and every
//! refused one was refused for lack of Write. Stored content is read straight
//! from the backend, because the caller has no Read.

use std::sync::Arc;

use actix_web::test;
use bytes::Bytes;

use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::{build_app, AppState};

const RESOURCE: &str = "/inbox/log";
const EXISTING: &str =
    "<http://example.org/alice> <http://example.org/knows> <http://example.org/bob> .\n";

const APPEND_ONLY_ACL: &str = r#"
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<#append> a acl:Authorization ;
    acl:agentClass foaf:Agent ;
    acl:accessTo </> ;
    acl:default </> ;
    acl:mode acl:Append .
"#;

const WRITE_ACL: &str = r#"
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<#write> a acl:Authorization ;
    acl:agentClass foaf:Agent ;
    acl:accessTo </> ;
    acl:default </> ;
    acl:mode acl:Read, acl:Write, acl:Append .
"#;

const N3_HEAD: &str = "@prefix solid: <http://www.w3.org/ns/solid/terms#> .\n";
const CAROL: &str =
    "<http://example.org/alice> <http://example.org/knows> <http://example.org/carol> .";
const BOB: &str =
    "<http://example.org/alice> <http://example.org/knows> <http://example.org/bob> .";
const GHOST: &str =
    "<http://example.org/alice> <http://example.org/knows> <http://example.org/ghost> .";

async fn pod(acl: &str) -> Arc<MemoryBackend> {
    let storage = Arc::new(MemoryBackend::new());
    storage
        .put("/.acl", Bytes::from(acl.to_string()), "text/turtle")
        .await
        .unwrap();
    storage
        .put(RESOURCE, Bytes::from(EXISTING), "text/turtle")
        .await
        .unwrap();
    storage
}

async fn patch(storage: &Arc<MemoryBackend>, uri: &str, ct: &str, body: &str) -> u16 {
    let app = test::init_service(build_app(AppState::new(storage.clone()))).await;
    let req = test::TestRequest::patch()
        .uri(uri)
        .insert_header(("content-type", ct))
        .set_payload(body.to_string())
        .to_request();
    test::call_service(&app, req).await.status().as_u16()
}

async fn stored(storage: &Arc<MemoryBackend>) -> String {
    let (body, _) = storage.get(RESOURCE).await.unwrap();
    String::from_utf8(body.to_vec()).unwrap()
}

/// Refused for lack of permission (401 anonymous, 403 authenticated), and the
/// stored body is untouched.
async fn assert_refused(ct: &str, body: &str) {
    let storage = pod(APPEND_ONLY_ACL).await;
    let status = patch(&storage, RESOURCE, ct, body).await;
    assert!(
        status == 401 || status == 403,
        "expected 401/403 for {body:?}, got {status}"
    );
    assert_eq!(stored(&storage).await, EXISTING, "body changed: {body:?}");
}

/// Accepted under Append alone, keeping what was stored and adding carol.
async fn assert_appended(ct: &str, body: &str) {
    let storage = pod(APPEND_ONLY_ACL).await;
    let status = patch(&storage, RESOURCE, ct, body).await;
    assert_eq!(status, 204, "expected 204 for {body:?}");
    let now = stored(&storage).await;
    assert!(now.contains("carol"), "insert missing: {now}");
    assert!(now.contains("bob"), "existing triple lost: {now}");
}

#[actix_web::test]
async fn n3_insert_only_needs_only_append() {
    let body = format!("{N3_HEAD}_:p a solid:InsertDeletePatch ; solid:inserts {{ {CAROL} }} .");
    assert_appended("text/n3", &body).await;
}

#[actix_web::test]
async fn n3_empty_delete_block_is_still_insert_only() {
    let body = format!(
        "{N3_HEAD}_:p a solid:InsertDeletePatch ; solid:deletes {{ }} ; solid:inserts {{ {CAROL} }} ."
    );
    assert_appended("text/n3", &body).await;
}

#[actix_web::test]
async fn sparql_insert_data_needs_only_append() {
    assert_appended(
        "application/sparql-update",
        &format!("INSERT DATA {{ {CAROL} }}"),
    )
    .await;
}

#[actix_web::test]
async fn sparql_empty_delete_data_alongside_insert_data_is_insert_only() {
    assert_appended(
        "application/sparql-update",
        &format!("DELETE DATA {{ }} ; INSERT DATA {{ {CAROL} }}"),
    )
    .await;
}

#[actix_web::test]
async fn append_only_insert_creates_an_absent_resource() {
    let storage = pod(APPEND_ONLY_ACL).await;
    let body = format!("INSERT DATA {{ {CAROL} }}");
    let status = patch(&storage, "/inbox/new", "application/sparql-update", &body).await;
    assert_eq!(status, 201);
}

#[actix_web::test]
async fn n3_delete_needs_write() {
    let body = format!(
        "{N3_HEAD}_:p a solid:InsertDeletePatch ; solid:deletes {{ {BOB} }} ; solid:inserts {{ {CAROL} }} ."
    );
    assert_refused("text/n3", &body).await;
}

#[actix_web::test]
async fn n3_delete_of_an_absent_triple_still_needs_write() {
    let body = format!(
        "{N3_HEAD}_:p a solid:InsertDeletePatch ; solid:deletes {{ {GHOST} }} ; solid:inserts {{ {CAROL} }} ."
    );
    assert_refused("text/n3", &body).await;
}

#[actix_web::test]
async fn n3_where_driven_patch_needs_write() {
    let body = format!(
        "{N3_HEAD}_:p a solid:InsertDeletePatch ; solid:where {{ ?s <http://example.org/knows> ?o }} ; solid:inserts {{ {CAROL} }} ."
    );
    assert_refused("text/n3", &body).await;
}

#[actix_web::test]
async fn n3_that_does_not_parse_needs_write() {
    assert_refused("text/n3", "this is not n3 {{{").await;
}

#[actix_web::test]
async fn sparql_deletes_need_write() {
    for body in [
        format!("DELETE DATA {{ {BOB} }}"),
        format!("DELETE DATA {{ {GHOST} }}"),
        format!("INSERT DATA {{ {CAROL} }} ; DELETE DATA {{ {BOB} }}"),
        "DELETE WHERE { ?s ?p ?o }".to_string(),
        format!("DELETE {{ ?s ?p ?o }} INSERT {{ {CAROL} }} WHERE {{ ?s ?p ?o }}"),
        format!("INSERT {{ {CAROL} }} WHERE {{ ?s ?p ?o }}"),
        "CLEAR DEFAULT".to_string(),
        "DROP ALL".to_string(),
        String::new(),
        "not sparql".to_string(),
    ] {
        assert_refused("application/sparql-update", &body).await;
    }
}

#[actix_web::test]
async fn json_patch_needs_write() {
    assert_refused(
        "application/json-patch+json",
        r#"[{"op":"add","path":"/x","value":1}]"#,
    )
    .await;
}

#[actix_web::test]
async fn append_does_not_reach_an_acl_sidecar() {
    let storage = pod(APPEND_ONLY_ACL).await;
    let body =
        "INSERT DATA { <http://example.org/a> <http://example.org/b> <http://example.org/c> }";
    let status = patch(
        &storage,
        "/inbox/log.acl",
        "application/sparql-update",
        body,
    )
    .await;
    assert!(status == 401 || status == 403, "got {status}");
    let (acl, _) = storage.get("/.acl").await.unwrap();
    assert_eq!(acl, Bytes::from(APPEND_ONLY_ACL));
}

#[actix_web::test]
async fn write_grant_still_deletes_and_absent_delete_conflicts() {
    let storage = pod(WRITE_ACL).await;
    let body = format!("{N3_HEAD}_:p a solid:InsertDeletePatch ; solid:deletes {{ {BOB} }} ; solid:inserts {{ {CAROL} }} .");
    assert_eq!(patch(&storage, RESOURCE, "text/n3", &body).await, 204);
    let now = stored(&storage).await;
    assert!(now.contains("carol") && !now.contains("bob"), "{now}");

    let body = format!("{N3_HEAD}_:p a solid:InsertDeletePatch ; solid:deletes {{ {GHOST} }} .");
    assert_eq!(patch(&storage, RESOURCE, "text/n3", &body).await, 409);
}

#[actix_web::test]
async fn no_grant_at_all_refuses_even_an_insert() {
    let storage = pod("").await;
    storage
        .put(
            "/.acl",
            Bytes::from("@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n"),
            "text/turtle",
        )
        .await
        .unwrap();
    let body = format!("INSERT DATA {{ {CAROL} }}");
    let status = patch(&storage, RESOURCE, "application/sparql-update", &body).await;
    assert!(status == 401 || status == 403, "got {status}");
}
