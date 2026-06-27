//! B3 — container listing must not enumerate children the caller cannot read.
//!
//! Under a publicly-readable root, a container holds two children: one that
//! inherits the public `acl:default` (readable) and one with a stricter own
//! `.acl` granting Read only to its owner. An anonymous GET of the container
//! must list the readable child and omit the restricted one — and must never
//! surface the restricted child's `.acl` sidecar (which would leak its name).

use std::sync::Arc;

use actix_web::test;
use bytes::Bytes;

use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::{build_app, AppState};

const PUBLIC_ROOT_ACL: &str = r#"
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<#public> a acl:Authorization ;
    acl:agentClass foaf:Agent ;
    acl:accessTo </> ;
    acl:default </> ;
    acl:mode acl:Read .
"#;

// Restricts /c/private.txt to a single owner agent — anonymous callers get
// nothing, overriding the inherited public default for this child.
const PRIVATE_CHILD_ACL: &str = r#"
@prefix acl: <http://www.w3.org/ns/auth/acl#> .

<#owner> a acl:Authorization ;
    acl:agent <did:nostr:owner> ;
    acl:accessTo </c/private.txt> ;
    acl:mode acl:Read, acl:Write, acl:Control .
"#;

async fn seed(storage: &dyn Storage) {
    storage
        .put("/.acl", Bytes::from(PUBLIC_ROOT_ACL), "text/turtle")
        .await
        .unwrap();
    storage
        .put("/c/visible.txt", Bytes::from_static(b"public"), "text/plain")
        .await
        .unwrap();
    storage
        .put("/c/private.txt", Bytes::from_static(b"secret"), "text/plain")
        .await
        .unwrap();
    storage
        .put("/c/private.txt.acl", Bytes::from(PRIVATE_CHILD_ACL), "text/turtle")
        .await
        .unwrap();
}

#[actix_web::test]
async fn container_listing_omits_unreadable_children() {
    let storage = Arc::new(MemoryBackend::new());
    seed(storage.as_ref()).await;
    let app = test::init_service(build_app(AppState::new(storage))).await;

    // Anonymous GET — granted on the container via the inherited public default.
    let req = test::TestRequest::get()
        .uri("/c/")
        .insert_header(("accept", "application/ld+json"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body = test::read_body(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let ids: Vec<String> = json
        .get("ldp:contains")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m.get("@id").and_then(|v| v.as_str()).map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    assert!(
        ids.iter().any(|i| i.ends_with("/c/visible.txt")),
        "readable child must be listed: {ids:?}"
    );
    assert!(
        !ids.iter().any(|i| i.contains("private.txt")),
        "unreadable child (and its .acl sidecar) must be hidden: {ids:?}"
    );
}
