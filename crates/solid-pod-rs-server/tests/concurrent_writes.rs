//! Per-resource write serialisation and conditional writes across every
//! LDP write path (PUT, PATCH, POST, DELETE).
//!
//! The 2026-11-01 JSS 0.0.224 parity audit kept 3–4 of 20 concurrent PATCH
//! inserts, every one answered 204: PATCH is read-modify-write, and without
//! a lock held across the read, the precondition check and the write, each
//! request reads the old body. POST had the same shape: it probes for a free
//! name and then writes, so two POSTs with one `Slug` could both mint the
//! same name and the second silently replaced the first.
//!
//! These run on `FsBackend` because its I/O yields to the runtime, so the
//! requests genuinely interleave; `MemoryBackend` never yields and would
//! pass without any lock.

use std::collections::HashSet;
use std::sync::Arc;

use actix_web::test;
use bytes::Bytes;

use solid_pod_rs::storage::fs::FsBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::{build_app, AppState};

const PUBLIC_RW_ACL: &str = "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
     @prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
     <#public> a acl:Authorization ; acl:agentClass foaf:Agent ;\n\
       acl:accessTo </> ; acl:default </> ;\n\
       acl:mode acl:Read, acl:Write, acl:Append .\n";

const N: usize = 20;

async fn fs_storage(dir: &tempfile::TempDir) -> Arc<dyn Storage> {
    let s: Arc<dyn Storage> = Arc::new(FsBackend::new(dir.path()).await.unwrap());
    s.put("/.acl", Bytes::from(PUBLIC_RW_ACL), "text/turtle")
        .await
        .unwrap();
    s
}

/// Twenty concurrent PATCH inserts into one resource all land. Full IRIs
/// only, so the request is valid for every N3 Patch reader this crate has
/// shipped and a failure can only come from lost updates.
#[actix_web::test]
async fn concurrent_patch_inserts_with_full_iris_all_land() {
    let dir = tempfile::tempdir().unwrap();
    let storage = fs_storage(&dir).await;
    storage
        .put("/public/log.ttl", Bytes::from(""), "text/turtle")
        .await
        .unwrap();
    let app = test::init_service(build_app(AppState::new(storage))).await;

    let requests = (0..N).map(|i| {
        let body = format!(
            "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n\
             _:p a solid:InsertDeletePatch; solid:inserts {{ \
             <http://example.org/c{i}> <http://example.org/p> \"m{i}\" . }}."
        );
        test::call_service(
            &app,
            test::TestRequest::patch()
                .uri("/public/log.ttl")
                .insert_header(("content-type", "text/n3"))
                .set_payload(body)
                .to_request(),
        )
    });
    let responses = futures_util::future::join_all(requests).await;
    for r in &responses {
        assert!(r.status().is_success(), "PATCH status {}", r.status());
    }
    let resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/public/log.ttl").to_request(),
    )
    .await;
    let stored = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
    let kept = (0..N)
        .filter(|i| stored.contains(&format!("<http://example.org/c{i}>")))
        .count();
    assert_eq!(kept, N, "lost updates, kept {kept} of {N}: {stored}");
}

/// Twenty concurrent POSTs with the same `Slug` create twenty distinct
/// resources, each holding its own body.
#[actix_web::test]
async fn concurrent_posts_with_one_slug_never_overwrite_each_other() {
    let dir = tempfile::tempdir().unwrap();
    let storage = fs_storage(&dir).await;
    storage.create_container("/public/").await.unwrap();
    let app = test::init_service(build_app(AppState::new(storage.clone()))).await;

    let requests = (0..N).map(|i| {
        test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/public/")
                .insert_header(("content-type", "text/plain"))
                .insert_header(("slug", "note.txt"))
                .set_payload(format!("body {i}"))
                .to_request(),
        )
    });
    let responses = futures_util::future::join_all(requests).await;
    let mut locations = HashSet::new();
    for r in &responses {
        assert_eq!(r.status().as_u16(), 201, "POST status");
        let loc = r
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .expect("POST returns Location")
            .to_string();
        locations.insert(loc);
    }
    assert_eq!(locations.len(), N, "POSTs shared a target: {locations:?}");

    let mut bodies = HashSet::new();
    for loc in &locations {
        let (bytes, _) = storage.get(loc).await.unwrap();
        bodies.insert(String::from_utf8(bytes.to_vec()).unwrap());
    }
    assert_eq!(bodies.len(), N, "a POST body was overwritten: {bodies:?}");
}

/// PUT `body` to `/public/doc.txt` and return the new ETag.
macro_rules! put_doc {
    ($app:expr, $body:expr) => {{
        let resp = test::call_service(
            $app,
            test::TestRequest::put()
                .uri("/public/doc.txt")
                .insert_header(("content-type", "text/plain"))
                .set_payload($body)
                .to_request(),
        )
        .await;
        assert!(resp.status().is_success(), "PUT status {}", resp.status());
        resp.headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .expect("PUT returns an ETag")
            .to_string()
    }};
}

/// DELETE evaluates `If-Match` against the stored ETag (RFC 9110 §13.1.1):
/// a stale tag is refused and leaves the resource in place.
#[actix_web::test]
async fn delete_honours_if_match() {
    let dir = tempfile::tempdir().unwrap();
    let storage = fs_storage(&dir).await;
    let app = test::init_service(build_app(AppState::new(storage.clone()))).await;

    let stale = put_doc!(&app, "v1");
    let current = put_doc!(&app, "v2");
    assert_ne!(stale, current);

    let resp = test::call_service(
        &app,
        test::TestRequest::delete()
            .uri("/public/doc.txt")
            .insert_header(("if-match", stale))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 412, "stale If-Match on DELETE");
    assert!(storage.exists("/public/doc.txt").await.unwrap());

    let resp = test::call_service(
        &app,
        test::TestRequest::delete()
            .uri("/public/doc.txt")
            .insert_header(("if-match", current))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 204, "current If-Match on DELETE");
    assert!(!storage.exists("/public/doc.txt").await.unwrap());
}

/// `If-None-Match` naming the current ETag refuses a write (RFC 9110
/// §13.1.2: 412 for a state-changing method, never 304).
#[actix_web::test]
async fn if_none_match_with_the_current_etag_refuses_put() {
    let dir = tempfile::tempdir().unwrap();
    let storage = fs_storage(&dir).await;
    let app = test::init_service(build_app(AppState::new(storage.clone()))).await;

    let current = put_doc!(&app, "v1");
    let resp = test::call_service(
        &app,
        test::TestRequest::put()
            .uri("/public/doc.txt")
            .insert_header(("content-type", "text/plain"))
            .insert_header(("if-none-match", current))
            .set_payload("v2")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 412);
    let (bytes, _) = storage.get("/public/doc.txt").await.unwrap();
    assert_eq!(&bytes[..], b"v1");
}
