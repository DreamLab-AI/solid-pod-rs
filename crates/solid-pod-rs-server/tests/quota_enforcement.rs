#![cfg(feature = "quota")]

use std::sync::Arc;

use actix_web::test;
use bytes::Bytes;
use solid_pod_rs::quota::{FsQuotaStore, QuotaPolicy};
use solid_pod_rs::storage::{memory::MemoryBackend, Storage};
use solid_pod_rs_server::{build_app, AppState};

#[actix_web::test]
async fn server_write_paths_cannot_overcommit_atomic_pod_quota() {
    let storage = Arc::new(MemoryBackend::new());
    storage
        .put(
            "/alice.acl",
            Bytes::from_static(
                br##"{
                  "@graph": [{
                    "@id": "#public-write",
                    "@type": "acl:Authorization",
                    "acl:agentClass": {"@id": "foaf:Agent"},
                    "acl:default": {"@id": "/alice/"},
                    "acl:mode": [{"@id": "acl:Write"}, {"@id": "acl:Read"}]
                  }]
                }"##,
            ),
            "application/ld+json",
        )
        .await
        .unwrap();

    let quota_dir = tempfile::tempdir().unwrap();
    let quota = Arc::new(FsQuotaStore::new(quota_dir.path().to_path_buf(), 10));
    let mut state = AppState::new(storage);
    state.quota = Some(quota.clone());
    let app = test::init_service(build_app(state)).await;

    let first = test::TestRequest::put()
        .uri("/alice/first")
        .set_payload("12345678")
        .to_request();
    assert_eq!(test::call_service(&app, first).await.status().as_u16(), 201);

    let second = test::TestRequest::put()
        .uri("/alice/second")
        .set_payload("12345")
        .to_request();
    assert_eq!(
        test::call_service(&app, second).await.status().as_u16(),
        507
    );
    assert_eq!(quota.usage("alice").await.unwrap().used_bytes, 8);
}
