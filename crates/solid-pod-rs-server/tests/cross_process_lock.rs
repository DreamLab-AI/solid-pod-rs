//! SP-PAR-275: the server's write path takes the storage backend's
//! cross-process lock, so a write waits while another process (here a second
//! `FsBackend` handle on the same directory) holds the resource, and proceeds
//! when it lets go. Property preserved: a read-modify-write on a resource is
//! never interleaved with another process's. Catching test: remove the
//! `lock_exclusive` call from `lock_resource_pod` and the elapsed-time
//! assertion fails (the PUT would not wait).
#![cfg(unix)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use actix_web::test;
use bytes::Bytes;
use solid_pod_rs::storage::fs::FsBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::{build_app, AppState};

const OPEN_ACL: &str = "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
     @prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
     <#all> a acl:Authorization ; acl:agentClass foaf:Agent ;\n\
       acl:accessTo </> ; acl:default </> ; acl:mode acl:Read, acl:Write, acl:Control .\n";

#[actix_web::test]
async fn a_write_waits_for_another_process_holding_the_resource() {
    let dir = tempfile::tempdir().unwrap();
    let ours = Arc::new(FsBackend::new(dir.path()).await.unwrap());
    let other = FsBackend::new(dir.path()).await.unwrap();
    ours.put("/.acl", Bytes::from(OPEN_ACL), "text/turtle")
        .await
        .unwrap();
    ours.put("/doc.txt", Bytes::from("v0"), "text/plain")
        .await
        .unwrap();
    let app = test::init_service(build_app(AppState::new(ours.clone()))).await;

    let held = other
        .lock_exclusive("/doc.txt", Duration::from_secs(1))
        .await
        .unwrap()
        .unwrap();
    let release = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(400)).await;
        drop(held);
    });
    let started = Instant::now();
    let rsp = test::call_service(
        &app,
        test::TestRequest::put()
            .uri("/doc.txt")
            .insert_header(("content-type", "text/plain"))
            .set_payload("v1")
            .to_request(),
    )
    .await;
    assert!(rsp.status().is_success(), "{}", rsp.status());
    assert!(
        started.elapsed() >= Duration::from_millis(350),
        "the PUT did not wait for the other process: {:?}",
        started.elapsed()
    );
    release.await.unwrap();
    let (body, _) = ours.get("/doc.txt").await.unwrap();
    assert_eq!(&body[..], b"v1");
    // A different resource is not held up by that lock (a different stripe,
    // except by a 1-in-256 collision, which the wait bound still tolerates).
}
