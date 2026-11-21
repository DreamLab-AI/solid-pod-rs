//! Phase-1 regression tests for the checklist's `semantic-difference` rows:
//! each pins the behaviour the row describes, so a drift in either direction
//! is caught.

use std::sync::Arc;

use actix_web::test;
use bytes::Bytes;
use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::{build_app, AppState};

const OPEN_ACL: &str = "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
     @prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
     <#all> a acl:Authorization ; acl:agentClass foaf:Agent ;\n\
       acl:accessTo </> ; acl:default </> ;\n\
       acl:mode acl:Read, acl:Write, acl:Control .\n";

async fn open() -> Arc<dyn Storage> {
    let s: Arc<dyn Storage> = Arc::new(MemoryBackend::new());
    s.put("/.acl", Bytes::from(OPEN_ACL), "text/turtle")
        .await
        .unwrap();
    s.put("/c/x.txt", Bytes::from("x"), "text/plain")
        .await
        .unwrap();
    s
}

/// Row 23: `Accept-Ranges` is `bytes` on a resource and `none` on a container.
#[actix_web::test]
async fn accept_ranges_is_bytes_on_resources_and_none_on_containers() {
    let app = test::init_service(build_app(AppState::new(open().await))).await;
    for (uri, want) in [("/c/", "none"), ("/c/x.txt", "bytes")] {
        for method in ["OPTIONS", "GET", "HEAD"] {
            let resp = test::call_service(
                &app,
                test::TestRequest::default()
                    .method(method.parse().unwrap())
                    .uri(uri)
                    .to_request(),
            )
            .await;
            let got = resp
                .headers()
                .get("accept-ranges")
                .map(|v| v.to_str().unwrap().to_string());
            assert_eq!(got.as_deref(), Some(want), "{method} {uri}");
        }
    }
}
