//! B6.2 — per-sender rate limit on container `POST` (inbox / append).
//!
//! A single appender (here anonymous, keyed by source IP) must not be able
//! to flood a publicly-appendable container. With the write limiter tightened
//! to 2 per window, the third POST from the same sender is refused with 429.

use std::sync::Arc;
use std::time::Duration;

use actix_web::test;
use bytes::Bytes;

use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::{build_app, AppState, RouteRateLimiter};

const PUBLIC_APPEND_ACL: &str = r#"
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<#public> a acl:Authorization ;
    acl:agentClass foaf:Agent ;
    acl:accessTo </> ;
    acl:default </> ;
    acl:mode acl:Read, acl:Write, acl:Append .
"#;

async fn seed_public_append(storage: &dyn Storage) {
    storage
        .put("/.acl", Bytes::from(PUBLIC_APPEND_ACL), "text/turtle")
        .await
        .unwrap();
    storage
        .put("/inbox/", Bytes::from_static(b""), "text/turtle")
        .await
        .unwrap();
}

fn post_to_inbox() -> actix_web::test::TestRequest {
    test::TestRequest::post()
        .uri("/inbox/")
        .insert_header(("content-type", "text/plain"))
        .set_payload(Bytes::from_static(b"hello"))
}

#[actix_web::test]
async fn container_post_rate_limited_per_sender() {
    let storage = Arc::new(MemoryBackend::new());
    seed_public_append(storage.as_ref()).await;
    let mut state = AppState::new(storage);
    state.write_limiter = Arc::new(RouteRateLimiter::new(2, Duration::from_secs(60)));
    let app = test::init_service(build_app(state)).await;

    for i in 0..2 {
        let resp = test::call_service(&app, post_to_inbox().to_request()).await;
        assert_eq!(
            resp.status().as_u16(),
            201,
            "append {i} within the limit should be Created"
        );
    }

    let resp = test::call_service(&app, post_to_inbox().to_request()).await;
    assert_eq!(
        resp.status().as_u16(),
        429,
        "third append from the same sender must be rate-limited"
    );
    assert!(
        resp.headers().get("Retry-After").is_some(),
        "429 must carry Retry-After"
    );
}
