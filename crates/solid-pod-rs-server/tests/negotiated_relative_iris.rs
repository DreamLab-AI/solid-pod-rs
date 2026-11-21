//! A negotiated read of a stored Turtle body that holds relative IRIs (a
//! Turtle PUT, `<#a>`) resolves them against the URL it is read from, so
//! N-Triples and JSON-LD output never carry a relative IRI.

use std::sync::Arc;

use actix_web::test;
use bytes::Bytes;
use solid_pod_rs::storage::{memory::MemoryBackend, Storage};
use solid_pod_rs_server::{build_app, AppState};

const OPEN_ACL: &str = "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
     @prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
     <#all> a acl:Authorization ; acl:agentClass foaf:Agent ;\n\
       acl:accessTo </> ; acl:default </> ; acl:mode acl:Read .\n";

#[actix_web::test]
async fn relative_iris_in_a_stored_turtle_body_are_resolved_on_a_negotiated_read() {
    let s: Arc<dyn Storage> = Arc::new(MemoryBackend::new());
    s.put("/.acl", Bytes::from(OPEN_ACL), "text/turtle")
        .await
        .unwrap();
    s.put(
        "/doc.ttl",
        Bytes::from("<#a> <#b> \"v1\" .\n"),
        "text/turtle",
    )
    .await
    .unwrap();
    let app = test::init_service(build_app(AppState::new(s))).await;
    for accept in ["application/n-triples", "application/ld+json"] {
        let rsp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/doc.ttl")
                .insert_header(("host", "pod.example"))
                .insert_header(("accept", accept))
                .to_request(),
        )
        .await;
        assert_eq!(rsp.status().as_u16(), 200, "{accept}");
        let body = String::from_utf8(test::read_body(rsp).await.to_vec()).unwrap();
        assert!(
            body.contains("http://pod.example/doc.ttl#a") && !body.contains("<#a>"),
            "{accept}: {body}"
        );
    }
}
