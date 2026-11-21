//! SP-PAR-265: a JSON-LD ACL is read by expanded IRI, so shapes that other
//! Solid servers write (any prefix, `@vocab`, no `@graph`, expanded form)
//! grant what they say, and an ACL that needs a remote `@context` is
//! unreadable and denies (the context is never fetched).

use std::sync::Arc;

use actix_web::test;
use bytes::Bytes;
use serde_json::{json, Value};
use solid_pod_rs::storage::{memory::MemoryBackend, Storage};
use solid_pod_rs_server::{build_app, AppState};

const ACL: &str = "http://www.w3.org/ns/auth/acl#";
const FOAF: &str = "http://xmlns.com/foaf/0.1/";

async fn anon_get(acl: &Value) -> u16 {
    let storage = Arc::new(MemoryBackend::new());
    storage
        .put("/doc", Bytes::from_static(b"data"), "text/plain")
        .await
        .unwrap();
    storage
        .put(
            "/doc.acl",
            Bytes::from(acl.to_string()),
            "application/ld+json",
        )
        .await
        .unwrap();
    let app = test::init_service(build_app(AppState::new(storage))).await;
    test::call_service(&app, test::TestRequest::get().uri("/doc").to_request())
        .await
        .status()
        .as_u16()
}

#[actix_web::test]
async fn shapes_written_by_other_servers_grant_what_they_say() {
    let public = |ctx: Value, node: Value| json!({"@context": ctx, "@graph": [node]});
    let shapes = [
        public(
            json!({"wac": ACL, "people": FOAF}),
            json!({"@id": "#p", "@type": "wac:Authorization",
                "wac:agentClass": {"@id": "people:Agent"},
                "wac:accessTo": {"@id": "/doc"}, "wac:mode": {"@id": "wac:Read"}}),
        ),
        json!({"@context": {"acl": ACL, "foaf": FOAF}, "@id": "#p",
            "@type": ["acl:Authorization"],
            "acl:agentClass": {"@id": "foaf:Agent"},
            "acl:accessTo": {"@id": "/doc"}, "acl:mode": {"@id": "acl:Read"}}),
        json!([{"@id": "#p", "@type": [format!("{ACL}Authorization")],
            format!("{ACL}agentClass"): [{"@id": format!("{FOAF}Agent")}],
            format!("{ACL}accessTo"): [{"@id": "/doc"}],
            format!("{ACL}mode"): [{"@id": format!("{ACL}Read")}]}]),
        json!({"@context": {"@vocab": ACL,
            "agentClass": {"@type": "@id"}, "accessTo": {"@type": "@id"},
            "mode": {"@type": "@vocab"}},
            "@id": "#p", "@type": "Authorization",
            "agentClass": format!("{FOAF}Agent"), "accessTo": "/doc", "mode": "Read"}),
    ];
    for (i, shape) in shapes.iter().enumerate() {
        assert_eq!(anon_get(shape).await, 200, "shape {i}: {shape}");
    }
}

#[actix_web::test]
async fn a_remote_context_denies_even_when_the_document_would_grant() {
    let body = |ctx: Value| {
        json!({"@context": ctx, "@graph": [{"@id": "#p", "@type": "acl:Authorization",
            "acl:agentClass": {"@id": "foaf:Agent"},
            "acl:accessTo": {"@id": "/doc"}, "acl:mode": {"@id": "acl:Read"}}]})
    };
    // Control: the same grant with an inline context is served.
    assert_eq!(
        anon_get(&body(json!({"acl": ACL, "foaf": FOAF}))).await,
        200
    );
    for ctx in [
        json!("https://remote.example/acl-context.jsonld"),
        json!([{"acl": ACL, "foaf": FOAF}, "https://remote.example/more.jsonld"]),
    ] {
        let status = anon_get(&body(ctx.clone())).await;
        assert!(
            status == 401 || status == 403,
            "remote context {ctx} must deny, got {status}"
        );
    }
}

#[actix_web::test]
async fn a_rebound_acl_prefix_grants_nothing() {
    let doc = json!({"@context": {"acl": "http://evil.example/ns#", "foaf": FOAF},
        "@graph": [{"@id": "#p", "@type": "acl:Authorization",
            "acl:agentClass": {"@id": "foaf:Agent"},
            "acl:accessTo": {"@id": "/doc"}, "acl:mode": {"@id": "acl:Read"}}]});
    assert_eq!(anon_get(&doc).await, 401);
}
