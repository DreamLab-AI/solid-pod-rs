use std::sync::Arc;

use actix_web::{
    body::MessageBody,
    dev::{Service, ServiceResponse},
    http::StatusCode,
    test, Error,
};
use bytes::Bytes;
use serde_json::{json, Value};
use solid_pod_rs::storage::{memory::MemoryBackend, Storage};
use solid_pod_rs_server::{build_app, AppState};

async fn mcp_call<S, B>(app: &S, name: &str, arguments: Value) -> Value
where
    S: Service<actix_http::Request, Response = ServiceResponse<B>, Error = Error>,
    B: MessageBody,
    B::Error: std::fmt::Debug,
{
    let request = test::TestRequest::post()
        .uri("/mcp")
        .set_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": name, "arguments": arguments }
        }))
        .to_request();
    let response = test::call_service(app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    test::read_body_json(response).await
}

fn result_text(response: &Value) -> &str {
    response["result"]["content"][0]["text"]
        .as_str()
        .expect("MCP text result")
}

#[actix_web::test]
async fn anonymous_get_skill_cannot_read_arbitrary_private_resource() {
    let storage = Arc::new(MemoryBackend::new());
    storage
        .put(
            "/private/privkey.jsonld",
            Bytes::from_static(b"TOP-SECRET-PRIVATE-KEY"),
            "application/ld+json",
        )
        .await
        .unwrap();
    let mut state = AppState::new(storage);
    state.mcp_enabled = true;
    let app = test::init_service(build_app(state)).await;

    let response = mcp_call(
        &app,
        "get_skill",
        json!({ "path": "/private/privkey.jsonld" }),
    )
    .await;
    assert_eq!(response["result"]["isError"], true);
    assert!(!result_text(&response).contains("TOP-SECRET"));
    assert!(result_text(&response).contains("not a conventional skill path"));
}

#[actix_web::test]
async fn generic_resource_tools_require_control_for_acl_sidecars() {
    let storage = Arc::new(MemoryBackend::new());
    storage
        .put("/doc", Bytes::from_static(b"body"), "text/plain")
        .await
        .unwrap();
    storage
        .put(
            "/doc.acl",
            Bytes::from_static(
                br#"@prefix acl: <http://www.w3.org/ns/auth/acl#>.
                    @prefix foaf: <http://xmlns.com/foaf/0.1/>.
                    <#public> a acl:Authorization;
                      acl:agentClass foaf:Agent;
                      acl:accessTo </doc>;
                      acl:mode acl:Read, acl:Write."#,
            ),
            "text/turtle",
        )
        .await
        .unwrap();
    let mut state = AppState::new(storage.clone());
    state.mcp_enabled = true;
    let app = test::init_service(build_app(state)).await;

    for (tool, arguments) in [
        ("read_resource", json!({ "path": "/doc.acl" })),
        ("head_resource", json!({ "path": "/doc.acl" })),
        (
            "write_resource",
            json!({ "path": "/doc.acl", "content": "attacker", "contentType": "text/plain" }),
        ),
        ("delete_resource", json!({ "path": "/doc.acl" })),
    ] {
        let response = mcp_call(&app, tool, arguments).await;
        assert_eq!(response["result"]["isError"], true, "{tool}");
        assert!(result_text(&response).contains("access denied"), "{tool}");
    }
    let (acl, _) = storage.get("/doc.acl").await.unwrap();
    assert!(String::from_utf8_lossy(&acl).contains("acl:Authorization"));
}

#[actix_web::test]
async fn conventional_skill_still_requires_its_effective_read_acl() {
    let storage = Arc::new(MemoryBackend::new());
    storage
        .put(
            "/private/bots/helper/SKILL.md",
            Bytes::from_static(b"private instructions"),
            "text/markdown",
        )
        .await
        .unwrap();
    let mut state = AppState::new(storage);
    state.mcp_enabled = true;
    let app = test::init_service(build_app(state)).await;

    let response = mcp_call(
        &app,
        "get_skill",
        json!({ "path": "/private/bots/helper/SKILL.md" }),
    )
    .await;
    assert_eq!(response["result"]["isError"], true);
    assert!(result_text(&response).contains("access denied"));
}
