//! ER-22 review 2: MCP tools honour the same dotfile allowlist as the REST
//! `DotfileGuard`. A Write grant on `/alice/` must not reach `.git/`,
//! `*.meta.json` storage sidecars or the fs backend's scratch names through
//! any tool.

use std::sync::Arc;

use actix_web::test;
use base64::Engine as _;
use bytes::Bytes;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use solid_pod_rs::storage::{memory::MemoryBackend, Storage};
use solid_pod_rs_server::{build_app, AppState};

const SECRET: &str = "01234567890123456789012345678901";
const WRITER: &str = "https://writer.example/profile/card#me";

fn bearer(web_id: &str) -> String {
    std::env::set_var("TOKEN_SECRET", SECRET);
    let data = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(json!({"webId": web_id, "iat": 1, "exp": u64::MAX / 2}).to_string());
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
    mac.update(data.as_bytes());
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("Bearer {data}.{sig}")
}

fn writer_acl() -> String {
    format!(
        "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
         <#w> a acl:Authorization ; acl:agent <{WRITER}> ;\n\
         acl:accessTo </alice/> ; acl:default </alice/> ;\n\
         acl:mode acl:Read, acl:Write, acl:Control .\n"
    )
}

async fn state() -> (AppState, Arc<MemoryBackend>) {
    let s = Arc::new(MemoryBackend::new());
    s.put("/alice/.acl", Bytes::from(writer_acl()), "text/turtle")
        .await
        .unwrap();
    s.create_container("/alice/").await.unwrap();
    s.put("/alice.acl", Bytes::from(writer_acl()), "text/turtle")
        .await
        .unwrap();
    s.put("/alice/x", Bytes::from("x"), "text/plain")
        .await
        .unwrap();
    let mut st = AppState::new(s.clone());
    st.mcp_enabled = true;
    (st, s)
}

/// Returns `(is_error, text)` for either a JSON-RPC result or the bare tool
/// error the streaming `subscribe` path answers with.
async fn mcp(state: &AppState, name: &str, args: Value) -> (bool, String) {
    let app = test::init_service(build_app(state.clone())).await;
    let body = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{"name":name,"arguments":args}}))
    .unwrap();
    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header(("Authorization", bearer(WRITER)))
        .insert_header(("Content-Type", "application/json"))
        .set_payload(body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    let v: Value = test::read_body_json(resp).await;
    let r = v.get("result").unwrap_or(&v);
    (
        r["isError"].as_bool().unwrap_or(false),
        r["content"][0]["text"].as_str().unwrap_or("").to_string(),
    )
}

/// Every refused spelling, one per dotfile class.
const BAD: &[&str] = &[
    "/alice/.git/config",
    "/alice/.git/hooks/pre-commit",
    "/alice/.env",
    "/alice/x.meta.json",
    "/alice/sub/y.meta.json",
    "/alice/.solid-pod-tmp-x",
    "/alice/y.solid-pod-tmp-1",
    "/alice/%2egit/config",
    "alice/.git/config",
];

#[actix_web::test]
async fn path_tools_refuse_every_dotfile_class() {
    let (st, store) = state().await;
    for p in BAD {
        for tool in [
            "write_resource",
            "read_resource",
            "head_resource",
            "delete_resource",
            "get_skill",
            "read_acl",
            "write_acl",
        ] {
            let (err, text) = mcp(
                &st,
                tool,
                json!({"path": p, "content": "[core]\n", "authorizations": [
                    {"agents": [WRITER], "modes": ["Read","Write","Control"]}]}),
            )
            .await;
            assert!(
                err && text.contains("dotfile"),
                "{tool} {p}: err={err} {text}"
            );
        }
        let canon = p.trim_start_matches('/').replace("%2e", ".");
        assert!(
            !store.exists(&format!("/{canon}")).await.unwrap(),
            "{p} was written"
        );
    }
    // Container-shaped tools.
    for c in ["/alice/.git/", "/alice/.solid-pod-tmp-d/"] {
        for (tool, args) in [
            ("list_resources", json!({"path": c})),
            ("create_resource", json!({"container": c, "slug": "z"})),
            ("subscribe", json!({"path": c})),
        ] {
            let (err, text) = mcp(&st, tool, args).await;
            assert!(err && text.contains("dotfile"), "{tool} {c}: {text}");
        }
    }
    assert!(!store.exists("/alice/.git/config").await.unwrap());
    assert!(!store.exists("/alice/x.meta.json").await.unwrap());
}

#[actix_web::test]
async fn create_resource_refuses_dotfile_slugs() {
    let (st, store) = state().await;
    for slug in [".git", ".env", "x.meta.json", "q.solid-pod-tmp-1"] {
        let (err, text) = mcp(
            &st,
            "create_resource",
            json!({"container": "/alice/", "slug": slug, "content": "x"}),
        )
        .await;
        assert!(err, "slug {slug}: {text}");
        assert!(
            !store.exists(&format!("/alice/{slug}")).await.unwrap(),
            "slug {slug} created"
        );
    }
}

#[actix_web::test]
async fn ordinary_paths_still_work_over_mcp() {
    let (st, store) = state().await;
    let (err, text) = mcp(
        &st,
        "write_resource",
        json!({"path": "/alice/y", "content": "hi"}),
    )
    .await;
    assert!(!err, "{text}");
    assert!(store.exists("/alice/y").await.unwrap());
    let (err, text) = mcp(&st, "read_resource", json!({"path": "/alice/y"})).await;
    assert!(!err && text.contains("hi"), "{text}");
    let (err, text) = mcp(
        &st,
        "create_resource",
        json!({"container": "/alice/", "slug": "z", "content": "c"}),
    )
    .await;
    assert!(!err, "{text}");
    // The allowlisted `.acl` stays reachable, as over REST.
    let (err, text) = mcp(
        &st,
        "write_acl",
        json!({"path": "/alice/y", "authorizations": [
            {"agents": [WRITER], "modes": ["Read","Write","Control"]}]}),
    )
    .await;
    assert!(!err, "{text}");
    let (err, text) = mcp(&st, "list_resources", json!({"path": "/alice/"})).await;
    assert!(!err, "{text}");
}
