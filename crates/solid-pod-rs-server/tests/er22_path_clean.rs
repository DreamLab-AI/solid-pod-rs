//! ER-22 path-cleaning regressions: every spelling of a protected
//! `/.well-known/` path (missing leading slash, empty segments, `.`
//! segments, percent-encoding) must be authorised and served as the one
//! canonical path, over MCP, COPY and plain HTTP, on both storage backends.

use std::sync::Arc;

use actix_web::test;
use base64::Engine as _;
use bytes::Bytes;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use solid_pod_rs::security::DotfileAllowlist;
use solid_pod_rs::storage::{fs::FsBackend, memory::MemoryBackend, Storage};
use solid_pod_rs_server::{build_app, AppState};

const SECRET: &str = "01234567890123456789012345678901";
const OWNER: &str = "https://owner.example/profile/card#me";
const WRITER: &str = "https://writer.example/profile/card#me";
const TRAIL: &str = r#"{"ticker":"x","privkey":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}"#;
const REFUNDS: &str = r#"[{"payer":"did:nostr:payer-secret","amount":42}]"#;
const EPOCH: &str = r#"{"epoch":7}"#;
const INTENT: &str = r#"{"intent":"broadcast"}"#;

const SPELLINGS: &[&str] = &[
    "/.well-known/token/x.json",
    ".well-known/token/x.json",
    "//.well-known/token/x.json",
    "/.well-known//token/x.json",
    "/./.well-known/token/x.json",
    "/.well-known/./token/x.json",
    "/%2ewell-known/token/x.json",
    "/.well-known/%74oken/x.json",
    "/.WELL-KNOWN/Token/x.json",
];

fn bearer(web_id: &str) -> String {
    std::env::set_var("TOKEN_SECRET", SECRET);
    let data = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(json!({"webId": web_id, "iat": 1, "exp": u64::MAX / 2}).to_string());
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
    mac.update(data.as_bytes());
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("Bearer {data}.{sig}")
}

fn root_acl() -> String {
    format!(
        "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
         @prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
         <#o> a acl:Authorization ; acl:agent <{OWNER}> ; acl:accessTo </> ; acl:default </> ;\n\
           acl:mode acl:Read, acl:Write, acl:Control .\n\
         <#w> a acl:Authorization ; acl:agent <{WRITER}> ; acl:accessTo </> ; acl:default </> ;\n\
           acl:mode acl:Read, acl:Write .\n\
         <#p> a acl:Authorization ; acl:agentClass foaf:Agent ; acl:accessTo </> ; acl:default </> ;\n\
           acl:mode acl:Read .\n"
    )
}

async fn put(s: &dyn Storage, path: &str, body: &str) {
    s.put(path, Bytes::from(body.to_string()), "application/json")
        .await
        .unwrap();
}

async fn seeded(fs: bool) -> (Arc<dyn Storage>, Option<tempfile::TempDir>) {
    let (s, dir): (Arc<dyn Storage>, _) = if fs {
        let d = tempfile::tempdir().unwrap();
        (Arc::new(FsBackend::new(d.path()).await.unwrap()), Some(d))
    } else {
        (Arc::new(MemoryBackend::new()), None)
    };
    put(s.as_ref(), "/.acl", &root_acl()).await;
    put(s.as_ref(), "/.well-known/token/x.json", TRAIL).await;
    put(
        s.as_ref(),
        "/.well-known/prov/refunds-pending.json",
        REFUNDS,
    )
    .await;
    put(s.as_ref(), "/.well-known/prov/epoch.json", EPOCH).await;
    put(s.as_ref(), "/.well-known/gitmark/prov/intent.json", INTENT).await;
    put(s.as_ref(), "/open/y", "ok").await;
    (s, dir)
}

fn app_state(s: Arc<dyn Storage>) -> AppState {
    let mut st = AppState::new(s);
    st.mcp_enabled = true;
    st.dotfiles = Arc::new(DotfileAllowlist::new(vec![
        ".acl".into(),
        ".meta".into(),
        ".well-known".into(),
    ]));
    st
}

async fn mcp(s: Arc<dyn Storage>, who: Option<&str>, name: &str, args: Value) -> String {
    let app = test::init_service(build_app(app_state(s))).await;
    let mut req = test::TestRequest::post().uri("/mcp").set_json(json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": args}
    }));
    if let Some(w) = who {
        req = req.insert_header(("Authorization", bearer(w)));
    }
    let resp = test::call_service(&app, req.to_request()).await;
    String::from_utf8_lossy(&test::read_body(resp).await).into_owned()
}

async fn exists_with(s: &Arc<dyn Storage>, path: &str, body: &str) -> bool {
    match s.get(path).await {
        Ok((b, _)) => b.as_ref() == body.as_bytes(),
        Err(_) => false,
    }
}

async fn run_each_backend<F, Fut>(f: F)
where
    F: Fn(Arc<dyn Storage>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    for fs in [false, true] {
        let (s, _keep) = seeded(fs).await;
        f(s).await;
    }
}

#[actix_web::test]
async fn mcp_read_and_head_deny_every_trail_spelling() {
    run_each_backend(|s| async move {
        for sp in SPELLINGS {
            for tool in ["read_resource", "head_resource"] {
                let out = mcp(s.clone(), None, tool, json!({"path": sp})).await;
                assert!(!out.contains("deadbeef"), "{tool} {sp}: {out}");
                assert!(!out.contains("\"size\""), "{tool} {sp}: {out}");
            }
        }
        for sp in [
            "/.well-known/prov/refunds-pending.json",
            ".well-known/prov/refunds-pending.json",
            "/.well-known//prov/refunds-pending.json",
            "/./.well-known/prov/epoch.json",
        ] {
            let out = mcp(s.clone(), None, "read_resource", json!({"path": sp})).await;
            assert!(
                !out.contains("payer-secret") && !out.contains("epoch\\\":7"),
                "{sp}: {out}"
            );
        }
    })
    .await;
}

#[actix_web::test]
async fn mcp_list_denies_trail_and_prov_containers() {
    run_each_backend(|s| async move {
        for sp in [
            "/.well-known/token/",
            ".well-known/token/",
            "//.well-known/token/",
            "/.well-known//token/",
            "/./.well-known/token/",
            "/.well-known/./token/",
            "/.well-known/prov/",
            ".well-known/prov/",
        ] {
            let out = mcp(s.clone(), None, "list_resources", json!({"path": sp})).await;
            assert!(
                !out.contains("x.json") && !out.contains("epoch.json"),
                "{sp}: {out}"
            );
            assert!(!out.contains("refunds-pending"), "{sp}: {out}");
        }
    })
    .await;
}

#[actix_web::test]
async fn mcp_write_create_delete_cannot_touch_protected_files() {
    run_each_backend(|s| async move {
        for sp in SPELLINGS {
            mcp(
                s.clone(),
                Some(WRITER),
                "write_resource",
                json!({"path": sp, "content": "PWNED"}),
            )
            .await;
            mcp(
                s.clone(),
                Some(WRITER),
                "delete_resource",
                json!({"path": sp}),
            )
            .await;
            assert!(
                exists_with(&s, "/.well-known/token/x.json", TRAIL).await,
                "{sp}"
            );
        }
        for sp in [
            "/.well-known/prov/epoch.json",
            ".well-known/prov/epoch.json",
            "/.well-known//prov/epoch.json",
            "/./.well-known/prov/epoch.json",
        ] {
            mcp(
                s.clone(),
                Some(WRITER),
                "write_resource",
                json!({"path": sp, "content": "PWNED"}),
            )
            .await;
            mcp(
                s.clone(),
                Some(WRITER),
                "delete_resource",
                json!({"path": sp}),
            )
            .await;
            assert!(
                exists_with(&s, "/.well-known/prov/epoch.json", EPOCH).await,
                "{sp}"
            );
        }
        for sp in [
            "/.well-known/gitmark/prov/intent.json",
            ".well-known/gitmark/prov/intent.json",
            "//.well-known/gitmark//prov/intent.json",
        ] {
            mcp(
                s.clone(),
                Some(WRITER),
                "write_resource",
                json!({"path": sp, "content": "PWNED"}),
            )
            .await;
            mcp(
                s.clone(),
                Some(WRITER),
                "delete_resource",
                json!({"path": sp}),
            )
            .await;
            assert!(
                exists_with(&s, "/.well-known/gitmark/prov/intent.json", INTENT).await,
                "{sp}"
            );
        }
        // create_resource through a messy container spelling
        for c in [
            ".well-known/token/",
            "//.well-known/token/",
            "/.well-known/./token/",
        ] {
            mcp(
                s.clone(),
                Some(WRITER),
                "create_resource",
                json!({"container": c, "slug": "evil.json", "content": "PWNED"}),
            )
            .await;
            assert!(s.get("/.well-known/token/evil.json").await.is_err(), "{c}");
        }
    })
    .await;
}

#[actix_web::test]
async fn mcp_ordinary_paths_still_work_with_messy_spellings() {
    run_each_backend(|s| async move {
        let out = mcp(s.clone(), None, "read_resource", json!({"path": "open//y"})).await;
        assert!(out.contains("ok"), "{out}");
        mcp(
            s.clone(),
            Some(WRITER),
            "write_resource",
            json!({"path": "open/z", "content": "zz"}),
        )
        .await;
        assert!(exists_with(&s, "/open/z", "zz").await);
        let out = mcp(
            s.clone(),
            None,
            "read_resource",
            json!({"path": "/open/../x"}),
        )
        .await;
        assert!(out.contains("isError"), "{out}");
    })
    .await;
}

#[actix_web::test]
async fn copy_source_spellings_cannot_reach_trail_secret() {
    for fs in [false, true] {
        let (s, _keep) = seeded(fs).await;
        for sp in [
            "/.well-known/token/x.json",
            "//.well-known/token/x.json",
            "/.well-known//token/x.json",
            "http://localhost:8080/.well-known//token/x.json",
            "http://localhost:8080//.well-known/token/x.json",
            "/%2ewell-known/token/x.json",
        ] {
            let app = test::init_service(build_app(app_state(s.clone()))).await;
            let req = test::TestRequest::default()
                .method(actix_web::http::Method::from_bytes(b"COPY").unwrap())
                .uri("/copied")
                .insert_header(("Host", "localhost:8080"))
                .insert_header(("Source", sp))
                .insert_header(("Authorization", bearer(WRITER)))
                .to_request();
            let resp = test::call_service(&app, req).await;
            let st = resp.status().as_u16();
            assert!(!(200..300).contains(&st), "COPY {sp} -> {st} (fs={fs})");
            assert!(
                s.get("/copied").await.is_err(),
                "COPY {sp} copied (fs={fs})"
            );
        }
    }
}

#[actix_web::test]
async fn copy_source_cannot_reach_prov_state() {
    for fs in [false, true] {
        let (s, _keep) = seeded(fs).await;
        for sp in [
            "/.well-known/prov/refunds-pending.json",
            "/.well-known//prov/refunds-pending.json",
            "http://localhost:8080//.well-known/prov/epoch.json",
        ] {
            let app = test::init_service(build_app(app_state(s.clone()))).await;
            let req = test::TestRequest::default()
                .method(actix_web::http::Method::from_bytes(b"COPY").unwrap())
                .uri("/copied")
                .insert_header(("Host", "localhost:8080"))
                .insert_header(("Source", sp))
                .insert_header(("Authorization", bearer(WRITER)))
                .to_request();
            let resp = test::call_service(&app, req).await;
            let st = resp.status().as_u16();
            assert!(!(200..300).contains(&st), "COPY {sp} -> {st} (fs={fs})");
            assert!(
                s.get("/copied").await.is_err(),
                "COPY {sp} copied (fs={fs})"
            );
        }
    }
}

#[actix_web::test]
async fn http_get_and_put_cannot_reach_protected_files() {
    for fs in [false, true] {
        let (s, _keep) = seeded(fs).await;
        let app = test::init_service(build_app(app_state(s.clone()))).await;
        for uri in [
            "/.well-known/token/x.json",
            "//.well-known/token/x.json",
            "/.well-known//token/x.json",
            "/.well-known/prov/refunds-pending.json",
            "/.well-known/prov/epoch.json",
        ] {
            let resp =
                test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
            let body = test::read_body(resp).await;
            let body = String::from_utf8_lossy(&body);
            assert!(
                !body.contains("deadbeef") && !body.contains("payer-secret"),
                "GET {uri}"
            );
            let resp = test::call_service(
                &app,
                test::TestRequest::put()
                    .uri(uri)
                    .insert_header(("Authorization", bearer(WRITER)))
                    .set_payload("PWNED")
                    .to_request(),
            )
            .await;
            assert!(
                !resp.status().is_success(),
                "PUT {uri} -> {}",
                resp.status()
            );
        }
        assert!(exists_with(&s, "/.well-known/prov/epoch.json", EPOCH).await);
        assert!(exists_with(&s, "/.well-known/token/x.json", TRAIL).await);
    }
}
