//! ER-22 regression tests: the Web Ledger and the other payment documents
//! under `/.well-known/webledgers/` are server-managed state. A principal
//! holding only a (possibly inherited) `acl:Write` or `acl:Read` must not be
//! able to forge, delete or read them; the payment code, which talks to
//! `Storage` directly, must keep working.
#![cfg(feature = "dev-bearer")]

use std::sync::Arc;

use actix_web::{http::Method, test};
use base64::Engine as _;
use bytes::Bytes;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use solid_pod_rs::storage::{memory::MemoryBackend, Storage};
use solid_pod_rs_server::{build_app, AppState};

const SECRET: &str = "01234567890123456789012345678901";
const OWNER: &str = "https://owner.example/profile/card#me";
const WRITER: &str = "https://writer.example/profile/card#me";
const LEDGER: &str = "/.well-known/webledgers/webledgers.json";
const REAL: &str = r#"{"entries":[{"url":"did:nostr:real","amount":"1"}]}"#;
const FORGED: &str = r#"{"entries":[{"url":"did:nostr:writer","amount":"999999"}]}"#;
const STATE_PATHS: [&str; 5] = [
    "/.well-known/webledgers/webledgers.json",
    "/.well-known/webledgers/state.json",
    "/.well-known/webledgers/replay.json",
    "/.well-known/webledgers/offers.json",
    "/.well-known/webledgers/pool.json",
];

fn bearer(web_id: &str) -> String {
    std::env::set_var("TOKEN_SECRET", SECRET);
    let data = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::json!({"webId": web_id, "iat": dev_now() - 10, "exp": dev_now() + 3600, "aud": solid_pod_rs_server::DEV_BEARER_AUDIENCE}).to_string());
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
    mac.update(data.as_bytes());
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("Bearer {data}.{sig}")
}

/// Root ACL: OWNER full control, WRITER read+write (inherited everywhere),
/// the public may read.
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

async fn seeded() -> Arc<MemoryBackend> {
    let s = Arc::new(MemoryBackend::new());
    for (p, b, ct) in [
        ("/.acl", root_acl().as_str(), "text/turtle"),
        ("/pub/forged.json", FORGED, "application/json"),
    ] {
        s.put(p, Bytes::from(b.to_string()), ct).await.unwrap();
    }
    for p in STATE_PATHS {
        s.put(p, Bytes::from(REAL), "application/json")
            .await
            .unwrap();
    }
    s
}

async fn call(
    s: Arc<MemoryBackend>,
    method: &str,
    uri: &str,
    who: Option<&str>,
    extra: &[(&str, &str)],
    body: &str,
) -> (u16, String) {
    let app = test::init_service(build_app(AppState::new(s))).await;
    let mut req = test::TestRequest::default()
        .method(Method::from_bytes(method.as_bytes()).unwrap())
        .uri(uri);
    if let Some(w) = who {
        req = req.insert_header(("Authorization", bearer(w)));
    }
    for (k, v) in extra {
        req = req.insert_header((*k, *v));
    }
    let resp = test::call_service(&app, req.set_payload(body.to_string()).to_request()).await;
    let st = resp.status().as_u16();
    (
        st,
        String::from_utf8_lossy(&test::read_body(resp).await).into_owned(),
    )
}

async fn ledger_unchanged(s: &MemoryBackend) {
    for p in STATE_PATHS {
        assert_eq!(s.get(p).await.unwrap().0, Bytes::from(REAL), "{p} changed");
    }
}

#[actix_web::test]
async fn writer_cannot_put_over_ledger_documents() {
    for p in STATE_PATHS {
        let s = seeded().await;
        let (st, _) = call(
            s.clone(),
            "PUT",
            p,
            Some(WRITER),
            &[("Content-Type", "application/json")],
            FORGED,
        )
        .await;
        assert_eq!(st, 403, "PUT {p}");
        ledger_unchanged(&s).await;
    }
}

#[actix_web::test]
async fn writer_cannot_create_or_delete_in_ledger_directory() {
    let s = seeded().await;
    let (st, _) = call(
        s.clone(),
        "PUT",
        "/.well-known/webledgers/extra.json",
        Some(WRITER),
        &[("Content-Type", "application/json")],
        FORGED,
    )
    .await;
    assert_eq!(st, 403);
    assert!(s.get("/.well-known/webledgers/extra.json").await.is_err());
    for p in STATE_PATHS {
        let (st, _) = call(s.clone(), "DELETE", p, Some(WRITER), &[], "").await;
        assert_eq!(st, 403, "DELETE {p}");
    }
    ledger_unchanged(&s).await;
}

#[actix_web::test]
async fn writer_cannot_patch_ledger() {
    let s = seeded().await;
    let (st, _) = call(
        s.clone(),
        "PATCH",
        LEDGER,
        Some(WRITER),
        &[("Content-Type", "application/sparql-update")],
        "INSERT DATA { <#a> <#b> <#c> }",
    )
    .await;
    assert_eq!(st, 403);
    ledger_unchanged(&s).await;
}

#[actix_web::test]
async fn writer_cannot_copy_into_ledger() {
    for p in STATE_PATHS {
        let s = seeded().await;
        let (st, _) = call(
            s.clone(),
            "COPY",
            p,
            Some(WRITER),
            &[("Source", "/pub/forged.json")],
            "",
        )
        .await;
        assert_eq!(st, 403, "COPY -> {p}");
        ledger_unchanged(&s).await;
    }
}

#[actix_web::test]
async fn writer_cannot_write_ledger_over_mcp() {
    let s = seeded().await;
    let mut state = AppState::new(s.clone());
    state.mcp_enabled = true;
    let app = test::init_service(build_app(state)).await;
    for tool in ["write_resource", "create_resource", "delete_resource"] {
        let req = test::TestRequest::post()
            .uri("/mcp")
            .insert_header(("Authorization", bearer(WRITER)))
            .set_json(serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": tool,
                           "arguments": {"path": LEDGER, "content": FORGED, "body": FORGED,
                                         "content_type": "application/json"}}
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        let _ = test::read_body(resp).await;
        ledger_unchanged(&s).await;
    }
}

/// The documents hold every principal's balance, the replay set and open
/// intents; `/pay/.balance` exposes only the caller's own entry. Neither a
/// public-read root nor a Read/Write grant reaches them over HTTP.
#[actix_web::test]
async fn ledger_documents_are_not_readable_without_control() {
    for p in STATE_PATHS {
        let s = seeded().await;
        for who in [None, Some(WRITER)] {
            let (st, body) = call(s.clone(), "GET", p, who, &[], "").await;
            assert!(matches!(st, 401 | 403), "GET {p} {who:?} -> {st}");
            assert!(!body.contains("did:nostr:real"));
        }
        let (st, _) = call(s, "GET", p, Some(OWNER), &[], "").await;
        assert_eq!(st, 200, "owner GET {p}");
    }
}

#[actix_web::test]
async fn owner_can_still_write_ledger_and_spelling_variants_are_guarded() {
    let s = seeded().await;
    let (st, _) = call(
        s.clone(),
        "PUT",
        LEDGER,
        Some(OWNER),
        &[("Content-Type", "application/json")],
        REAL,
    )
    .await;
    assert!((200..300).contains(&st), "owner PUT -> {st}");
    for p in [
        "/.well-known/webledgers/webledgers.json",
        "//.well-known/webledgers/webledgers.json",
        "/.WELL-KNOWN/WebLedgers/webledgers.json",
        "/.well-known/%77ebledgers/webledgers.json",
        "/.well-known/webledgers/",
    ] {
        let (st, _) = call(
            s.clone(),
            "PUT",
            p,
            Some(WRITER),
            &[("Content-Type", "application/json")],
            FORGED,
        )
        .await;
        assert!(!(200..300).contains(&st), "PUT {p} -> {st}");
    }
    assert_eq!(s.get(LEDGER).await.unwrap().0, Bytes::from(REAL));
}

fn dev_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
