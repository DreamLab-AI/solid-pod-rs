//! MCP resource tools share the REST enforcement path: payment conditions are
//! debited on read, the pod quota is reserved on write, and a missing target
//! does not borrow its parent container's grant.
#![cfg(feature = "dev-bearer")]

use std::sync::Arc;

use actix_web::test;
use base64::Engine as _;
use bytes::Bytes;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use solid_pod_rs::payments::WebLedger;
use solid_pod_rs::storage::{memory::MemoryBackend, Storage};
use solid_pod_rs_server::{build_app, AppState};

const SECRET: &str = "01234567890123456789012345678901";
const NOSTR_SECRET: &str = "5555555555555555555555555555555555555555555555555555555555555555";
const WRITER: &str = "https://writer.example/profile/card#me";

fn bearer(web_id: &str) -> String {
    std::env::set_var("TOKEN_SECRET", SECRET);
    let data = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(json!({"webId": web_id, "iat": dev_now() - 10, "exp": dev_now() + 3600, "aud": solid_pod_rs_server::DEV_BEARER_AUDIENCE}).to_string());
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
    mac.update(data.as_bytes());
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("Bearer {data}.{sig}")
}

fn rpc(name: &str, args: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": args}
    }))
    .unwrap()
}

fn nip98(body: &[u8]) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .saturating_sub(10);
    let token = solid_pod_rs::auth::nip98::mint_with_payload(
        "http://localhost:8080/mcp",
        "POST",
        Some(body),
        NOSTR_SECRET,
        now,
    )
    .unwrap();
    format!("Nostr {token}")
}

/// The `did:nostr:` principal that `NOSTR_SECRET` authenticates as.
fn payer() -> String {
    let header = nip98(b"{}");
    let token = header.trim_start_matches("Nostr ");
    let raw = base64::engine::general_purpose::STANDARD
        .decode(token)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(token))
        .unwrap();
    let event: Value = serde_json::from_slice(&raw).unwrap();
    format!("did:nostr:{}", event["pubkey"].as_str().unwrap())
}

/// Call an MCP tool as `who`: `None` is the `NOSTR_SECRET` principal, `Some`
/// a development-bearer WebID.
async fn mcp(state: AppState, who: Option<&str>, name: &str, args: Value) -> (bool, String) {
    let app = test::init_service(build_app(state)).await;
    let body = rpc(name, args);
    let auth = match who {
        Some(w) => bearer(w),
        None => nip98(&body),
    };
    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header(("Authorization", auth))
        .insert_header(("Content-Type", "application/json"))
        .set_payload(body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    let v: Value = test::read_body_json(resp).await;
    (
        v["result"]["isError"].as_bool().unwrap_or(false),
        v["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string(),
    )
}

async fn balance(s: &dyn Storage, payer: &str) -> u64 {
    let (b, _) = s
        .get("/.well-known/webledgers/webledgers.json")
        .await
        .unwrap();
    serde_json::from_slice::<WebLedger>(&b)
        .unwrap()
        .get_balance(payer)
}

#[actix_web::test]
async fn mcp_read_of_pay_per_read_resource_debits_the_account() {
    let payer = payer();
    let s = Arc::new(MemoryBackend::new());
    let acl = format!(
        "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
         <#paid> a acl:Authorization ; acl:agent <{payer}> ;\n\
           acl:accessTo </premium/doc> ; acl:mode acl:Read ;\n\
           acl:condition [ a acl:PaymentCondition ; acl:costSats 100 ] .\n"
    );
    s.put("/premium/doc.acl", Bytes::from(acl), "text/turtle")
        .await
        .unwrap();
    s.put("/premium/doc", Bytes::from("PAID"), "text/plain")
        .await
        .unwrap();
    let mut ledger = WebLedger::new("t");
    ledger
        .credit_by_outpoint(&payer, "satoshi", &"ab".repeat(32), 0, 500)
        .unwrap();
    s.put(
        "/.well-known/webledgers/webledgers.json",
        Bytes::from(serde_json::to_vec(&ledger).unwrap()),
        "application/json",
    )
    .await
    .unwrap();
    let mut state = AppState::new(s.clone());
    state.mcp_enabled = true;
    let (err, out) = mcp(
        state,
        None,
        "read_resource",
        json!({"path": "/premium/doc"}),
    )
    .await;
    assert!(!err && out.contains("PAID"), "{out}");
    assert_eq!(
        balance(s.as_ref(), &payer).await,
        400,
        "read was not charged"
    );
}

#[cfg(feature = "quota")]
#[actix_web::test]
async fn mcp_write_past_quota_is_refused() {
    use solid_pod_rs::quota::{FsQuotaStore, QuotaPolicy};
    let s = Arc::new(MemoryBackend::new());
    let acl = format!(
        "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
         <#w> a acl:Authorization ; acl:agent <{WRITER}> ;\n\
           acl:default </alice/> ; acl:mode acl:Read, acl:Write .\n"
    );
    s.put("/alice.acl", Bytes::from(acl), "text/turtle")
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let quota = Arc::new(FsQuotaStore::new(dir.path().to_path_buf(), 10));
    let mut state = AppState::new(s.clone());
    state.mcp_enabled = true;
    state.quota = Some(quota.clone());
    let (ok_err, ok) = mcp(
        state.clone(),
        Some(WRITER),
        "write_resource",
        json!({"path": "/alice/first", "content": "12345678"}),
    )
    .await;
    assert!(!ok_err && ok.contains("wrote"), "{ok}");
    let (over_err, over) = mcp(
        state,
        Some(WRITER),
        "write_resource",
        json!({"path": "/alice/second", "content": "12345"}),
    )
    .await;
    assert!(over_err, "{over}");
    assert!(
        s.get("/alice/second").await.is_err(),
        "over-quota write landed"
    );
    assert_eq!(quota.usage("alice").await.unwrap().used_bytes, 8);
}

#[actix_web::test]
async fn mcp_write_to_missing_target_does_not_borrow_the_parent_grant() {
    // Write is granted on the container itself (`accessTo`, no `default`), so a
    // new child is not covered; REST refuses the PUT, and MCP must too.
    let s = Arc::new(MemoryBackend::new());
    let acl = format!(
        "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
         <#w> a acl:Authorization ; acl:agent <{WRITER}> ;\n\
           acl:accessTo </box/> ; acl:mode acl:Read, acl:Write .\n"
    );
    s.put("/box.acl", Bytes::from(acl), "text/turtle")
        .await
        .unwrap();
    s.put("/box/", Bytes::new(), "text/plain").await.ok();
    let mut state = AppState::new(s.clone());
    state.mcp_enabled = true;
    let (err, out) = mcp(
        state.clone(),
        Some(WRITER),
        "write_resource",
        json!({"path": "/box/new", "content": "x"}),
    )
    .await;
    assert!(err && out.contains("access denied"), "{out}");
    assert!(s.get("/box/new").await.is_err());

    // Positive control: with `acl:default` the same write is granted.
    let acl = format!(
        "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
         <#w> a acl:Authorization ; acl:agent <{WRITER}> ;\n\
           acl:accessTo </box/> ; acl:default </box/> ; acl:mode acl:Read, acl:Write .\n"
    );
    s.put("/box.acl", Bytes::from(acl), "text/turtle")
        .await
        .unwrap();
    let (err, out) = mcp(
        state,
        Some(WRITER),
        "write_resource",
        json!({"path": "/box/new", "content": "x"}),
    )
    .await;
    assert!(!err && out.contains("wrote"), "{out}");
}

fn dev_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
