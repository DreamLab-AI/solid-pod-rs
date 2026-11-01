//! Lane-1 audit probe (scratch copy only): run JSS #631 fixtures through our code.
#![cfg(feature = "dev-bearer")]

use std::sync::Arc;

use actix_web::test;
use base64::Engine as _;
use bytes::Bytes;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use solid_pod_rs::storage::{memory::MemoryBackend, Storage};
use solid_pod_rs::wac::{evaluate_access, parse_jsonld_acl, parse_turtle_acl, AccessMode};
use solid_pod_rs_server::{build_app, AppState};

const SECRET: &str = "01234567890123456789012345678901";
const OWNER: &str = "https://owner.example/profile/card#me";
const ACL: &str = "http://www.w3.org/ns/auth/acl#";
const RES: &str = "/me/public/doc.ttl";
const RES_ACL: &str = "/me/public/doc.ttl.acl";

fn dev_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn bearer(web_id: &str) -> String {
    std::env::set_var("TOKEN_SECRET", SECRET);
    let data = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        serde_json::json!({"webId": web_id, "iat": dev_now() - 10, "exp": dev_now() + 3600, "aud": solid_pod_rs_server::DEV_BEARER_AUDIENCE}).to_string(),
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
    mac.update(data.as_bytes());
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("Bearer {data}.{sig}")
}
fn owner_acl_ttl() -> String {
    format!("@prefix acl: <{ACL}> .\n<#owner> a acl:Authorization ; acl:agent <{OWNER}> ;\n  acl:accessTo <{RES}> ; acl:mode acl:Read, acl:Write, acl:Control .\n")
}

async fn fresh() -> Arc<dyn Storage> {
    let s: Arc<dyn Storage> = Arc::new(MemoryBackend::new());
    s.put(RES, Bytes::from("<#a> <#b> <#c> .\n"), "text/turtle").await.unwrap();
    s.put(RES_ACL, Bytes::from(owner_acl_ttl()), "text/turtle").await.unwrap();
    s
}

async fn call(s: &Arc<dyn Storage>, method: &str, uri: &str, ct: Option<&str>, body: &str, who: Option<&str>) -> (u16, String) {
    let app = test::init_service(build_app(AppState::new(s.clone()))).await;
    let mut req = match method {
        "PUT" => test::TestRequest::put(),
        "PATCH" => test::TestRequest::patch(),
        _ => test::TestRequest::get(),
    }
    .uri(uri);
    if let Some(c) = ct {
        req = req.insert_header(("content-type", c));
    }
    if let Some(w) = who {
        req = req.insert_header(("Authorization", bearer(w)));
    }
    if method != "GET" {
        req = req.set_payload(body.to_string());
    }
    let resp = test::call_service(&app, req.to_request()).await;
    let st = resp.status().as_u16();
    let b = test::read_body(resp).await;
    (st, String::from_utf8_lossy(&b).chars().take(160).collect())
}


async fn seeded(acl: &str) -> Arc<dyn Storage> {
    let s: Arc<dyn Storage> = Arc::new(MemoryBackend::new());
    s.put(RES, Bytes::from("<#a> <#b> <#c> .\n"), "text/turtle").await.unwrap();
    s.put(RES_ACL, Bytes::from(acl.to_string()), "text/turtle").await.unwrap();
    s
}

fn ttl(target_access: &str) -> String {
    format!("@prefix acl: <{ACL}> .\n<#owner> a acl:Authorization ; acl:agent <{OWNER}> ;\n  acl:accessTo <{target_access}> ; acl:mode acl:Read, acl:Write, acl:Control .\n")
}

#[actix_web::test]
async fn v1_absolute_vs_relative_seeded() {
    for target in [
        "/me/public/doc.ttl",
        "http://localhost:8080/me/public/doc.ttl",
        "http://127.0.0.1:8080/me/public/doc.ttl",
        "https://pod.example/me/public/doc.ttl",
        "./doc.ttl",
        "doc.ttl",
        "",
    ] {
        let s = seeded(&ttl(target)).await;
        let (g, _) = call(&s, "GET", RES, None, "", Some(OWNER)).await;
        let (ga, _) = call(&s, "GET", RES_ACL, None, "", Some(OWNER)).await;
        println!("V1 seeded accessTo <{target}>: owner GET res={g} acl={ga}");
    }
    // container default via root ACL
    for target in ["/", "./", "http://localhost:8080/", "<self-empty>"] {
        let t = if target == "<self-empty>" { "" } else { target };
        let s: Arc<dyn Storage> = Arc::new(MemoryBackend::new());
        s.put(RES, Bytes::from("<#a> <#b> <#c> .\n"), "text/turtle").await.unwrap();
        s.put("/.acl", Bytes::from(format!("@prefix acl: <{ACL}> .\n<#owner> a acl:Authorization ; acl:agent <{OWNER}> ;\n  acl:accessTo <{t}> ; acl:default <{t}> ; acl:mode acl:Read, acl:Write, acl:Control .\n")), "text/turtle").await.unwrap();
        let (g, _) = call(&s, "GET", RES, None, "", Some(OWNER)).await;
        let (r, _) = call(&s, "GET", "/", None, "", Some(OWNER)).await;
        println!("V1 root .acl accessTo+default <{t}>: owner GET {RES}={g} GET /={r}");
    }
}

#[actix_web::test]
async fn v1_absolute_put_lockout_turtle() {
    let s = seeded(&owner_acl_ttl()).await;
    let (p, b) = call(&s, "PUT", RES_ACL, Some("text/turtle"), &ttl("http://localhost:8080/me/public/doc.ttl"), Some(OWNER)).await;
    let (g, _) = call(&s, "GET", RES, None, "", Some(OWNER)).await;
    let (rep, _) = call(&s, "PUT", RES_ACL, Some("text/turtle"), &owner_acl_ttl(), Some(OWNER)).await;
    println!("V1 PUT turtle abs accessTo: PUT={p} {b:?} -> owner GET={g} repair PUT={rep}");
}

#[actix_web::test]
async fn v1_unparseable_lockout() {
    for (ct, body) in [("application/ld+json", "{not json"), ("application/ld+json", "[]"), ("text/plain", "hello"), ("text/turtle", "this is @@ not turtle <<")] {
        let s = seeded(&owner_acl_ttl()).await;
        let (p, b) = call(&s, "PUT", RES_ACL, Some(ct), body, Some(OWNER)).await;
        let (g, _) = call(&s, "GET", RES, None, "", Some(OWNER)).await;
        let (ga, _) = call(&s, "GET", RES_ACL, None, "", Some(OWNER)).await;
        let (rep, _) = call(&s, "PUT", RES_ACL, Some("text/turtle"), &owner_acl_ttl(), Some(OWNER)).await;
        println!("V1 unparseable {ct} {body:?}: PUT={p} {b:?} -> owner GET res={g} acl={ga} repair={rep}");
    }
}

#[actix_web::test]
async fn v1_provisioned_type_index() {
    use solid_pod_rs::{provision_pod, ProvisionPlan};
    let s: Arc<dyn Storage> = Arc::new(MemoryBackend::new());
    let plan = ProvisionPlan::new("abc123", "http://localhost:8080");
    let out = provision_pod(&*s, &plan).await.unwrap();
    let (acl, _) = s.get("/settings/publicTypeIndex.jsonld.acl").await.unwrap();
    println!("V1 provision webid={} pod_root={}\n--acl--\n{}", out.webid, out.pod_root, String::from_utf8_lossy(&acl));
    let (anon, _) = call(&s, "GET", "/settings/publicTypeIndex.jsonld", None, "", None).await;
    let (own, _) = call(&s, "GET", "/settings/publicTypeIndex.jsonld", None, "", Some(&out.webid)).await;
    println!("V1 provisioned publicTypeIndex: anon GET={anon} owner GET={own}");
}

#[actix_web::test]
async fn v1_named_pod_create() {
    let s: Arc<dyn Storage> = Arc::new(MemoryBackend::new());
    let mut st = AppState::new(s.clone());
    st.nodeinfo.open_registrations = true;
    let app = test::init_service(build_app(st)).await;
    let req = test::TestRequest::post().uri("/.pods")
        .insert_header(("content-type", "application/json"))
        .set_payload(r#"{"name":"alice"}"#).to_request();
    let resp = test::call_service(&app, req).await;
    let code = resp.status().as_u16();
    let body = String::from_utf8_lossy(&test::read_body(resp).await).to_string();
    println!("V1 named-pod POST /.pods: {code} {body}");
    let webid = serde_json::from_str::<serde_json::Value>(&body).ok()
        .and_then(|v| v["webId"].as_str().map(String::from)).unwrap_or_default();
    let keys = s.list("/").await.map(|v| format!("{v:?}")).unwrap_or_else(|e| format!("{e}"));
    println!("V1 named-pod storage root list: {keys}");
    for (m, uri, who) in [("PUT", "/alice/public/x.ttl", Some(webid.as_str())), ("GET", "/alice/", Some(webid.as_str())), ("GET", "/alice/profile/card", None), ("PUT", "/alice/public/y.ttl", None)] {
        let mut r = if m == "PUT" { test::TestRequest::put() } else { test::TestRequest::get() }.uri(uri);
        if m == "PUT" { r = r.insert_header(("content-type", "text/turtle")).set_payload("<#a> <#b> <#c> .\n"); }
        if let Some(w) = who { if !w.is_empty() { r = r.insert_header(("Authorization", bearer(w))); } }
        let resp = test::call_service(&app, r.to_request()).await;
        println!("V1 named-pod {m} {uri} as {}: {}", if who.is_some() {"owner"} else {"anon"}, resp.status().as_u16());
    }
}

macro_rules! hdr_call {
    ($app:expr, $method:expr, $uri:expr, $ct:expr, $body:expr, $who:expr) => {{
        let method: &str = $method; let ct: Option<&str> = $ct; let who: Option<&str> = $who;
        let mut r = match method { "PUT" => test::TestRequest::put(), _ => test::TestRequest::get() }.uri($uri);
        if let Some(c) = ct { r = r.insert_header(("content-type", c)); }
        if let Some(w) = who { r = r.insert_header(("Authorization", bearer(w))); }
        if method == "PUT" { r = r.set_payload(($body).to_string()); }
        let resp = test::call_service($app, r.to_request()).await;
        let link = resp.headers().get("link").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        (resp.status().as_u16(), link)
    }};
}

#[actix_web::test]
async fn v1_m4_container_acl_location() {
    let s: Arc<dyn Storage> = Arc::new(MemoryBackend::new());
    // Root ACL: owner full control everywhere; public read by default everywhere.
    s.put("/.acl", Bytes::from(format!("@prefix acl: <{ACL}> .\n@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n<#owner> a acl:Authorization ; acl:agent <{OWNER}> ; acl:accessTo </> ; acl:default </> ; acl:mode acl:Read, acl:Write, acl:Control .\n<#pub> a acl:Authorization ; acl:agentClass foaf:Agent ; acl:accessTo </> ; acl:default </> ; acl:mode acl:Read .\n")), "text/turtle").await.unwrap();
    s.put("/c/.meta", Bytes::from_static(b"{}"), "application/ld+json").await.unwrap();
    s.put("/c/x.ttl", Bytes::from("<#a> <#b> <#c> .\n"), "text/turtle").await.unwrap();
    let app = test::init_service(build_app(AppState::new(s.clone()))).await;
    let (st, link) = hdr_call!(&app, "GET", "/c/", None, "", Some(OWNER));
    println!("V1 M4 GET /c/ owner: {st} Link: {link}");
    let (st, link) = hdr_call!(&app, "GET", "/nope/", None, "", Some(OWNER));
    println!("V1 M4 GET /nope/ (404) owner: {st} Link: {link}");
    let (st, _) = hdr_call!(&app, "GET", "/c/x.ttl", None, "", None);
    println!("V1 M4 baseline anon GET /c/x.ttl: {st}");
    let restrictive = format!("@prefix acl: <{ACL}> .\n<#owner> a acl:Authorization ; acl:agent <{OWNER}> ; acl:accessTo </c/> ; acl:default </c/> ; acl:mode acl:Read, acl:Write, acl:Control .\n");
    // 1. Write at the advertised (JSS-layout) location /c/.acl
    let (p, _) = hdr_call!(&app, "PUT", "/c/.acl", Some("text/turtle"), &restrictive, Some(OWNER));
    let (a, _) = hdr_call!(&app, "GET", "/c/x.ttl", None, "", None);
    let (ac, _) = hdr_call!(&app, "GET", "/c/", None, "", None);
    let (o, _) = hdr_call!(&app, "GET", "/c/x.ttl", None, "", Some(OWNER));
    println!("V1 M4 after PUT /c/.acl (owner-only) = {p}: anon GET /c/x.ttl={a} anon GET /c/={ac} owner GET /c/x.ttl={o}");
    let (ra, _) = hdr_call!(&app, "GET", "/c/.acl", None, "", Some(OWNER));
    let (rb, _) = hdr_call!(&app, "GET", "/c.acl", None, "", Some(OWNER));
    println!("V1 M4 stored: GET /c/.acl={ra} GET /c.acl={rb}");
    // 2. Write at the resolver's location /c.acl
    let (p2, _) = hdr_call!(&app, "PUT", "/c.acl", Some("text/turtle"), &restrictive, Some(OWNER));
    let (a2, _) = hdr_call!(&app, "GET", "/c/x.ttl", None, "", None);
    let (ac2, _) = hdr_call!(&app, "GET", "/c/", None, "", None);
    let (o2, _) = hdr_call!(&app, "GET", "/c/x.ttl", None, "", Some(OWNER));
    println!("V1 M4 after PUT /c.acl (owner-only) = {p2}: anon GET /c/x.ttl={a2} anon GET /c/={ac2} owner GET /c/x.ttl={o2}");
}
