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

fn lib_report(name: &str, doc: Result<solid_pod_rs::wac::AclDocument, solid_pod_rs::PodError>, agent: &str, path: &str) {
    match doc {
        Err(e) => println!("LIB {name}: Err({e})"),
        Ok(d) => {
            let n = d.graph.as_ref().map(|g| g.len());
            let r = evaluate_access(Some(&d), Some(agent), path, AccessMode::Read, None);
            let w = evaluate_access(Some(&d), Some(agent), path, AccessMode::Write, None);
            let c = evaluate_access(Some(&d), Some(agent), path, AccessMode::Control, None);
            let pubr = evaluate_access(Some(&d), None, path, AccessMode::Read, None);
            println!("LIB {name}: Ok graph={n:?} owner R={r} W={w} C={c} anonR={pubr} agentClass={:?}",
                d.graph.as_ref().and_then(|g| g.first()).map(|a| format!("{:?}", a.agent_class)));
        }
    }
}

#[actix_web::test]
async fn lib_fixtures() {
    let web_id = "http://127.0.0.1:8732/me/profile/card.jsonld#me";
    let abs = "http://127.0.0.1:8732/me/public/doc.ttl";
    for (label, target) in [("abs", abs), ("path", RES)] {
        let expanded = serde_json::json!([{
            "@id": "#owner", "@type": [format!("{ACL}Authorization")],
            format!("{ACL}agent"): [{"@id": web_id}],
            format!("{ACL}accessTo"): [{"@id": target}],
            format!("{ACL}mode"): [{"@id": format!("{ACL}Read")},{"@id": format!("{ACL}Write")},{"@id": format!("{ACL}Control")}]
        }]);
        lib_report(&format!("805 expanded/{label}"), parse_jsonld_acl(expanded.to_string().as_bytes()), web_id, RES);
        let alt = serde_json::json!({"@context": {"wac": ACL}, "@graph": [{
            "@id": "#owner", "@type": "wac:Authorization",
            "wac:agent": {"@id": web_id}, "wac:accessTo": {"@id": target},
            "wac:mode": [{"@id":"wac:Read"},{"@id":"wac:Write"},{"@id":"wac:Control"}]}]});
        lib_report(&format!("816 altprefix/{label}"), parse_jsonld_acl(alt.to_string().as_bytes()), web_id, RES);
        let arr = serde_json::json!({"@context": ["https://www.w3.org/ns/solid/context", {"auth": ACL}], "@graph": [{
            "@id": "#owner", "@type": "auth:Authorization",
            "auth:agent": {"@id": web_id}, "auth:accessTo": {"@id": target},
            "auth:mode": [{"@id":"auth:Read"},{"@id":"auth:Write"},{"@id":"auth:Control"}]}]});
        lib_report(&format!("830 ctxarray/{label}"), parse_jsonld_acl(arr.to_string().as_bytes()), web_id, RES);
        let vocab = serde_json::json!({"@context": {"@vocab": ACL,
            "agent": {"@id": format!("{ACL}agent"), "@type": "@id"},
            "accessTo": {"@id": format!("{ACL}accessTo"), "@type": "@id"},
            "mode": {"@id": format!("{ACL}mode"), "@type": "@id"}},
            "@id": "#owner", "@type": "Authorization", "agent": web_id, "accessTo": target, "mode": ["Read","Write","Control"]});
        lib_report(&format!("844 vocab/{label}"), parse_jsonld_acl(vocab.to_string().as_bytes()), web_id, RES);
        let ttl = format!("@prefix wac: <{ACL}> .\n<#owner> a wac:Authorization ;\n  wac:agent <{web_id}> ;\n  wac:accessTo <{target}> ;\n  wac:mode wac:Read, wac:Write, wac:Control .");
        lib_report(&format!("861 turtle-wac/{label}"), parse_turtle_acl(&ttl), web_id, RES);
        // control: canonical acl:-keyed @graph form
        let canon = serde_json::json!({"@context": {"acl": ACL}, "@graph": [{
            "@id": "#owner", "@type": "acl:Authorization",
            "acl:agent": {"@id": web_id}, "acl:accessTo": {"@id": target},
            "acl:mode": [{"@id":"acl:Read"},{"@id":"acl:Write"},{"@id":"acl:Control"}]}]});
        lib_report(&format!("control canonical-@graph/{label}"), parse_jsonld_acl(canon.to_string().as_bytes()), web_id, RES);
        // JSS-common single top-level node, acl: keys, no @graph
        let single = serde_json::json!({"@context": {"acl": ACL},
            "@id": "#owner", "@type": "acl:Authorization",
            "acl:agent": {"@id": web_id}, "acl:accessTo": {"@id": target},
            "acl:mode": [{"@id":"acl:Read"},{"@id":"acl:Write"},{"@id":"acl:Control"}]});
        lib_report(&format!("single-node acl:/{label}"), parse_jsonld_acl(single.to_string().as_bytes()), web_id, RES);
        // @type as array inside @graph
        let tarr = serde_json::json!({"@context": {"acl": ACL}, "@graph": [{
            "@id": "#owner", "@type": ["acl:Authorization"],
            "acl:agent": {"@id": web_id}, "acl:accessTo": {"@id": target},
            "acl:mode": [{"@id":"acl:Read"}]}]});
        lib_report(&format!("type-array/{label}"), parse_jsonld_acl(tarr.to_string().as_bytes()), web_id, RES);
    }
    let agentclass = serde_json::json!({"@context": {"wac": ACL, "people": "http://xmlns.com/foaf/0.1/"}, "@graph": [{
        "@id": "#public", "@type": "wac:Authorization",
        "wac:agentClass": {"@id": "people:Agent"}, "wac:accessTo": {"@id": RES}, "wac:mode": {"@id": "wac:Read"}}]});
    lib_report("870 agentclass-people", parse_jsonld_acl(agentclass.to_string().as_bytes()), web_id, RES);
    let agentclass2 = serde_json::json!({"@context": {"acl": ACL, "people": "http://xmlns.com/foaf/0.1/"}, "@graph": [{
        "@id": "#public", "@type": "acl:Authorization",
        "acl:agentClass": {"@id": "people:Agent"}, "acl:accessTo": {"@id": RES}, "acl:mode": {"@id": "acl:Read"}}]});
    lib_report("870b agentclass-people (acl: keys)", parse_jsonld_acl(agentclass2.to_string().as_bytes()), web_id, RES);
    // JSON text through Turtle parser (what the guard's heuristic does)
    let expanded = serde_json::json!([{"@id": "#owner", "@type": [format!("{ACL}Authorization")], format!("{ACL}agent"): [{"@id": web_id}]}]).to_string();
    lib_report("json-through-turtle", parse_turtle_acl(&expanded), web_id, RES);
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

async fn put_case(name: &str, ct: &str, body: &str) {
    let s = fresh().await;
    let (st, b) = call(&s, "PUT", RES_ACL, Some(ct), body, Some(OWNER)).await;
    let (g, _) = call(&s, "GET", RES, None, "", Some(OWNER)).await;
    let (ga, _) = call(&s, "GET", RES_ACL, None, "", Some(OWNER)).await;
    let (anon, _) = call(&s, "GET", RES, None, "", None).await;
    // repair attempt with the original owner ACL
    let (rep, _) = call(&s, "PUT", RES_ACL, Some("text/turtle"), &owner_acl_ttl(), Some(OWNER)).await;
    println!("HTTP {name}: PUT={st} body={b:?} | after: owner GET res={g} owner GET acl={ga} anon GET res={anon} | repair PUT={rep}");
}

#[actix_web::test]
async fn http_fixtures() {
    let ld = "application/ld+json";
    for (label, target) in [("path", RES.to_string()), ("abs", format!("http://localhost:8080{RES}"))] {
        let expanded = serde_json::json!([{
            "@id": "#owner", "@type": [format!("{ACL}Authorization")],
            format!("{ACL}agent"): [{"@id": OWNER}],
            format!("{ACL}accessTo"): [{"@id": target}],
            format!("{ACL}mode"): [{"@id": format!("{ACL}Read")},{"@id": format!("{ACL}Write")},{"@id": format!("{ACL}Control")}]
        }]);
        put_case(&format!("899 expanded-array/{label}"), ld, &expanded.to_string()).await;
        let canon = serde_json::json!({"@context": {"acl": ACL}, "@graph": [{
            "@id": "#owner", "@type": "acl:Authorization",
            "acl:agent": {"@id": OWNER}, "acl:accessTo": {"@id": target},
            "acl:mode": [{"@id":"acl:Read"},{"@id":"acl:Write"},{"@id":"acl:Control"}]}]});
        put_case(&format!("control canonical-@graph/{label}"), ld, &canon.to_string()).await;
    }
    put_case("928 no-authorizations", ld, &serde_json::json!({"@context": {"acl": ACL}, "@id": "#owner", "acl:agent": {"@id": "x"}}).to_string()).await;
    put_case("941 agent-no-mode", ld, &serde_json::json!({"@context": {"acl": ACL}, "@id": "#owner", "@type": "acl:Authorization", "acl:agent": {"@id": OWNER}, "acl:accessTo": {"@id": RES}}).to_string()).await;
    put_case("957 mode-no-agent", ld, &serde_json::json!({"@context": {"acl": ACL}, "@id": "#owner", "@type": "acl:Authorization", "acl:accessTo": {"@id": RES}, "acl:mode": [{"@id":"acl:Read"},{"@id":"acl:Control"}]}).to_string()).await;
    put_case("941g agent-no-mode @graph", ld, &serde_json::json!({"@context": {"acl": ACL}, "@graph": [{"@id": "#owner", "@type": "acl:Authorization", "acl:agent": {"@id": OWNER}, "acl:accessTo": {"@id": RES}}]}).to_string()).await;
    put_case("957g mode-no-agent @graph", ld, &serde_json::json!({"@context": {"acl": ACL}, "@graph": [{"@id": "#owner", "@type": "acl:Authorization", "acl:accessTo": {"@id": RES}, "acl:mode": [{"@id":"acl:Read"},{"@id":"acl:Control"}]}]}).to_string()).await;
    put_case("973setup single-expanded-node", ld, &serde_json::json!({"@id": "#owner", "@type": format!("{ACL}Authorization"), format!("{ACL}agent"): {"@id": OWNER}, format!("{ACL}accessTo"): {"@id": RES}, format!("{ACL}mode"): [{"@id": format!("{ACL}Read")},{"@id": format!("{ACL}Write")},{"@id": format!("{ACL}Control")}]}).to_string()).await;
    put_case("1004 invalid-json", ld, "{not json").await;
    put_case("empty-array []", ld, "[]").await;
    put_case("text/plain garbage", "text/plain", "hello").await;
    put_case("graph-with-string-mode", ld, &serde_json::json!({"@graph": [{"acl:mode": "acl:Read"}]}).to_string()).await;
    put_case("turtle zero-auth", "text/turtle", &format!("@prefix acl: <{ACL}> .\n")).await;
    put_case("turtle wac-prefix owner", "text/turtle", &format!("@prefix wac: <{ACL}> .\n<#owner> a wac:Authorization ; wac:agent <{OWNER}> ; wac:accessTo <{RES}> ; wac:mode wac:Read, wac:Write, wac:Control .\n")).await;
    put_case("public-read-only (grants something, drops owner Control)", "text/turtle", &format!("@prefix acl: <{ACL}> .\n@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n<#p> a acl:Authorization ; acl:agentClass foaf:Agent ; acl:accessTo <{RES}> ; acl:mode acl:Read .\n")).await;

    // 973 PATCH: delete the only agent from a (Turtle-stored) owner ACL.
    let s = fresh().await;
    let patch = format!("@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n@prefix acl: <{ACL}>.\n_:patch a solid:InsertDeletePatch;\n  solid:deletes {{ <#owner> acl:agent <{OWNER}> }}.\n");
    let (st, b) = call(&s, "PATCH", RES_ACL, Some("text/n3"), &patch, Some(OWNER)).await;
    let (g, _) = call(&s, "GET", RES, None, "", Some(OWNER)).await;
    println!("HTTP 973 PATCH delete-only-agent: PATCH={st} body={b:?} | after owner GET res={g}");
    // same, deleting a mode while keeping Control
    let s = fresh().await;
    let patch2 = format!("@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n@prefix acl: <{ACL}>.\n_:patch a solid:InsertDeletePatch;\n  solid:deletes {{ <#owner> acl:mode acl:Write }}.\n");
    let (st, b) = call(&s, "PATCH", RES_ACL, Some("text/n3"), &patch2, Some(OWNER)).await;
    println!("HTTP PATCH delete-write-keep-control: PATCH={st} body={b:?}");
}
