//! Shared harness for the container-ACL layout tests (SP-PAR-290).
#![allow(dead_code)]

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};

use actix_web::{http::Method, test};
use bytes::Bytes;
use solid_pod_rs::auth::nip98;
use solid_pod_rs::storage::{memory::MemoryBackend, Storage};
use solid_pod_rs_server::{build_app, AppState};

const ACL: &str = "http://www.w3.org/ns/auth/acl#";

pub struct Agent {
    secret: String,
    pub id: String,
}

pub fn agent(seed: u8) -> Agent {
    let mut bytes = [0x61; 32];
    bytes[0] = seed;
    let key = k256::schnorr::SigningKey::from_slice(&bytes).unwrap();
    Agent {
        secret: hex::encode(key.to_bytes()),
        id: format!("did:nostr:{}", hex::encode(key.verifying_key().to_bytes())),
    }
}

static CLOCK: AtomicU64 = AtomicU64::new(0);

pub async fn call(
    state: AppState,
    who: Option<&Agent>,
    method: &str,
    path: &str,
    body: &str,
) -> (u16, Option<String>) {
    let app = test::init_service(build_app(state)).await;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // A unique query string keeps every signed request a distinct NIP-98
    // event, so the single-use replay guard never refuses one.
    let n = CLOCK.fetch_add(1, Ordering::Relaxed);
    let target = format!("{path}?n={n}");
    let path = target.as_str();
    let mut req = test::TestRequest::default()
        .method(Method::from_bytes(method.as_bytes()).unwrap())
        .uri(path)
        .insert_header(("host", "pod.example"))
        .insert_header(("content-type", "text/turtle"))
        .set_payload(body.to_owned());
    if let Some(a) = who {
        let token = nip98::mint_with_payload(
            &format!("http://pod.example{path}"),
            method,
            Some(body.as_bytes()),
            &a.secret,
            now,
        )
        .unwrap();
        req = req.insert_header(("authorization", nip98::authorization_header(&token)));
    }
    let resp = test::call_service(&app, req.to_request()).await;
    let link = resp
        .headers()
        .get("link")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    (resp.status().as_u16(), link)
}

fn rule(id: &str, agents: &[&str], target: &str, modes: &str) -> String {
    let agents = agents
        .iter()
        .map(|a| format!("<{a}>"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "<#{id}> a acl:Authorization ; acl:agent {agents} ;\n  acl:accessTo <{target}> ; acl:default <{target}> ;\n  acl:mode {modes} .\n"
    )
}

pub fn turtle(rules: &str) -> String {
    format!("@prefix acl: <{ACL}> .\n{rules}")
}

/// A disk state of the container ACL.
#[derive(Clone, Copy, Debug)]
pub enum Disk {
    None,
    SidecarOnly,
    InnerOnly,
    BothIdentical,
    BothDiffering,
    MalformedSidecar,
    MalformedInner,
}

pub const ALL: [Disk; 7] = [
    Disk::None,
    Disk::SidecarOnly,
    Disk::InnerOnly,
    Disk::BothIdentical,
    Disk::BothDiffering,
    Disk::MalformedSidecar,
    Disk::MalformedInner,
];

pub async fn storage(disk: Disk, owner: &Agent, b: &Agent) -> Arc<MemoryBackend> {
    let s = Arc::new(MemoryBackend::new());
    let full = "acl:Read, acl:Write, acl:Control";
    // The root: owner and B hold everything, inherited.
    let root = turtle(&rule("root", &[&owner.id, &b.id], "/", full));
    s.put("/.acl", Bytes::from(root), "text/turtle")
        .await
        .unwrap();
    for p in ["/docs/a.txt", "/docs/sub/b.txt"] {
        s.put(p, Bytes::from_static(b"x"), "text/plain")
            .await
            .unwrap();
    }
    let owner_only = turtle(&rule("c", &[&owner.id], "/docs/", full));
    // `differing`: the inner copy admits B as well, the sidecar does not.
    let wider = turtle(&rule("c", &[&owner.id, &b.id], "/docs/", full));
    let bad = "this is not an acl".to_string();
    let put = |key: &'static str, body: String| {
        let s = s.clone();
        async move { s.put(key, Bytes::from(body), "text/turtle").await.unwrap() }
    };
    match disk {
        Disk::None => {}
        Disk::SidecarOnly => {
            put("/docs.acl", owner_only).await;
        }
        Disk::InnerOnly => {
            put("/docs/.acl", owner_only).await;
        }
        Disk::BothIdentical => {
            put("/docs.acl", owner_only.clone()).await;
            put("/docs/.acl", owner_only).await;
        }
        Disk::BothDiffering => {
            put("/docs.acl", owner_only).await;
            put("/docs/.acl", wider).await;
        }
        Disk::MalformedSidecar => {
            put("/docs.acl", bad).await;
        }
        Disk::MalformedInner => {
            put("/docs/.acl", bad).await;
            put("/docs.acl", owner_only).await;
        }
    }
    s
}

/// One row of the matrix as a compact literal-comparable string.
pub async fn row(mk: impl Fn() -> AppState, owner: &Agent, b: &Agent) -> String {
    let mut out = Vec::new();
    for (name, who) in [("owner", Some(owner)), ("B", Some(b)), ("anon", None)] {
        let mut cells = Vec::new();
        for p in ["/docs/", "/docs/a.txt", "/docs/sub/b.txt"] {
            cells.push(call(mk(), who, "GET", p, "").await.0);
        }
        for p in ["/docs/a.txt", "/docs/sub/b.txt", "/docs/new.txt"] {
            cells.push(call(mk(), who, "PUT", p, "<#a> <#b> <#c> .").await.0);
        }
        for p in ["/docs.acl", "/docs/.acl"] {
            cells.push(call(mk(), who, "GET", p, "").await.0);
        }
        let cells: Vec<String> = cells.iter().map(u16::to_string).collect();
        out.push(format!("{name}:{}", cells.join(",")));
    }
    out.join(" ")
}
