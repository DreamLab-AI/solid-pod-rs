//! SP-PAR-281: the ActivityPub inbox, outbox, collections, WebFinger link and
//! signed delivery, mounted on the pod server behind `--ap-federation`.
//!
//! Properties under test, each with the check that fails if it is violated:
//!
//! * nothing is mounted unless federation is configured;
//! * the inbox stores nothing until the request is proven to come from the
//!   actor it names (unsigned, tampered, wrong signer, oversized, wrong host);
//! * only the pod owner (Control on `/`, NIP-98 bound to the body) can post
//!   to the outbox;
//! * outbound fetches and deliveries use the guarded, pinned path: the
//!   default policy refuses loopback, so the two-server flow below runs only
//!   because the test names the allowance;
//! * the key and the store under `.ap/` are never served.
#![cfg(feature = "activitypub")]

use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use actix_web::{test, HttpServer};
use bytes::Bytes;
use serde_json::{json, Value};
use solid_pod_rs::auth::nip98;
use solid_pod_rs::storage::{memory::MemoryBackend, Storage};
use solid_pod_rs_activitypub::{
    generate_actor_keypair, sign_request, OutboundRequest, SsrfGuard, Store,
};
use solid_pod_rs_server::activitypub::{ApConfig, Federation};
use solid_pod_rs_server::{build_app, AppState};

const ACL: &str = "http://www.w3.org/ns/auth/acl#";

fn token(url: &str, method: &str, body: Option<&[u8]>, sk: u8) -> String {
    static BASE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let base = *BASE.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(30)
    });
    let now = base + SEQ.fetch_add(1, Ordering::Relaxed);
    let hex_sk = hex::encode([sk; 32]);
    let t = nip98::mint_with_payload(url, method, body, &hex_sk, now).unwrap();
    format!("Nostr {t}")
}

fn did_of(sk: u8) -> String {
    let key = k256::schnorr::SigningKey::from_slice(&[sk; 32]).unwrap();
    format!("did:nostr:{}", hex::encode(key.verifying_key().to_bytes()))
}

async fn owner_acl(storage: &MemoryBackend, owner_sk: u8) {
    storage
        .put(
            "/.acl",
            Bytes::from(format!(
                "@prefix acl: <{ACL}> .\n<#o> a acl:Authorization ; acl:agent <{}> ; \
                 acl:accessTo </> ; acl:default </> ; acl:mode acl:Read, acl:Write, acl:Control .\n",
                did_of(owner_sk)
            )),
            "text/turtle",
        )
        .await
        .unwrap();
}

/// One running pod with federation mounted.
struct Node {
    base: String,
    owner_sk: u8,
    fed: Arc<Federation>,
    private_pem: String,
    public_pem: String,
    _dir: tempfile::TempDir,
}

async fn node(user: &str, owner_sk: u8, guard: SsrfGuard) -> Node {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(MemoryBackend::new());
    owner_acl(&storage, owner_sk).await;
    let (private_pem, public_pem) = generate_actor_keypair().unwrap();
    let cfg = ApConfig::from_knobs(Some(user), Some(user), None, None, public_pem.clone()).unwrap();
    let store = Store::connect(&format!(
        "sqlite://{}?mode=rwc",
        dir.path().join("ap.db").display()
    ))
    .await
    .unwrap();
    let fed = Federation::start(
        &cfg,
        private_pem.clone(),
        &base,
        store,
        guard,
        Duration::from_millis(100),
    )
    .unwrap();
    let mut state = AppState::new(storage);
    state.public_base_url = Some(base.clone());
    state.activitypub = Some(Arc::new(cfg));
    state.set_ap_federation(fed.clone());
    let server = HttpServer::new(move || build_app(state.clone()))
        .workers(1)
        .listen(listener)
        .unwrap();
    actix_web::rt::spawn(server.run());
    Node {
        base,
        owner_sk,
        fed,
        private_pem,
        public_pem,
        _dir: dir,
    }
}

impl Node {
    fn actor(&self) -> String {
        format!("{}/profile/card.jsonld#me", self.base)
    }

    /// POST `body` to this node's outbox as its owner.
    async fn post_outbox(&self, body: &Value) -> reqwest::Response {
        let url = format!("{}/profile/card.jsonld/outbox", self.base);
        let raw = serde_json::to_vec(body).unwrap();
        reqwest::Client::new()
            .post(&url)
            .header(
                "authorization",
                token(&url, "POST", Some(&raw), self.owner_sk),
            )
            .header("content-type", "application/activity+json")
            .body(raw)
            .send()
            .await
            .unwrap()
    }
}

/// A request signed by `signer` addressed to `target_inbox`, as a remote
/// server would send it.
fn signed(signer: &Node, target_inbox: &str, body: &Value) -> OutboundRequest {
    let mut req = OutboundRequest {
        method: "POST".into(),
        url: target_inbox.into(),
        headers: vec![("Content-Type".into(), "application/activity+json".into())],
        body: serde_json::to_vec(body).unwrap(),
    };
    sign_request(
        &mut req,
        &signer.private_pem,
        &format!("{}/profile/card.jsonld#main-key", signer.base),
    )
    .unwrap();
    req
}

async fn send(req: &OutboundRequest) -> reqwest::Response {
    let mut b = reqwest::Client::new().post(&req.url);
    for (k, v) in &req.headers {
        b = b.header(k, v);
    }
    b.body(req.body.clone()).send().await.unwrap()
}

async fn eventually<F, Fut>(what: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..100 {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for: {what}");
}

const LOOPBACK: SsrfGuard = SsrfGuard::permit_loopback_for_tests();

#[actix_web::test]
async fn nothing_is_mounted_without_federation() {
    let app = test::init_service(build_app(AppState::new(Arc::new(MemoryBackend::new())))).await;
    for (method, uri) in [
        ("POST", "/inbox"),
        ("POST", "/profile/card.jsonld/inbox"),
        ("POST", "/profile/card.jsonld/outbox"),
    ] {
        let req = test::TestRequest::default()
            .method(method.parse().unwrap())
            .uri(uri)
            .set_payload("{}")
            .to_request();
        let status = test::call_service(&app, req).await.status().as_u16();
        assert!(matches!(status, 401 | 403 | 404 | 405), "{uri}: {status}");
    }
    for uri in [
        "/profile/card.jsonld/outbox",
        "/profile/card.jsonld/followers",
        "/profile/card.jsonld/following",
    ] {
        let req = test::TestRequest::get().uri(uri).to_request();
        let status = test::call_service(&app, req).await.status().as_u16();
        assert!(matches!(status, 401 | 403 | 404), "{uri}: {status}");
    }
}

#[actix_web::test]
async fn an_unsigned_inbox_post_is_refused_and_stores_nothing() {
    let a = node("alice", 0x11, LOOPBACK).await;
    let follow =
        json!({"id": "http://x/f/1", "type": "Follow", "actor": "http://x/a", "object": a.actor()});
    for path in ["/inbox", "/profile/card.jsonld/inbox"] {
        let r = reqwest::Client::new()
            .post(format!("{}{path}", a.base))
            .json(&follow)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 401, "{path}");
    }
    assert_eq!(a.fed.store().inbox_count().await.unwrap(), 0);
    assert_eq!(a.fed.store().follower_count(&a.actor()).await.unwrap(), 0);
}

#[actix_web::test]
async fn a_tampered_wrong_signer_or_wrong_host_request_is_refused() {
    let a = node("alice", 0x11, LOOPBACK).await;
    let b = node("bob", 0x22, LOOPBACK).await;
    let inbox = format!("{}/profile/card.jsonld/inbox", a.base);
    let follow = json!({"id": format!("{}/f/1", b.base), "type": "Follow", "actor": b.actor(), "object": a.actor()});

    // Body changed after signing: the digest no longer matches.
    let mut tampered = signed(&b, &inbox, &follow);
    tampered.body = serde_json::to_vec(
        &json!({"id": "http://x/f/2", "type": "Follow", "actor": b.actor(), "object": a.actor()}),
    )
    .unwrap();
    assert_eq!(send(&tampered).await.status().as_u16(), 401);

    // Signed by B, but the activity names C as the actor.
    let forged = json!({"id": format!("{}/f/3", b.base), "type": "Follow", "actor": "http://c.example/actor", "object": a.actor()});
    assert_eq!(
        send(&signed(&b, &inbox, &forged)).await.status().as_u16(),
        403
    );

    // Signed for another host: refused before any key is fetched.
    let ok = signed(&b, &inbox, &follow);
    let r = reqwest::Client::new()
        .post(&ok.url)
        .header("host", "other.example")
        .header("content-type", "application/activity+json")
        .header(
            "signature",
            &ok.headers.iter().find(|(n, _)| n == "Signature").unwrap().1,
        )
        .header(
            "date",
            &ok.headers.iter().find(|(n, _)| n == "Date").unwrap().1,
        )
        .header(
            "digest",
            &ok.headers.iter().find(|(n, _)| n == "Digest").unwrap().1,
        )
        .body(ok.body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 421);

    assert_eq!(a.fed.store().follower_count(&a.actor()).await.unwrap(), 0);
    assert!(!a
        .fed
        .store()
        .is_follower(&a.actor(), "http://c.example/actor")
        .await
        .unwrap());
}

#[actix_web::test]
async fn an_oversized_inbox_body_is_refused() {
    let a = node("alice", 0x11, LOOPBACK).await;
    let big = vec![b'a'; 300 * 1024];
    let r = reqwest::Client::new()
        .post(format!("{}/inbox", a.base))
        .body(big)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 413);
}

#[actix_web::test]
async fn only_the_owner_can_post_to_the_outbox() {
    let a = node("alice", 0x11, LOOPBACK).await;
    let url = format!("{}/profile/card.jsonld/outbox", a.base);
    let note = json!({"type": "Note", "content": "hello"});
    let raw = serde_json::to_vec(&note).unwrap();

    let anon = reqwest::Client::new()
        .post(&url)
        .body(raw.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(anon.status().as_u16(), 401);

    let other = reqwest::Client::new()
        .post(&url)
        .header("authorization", token(&url, "POST", Some(&raw), 0x33))
        .body(raw.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(other.status().as_u16(), 403);

    // A token minted for a different body does not authorise this one.
    let rebound = reqwest::Client::new()
        .post(&url)
        .header("authorization", token(&url, "POST", Some(b"{}"), 0x11))
        .body(raw.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(rebound.status().as_u16(), 401);

    let owner = a.post_outbox(&note).await;
    assert_eq!(owner.status().as_u16(), 201);
    let created: Value = owner.json().await.unwrap();
    assert_eq!(created["type"], "Create");
    assert_eq!(created["actor"], a.actor());

    let page: Value = reqwest::get(&url).await.unwrap().json().await.unwrap();
    assert_eq!(page["totalItems"], 1);
    assert_eq!(page["orderedItems"][0]["object"]["content"], "hello");

    // Activities that mean something other than "tell the followers" are refused.
    let r = a.post_outbox(&json!({"type": "Undo", "object": {}})).await;
    assert_eq!(r.status().as_u16(), 400);
}

#[actix_web::test]
async fn the_default_policy_refuses_a_loopback_follow_target() {
    let a = node("alice", 0x11, SsrfGuard::strict()).await;
    let r = a
        .post_outbox(&json!({"type": "Follow", "object": "http://127.0.0.1:9/actor"}))
        .await;
    assert_eq!(r.status().as_u16(), 502);
    assert_eq!(a.fed.store().outbox_count().await.unwrap(), 0);
}

#[actix_web::test]
async fn webfinger_links_the_actor_only_for_this_actor() {
    let a = node("alice", 0x11, LOOPBACK).await;
    let host = a.base.trim_start_matches("http://");
    let ok: Value = reqwest::get(format!(
        "{}/.well-known/webfinger?resource=acct:alice@{host}",
        a.base
    ))
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let links = ok["links"].as_array().unwrap();
    assert!(links.iter().any(|l| l["rel"] == "self"
        && l["type"] == "application/activity+json"
        && l["href"] == a.actor()));
    let other = reqwest::get(format!(
        "{}/.well-known/webfinger?resource=acct:mallory@{host}",
        a.base
    ))
    .await
    .unwrap();
    // Another account still gets the ordinary Solid WebFinger, without the
    // ActivityPub link.
    assert_eq!(other.status().as_u16(), 200);
    let other: Value = other.json().await.unwrap();
    assert!(!other["links"]
        .as_array()
        .unwrap()
        .iter()
        .any(|l| l["rel"] == "self"));
}

#[actix_web::test]
async fn two_servers_follow_accept_and_deliver_a_note() {
    let a = node("alice", 0x11, LOOPBACK).await;
    let b = node("bob", 0x22, LOOPBACK).await;

    // A's owner follows B: A fetches B's actor, delivers a signed Follow; B
    // fetches A's key, verifies, records the follower and delivers an Accept.
    let r = a
        .post_outbox(&json!({"type": "Follow", "object": b.actor()}))
        .await;
    assert_eq!(r.status().as_u16(), 201, "{}", r.text().await.unwrap());
    eventually("B records A as a follower", || async {
        b.fed
            .store()
            .is_follower(&b.actor(), &a.actor())
            .await
            .unwrap()
    })
    .await;
    eventually("A sees the Accept", || async {
        a.fed
            .store()
            .is_following(&a.actor(), &b.actor())
            .await
            .unwrap()
    })
    .await;

    // The collections show it.
    let followers: Value = reqwest::get(format!("{}/profile/card.jsonld/followers", b.base))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(followers["totalItems"], 1);
    assert_eq!(followers["orderedItems"][0], a.actor());
    let following: Value = reqwest::get(format!("{}/profile/card.jsonld/following", a.base))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(following["orderedItems"][0], b.actor());

    // B posts a Note; it reaches A's inbox, signed and verified.
    let r = b
        .post_outbox(&json!({"type": "Note", "content": "hello from bob"}))
        .await;
    assert_eq!(r.status().as_u16(), 201);
    let created: Value = r.json().await.unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    eventually("the Note reaches A", || async {
        a.fed.store().get_inbox(&id).await.unwrap().is_some()
    })
    .await;
    let row = a.fed.store().get_inbox(&id).await.unwrap().unwrap();
    assert_eq!(row.activity["object"]["content"], "hello from bob");
    assert_eq!(row.activity["actor"], b.actor());
    let _ = (&a.public_pem, &b.public_pem);
}

#[actix_web::test]
async fn the_key_and_the_store_under_dot_ap_are_never_served() {
    use solid_pod_rs::storage::fs::FsBackend;
    use solid_pod_rs_server::activitypub::load_or_create_keypair;

    let dir = tempfile::tempdir().unwrap();
    let (private_pem, public_pem) = load_or_create_keypair(Some(dir.path())).unwrap();
    let storage = Arc::new(FsBackend::new(dir.path()).await.unwrap());
    owner_acl_fs(&*storage, 0x11).await;
    let cfg = ApConfig::from_knobs(Some("alice"), None, None, None, public_pem).unwrap();
    let store = Store::connect(&format!(
        "sqlite://{}?mode=rwc",
        dir.path().join(".ap").join("ap.db").display()
    ))
    .await
    .unwrap();
    let fed = Federation::start(
        &cfg,
        private_pem.clone(),
        "http://localhost:8080",
        store,
        SsrfGuard::strict(),
        Duration::from_secs(3600),
    )
    .unwrap();
    let mut st = AppState::new(storage);
    st.data_root = Some(dir.path().to_path_buf());
    st.public_base_url = Some("http://localhost:8080".into());
    st.set_ap_federation(fed);
    let app = test::init_service(build_app(st)).await;

    for (method, path) in [
        ("GET", "/.ap/keys.json"),
        ("GET", "/.ap/ap.db"),
        ("PUT", "/.ap/keys.json"),
        ("DELETE", "/.ap/keys.json"),
    ] {
        let url = format!("http://localhost:8080{path}");
        let body: &[u8] = b"x";
        let payload = (method == "PUT").then_some(body);
        let req = test::TestRequest::default()
            .method(method.parse().unwrap())
            .uri(path)
            .insert_header(("authorization", token(&url, method, payload, 0x11)))
            .set_payload(payload.map(<[u8]>::to_vec).unwrap_or_default())
            .to_request();
        let rsp = test::call_service(&app, req).await;
        let status = rsp.status().as_u16();
        let text = String::from_utf8_lossy(&test::read_body(rsp).await).to_string();
        assert!(status >= 400, "{method} {path}: {status}");
        assert!(
            !text.contains("PRIVATE KEY"),
            "{method} {path} leaked the key"
        );
    }
    // The key is intact, and the root listing does not mention `.ap`.
    assert!(std::fs::read_to_string(dir.path().join(".ap/keys.json"))
        .unwrap()
        .contains("PRIVATE KEY"));
    let url = "http://localhost:8080/";
    let req = test::TestRequest::get()
        .uri("/")
        .insert_header(("authorization", token(url, "GET", None, 0x11)))
        .insert_header(("accept", "application/ld+json"))
        .to_request();
    let rsp = test::call_service(&app, req).await;
    let text = String::from_utf8_lossy(&test::read_body(rsp).await).to_string();
    assert!(!text.contains(".ap"), "listing names .ap: {text}");
}

async fn owner_acl_fs(storage: &dyn Storage, owner_sk: u8) {
    storage
        .put(
            "/.acl",
            Bytes::from(format!(
                "@prefix acl: <{ACL}> .\n<#o> a acl:Authorization ; acl:agent <{}> ; \
                 acl:accessTo </> ; acl:default </> ; acl:mode acl:Read, acl:Write, acl:Control .\n",
                did_of(owner_sk)
            )),
            "text/turtle",
        )
        .await
        .unwrap();
}
