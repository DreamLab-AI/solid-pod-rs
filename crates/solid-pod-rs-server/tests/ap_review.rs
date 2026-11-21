//! Review hardening of the ActivityPub federation (parity4-review A1 to A5):
//! each test names the property it preserves and fails if it is violated.
#![cfg(feature = "activitypub")]
#![allow(dead_code)]

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use actix_web::HttpServer;
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
    // `created_at` must track the wall clock: the server refuses a NIP-98 event
    // more than 60 s from its own time, so a base fixed at first use goes stale
    // whenever the process runs slowly (coverage instrumentation). Distinct
    // events need distinct seconds (replay protection), so never reuse one.
    static LAST: std::sync::Mutex<u64> = std::sync::Mutex::new(0);
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let now = {
        let mut last = LAST.lock().unwrap();
        *last = wall.max(*last + 1);
        *last
    };
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
async fn repeated_follows_from_one_actor_leave_every_row_count_constant() {
    // Property: an unauthenticated-in-effect sender (any signing actor) cannot
    // grow the target's inbox, outbox or delivery queue by repeating a Follow
    // under fresh ids; the first Follow is accepted and answered exactly once.
    let sender = node("mallory", 0x33, LOOPBACK).await;
    let target = node("bob", 0x22, LOOPBACK).await;
    let inbox = format!("{}/inbox", target.base);
    let follow = |n: usize| {
        json!({
            "id": format!("{}/follows/{n}", sender.base),
            "type": "Follow",
            "actor": sender.actor(),
            "object": target.actor(),
            "padding": "x".repeat(20_000),
        })
    };
    let r = send(&signed(&sender, &inbox, &follow(0))).await;
    assert_eq!(r.status().as_u16(), 202);
    let store = target.fed.store();
    assert_eq!(store.outbox_count().await.unwrap(), 1);
    let inbox_rows = store.inbox_count().await.unwrap();
    for n in 1..60 {
        let r = send(&signed(&sender, &inbox, &follow(n))).await;
        assert_eq!(r.status().as_u16(), 202, "follow {n}");
    }
    assert_eq!(store.outbox_count().await.unwrap(), 1, "no further Accepts");
    assert_eq!(
        store.inbox_count().await.unwrap(),
        inbox_rows,
        "no further inbox rows"
    );
    assert!(
        store.delivery_queue_len().await.unwrap() <= 1,
        "no further deliveries"
    );
    // The one Accept does not carry the sender's body.
    let rows = store.recent_outbox(&target.actor(), 5).await.unwrap();
    assert!(rows[0].activity.to_string().len() < 2_048);
}

// ---------------------------------------------------------------------------
// A3: slow bodies hold no inbox slot and are cut off
// ---------------------------------------------------------------------------

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Open a connection that has sent its headers and a few body bytes, then
/// stops (a trickling client).
async fn trickler(target: &Node) -> tokio::net::TcpStream {
    let authority = target.base.trim_start_matches("http://").to_string();
    let mut s = tokio::net::TcpStream::connect(&authority).await.unwrap();
    s.write_all(
        format!(
            "POST /inbox HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/activity+json\r\n\
             Content-Length: 1000\r\n\r\n{{\"ty"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    s
}

#[actix_web::test]
async fn trickling_clients_do_not_hold_inbox_slots() {
    // Property: a client that has not finished sending its body holds no
    // concurrency slot, so MAX_CONCURRENT_INBOX of them cannot lock out a
    // genuine, signed request.
    use solid_pod_rs_server::activitypub::MAX_CONCURRENT_INBOX;
    let sender = node("carol", 0x44, LOOPBACK).await;
    let target = node("bob", 0x22, LOOPBACK).await;
    let mut held = Vec::new();
    for _ in 0..MAX_CONCURRENT_INBOX {
        held.push(trickler(&target).await);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let follow = json!({
        "id": format!("{}/follows/1", sender.base),
        "type": "Follow",
        "actor": sender.actor(),
        "object": target.actor(),
    });
    let r = send(&signed(&sender, &format!("{}/inbox", target.base), &follow)).await;
    assert_eq!(
        r.status().as_u16(),
        202,
        "a genuine request was refused while clients trickled"
    );
    drop(held);
}

#[actix_web::test]
async fn a_trickled_body_is_cut_off() {
    // Property: the body read has a deadline; a stalled body ends with a
    // response (408) instead of holding the connection indefinitely.
    use solid_pod_rs_server::activitypub::BODY_READ_TIMEOUT;
    let target = node("bob", 0x22, LOOPBACK).await;
    let mut s = trickler(&target).await;
    let mut buf = Vec::new();
    let waited = tokio::time::timeout(
        BODY_READ_TIMEOUT + Duration::from_secs(4),
        s.read_to_end(&mut buf),
    )
    .await;
    assert!(waited.is_ok(), "the stalled body was never cut off");
    assert!(
        String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 408"),
        "got {:?}",
        String::from_utf8_lossy(&buf)
    );
}

#[actix_web::test]
async fn the_default_policy_refuses_a_loopback_follow_target_over_https_too() {
    // Property: the loopback refusal stands on its own. Plain http is refused
    // by scheme under the strict guard, so this uses https to show the
    // address check still refuses 127.0.0.1.
    let a = node("alice", 0x11, SsrfGuard::strict()).await;
    let r = a
        .post_outbox(&json!({"type": "Follow", "object": "https://127.0.0.1:9/actor"}))
        .await;
    assert_eq!(r.status().as_u16(), 502);
    assert_eq!(a.fed.store().outbox_count().await.unwrap(), 0);
}
