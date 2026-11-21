//! SP-PAR-279: `GET /.notifications` speaks `solid-0.1` over a WebSocket, a
//! WAC Read check guards every subscription and every delivery, and
//! `Updates-Via` is advertised only when the route is mounted.
//!
//! These tests run a real listener on a loopback port and a real WebSocket
//! client, because the property under test is what crosses the wire.

use std::sync::Arc;
use std::time::Duration;

use actix_web::HttpServer;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use solid_pod_rs::storage::{memory::MemoryBackend, Storage};
use solid_pod_rs_server::{build_app, AppState};
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};

const ACL: &str = "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n";
const OWNER: &str = "did:nostr:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

struct Server {
    port: u16,
    storage: Arc<MemoryBackend>,
}

impl Server {
    async fn start(configure: impl FnOnce(&mut AppState)) -> Self {
        let storage = Arc::new(MemoryBackend::new());
        // Root: owner only. Everything below is public only by its own ACL.
        put(&storage, "/.acl", &owner_only("/", true)).await;
        put(&storage, "/pub.acl", &public_read("/pub/", true)).await;
        put(&storage, "/pub/a.txt", "a").await;
        put(&storage, "/pub/secret.txt", "s").await;
        put(
            &storage,
            "/pub/secret.txt.acl",
            &owner_only("/pub/secret.txt", false),
        )
        .await;
        let mut state = AppState::new(storage.clone());
        configure(&mut state);
        let server = HttpServer::new(move || build_app(state.clone()))
            .workers(1)
            .bind(("127.0.0.1", 0))
            .unwrap();
        let port = server.addrs()[0].port();
        actix_web::rt::spawn(server.run());
        Self { port, storage }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    async fn connect(&self, origin: Option<&str>) -> Result<Ws, String> {
        let mut req = format!("ws://127.0.0.1:{}/.notifications", self.port)
            .into_client_request()
            .unwrap();
        if let Some(o) = origin {
            req.headers_mut().insert("origin", o.parse().unwrap());
        }
        tokio_tungstenite::connect_async(req)
            .await
            .map(|(ws, _)| ws)
            .map_err(|e| e.to_string())
    }
}

async fn put(storage: &MemoryBackend, path: &str, body: &str) {
    let ct = if path.ends_with(".acl") {
        "text/turtle"
    } else {
        "text/plain"
    };
    storage
        .put(path, Bytes::from(body.to_owned()), ct)
        .await
        .unwrap();
}

fn public_read(target: &str, default: bool) -> String {
    let d = if default {
        format!("acl:default <{target}> ;")
    } else {
        String::new()
    };
    format!("{ACL}<#p> a acl:Authorization ; acl:agentClass foaf:Agent ; acl:accessTo <{target}> ; {d} acl:mode acl:Read .\n")
}

fn owner_only(target: &str, default: bool) -> String {
    let d = if default {
        format!("acl:default <{target}> ;")
    } else {
        String::new()
    };
    format!("{ACL}<#o> a acl:Authorization ; acl:agent <{OWNER}> ; acl:accessTo <{target}> ; {d} acl:mode acl:Read, acl:Write, acl:Control .\n")
}

/// The next text frame within `ms`, skipping pings; `None` on silence.
async fn text(ws: &mut Ws, ms: u64) -> Option<String> {
    loop {
        match tokio::time::timeout(Duration::from_millis(ms), ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => return Some(t.to_string()),
            Ok(Some(Ok(_))) => continue,
            _ => return None,
        }
    }
}

async fn say(ws: &mut Ws, line: &str) {
    ws.send(Message::text(line)).await.unwrap();
}

#[actix_web::test]
async fn a_client_gets_the_greeting_and_an_ack_for_a_readable_resource() {
    let s = Server::start(|_| {}).await;
    let mut ws = s.connect(None).await.expect("upgrade");
    assert_eq!(
        text(&mut ws, 2000).await.as_deref(),
        Some("protocol solid-0.1")
    );
    let url = s.url("/pub/a.txt");
    say(&mut ws, &format!("sub {url}")).await;
    assert_eq!(text(&mut ws, 2000).await, Some(format!("ack {url}")));
}

#[actix_web::test]
async fn a_change_to_a_subscribed_resource_is_published() {
    let s = Server::start(|_| {}).await;
    let mut ws = s.connect(None).await.unwrap();
    text(&mut ws, 2000).await;
    let url = s.url("/pub/a.txt");
    say(&mut ws, &format!("sub {url}")).await;
    text(&mut ws, 2000).await;
    put(&s.storage, "/pub/a.txt", "changed").await;
    assert_eq!(text(&mut ws, 2000).await, Some(format!("pub {url}")));
    // A container subscriber is told which child changed.
    let dir = s.url("/pub/");
    say(&mut ws, &format!("sub {dir}")).await;
    assert_eq!(text(&mut ws, 2000).await, Some(format!("ack {dir}")));
    put(&s.storage, "/pub/b.txt", "new").await;
    put(
        &s.storage,
        "/pub/b.txt.acl",
        &public_read("/pub/b.txt", false),
    )
    .await;
    let mut seen = Vec::new();
    while let Some(f) = text(&mut ws, 500).await {
        seen.push(f);
    }
    assert!(
        seen.contains(&format!("pub {}", s.url("/pub/b.txt"))),
        "{seen:?}"
    );
}

#[actix_web::test]
async fn a_subscription_without_read_is_refused_and_nothing_is_published() {
    let s = Server::start(|_| {}).await;
    let mut ws = s.connect(None).await.unwrap();
    text(&mut ws, 2000).await;
    for path in ["/pub/secret.txt", "/", "/nowhere/else"] {
        let url = s.url(path);
        say(&mut ws, &format!("sub {url}")).await;
        assert_eq!(
            text(&mut ws, 2000).await,
            Some(format!("err {url} forbidden")),
            "{path}"
        );
    }
    put(&s.storage, "/pub/secret.txt", "changed").await;
    assert_eq!(text(&mut ws, 400).await, None);
}

#[actix_web::test]
async fn a_readable_ancestor_subscription_never_reveals_an_unreadable_change() {
    let s = Server::start(|_| {}).await;
    let mut ws = s.connect(None).await.unwrap();
    text(&mut ws, 2000).await;
    let dir = s.url("/pub/");
    say(&mut ws, &format!("sub {dir}")).await;
    assert_eq!(text(&mut ws, 2000).await, Some(format!("ack {dir}")));
    // The change is under a container the subscriber can read, but the
    // resource itself is owner-only: no `pub`, and no `err` naming it.
    put(&s.storage, "/pub/secret.txt", "changed again").await;
    assert_eq!(
        text(&mut ws, 500).await,
        None,
        "an unreadable change must not be announced"
    );
    // Control: a readable change under the same container is published.
    put(&s.storage, "/pub/a.txt", "again").await;
    assert_eq!(
        text(&mut ws, 2000).await,
        Some(format!("pub {}", s.url("/pub/a.txt")))
    );
}

#[actix_web::test]
async fn access_revoked_after_subscribing_stops_deliveries() {
    let s = Server::start(|_| {}).await;
    let mut ws = s.connect(None).await.unwrap();
    text(&mut ws, 2000).await;
    let a = s.url("/pub/a.txt");
    say(&mut ws, &format!("sub {a}")).await;
    assert_eq!(text(&mut ws, 2000).await, Some(format!("ack {a}")));
    // Revoke: a.txt becomes owner-only after the subscription was accepted.
    put(
        &s.storage,
        "/pub/a.txt.acl",
        &owner_only("/pub/a.txt", false),
    )
    .await;
    while text(&mut ws, 300).await.is_some() {}
    put(&s.storage, "/pub/a.txt", "after revocation").await;
    assert_eq!(
        text(&mut ws, 600).await,
        None,
        "delivery must re-check WAC at delivery time"
    );
}

#[actix_web::test]
async fn foreign_and_malformed_urls_are_refused() {
    let s = Server::start(|_| {}).await;
    let mut ws = s.connect(None).await.unwrap();
    text(&mut ws, 2000).await;
    let port = s.port;
    for url in [
        "http://other.example/pub/a.txt".to_string(),
        format!("https://127.0.0.1:{port}/pub/a.txt"),
        format!("http://127.0.0.1:{}/pub/a.txt", port.wrapping_add(1)),
        format!("http://user@127.0.0.1:{port}/pub/a.txt"),
        format!("http://127.0.0.1:{port}/pub/a.txt?x=1"),
        format!("http://127.0.0.1:{port}/pub/../.acl"),
        format!("http://127.0.0.1:{port}/pub%2Fa.txt"),
        "/pub/a.txt".to_string(),
        "not a url".to_string(),
    ] {
        say(&mut ws, &format!("sub {url}")).await;
        assert_eq!(
            text(&mut ws, 2000).await,
            Some(format!("err {url} forbidden")),
            "{url}"
        );
    }
    say(&mut ws, "hello").await;
    assert_eq!(
        text(&mut ws, 2000).await.as_deref(),
        Some("err unknown command")
    );
    say(&mut ws, &format!("sub {}", "x".repeat(3000))).await;
    assert_eq!(
        text(&mut ws, 2000).await.as_deref(),
        Some("err uri too long")
    );
}

#[actix_web::test]
async fn updates_via_and_the_route_are_on_or_off_together() {
    use actix_web::test::{call_service, init_service, TestRequest};
    // Mounted: advertised, and `/.well-known/solid` names the gateway.
    let on = AppState::new(Arc::new(MemoryBackend::new()));
    assert!(on.notifications.is_some());
    let app = init_service(build_app(on)).await;
    let rsp = call_service(
        &app,
        TestRequest::get().uri("/.well-known/solid").to_request(),
    )
    .await;
    let body = actix_web::test::read_body(rsp).await;
    assert!(String::from_utf8_lossy(&body).contains(".notifications"));

    // Not mounted: no header on any resource, no gateway in discovery, and
    // `/.notifications` is only the refused dotfile it always was.
    let mut off = AppState::new(Arc::new(MemoryBackend::new()));
    off.notifications = None;
    off.storage
        .put("/x", Bytes::from_static(b"x"), "text/plain")
        .await
        .unwrap();
    off.storage
        .put("/.acl", Bytes::from(public_read("/", true)), "text/turtle")
        .await
        .unwrap();
    let app = init_service(build_app(off)).await;
    for method in [
        TestRequest::get(),
        TestRequest::default().method(actix_web::http::Method::HEAD),
    ] {
        let rsp = call_service(&app, method.uri("/x").to_request()).await;
        assert!(rsp.status().is_success(), "{}", rsp.status());
        assert!(
            rsp.headers().get("updates-via").is_none(),
            "Updates-Via sent with no route"
        );
    }
    let rsp = call_service(
        &app,
        TestRequest::get().uri("/.well-known/solid").to_request(),
    )
    .await;
    let body = actix_web::test::read_body(rsp).await;
    assert!(!String::from_utf8_lossy(&body).contains(".notifications"));
    let rsp = call_service(&app, TestRequest::get().uri("/.notifications").to_request()).await;
    assert_eq!(rsp.status().as_u16(), 403);
}

#[actix_web::test]
async fn a_browser_origin_outside_the_allow_list_cannot_upgrade() {
    let s = Server::start(|st| st.allowed_origins = vec!["https://app.example".into()]).await;
    assert!(s.connect(Some("https://evil.example")).await.is_err());
    let mut ok = s
        .connect(Some("https://app.example"))
        .await
        .expect("allowed origin");
    assert_eq!(
        text(&mut ok, 2000).await.as_deref(),
        Some("protocol solid-0.1")
    );
}
