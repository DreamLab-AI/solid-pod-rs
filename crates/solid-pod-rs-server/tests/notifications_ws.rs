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

#[actix_web::test]
async fn one_remote_address_cannot_hold_more_than_its_cap_and_slots_are_returned() {
    use solid_pod_rs_server::notifications_ws::NotifyHub;
    let s = Server::start(|st| {
        st.notifications = Some(NotifyHub::with_limits(
            100,
            2,
            Duration::from_secs(30),
            Duration::from_secs(90),
        ));
    })
    .await;
    let a = s.connect(None).await.expect("first");
    let b = s.connect(None).await.expect("second");
    assert!(
        s.connect(None).await.is_err(),
        "third from the same address is refused"
    );
    drop(a);
    // The slot comes back once the server notices the close.
    let mut again = None;
    for _ in 0..40 {
        if let Ok(ws) = s.connect(None).await {
            again = Some(ws);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(again.is_some(), "a freed slot must be reusable");
    drop(b);
}

#[actix_web::test]
async fn the_global_cap_refuses_beyond_the_total() {
    use solid_pod_rs_server::notifications_ws::NotifyHub;
    let s = Server::start(|st| {
        st.notifications = Some(NotifyHub::with_limits(
            1,
            16,
            Duration::from_secs(30),
            Duration::from_secs(90),
        ));
    })
    .await;
    let _a = s.connect(None).await.expect("first");
    assert!(s.connect(None).await.is_err());
}

#[actix_web::test]
async fn a_silent_socket_is_closed_and_frees_its_slot() {
    use solid_pod_rs_server::notifications_ws::NotifyHub;
    let hub = NotifyHub::with_limits(
        10,
        10,
        Duration::from_millis(100),
        Duration::from_millis(300),
    );
    let probe = hub.clone();
    let s = Server::start(move |st| st.notifications = Some(hub)).await;
    // Connect and then never read: the client library only answers pings
    // while it is being polled, so this peer is silent as far as the server
    // can tell.
    let _silent = s.connect(None).await.expect("upgrade");
    assert_eq!(probe.connections(), 1);
    let mut freed = false;
    for _ in 0..60 {
        if probe.connections() == 0 {
            freed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(freed, "an idle socket must be closed and release its slot");
}

#[actix_web::test]
async fn a_live_socket_survives_the_idle_timeout_by_answering_pings() {
    use solid_pod_rs_server::notifications_ws::NotifyHub;
    let hub = NotifyHub::with_limits(
        10,
        10,
        Duration::from_millis(100),
        Duration::from_millis(400),
    );
    let s = Server::start(move |st| st.notifications = Some(hub)).await;
    let mut ws = s.connect(None).await.unwrap();
    // Reading polls the client, which answers each ping with a pong.
    let until = tokio::time::Instant::now() + Duration::from_millis(1200);
    while tokio::time::Instant::now() < until {
        let _ = tokio::time::timeout(Duration::from_millis(100), ws.next()).await;
    }
    let url = s.url("/pub/a.txt");
    say(&mut ws, &format!("sub {url}")).await;
    let mut got = None;
    for _ in 0..10 {
        if let Some(t) = text(&mut ws, 500).await {
            if t.starts_with("ack") {
                got = Some(t);
                break;
            }
        }
    }
    assert_eq!(
        got,
        Some(format!("ack {url}")),
        "a live socket must not be closed"
    );
}

#[actix_web::test]
async fn an_oversized_frame_is_not_accepted() {
    let s = Server::start(|_| {}).await;
    let mut ws = s.connect(None).await.unwrap();
    text(&mut ws, 2000).await;
    ws.send(Message::text("x".repeat(64 * 1024))).await.unwrap();
    // The server drops the connection rather than buffering the frame.
    let mut closed = false;
    for _ in 0..10 {
        match tokio::time::timeout(Duration::from_millis(500), ws.next()).await {
            Ok(None) | Ok(Some(Err(_))) | Ok(Some(Ok(Message::Close(_)))) => {
                closed = true;
                break;
            }
            Ok(Some(Ok(_))) => continue,
            Err(_) => continue,
        }
    }
    assert!(
        closed,
        "an inbound frame over the cap must close the socket"
    );
}

#[actix_web::test]
async fn a_socket_cannot_hold_more_than_the_subscription_cap() {
    let s = Server::start(|_| {}).await;
    let mut ws = s.connect(None).await.unwrap();
    text(&mut ws, 2000).await;
    for i in 0..100 {
        let url = s.url(&format!("/pub/n{i}"));
        say(&mut ws, &format!("sub {url}")).await;
        assert_eq!(text(&mut ws, 2000).await, Some(format!("ack {url}")), "{i}");
    }
    say(&mut ws, &format!("sub {}", s.url("/pub/one-too-many"))).await;
    assert_eq!(
        text(&mut ws, 2000).await.as_deref(),
        Some("err subscription limit reached")
    );
}

/// Only the GET upgrade is carved out of the dotfile guard: any other method
/// on `/.notifications` is the refused dotfile it always was, so a Write
/// holder cannot use the carve-out to create a dotfile in the pod root.
#[actix_web::test]
async fn only_get_passes_the_dotfile_guard_on_the_notifications_path() {
    use actix_web::http::Method;
    use actix_web::test::{call_service, init_service, TestRequest};
    let storage = Arc::new(MemoryBackend::new());
    // Everyone may do everything: only the dotfile guard can refuse.
    put(
        &storage,
        "/.acl",
        &format!(
            "{ACL}<#a> a acl:Authorization ; acl:agentClass foaf:Agent ; acl:accessTo </> ; acl:default </> ; acl:mode acl:Read, acl:Write, acl:Control .\n"
        ),
    )
    .await;
    let app = init_service(build_app(AppState::new(storage.clone()))).await;
    for m in [
        Method::PUT,
        Method::DELETE,
        Method::HEAD,
        Method::POST,
        Method::PATCH,
        Method::OPTIONS,
    ] {
        let rsp = call_service(
            &app,
            TestRequest::default()
                .method(m.clone())
                .uri("/.notifications")
                .insert_header(("content-type", "text/plain"))
                .set_payload("x")
                .to_request(),
        )
        .await;
        assert_eq!(
            rsp.status().as_u16(),
            403,
            "{m} must be refused by the dotfile guard"
        );
    }
    assert!(
        !storage.exists("/.notifications").await.unwrap(),
        "no dotfile was created"
    );
    // GET reaches the route (a non-upgrade GET is a 400 from the upgrade, not 403).
    let rsp = call_service(&app, TestRequest::get().uri("/.notifications").to_request()).await;
    assert_ne!(rsp.status().as_u16(), 403);
}
