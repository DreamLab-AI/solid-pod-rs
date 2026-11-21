//! SP-PAR-282: the WebRTC signalling relay behind `--webrtc`.
//!
//! Properties, each with the check that fails if it is violated:
//!
//! * nothing is mounted by default;
//! * an unauthenticated upgrade is refused before any socket is taken;
//! * a message reaches only the named peer, `from` is the authenticated
//!   sender (a forged `from` is ignored);
//! * the relay is bounded: connection cap, frame size, idle timeout, rate.

use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use actix_web::{test, HttpServer};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use solid_pod_rs::auth::nip98;
use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs_server::webrtc_mount::{Limits, WebRtcMount};
use solid_pod_rs_server::{build_app, AppState};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

fn did_of(sk: u8) -> String {
    let key = k256::schnorr::SigningKey::from_slice(&[sk; 32]).unwrap();
    format!("did:nostr:{}", hex::encode(key.verifying_key().to_bytes()))
}

fn token(url: &str, sk: u8) -> String {
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
    let t = nip98::mint(url, "GET", &hex::encode([sk; 32]), now).unwrap();
    format!("Nostr {t}")
}

struct Server {
    port: u16,
}

async fn serve(limits: Limits) -> Server {
    serve_with(limits, false).await
}

async fn serve_with(limits: Limits, trust_proxy: bool) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut state = AppState::new(Arc::new(MemoryBackend::new()));
    state.public_base_url = Some(format!("http://127.0.0.1:{port}"));
    state.trust_proxy = trust_proxy;
    state.webrtc = Some(WebRtcMount::with_limits("/webrtc", limits).unwrap());
    let server = HttpServer::new(move || build_app(state.clone()))
        .workers(1)
        .listen(listener)
        .unwrap();
    actix_web::rt::spawn(server.run());
    Server { port }
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

#[allow(clippy::result_large_err)]
async fn connect(s: &Server, sk: Option<u8>) -> Result<Ws, tokio_tungstenite::tungstenite::Error> {
    connect_via(s, sk, None).await
}

/// Connect as a client a reverse proxy forwarded for `forwarded_for`.
#[allow(clippy::result_large_err)]
async fn connect_via(
    s: &Server,
    sk: Option<u8>,
    forwarded_for: Option<&str>,
) -> Result<Ws, tokio_tungstenite::tungstenite::Error> {
    let mut req = format!("ws://127.0.0.1:{}/webrtc", s.port)
        .into_client_request()
        .unwrap();
    if let Some(sk) = sk {
        let url = format!("http://127.0.0.1:{}/webrtc", s.port);
        req.headers_mut()
            .insert("authorization", token(&url, sk).parse().unwrap());
    }
    if let Some(xff) = forwarded_for {
        req.headers_mut()
            .insert("x-forwarded-for", xff.parse().unwrap());
    }
    tokio_tungstenite::connect_async(req)
        .await
        .map(|(ws, _)| ws)
}

async fn next_json(ws: &mut Ws) -> Option<Value> {
    loop {
        match tokio::time::timeout(Duration::from_secs(3), ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => return serde_json::from_str(&t).ok(),
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
            _ => return None,
        }
    }
}

#[actix_web::test]
async fn nothing_is_mounted_by_default() {
    let app = test::init_service(build_app(AppState::new(Arc::new(MemoryBackend::new())))).await;
    let req = test::TestRequest::get()
        .uri("/webrtc")
        .insert_header(("upgrade", "websocket"))
        .to_request();
    let status = test::call_service(&app, req).await.status().as_u16();
    assert!(matches!(status, 401 | 403 | 404), "{status}");
}

#[actix_web::test]
async fn an_unauthenticated_upgrade_is_refused() {
    let s = serve(Limits::default()).await;
    let err = connect(&s, None).await.unwrap_err();
    assert!(err.to_string().contains("401"), "{err}");
}

#[actix_web::test]
async fn offers_reach_only_the_named_peer_with_the_true_sender() {
    let s = serve(Limits::default()).await;
    let mut a = connect(&s, Some(0x11)).await.unwrap();
    let mut b = connect(&s, Some(0x22)).await.unwrap();
    let mut c = connect(&s, Some(0x33)).await.unwrap();

    a.send(Message::text(
        json!({"type": "offer", "to": did_of(0x22), "from": did_of(0x33), "sdp": "v=0"})
            .to_string(),
    ))
    .await
    .unwrap();
    let got = next_json(&mut b).await.expect("B receives the offer");
    assert_eq!(got["type"], "offer");
    assert_eq!(
        got["from"],
        did_of(0x11),
        "from is the authenticated sender"
    );
    assert_eq!(got["sdp"], "v=0");
    assert!(next_json(&mut c).await.is_none(), "C hears nothing");

    // Bad JSON and a content-addressed announce are errors. (An offline peer
    // is deliberately not: see `a_present_and_an_absent_peer_are_indistinguishable_to_a_sender`.)
    for bad in [
        "not json".to_string(),
        json!({"type": "announce", "resource": "abcdef012345"}).to_string(),
    ] {
        a.send(Message::text(bad)).await.unwrap();
        let e = next_json(&mut a).await.expect("an error frame");
        assert_eq!(e["type"], "error");
    }
}

#[actix_web::test]
async fn the_relay_is_bounded() {
    let s = serve(Limits {
        max_connections: 2,
        idle: Duration::from_millis(600),
        rate_messages: 5,
        ..Limits::default()
    })
    .await;

    // Connection cap: the third socket is refused with 503.
    let mut a = connect(&s, Some(0x11)).await.unwrap();
    let _b = connect(&s, Some(0x22)).await.unwrap();
    let err = connect(&s, Some(0x33)).await.unwrap_err();
    assert!(err.to_string().contains("503"), "{err}");

    // Rate limit: the sixth message in the window closes the socket.
    for _ in 0..6 {
        let _ = a
            .send(Message::text(
                json!({"type": "hangup", "to": did_of(0x22)}).to_string(),
            ))
            .await;
    }
    let mut closed = false;
    for _ in 0..20 {
        match tokio::time::timeout(Duration::from_secs(2), a.next()).await {
            Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) => {
                closed = true;
                break;
            }
            Ok(Some(Ok(_))) => {}
            Err(_) => break,
        }
    }
    assert!(closed, "the rate limit closes the socket");
}

#[actix_web::test]
async fn an_oversized_frame_and_an_idle_socket_are_closed() {
    let s = serve(Limits {
        max_connections: 8,
        idle: Duration::from_millis(500),
        rate_messages: 60,
        ..Limits::default()
    })
    .await;
    let mut big = connect(&s, Some(0x11)).await.unwrap();
    let _ = big.send(Message::text("x".repeat(70 * 1024))).await;
    let mut closed = false;
    for _ in 0..10 {
        match tokio::time::timeout(Duration::from_secs(2), big.next()).await {
            Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) => {
                closed = true;
                break;
            }
            Ok(Some(Ok(_))) => {}
            Err(_) => break,
        }
    }
    assert!(closed, "an oversized frame closes the socket");

    let mut idle = connect(&s, Some(0x22)).await.unwrap();
    let mut closed = false;
    for _ in 0..10 {
        match tokio::time::timeout(Duration::from_secs(3), idle.next()).await {
            Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) => {
                closed = true;
                break;
            }
            Ok(Some(Ok(_))) => {}
            Err(_) => break,
        }
    }
    assert!(closed, "an idle socket is closed");
}

// ---------------------------------------------------------------------------
// Review C
// ---------------------------------------------------------------------------

async fn closes_within(ws: &mut Ws, secs: u64) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(300), ws.next()).await {
            Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) => return true,
            Ok(Some(Ok(_))) | Err(_) => {}
        }
    }
    false
}

#[actix_web::test]
async fn pings_and_binary_frames_count_against_the_rate_limit() {
    // Property: the rate limit counts every frame the client sends, so ping
    // and binary frames cannot be used to burn the server's time unmetered.
    for frame in [Message::Ping(vec![]), Message::Binary(vec![0u8; 4])] {
        let s = serve(Limits {
            rate_messages: 5,
            ..Limits::default()
        })
        .await;
        let mut a = connect(&s, Some(0x11)).await.unwrap();
        for _ in 0..8 {
            let _ = a.send(frame.clone()).await;
        }
        assert!(closes_within(&mut a, 5).await, "{frame:?} was not metered");
    }
}

#[actix_web::test]
async fn a_busy_socket_is_closed_at_the_session_limit() {
    // Property: a client that keeps the socket active (pings reset the idle
    // timer) still cannot hold its slot beyond the maximum session lifetime.
    let s = serve(Limits {
        idle: Duration::from_secs(30),
        max_session: Duration::from_millis(700),
        ..Limits::default()
    })
    .await;
    let mut a = connect(&s, Some(0x11)).await.unwrap();
    let start = tokio::time::Instant::now();
    let mut closed = false;
    while start.elapsed() < Duration::from_secs(5) {
        if a.send(Message::Ping(vec![])).await.is_err() {
            closed = true;
            break;
        }
        if let Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) =
            tokio::time::timeout(Duration::from_millis(150), a.next()).await
        {
            closed = true;
            break;
        }
    }
    assert!(closed, "a pinging socket was never closed");
    assert!(start.elapsed() < Duration::from_secs(4));
}

#[actix_web::test]
async fn one_address_cannot_take_every_slot() {
    // Property: one peer address holds at most `max_per_ip` sockets, so it
    // cannot lock other addresses out of the global pool; the refusal is 503.
    let s = serve(Limits {
        max_per_ip: 2,
        ..Limits::default()
    })
    .await;
    let _a = connect(&s, Some(0x11)).await.unwrap();
    let _b = connect(&s, Some(0x22)).await.unwrap();
    let err = connect(&s, Some(0x33)).await.unwrap_err();
    assert!(err.to_string().contains("503"), "{err}");
    // A slot is returned when a socket closes.
    drop(_a);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(connect(&s, Some(0x44)).await.is_ok());
}

#[actix_web::test]
async fn behind_a_trusted_proxy_each_forwarded_client_has_its_own_budget() {
    // Property: with `trust_proxy` on, the per-address cap is per client (the
    // address the proxy forwarded), so one proxy in front does not collapse
    // every client onto a single budget. Every socket here comes from
    // 127.0.0.1; only the forwarded address differs.
    let s = serve_with(
        Limits {
            max_per_ip: 1,
            ..Limits::default()
        },
        true,
    )
    .await;
    let _a = connect_via(&s, Some(0x11), Some("198.51.100.1"))
        .await
        .unwrap();
    let _b = connect_via(&s, Some(0x22), Some("198.51.100.2"))
        .await
        .unwrap();
    // The same forwarded client is still held to its own cap.
    let err = connect_via(&s, Some(0x33), Some("198.51.100.1"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("503"), "{err}");
    // An unusable forwarded value falls back to the peer address (which is
    // not yet at its cap, since nothing was counted against 127.0.0.1), and
    // that fallback is itself capped rather than uncapped.
    let _c = connect_via(&s, Some(0x44), Some("not-an-address"))
        .await
        .unwrap();
    let err = connect_via(&s, Some(0x55), Some("also-not-an-address"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("503"), "{err}");
}

#[actix_web::test]
async fn without_trust_proxy_the_forwarded_address_is_ignored() {
    // Property: a client cannot mint itself a fresh budget with a header the
    // operator did not vouch for.
    let s = serve_with(
        Limits {
            max_per_ip: 1,
            ..Limits::default()
        },
        false,
    )
    .await;
    let _a = connect_via(&s, Some(0x11), Some("198.51.100.1"))
        .await
        .unwrap();
    let err = connect_via(&s, Some(0x22), Some("198.51.100.2"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("503"), "{err}");
}

#[actix_web::test]
async fn a_present_and_an_absent_peer_are_indistinguishable_to_a_sender() {
    // Property: the relay does not reveal whether a pubkey is online. A
    // well-formed message to an online peer and to an absent one get the same
    // response (none), so a sender cannot probe for presence.
    let s = serve(Limits::default()).await;
    let mut a = connect(&s, Some(0x11)).await.unwrap();
    let mut b = connect(&s, Some(0x22)).await.unwrap();
    for to in [did_of(0x22), did_of(0x99)] {
        a.send(Message::text(
            json!({"type": "offer", "to": to, "sdp": "v=0"}).to_string(),
        ))
        .await
        .unwrap();
        assert!(
            next_json(&mut a).await.is_none(),
            "the sender was told something about {to}"
        );
    }
    assert!(
        next_json(&mut b).await.is_some(),
        "the online peer still gets its offer"
    );
}
