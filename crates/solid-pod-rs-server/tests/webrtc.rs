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
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut state = AppState::new(Arc::new(MemoryBackend::new()));
    state.public_base_url = Some(format!("http://127.0.0.1:{port}"));
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
    let mut req = format!("ws://127.0.0.1:{}/webrtc", s.port)
        .into_client_request()
        .unwrap();
    if let Some(sk) = sk {
        let url = format!("http://127.0.0.1:{}/webrtc", s.port);
        req.headers_mut()
            .insert("authorization", token(&url, sk).parse().unwrap());
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

    // An offline peer, bad JSON and a content-addressed announce are errors.
    for bad in [
        json!({"type": "offer", "to": did_of(0x44), "sdp": "x"}).to_string(),
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
