//! SP-PAR-278 / SP-PAR-280: the embedded Nostr relay, mounted behind
//! `--nostr` (default off), with NIP-11 information at the relay URL and an
//! exemption from the pod's WAC that covers exactly the relay's own two paths,
//! matched on whole path segments.

use std::sync::Arc;
use std::time::Duration;

use actix_web::{http::header, test, HttpServer};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use solid_pod_rs::storage::{memory::MemoryBackend, Storage};
use solid_pod_rs_nostr::Event;
use solid_pod_rs_server::nostr_mount::NostrMount;
use solid_pod_rs_server::{build_app, AppState};
use tokio_tungstenite::tungstenite::Message;

const NO_ACL_PUBLIC: &str = "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
    <#o> a acl:Authorization ; acl:agent <did:nostr:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa> ; \
    acl:accessTo </> ; acl:default </> ; acl:mode acl:Read, acl:Write, acl:Control .\n";

async fn state(mount: Option<NostrMount>) -> AppState {
    let storage = Arc::new(MemoryBackend::new());
    // Owner-only pod: anything under it that is not the relay needs WAC.
    storage
        .put("/.acl", Bytes::from(NO_ACL_PUBLIC), "text/turtle")
        .await
        .unwrap();
    for p in ["/relay/x", "/relayx", "/relay.txt", "/nostr/x"] {
        storage
            .put(p, Bytes::from_static(b"pod data"), "text/plain")
            .await
            .unwrap();
    }
    let mut st = AppState::new(storage);
    st.nostr = mount;
    st
}

fn signed(kind: u64, created_at: u64, content: &str) -> Event {
    let sk = k256::schnorr::SigningKey::from_slice(&[0x42u8; 32]).unwrap();
    let pubkey = hex::encode(sk.verifying_key().to_bytes());
    let mut ev = Event {
        id: String::new(),
        pubkey,
        created_at,
        kind,
        tags: vec![],
        content: content.to_string(),
        sig: String::new(),
    };
    ev.id = ev.canonical_id();
    let sig = sk
        .sign_raw(&hex::decode(&ev.id).unwrap(), &[0u8; 32])
        .unwrap();
    ev.sig = hex::encode(sig.to_bytes());
    ev
}

async fn get(
    state: AppState,
    uri: &str,
    accept: Option<&str>,
) -> (u16, Option<String>, Option<String>, String) {
    let app = test::init_service(build_app(state)).await;
    let mut req = test::TestRequest::get().uri(uri);
    if let Some(a) = accept {
        req = req.insert_header((header::ACCEPT, a));
    }
    let rsp = test::call_service(&app, req.to_request()).await;
    let status = rsp.status().as_u16();
    let ct = rsp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let cors = rsp
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = String::from_utf8_lossy(&test::read_body(rsp).await).into_owned();
    (status, ct, cors, body)
}

#[actix_web::test]
async fn nothing_is_mounted_by_default() {
    let (status, _, _, body) =
        get(state(None).await, "/relay", Some("application/nostr+json")).await;
    assert_ne!(status, 200, "{body}");
    assert!(!body.contains("supported_nips"), "{body}");
}

#[actix_web::test]
async fn nip11_information_is_served_at_the_relay_url() {
    let mount = NostrMount::new("/relay", 100).unwrap();
    let (status, ct, cors, body) = get(
        state(Some(mount.clone())).await,
        "/relay",
        Some("application/nostr+json"),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(ct.as_deref(), Some("application/nostr+json"));
    assert_eq!(cors.as_deref(), Some("*"));
    let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
    for field in [
        "name",
        "description",
        "pubkey",
        "contact",
        "supported_nips",
        "software",
        "version",
    ] {
        assert!(doc.get(field).is_some(), "NIP-11 field {field}: {body}");
    }
    let nips: Vec<u64> = doc["supported_nips"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|n| n.as_u64())
        .collect();
    assert!(
        nips.contains(&1) && nips.contains(&11) && nips.contains(&16),
        "{nips:?}"
    );
    // Accept lists with parameters and other types still match.
    let (status, _, _, _) = get(
        state(Some(mount.clone())).await,
        "/relay",
        Some("text/html;q=0.5, application/nostr+json;q=0.9"),
    )
    .await;
    assert_eq!(status, 200);
    // A plain GET stays 404, and so does one that only asks for JSON.
    for accept in [None, Some("text/html"), Some("application/json")] {
        let (status, _, _, body) = get(state(Some(mount.clone())).await, "/relay", accept).await;
        assert_eq!(status, 404, "{accept:?}: {body}");
    }
    // The `/info` alias, whatever `Accept` says.
    let (status, ct, _, _) = get(state(Some(mount)).await, "/relay/info", None).await;
    assert_eq!(status, 200);
    assert_eq!(ct.as_deref(), Some("application/nostr+json"));
}

#[actix_web::test]
async fn the_cors_preflight_for_the_information_fetch_is_answered() {
    let mount = NostrMount::new("/relay", 100).unwrap();
    let app = test::init_service(build_app(state(Some(mount)).await)).await;
    let rsp = test::call_service(
        &app,
        test::TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .uri("/relay")
            .insert_header(("origin", "https://client.example"))
            .insert_header(("access-control-request-method", "GET"))
            .insert_header(("access-control-request-headers", "accept"))
            .to_request(),
    )
    .await;
    assert!(rsp.status().is_success(), "{}", rsp.status());
    assert_eq!(
        rsp.headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("*")
    );
}

/// The exemption is the relay's own two exact paths and nothing broader: the
/// neighbours are pod paths, answered by WAC (owner-only here, so 401).
#[actix_web::test]
async fn the_wac_exemption_matches_whole_path_segments_only() {
    let mount = NostrMount::new("/relay", 100).unwrap();
    for uri in [
        "/relay/x",
        "/relayx",
        "/relay.txt",
        "/relay/",
        "/relay/info/x",
        "/relay%2Fx",
        "/RELAY/x",
    ] {
        let (status, ct, _, body) = get(
            state(Some(mount.clone())).await,
            uri,
            Some("application/nostr+json"),
        )
        .await;
        assert!(
            ct.as_deref() != Some("application/nostr+json") && !body.contains("supported_nips"),
            "{uri} reached the relay: {status} {body}"
        );
        assert!(
            !body.contains("pod data"),
            "{uri} bypassed WAC: {status} {body}"
        );
    }
    // Control: a plain pod path really is WAC-protected in this fixture.
    let (status, _, _, _) = get(state(None).await, "/relayx", None).await;
    assert_eq!(status, 401);
}

#[actix_web::test]
async fn the_mount_path_is_configurable_and_validated() {
    let mount = NostrMount::new("/nostr", 100).unwrap();
    let (status, _, _, _) = get(
        state(Some(mount.clone())).await,
        "/nostr",
        Some("application/nostr+json"),
    )
    .await;
    assert_eq!(status, 200);
    let (status, _, _, body) = get(
        state(Some(mount)).await,
        "/relay",
        Some("application/nostr+json"),
    )
    .await;
    assert_ne!(status, 200, "{body}");
    for bad in [
        "/",
        "",
        "relay",
        "/.well-known",
        "/a/../b",
        "/re%6Cay",
        "/a//b",
    ] {
        assert!(NostrMount::new(bad, 10).is_err(), "{bad:?}");
    }
}

struct Server {
    port: u16,
    mount: NostrMount,
}

async fn serve(max_events: usize) -> Server {
    let mount = NostrMount::new("/relay", max_events).unwrap();
    let st = state(Some(mount.clone())).await;
    let server = HttpServer::new(move || build_app(st.clone()))
        .workers(1)
        .bind(("127.0.0.1", 0))
        .unwrap();
    let port = server.addrs()[0].port();
    actix_web::rt::spawn(server.run());
    Server { port, mount }
}

async fn next_text<S>(ws: &mut S) -> Option<String>
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        match tokio::time::timeout(Duration::from_millis(2000), ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => return Some(t.to_string()),
            Ok(Some(Ok(_))) => continue,
            _ => return None,
        }
    }
}

#[actix_web::test]
async fn a_websocket_client_can_publish_and_subscribe() {
    let s = serve(100).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{}/relay", s.port))
        .await
        .expect("upgrade");
    let ev = signed(1, 1_700_000_000, "hello relay");
    ws.send(Message::text(serde_json::json!(["EVENT", ev]).to_string()))
        .await
        .unwrap();
    let ok: serde_json::Value = serde_json::from_str(&next_text(&mut ws).await.unwrap()).unwrap();
    assert_eq!(ok[0], "OK");
    assert_eq!(ok[1], ev.id.as_str());
    assert_eq!(ok[2], true, "{ok}");
    ws.send(Message::text(r#"["REQ","s1",{"kinds":[1]}]"#))
        .await
        .unwrap();
    let first: serde_json::Value =
        serde_json::from_str(&next_text(&mut ws).await.unwrap()).unwrap();
    assert_eq!(
        (first[0].as_str(), first[1].as_str()),
        (Some("EVENT"), Some("s1"))
    );
    assert_eq!(first[2]["content"], "hello relay");
    let eose: serde_json::Value = serde_json::from_str(&next_text(&mut ws).await.unwrap()).unwrap();
    assert_eq!(eose[0], "EOSE");
    // A live event after the subscription reaches it.
    let live = signed(1, 1_700_000_100, "live one");
    ws.send(Message::text(
        serde_json::json!(["EVENT", live]).to_string(),
    ))
    .await
    .unwrap();
    let mut seen = Vec::new();
    for _ in 0..2 {
        if let Some(t) = next_text(&mut ws).await {
            seen.push(t);
        }
    }
    assert!(
        seen.iter()
            .any(|t| t.contains("live one") && t.contains("\"EVENT\"")),
        "{seen:?}"
    );
    // A forged event is refused.
    let mut forged = signed(1, 1_700_000_200, "forged");
    forged.content = "tampered".into();
    ws.send(Message::text(
        serde_json::json!(["EVENT", forged]).to_string(),
    ))
    .await
    .unwrap();
    let mut refusal = None;
    for _ in 0..3 {
        match next_text(&mut ws).await {
            Some(t) if t.contains("\"OK\"") => {
                refusal = Some(t);
                break;
            }
            Some(_) => continue,
            None => break,
        }
    }
    let refusal: serde_json::Value = serde_json::from_str(&refusal.expect("an OK frame")).unwrap();
    assert_eq!(refusal[2], false, "{refusal}");
}

#[actix_web::test]
async fn the_event_store_is_bounded_by_the_configured_maximum() {
    let s = serve(2).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{}/relay", s.port))
        .await
        .unwrap();
    for i in 0..5u64 {
        let ev = signed(1, 1_700_000_000 + i, &format!("e{i}"));
        ws.send(Message::text(serde_json::json!(["EVENT", ev]).to_string()))
            .await
            .unwrap();
        next_text(&mut ws).await.expect("OK");
    }
    assert!(
        s.mount.relay().snapshot().len() <= 2,
        "{}",
        s.mount.relay().snapshot().len()
    );
}
