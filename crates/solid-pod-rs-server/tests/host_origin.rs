//! Security review M1: the public origin comes from configuration, never
//! from client-controlled `Host` forwarding headers.
//!
//! The attack: a NIP-98 event the victim signed for `https://evil.example/<path>`
//! (for instance on a hostile login page) is replayed to this server with
//! `X-Forwarded-Host: evil.example` so the `u` tag matches. Only the plain
//! `Host` header, a configured origin or (behind `trust_proxy`) the proxy
//! headers may decide the host.

use std::sync::Arc;

use actix_web::http::StatusCode;
use actix_web::test;
use bytes::Bytes;
use solid_pod_rs::auth::nip98;
use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::{build_app, AppState};

const SK_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn did_for_key() -> String {
    let sk = hex::decode(SK_HEX).unwrap();
    let signing = k256::schnorr::SigningKey::from_bytes(&sk).unwrap();
    format!(
        "did:nostr:{}",
        hex::encode(signing.verifying_key().to_bytes())
    )
}

/// A fresh NIP-98 header for an arbitrary absolute URL (distinct event id per
/// call so the replay guard never interferes).
fn nip98_for(url: &str, method: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .saturating_sub(40)
        + SEQ.fetch_add(1, Ordering::Relaxed);
    let token = nip98::mint_with_payload(url, method, None, SK_HEX, now).expect("mint");
    format!("Nostr {token}")
}

async fn state() -> AppState {
    let storage = Arc::new(MemoryBackend::new());
    let acl = format!(
        r#"{{"@graph":[{{"@type":"acl:Authorization","acl:agent":{{"@id":"{did}"}},
        "acl:accessTo":{{"@id":"/private/"}},"acl:default":{{"@id":"/private/"}},
        "acl:mode":[{{"@id":"acl:Read"}}]}}]}}"#,
        did = did_for_key()
    );
    storage
        .put("/private.acl", Bytes::from(acl), "application/ld+json")
        .await
        .unwrap();
    storage
        .put(
            "/private/secret.ttl",
            Bytes::from("<#s> <#p> <#o> ."),
            "text/turtle",
        )
        .await
        .unwrap();
    AppState::new(storage)
}

async fn status(state: AppState, headers: &[(&str, &str)], auth_url: &str) -> StatusCode {
    let app = test::init_service(build_app(state)).await;
    let mut req = test::TestRequest::get()
        .uri("/private/secret.ttl")
        .insert_header(("authorization", nip98_for(auth_url, "GET")));
    for h in headers {
        req = req.insert_header(*h);
    }
    test::call_service(&app, req.to_request()).await.status()
}

#[actix_web::test]
async fn control_token_for_the_real_host_is_accepted() {
    let s = status(
        state().await,
        &[("host", "pod.example")],
        "http://pod.example/private/secret.ttl",
    )
    .await;
    assert_eq!(s, StatusCode::OK);
}

#[actix_web::test]
async fn replay_with_forged_x_forwarded_host_is_refused() {
    let s = status(
        state().await,
        &[
            ("host", "pod.example"),
            ("x-forwarded-host", "evil.example"),
        ],
        "http://evil.example/private/secret.ttl",
    )
    .await;
    assert!(
        s == StatusCode::UNAUTHORIZED || s == StatusCode::FORBIDDEN,
        "forged X-Forwarded-Host must not satisfy NIP-98 URL matching, got {s}"
    );
}

#[actix_web::test]
async fn replay_with_forged_forwarded_header_is_refused() {
    let s = status(
        state().await,
        &[("host", "pod.example"), ("forwarded", "host=evil.example")],
        "http://evil.example/private/secret.ttl",
    )
    .await;
    assert!(
        s == StatusCode::UNAUTHORIZED || s == StatusCode::FORBIDDEN,
        "got {s}"
    );
}

#[actix_web::test]
async fn trusted_proxy_may_set_the_host() {
    let mut st = state().await;
    st.trust_proxy = true;
    let s = status(
        st,
        &[("host", "10.0.0.5"), ("x-forwarded-host", "pod.example")],
        "http://pod.example/private/secret.ttl",
    )
    .await;
    assert_eq!(s, StatusCode::OK);
}

#[actix_web::test]
async fn configured_public_origin_beats_a_trusted_header_too() {
    let mut st = state().await;
    st.trust_proxy = true;
    st.public_base_url = Some("https://pod.example".into());
    // Signed for the attacker's host: refused even though the proxy flag is on.
    let s = status(
        st.clone(),
        &[
            ("host", "pod.example"),
            ("x-forwarded-host", "evil.example"),
        ],
        "https://evil.example/private/secret.ttl",
    )
    .await;
    assert!(
        s == StatusCode::UNAUTHORIZED || s == StatusCode::FORBIDDEN,
        "{s}"
    );
    // Signed for the configured origin: accepted whatever the Host says.
    let s = status(
        st,
        &[("host", "10.9.9.9")],
        "https://pod.example/private/secret.ttl",
    )
    .await;
    assert_eq!(s, StatusCode::OK);
}

#[actix_web::test]
async fn host_outside_the_allow_list_gets_421() {
    let mut st = state().await;
    st.allowed_hosts = vec!["pod.example".into()];
    let app = test::init_service(build_app(st)).await;
    let bad = test::TestRequest::get()
        .uri("/private/secret.ttl")
        .insert_header(("host", "evil.example"))
        .to_request();
    assert_eq!(
        test::call_service(&app, bad).await.status(),
        StatusCode::MISDIRECTED_REQUEST
    );
    // A forged forwarding header cannot launder a bad Host without trust_proxy
    // and cannot hide one either: the plain Host is what is checked.
    let ok = test::TestRequest::get()
        .uri("/private/secret.ttl")
        .insert_header(("host", "pod.example:8080"))
        .to_request();
    assert_ne!(
        test::call_service(&app, ok).await.status(),
        StatusCode::MISDIRECTED_REQUEST
    );
}
