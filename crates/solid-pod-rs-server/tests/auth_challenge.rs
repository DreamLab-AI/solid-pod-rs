//! SP-OIDC-02: the 401 challenge advertises only the schemes resource
//! admission honours. Admission verifies NIP-98 (`Nostr`) and, in
//! `dev-bearer` builds, the development HMAC bearer. It dispatches no
//! OIDC/DPoP access token, so `DPoP` must never be offered, and `Bearer` only
//! when the development bearer is compiled in.

use std::sync::Arc;

use actix_web::test;
use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs_server::{build_app, AppState, RESOURCE_AUTH_CHALLENGE};

async fn challenge_of(method: test::TestRequest) -> (u16, String) {
    let state = AppState::new(Arc::new(MemoryBackend::new()));
    let app = test::init_service(build_app(state)).await;
    let rsp = test::call_service(&app, method.to_request()).await;
    let status = rsp.status().as_u16();
    let challenge = rsp
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    (status, challenge)
}

#[actix_web::test]
async fn an_unauthenticated_denial_never_offers_dpop() {
    for req in [
        test::TestRequest::get().uri("/private/doc"),
        test::TestRequest::put()
            .uri("/private/doc")
            .insert_header(("content-type", "text/plain"))
            .set_payload("x"),
        test::TestRequest::delete().uri("/private/doc"),
    ] {
        let (status, challenge) = challenge_of(req).await;
        assert_eq!(status, 401);
        assert_eq!(challenge, RESOURCE_AUTH_CHALLENGE);
        assert!(challenge.contains("Nostr realm=\"Solid\""), "{challenge}");
        assert!(!challenge.contains("DPoP"), "{challenge}");
    }
}

#[cfg(not(feature = "dev-bearer"))]
#[actix_web::test]
async fn bearer_is_not_offered_when_no_bearer_is_honoured() {
    let (_, challenge) = challenge_of(test::TestRequest::get().uri("/private/doc")).await;
    assert!(!challenge.contains("Bearer"), "{challenge}");
}

#[cfg(feature = "dev-bearer")]
#[actix_web::test]
async fn bearer_is_offered_only_with_the_development_bearer() {
    let (_, challenge) = challenge_of(test::TestRequest::get().uri("/private/doc")).await;
    assert!(challenge.contains("Bearer realm=\"Solid\""), "{challenge}");
}
