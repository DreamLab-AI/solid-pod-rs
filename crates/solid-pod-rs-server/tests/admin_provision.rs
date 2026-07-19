//! Integration tests for `POST /_admin/provision/{pubkey}` — the native-pod
//! provisioning endpoint the forum auth-worker calls.
//!
//! Regression coverage for the two provisioning bugs fixed in
//! `fix/admin-provision-pod-namespace` (both proven live against the running
//! 0.5.0-alpha.3 server, where every authenticated write to a freshly
//! provisioned pod 403'd):
//!
//! * **BUG 1** — the pod was written to `data_root/{pk}` (bare), but the LDP
//!   handlers serve `/pods/{pk}/…` from `data_root/pods/{pk}/…` and the
//!   returned `podUrl` is `/pods/{pk}/`. The pod was invisible to its own URL.
//! * **BUG 2** — the owner ACL was written INSIDE the pod at `{pod}/.acl`
//!   (storage key `/pods/{pk}/.acl`), which the walk-up WAC resolver never
//!   reads. It probes the SIBLING sidecar `/pods/{pk}.acl`.
//!
//! These tests drive the REAL provision handler end-to-end (FS-backed, no
//! network) and then perform an authenticated NIP-98 PUT into the fresh pod,
//! asserting the write now succeeds (201) for the owner and is denied (403)
//! for a stranger.

use std::sync::Arc;

use actix_web::http::header;
use actix_web::test;
use solid_pod_rs::auth::nip98;
use solid_pod_rs::storage::fs::FsBackend;
use solid_pod_rs_server::{build_app, AppState};

const ADMIN_KEY: &str = "test-provision-psk";

/// The pod owner's 32-byte secret (64 hex). Its x-only pubkey is the pod name.
const OWNER_SK: &str = "1111111111111111111111111111111111111111111111111111111111111111";
/// A different key — a non-owner whose authenticated writes must be denied.
const STRANGER_SK: &str = "2222222222222222222222222222222222222222222222222222222222222222";

/// x-only (64-hex) pubkey for a secret key — the NIP-98 identity and pod name.
fn xonly(sk_hex: &str) -> String {
    let sk = k256::schnorr::SigningKey::from_bytes(&hex::decode(sk_hex).unwrap()).unwrap();
    hex::encode(sk.verifying_key().to_bytes())
}

/// Build an FS-backed `AppState` (provision requires `data_root`) with the
/// admin PSK configured, returning the state and the backing temp dir.
async fn fs_state() -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().to_path_buf();
    let fs = FsBackend::new(root.clone()).await.expect("fs backend");
    let mut state = AppState::new(Arc::new(fs));
    state.data_root = Some(root);
    state.admin_key = Some(ADMIN_KEY.to_string());
    (state, tmp)
}

/// Mint a NIP-98 `Authorization` header for `method`+`path` signed by `sk_hex`.
/// The handler reconstructs the signed URL from actix `connection_info`, which
/// in the test harness is `http://localhost:8080`; mirror it exactly so strict
/// URL binding passes. Each token is a distinct event (unique `created_at`) so
/// the process-global single-use replay guard never rejects a second mint.
fn nip98_auth(sk_hex: &str, method: &str, path: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;
    static BASE: OnceLock<u64> = OnceLock::new();
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let base = *BASE.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(30)
    });
    let now = base + SEQ.fetch_add(1, Ordering::Relaxed);
    let url = format!("http://localhost:8080{path}");
    let token = nip98::mint(&url, method, sk_hex, now)
        .expect("nip98-schnorr is enabled in the workspace test build");
    format!("Nostr {token}")
}

// ---------------------------------------------------------------------------
// Provisioning + on-disk layout
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn provision_requires_admin_key() {
    let (state, _tmp) = fs_state().await;
    let app = test::init_service(build_app(state)).await;
    let pk = xonly(OWNER_SK);

    // No admin key header → 403.
    let req = test::TestRequest::post()
        .uri(&format!("/_admin/provision/{pk}"))
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(rsp.status().as_u16(), 403, "missing admin key → 403");

    // Wrong admin key → 403.
    let req = test::TestRequest::post()
        .uri(&format!("/_admin/provision/{pk}"))
        .insert_header(("x-pod-admin-key", "wrong"))
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(rsp.status().as_u16(), 403, "wrong admin key → 403");
}

#[actix_web::test]
async fn provision_writes_pod_into_pods_namespace_with_sibling_acl() {
    let (state, tmp) = fs_state().await;
    let root = tmp.path().to_path_buf();
    let app = test::init_service(build_app(state)).await;
    let pk = xonly(OWNER_SK);

    let req = test::TestRequest::post()
        .uri(&format!("/_admin/provision/{pk}"))
        .insert_header(("x-pod-admin-key", ADMIN_KEY))
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(rsp.status().as_u16(), 200, "valid admin key → 200");

    let json: serde_json::Value = test::read_body_json(rsp).await;
    assert_eq!(json["ok"], true);
    // The base is `state.nodeinfo.base_url`; assert the namespace path suffix.
    assert!(
        json["podUrl"]
            .as_str()
            .unwrap()
            .ends_with(&format!("/pods/{pk}/")),
        "podUrl must advertise the /pods/{{pk}}/ namespace, got {:?}",
        json["podUrl"]
    );

    // BUG 1 fix: the pod lives under `data_root/pods/{pk}/`, matching the URL.
    assert!(
        root.join("pods").join(&pk).is_dir(),
        "pod dir must be data_root/pods/{{pk}} (the /pods/ URL namespace)"
    );
    // BUG 2 fix: the owner ACL is the SIBLING sidecar the resolver reads.
    assert!(
        root.join("pods").join(format!("{pk}.acl")).is_file(),
        "owner ACL must be the sibling data_root/pods/{{pk}}.acl"
    );
    // The bare-namespace location the buggy handler used must NOT be created.
    assert!(
        !root.join(&pk).exists(),
        "no bare data_root/{{pk}} pod should be created (that was BUG 1)"
    );
}

// ---------------------------------------------------------------------------
// The headline guarantee: provision → authenticated PUT succeeds
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn provisioned_owner_can_put_into_pod() {
    let (state, _tmp) = fs_state().await;
    let app = test::init_service(build_app(state)).await;
    let pk = xonly(OWNER_SK);

    // Provision the pod.
    let req = test::TestRequest::post()
        .uri(&format!("/_admin/provision/{pk}"))
        .insert_header(("x-pod-admin-key", ADMIN_KEY))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status().as_u16(),
        200,
        "provision must succeed"
    );

    // Authenticated NIP-98 PUT into the fresh pod (the write that used to 403).
    let resource = format!("/pods/{pk}/media/public/x");
    let auth = nip98_auth(OWNER_SK, "PUT", &resource);
    let req = test::TestRequest::put()
        .uri(&resource)
        .insert_header((header::AUTHORIZATION, auth))
        .insert_header((header::CONTENT_TYPE, "text/plain"))
        .set_payload("hello")
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(
        rsp.status().as_u16(),
        201,
        "provisioned owner's authenticated PUT must succeed (201 Created), \
         not 403 — the resolver now finds the sibling owner ACL"
    );

    // And the owner can read it back.
    let auth = nip98_auth(OWNER_SK, "GET", &resource);
    let req = test::TestRequest::get()
        .uri(&resource)
        .insert_header((header::AUTHORIZATION, auth))
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(
        rsp.status().as_u16(),
        200,
        "owner GET of own resource → 200"
    );
    let body = test::read_body(rsp).await;
    assert_eq!(&body[..], b"hello");
}

#[actix_web::test]
async fn stranger_cannot_put_into_provisioned_pod() {
    let (state, _tmp) = fs_state().await;
    let app = test::init_service(build_app(state)).await;
    let pk = xonly(OWNER_SK);

    // Provision the owner's pod.
    let req = test::TestRequest::post()
        .uri(&format!("/_admin/provision/{pk}"))
        .insert_header(("x-pod-admin-key", ADMIN_KEY))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 200);

    // A DIFFERENT authenticated agent must be denied (the owner ACL grants
    // only `did:nostr:{owner}`) — proves the sibling ACL is enforced, not
    // world-writable.
    let resource = format!("/pods/{pk}/media/public/x");
    let auth = nip98_auth(STRANGER_SK, "PUT", &resource);
    let req = test::TestRequest::put()
        .uri(&resource)
        .insert_header((header::AUTHORIZATION, auth))
        .insert_header((header::CONTENT_TYPE, "text/plain"))
        .set_payload("intruder")
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(
        rsp.status().as_u16(),
        403,
        "a non-owner's authenticated PUT must be denied (403)"
    );
    assert_ne!(
        xonly(STRANGER_SK),
        pk,
        "sanity: stranger key differs from owner key"
    );
}
