//! SP-PAR-291: the dotfile guard defers to an app-plugin mount prefix.
//!
//! With `forge` compiled in, `/forge` owns every path beneath it, so a dot
//! segment there reaches the forge (which applies its own rules) instead of
//! being answered 403 by the guard. The carve-out is only the mount itself:
//! a lookalike prefix, a traversal out of it and every dotfile elsewhere stay
//! refused, and without the feature nothing is carved out.
//!
//! Run the forge half with `cargo test -p solid-pod-rs-server --features forge`.

use std::sync::Arc;

use actix_web::test;
use solid_pod_rs::storage::fs::FsBackend;
use solid_pod_rs_server::{build_app, AppState};

const GUARD_BODY: &str = "dotfile path denied by allowlist";

async fn status_and_body(uri: &str) -> (u16, String) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().to_path_buf();
    let fs = FsBackend::new(root.clone()).await.expect("fs backend");
    let mut state = AppState::new(Arc::new(fs));
    state.data_root = Some(root);
    let app = test::init_service(build_app(state)).await;
    let req = test::TestRequest::get().uri(uri).to_request();
    let rsp = test::call_service(&app, req).await;
    let status = rsp.status().as_u16();
    let body = test::read_body(rsp).await;
    (status, String::from_utf8_lossy(&body).into_owned())
}

async fn guard_refuses(uri: &str) -> bool {
    let (status, body) = status_and_body(uri).await;
    status == 403 && body.contains(GUARD_BODY)
}

#[actix_web::test]
async fn dotfiles_outside_a_plugin_mount_stay_refused() {
    for uri in [
        "/.env",
        "/.git/config",
        "/alice/.env",
        "/forgery/.env",
        "/forge.env/.env",
    ] {
        assert!(guard_refuses(uri).await, "{uri} must stay refused");
    }
}

#[cfg(feature = "forge")]
#[actix_web::test]
async fn a_dot_segment_under_the_forge_mount_reaches_the_forge() {
    for uri in [
        "/forge/.env",
        "/forge/casey/.hidden",
        "/forge/casey/.git/config",
    ] {
        assert!(!guard_refuses(uri).await, "{uri} should reach the forge");
    }
}

#[cfg(feature = "forge")]
#[actix_web::test]
async fn the_forge_prefix_is_no_way_to_a_protected_dotfile() {
    // Traversal out of the mount, plain and percent-encoded, is refused by the
    // traversal guard, never carved out and never served.
    for uri in [
        "/forge/../.env",
        "/forge/%2e%2e/.env",
        "/forge/%252e%252e/.env",
        "/forge/./../.git/config",
    ] {
        let (status, body) = status_and_body(uri).await;
        assert!(
            status == 400 || status == 403,
            "{uri} gave {status}: {body}"
        );
        assert!(!body.contains("SECRET"), "{uri} leaked: {body}");
    }
    // A prefix that merely starts with the mount name is not the mount.
    assert!(guard_refuses("/forgery/.env").await);
    // An encoded slash does not fake the mount boundary: the request is
    // treated exactly as the same shape outside the mount is.
    let inside = status_and_body("/forge%2f.env").await;
    let outside = status_and_body("/alice%2f.env").await;
    assert_eq!(inside.0, outside.0, "{inside:?} vs {outside:?}");
}

#[cfg(not(feature = "forge"))]
#[actix_web::test]
async fn without_the_forge_feature_nothing_is_carved_out() {
    assert!(guard_refuses("/forge/.env").await);
    assert!(guard_refuses("/forge/casey/.hidden").await);
}
