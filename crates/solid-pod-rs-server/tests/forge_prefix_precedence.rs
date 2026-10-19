//! The forge mount owns its prefix (JSS #616 / #206 parity).
//!
//! JSS 0.0.221 made its core git lane defer to plugin-owned prefixes: a
//! git-looking URL under an app path (the forge at `/forge/<owner>/<name>.git`)
//! falls through to the plugin, which does its own authorisation and runs its
//! own backend, instead of being caught by the pod's git lane.
//!
//! Here the same property is structural: the `/forge` routes are registered
//! before the pod-git catch-all. These tests pin it, because the pod git lane
//! refuses every push with `push_not_served` (ER-28), and a forge push that
//! was swallowed by that refusal would be indistinguishable from "push is off"
//! to a client that is entitled to push through the forge.
//!
//! Run with: `cargo test -p solid-pod-rs-server --features forge`.
#![cfg(feature = "forge")]

use std::sync::Arc;

use solid_pod_rs::storage::fs::FsBackend;
use solid_pod_rs_server::{build_app, AppState};

async fn state() -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().to_path_buf();
    std::fs::create_dir_all(root.join("alice")).expect("pod dir");
    let fs = FsBackend::new(root.clone()).await.expect("fs backend");
    let mut state = AppState::new(Arc::new(fs));
    state.data_root = Some(root);
    (state, tmp)
}

async fn body_text<B: actix_web::body::MessageBody>(
    rsp: actix_web::dev::ServiceResponse<B>,
) -> (u16, String) {
    let status = rsp.status().as_u16();
    let body = actix_web::test::read_body(rsp).await;
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[actix_web::test]
async fn forge_receive_pack_is_not_swallowed_by_the_pod_push_refusal() {
    let (state, _tmp) = state().await;
    let app = actix_web::test::init_service(build_app(state)).await;

    // Control: the pod git lane refuses push for everyone (ER-28).
    let pod = actix_web::test::TestRequest::post()
        .uri("/alice/git-receive-pack")
        .to_request();
    let (status, text) = body_text(actix_web::test::call_service(&app, pod).await).await;
    assert_eq!(status, 403);
    assert!(text.contains("push_not_served"), "control: {text}");

    // The same verbs under the forge prefix reach the forge, whatever it
    // then decides (here: an anonymous caller, no such repository).
    for (method, uri) in [
        (
            "GET",
            "/forge/casey/agent.git/info/refs?service=git-receive-pack",
        ),
        ("POST", "/forge/casey/agent.git/git-receive-pack"),
        (
            "GET",
            "/forge/casey/agent.git/info/refs?service=git-upload-pack",
        ),
    ] {
        let req = actix_web::test::TestRequest::default()
            .method(method.parse().unwrap())
            .uri(uri)
            .to_request();
        let (status, text) = body_text(actix_web::test::call_service(&app, req).await).await;
        assert!(
            !text.contains("push_not_served"),
            "{method} {uri} was caught by the pod git lane: {status} {text}"
        );
    }
}
