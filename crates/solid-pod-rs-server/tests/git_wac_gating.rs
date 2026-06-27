//! Git WAC-gating integration tests (ADR-059 D6, Phase 1).
//!
//! Before this fix `handle_git` handed every git smart-HTTP request straight
//! to the CGI with no authorisation check: a private pod's history was
//! anonymously clonable and pushes were anonymous (R5 "No WAC" finding). The
//! server now resolves the caller's `did:nostr` from the git
//! `Basic nostr:`/`Nostr` NIP-98 credential and enforces Read for
//! clone/fetch and Write for push against the pod-root container ACL.
//!
//! These assertions are deterministic and CGI-independent: the WAC gate runs
//! *before* the `git http-backend` CGI is ever spawned, so a denial surfaces
//! as 401/403 regardless of whether a git repo (or the CGI binary) exists. A
//! public pod that passes the gate but has no initialised repo surfaces as
//! 404 (`NotARepository`) — which is exactly how we tell "gate denied"
//! (401/403) apart from "gate allowed, nothing to serve" (404).
//!
//! Run with: `cargo test -p solid-pod-rs-server --features git`.
#![cfg(feature = "git")]

use std::sync::Arc;

use solid_pod_rs::storage::fs::FsBackend;
use solid_pod_rs_server::{build_app, AppState};

const OWNER: &str = "did:nostr:6e1cf6...owner";

/// Owner-only ACL: a single rule granting one `did:nostr` Read+Write over the
/// `/alice/` container and its descendants. No `foaf:Agent` class, so an
/// anonymous caller is denied.
fn owner_only_acl(container: &str) -> String {
    format!(
        r##"{{
            "@context": {{"acl": "http://www.w3.org/ns/auth/acl#"}},
            "@graph": [{{
                "@id": "#owner",
                "acl:agent": {{"@id": "{OWNER}"}},
                "acl:accessTo": {{"@id": "{container}"}},
                "acl:default": {{"@id": "{container}"}},
                "acl:mode": [{{"@id": "acl:Read"}}, {{"@id": "acl:Write"}}]
            }}]
        }}"##
    )
}

/// Public ACL: `foaf:Agent` may Read the container — anonymous reads pass.
fn public_read_acl(container: &str) -> String {
    format!(
        r##"{{
            "@context": {{
                "acl": "http://www.w3.org/ns/auth/acl#",
                "foaf": "http://xmlns.com/foaf/0.1/"
            }},
            "@graph": [{{
                "@id": "#public",
                "acl:agentClass": {{"@id": "foaf:Agent"}},
                "acl:accessTo": {{"@id": "{container}"}},
                "acl:default": {{"@id": "{container}"}},
                "acl:mode": {{"@id": "acl:Read"}}
            }}]
        }}"##
    )
}

/// Build an fs-backed `AppState` rooted at a fresh temp dir, with `data_root`
/// set (git requires it), seeding pod containers + their `.acl` sidecars.
async fn fs_state_with_pods(pods: &[(&str, String)]) -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().to_path_buf();
    for (pod, acl) in pods {
        // The pod container dir must exist so `handle_git`'s
        // `repo_root.exists()` check passes.
        std::fs::create_dir_all(root.join(pod)).expect("create pod dir");
        // The effective ACL for container `/{pod}/` is the *sibling*
        // sidecar `/{pod}.acl` (resolver.rs:70 — `{trimmed}.acl`), which is
        // the same path every other authz check in the server resolves. Write
        // it there, next to the container dir, not inside it.
        std::fs::write(root.join(format!("{pod}.acl")), acl).expect("write .acl");
    }
    let fs = FsBackend::new(root.clone()).await.expect("fs backend");
    let mut state = AppState::new(Arc::new(fs));
    state.data_root = Some(root);
    (state, tmp)
}

#[actix_web::test]
async fn anonymous_clone_of_private_pod_is_denied() {
    let (state, _tmp) = fs_state_with_pods(&[("alice", owner_only_acl("/alice/"))]).await;
    let app = actix_web::test::init_service(build_app(state)).await;

    // Anonymous capability advertisement (the first request of a clone).
    let req = actix_web::test::TestRequest::get()
        .uri("/alice/info/refs?service=git-upload-pack")
        .to_request();
    let rsp = actix_web::test::call_service(&app, req).await;

    let status = rsp.status().as_u16();
    assert!(
        status == 401 || status == 403,
        "anonymous clone of a private pod must be denied by WAC before the CGI \
         (expected 401/403, got {status})"
    );
}

#[actix_web::test]
async fn wac_denied_git_response_carries_cors_headers() {
    // #548/#371: a browser-based git client hitting an auth-gated repo must see
    // the real 401/403 — which requires CORS headers on the WAC-denial response,
    // not just on the git service's own responses (the gate runs before it).
    let (state, _tmp) = fs_state_with_pods(&[("alice", owner_only_acl("/alice/"))]).await;
    let app = actix_web::test::init_service(build_app(state)).await;

    let req = actix_web::test::TestRequest::get()
        .uri("/alice/info/refs?service=git-upload-pack")
        .to_request();
    let rsp = actix_web::test::call_service(&app, req).await;

    let status = rsp.status().as_u16();
    assert!(status == 401 || status == 403, "expected denial, got {status}");
    assert_eq!(
        rsp.headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("*"),
        "WAC-denied git response must carry CORS so browser git clients see the status"
    );
    assert!(
        rsp.headers().get("access-control-allow-methods").is_some(),
        "WAC-denied git response must advertise allowed methods"
    );
}

#[actix_web::test]
async fn anonymous_push_to_private_pod_is_denied() {
    let (state, _tmp) = fs_state_with_pods(&[("alice", owner_only_acl("/alice/"))]).await;
    let app = actix_web::test::init_service(build_app(state)).await;

    // A push is `git-receive-pack` — gated as Write.
    let req = actix_web::test::TestRequest::post()
        .uri("/alice/git-receive-pack")
        .insert_header(("content-type", "application/x-git-receive-pack-request"))
        .set_payload(actix_web::web::Bytes::from_static(b""))
        .to_request();
    let rsp = actix_web::test::call_service(&app, req).await;

    let status = rsp.status().as_u16();
    assert!(
        status == 401 || status == 403,
        "anonymous push must be denied by WAC (expected 401/403, got {status})"
    );
}

#[actix_web::test]
async fn anonymous_read_of_public_pod_passes_gate() {
    // Public pod, but no git repo initialised: the WAC gate must ALLOW the
    // anonymous read (public foaf:Agent Read), after which the git service
    // reports 404 NotARepository. A 404 (not 401/403) proves the gate opened.
    let (state, _tmp) = fs_state_with_pods(&[("bob", public_read_acl("/bob/"))]).await;
    let app = actix_web::test::init_service(build_app(state)).await;

    let req = actix_web::test::TestRequest::get()
        .uri("/bob/info/refs?service=git-upload-pack")
        .to_request();
    let rsp = actix_web::test::call_service(&app, req).await;

    let status = rsp.status().as_u16();
    assert!(
        status != 401 && status != 403,
        "anonymous read of a public pod must PASS the WAC gate \
         (expected non-401/403, e.g. 404 no-repo; got {status})"
    );
}
