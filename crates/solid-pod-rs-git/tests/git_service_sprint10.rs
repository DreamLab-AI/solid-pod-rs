//! Sprint 10 integration tests for `solid-pod-rs-git` — PARITY rows
//! 69 (Basic nostr: auth) + 100 (Git HTTP with
//! `receive.denyCurrentBranch=updateInstead`).
//!
//! All tests that require the `git-http-backend` CGI binary are
//! gated behind the `with-git-binary` feature so CI without git can
//! still exercise unit tests. When the binary is present at the
//! default path (`/usr/lib/git-core/git-http-backend`) these flip on
//! and exercise the full CGI roundtrip.

use std::path::PathBuf;
use std::process::Command;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bytes::Bytes;
use sha2::{Digest, Sha256};
use async_trait::async_trait;
use solid_pod_rs_git::{
    AuthError, BasicNostrExtractor, GitAuth, GitHttpService, GitRequest,
    DEFAULT_GIT_HTTP_BACKEND,
};

/// Test-only auth that accepts every request. Isolates the routing /
/// config-mutator tests from NIP-98 / Schnorr verification specifics
/// (which have dedicated tests in the `solid-pod-rs` core crate and
/// `auth.rs` unit tests). Using this keeps the sprint-10 integration
/// tests stable under both default and `--all-features` builds, where
/// the `nip98-schnorr` feature flips the verifier from permissive to
/// strict.
struct AlwaysAllow;

#[async_trait]
impl GitAuth for AlwaysAllow {
    async fn authorise(&self, _req: &GitRequest) -> Result<String, AuthError> {
        Ok("test-user".into())
    }
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

fn git_backend_available() -> bool {
    let p = std::env::var("GIT_HTTP_BACKEND_PATH")
        .unwrap_or_else(|_| DEFAULT_GIT_HTTP_BACKEND.to_string());
    PathBuf::from(p).exists() && Command::new("git").arg("--version").output().is_ok()
}

/// Initialise a regular git repo with one commit in `path`. Returns
/// the SHA of the head commit (hex).
fn init_repo_with_commit(path: &std::path::Path) -> String {
    let run = |args: &[&str]| {
        let out = Command::new("git")
            .args(args)
            .current_dir(path)
            .output()
            .expect("git");
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };

    assert!(Command::new("git")
        .args(["init", path.to_str().unwrap()])
        .status()
        .unwrap()
        .success());
    run(&["config", "user.email", "test@example.com"]);
    run(&["config", "user.name", "Test"]);

    std::fs::write(path.join("hello.txt"), "hello world\n").unwrap();
    run(&["add", "hello.txt"]);
    run(&["commit", "-m", "initial"]);
    run(&["rev-parse", "HEAD"])
}

/// Craft a structurally-valid NIP-98 `Authorization: Basic
/// nostr:<token>` header. The core verifier accepts this when the
/// `nip98-schnorr` feature is *not* enabled on solid-pod-rs (default
/// build), because Schnorr verification is then a no-op.
fn basic_nostr_header(url: &str, method: &str, body: Option<&[u8]>) -> String {
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut tags = vec![
        vec!["u".to_string(), url.to_string()],
        vec!["method".to_string(), method.to_string()],
    ];
    if let Some(b) = body {
        if !b.is_empty() {
            tags.push(vec![
                "payload".to_string(),
                hex::encode(Sha256::digest(b)),
            ]);
        }
    }

    let event = serde_json::json!({
        "id": "0".repeat(64),
        "pubkey": "a".repeat(64),
        "created_at": created_at,
        "kind": 27235,
        "tags": tags,
        "content": "",
        "sig": "0".repeat(128),
    });

    let token = BASE64.encode(serde_json::to_string(&event).unwrap());
    let basic = BASE64.encode(format!("nostr:{token}"));
    format!("Basic {basic}")
}

// ---------------------------------------------------------------------------
// Binder-agnostic unit tests (no CGI).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn receive_pack_post_rejects_without_auth() {
    let td = tempfile::TempDir::new().unwrap();
    // Make it look like a repo so we don't short-circuit at 404.
    std::fs::create_dir(td.path().join("repo")).unwrap();
    std::fs::create_dir(td.path().join("repo/.git")).unwrap();

    let svc = GitHttpService::new(td.path().to_path_buf())
        .with_auth(BasicNostrExtractor::new());

    let req = GitRequest {
        method: "POST".into(),
        path: "/repo/git-receive-pack".into(),
        query: String::new(),
        headers: vec![],
        body: Bytes::new(),
        host_url: Some("http://localhost".into()),
    };

    let err = svc.handle(req).await.unwrap_err();
    assert_eq!(err.status_code(), 401);
}

#[tokio::test]
async fn receive_pack_post_accepts_nip98_basic_auth_header() {
    let td = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(td.path().join("repo")).unwrap();
    std::fs::create_dir(td.path().join("repo/.git")).unwrap();

    let svc = GitHttpService::new(td.path().to_path_buf())
        .with_auth(BasicNostrExtractor::new());

    let url = "http://localhost/repo/git-receive-pack";
    let header = basic_nostr_header(url, "POST", None);
    let req = GitRequest {
        method: "POST".into(),
        path: "/repo/git-receive-pack".into(),
        query: String::new(),
        headers: vec![("Authorization".into(), header)],
        body: Bytes::new(),
        host_url: Some("http://localhost".into()),
    };

    // Auth should pass. The CGI spawn may still fail because we did
    // not fully initialise the repo (or the binary may be absent) —
    // but that produces a different (non-401) status code, which is
    // what we are asserting here.
    let result = svc.handle(req).await;
    match result {
        Ok(r) => assert_ne!(
            r.status, 401,
            "auth must succeed but got 401 response"
        ),
        Err(e) => {
            assert_ne!(
                e.status_code(),
                401,
                "auth must succeed but got 401: {e:?}"
            );
        }
    }
}

#[tokio::test]
async fn path_traversal_denied_via_parent_dir() {
    let td = tempfile::TempDir::new().unwrap();
    let svc = GitHttpService::new(td.path().to_path_buf());

    let req = GitRequest {
        method: "GET".into(),
        path: "/../../etc/passwd/info/refs".into(),
        query: "service=git-upload-pack".into(),
        headers: vec![],
        body: Bytes::new(),
        host_url: None,
    };

    // The guard strips `..` at the slug level, so this should resolve
    // to a missing-repo (404) rather than traversing — either a 400
    // (path rejected) or 404 (not a repo) is acceptable and proves
    // we did not escape the root.
    let err = svc.handle(req).await.unwrap_err();
    assert!(
        matches!(err.status_code(), 400 | 404),
        "expected 400/404, got {}",
        err.status_code()
    );
}

#[tokio::test]
async fn not_a_repo_returns_404() {
    let td = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(td.path().join("nope")).unwrap();
    let svc = GitHttpService::new(td.path().to_path_buf());

    let req = GitRequest {
        method: "GET".into(),
        path: "/nope/info/refs".into(),
        query: "service=git-upload-pack".into(),
        headers: vec![],
        body: Bytes::new(),
        host_url: None,
    };
    let err = svc.handle(req).await.unwrap_err();
    assert_eq!(err.status_code(), 404);
}

#[tokio::test]
async fn options_preflight_returns_cors() {
    let td = tempfile::TempDir::new().unwrap();
    let svc = GitHttpService::new(td.path().to_path_buf());
    let req = GitRequest {
        method: "OPTIONS".into(),
        path: "/repo/info/refs".into(),
        query: String::new(),
        headers: vec![],
        body: Bytes::new(),
        host_url: None,
    };
    let resp = svc.handle(req).await.unwrap();
    assert_eq!(resp.status, 200);
    let header_names: Vec<_> = resp.headers.iter().map(|(k, _)| k.as_str()).collect();
    assert!(header_names
        .iter()
        .any(|k| k.eq_ignore_ascii_case("access-control-allow-origin")));
    assert!(header_names
        .iter()
        .any(|k| k.eq_ignore_ascii_case("access-control-allow-methods")));
}

// ---------------------------------------------------------------------------
// CGI roundtrip tests. Require the `git` CLI + `git-http-backend`
// binary at runtime. Gated by the `with-git-binary` feature AND by
// a runtime probe so `cargo test --all-features` is still green even
// without the binary.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn info_refs_get_returns_service_advertisement() {
    if !git_backend_available() {
        eprintln!("skipping: git-http-backend binary not found");
        return;
    }
    let td = tempfile::TempDir::new().unwrap();
    let repo = td.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    let _sha = init_repo_with_commit(&repo);

    let svc = GitHttpService::new(td.path().to_path_buf());
    let req = GitRequest {
        method: "GET".into(),
        path: "/repo/info/refs".into(),
        query: "service=git-upload-pack".into(),
        headers: vec![],
        body: Bytes::new(),
        host_url: None,
    };
    let resp = svc.handle(req).await.expect("handle");
    assert_eq!(resp.status, 200);
    // `git http-backend` emits the `# service=git-upload-pack` line
    // as part of the smart-HTTP packfile advertisement.
    let body_str = String::from_utf8_lossy(&resp.body);
    assert!(
        body_str.contains("# service=git-upload-pack"),
        "body did not advertise the upload-pack service; got: {}",
        &body_str[..body_str.len().min(200)]
    );
}

#[tokio::test]
async fn upload_pack_post_returns_packfile_magic() {
    if !git_backend_available() {
        eprintln!("skipping: git-http-backend binary not found");
        return;
    }
    let td = tempfile::TempDir::new().unwrap();
    let repo = td.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    let sha = init_repo_with_commit(&repo);

    let svc = GitHttpService::new(td.path().to_path_buf());

    // Build a minimal pkt-line request: want <sha>\n, flush, done\n.
    // Format each pkt-line as `hhhh<data>` where hhhh is the 4-char
    // hex length (including the hhhh itself).
    let want = format!("want {sha} multi_ack_detailed no-done side-band-64k thin-pack ofs-delta\n");
    let want_line = format!("{:04x}{}", want.len() + 4, want);
    let done_line = format!("{:04x}{}", "done\n".len() + 4, "done\n");
    // Request body = <want-pkt><flush-pkt><done-pkt>.
    let body = format!("{want_line}0000{done_line}");

    let req = GitRequest {
        method: "POST".into(),
        path: "/repo/git-upload-pack".into(),
        query: String::new(),
        headers: vec![(
            "Content-Type".into(),
            "application/x-git-upload-pack-request".into(),
        )],
        body: Bytes::from(body.into_bytes()),
        host_url: None,
    };
    let resp = svc.handle(req).await.expect("handle");
    assert_eq!(resp.status, 200);
    assert!(
        !resp.body.is_empty(),
        "empty body from upload-pack; stderr must have a reason"
    );
    // The response is a pkt-line stream; the side-band-64k prefix
    // means data bytes come on channel 1. We assert non-empty + that
    // the content-type header indicates a packfile result.
    let ct = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    assert!(
        ct.contains("upload-pack-result"),
        "expected upload-pack-result content-type, got {ct}"
    );
}

#[tokio::test]
async fn update_instead_applied_on_push_config() {
    if !git_backend_available() {
        eprintln!("skipping: git binary not found");
        return;
    }
    let td = tempfile::TempDir::new().unwrap();
    let repo = td.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    let _sha = init_repo_with_commit(&repo);

    // Drive a receive-pack request that will fail early (no real
    // pkt-lines), but the service still runs the config mutator
    // before spawning the CGI.
    let svc = GitHttpService::new(td.path().to_path_buf())
        .with_auth(BasicNostrExtractor::new());

    let url = "http://localhost/repo/git-receive-pack";
    let header = basic_nostr_header(url, "POST", None);
    let req = GitRequest {
        method: "POST".into(),
        path: "/repo/git-receive-pack".into(),
        query: String::new(),
        headers: vec![(
            "Authorization".into(),
            header,
        )],
        body: Bytes::new(),
        host_url: Some("http://localhost".into()),
    };
    let _ = svc.handle(req).await;

    // Whether the CGI succeeded or not, the mutator should have run.
    let out = Command::new("git")
        .args(["config", "--local", "receive.denyCurrentBranch"])
        .current_dir(&repo)
        .env("GIT_DIR", repo.join(".git"))
        .output()
        .unwrap();
    assert!(out.status.success(), "git config read failed");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "updateInstead",
        "receive.denyCurrentBranch must be updateInstead after a write request"
    );

    let out2 = Command::new("git")
        .args(["config", "--local", "http.receivepack"])
        .current_dir(&repo)
        .env("GIT_DIR", repo.join(".git"))
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out2.stdout).trim(),
        "true",
        "http.receivepack must be true after a write request"
    );
}
