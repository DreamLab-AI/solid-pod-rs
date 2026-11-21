//! SP-FORGE-DOTSEG at the HTTP boundary: with the forge mounted, the dotfile
//! guard defers to `/forge`, so the forge router is the only barrier for paths
//! beneath it. A real bare repository under `<data_root>/.forge/repos` carries
//! marker files in its `config`, its `hooks/` and the forge key directory; no
//! spelling of a dot segment (plain, encoded, double-encoded) may return one.
//!
//! Run with: `cargo test -p solid-pod-rs-server --features forge --test forge_dot_segments`.
#![cfg(feature = "forge")]

use std::path::Path;
use std::sync::Arc;

use actix_web::test;
use solid_pod_rs::storage::fs::FsBackend;
use solid_pod_rs_server::{build_app, AppState};

fn git(cwd: &Path, args: &[&str]) {
    let out = std::process::Command::new("git")
        .args([
            "-c",
            "user.name=T",
            "-c",
            "user.email=t@e.st",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[actix_web::test]
async fn no_dot_segment_spelling_under_the_forge_mount_returns_repository_internals() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("pod");
    let forge = root.join(".forge");
    let work = tmp.path().join("seed");
    std::fs::create_dir_all(&work).unwrap();
    git(&work, &["init", "-q", "-b", "main"]);
    std::fs::write(work.join("README.md"), "# Demo\n").unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-q", "-m", "initial"]);
    let bare = forge.join("repos/casey/demo.git");
    std::fs::create_dir_all(bare.parent().unwrap()).unwrap();
    git(
        tmp.path(),
        &[
            "clone",
            "-q",
            "--bare",
            work.to_str().unwrap(),
            bare.to_str().unwrap(),
        ],
    );
    let mut cfg = std::fs::read_to_string(bare.join("config")).unwrap();
    cfg.push_str("[credential]\n\ttoken = MARKER-REPO-CONFIG\n");
    std::fs::write(bare.join("config"), cfg).unwrap();
    std::fs::create_dir_all(bare.join("hooks")).unwrap();
    std::fs::write(bare.join("hooks/pre-receive"), "# MARKER-HOOK\n").unwrap();
    std::fs::write(forge.join(".forge-token-key"), "MARKER-FORGE-KEY").unwrap();
    std::fs::write(root.join("top-secret.txt"), "MARKER-POD-ROOT").unwrap();

    let fs = FsBackend::new(root.clone()).await.expect("fs backend");
    let mut state = AppState::new(Arc::new(fs));
    state.data_root = Some(root);
    let app = test::init_service(build_app(state)).await;

    // Control: the forge serves the repository page, so the refusals are real.
    let rsp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/forge/casey/demo")
            .to_request(),
    )
    .await;
    assert_eq!(rsp.status().as_u16(), 200, "control");

    for uri in [
        "/forge/casey/demo.git/config",
        "/forge/casey/demo.git/hooks/pre-receive",
        "/forge/casey/demo/.git/config",
        "/forge/.forge-token-key",
        "/forge/casey/../../.forge-token-key",
        "/forge/casey/%2e%2e/%2e%2e/.forge-token-key",
        "/forge/casey/%252e%252e/%252e%252e/.forge-token-key",
        "/forge/casey/demo/raw/main/../../config",
        "/forge/casey/demo/raw/main/%2e%2e/%2e%2e/config",
        "/forge/casey/demo/raw/main/%252e%252e/config",
        "/forge/casey/demo/raw/main/..%2f..%2fconfig",
        "/forge/casey/demo.git/%2e%2e/%2e%2e/%2e%2e/top-secret.txt",
        "/forge/casey/demo.git/./config",
        "/forge/casey/demo.git/hooks/../info/refs",
        "/forge/../../top-secret.txt",
        "/forge/casey%2f..%2f..%2f..%2ftop-secret.txt",
        "/forge/casey/demo.git/config%00",
        "/forge/casey/demo.git%5cconfig",
    ] {
        let rsp = test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
        let status = rsp.status().as_u16();
        let body = String::from_utf8_lossy(&test::read_body(rsp).await).into_owned();
        assert!(!body.contains("MARKER-"), "{uri} leaked ({status}): {body}");
        assert_ne!(status, 200, "{uri} answered 200: {body}");
    }
}
