//! SP-FORGE-DOTSEG: since SP-PAR-291 the server's dotfile guard defers to the
//! `/forge` mount, so the forge router is the only barrier for paths beneath
//! it. This drives [`ForgeService::handle`] with dot-segment spellings (plain,
//! percent-encoded and double-encoded, after the server's one decode) aimed at
//! repository internals (`config`, `hooks/`), the forge's own key material and
//! files above the repository root, and asserts that no response carries any
//! planted marker and that a traversal never answers 200.

use std::path::Path;

use bytes::Bytes;
use solid_pod_rs_forge::{ForgeAgent, ForgeConfig, ForgeRequest, ForgeService};
use tempfile::TempDir;

const HOST: &str = "https://pod.example";

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

fn get(path: &str) -> ForgeRequest {
    ForgeRequest {
        method: "GET".into(),
        path: path.into(),
        query: String::new(),
        headers: vec![],
        raw_body: Bytes::new(),
        host_url: Some(HOST.into()),
    }
}

/// A service over a seeded bare repo `casey/demo` whose internals, the plugin
/// directory and the directory above `repos/` each hold a `MARKER-` file.
fn fixture() -> (TempDir, ForgeService) {
    let td = TempDir::new().unwrap();
    let plugin = td.path().join("plugin");
    let svc = ForgeService::new(ForgeConfig::default(), &plugin).unwrap();
    let work = td.path().join("seed");
    std::fs::create_dir_all(&work).unwrap();
    git(&work, &["init", "-q", "-b", "main"]);
    std::fs::write(work.join("README.md"), "# Demo\n").unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-q", "-m", "initial"]);
    let bare = plugin.join("repos/casey/demo.git");
    std::fs::create_dir_all(bare.parent().unwrap()).unwrap();
    git(
        td.path(),
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
    std::fs::write(bare.join("hooks/pre-receive"), "#!/bin/sh\n# MARKER-HOOK\n").unwrap();
    std::fs::write(plugin.join(".forge-token-key"), "MARKER-FORGE-KEY").unwrap();
    std::fs::write(plugin.join("repos/casey/note.txt"), "MARKER-OWNER-DIR").unwrap();
    std::fs::write(plugin.join("repos/top.txt"), "MARKER-REPOS-ROOT").unwrap();
    std::fs::write(td.path().join("outside.txt"), "MARKER-ABOVE-PLUGIN").unwrap();
    (td, svc)
}

async fn send(svc: &ForgeService, path: &str) -> (u16, String) {
    let r = svc.handle(get(path), ForgeAgent::Anonymous).await;
    match r {
        Ok(resp) => (
            resp.status,
            String::from_utf8_lossy(&resp.body).into_owned(),
        ),
        Err(e) => (500, format!("{e}")),
    }
}

#[tokio::test]
async fn the_control_paths_are_served_so_a_refusal_below_is_the_forge_s() {
    let (_td, svc) = fixture();
    for p in [
        "/forge/casey/demo",
        "/forge/casey/demo/blob/main/README.md",
        "/forge/casey/demo/raw/main/README.md",
    ] {
        let (status, _) = send(&svc, p).await;
        assert_eq!(status, 200, "{p}");
    }
}

#[tokio::test]
async fn no_dot_segment_spelling_reaches_repository_internals_or_key_material() {
    let (_td, svc) = fixture();
    let spellings = [
        // Repository internals addressed by name.
        "/forge/casey/demo.git/config",
        "/forge/casey/demo.git/hooks/pre-receive",
        "/forge/casey/demo/.git/config",
        "/forge/casey/demo/hooks/pre-receive",
        "/forge/casey/.git/config",
        "/forge/.git/config",
        "/forge/.forge-token-key",
        "/forge/casey/.forge-token-key",
        // `..` out of the repository, the owner directory, repos/ and the mount.
        "/forge/casey/demo.git/../../top.txt",
        "/forge/casey/demo/../note.txt",
        "/forge/casey/demo/raw/main/../../config",
        "/forge/casey/demo/blob/main/../../../note.txt",
        "/forge/casey/demo/tree/main/../..",
        "/forge/casey/demo.git/hooks/../info/refs",
        "/forge/casey/demo.git/info/../../../top.txt",
        "/forge/../.forge-token-key",
        "/forge/../../outside.txt",
        "/forge/casey/../../.forge-token-key",
        "/forge/casey/../../../outside.txt",
        // Single-dot segments.
        "/forge/./casey/demo",
        "/forge/casey/./demo/raw/main/README.md",
        "/forge/casey/demo.git/./info/refs",
        "/forge/casey/demo.git/./config",
        // Encoded dot and slash (still encoded after the server's one decode,
        // so the original request carried a double encoding).
        "/forge/casey/demo/raw/main/%2e%2e/config",
        "/forge/casey/demo/raw/main/%2E%2E/%2E%2E/config",
        "/forge/casey/%2e%2e/%2e%2e/.forge-token-key",
        "/forge/casey/demo.git/%2e%2e/%2e%2e/top.txt",
        "/forge/casey/demo.git%2fconfig",
        "/forge/casey%2f..%2f..%2ftop.txt",
        "/forge/casey/demo/raw/main/..%2f..%2fconfig",
        "/forge/casey/demo/raw/main/%252e%252e/config",
        "/forge/casey/%252e%252e/%252e%252e/.forge-token-key",
        "/forge/%2e/casey/demo.git/%2e/config",
        // Backslash and NUL separators.
        "/forge/casey\\..\\..\\.forge-token-key",
        "/forge/casey/demo/raw/main/..\\config",
        "/forge/casey/demo.git/config%00/info/refs",
        "/forge/casey/demo/raw/main/README.md%00../../config",
        // Mixed prefix games.
        "/forge//casey/demo.git/config",
        "/forge/casey//demo.git//config",
        "/forge/casey/demo.git/info/refs/../../config",
        "/forge/api/hosted/../../.forge-token-key",
        "/forge/api/repos/casey/demo/../../../.forge-token-key",
        "/forge/api/repos/casey/../../top.txt",
    ];
    for p in spellings {
        let (status, body) = send(&svc, p).await;
        assert!(!body.contains("MARKER-"), "{p} leaked ({status}): {body}");
        // A traversal or internals request must never succeed. The one
        // tolerated 200 is a spelling that resolves, after the router's own
        // normalisation, to the legitimate repository page; none above does.
        assert_ne!(status, 200, "{p} was answered 200: {body}");
    }
}

#[tokio::test]
async fn a_post_with_dot_segments_does_not_reach_a_write_handler() {
    let (td, svc) = fixture();
    for p in [
        "/forge/casey/../demo/issues",
        "/forge/casey/demo/issues/../../../hooks",
        "/forge/casey/%2e%2e/demo/issues",
        "/forge/api/repos/casey/demo/../../../x/fork",
    ] {
        let mut req = get(p);
        req.method = "POST".into();
        req.headers = vec![("content-type".into(), "application/json".into())];
        req.raw_body = Bytes::from_static(b"{\"title\":\"x\"}");
        let resp = svc.handle(req, ForgeAgent::Anonymous).await;
        let status = resp.map(|r| r.status).unwrap_or(500);
        assert!(
            matches!(status, 400 | 401 | 403 | 404 | 405),
            "{p} gave {status}"
        );
    }
    // Nothing was created above the repository root.
    assert!(!td.path().join("plugin/x").exists());
    assert!(!td.path().join("plugin/repos/x").exists());
}
