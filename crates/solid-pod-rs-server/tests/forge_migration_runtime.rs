//! SP-GIT-02 Commit B1, test 17 (server half): `ForgeService::new` runs the
//! boot migration of legacy mirror stores on its own thread and runtime, so
//! it completes inside actix's current-thread runtime without panicking.
//! Run with `cargo test -p solid-pod-rs-server --features forge-full forge`.
#![cfg(feature = "forge")]

use std::path::{Path, PathBuf};
use std::process::Command;

use solid_pod_rs_forge::{ForgeAgent, ForgeConfig, ForgeRequest, ForgeService};

const HELD: &str = "b1-server-held-bytes\n";

fn git(cwd: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args([
            "-c",
            "user.name=Agent",
            "-c",
            "user.email=agent@example.org",
        ])
        .args(args)
        .current_dir(cwd)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A lost-record legacy store (hideRefs and `refs/mirror`, no record) with a
/// held side commit. Returns `(plugin, owner, held, approved)`.
fn legacy(home: &Path) -> (PathBuf, String, String, String) {
    let up = home.join("up");
    std::fs::create_dir_all(&up).unwrap();
    git(&up, &["init", "--quiet", "-b", "main"]);
    std::fs::write(up.join("public.txt"), "approved\n").unwrap();
    git(&up, &["add", "-A"]);
    git(&up, &["commit", "--quiet", "-m", "approved"]);
    let approved = git(&up, &["rev-parse", "HEAD"]);
    git(&up, &["checkout", "--quiet", "-b", "side"]);
    std::fs::write(up.join("held.txt"), HELD).unwrap();
    git(&up, &["add", "-A"]);
    git(&up, &["commit", "--quiet", "-m", "held"]);
    let held = git(&up, &["rev-parse", "HEAD"]);
    git(&up, &["checkout", "--quiet", "main"]);
    let plugin = home.join("plugin");
    let owner = "c".repeat(64);
    let served = plugin.join("repos").join(&owner).join("sample.git");
    std::fs::create_dir_all(served.parent().unwrap()).unwrap();
    git(
        home,
        &[
            "init",
            "--bare",
            "--quiet",
            "-b",
            "main",
            served.to_str().unwrap(),
        ],
    );
    git(
        &served,
        &["config", "--add", "uploadpack.hideRefs", "refs/mirror"],
    );
    git(
        &served,
        &[
            "fetch",
            "--quiet",
            "--no-tags",
            up.to_str().unwrap(),
            "+refs/heads/*:refs/mirror/*",
        ],
    );
    git(&served, &["update-ref", "refs/heads/main", &approved]);
    git(&served, &["update-ref", "refs/misc/stash-held", &held]);
    // C15-hard: the held objects also sit in a `.keep` pack.
    git(&served, &["repack", "-a", "-d", "-q"]);
    for e in std::fs::read_dir(served.join("objects/pack"))
        .unwrap()
        .flatten()
    {
        if e.path().extension().is_some_and(|x| x == "pack") {
            std::fs::write(e.path().with_extension("keep"), b"b1\n").unwrap();
        }
    }
    (plugin, owner, held, approved)
}

fn get(path: String) -> ForgeRequest {
    ForgeRequest {
        method: "GET".into(),
        path,
        query: String::new(),
        headers: vec![],
        raw_body: bytes::Bytes::new(),
        host_url: None,
    }
}

async fn assert_migrated(plugin: &Path, owner: &str, held: &str, approved: &str) {
    let svc = ForgeService::new(ForgeConfig::default(), plugin).expect("forge builds");
    let h = svc
        .handle(
            get(format!("/forge/{owner}/sample/raw/{held}/held.txt")),
            ForgeAgent::Anonymous,
        )
        .await
        .expect("the forge answers");
    assert_eq!(h.status, 404, "{}", String::from_utf8_lossy(&h.body));
    let served = plugin.join("repos").join(owner).join("sample.git");
    let present = Command::new("git")
        .args(["cat-file", "-e", held])
        .current_dir(&served)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .status()
        .expect("git runs");
    assert!(!present.success(), "the held commit is in the served store");
    let a = svc
        .handle(
            get(format!("/forge/{owner}/sample/raw/{approved}/public.txt")),
            ForgeAgent::Anonymous,
        )
        .await
        .expect("the forge answers");
    assert_eq!(a.status, 200, "{}", String::from_utf8_lossy(&a.body));
    assert!(plugin
        .join("repos")
        .join(owner)
        .join("sample.git/mirror-publication-v1")
        .is_file());
}

#[test]
fn forge_migration_completes_inside_an_actix_system() {
    let tmp = tempfile::tempdir().unwrap();
    let (plugin, owner, held, approved) = legacy(tmp.path());
    actix_web::rt::System::new().block_on(assert_migrated(&plugin, &owner, &held, &approved));
}

#[actix_web::test]
async fn forge_migration_completes_inside_an_actix_web_test() {
    let tmp = tempfile::tempdir().unwrap();
    let (plugin, owner, held, approved) = legacy(tmp.path());
    assert_migrated(&plugin, &owner, &held, &approved).await;
}
