//! Hidden-ref policy through the real HTTP CGI, using synthetic local objects.
#![cfg(feature = "with-git-binary")]

use std::{io::Write, path::Path, process::Stdio};

use bytes::Bytes;
use solid_pod_rs_git::{hardened_git, GitError, GitHttpService, GitRequest};

fn git(repo: &Path, args: &[&str]) -> String {
    let output = hardened_git()
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn request(method: &str, endpoint: &str, query: &str, body: String) -> GitRequest {
    GitRequest {
        method: method.into(),
        path: format!("/repo/{endpoint}"),
        query: query.into(),
        headers: vec![(
            "content-type".into(),
            "application/x-git-upload-pack-request".into(),
        )],
        body: Bytes::from(body),
        host_url: None,
    }
}

fn want(sha: &str) -> String {
    let line = format!("want {sha}\n");
    format!("{:04x}{line}00000009done\n", line.len() + 4)
}

async fn check_hidden_tip(permissive_repository: bool) {
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    git(&repo, &["config", "user.name", "Audit Fixture"]);
    git(&repo, &["config", "user.email", "audit@example.invalid"]);
    std::fs::write(repo.join("public.txt"), "synthetic-public\n").unwrap();
    git(&repo, &["add", "public.txt"]);
    git(&repo, &["commit", "-qm", "public"]);
    let public = git(&repo, &["rev-parse", "HEAD"]);
    std::fs::write(repo.join("held.txt"), "synthetic-held-back\n").unwrap();
    git(&repo, &["add", "held.txt"]);
    git(&repo, &["commit", "-qm", "held"]);
    let held = git(&repo, &["rev-parse", "HEAD"]);
    git(&repo, &["update-ref", "refs/mirror/held", &held]);
    git(&repo, &["reset", "-q", "--hard", &public]);
    for key in ["uploadpack.hideRefs", "transfer.hideRefs"] {
        git(&repo, &["config", key, "refs/mirror"]);
    }
    if permissive_repository {
        for key in [
            "uploadpack.allowTipSHA1InWant",
            "uploadpack.allowReachableSHA1InWant",
            "uploadpack.allowAnySHA1InWant",
        ] {
            git(&repo, &["config", key, "true"]);
        }
    }
    let service = GitHttpService::new(root.path().to_path_buf());
    // Explicit feature selection requires a working backend: never silently skip.
    let advertisement = service
        .handle(request(
            "GET",
            "info/refs",
            "service=git-upload-pack",
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(advertisement.status, 200);
    let refs = String::from_utf8_lossy(&advertisement.body);
    assert!(refs.contains(&public));
    assert!(!refs.contains(&held));

    // Positive control: a normal advertised tip still produces usable objects.
    let response = service
        .handle(request("POST", "git-upload-pack", "", want(&public)))
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    assert!(response.body.starts_with(b"0008NAK\nPACK"));
    let receiver = tempfile::tempdir().unwrap();
    git(receiver.path(), &["init", "-q"]);
    let mut child = hardened_git()
        .arg("-C")
        .arg(receiver.path())
        .args(["index-pack", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&response.body[8..])
        .unwrap();
    let decoded = child.wait_with_output().unwrap();
    assert!(
        decoded.status.success(),
        "{}",
        String::from_utf8_lossy(&decoded.stderr)
    );
    assert_eq!(
        git(receiver.path(), &["show", &format!("{public}:public.txt")]),
        "synthetic-public"
    );

    let hidden = service
        .handle(request("POST", "git-upload-pack", "", want(&held)))
        .await;
    match hidden {
        Ok(response) => {
            assert!(
                !response.body.windows(4).any(|bytes| bytes == b"PACK"),
                "hidden tip produced a pack"
            );
            assert!(
                String::from_utf8_lossy(&response.body).contains("not our ref"),
                "unexpected rejection: {response:?}"
            );
        }
        Err(GitError::BackendFailed { stderr, .. }) => assert!(
            stderr.contains("not our ref"),
            "unexpected backend failure: {stderr}"
        ),
        Err(error) => panic!("fixture failed before hidden-ref policy: {error}"),
    }
}

#[tokio::test]
async fn hidden_tip_is_not_fetchable_by_known_hash() {
    check_hidden_tip(false).await;
}

#[tokio::test]
async fn repository_config_cannot_enable_hidden_tip_fetch() {
    check_hidden_tip(true).await;
}
