//! Pre-receive path guard (ER-22): drives `GitHttpService` with real
//! `git-receive-pack` bodies built by the local `git` binary.
//!
//! The guard under test is a toy classifier (`/.well-known/**` and any path
//! containing `secret`); the server's real classifier is tested in
//! `solid-pod-rs-server`. These tests exercise the mechanics: every commit in
//! the pushed range, rename/delete/recreate, other refs, atomicity, bounds.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use solid_pod_rs_git::push_guard::{MAX_PUSH_COMMITS, MAX_PUSH_PATHS};
use solid_pod_rs_git::{AuthError, GitAuth, GitError, GitHttpService, GitRequest};

struct AllowAll;

#[async_trait]
impl GitAuth for AllowAll {
    async fn authorise(&self, _req: &GitRequest) -> Result<String, AuthError> {
        Ok("tester".into())
    }
}

const ZERO: &str = "0000000000000000000000000000000000000000";

fn git_in(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn backend() -> PathBuf {
    let exec = git_in(Path::new("."), &["--exec-path"]);
    let p = PathBuf::from(exec).join("git-http-backend");
    assert!(p.exists(), "git-http-backend not found at {}", p.display());
    p
}

fn toy_guard(p: &str) -> bool {
    p.starts_with("/.well-known/") || p.contains("secret")
}

struct Pod {
    td: tempfile::TempDir,
    guarded: bool,
}

impl Pod {
    fn new() -> Self {
        let td = tempfile::tempdir().unwrap();
        std::fs::create_dir(td.path().join("pod")).unwrap();
        Self { td, guarded: true }
    }

    fn svc(&self, guarded: bool) -> GitHttpService {
        let s = GitHttpService::new(self.td.path().to_path_buf())
            .with_backend_path(backend())
            .with_auth(AllowAll);
        if guarded && self.guarded {
            s.with_push_guard(Arc::new(toy_guard))
        } else {
            s
        }
    }

    fn dir(&self) -> PathBuf {
        self.td.path().join("pod")
    }

    async fn push_with(
        &self,
        svc: &GitHttpService,
        body: Vec<u8>,
    ) -> Result<(u16, String), GitError> {
        let req = GitRequest {
            method: "POST".into(),
            path: "/pod/git-receive-pack".into(),
            query: String::new(),
            headers: vec![(
                "content-type".into(),
                "application/x-git-receive-pack-request".into(),
            )],
            body: Bytes::from(body),
            host_url: Some("http://localhost".into()),
        };
        let r = svc.handle(req).await?;
        Ok((r.status, String::from_utf8_lossy(&r.body).into_owned()))
    }

    async fn push(&self, body: Vec<u8>) -> Result<(u16, String), GitError> {
        self.push_with(&self.svc(true), body).await
    }

    fn rev(&self, r: &str) -> Option<String> {
        let out = Command::new("git")
            .args(["rev-parse", "-q", "--verify", r])
            .env("GIT_DIR", self.dir().join(".git"))
            .output()
            .unwrap();
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    fn assert_untouched(&self, refname: &str, forbidden: &[&str]) {
        assert_eq!(self.rev(refname), None, "{refname} must not exist");
        for f in forbidden {
            assert!(!self.dir().join(f).exists(), "{f} was checked out");
        }
        let leftovers: Vec<_> = std::fs::read_dir(self.dir().join(".git"))
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains("quarantine"))
            .collect();
        assert!(leftovers.is_empty(), "quarantine directory left behind");
    }
}

struct Client {
    td: tempfile::TempDir,
}

impl Client {
    fn new() -> Self {
        let td = tempfile::tempdir().unwrap();
        git_in(td.path(), &["init", "-q", "-b", "main"]);
        git_in(td.path(), &["config", "user.email", "t@example.com"]);
        git_in(td.path(), &["config", "user.name", "T"]);
        Self { td }
    }

    fn g(&self, args: &[&str]) -> String {
        git_in(self.td.path(), args)
    }

    fn commit(&self, files: &[(&str, &str)]) -> String {
        for (p, c) in files {
            let full = self.td.path().join(p);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, c).unwrap();
        }
        self.g(&["add", "-A"]);
        self.g(&["commit", "-qm", "c"]);
        self.g(&["rev-parse", "HEAD"])
    }

    /// A receive-pack body updating `cmds` = (old, new, ref), with a pack of
    /// everything reachable from the new ids and not from the old ones.
    fn body(&self, cmds: &[(&str, &str, &str)]) -> Vec<u8> {
        self.body_caps(cmds, "report-status")
    }

    fn body_caps(&self, cmds: &[(&str, &str, &str)], caps: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, (old, new, r)) in cmds.iter().enumerate() {
            let line = if i == 0 {
                format!("{old} {new} {r}\0 {caps}\n")
            } else {
                format!("{old} {new} {r}\n")
            };
            out.extend(format!("{:04x}{line}", line.len() + 4).into_bytes());
        }
        out.extend(b"0000");
        let mut revs = String::new();
        for (old, new, _) in cmds {
            if *new != ZERO {
                revs.push_str(&format!("{new}\n"));
            }
            if *old != ZERO {
                revs.push_str(&format!("^{old}\n"));
            }
        }
        let mut p = Command::new("git")
            .args(["pack-objects", "--stdout", "-q", "--revs", "--thin"])
            .current_dir(self.td.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        std::io::Write::write_all(&mut p.stdin.take().unwrap(), revs.as_bytes()).unwrap();
        out.extend(p.wait_with_output().unwrap().stdout);
        out
    }
}

fn refused(r: Result<(u16, String), GitError>) -> String {
    let (status, body) = r.expect("a refusal is a report-status response, not an error");
    assert_eq!(status, 200);
    assert!(body.contains("unpack ok"), "{body}");
    assert!(body.contains("push refused"), "not refused: {body}");
    assert!(body.contains("ng refs/"), "{body}");
    body
}

fn accepted(r: Result<(u16, String), GitError>) {
    let (status, body) = r.expect("push");
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("ok refs/"), "push not accepted: {body}");
}

#[tokio::test]
async fn ordinary_push_still_succeeds_and_checks_out() {
    let pod = Pod::new();
    let c = Client::new();
    let a = c.commit(&[("docs/a.txt", "hello\n")]);
    accepted(pod.push(c.body(&[(ZERO, &a, "refs/heads/main")])).await);
    assert_eq!(
        std::fs::read_to_string(pod.dir().join("docs/a.txt")).unwrap(),
        "hello\n"
    );
    // A second, thin push on top of existing history, and a non-default ref.
    let b = c.commit(&[("docs/b.txt", "b\n")]);
    accepted(pod.push(c.body(&[(&a, &b, "refs/heads/main")])).await);
    accepted(pod.push(c.body(&[(ZERO, &b, "refs/heads/feature")])).await);
    assert!(pod.dir().join("docs/b.txt").exists());
}

#[tokio::test]
async fn guarded_paths_are_refused_and_nothing_is_applied() {
    for bad in [
        ".well-known/webledgers/webledgers.json",
        ".well-known/token/x.json",
        ".well-known/gitmark/p/blocktrails.json",
        ".well-known/prov/epoch.json",
        "deep/dir/secret.txt",
    ] {
        let pod = Pod::new();
        let c = Client::new();
        let new = c.commit(&[(bad, "{}")]);
        refused(pod.push(c.body(&[(ZERO, &new, "refs/heads/main")])).await);
        pod.assert_untouched("refs/heads/main", &[bad]);
    }
}

#[tokio::test]
async fn allowed_and_forbidden_in_one_push_is_all_or_nothing() {
    let pod = Pod::new();
    let c = Client::new();
    let new = c.commit(&[("docs/ok.txt", "ok"), (".well-known/token/t.json", "{}")]);
    refused(pod.push(c.body(&[(ZERO, &new, "refs/heads/main")])).await);
    pod.assert_untouched("refs/heads/main", &["docs/ok.txt", ".well-known"]);
}

#[tokio::test]
async fn case_variant_of_a_guarded_path_is_refused() {
    let pod = Pod::new();
    let c = Client::new();
    let new = c.commit(&[(".WELL-KNOWN/Token/x.json", "{}")]);
    refused(pod.push(c.body(&[(ZERO, &new, "refs/heads/main")])).await);
    pod.assert_untouched("refs/heads/main", &[".WELL-KNOWN"]);
}

#[tokio::test]
async fn guarded_path_on_a_non_default_ref_is_refused() {
    let pod = Pod::new();
    let c = Client::new();
    let new = c.commit(&[(".well-known/token/x.json", "{}")]);
    refused(pod.push(c.body(&[(ZERO, &new, "refs/heads/other")])).await);
    pod.assert_untouched("refs/heads/other", &[".well-known"]);
    // A tag pointing at the commit is refused the same way.
    c.g(&["tag", "-a", "-m", "t", "v1"]);
    refused(
        pod.push(c.body(&[(ZERO, &c.g(&["rev-parse", "v1"]), "refs/tags/v1")]))
            .await,
    );
    pod.assert_untouched("refs/tags/v1", &[".well-known"]);
}

#[tokio::test]
async fn promoting_an_object_already_in_the_repo_is_refused() {
    // The bad commit reached the object store through another ref (here via an
    // unguarded service). A later, pack-less push moving the checked-out
    // branch onto it must still be refused: the tip tree is diffed against HEAD.
    let mut pod = Pod::new();
    let c = Client::new();
    let base = c.commit(&[("docs/a.txt", "a")]);
    accepted(pod.push(c.body(&[(ZERO, &base, "refs/heads/main")])).await);
    let bad = c.commit(&[(".well-known/token/x.json", "{}")]);
    pod.guarded = false;
    accepted(pod.push(c.body(&[(ZERO, &bad, "refs/heads/other")])).await);
    pod.guarded = true;
    assert!(!pod.dir().join(".well-known").exists());
    refused(pod.push(c.body(&[(&base, &bad, "refs/heads/main")])).await);
    assert_eq!(pod.rev("refs/heads/main").as_deref(), Some(base.as_str()));
    assert!(!pod.dir().join(".well-known").exists());
}

#[tokio::test]
async fn delete_then_recreate_inside_one_pack_is_refused() {
    let pod = Pod::new();
    let c = Client::new();
    let base = c.commit(&[("docs/a.txt", "a")]);
    accepted(pod.push(c.body(&[(ZERO, &base, "refs/heads/main")])).await);
    let c1 = c.commit(&[(".well-known/token/x.json", "{}")]);
    std::fs::remove_dir_all(c.td.path().join(".well-known")).unwrap();
    let c2 = c.commit(&[("docs/b.txt", "b")]);
    assert_ne!(c1, c2);
    // The tip tree is clean; the intermediate commit is not.
    refused(pod.push(c.body(&[(&base, &c2, "refs/heads/main")])).await);
    assert_eq!(pod.rev("refs/heads/main").as_deref(), Some(base.as_str()));
    assert!(!pod.dir().join("docs/b.txt").exists());
}

#[tokio::test]
async fn promoting_onto_an_unborn_head_is_refused() {
    // HEAD is unborn; the bad content sits in the parent of the pushed tip, so
    // only a diff of the whole tip tree against the empty tree sees it.
    let mut pod = Pod::new();
    let c = Client::new();
    c.commit(&[(".well-known/token/x.json", "{}")]);
    let tip = c.commit(&[("docs/a.txt", "a")]);
    pod.guarded = false;
    accepted(pod.push(c.body(&[(ZERO, &tip, "refs/heads/other")])).await);
    pod.guarded = true;
    refused(pod.push(c.body(&[(ZERO, &tip, "refs/heads/main")])).await);
    pod.assert_untouched("refs/heads/main", &[".well-known", "docs/a.txt"]);
}

#[tokio::test]
async fn rename_into_a_guarded_path_is_refused() {
    let pod = Pod::new();
    let c = Client::new();
    let base = c.commit(&[(
        "docs/a.txt",
        "a content that git can match as a rename\n"
            .repeat(20)
            .as_str(),
    )]);
    accepted(pod.push(c.body(&[(ZERO, &base, "refs/heads/main")])).await);
    std::fs::create_dir_all(c.td.path().join(".well-known/token")).unwrap();
    c.g(&["mv", "docs/a.txt", ".well-known/token/a.json"]);
    c.g(&["commit", "-qm", "mv"]);
    let new = c.g(&["rev-parse", "HEAD"]);
    refused(pod.push(c.body(&[(&base, &new, "refs/heads/main")])).await);
    assert_eq!(pod.rev("refs/heads/main").as_deref(), Some(base.as_str()));
    assert!(pod.dir().join("docs/a.txt").exists());
    assert!(!pod.dir().join(".well-known").exists());
}

#[tokio::test]
async fn deleting_a_guarded_path_is_refused() {
    let mut pod = Pod::new();
    let c = Client::new();
    let base = c.commit(&[(".well-known/token/x.json", "{}"), ("docs/a.txt", "a")]);
    pod.guarded = false;
    accepted(pod.push(c.body(&[(ZERO, &base, "refs/heads/main")])).await);
    pod.guarded = true;
    c.g(&["rm", "-q", ".well-known/token/x.json"]);
    c.g(&["commit", "-qm", "rm"]);
    let new = c.g(&["rev-parse", "HEAD"]);
    refused(pod.push(c.body(&[(&base, &new, "refs/heads/main")])).await);
    assert!(pod.dir().join(".well-known/token/x.json").exists());
}

#[tokio::test]
async fn symlinks_and_submodules_are_refused() {
    let pod = Pod::new();
    let c = Client::new();
    std::os::unix::fs::symlink("../elsewhere", c.td.path().join("link")).unwrap();
    let new = c.commit(&[("docs/a.txt", "a")]);
    refused(pod.push(c.body(&[(ZERO, &new, "refs/heads/main")])).await);
    pod.assert_untouched("refs/heads/main", &["link", "docs/a.txt"]);

    let c = Client::new();
    c.commit(&[("x", "x")]);
    let sha = c.g(&["rev-parse", "HEAD"]);
    c.g(&[
        "update-index",
        "--add",
        "--cacheinfo",
        &format!("160000,{sha},sub"),
    ]);
    c.g(&["commit", "-qm", "sub"]);
    let new = c.g(&["rev-parse", "HEAD"]);
    refused(pod.push(c.body(&[(ZERO, &new, "refs/heads/main")])).await);
    pod.assert_untouched("refs/heads/main", &["sub", "x"]);
}

#[tokio::test]
async fn refusal_is_side_band_framed_when_the_client_asked_for_it() {
    let pod = Pod::new();
    let c = Client::new();
    let new = c.commit(&[(".well-known/token/x.json", "{}")]);
    let body = c.body_caps(
        &[(ZERO, &new, "refs/heads/main")],
        "report-status side-band-64k",
    );
    let req = GitRequest {
        method: "POST".into(),
        path: "/pod/git-receive-pack".into(),
        query: String::new(),
        headers: vec![],
        body: Bytes::from(body),
        host_url: None,
    };
    let r = pod.svc(true).handle(req).await.unwrap();
    assert_eq!(r.status, 200);
    let b = String::from_utf8_lossy(&r.body).into_owned();
    // pkt-line length, then band 1, then the inner report.
    assert_eq!(&b[4..5], "\u{1}", "{b:?}");
    assert!(b.contains("unpack ok") && b.contains("ng refs/heads/main push refused"));
    assert!(b.ends_with("0000"));
}

#[tokio::test]
async fn without_report_status_the_refusal_is_a_403() {
    let pod = Pod::new();
    let c = Client::new();
    let new = c.commit(&[(".well-known/token/x.json", "{}")]);
    let body = c.body_caps(&[(ZERO, &new, "refs/heads/main")], "agent=x");
    let err = pod.push(body).await.unwrap_err();
    assert_eq!(err.status_code(), 403);
    assert!(matches!(err, GitError::PushRefused(_)));
}

#[tokio::test]
async fn malformed_and_empty_requests_are_refused_not_hung() {
    let pod = Pod::new();
    // Truncated pkt-line.
    let err = pod.push(b"00ffshort".to_vec()).await.unwrap_err();
    assert_eq!(err.status_code(), 403);
    // Garbage where a pack should be.
    let c = Client::new();
    let new = c.commit(&[("docs/a.txt", "a")]);
    let mut body = c.body(&[(ZERO, &new, "refs/heads/main")]);
    let at = body.windows(4).position(|w| w == b"PACK").unwrap();
    body.truncate(at + 12);
    body.extend(b"garbage-garbage");
    refused(pod.push(body).await);
    pod.assert_untouched("refs/heads/main", &["docs/a.txt"]);
}

#[tokio::test]
async fn flush_only_and_delete_only_pushes_are_not_blocked() {
    let pod = Pod::new();
    // A client with nothing to push sends just a flush; the guard has nothing
    // to inspect and the request reaches the CGI.
    let r = pod.push(b"0000".to_vec()).await;
    assert!(!matches!(r, Err(GitError::PushRefused(_))), "{r:?}");
    let c = Client::new();
    let a = c.commit(&[("docs/a.txt", "a")]);
    accepted(pod.push(c.body(&[(ZERO, &a, "refs/heads/feature")])).await);
    let r = pod.push(c.body(&[(&a, ZERO, "refs/heads/feature")])).await;
    let (status, body) = r.unwrap();
    assert_eq!(status, 200, "{body}");
    assert!(!body.contains("push refused"), "{body}");
}

/// Build a repo with `n` commits via fast-import (cheap) and return the tip.
fn many_commits(c: &Client, n: usize) -> String {
    let mut s = String::new();
    for i in 0..n {
        s.push_str(&format!(
            "commit refs/heads/main\ncommitter T <t@e.com> {} +0000\ndata 1\nm\nM 100644 inline f\ndata {}\n{i}\n",
            1_700_000_000 + i,
            i.to_string().len() + 1
        ));
    }
    let mut p = Command::new("git")
        .args(["fast-import", "--quiet"])
        .current_dir(c.td.path())
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(&mut p.stdin.take().unwrap(), s.as_bytes()).unwrap();
    assert!(p.wait().unwrap().success());
    c.g(&["rev-parse", "refs/heads/main"])
}

#[tokio::test]
async fn too_many_commits_is_refused_within_the_bound() {
    let pod = Pod::new();
    let c = Client::new();
    let tip = many_commits(&c, MAX_PUSH_COMMITS + 1);
    let started = std::time::Instant::now();
    let body = refused(pod.push(c.body(&[(ZERO, &tip, "refs/heads/main")])).await);
    assert!(body.contains("too many commits"), "{body}");
    assert!(started.elapsed().as_secs() < 55);
    pod.assert_untouched("refs/heads/main", &["f"]);
}

#[tokio::test]
async fn too_many_changed_paths_is_refused() {
    let pod = Pod::new();
    let c = Client::new();
    let mut s =
        String::from("commit refs/heads/main\ncommitter T <t@e.com> 1700000000 +0000\ndata 1\nm\n");
    for i in 0..=MAX_PUSH_PATHS {
        s.push_str(&format!("M 100644 inline d/f{i}\ndata 1\nx\n"));
    }
    let mut p = Command::new("git")
        .args(["fast-import", "--quiet"])
        .current_dir(c.td.path())
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(&mut p.stdin.take().unwrap(), s.as_bytes()).unwrap();
    assert!(p.wait().unwrap().success());
    let tip = c.g(&["rev-parse", "refs/heads/main"]);
    let body = refused(pod.push(c.body(&[(ZERO, &tip, "refs/heads/main")])).await);
    assert!(body.contains("too many paths"), "{body}");
    pod.assert_untouched("refs/heads/main", &["d"]);
}
