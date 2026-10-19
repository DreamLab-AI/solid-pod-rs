//! Web-edit (`POST api/repos/<o>/<n>/edit`) and ephemeral preview
//! (`POST .../preview`) on real bare repositories.
//!
//! Transcribes the JSS forge suites `web-edit` (forge/test.js 2455-2552),
//! `openEdit demo` (2875-2905) and the preview/edit-to-30618 cases (~2760-2810),
//! and adds negative tests for the write path: option injection through path,
//! branch and message, symlink and `.git` components, NUL, backslash,
//! absolute paths, `..`, ASCII case-folding of `.git`, a stale-tip
//! compare-and-swap, lost-update races and the exact `openEdit` authorisation.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use serde_json::{json, Value};
use solid_pod_rs_forge::merge::TipRecorder;
use solid_pod_rs_forge::{ForgeAgent, ForgeConfig, ForgeRequest, ForgeResponse, ForgeService};
use tempfile::TempDir;

const HOST: &str = "https://pod.example";
const EDIT: &str = "/forge/api/repos/casey/editme/edit";

fn git_ok() -> bool {
    std::process::Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn git(cwd: &Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .args([
            "-c",
            "user.name=Seed",
            "-c",
            "user.email=s@e.st",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "protocol.file.allow=always",
        ])
        .args(args)
        .current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn pod(user: &str) -> ForgeAgent {
    ForgeAgent::Pod {
        webid: format!("{HOST}/{user}/profile/card#me"),
        username: user.to_string(),
    }
}

fn post(path: &str, body: &Value) -> ForgeRequest {
    ForgeRequest {
        method: "POST".into(),
        path: path.into(),
        query: String::new(),
        headers: vec![("content-type".into(), "application/json".into())],
        raw_body: Bytes::from(body.to_string()),
        host_url: Some(HOST.into()),
    }
}

fn raw_post(path: &str, body: &[u8]) -> ForgeRequest {
    ForgeRequest {
        raw_body: Bytes::copy_from_slice(body),
        ..post(path, &json!({}))
    }
}

fn header<'a>(r: &'a ForgeResponse, name: &str) -> Option<&'a str> {
    r.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn json_of(r: &ForgeResponse) -> Value {
    serde_json::from_slice(&r.body).unwrap_or(Value::Null)
}

#[derive(Default)]
struct CountTips(Mutex<Vec<String>>);

#[async_trait]
impl TipRecorder for CountTips {
    async fn record_tip(&self, owner: &str, repo: &str) {
        self.0.lock().unwrap().push(format!("{owner}/{repo}"));
    }
}

struct Fx {
    td: TempDir,
    svc: ForgeService,
}

impl Fx {
    fn with(cfg: ForgeConfig) -> Self {
        let td = TempDir::new().unwrap();
        let svc = ForgeService::new(cfg, td.path().join("plugin")).unwrap();
        let fx = Self { td, svc };
        fx.seed("casey", "editme");
        fx
    }

    fn new() -> Self {
        Self::with(ForgeConfig::default())
    }

    fn repo(&self, owner: &str, name: &str) -> PathBuf {
        self.td
            .path()
            .join("plugin/repos")
            .join(owner)
            .join(format!("{name}.git"))
    }

    /// `index.html`, a `docs/` directory, a symlink `link -> index.html`, a
    /// symlink `ldir -> docs` and an executable `run.sh`.
    fn seed(&self, owner: &str, name: &str) {
        let work = self.td.path().join(format!("seed-{owner}-{name}"));
        std::fs::create_dir_all(work.join("docs")).unwrap();
        git(&work, &["init", "-q", "-b", "main"]);
        std::fs::write(work.join("index.html"), "<h1>original</h1>\n").unwrap();
        std::fs::write(work.join("docs/a.md"), "a\n").unwrap();
        std::fs::write(work.join("run.sh"), "#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};
            symlink("index.html", work.join("link")).unwrap();
            symlink("docs", work.join("ldir")).unwrap();
            std::fs::set_permissions(work.join("run.sh"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        git(&work, &["add", "-A"]);
        git(&work, &["commit", "-q", "-m", "seed"]);
        let bare = self.repo(owner, name);
        std::fs::create_dir_all(bare.parent().unwrap()).unwrap();
        git(
            self.td.path(),
            &[
                "clone",
                "-q",
                "--bare",
                work.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
        );
    }

    fn head(&self, branch: &str) -> String {
        git(
            &self.repo("casey", "editme"),
            &["rev-parse", &format!("refs/heads/{branch}")],
        )
    }

    fn show(&self, rev_path: &str) -> String {
        let out = std::process::Command::new("git")
            .args(["show", rev_path])
            .current_dir(self.repo("casey", "editme"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(out.status.success(), "git show {rev_path}");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    async fn edit_as(&self, agent: &ForgeAgent, body: Value) -> ForgeResponse {
        self.svc
            .handle(post(EDIT, &body), agent.clone())
            .await
            .unwrap()
    }

    async fn edit(&self, body: Value) -> ForgeResponse {
        self.edit_as(&pod("casey"), body).await
    }
}

macro_rules! need_git {
    () => {
        if !git_ok() {
            return;
        }
    };
}

// ---- JSS 2455 "owner edits index.html -> 200 changed:true ..." -----------

#[tokio::test]
async fn owner_edit_commits_and_is_cors_readable() {
    need_git!();
    let fx = Fx::new();
    let before = fx.head("main");
    let r = fx
        .edit(json!({"path": "index.html", "content": "<h1>edited via web</h1>\n", "message": "web tweak"}))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(header(&r, "access-control-allow-origin"), Some("*"));
    let j = json_of(&r);
    assert_eq!(j["ok"], true);
    assert_eq!(j["changed"], true);
    let commit = j["commit"].as_str().unwrap();
    assert_eq!(commit.len(), 40);
    assert!(commit.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(j["url"], "/forge/casey/editme");
    assert_ne!(commit, before);
    assert_eq!(fx.head("main"), commit, "main advanced to the commit");
    assert_eq!(fx.show("main:index.html"), "<h1>edited via web</h1>\n");
    // the new commit is a child of the old tip and the other files survive
    assert_eq!(
        git(&fx.repo("casey", "editme"), &["rev-parse", "main^"]),
        before
    );
    assert_eq!(fx.show("main:docs/a.md"), "a\n");
    // authorship: the caller is the author, the forge is the committer
    let log = git(
        &fx.repo("casey", "editme"),
        &["log", "-1", "--format=%an|%ae|%cn|%ce|%s", "main"],
    );
    assert_eq!(
        log,
        "casey|casey@forge.invalid|forge web edit|forge@forge.invalid|web tweak"
    );
    // the working-tree-less bare repo is still sound
    git(&fx.repo("casey", "editme"), &["fsck", "--strict"]);
    // no scratch files are left behind
    let tmp = fx.svc.plugin_dir().join("web-edit-tmp");
    assert_eq!(std::fs::read_dir(tmp).unwrap().count(), 0);
}

// ---- JSS 2478 "editing to the SAME content makes no commit" -------------

#[tokio::test]
async fn same_content_makes_no_commit() {
    need_git!();
    let fx = Fx::new();
    let before = fx.head("main");
    let r = fx
        .edit(json!({"path": "index.html", "content": "<h1>original</h1>\n"}))
        .await;
    assert_eq!(r.status, 200);
    let j = json_of(&r);
    assert_eq!(j["changed"], false);
    assert_eq!(j["commit"], before.as_str());
    assert_eq!(fx.head("main"), before);
}

// ---- JSS 2492 "a subdir path creates the file with parent dirs made" ----

#[tokio::test]
async fn subdir_path_creates_parents() {
    need_git!();
    let fx = Fx::new();
    let r = fx
        .edit(json!({"path": "deep/er/guide.md", "content": "# Guide\n\nhello\n"}))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(json_of(&r)["changed"], true);
    assert_eq!(fx.show("main:deep/er/guide.md"), "# Guide\n\nhello\n");
}

// ---- JSS 2504 "path traversal and unsafe paths are 400" + more ----------

#[tokio::test]
async fn unsafe_paths_are_400_and_change_nothing() {
    need_git!();
    let fx = Fx::new();
    let before = fx.head("main");
    let long = format!("{}/x", "a".repeat(1100));
    let bad = [
        "../x",
        "/etc/x",
        "a/../../b",
        ".git/x",
        "a\\b",
        ".acl",
        "",
        // beyond the JSS list: case-folded .git, NUL, NTFS aliases, control
        "a/.GIT/x",
        "a/.Git/x",
        "A/.gIt",
        "a/.git./x",
        "a/git~1/x",
        "a\u{0}b",
        "a\nb",
        "a/./b",
        "a//b",
        "docs/",
        "--upload-pack=touch /tmp/pwn",
        "a;b",
        "a b",
        "$(id)",
        long.as_str(),
    ];
    for p in bad {
        let r = fx.edit(json!({"path": p, "content": "x"})).await;
        assert_eq!(r.status, 400, "path {p:?} must be 400");
        assert_eq!(header(&r, "access-control-allow-origin"), Some("*"));
    }
    assert_eq!(fx.head("main"), before);
    // a path that is not a string, and a missing path
    for body in [
        json!({"path": 7, "content": "x"}),
        json!({"path": null, "content": "x"}),
        json!({"content": "x"}),
    ] {
        assert_eq!(fx.edit(body).await.status, 400);
    }
}

// ---- JSS 2516 "oversized content is rejected" ---------------------------

#[tokio::test]
async fn oversized_content_is_413_and_the_cap_is_inclusive() {
    need_git!();
    let fx = Fx::new();
    let big = fx
        .edit(json!({"path": "big.txt", "content": "a".repeat(1024 * 1024 + 1)}))
        .await;
    assert_eq!(big.status, 413);
    assert_eq!(header(&big, "access-control-allow-origin"), Some("*"));
    let exact = fx
        .edit(json!({"path": "big.txt", "content": "a".repeat(1024 * 1024)}))
        .await;
    assert_eq!(exact.status, 200, "exactly 1 MiB is allowed");
    assert_eq!(fx.show("main:big.txt").len(), 1024 * 1024);
    // a multi-byte character counts as its UTF-8 bytes
    let wide = fx
        .edit(json!({"path": "wide.txt", "content": "\u{e9}".repeat(540_000)}))
        .await;
    assert_eq!(wide.status, 413);
    // a body beyond cap + 128 KiB of framing is refused outright
    let r = fx
        .svc
        .handle(
            raw_post(EDIT, &vec![b' '; 1024 * 1024 + 128 * 1024 + 1]),
            pod("casey"),
        )
        .await
        .unwrap();
    assert_eq!(r.status, 400);
}

// ---- JSS 2525 anonymous 401, non-owner 403 (openEdit unset) -------------

#[tokio::test]
async fn anonymous_is_401_and_a_non_owner_is_403() {
    need_git!();
    let fx = Fx::new();
    let before = fx.head("main");
    let anon = fx
        .edit_as(
            &ForgeAgent::Anonymous,
            json!({"path": "index.html", "content": "nope\n"}),
        )
        .await;
    assert_eq!(anon.status, 401);
    assert_eq!(
        header(&anon, "access-control-allow-origin"),
        Some("*"),
        "even the 401 is CORS-readable"
    );
    assert!(header(&anon, "www-authenticate")
        .unwrap()
        .starts_with("Bearer"));
    let other = fx
        .edit_as(
            &pod("rival"),
            json!({"path": "index.html", "content": "nope\n"}),
        )
        .await;
    assert_eq!(other.status, 403);
    assert_eq!(header(&other, "access-control-allow-origin"), Some("*"));
    // a podless nostr agent whose key is not the namespace is a non-owner too
    let nostr = ForgeAgent::Nostr {
        pubkey_hex: "ab".repeat(32),
    };
    assert_eq!(
        fx.edit_as(&nostr, json!({"path": "index.html", "content": "nope\n"}))
            .await
            .status,
        403
    );
    // auth is checked before the body: a bad path from an anonymous caller is 401
    let r = fx
        .edit_as(
            &ForgeAgent::Anonymous,
            json!({"path": "../x", "content": "x"}),
        )
        .await;
    assert_eq!(r.status, 401);
    assert_eq!(fx.head("main"), before);
}

// ---- JSS 2541 "OPTIONS preflight is answered with the CORS grant" -------

#[tokio::test]
async fn options_preflight_is_answered_with_the_cors_grant() {
    let fx = Fx::new();
    for path in [EDIT, "/forge/api/repos/casey/editme/preview"] {
        let mut req = post(path, &json!({}));
        req.method = "OPTIONS".into();
        req.headers = vec![
            ("origin".into(), "https://demo.example".into()),
            ("access-control-request-method".into(), "POST".into()),
        ];
        let r = fx.svc.handle(req, ForgeAgent::Anonymous).await.unwrap();
        assert!([200, 204].contains(&r.status), "{}", r.status);
        assert_eq!(header(&r, "access-control-allow-origin"), Some("*"));
        assert!(header(&r, "access-control-allow-methods")
            .unwrap()
            .contains("POST"));
        assert!(header(&r, "access-control-allow-headers")
            .unwrap()
            .to_ascii_lowercase()
            .contains("authorization"));
    }
}

// ---- JSS 2875/2889 openEdit demo ----------------------------------------

#[tokio::test]
async fn open_edit_lets_an_anonymous_edit_through_but_paths_are_still_checked() {
    need_git!();
    let fx = Fx::with(ForgeConfig {
        open_edit: true,
        ..Default::default()
    });
    let before = fx.head("main");
    let r = fx
        .edit_as(
            &ForgeAgent::Anonymous,
            json!({"path": "index.html", "content": "<h1>edited anonymously</h1>\n"}),
        )
        .await;
    assert_eq!(r.status, 200);
    let j = json_of(&r);
    assert_eq!(j["changed"], true);
    assert_eq!(fx.show("main:index.html"), "<h1>edited anonymously</h1>\n");
    let who = git(
        &fx.repo("casey", "editme"),
        &["log", "-1", "--format=%an|%ae", "main"],
    );
    assert_eq!(who, "anonymous|anonymous@forge.invalid");
    assert_ne!(j["commit"], before.as_str());
    for p in ["../escape", ".git/config", "a/.GIT/x", "/abs"] {
        let r = fx
            .edit_as(&ForgeAgent::Anonymous, json!({"path": p, "content": "x"}))
            .await;
        assert_eq!(r.status, 400, "{p}");
    }
    // JSS has no "demo namespace": a signed non-owner is let in as well, and
    // is the author of record.
    let r = fx
        .edit_as(&pod("rival"), json!({"path": "r.txt", "content": "r\n"}))
        .await;
    assert_eq!(r.status, 200);
    let who = git(
        &fx.repo("casey", "editme"),
        &["log", "-1", "--format=%an", "main"],
    );
    assert_eq!(who, "rival");
    // an unknown repository is still 404
    let r = fx
        .svc
        .handle(
            post(
                "/forge/api/repos/casey/ghost/edit",
                &json!({"path": "a", "content": "x"}),
            ),
            ForgeAgent::Anonymous,
        )
        .await
        .unwrap();
    assert_eq!(r.status, 404);
}

// ---- negative tests for the write path ----------------------------------

#[tokio::test]
async fn option_injection_through_branch_path_and_message_is_inert() {
    need_git!();
    let fx = Fx::new();
    let before = fx.head("main");
    for b in [
        "--upload-pack=touch /tmp/pwn",
        "-x",
        "--orphan",
        "a..b",
        "x.lock",
        "a/.b",
        "a b",
        "main/x",
        "HEAD",
        "a/",
        "",
        "a@{1}",
        "a~1",
        "a^",
        "a:b",
        "a*",
        "a?",
        "a[",
        "a\\b",
        "a\u{0}b",
    ] {
        let r = fx
            .edit(json!({"path": "i.txt", "content": "x", "branch": b}))
            .await;
        assert_eq!(r.status, 400, "branch {b:?} must be 400, got {}", r.status);
    }
    for b in [json!(5), json!(null), json!(["main"]), json!({"a": 1})] {
        let r = fx
            .edit(json!({"path": "i.txt", "content": "x", "branch": b}))
            .await;
        assert_eq!(r.status, 400);
    }
    assert_eq!(fx.head("main"), before);
    assert!(
        git(
            &fx.repo("casey", "editme"),
            &["for-each-ref", "--format=%(refname)"]
        )
        .lines()
        .all(|l| l == "refs/heads/main"),
        "no stray ref was created"
    );
    // "-n" and "--help" style segments are plain file names, never options
    let r = fx.edit(json!({"path": "-n", "content": "dash\n"})).await;
    assert_eq!(r.status, 200);
    let r = fx
        .edit(json!({"path": "docs/--help", "content": "h\n"}))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(fx.show("main:-n"), "dash\n");
    assert_eq!(fx.show("main:docs/--help"), "h\n");
    // a message that looks like an option is just the message
    let r = fx
        .edit(json!({"path": "m.txt", "content": "m\n", "message": "--amend -m x\n\u{0}\t-F /etc/passwd"}))
        .await;
    assert_eq!(r.status, 200);
    let subj = git(
        &fx.repo("casey", "editme"),
        &["log", "-1", "--format=%s", "main"],
    );
    assert_eq!(subj, "--amend -m x -F /etc/passwd");
}

#[tokio::test]
async fn symlink_directory_and_file_conflicts_are_refused() {
    need_git!();
    if !cfg!(unix) {
        return;
    }
    let fx = Fx::new();
    let before = fx.head("main");
    // leaf is a symlink: never written through
    assert_eq!(
        fx.edit(json!({"path": "link", "content": "pwn\n"}))
            .await
            .status,
        409
    );
    // a symlink on the way
    assert_eq!(
        fx.edit(json!({"path": "ldir/x.txt", "content": "pwn\n"}))
            .await
            .status,
        409
    );
    assert_eq!(
        fx.edit(json!({"path": "ldir/a.md", "content": "pwn\n"}))
            .await
            .status,
        409
    );
    // a file on the way, and a directory as the leaf
    assert_eq!(
        fx.edit(json!({"path": "index.html/x", "content": "x"}))
            .await
            .status,
        409
    );
    assert_eq!(
        fx.edit(json!({"path": "docs", "content": "x"}))
            .await
            .status,
        409
    );
    assert_eq!(fx.head("main"), before);
    assert_eq!(fx.show("main:index.html"), "<h1>original</h1>\n");
    assert_eq!(fx.show("main:docs/a.md"), "a\n");
    // the conflict reply never leaks a path of the host
    let r = fx.edit(json!({"path": "link", "content": "x"})).await;
    let text = String::from_utf8_lossy(&r.body).into_owned();
    assert!(!text.contains("/plugin"), "{text}");
}

#[tokio::test]
async fn an_executable_keeps_its_mode() {
    need_git!();
    if !cfg!(unix) {
        return;
    }
    let fx = Fx::new();
    let r = fx
        .edit(json!({"path": "run.sh", "content": "#!/bin/sh\necho hi\n"}))
        .await;
    assert_eq!(r.status, 200);
    let ls = git(&fx.repo("casey", "editme"), &["ls-tree", "main", "run.sh"]);
    assert!(ls.starts_with("100755 blob"), "{ls}");
    let ls = git(&fx.repo("casey", "editme"), &["ls-tree", "main", "new.txt"]);
    assert!(ls.is_empty());
    fx.edit(json!({"path": "new.txt", "content": "n\n"})).await;
    let ls = git(&fx.repo("casey", "editme"), &["ls-tree", "main", "new.txt"]);
    assert!(ls.starts_with("100644 blob"), "{ls}");
}

#[tokio::test]
async fn content_is_stored_verbatim_without_filters() {
    need_git!();
    let fx = Fx::new();
    let body = "line1\r\nline2\r\n\u{0}tail \u{e9}\u{1f600}";
    let r = fx.edit(json!({"path": "raw.bin", "content": body})).await;
    assert_eq!(r.status, 200);
    assert_eq!(fx.show("main:raw.bin"), body);
}

#[tokio::test]
async fn a_new_branch_starts_from_the_default_branch_and_main_is_untouched() {
    need_git!();
    let fx = Fx::new();
    let main_before = fx.head("main");
    let r = fx
        .edit(json!({"path": "f.txt", "content": "f\n", "branch": "feature/web"}))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(fx.head("main"), main_before);
    assert_eq!(
        git(
            &fx.repo("casey", "editme"),
            &["rev-parse", "refs/heads/feature/web^"]
        ),
        main_before
    );
    assert_eq!(fx.show("feature/web:f.txt"), "f\n");
    // editing the existing branch again lands on its own tip
    let r = fx
        .edit(json!({"path": "g.txt", "content": "g\n", "branch": "feature/web"}))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(fx.show("feature/web:f.txt"), "f\n");
    assert_eq!(fx.show("feature/web:g.txt"), "g\n");
    // a same-content edit on a branch that does not exist makes no branch
    let r = fx
        .edit(json!({"path": "index.html", "content": "<h1>original</h1>\n", "branch": "ghost"}))
        .await;
    assert_eq!(json_of(&r)["changed"], false);
    assert!(!git(&fx.repo("casey", "editme"), &["branch", "--list", "ghost"]).contains("ghost"));
}

#[tokio::test]
async fn an_empty_repository_gets_a_root_commit() {
    need_git!();
    let fx = Fx::new();
    let empty = fx.repo("casey", "fresh");
    std::fs::create_dir_all(empty.parent().unwrap()).unwrap();
    git(
        fx.td.path(),
        &[
            "init",
            "-q",
            "--bare",
            "-b",
            "main",
            empty.to_str().unwrap(),
        ],
    );
    let r = fx
        .svc
        .handle(
            post(
                "/forge/api/repos/casey/fresh/edit",
                &json!({"path": "README.md", "content": "# hi\n"}),
            ),
            pod("casey"),
        )
        .await
        .unwrap();
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(git(&empty, &["rev-list", "--count", "main"]), "1");
    assert_eq!(git(&empty, &["show", "main:README.md"]), "# hi");
}

#[tokio::test]
async fn parallel_edits_lose_no_commit() {
    need_git!();
    let fx = Arc::new(Fx::new());
    let before_count: usize = git(
        &fx.repo("casey", "editme"),
        &["rev-list", "--count", "main"],
    )
    .parse()
    .unwrap();
    let mut tasks = Vec::new();
    for i in 0..12 {
        let fx = Arc::clone(&fx);
        tasks.push(tokio::spawn(async move {
            fx.edit(json!({"path": format!("p/f{i}.txt"), "content": format!("{i}\n")}))
                .await
                .status
        }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap(), 200);
    }
    let count: usize = git(
        &fx.repo("casey", "editme"),
        &["rev-list", "--count", "main"],
    )
    .parse()
    .unwrap();
    assert_eq!(count, before_count + 12, "every edit is its own commit");
    for i in 0..12 {
        assert_eq!(fx.show(&format!("main:p/f{i}.txt")), format!("{i}\n"));
    }
}

#[tokio::test]
async fn bad_requests_and_methods() {
    need_git!();
    let fx = Fx::new();
    let agent = pod("casey");
    // not JSON, JSON but not an object, empty body
    for body in [&b"not json"[..], b"[1,2]", b"\"s\"", b"null", b""] {
        let r = fx
            .svc
            .handle(raw_post(EDIT, body), agent.clone())
            .await
            .unwrap();
        assert_eq!(r.status, 400, "{body:?}");
        assert_eq!(header(&r, "access-control-allow-origin"), Some("*"));
    }
    // content must be a string
    for c in [json!(1), json!(null), json!(["x"])] {
        assert_eq!(
            fx.edit(json!({"path": "a.txt", "content": c})).await.status,
            400
        );
    }
    assert_eq!(fx.edit(json!({"path": "a.txt"})).await.status, 400);
    // GET is a 405, an unknown repository a 404 (both from the owner)
    let mut get = post(EDIT, &json!({}));
    get.method = "GET".into();
    assert_eq!(fx.svc.handle(get, agent.clone()).await.unwrap().status, 405);
    let r = fx
        .svc
        .handle(
            post(
                "/forge/api/repos/casey/ghost/edit",
                &json!({"path": "a", "content": "x"}),
            ),
            agent.clone(),
        )
        .await
        .unwrap();
    assert_eq!(r.status, 404);
    assert_eq!(header(&r, "access-control-allow-origin"), Some("*"));
    // trailing segments are not the edit endpoint
    let r = fx
        .svc
        .handle(
            post(&format!("{EDIT}/x"), &json!({"path": "a", "content": "x"})),
            agent,
        )
        .await
        .unwrap();
    assert_eq!(r.status, 404);
}

#[tokio::test]
async fn a_changed_edit_calls_the_tip_hook_and_a_noop_does_not() {
    need_git!();
    let td = TempDir::new().unwrap();
    let tips = Arc::new(CountTips::default());
    let svc = ForgeService::new(ForgeConfig::default(), td.path().join("plugin"))
        .unwrap()
        .with_tip_recorder(tips.clone() as Arc<dyn TipRecorder>);
    let fx = Fx { td, svc };
    fx.seed("casey", "editme");
    assert_eq!(
        fx.edit(json!({"path": "t.txt", "content": "1\n"}))
            .await
            .status,
        200
    );
    assert_eq!(tips.0.lock().unwrap().as_slice(), ["casey/editme"]);
    assert_eq!(
        fx.edit(json!({"path": "t.txt", "content": "1\n"}))
            .await
            .status,
        200
    );
    assert_eq!(
        tips.0.lock().unwrap().len(),
        1,
        "a no-op does not move the tip"
    );
    assert_eq!(
        fx.edit(json!({"path": "t.txt", "content": "2\n", "branch": "side"}))
            .await
            .status,
        200
    );
    assert_eq!(tips.0.lock().unwrap().len(), 2);
}

// ---- config ------------------------------------------------------------

#[test]
fn open_edit_defaults_off_and_reads_from_the_json_layer() {
    assert!(!ForgeConfig::default().open_edit);
    assert!(ForgeConfig::from_json(&json!({"openEdit": true})).open_edit);
    assert!(
        !ForgeConfig::from_json(&json!({"openEdit": "yes"})).open_edit,
        "only a boolean true counts"
    );
    assert!(!ForgeConfig::from_json(&json!({})).open_edit);
    // an explicit key wins over the defaults file
    let c = ForgeConfig::from_layers(json!({"openEdit": false}), None);
    assert!(!c.open_edit);
}

// ---- preview and announce (feature `announce`) --------------------------

#[cfg(feature = "announce")]
mod announce {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use solid_pod_rs_nostr::SsrfCheck;
    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::Message;

    struct AllowAll;
    #[async_trait]
    impl SsrfCheck for AllowAll {
        async fn verify_host(&self, _host: &str) -> Result<Option<std::net::IpAddr>, String> {
            Ok(None)
        }
    }

    async fn relay() -> (String, Arc<Mutex<Vec<Value>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let sink = Arc::clone(&sink);
                tokio::spawn(async move {
                    let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
                    while let Some(Ok(Message::Text(t))) = ws.next().await {
                        let v: Value = serde_json::from_str(&t).unwrap();
                        if v[0] == "EVENT" {
                            let id = v[1]["id"].clone();
                            sink.lock().unwrap().push(v[1].clone());
                            let _ = ws
                                .send(Message::text(json!(["OK", id, true, ""]).to_string()))
                                .await;
                        }
                    }
                });
            }
        });
        (url, seen)
    }

    async fn until<T>(mut f: impl FnMut() -> Option<T>) -> T {
        for _ in 0..100 {
            if let Some(v) = f() {
                return v;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("condition not reached");
    }

    fn fx_with_relay(url: &str, open_edit: bool) -> Fx {
        let td = TempDir::new().unwrap();
        let cfg = ForgeConfig {
            announce_relays: vec![url.to_string()],
            open_edit,
            ..Default::default()
        };
        let svc = ForgeService::new(cfg, td.path().join("plugin"))
            .unwrap()
            .with_announce_ssrf(Arc::new(AllowAll));
        let fx = Fx { td, svc };
        fx.seed("casey", "editme");
        fx
    }

    const PREVIEW: &str = "/forge/api/repos/casey/editme/preview";

    async fn preview(fx: &Fx, agent: &ForgeAgent, body: Value) -> ForgeResponse {
        fx.svc
            .handle(post(PREVIEW, &body), agent.clone())
            .await
            .unwrap()
    }

    // JSS ~2760 "an edit flows through NIP-34": the post-edit 30618 carries
    // the commit the edit just produced.
    #[tokio::test]
    async fn an_edit_is_announced_with_the_new_commit() {
        need_git!();
        let (url, seen) = relay().await;
        let fx = fx_with_relay(&url, false);
        let r = fx
            .edit(json!({"path": "NOTES.md", "content": "a note added over HTTP\n", "message": "web edit note"}))
            .await;
        assert_eq!(r.status, 200);
        let commit = json_of(&r)["commit"].as_str().unwrap().to_string();
        let state = until(|| {
            seen.lock()
                .unwrap()
                .iter()
                .find(|e| {
                    e["kind"] == 30618
                        && e["tags"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|t| t[0] == "refs/heads/main" && t[1] == commit.as_str())
                })
                .cloned()
        })
        .await;
        assert_eq!(state["kind"], 30618);
        // a no-op edit announces nothing new
        let n = seen.lock().unwrap().len();
        let r = fx
            .edit(json!({"path": "NOTES.md", "content": "a note added over HTTP\n"}))
            .await;
        assert_eq!(json_of(&r)["changed"], false);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(seen.lock().unwrap().len(), n);
    }

    // JSS 2790 "POST /preview emits an EPHEMERAL 21617 ... and makes NO commit"
    #[tokio::test]
    async fn preview_publishes_an_ephemeral_event_and_makes_no_commit() {
        need_git!();
        let (url, seen) = relay().await;
        let fx = fx_with_relay(&url, false);
        let head0 = fx.head("main");
        let r = preview(
            &fx,
            &pod("casey"),
            json!({"path": "index.html", "content": "<h1>ephemeral draft</h1>\n"}),
        )
        .await;
        assert_eq!(r.status, 200);
        assert_eq!(header(&r, "access-control-allow-origin"), Some("*"));
        let j = json_of(&r);
        assert_eq!(j["ok"], true);
        assert_eq!(j["published"], true);
        assert_eq!(j["kind"], 21617);
        assert_eq!(j["path"], "index.html");
        assert_eq!(
            j["relays"][0]["ok"], true,
            "the forge parsed the relay OK true"
        );
        let id = j["id"].as_str().unwrap().to_string();
        let ev = until(|| {
            seen.lock()
                .unwrap()
                .iter()
                .find(|e| e["id"] == id.as_str())
                .cloned()
        })
        .await;
        let kind = ev["kind"].as_u64().unwrap();
        assert!((20000..30000).contains(&kind), "NIP-01 ephemeral range");
        assert_eq!(ev["content"], "<h1>ephemeral draft</h1>\n");
        let tag = |n: &str| {
            ev["tags"]
                .as_array()
                .unwrap()
                .iter()
                .find(|t| t[0] == n)
                .map(|t| t[1].as_str().unwrap().to_string())
        };
        assert_eq!(tag("d").as_deref(), Some("casey/editme"));
        assert_eq!(tag("f").as_deref(), Some("index.html"));
        assert_eq!(tag("branch").as_deref(), Some("main"));
        let parsed = solid_pod_rs_nostr::Event {
            id: ev["id"].as_str().unwrap().into(),
            pubkey: ev["pubkey"].as_str().unwrap().into(),
            created_at: ev["created_at"].as_u64().unwrap(),
            kind,
            tags: serde_json::from_value(ev["tags"].clone()).unwrap(),
            content: ev["content"].as_str().unwrap().into(),
            sig: ev["sig"].as_str().unwrap().into(),
        };
        assert!(parsed.verify().is_ok(), "validly signed");
        assert_eq!(fx.head("main"), head0, "HEAD is UNCHANGED");
        assert!(git(
            &fx.repo("casey", "editme"),
            &["for-each-ref", "--format=%(refname)"]
        )
        .lines()
        .all(|l| l == "refs/heads/main"));
    }

    #[tokio::test]
    async fn preview_has_the_same_authorisation_and_validation_as_edit() {
        need_git!();
        let (url, seen) = relay().await;
        let fx = fx_with_relay(&url, false);
        let body = json!({"path": "index.html", "content": "x"});
        let anon = preview(&fx, &ForgeAgent::Anonymous, body.clone()).await;
        assert_eq!(anon.status, 401);
        assert_eq!(header(&anon, "access-control-allow-origin"), Some("*"));
        assert_eq!(preview(&fx, &pod("rival"), body.clone()).await.status, 403);
        for p in ["../x", ".git/x", "a/.GIT/x", "a\\b", ""] {
            let r = preview(&fx, &pod("casey"), json!({"path": p, "content": "x"})).await;
            assert_eq!(r.status, 400, "{p}");
        }
        let r = preview(
            &fx,
            &pod("casey"),
            json!({"path": "a", "content": "a".repeat(1024 * 1024 + 1)}),
        )
        .await;
        assert_eq!(r.status, 413);
        for b in ["--upload-pack=x", "-x", "a..b", "x.lock"] {
            let r = preview(
                &fx,
                &pod("casey"),
                json!({"path": "a", "content": "x", "branch": b}),
            )
            .await;
            assert_eq!(r.status, 400, "{b}");
        }
        let r = fx
            .svc
            .handle(
                post("/forge/api/repos/casey/ghost/preview", &body),
                pod("casey"),
            )
            .await
            .unwrap();
        assert_eq!(r.status, 404);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(seen.lock().unwrap().is_empty(), "nothing reached the relay");
    }

    #[tokio::test]
    async fn preview_with_no_relays_reports_unpublished_and_open_edit_admits_anonymous() {
        need_git!();
        let fx = Fx::new();
        let r = preview(&fx, &pod("casey"), json!({"path": "a.txt", "content": "x"})).await;
        assert_eq!(r.status, 200);
        let j = json_of(&r);
        assert_eq!(j["ok"], true);
        assert_eq!(j["published"], false);
        assert!(j["reason"].as_str().unwrap().contains("no relays"));
        // openEdit relaxes preview exactly as it relaxes edit
        let (url, seen) = relay().await;
        let fx = fx_with_relay(&url, true);
        let r = preview(
            &fx,
            &ForgeAgent::Anonymous,
            json!({"path": "a.txt", "content": "x", "branch": "other"}),
        )
        .await;
        assert_eq!(r.status, 200);
        let id = json_of(&r)["id"].as_str().unwrap().to_string();
        let ev = until(|| {
            seen.lock()
                .unwrap()
                .iter()
                .find(|e| e["id"] == id.as_str())
                .cloned()
        })
        .await;
        assert!(ev["tags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t[0] == "branch" && t[1] == "other"));
    }
}

// ---- anchoring (feature `anchoring`) -------------------------------------

/// JSS `recordTipSafe` after an edit: with a forge-held trail, an edit that
/// moves the default branch stacks a mark for the new tip; a no-op edit and a
/// side-branch edit do not.
#[cfg(feature = "anchoring")]
#[tokio::test]
async fn an_edit_advances_the_forge_held_anchor() {
    need_git!();
    let fx = Fx::new();
    let marks = "/forge/api/repos/casey/editme/marks";
    let call = |method: &str, path: &str| {
        let mut r = post(path, &json!({}));
        r.method = method.into();
        r
    };
    let en = fx
        .svc
        .handle(call("POST", &format!("{marks}/enable")), pod("casey"))
        .await
        .unwrap();
    assert_eq!(en.status, 201);
    let count = |fx: &Fx| {
        let svc = fx.svc.clone();
        let req = call("GET", marks);
        async move {
            let r = svc.handle(req, ForgeAgent::Anonymous).await.unwrap();
            json_of(&r)["marks"].as_array().map_or(0, Vec::len)
        }
    };
    let before = count(&fx).await;
    assert_eq!(before, 1, "the genesis mark");
    // a side branch is not the default branch: no mark
    fx.edit(json!({"path": "s.txt", "content": "s\n", "branch": "side"}))
        .await;
    assert_eq!(count(&fx).await, before);
    // a no-op edit: no mark
    fx.edit(json!({"path": "index.html", "content": "<h1>original</h1>\n"}))
        .await;
    assert_eq!(count(&fx).await, before);
    // a real edit on the default branch: one more mark, targeting the new tip
    let r = fx.edit(json!({"path": "t.txt", "content": "t\n"})).await;
    assert_eq!(r.status, 200);
    let commit = json_of(&r)["commit"].as_str().unwrap().to_string();
    assert_eq!(count(&fx).await, before + 1);
    let listing = fx
        .svc
        .handle(call("GET", marks), ForgeAgent::Anonymous)
        .await
        .unwrap();
    let last = json_of(&listing)["marks"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert_eq!(last["state"]["commit"], commit.as_str());
}
