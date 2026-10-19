//! End-to-end fork, compare, pull-request and merge flow on real bare
//! repositories. Transcribes the JSS forge `forks, compare and pull requests
//! (tier 3a)` suite (forge/test.js 1130-1297, 1335-1416, 1458, 1508, 1791) and
//! adds negative tests: foreign namespace, conflict, stale base, option
//! injection in branch names, tampered spine data and the git version gate.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use serde_json::{json, Value};
use solid_pod_rs_forge::bodies::{FetchResult, LoopbackFetch};
use solid_pod_rs_forge::merge::TipRecorder;
use solid_pod_rs_forge::{ForgeAgent, ForgeConfig, ForgeRequest, ForgeService};
use tempfile::TempDir;

const HOST: &str = "https://pod.example";
const API: &str = "/forge/api/repos/casey/demo";

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
            "user.name=Tester",
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
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[derive(Default)]
struct MockLb(Mutex<HashMap<String, Vec<u8>>>);

#[async_trait]
impl LoopbackFetch for MockLb {
    async fn get(&self, url: &str, _m: usize, _t: u64) -> FetchResult {
        match self.0.lock().unwrap().get(url) {
            Some(b) => FetchResult::Body(b.clone()),
            None => FetchResult::Removed,
        }
    }
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
    lb: Arc<MockLb>,
    n: Mutex<u32>,
}

fn pod(user: &str) -> ForgeAgent {
    ForgeAgent::Pod {
        webid: format!("{HOST}/{user}/profile/card#me"),
        username: user.to_string(),
    }
}

fn req(method: &str, path: &str, query: &str, body: Option<Value>) -> ForgeRequest {
    ForgeRequest {
        method: method.into(),
        path: path.into(),
        query: query.into(),
        headers: vec![("content-type".into(), "application/json".into())],
        raw_body: body.map(|v| Bytes::from(v.to_string())).unwrap_or_default(),
        host_url: Some(HOST.into()),
    }
}

fn hexs(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

impl Fx {
    fn new() -> Self {
        let td = TempDir::new().unwrap();
        let lb = Arc::new(MockLb::default());
        let svc = ForgeService::new(ForgeConfig::default(), td.path().join("plugin"))
            .unwrap()
            .with_loopback(lb.clone() as Arc<dyn LoopbackFetch>);
        let fx = Self {
            td,
            svc,
            lb,
            n: Mutex::new(0),
        };
        fx.seed("casey", "demo");
        fx
    }

    fn repo(&self, owner: &str, name: &str) -> PathBuf {
        self.td
            .path()
            .join("plugin/repos")
            .join(owner)
            .join(format!("{name}.git"))
    }

    fn seed(&self, owner: &str, name: &str) {
        let work = self.td.path().join(format!("seed-{owner}-{name}"));
        std::fs::create_dir_all(work.join("src")).unwrap();
        std::fs::create_dir_all(work.join("docs")).unwrap();
        git(&work, &["init", "-q", "-b", "main"]);
        std::fs::write(work.join("README.md"), "# Demo\n").unwrap();
        std::fs::write(
            work.join("src/main.js"),
            "function main() {\n  return 1;\n}\n",
        )
        .unwrap();
        std::fs::write(work.join("docs/notes.txt"), "notes\n").unwrap();
        git(&work, &["add", "-A"]);
        git(&work, &["commit", "-q", "-m", "initial"]);
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

    /// Clone `owner`'s bare repo, branch `branch` from its `from`, write a
    /// file, commit and push `branch` back. Returns the new commit.
    fn push_branch(
        &self,
        owner: &str,
        branch: &str,
        from: &str,
        file: &str,
        content: &str,
        msg: &str,
    ) -> String {
        let id = {
            let mut n = self.n.lock().unwrap();
            *n += 1;
            *n
        };
        let work = self.td.path().join(format!("w{id}"));
        let bare = self.repo(owner, "demo");
        git(
            self.td.path(),
            &[
                "clone",
                "-q",
                bare.to_str().unwrap(),
                work.to_str().unwrap(),
            ],
        );
        let local = format!("t{id}");
        git(
            &work,
            &["checkout", "-q", "-b", &local, &format!("origin/{from}")],
        );
        if let Some(parent) = Path::new(file).parent() {
            std::fs::create_dir_all(work.join(parent)).unwrap();
        }
        std::fs::write(work.join(file), content).unwrap();
        git(&work, &["add", "-A"]);
        git(&work, &["commit", "-q", "-m", msg]);
        let sha = git(&work, &["rev-parse", "HEAD"]);
        git(
            &work,
            &[
                "push",
                "-q",
                bare.to_str().unwrap(),
                &format!("{local}:refs/heads/{branch}"),
            ],
        );
        sha
    }

    async fn call(&self, r: ForgeRequest, a: ForgeAgent) -> (u16, Value, String) {
        let resp = self.svc.handle(r, a).await.unwrap();
        let text = String::from_utf8_lossy(&resp.body).into_owned();
        let v = serde_json::from_str(&text).unwrap_or(Value::Null);
        (resp.status, v, text)
    }

    async fn get(&self, path: &str) -> (u16, Value, String) {
        let (p, q) = path.split_once('?').unwrap_or((path, ""));
        self.call(req("GET", p, q, None), ForgeAgent::Anonymous)
            .await
    }

    async fn post(&self, path: &str, a: ForgeAgent, body: Option<Value>) -> (u16, Value, String) {
        self.call(req("POST", path, "", body), a).await
    }

    /// Put a pod body in the mock and return its URL.
    fn pod_body(&self, user: &str, file: &str, text: &str) -> String {
        let url = format!("{HOST}/{user}/public/forge/casey--demo/{file}");
        self.lb
            .0
            .lock()
            .unwrap()
            .insert(url.clone(), text.as_bytes().to_vec());
        url
    }

    async fn open_pr(&self, user: &str, title: &str, head: &str) -> (u16, Value) {
        let url = self.pod_body(user, &format!("pull-{}.jsonld", hexs(title)), title);
        let (s, v, _) = self
            .post(
                &format!("{API}/pulls"),
                pod(user),
                Some(json!({"title": title, "base": "main", "head": head, "resourceUrl": url})),
            )
            .await;
        (s, v)
    }
}

async fn forked() -> Fx {
    let fx = Fx::new();
    let (s, ..) = fx.post(&format!("{API}/fork"), pod("dana"), None).await;
    assert_eq!(s, 201);
    fx
}

#[tokio::test]
async fn fork_create_lineage_and_negatives() {
    if !git_ok() {
        return;
    }
    let fx = Fx::new();
    assert_eq!(
        fx.post(&format!("{API}/fork"), ForgeAgent::Anonymous, None)
            .await
            .0,
        401
    );
    let (s, j, _) = fx.post(&format!("{API}/fork"), pod("dana"), None).await;
    assert_eq!(s, 201);
    assert_eq!(j["owner"], "dana");
    assert_eq!(j["name"], "demo");
    assert_eq!(j["parent"], "casey/demo");
    assert_eq!(j["cloneUrl"], format!("{HOST}/forge/dana/demo.git"));
    let dir = fx.repo("dana", "demo");
    assert!(dir.is_dir(), "bare fork under repos/dana");
    assert_eq!(
        git(&dir, &["config", "--get", "forge.parent"]),
        "casey/demo"
    );
    assert!(git(&dir, &["config", "--get-all", "uploadpack.hideRefs"]).contains("refs/forge/"));
    assert!(git(&dir, &["config", "--get-all", "transfer.hideRefs"]).contains("refs/forge/"));
    assert!(git(&dir, &["remote"]).is_empty(), "origin dropped");
    assert_eq!(
        fx.post(&format!("{API}/fork"), pod("dana"), None).await.0,
        409
    );
    let names: Vec<_> = std::fs::read_dir(fx.td.path().join("plugin/repos/dana"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["demo.git".to_string()]);
    for bad in ["../x", "a.git", ".hidden", "-rf", "a/b", "x..y", ""] {
        let (s, ..) = fx
            .post(
                &format!("{API}/fork"),
                pod("casey"),
                Some(json!({"name": bad})),
            )
            .await;
        assert_eq!(s, 422, "{bad:?}");
    }
    assert_eq!(
        fx.post(
            &format!("{API}/fork"),
            pod("casey"),
            Some(json!({"name": 7}))
        )
        .await
        .0,
        422
    );
    assert_eq!(
        fx.post(
            &format!("{API}/fork"),
            pod("casey"),
            Some(json!({"name": "demo2"}))
        )
        .await
        .0,
        201
    );
    assert_eq!(
        fx.post("/forge/api/repos/casey/ghost/fork", pod("dana"), None)
            .await
            .0,
        404
    );
    assert_eq!(fx.get(&format!("{API}/fork")).await.0, 405);
}

#[tokio::test]
async fn lineage_and_fork_count_render() {
    if !git_ok() {
        return;
    }
    let fx = forked().await;
    let (_, _, home) = fx.get("/forge/dana/demo").await;
    assert!(home.contains("forked from"));
    assert!(home.contains("href=\"/forge/casey/demo\""));
    let (_, _, parent) = fx.get("/forge/casey/demo").await;
    assert!(parent.contains("1 fork"));
    let (_, _, list) = fx.get("/forge").await;
    assert!(list.contains("forked from"));
    let (_, _, owner) = fx.get("/forge/dana").await;
    assert!(owner.contains("forked from"));
}

#[tokio::test]
async fn compare_json_and_html() {
    if !git_ok() {
        return;
    }
    let fx = forked().await;
    let feat = fx.push_branch(
        "dana",
        "feature",
        "main",
        "CONTRIBUTING.md",
        "# Contributing\n\nPlease be kind.\n",
        "add contributing guide",
    );
    let (s, c, _) = fx.get(&format!("{API}/compare/main...dana:feature")).await;
    assert_eq!(s, 200);
    assert_eq!(c["aheadBy"], 1);
    assert_eq!(c["behindBy"], 0);
    assert_eq!(c["head"]["owner"], "dana");
    assert_eq!(c["head"]["sha"], feat);
    assert_eq!(c["commits"].as_array().unwrap().len(), 1);
    assert_eq!(c["commits"][0]["subject"], "add contributing guide");
    assert_eq!(c["files"].as_array().unwrap().len(), 1);
    assert_eq!(c["files"][0]["name"], "CONTRIBUTING.md");
    assert!(c["base"]["sha"].as_str().is_some());
    let refs = git(&fx.repo("casey", "demo"), &["for-each-ref", "refs/forge"]);
    assert!(refs.contains("refs/forge/heads/dana/feature"));

    for bad in [
        "main...nosuchowner:feature",
        "main...dana:no-such-branch",
        "main",
        "main...dana:bad..ref",
        "main...dana:--upload-pack=x",
        "main...-x:feature",
        "main...dana:a//b",
        "main...dana:a/",
        "--output=x...dana:feature",
        "...dana:feature",
    ] {
        assert_eq!(
            fx.get(&format!("{API}/compare/{bad}")).await.0,
            404,
            "{bad}"
        );
    }

    let (s, _, html) = fx
        .get("/forge/casey/demo/compare/main...dana:feature")
        .await;
    assert_eq!(s, 200);
    assert!(html.contains("1 ahead, 0 behind"));
    assert!(html.contains("add contributing guide"));
    assert!(html.contains("CONTRIBUTING.md"));
    assert!(html.contains("<tr class=\"add\">"));
    assert!(html.contains("Open pull request"));
}

#[tokio::test]
async fn hidden_refs_leak_without_config_and_heal_lazily() {
    if !git_ok() {
        return;
    }
    let fx = forked().await;
    fx.push_branch("dana", "feature", "main", "a.txt", "a\n", "a");
    let base = fx.repo("casey", "demo");
    let cmp = format!("{API}/compare/main...dana:feature");
    assert_eq!(fx.get(&cmp).await.0, 200);
    let ls = git(fx.td.path(), &["ls-remote", base.to_str().unwrap()]);
    assert!(
        !ls.contains("refs/forge/"),
        "hidden after the first fetch: {ls}"
    );
    assert!(git(&base, &["for-each-ref", "refs/forge"]).contains("refs/forge/heads/dana/feature"));
    git(&base, &["config", "--unset-all", "uploadpack.hideRefs"]);
    git(&base, &["config", "--unset-all", "transfer.hideRefs"]);
    let ls = git(fx.td.path(), &["ls-remote", base.to_str().unwrap()]);
    assert!(ls.contains("refs/forge/"), "leaks without the config");
    // Having only one of the two settings is not enough: the other is healed.
    git(&base, &["config", "uploadpack.hideRefs", "refs/forge/"]);
    assert_eq!(fx.get(&cmp).await.0, 200);
    assert!(git(&base, &["config", "--get-all", "transfer.hideRefs"]).contains("refs/forge/"));
    git(&base, &["config", "--unset-all", "uploadpack.hideRefs"]);
    git(&base, &["config", "--unset-all", "transfer.hideRefs"]);
    assert_eq!(fx.get(&cmp).await.0, 200);
    let ls = git(fx.td.path(), &["ls-remote", base.to_str().unwrap()]);
    assert!(
        !ls.contains("refs/forge/"),
        "the first compare-fetch healed the config"
    );
    // An unrelated hideRefs value is preserved, not overwritten.
    git(&base, &["config", "--unset-all", "uploadpack.hideRefs"]);
    git(&base, &["config", "uploadpack.hideRefs", "refs/mirror/"]);
    assert_eq!(fx.get(&cmp).await.0, 200);
    let all = git(&base, &["config", "--get-all", "uploadpack.hideRefs"]);
    assert!(all.contains("refs/mirror/") && all.contains("refs/forge/"));
}

#[tokio::test]
async fn pr_create_validation_and_negatives() {
    if !git_ok() {
        return;
    }
    let fx = forked().await;
    fx.push_branch(
        "dana",
        "feature",
        "main",
        "CONTRIBUTING.md",
        "hello\n",
        "add guide",
    );
    let url = fx.pod_body("dana", "pull-x.jsonld", "body");
    let body =
        |t: &str, b: &str, h: &str| json!({"title": t, "base": b, "head": h, "resourceUrl": url});
    let (s, ..) = fx
        .post(
            &format!("{API}/pulls"),
            ForgeAgent::Anonymous,
            Some(body("nope", "main", "dana:feature")),
        )
        .await;
    assert_eq!(s, 401);
    for (t, b, h) in [
        ("x", "main", "nosuchowner:feature"),
        ("x", "main", "dana:--upload-pack=x"),
        ("x", "main", "-x:feature"),
        ("x", "main", "dana:bad..ref"),
        ("x", "main", "dana:a//b"),
        ("x", "main", "dana:a/"),
        ("x", "--output=x", "dana:feature"),
        ("x", "nope", "dana:feature"),
        ("", "main", "dana:feature"),
        ("x", "main", "main"),
    ] {
        let (s, ..) = fx
            .post(&format!("{API}/pulls"), pod("dana"), Some(body(t, b, h)))
            .await;
        assert_eq!(s, 422, "{t:?} {b:?} {h:?}");
    }
    let long = "t".repeat(257);
    assert_eq!(
        fx.post(
            &format!("{API}/pulls"),
            pod("dana"),
            Some(body(&long, "main", "dana:feature"))
        )
        .await
        .0,
        422
    );
    assert_eq!(
        fx.post(
            &format!("{API}/pulls"),
            pod("dana"),
            Some(json!({"title": "x", "base": "main", "head": "dana:feature"}))
        )
        .await
        .0,
        422
    );
    let foreign = fx.pod_body("casey", "pull-y.jsonld", "casey's words");
    let (s, ..) = fx
        .post(
            &format!("{API}/pulls"),
            pod("dana"),
            Some(json!({"title": "x", "base": "main", "head": "dana:feature", "resourceUrl": foreign})),
        )
        .await;
    assert_eq!(s, 403, "a pointer into another agent's pod is refused");
    let (s, j) = fx
        .open_pr("dana", "Add contributing guide", "dana:feature")
        .await;
    assert_eq!(s, 201);
    assert_eq!(j["number"], 1, "failures consumed no number");
    assert!(j["resourceUrl"]
        .as_str()
        .unwrap()
        .contains("/dana/public/forge/casey--demo/pull-"));
}

#[tokio::test]
async fn full_pr_story_merge_conflict_close_ff_and_cas() {
    if !git_ok() {
        return;
    }
    let base_fx = forked().await;
    let tips = Arc::new(CountTips::default());
    let svc = base_fx
        .svc
        .clone()
        .with_tip_recorder(tips.clone() as Arc<dyn TipRecorder>);
    let fx = Fx { svc, ..base_fx };
    let casey_dir = fx.repo("casey", "demo");
    let dana_dir = fx.repo("dana", "demo");

    let feat = fx.push_branch(
        "dana",
        "feature",
        "main",
        "CONTRIBUTING.md",
        "# Contributing\n",
        "add contributing guide",
    );
    let (s, j) = fx
        .open_pr("dana", "Add contributing guide", "dana:feature")
        .await;
    assert_eq!((s, j["number"].clone()), (201, json!(1)));

    let curl = fx.pod_body("casey", "comment-1.jsonld", "Looks good, thanks!");
    let (s, j, _) = fx
        .post(
            &format!("{API}/pulls/1/comments"),
            pod("casey"),
            Some(json!({"resourceUrl": curl})),
        )
        .await;
    assert_eq!(s, 201);
    assert!(j["resourceUrl"]
        .as_str()
        .unwrap()
        .contains("/casey/public/forge/casey--demo/comment-"));
    let (_, pr, _) = fx.get(&format!("{API}/pulls/1")).await;
    assert_eq!(pr["state"], "open");
    assert_eq!(pr["head"]["owner"], "dana");
    assert_eq!(pr["head"]["ref"], "feature");
    assert_eq!(pr["base"], "main");
    assert!(pr["baseSha"].as_str().is_some());
    assert_eq!(pr["mergeable"], true);
    assert_eq!(pr["conflicts"], json!([]));
    assert_eq!(pr["thread"].as_array().unwrap().len(), 2);
    assert_eq!(
        pr["thread"][0]["author"],
        format!("{HOST}/dana/profile/card#me")
    );
    assert_eq!(pr["thread"][0]["authorInfo"]["kind"], "webid");
    assert_eq!(pr["thread"][1]["body"], "Looks good, thanks!");

    let (_, _, home) = fx.get("/forge/casey/demo").await;
    assert!(
        home.contains("Pull requests <span class=\"badge\">1</span>"),
        "{home}"
    );
    let (_, _, list) = fx.get("/forge/casey/demo/pulls").await;
    assert!(
        list.contains("Add contributing guide")
            && list.contains("pr-open")
            && list.contains("dana:feature")
    );
    let (_, _, conv) = fx.get("/forge/casey/demo/pulls/1").await;
    assert!(conv.contains("opened this pull request"));
    assert!(conv.contains("no conflicts with the base branch"));
    assert!(conv.contains("id=\"do-merge\""));
    assert!(conv.contains("Looks good, thanks!"));
    let (_, _, commits) = fx.get("/forge/casey/demo/pulls/1/commits").await;
    assert!(commits.contains("add contributing guide"));
    let (_, _, files) = fx.get("/forge/casey/demo/pulls/1/files").await;
    assert!(files.contains("CONTRIBUTING.md") && files.contains("<tr class=\"add\">"));

    // dana cannot merge into casey's repo (403); anonymous is 401
    assert_eq!(
        fx.post(&format!("{API}/pulls/1/merge"), pod("dana"), None)
            .await
            .0,
        403
    );
    assert_eq!(
        fx.post(&format!("{API}/pulls/1/merge"), ForgeAgent::Anonymous, None)
            .await
            .0,
        401
    );
    assert_eq!(fx.get(&format!("{API}/pulls/1")).await.1["state"], "open");
    assert!(
        tips.0.lock().unwrap().is_empty(),
        "failed merges record no tip"
    );

    // diverge main, then a real two-parent merge
    fx.push_branch(
        "casey",
        "main",
        "main",
        "README.md",
        "# Demo\nA line added upstream.\n",
        "upstream readme note",
    );
    let (s, j, _) = fx
        .post(&format!("{API}/pulls/1/merge"), pod("casey"), None)
        .await;
    assert_eq!(s, 200, "{j}");
    assert_eq!(j["state"], "merged");
    assert_eq!(j["fastForward"], false);
    let merge_sha = j["sha"].as_str().unwrap().to_string();
    let log = git(&casey_dir, &["log", "--format=%H|%P|%an|%cn|%s", "main"]);
    assert!(log.contains(&feat), "dana's commit is reachable from main");
    let line = log.lines().find(|l| l.starts_with(&merge_sha)).unwrap();
    let f: Vec<&str> = line.split('|').collect();
    assert_eq!(f[1].split(' ').count(), 2, "two parents");
    assert_eq!(f[2], "casey");
    assert_eq!(f[3], "forge");
    assert_eq!(f[4], "Merge pull request #1 from dana:feature");
    let (_, pr, _) = fx.get(&format!("{API}/pulls/1")).await;
    assert_eq!(pr["state"], "merged");
    assert_eq!(pr["merged"]["sha"], merge_sha);
    assert_eq!(
        pr["merged"]["mergedBy"],
        format!("{HOST}/casey/profile/card#me")
    );
    assert_eq!(tips.0.lock().unwrap().as_slice(), ["casey/demo"]);
    let (_, _, conv) = fx.get("/forge/casey/demo/pulls/1").await;
    assert!(conv.contains("state-merged"));
    let (_, _, ml) = fx.get("/forge/casey/demo/pulls?state=merged").await;
    assert!(ml.contains("Add contributing guide") && ml.contains("pr-merged"));
    assert_eq!(
        fx.post(&format!("{API}/pulls/1/merge"), pod("casey"), None)
            .await
            .0,
        422
    );
    let (_, _, files) = fx.get("/forge/casey/demo/pulls/1/files").await;
    assert!(
        files.contains("CONTRIBUTING.md"),
        "frozen shas drive the files tab"
    );

    // conflict: both sides change the same line
    git(
        &dana_dir,
        &[
            "fetch",
            "-q",
            casey_dir.to_str().unwrap(),
            "main:refs/heads/main",
        ],
    );
    fx.push_branch(
        "dana",
        "branch2",
        "main",
        "src/main.js",
        "function main() {\n  return 42;\n}\n",
        "main goes to 42",
    );
    fx.push_branch(
        "casey",
        "main",
        "main",
        "src/main.js",
        "function main() {\n  return 3;\n}\n",
        "main goes to 3",
    );
    let (s, j) = fx.open_pr("dana", "Return 42", "dana:branch2").await;
    assert_eq!((s, j["number"].clone()), (201, json!(2)));
    let (_, pr, _) = fx.get(&format!("{API}/pulls/2")).await;
    assert_eq!(pr["mergeable"], false);
    assert_eq!(pr["conflicts"], json!(["src/main.js"]));
    let (_, _, conv) = fx.get("/forge/casey/demo/pulls/2").await;
    assert!(conv.contains("conflicts that must be resolved") && conv.contains("src/main.js"));
    assert!(!conv.contains("id=\"do-merge\""));
    let before = git(&casey_dir, &["rev-parse", "main"]);
    let (s, mj, _) = fx
        .post(&format!("{API}/pulls/2/merge"), pod("casey"), None)
        .await;
    assert_eq!(s, 409);
    assert_eq!(mj["error"], "merge conflict");
    assert_eq!(mj["conflicts"], json!(["src/main.js"]));
    assert_eq!(
        git(&casey_dir, &["rev-parse", "main"]),
        before,
        "main untouched by a failed merge"
    );
    assert_eq!(fx.get(&format!("{API}/pulls/2")).await.1["state"], "open");

    // close (red chip); a merged PR cannot be closed
    let (s, j, _) = fx
        .post(&format!("{API}/pulls/2/close"), pod("casey"), None)
        .await;
    assert_eq!((s, j), (200, json!({"number": 2, "state": "closed"})));
    let (_, closed, _) = fx.get(&format!("{API}/pulls?state=closed")).await;
    let nums: Vec<_> = closed["pulls"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["number"].clone())
        .collect();
    assert_eq!(nums, vec![json!(2)]);
    let (_, _, html) = fx.get("/forge/casey/demo/pulls?state=closed").await;
    assert!(html.contains("Return 42") && html.contains("pr-closed"));
    assert_eq!(
        fx.post(&format!("{API}/pulls/1/close"), pod("casey"), None)
            .await
            .0,
        422
    );
    assert_eq!(
        fx.post(&format!("{API}/pulls/2/reopen"), pod("mallory"), None)
            .await
            .0,
        403
    );
    assert_eq!(
        fx.post(&format!("{API}/pulls/2/reopen"), pod("dana"), None)
            .await
            .0,
        200
    );
    assert_eq!(
        fx.post(&format!("{API}/pulls/2/close"), pod("dana"), None)
            .await
            .0,
        200
    );

    // fast-forward: a branch from the current tip merges with no merge commit
    git(
        &dana_dir,
        &[
            "fetch",
            "-q",
            casey_dir.to_str().unwrap(),
            "main:refs/heads/main",
        ],
    );
    let ffc = fx.push_branch(
        "dana",
        "ff",
        "main",
        "docs/ff.txt",
        "fast forward\n",
        "ff change",
    );
    let (s, j) = fx.open_pr("dana", "FF change", "dana:ff").await;
    assert_eq!((s, j["number"].clone()), (201, json!(3)));
    let (s, j, _) = fx
        .post(&format!("{API}/pulls/3/merge"), pod("casey"), None)
        .await;
    assert_eq!(s, 200);
    assert_eq!(j["fastForward"], true);
    assert_eq!(
        j["sha"], ffc,
        "merged sha is dana's commit, no synthetic merge commit"
    );
    let tip = git(&casey_dir, &["log", "-1", "--format=%H|%P", "main"]);
    let (h, p) = tip.split_once('|').unwrap();
    assert_eq!(h, ffc);
    assert_eq!(p.split(' ').count(), 1);

    // CAS guard: the base moving between diff and merge is a 409 first time
    git(
        &dana_dir,
        &[
            "fetch",
            "-q",
            casey_dir.to_str().unwrap(),
            "main:refs/heads/main",
        ],
    );
    fx.push_branch(
        "dana",
        "cas",
        "main",
        "cas.txt",
        "compare and swap\n",
        "cas change",
    );
    let (s, j) = fx.open_pr("dana", "CAS probe", "dana:cas").await;
    assert_eq!((s, j["number"].clone()), (201, json!(4)));
    let seen = fx.get(&format!("{API}/pulls/4")).await.1["baseSha"]
        .as_str()
        .unwrap()
        .to_string();
    fx.push_branch(
        "casey",
        "main",
        "main",
        "docs/notes.txt",
        "notes\nmore\n",
        "notes tweak",
    );
    let (s, j, _) = fx
        .post(
            &format!("{API}/pulls/4/merge"),
            pod("casey"),
            Some(json!({"expectedBase": seen})),
        )
        .await;
    assert_eq!(s, 409, "stale expectedBase is rejected");
    assert!(j["error"].as_str().unwrap().contains("moved"));
    assert!(j["baseSha"].as_str().is_some());
    assert_eq!(fx.get(&format!("{API}/pulls/4")).await.1["state"], "open");
    for bad in ["--help", "xyz", "A"] {
        let (s, ..) = fx
            .post(
                &format!("{API}/pulls/4/merge"),
                pod("casey"),
                Some(json!({"expectedBase": bad})),
            )
            .await;
        assert_eq!(s, 422, "{bad}");
    }
    let (s, j, _) = fx
        .post(&format!("{API}/pulls/4/merge"), pod("casey"), None)
        .await;
    assert_eq!(s, 200);
    assert_eq!(j["fastForward"], false);
    let line = git(&casey_dir, &["log", "-1", "--format=%P|%s", "main"]);
    assert_eq!(line.split('|').next().unwrap().split(' ').count(), 2);
    assert!(line.ends_with("Merge pull request #4 from dana:cas"));

    let (_, l, _) = fx.get(&format!("{API}/pulls?state=open")).await;
    assert_eq!(l["openCount"], 0);
    assert_eq!(l["mergedCount"], 3);
    assert_eq!(l["closedCount"], 1);
}

#[tokio::test]
async fn nostr_agent_forks_into_hex_namespace_and_opens_hosted_pr() {
    if !git_ok() {
        return;
    }
    let fx = Fx::new();
    let pk = "ab".repeat(32);
    let nostr = || ForgeAgent::Nostr {
        pubkey_hex: pk.clone(),
    };
    let (s, fj, _) = fx.post(&format!("{API}/fork"), nostr(), None).await;
    assert_eq!(s, 201);
    assert_eq!(fj["owner"], pk);
    assert_eq!(
        git(&fx.repo(&pk, "demo"), &["config", "--get", "forge.parent"]),
        "casey/demo"
    );
    fx.push_branch(
        &pk,
        "npatch",
        "main",
        "nostr.txt",
        "signed\n",
        "nostr patch",
    );
    let head = format!("{pk}:npatch");
    let (s, pj, _) = fx
        .post(
            &format!("{API}/pulls"),
            nostr(),
            Some(json!({"title": "Nostr-born PR", "body": "from a key, not a pod", "base": "main", "head": head})),
        )
        .await;
    assert_eq!(s, 201);
    assert_eq!(pj["number"], 1);
    assert_eq!(pj["hosted"], true);
    assert!(pj["resourceUrl"]
        .as_str()
        .unwrap()
        .contains(&format!("/forge/api/hosted/{pk}/")));
    let (s, ..) = fx
        .post(
            &format!("{API}/pulls"),
            nostr(),
            Some(json!({"title": "x", "base": "main", "head": head})),
        )
        .await;
    assert_eq!(s, 422, "podless without a body");
    let (_, pr, _) = fx.get(&format!("{API}/pulls/1")).await;
    assert_eq!(pr["author"], format!("did:nostr:{pk}"));
    assert_eq!(pr["authorInfo"]["kind"], "nostr");
    assert_eq!(pr["head"]["owner"], pk);
    assert_eq!(pr["thread"][0]["hosted"], true);
    assert_eq!(pr["thread"][0]["body"], "from a key, not a pod");
    assert_eq!(
        fx.post(&format!("{API}/pulls/1/merge"), nostr(), None)
            .await
            .0,
        403
    );
}

#[tokio::test]
async fn merge_is_gated_on_git_version() {
    if !git_ok() {
        return;
    }
    let fx = forked().await;
    fx.push_branch("dana", "feature", "main", "a.txt", "a\n", "a");
    fx.open_pr("dana", "t", "dana:feature").await;
    let old = fx.svc.clone().with_git_version("git version 2.37.1");
    assert!(!old.merge_tree_ok());
    let r = old
        .handle(
            req("POST", &format!("{API}/pulls/1/merge"), "", None),
            pod("casey"),
        )
        .await
        .unwrap();
    assert_eq!(r.status, 501);
    let j: Value = serde_json::from_slice(&r.body).unwrap();
    assert!(j["error"].as_str().unwrap().contains("2.38"));
    let r = old
        .handle(
            req("POST", &format!("{API}/pulls/1/merge"), "", None),
            pod("dana"),
        )
        .await
        .unwrap();
    assert_eq!(r.status, 403, "authorisation precedes the capability gate");
    fx.push_branch("casey", "main", "main", "b.txt", "b\n", "b");
    let r = old
        .handle(
            req("GET", &format!("{API}/pulls/1"), "", None),
            ForgeAgent::Anonymous,
        )
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&r.body).unwrap();
    assert!(v["mergeable"].is_null(), "unknown verdict, not a guess");
    // the real service still merges
    let (s, ..) = fx
        .post(&format!("{API}/pulls/1/merge"), pod("casey"), None)
        .await;
    assert_eq!(s, 200);
}

#[tokio::test]
async fn tampered_spine_cannot_reach_git_argv() {
    if !git_ok() {
        return;
    }
    let fx = forked().await;
    fx.push_branch("dana", "feature", "main", "a.txt", "a\n", "a");
    fx.open_pr("dana", "t", "dana:feature").await;
    let path = fx.td.path().join("plugin/pulls/casey/demo.json");
    let orig = std::fs::read_to_string(&path).unwrap();
    let before = git(&fx.repo("casey", "demo"), &["rev-parse", "main"]);
    let marker = fx.td.path().join("pwned");
    let evil_base = format!("\"base\":\"--output={}\"", marker.display());
    for (from, to) in [
        ("\"base\":\"main\"", evil_base.as_str()),
        ("\"ref\":\"feature\"", "\"ref\":\"--upload-pack=x\""),
        ("\"owner\":\"dana\"", "\"owner\":\"-x\""),
    ] {
        assert!(orig.contains(from), "{from} in {orig}");
        std::fs::write(&path, orig.replacen(from, to, 1)).unwrap();
        let (s, ..) = fx
            .post(&format!("{API}/pulls/1/merge"), pod("casey"), None)
            .await;
        assert!((400..500).contains(&s), "{to}: {s}");
        let (s, v, _) = fx.get(&format!("{API}/pulls/1")).await;
        assert_eq!(s, 200);
        assert!(v["mergeable"].is_null());
    }
    assert!(!marker.exists());
    assert_eq!(
        git(&fx.repo("casey", "demo"), &["rev-parse", "main"]),
        before
    );
    std::fs::write(&path, "not json{").unwrap();
    assert_eq!(
        fx.get(&format!("{API}/pulls")).await.0,
        500,
        "corrupt index is an error"
    );
}

#[tokio::test]
async fn comments_are_bounded_and_authenticated() {
    if !git_ok() {
        return;
    }
    let fx = forked().await;
    fx.push_branch("dana", "feature", "main", "a.txt", "a\n", "a");
    fx.open_pr("dana", "t", "dana:feature").await;
    let c = format!("{API}/pulls/1/comments");
    assert_eq!(
        fx.post(&c, ForgeAgent::Anonymous, Some(json!({"body": "x"})))
            .await
            .0,
        401
    );
    assert_eq!(fx.post(&c, pod("casey"), Some(json!({}))).await.0, 422);
    assert_eq!(
        fx.post(&c, pod("casey"), Some(json!({"body": "x".repeat(70_000)})))
            .await
            .0,
        422
    );
    assert_eq!(
        fx.post(
            &format!("{API}/pulls/99/comments"),
            pod("casey"),
            Some(json!({"resourceUrl": "u"}))
        )
        .await
        .0,
        404
    );
    assert_eq!(fx.get(&c).await.0, 405);
    assert_eq!(fx.get(&format!("{API}/pulls/0")).await.0, 404);
    assert_eq!(fx.get(&format!("{API}/pulls/abc")).await.0, 404);
    let mut r = req("POST", "/forge/casey/demo/pulls/1/close", "", None);
    r.headers.clear();
    let resp = fx.svc.handle(r, pod("casey")).await.unwrap();
    assert_eq!(resp.status, 303);
    assert!(resp
        .headers
        .iter()
        .any(|(k, v)| k == "location" && v.ends_with("/pulls/1")));
}
