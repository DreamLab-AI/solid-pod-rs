//! The JSON API read surface and repo metadata edit.
//!
//! Dispatches the `/api/repos`, `/api/repos/<owner>`, `/api/repos/<owner>/<repo>`
//! and `/api/repos/<owner>/<repo>/{tree,blob,commits,commit}` routes. Shapes
//! follow the JSS `forge` JSON API (`apiRepoList`, `apiRepoMeta`, `apiTree`,
//! `apiBlob`, `apiCommits`, `apiCommit`, `apiRepoPatch`), cited by name only.
//! Strings are raw (JSON is the escape); the one exception is `readme.html`,
//! which is the already-escaped output of [`crate::markdown`].
//!
//! Every ref and path is validated with [`crate::guard`] before it reaches a
//! git argv, and git is only ever run through [`crate::gitrun`].

use std::path::Path;
use std::sync::Arc;

use serde_json::{json, Map, Value};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::error::ForgeError;
use crate::guard::{is_sha, ok_owner, ok_path, ok_ref, ok_repo};
use crate::ownership::ForgeAgent;
use crate::request::{ForgeRequest, ForgeResponse};
use crate::{gitrun, markdown, ForgeService};

/// Blobs and READMEs above this are "view raw" (JSS `RENDER_CAP`).
pub const RENDER_CAP: u64 = 512 * 1024;
/// Commits per page (JSS `PER_PAGE`).
pub const PER_PAGE: usize = 30;
/// Repo description cap (JSS `DESCRIPTION_CAP`).
pub const DESCRIPTION_CAP: usize = 512;
/// Repos returned by one list call.
const LIST_CAP: usize = 200;
/// Tree entries that get a `lastCommit`.
const LAST_COMMIT_CAP: usize = 100;
/// Body cap for JSON writes (JSS `ISSUE_BODY_CAP + 8192`).
pub const JSON_BODY_CAP: usize = 64 * 1024 + 8192;

/// A JSON response with the JSS `sendJson` headers.
#[must_use]
pub fn json_resp(status: u16, v: &Value) -> ForgeResponse {
    ForgeResponse::with_type(
        status,
        "application/json; charset=utf-8",
        bytes::Bytes::from(serde_json::to_vec(v).unwrap_or_else(|_| b"{}".to_vec())),
    )
    .with_header("x-content-type-options", "nosniff")
}

/// A JSON `{ "error": msg }` response (JSS `apiErr`).
#[must_use]
pub fn api_err(status: u16, msg: &str) -> ForgeResponse {
    json_resp(status, &json!({ "error": msg }))
}

/// `401` with the JSS `WWW-Authenticate: Bearer` challenge.
#[must_use]
pub fn unauthorised() -> ForgeResponse {
    api_err(401, "authentication required")
        .with_header("www-authenticate", "Bearer realm=\"jss-forge\"")
}

/// Parse the request body as a JSON **object** (JSS `readJsonBody`): `None`
/// when empty, oversized, unparseable or not an object.
#[must_use]
pub fn read_json_body(req: &ForgeRequest) -> Option<Map<String, Value>> {
    if req.raw_body.is_empty() || req.raw_body.len() > JSON_BODY_CAP {
        return None;
    }
    match serde_json::from_slice::<Value>(&req.raw_body) {
        Ok(Value::Object(m)) => Some(m),
        _ => None,
    }
}

/// Is the method a read (`GET` / `HEAD`)?
#[must_use]
pub fn is_read(req: &ForgeRequest) -> bool {
    req.method.eq_ignore_ascii_case("GET") || req.method.eq_ignore_ascii_case("HEAD")
}

/// Does `s` contain a NUL in its first 8000 bytes (git's binary heuristic)?
#[must_use]
pub fn looks_binary(buf: &[u8]) -> bool {
    buf.iter().take(8000).any(|&b| b == 0)
}

/// Repository summary used by the list endpoints and the HTML index.
#[derive(Debug, Clone)]
pub struct RepoSummary {
    /// Owner namespace.
    pub owner: String,
    /// Repository name.
    pub name: String,
    /// Description (file or README first line), possibly empty.
    pub description: String,
    /// Newest ref commit time, unix seconds.
    pub last_push: Option<u64>,
}

/// A parsed git ref listing row.
#[derive(Debug, Clone)]
pub struct RefRow {
    /// Short ref name.
    pub name: String,
    /// Abbreviated object name.
    pub sha: String,
    /// Creator date, unix seconds.
    pub when: i64,
    /// Subject line.
    pub subject: String,
}

/// One `ls-tree -l` row.
#[derive(Debug, Clone)]
pub struct TreeRow {
    /// File mode.
    pub mode: String,
    /// `blob`, `tree` or `commit`.
    pub kind: String,
    /// Object id.
    pub sha: String,
    /// Size, `None` for trees.
    pub size: Option<u64>,
    /// Entry name.
    pub name: String,
}

/// `for-each-ref` over `refs/heads` or `refs/tags`, newest first.
pub async fn list_refs(dir: &Path, kind: &str) -> Result<Vec<RefRow>, ForgeError> {
    let out = gitrun::text(
        dir,
        &[
            "for-each-ref",
            "--sort=-committerdate",
            "--format=%(refname:short)%00%(objectname:short)%00%(creatordate:unix)%00%(subject)",
            &format!("refs/{kind}"),
        ],
    )
    .await?;
    Ok(out
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let mut f = l.split('\0');
            RefRow {
                name: f.next().unwrap_or("").to_string(),
                sha: f.next().unwrap_or("").to_string(),
                when: f.next().and_then(|n| n.parse().ok()).unwrap_or(0),
                subject: f.next().unwrap_or("").to_string(),
            }
        })
        .collect())
}

fn refs_json(rows: &[RefRow]) -> Value {
    Value::Array(
        rows.iter()
            .map(|r| json!({"name": r.name, "sha": r.sha, "when": r.when, "subject": r.subject}))
            .collect(),
    )
}

/// Longest ref-name match wins (JSS `splitRefPath`): `["feature","x","src"]`
/// becomes `("feature/x", ["src"])` when `feature/x` is a branch or tag.
pub async fn split_ref_path(dir: &Path, segs: &[String]) -> (String, Vec<String>) {
    let mut names = std::collections::HashSet::new();
    for kind in ["heads", "tags"] {
        if let Ok(rows) = list_refs(dir, kind).await {
            names.extend(rows.into_iter().map(|r| r.name));
        }
    }
    for i in (1..=segs.len().min(20)).rev() {
        let cand = segs[..i].join("/");
        if names.contains(&cand) {
            return (cand, segs[i..].to_vec());
        }
    }
    (
        segs.first().cloned().unwrap_or_default(),
        segs.get(1..).map(<[String]>::to_vec).unwrap_or_default(),
    )
}

/// `ls-tree -z -l <ref>[:path]`, directories first.
pub async fn ls_tree(dir: &Path, rev: &str, path: &str) -> Result<Vec<TreeRow>, ForgeError> {
    let spec = if path.is_empty() {
        rev.to_string()
    } else {
        format!("{rev}:{path}")
    };
    let out = gitrun::text(dir, &["ls-tree", "-z", "-l", &spec]).await?;
    let mut rows: Vec<TreeRow> = out
        .split('\0')
        .filter(|e| !e.is_empty())
        .filter_map(|e| {
            let (meta, name) = e.split_once('\t')?;
            let mut m = meta.split_whitespace();
            let mode = m.next()?.to_string();
            let kind = m.next()?.to_string();
            let sha = m.next()?.to_string();
            let size = m.next().and_then(|s| s.parse().ok());
            Some(TreeRow {
                mode,
                kind,
                sha,
                size,
                name: name.to_string(),
            })
        })
        .collect();
    rows.sort_by(|a, b| {
        let (at, bt) = (a.kind == "tree", b.kind == "tree");
        bt.cmp(&at).then_with(|| {
            a.name
                .to_lowercase()
                .cmp(&b.name.to_lowercase())
                .then_with(|| a.name.cmp(&b.name))
        })
    });
    Ok(rows)
}

/// Last commit touching `path` (or the ref tip when empty).
pub async fn last_commit(dir: &Path, rev: &str, path: &str) -> Option<Value> {
    let fmt = "--format=%H%x00%h%x00%an%x00%ae%x00%at%x00%s";
    let mut args = vec!["log", "-1", fmt, rev, "--"];
    if !path.is_empty() {
        args.push(path);
    }
    let out = gitrun::text(dir, &args).await.ok()?;
    let out = out.trim();
    if out.is_empty() {
        return None;
    }
    let f: Vec<&str> = out.split('\0').collect();
    if f.len() < 6 {
        return None;
    }
    Some(json!({
        "sha": f[0], "short": f[1], "author": f[2], "email": f[3],
        "at": f[4].parse::<i64>().unwrap_or(0), "subject": f[5],
    }))
}

/// Description: git's `description` file when customised, else the README
/// first line.
pub async fn repo_description(dir: &Path) -> String {
    if let Ok(d) = tokio::fs::read_to_string(dir.join("description")).await {
        let d = d.trim();
        if !d.is_empty() && !d.starts_with("Unnamed repository") {
            return d.to_string();
        }
    }
    String::new()
}

async fn readme_first_line(dir: &Path, branch: &str) -> String {
    let Ok(entries) = ls_tree(dir, branch, "").await else {
        return String::new();
    };
    let Some(e) = entries
        .iter()
        .find(|e| e.kind == "blob" && is_readme_name(&e.name))
    else {
        return String::new();
    };
    if e.size.is_some_and(|s| s >= RENDER_CAP) {
        return String::new();
    }
    let Ok(buf) = gitrun::bytes(
        dir,
        &["cat-file", "blob", &format!("{branch}:{}", e.name)],
        RENDER_CAP as usize,
    )
    .await
    else {
        return String::new();
    };
    if looks_binary(&buf) {
        return String::new();
    }
    String::from_utf8_lossy(&buf)
        .lines()
        .find(|l| !l.trim().is_empty())
        .map(|l| {
            l.trim_start_matches('#')
                .trim()
                .chars()
                .take(160)
                .collect::<String>()
        })
        .unwrap_or_default()
}

/// `^readme(\.(md|markdown|txt))?$`, case-insensitive.
#[must_use]
pub fn is_readme_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "readme" || n == "readme.md" || n == "readme.markdown" || n == "readme.txt"
}

impl ForgeService {
    /// Public origin for absolute URLs: configured `base_url`, else the
    /// request's `host_url` (JSS `publicOrigin`).
    pub(crate) fn origin_of(&self, req: &ForgeRequest) -> String {
        self.cfg.public_origin(req.host_url.as_deref())
    }

    /// Absolute clone URL of `<owner>/<repo>`.
    pub(crate) fn clone_url(&self, req: &ForgeRequest, owner: &str, repo: &str) -> String {
        format!(
            "{}{}/{owner}/{repo}.git",
            self.origin_of(req),
            self.prefix()
        )
    }

    /// Summarise one repository (description + newest ref time).
    pub(crate) async fn repo_summary(&self, owner: &str, repo: &str) -> Option<RepoSummary> {
        let dir = crate::repo::repo_git_dir(&self.repo_root, owner, repo).ok()?;
        let mut description = repo_description(&dir).await;
        let last_push = gitrun::text(
            &dir,
            &[
                "for-each-ref",
                "--sort=-committerdate",
                "--count=1",
                "--format=%(committerdate:unix)",
            ],
        )
        .await
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok());
        if description.is_empty() && last_push.is_some() {
            let branch = crate::repo::browse::default_branch(&dir).await;
            description = readme_first_line(&dir, &branch).await;
        }
        Some(RepoSummary {
            owner: owner.to_string(),
            name: repo.to_string(),
            description,
            last_push,
        })
    }

    /// Summaries of every repo of `owners` (all owners when `None`), capped
    /// at 200, newest push first.
    pub(crate) async fn summaries(&self, owners: Option<&str>) -> Vec<RepoSummary> {
        let all = crate::repo::list_all(&self.repo_root).await;
        let mut out = Vec::new();
        for (o, r) in all {
            if owners.is_some_and(|f| f != o) {
                continue;
            }
            if out.len() >= LIST_CAP {
                break;
            }
            if let Some(s) = self.repo_summary(&o, &r).await {
                out.push(s);
            }
        }
        out.sort_by_key(|s| std::cmp::Reverse(s.last_push.unwrap_or(0)));
        out
    }

    /// `GET /api/repos` and `GET /api/repos/<owner>`.
    pub(crate) async fn h_api_repo_list(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        owner: Option<&str>,
    ) -> Result<ForgeResponse, ForgeError> {
        if !is_read(req) {
            return Ok(api_err(405, "method not allowed"));
        }
        if let Some(o) = owner {
            if !ok_owner(o) {
                return Ok(api_err(404, "not found"));
            }
        }
        // privateRepos: the listing is the caller's own namespace only.
        let filter = if self.cfg.private_repos {
            agent.owner().map(str::to_string)
        } else {
            owner.map(str::to_string)
        };
        let rows = self.summaries(filter.as_deref()).await;
        let repos: Vec<Value> = rows
            .iter()
            .map(|s| {
                json!({
                    "owner": s.owner, "name": s.name, "description": s.description,
                    "lastPush": s.last_push, "parent": Value::Null,
                    "cloneUrl": self.clone_url(req, &s.owner, &s.name),
                    "url": format!("{}/{}/{}", self.prefix(), s.owner, s.name),
                })
            })
            .collect();
        Ok(json_resp(200, &json!({ "repos": repos })))
    }

    /// `GET|PATCH /api/repos/<owner>/<repo>`.
    pub(crate) async fn h_api_repo(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        owner: &str,
        repo: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        if !ok_owner(owner) || !ok_repo(repo) {
            return Ok(api_err(404, "not found"));
        }
        let dir = match self.resolve_repo(owner, repo).await {
            Ok(d) => d,
            Err(_) => return Ok(api_err(404, "not found")),
        };
        if req.method.eq_ignore_ascii_case("PATCH") {
            return self.api_repo_patch(req, agent, owner, repo, &dir).await;
        }
        if !is_read(req) {
            return Ok(api_err(405, "method not allowed"));
        }
        self.api_repo_meta(req, owner, repo, &dir).await
    }

    async fn api_repo_meta(
        &self,
        req: &ForgeRequest,
        owner: &str,
        repo: &str,
        dir: &Path,
    ) -> Result<ForgeResponse, ForgeError> {
        let summary = self.repo_summary(owner, repo).await;
        let branch = crate::repo::browse::default_branch(dir).await;
        let branches = list_refs(dir, "heads").await.unwrap_or_default();
        let tags = list_refs(dir, "tags").await.unwrap_or_default();
        let mut readme = Value::Null;
        if !branches.is_empty() {
            if let Ok(entries) = ls_tree(dir, &branch, "").await {
                if let Some(e) = entries
                    .iter()
                    .find(|e| e.kind == "blob" && is_readme_name(&e.name))
                {
                    if !e.size.is_some_and(|s| s > RENDER_CAP) {
                        if let Ok(buf) = gitrun::bytes(
                            dir,
                            &["cat-file", "blob", &format!("{branch}:{}", e.name)],
                            RENDER_CAP as usize,
                        )
                        .await
                        {
                            if !looks_binary(&buf) {
                                let text = String::from_utf8_lossy(&buf).into_owned();
                                let lower = e.name.to_ascii_lowercase();
                                let is_md = lower.ends_with(".md") || lower.ends_with(".markdown");
                                let base = format!("{}/{owner}/{repo}", self.prefix());
                                let html = if is_md {
                                    markdown::render_with(
                                        &text,
                                        &markdown::MdCtx {
                                            raw_base: format!("{base}/raw/{branch}"),
                                            blob_base: format!("{base}/blob/{branch}"),
                                        },
                                    )
                                } else {
                                    format!("<pre>{}</pre>", crate::request::esc(&text))
                                };
                                readme = json!({"name": e.name, "html": html});
                            }
                        }
                    }
                }
            }
        }
        Ok(json_resp(
            200,
            &json!({
                "owner": owner,
                "name": repo,
                "description": summary.as_ref().map_or("", |s| s.description.as_str()),
                "lastPush": summary.as_ref().and_then(|s| s.last_push),
                "parent": Value::Null,
                "forks": 0,
                "empty": branches.is_empty(),
                "defaultBranch": branch,
                "branches": refs_json(&branches),
                "tags": refs_json(&tags),
                "cloneUrl": self.clone_url(req, owner, repo),
                "readme": readme,
            }),
        ))
    }

    /// JSS `apiRepoPatch`: `{description}`, owner only.
    async fn api_repo_patch(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        owner: &str,
        repo: &str,
        dir: &Path,
    ) -> Result<ForgeResponse, ForgeError> {
        let body = read_json_body(req);
        if matches!(agent, ForgeAgent::Anonymous) {
            return Ok(unauthorised());
        }
        if agent.owner() != Some(owner) {
            return Ok(api_err(403, "only the repo owner may edit the repo"));
        }
        let Some(p) = body else {
            return Ok(api_err(400, "invalid JSON body"));
        };
        let desc = p.get("description").and_then(Value::as_str).map(str::trim);
        let Some(desc) = desc.filter(|d| d.chars().count() <= DESCRIPTION_CAP) else {
            return Ok(api_err(
                422,
                &format!("description must be a string (max {DESCRIPTION_CAP} chars)"),
            ));
        };
        tokio::fs::write(dir.join("description"), format!("{desc}\n")).await?;
        Ok(json_resp(
            200,
            &json!({"owner": owner, "name": repo, "description": desc}),
        ))
    }

    /// Dispatch `/api/repos/<owner>/<repo>/<action>/…` for the actions in
    /// [`crate::router::API_ACTIONS`] (JSS `apiHandler` action switch).
    pub(crate) async fn h_api_repo_action(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        owner: &str,
        repo: &str,
        action: &str,
        tail: &[String],
    ) -> Result<ForgeResponse, ForgeError> {
        if !ok_owner(owner) || !ok_repo(repo) {
            return Ok(api_err(404, "not found"));
        }
        let dir = match self.resolve_repo(owner, repo).await {
            Ok(d) => d,
            Err(_) => return Ok(api_err(404, "not found")),
        };
        if !matches!(action, "issues" | "labels") && !is_read(req) {
            return Ok(api_err(405, "method not allowed"));
        }
        let res = match action {
            "issues" => {
                return self.h_api_issues(req, agent, owner, repo, tail).await;
            }
            "labels" => {
                return self.h_api_labels(req, agent, owner, repo, tail).await;
            }
            "search" if tail.is_empty() => return self.api_search(req, &dir).await,
            "releases" if tail.is_empty() => {
                return self.api_releases(req, owner, repo, &dir).await
            }
            "tree" if !tail.is_empty() => self.api_tree(&dir, tail).await,
            "blob" if tail.len() >= 2 => self.api_blob(&dir, tail).await,
            "commits" if !tail.is_empty() => self.api_commits(req, &dir, tail).await,
            "commit" if tail.len() == 1 => self.api_commit(&dir, &tail[0]).await,
            _ => Ok(api_err(404, "not found")),
        };
        // JSS: any failure inside a read handler is a clean 404.
        Ok(res.unwrap_or_else(|_| api_err(404, "not found")))
    }

    async fn api_tree(&self, dir: &Path, segs: &[String]) -> Result<ForgeResponse, ForgeError> {
        let (rev, rest) = split_ref_path(dir, segs).await;
        if !ok_ref(&rev) || !ok_path(&rest) {
            return Ok(api_err(404, "not found"));
        }
        let dir_path = rest.join("/");
        let entries = ls_tree(dir, &rev, &dir_path).await?;
        let sem = Arc::new(Semaphore::new(8));
        let mut set: JoinSet<(usize, Option<Value>)> = JoinSet::new();
        for (i, e) in entries.iter().enumerate().take(LAST_COMMIT_CAP) {
            let (sem, d, r) = (sem.clone(), dir.to_path_buf(), rev.clone());
            let p = if dir_path.is_empty() {
                e.name.clone()
            } else {
                format!("{dir_path}/{}", e.name)
            };
            set.spawn(async move {
                let _permit = sem.acquire_owned().await.ok();
                (i, last_commit(&d, &r, &p).await)
            });
        }
        let mut last: Vec<Option<Value>> = vec![None; entries.len()];
        while let Some(Ok((i, v))) = set.join_next().await {
            last[i] = v;
        }
        let out: Vec<Value> = entries
            .iter()
            .zip(last)
            .map(|(e, lc)| {
                json!({
                    "mode": e.mode, "type": e.kind, "sha": e.sha, "size": e.size,
                    "name": e.name, "lastCommit": lc,
                })
            })
            .collect();
        Ok(json_resp(
            200,
            &json!({"ref": rev, "path": dir_path, "entries": out}),
        ))
    }

    async fn api_blob(&self, dir: &Path, segs: &[String]) -> Result<ForgeResponse, ForgeError> {
        let (rev, rest) = split_ref_path(dir, segs).await;
        if !ok_ref(&rev) || rest.is_empty() || !ok_path(&rest) {
            return Ok(api_err(404, "not found"));
        }
        let p = rest.join("/");
        let spec = format!("{rev}:{p}");
        let ty = gitrun::text(dir, &["cat-file", "-t", &spec]).await?;
        if ty.trim() != "blob" {
            return Ok(api_err(404, "not found"));
        }
        let size: u64 = gitrun::text(dir, &["cat-file", "-s", &spec])
            .await?
            .trim()
            .parse()
            .unwrap_or(0);
        let mut out = json!({
            "ref": rev, "path": p, "size": size,
            "binary": false, "tooLarge": false, "content": Value::Null,
        });
        if size > RENDER_CAP {
            out["tooLarge"] = json!(true);
        } else {
            let buf =
                gitrun::bytes(dir, &["cat-file", "blob", &spec], RENDER_CAP as usize + 1).await?;
            if looks_binary(&buf) {
                out["binary"] = json!(true);
            } else {
                out["content"] = json!(String::from_utf8_lossy(&buf));
            }
        }
        Ok(json_resp(200, &out))
    }

    async fn api_commits(
        &self,
        req: &ForgeRequest,
        dir: &Path,
        segs: &[String],
    ) -> Result<ForgeResponse, ForgeError> {
        let rev = segs.join("/");
        if !ok_ref(&rev) && !is_sha(&rev) {
            return Ok(api_err(404, "not found"));
        }
        let page = req
            .query_param("page")
            .and_then(|p| p.trim().parse::<i64>().ok())
            .unwrap_or(1)
            .clamp(1, 10000) as usize;
        let skip = ((page - 1) * PER_PAGE).to_string();
        let n = format!("-n{}", PER_PAGE + 1);
        let out = gitrun::text(
            dir,
            &[
                "log",
                "-z",
                &format!("--skip={skip}"),
                &n,
                "--format=%H%x00%h%x00%an%x00%ae%x00%at%x00%s",
                &rev,
                "--",
            ],
        )
        .await?;
        let f: Vec<&str> = out.split('\0').collect();
        let mut commits = Vec::new();
        let mut i = 0;
        while i + 5 < f.len() {
            commits.push(json!({
                "sha": f[i].trim_start_matches('\n'), "short": f[i + 1], "author": f[i + 2],
                "email": f[i + 3], "at": f[i + 4].parse::<i64>().unwrap_or(0), "subject": f[i + 5],
            }));
            i += 6;
        }
        let has_more = commits.len() > PER_PAGE;
        commits.truncate(PER_PAGE);
        Ok(json_resp(
            200,
            &json!({"ref": rev, "page": page, "perPage": PER_PAGE, "hasMore": has_more, "commits": commits}),
        ))
    }

    async fn api_commit(&self, dir: &Path, sha: &str) -> Result<ForgeResponse, ForgeError> {
        if !is_sha(sha) {
            return Ok(api_err(404, "not found"));
        }
        let out = gitrun::text(
            dir,
            &[
                "show",
                "--no-patch",
                "--format=%H%x00%h%x00%an%x00%ae%x00%at%x00%P%x00%B",
                sha,
                "--",
            ],
        )
        .await;
        let Ok(out) = out else {
            return Ok(api_err(404, "not found"));
        };
        let mut f = out.splitn(7, '\0');
        let (full, short, author, email, at, parents, msg) = (
            f.next().unwrap_or(""),
            f.next().unwrap_or(""),
            f.next().unwrap_or(""),
            f.next().unwrap_or(""),
            f.next().unwrap_or("0"),
            f.next().unwrap_or(""),
            f.next().unwrap_or(""),
        );
        let patch = gitrun::text(
            dir,
            &["show", "--format=", "--patch", "--no-color", sha, "--"],
        )
        .await
        .unwrap_or_default();
        let files = crate::diff::parse_patch(&patch);
        Ok(json_resp(
            200,
            &json!({
                "sha": full.trim(), "short": short, "author": author, "email": email,
                "at": at.parse::<i64>().unwrap_or(0),
                "parents": parents.split(' ').filter(|p| !p.is_empty()).collect::<Vec<_>>(),
                "message": msg.trim(),
                "files": files,
            }),
        ))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::gitrun::testutil::demo_repo;
    use crate::ForgeConfig;
    use bytes::Bytes;
    use tempfile::TempDir;

    pub(crate) fn rq(method: &str, path: &str, query: &str, body: &str) -> ForgeRequest {
        ForgeRequest {
            method: method.into(),
            path: path.into(),
            query: query.into(),
            headers: vec![],
            raw_body: Bytes::from(body.to_string()),
            host_url: Some("https://pod.example".into()),
        }
    }

    pub(crate) fn casey() -> ForgeAgent {
        ForgeAgent::Pod {
            webid: "https://pod.example/casey/profile/card#me".into(),
            username: "casey".into(),
        }
    }

    pub(crate) fn dana() -> ForgeAgent {
        ForgeAgent::Pod {
            webid: "https://pod.example/dana/profile/card#me".into(),
            username: "dana".into(),
        }
    }

    /// A service over a temp dir holding the JSS-style `casey/demo` repo.
    pub(crate) fn fixture() -> (TempDir, ForgeService, String) {
        let td = TempDir::new().unwrap();
        let (_bare, sha2) = demo_repo(td.path());
        let svc = ForgeService::new(ForgeConfig::default(), td.path()).unwrap();
        (td, svc, sha2)
    }

    pub(crate) async fn get_json(
        svc: &ForgeService,
        path: &str,
        query: &str,
        agent: ForgeAgent,
    ) -> (u16, Value) {
        let r = svc.handle(rq("GET", path, query, ""), agent).await.unwrap();
        let v = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        (r.status, v)
    }

    #[tokio::test]
    async fn repo_list_has_stable_shape() {
        let (_td, svc, _) = fixture();
        let (st, v) = get_json(&svc, "/forge/api/repos", "", ForgeAgent::Anonymous).await;
        assert_eq!(st, 200);
        let demo = v["repos"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["owner"] == "casey" && r["name"] == "demo")
            .expect("casey/demo listed");
        assert_eq!(demo["cloneUrl"], "https://pod.example/forge/casey/demo.git");
        assert!(demo["lastPush"].is_u64());
        let (_, own) = get_json(&svc, "/forge/api/repos/casey", "", ForgeAgent::Anonymous).await;
        assert_eq!(own["repos"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn repo_meta_carries_branches_tags_readme_html() {
        let (_td, svc, _) = fixture();
        let (st, m) = get_json(
            &svc,
            "/forge/api/repos/casey/demo",
            "",
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(st, 200);
        assert_eq!(m["defaultBranch"], "main");
        assert_eq!(m["empty"], false);
        assert!(m["branches"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["name"] == "main"));
        assert!(m["tags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "v1.0"));
        assert_eq!(m["cloneUrl"], "https://pod.example/forge/casey/demo.git");
        let html = m["readme"]["html"].as_str().unwrap();
        assert!(html.contains("<h1>Demo Project</h1>"));
        assert!(!html.contains("<script>alert"), "README html is escaped");
    }

    #[tokio::test]
    async fn tree_entries_are_typed_sized_sorted_with_last_commits() {
        let (_td, svc, _) = fixture();
        let (st, v) = get_json(
            &svc,
            "/forge/api/repos/casey/demo/tree/main",
            "",
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(st, 200);
        let entries = v["entries"].as_array().unwrap();
        assert_eq!(entries[0]["type"], "tree", "folders sort first");
        let readme = entries.iter().find(|e| e["name"] == "README.md").unwrap();
        assert_eq!(readme["type"], "blob");
        assert!(readme["size"].as_u64().unwrap() > 0);
        assert!(readme["lastCommit"]["subject"].is_string());
        let (st, sub) = get_json(
            &svc,
            "/forge/api/repos/casey/demo/tree/main/src",
            "",
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(st, 200);
        assert_eq!(sub["path"], "src");
        assert_eq!(sub["entries"][0]["name"], "main.js");
    }

    #[tokio::test]
    async fn blob_returns_content_for_text_and_flags_binary() {
        let (_td, svc, _) = fixture();
        let (_, t) = get_json(
            &svc,
            "/forge/api/repos/casey/demo/blob/main/src/main.js",
            "",
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(t["binary"], false);
        assert_eq!(t["tooLarge"], false);
        assert!(t["content"].as_str().unwrap().contains("return 2;"));
        assert!(t["size"].is_u64());
        let (_, b) = get_json(
            &svc,
            "/forge/api/repos/casey/demo/blob/main/blob.bin",
            "",
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(b["binary"], true);
        assert!(b["content"].is_null());
    }

    #[tokio::test]
    async fn commits_paginate_with_has_more() {
        let (_td, svc, _) = fixture();
        let (_, p1) = get_json(
            &svc,
            "/forge/api/repos/casey/demo/commits/main",
            "",
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(p1["page"], 1);
        assert_eq!(p1["perPage"], 30);
        assert_eq!(p1["commits"].as_array().unwrap().len(), 2);
        assert_eq!(p1["hasMore"], false);
        assert_eq!(p1["commits"][0]["subject"], "tweak main");
        let (_, p2) = get_json(
            &svc,
            "/forge/api/repos/casey/demo/commits/main",
            "page=2",
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(p2["commits"].as_array().unwrap().len(), 0);
        assert_eq!(p2["hasMore"], false);
    }

    #[tokio::test]
    async fn commit_returns_structured_diff() {
        let (_td, svc, sha2) = fixture();
        let (st, c) = get_json(
            &svc,
            &format!("/forge/api/repos/casey/demo/commit/{sha2}"),
            "",
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(st, 200);
        assert_eq!(c["sha"], sha2);
        assert_eq!(c["message"], "tweak main");
        let files = c["files"].as_array().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0]["name"], "src/main.js");
        assert_eq!(files[0]["adds"], 1);
        assert_eq!(files[0]["dels"], 1);
        let lines = files[0]["hunks"][0]["lines"].as_array().unwrap();
        assert!(lines
            .iter()
            .any(|l| l["type"] == "add" && l["text"].as_str().unwrap().contains("return 2;")));
        assert!(lines
            .iter()
            .any(|l| l["type"] == "del" && l["text"].as_str().unwrap().contains("return 1;")));
        assert!(lines
            .iter()
            .all(|l| l["type"] != "add" || l["newLine"].is_u64()));
        // a branch name is not a sha
        let (st, _) = get_json(
            &svc,
            "/forge/api/repos/casey/demo/commit/main",
            "",
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(st, 404);
    }

    #[tokio::test]
    async fn unknown_repo_and_traversal_are_clean_json_4xx() {
        let (_td, svc, _) = fixture();
        let (st, v) = get_json(
            &svc,
            "/forge/api/repos/casey/nope",
            "",
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(st, 404);
        assert!(v["error"].is_string());
        for p in [
            "/forge/api/repos/casey/demo/blob/main/../../etc/passwd",
            "/forge/api/repos/casey/demo/blob/main/%2e%2e/x",
            "/forge/api/repos/casey/demo/blob/main/a%5Cb",
            "/forge/api/repos/casey/demo/blob/--upload-pack=x/f",
        ] {
            let (st, _) = get_json(&svc, p, "", ForgeAgent::Anonymous).await;
            assert!((400..500).contains(&st), "{p} got {st}");
        }
    }

    #[tokio::test]
    async fn repo_patch_description_is_owner_only() {
        let (td, svc, _) = fixture();
        let patch = |agent: ForgeAgent, body: &str| {
            let svc = svc.clone();
            let body = body.to_string();
            async move {
                svc.handle(rq("PATCH", "/forge/api/repos/casey/demo", "", &body), agent)
                    .await
                    .unwrap()
            }
        };
        assert_eq!(
            patch(ForgeAgent::Anonymous, r#"{"description":"x"}"#)
                .await
                .status,
            401
        );
        assert_eq!(patch(dana(), r#"{"description":"nope"}"#).await.status, 403);
        assert_eq!(patch(casey(), "not json").await.status, 400);
        assert_eq!(patch(casey(), r#"{"description":5}"#).await.status, 422);
        let long = format!(r#"{{"description":"{}"}}"#, "x".repeat(513));
        assert_eq!(patch(casey(), &long).await.status, 422);
        let ok = patch(
            casey(),
            r#"{"description":"A demo repo with <angle> brackets"}"#,
        )
        .await;
        assert_eq!(ok.status, 200);
        let (_, meta) = get_json(
            &svc,
            "/forge/api/repos/casey/demo",
            "",
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(meta["description"], "A demo repo with <angle> brackets");
        let file =
            std::fs::read_to_string(td.path().join("repos/casey/demo.git/description")).unwrap();
        assert_eq!(file, "A demo repo with <angle> brackets\n");
        // other methods on the meta route
        let r = svc
            .handle(rq("DELETE", "/forge/api/repos/casey/demo", "", ""), casey())
            .await
            .unwrap();
        assert_eq!(r.status, 405);
    }

    #[tokio::test]
    async fn options_allows_patch() {
        let (_td, svc, _) = fixture();
        let r = svc
            .handle(
                rq("OPTIONS", "/forge/api/repos/casey/demo", "", ""),
                ForgeAgent::Anonymous,
            )
            .await
            .unwrap();
        let m = r
            .headers
            .iter()
            .find(|(k, _)| k == "access-control-allow-methods")
            .unwrap();
        assert!(m.1.contains("PATCH"));
    }
}
