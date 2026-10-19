//! Pull requests: the `pulls` spine index, the JSON API and the server-rendered
//! pages.
//!
//! Follows the JSS forge `apiPullList`, `apiPullGet`, `apiPullCreate`,
//! `apiPullComment`, `apiPullState`, `pullDiffData`, `pullsListPage`,
//! `pullPage`, `pullCommitsPage`, `pullFilesPage` and `newPullPage` (cited by
//! name only). Titles, bodies and comments reuse the issue machinery: the spine
//! keeps only [`ThreadPointer`]s, the words live in the author's pod (or in
//! forge-hosted storage for a podless `did:nostr` agent), and pull numbering is
//! separate from issue numbering (a documented JSS deviation from GitHub).
//! Merging lives in [`crate::merge`].
//!
//! # Integration points
//!
//! * [`PullLabels`]: how label names on a pull request resolve to
//!   `{name, color}`; the labels tier installs its own with
//!   [`ForgeService::with_pull_labels`]. `PUT pulls/<n>/labels` is served
//!   through [`ForgeService::put_item_labels`].
//! * [`render_body_html`]: renders thread bodies with the crate's escape-first
//!   markdown renderer.
//! * [`crate::merge::TipRecorder`]: the anchoring hook called after a merge.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::bodies::{self, BodyOutcome, HostedReader};
use crate::compare::{self, commit_rows, query_decoded, valid_owner, valid_ref};
use crate::error::ForgeError;
use crate::html::{agent_label, crumbs, page};
use crate::merge::{NoopTipRecorder, TipRecorder};
use crate::prgit;
use crate::repo;
use crate::request::{esc, parse_form};
use crate::spine::issues::{IssueState, ThreadPointer};
use crate::spine::SpineStore;
use crate::{ForgeAgent, ForgeRequest, ForgeResponse, ForgeService};

/// The `pulls` spine kind (also the on-disk subdirectory name).
pub const KIND: &str = "pulls";

/// Pull requests per list page (JSS `ISSUES_PER_PAGE`).
pub const PULLS_PER_PAGE: usize = 25;
/// Longest title in characters (JSS `ISSUE_TITLE_CAP`).
pub const TITLE_CAP: usize = 256;
/// Largest body in bytes (JSS `ISSUE_BODY_CAP`).
pub const BODY_CAP: usize = 64 * 1024;
/// Most thread entries per pull request (JSS `THREAD_CAP`).
pub const THREAD_CAP: usize = 500;

/// The head of a pull request: a branch of `<owner>`'s same-named repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullHead {
    /// Head owner namespace.
    pub owner: String,
    /// Head repository name.
    pub repo: String,
    /// Branch name.
    #[serde(rename = "ref")]
    pub ref_name: String,
}

/// How a pull request was merged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MergeRecord {
    /// The resulting tip (the head itself for a fast-forward).
    pub sha: String,
    /// Author id of the merger.
    pub merged_by: String,
    /// Unix seconds.
    pub at: u64,
    /// Base tip at merge time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_sha: Option<String>,
    /// Head tip at merge time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_sha: Option<String>,
    /// `true` when no merge commit was made.
    #[serde(default)]
    pub fast_forward: bool,
}

/// One pull request's spine entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PullEntry {
    /// Allocated number.
    pub number: u64,
    /// Title (kept in the spine for cheap listing).
    pub title: String,
    /// `open`, `closed` or `merged`.
    pub state: IssueState,
    /// Author id (WebID or `did:nostr:<hex>`).
    pub author: String,
    /// Unix seconds of creation.
    pub created_at: u64,
    /// Target branch of this repository.
    pub base: String,
    /// Source branch.
    pub head: PullHead,
    /// Merge details once merged.
    #[serde(default)]
    pub merged: Option<MergeRecord>,
    /// Label names (resolved through [`PullLabels`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
    /// Thread pointers; the opening body is index 0.
    pub thread: Vec<ThreadPointer>,
}

impl PullEntry {
    /// The head as a compare spec, `owner:ref` (JSS `prHeadSpec`).
    #[must_use]
    pub fn head_spec(&self) -> String {
        format!("{}:{}", self.head.owner, self.head.ref_name)
    }
}

/// The pull index of one repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullIndex {
    /// Next number to allocate.
    pub next: u64,
    /// Pull requests keyed by number.
    #[serde(default)]
    pub pulls: BTreeMap<u64, PullEntry>,
}

impl Default for PullIndex {
    fn default() -> Self {
        Self {
            next: 1,
            pulls: BTreeMap::new(),
        }
    }
}

/// Load a pull index (default when absent; a corrupt file is an error rather
/// than a silent reset).
pub async fn load_pull_index(
    store: &dyn SpineStore,
    owner: &str,
    repo: &str,
) -> Result<PullIndex, ForgeError> {
    match store.load(KIND, owner, repo).await? {
        Some(b) => {
            let idx: PullIndex = serde_json::from_slice(&b).map_err(|e| {
                ForgeError::Backend(format!("corrupt pull index {owner}/{repo}: {e}"))
            })?;
            if idx.next < 1 {
                return Err(ForgeError::Backend(format!(
                    "corrupt pull index {owner}/{repo}: next < 1"
                )));
            }
            Ok(idx)
        }
        None => Ok(PullIndex::default()),
    }
}

/// Persist a pull index atomically.
pub async fn save_pull_index(
    store: &dyn SpineStore,
    owner: &str,
    repo: &str,
    idx: &PullIndex,
) -> Result<(), ForgeError> {
    store
        .store(KIND, owner, repo, &serde_json::to_vec(idx)?)
        .await
}

/// Lowercase state name as used on the wire.
#[must_use]
pub fn state_str(s: IssueState) -> &'static str {
    match s {
        IssueState::Open => "open",
        IssueState::Closed => "closed",
        IssueState::Merged => "merged",
    }
}

/// Resolve label names on a pull request to `{name, color}` objects.
///
/// Integration point for the labels tier, which owns the per-repository label
/// set. The default [`PlainLabels`] returns each name with a neutral colour.
pub trait PullLabels: Send + Sync {
    /// Resolve `names` for `<owner>/<repo>`.
    fn resolve(&self, owner: &str, repo: &str, names: &[String]) -> Vec<serde_json::Value>;
}

/// The default [`PullLabels`]: names only, neutral colour.
#[derive(Debug, Clone, Copy, Default)]
pub struct PlainLabels;

impl PullLabels for PlainLabels {
    fn resolve(&self, _owner: &str, _repo: &str, names: &[String]) -> Vec<serde_json::Value> {
        names
            .iter()
            .map(|n| serde_json::json!({"name": n, "color": "ededed"}))
            .collect()
    }
}

/// Pull-request runtime state carried by the service: the merge hook, the
/// label resolver and the git capability detected at start-up.
#[derive(Clone)]
pub struct PrExt {
    pub(crate) tip: Arc<dyn TipRecorder>,
    pub(crate) labels: Arc<dyn PullLabels>,
    pub(crate) merge_tree_ok: bool,
    pub(crate) git_version: String,
}

impl Default for PrExt {
    fn default() -> Self {
        let v = crate::merge::detected_git_version();
        Self {
            tip: Arc::new(NoopTipRecorder),
            labels: Arc::new(PlainLabels),
            merge_tree_ok: crate::merge::merge_tree_supported(v),
            git_version: v.to_string(),
        }
    }
}

impl std::fmt::Debug for PrExt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrExt")
            .field("merge_tree_ok", &self.merge_tree_ok)
            .field("git_version", &self.git_version)
            .finish()
    }
}

/// Render a thread body to HTML with the escape-first markdown renderer.
#[must_use]
pub fn render_body_html(text: &str) -> String {
    crate::markdown::render(text)
}

/// The owner namespace a stored author id maps to (JSS `ownerFromAgent`).
fn author_owner(author: &str) -> Option<String> {
    if let Some(h) = author.strip_prefix("did:nostr:") {
        return (h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| h.to_ascii_lowercase());
    }
    let rest = author
        .strip_prefix("https://")
        .or_else(|| author.strip_prefix("http://"))?;
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    let host = host.split(':').next().unwrap_or("");
    let segs: Vec<&str> = path
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    let name = if segs.len() >= 2 && segs[0] != "profile" {
        segs[0].to_string()
    } else {
        host.split('.').next().unwrap_or("").to_string()
    };
    valid_owner(&name).then_some(name)
}

/// Display name of a stored author id.
fn author_display(author: &str) -> String {
    match author_owner(author) {
        Some(o) => agent_label(&o),
        None => author.to_string(),
    }
}

/// Additive author metadata for the JSON API (JSS `authorMeta`, without `npub`).
fn author_meta(author: &str) -> serde_json::Value {
    let nostr = author.starts_with("did:nostr:");
    serde_json::json!({
        "id": author,
        "displayName": author_display(author),
        "kind": if nostr { "nostr" } else { "webid" },
    })
}

/// Parsed pull-request request body (JSON or form).
#[derive(Debug, Default)]
struct PrInput {
    title: Option<String>,
    body: Option<String>,
    base: Option<String>,
    head: Option<String>,
    resource_url: Option<String>,
    expected_base: Option<String>,
}

fn parse_input(req: &ForgeRequest) -> Option<PrInput> {
    let ct = req.header("content-type").unwrap_or("");
    let raw = String::from_utf8_lossy(&req.raw_body);
    if ct.contains("application/json") || raw.trim_start().starts_with('{') {
        let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
        return Some(PrInput {
            title: s("title"),
            body: s("body"),
            base: s("base"),
            head: s("head"),
            resource_url: s("resourceUrl"),
            expected_base: s("expectedBase"),
        });
    }
    let pairs = parse_form(&raw);
    let f = |k: &str| {
        pairs
            .iter()
            .find(|(kk, _)| kk == k)
            .map(|(_, v)| v.clone())
            .filter(|v| !v.is_empty())
    };
    Some(PrInput {
        title: f("title"),
        body: f("body"),
        base: f("base"),
        head: f("head"),
        resource_url: f("resourceUrl"),
        expected_base: f("expectedBase"),
    })
}

/// Turn a successful action response into a 303 to `location` (form posts).
fn redirect_on_ok(resp: ForgeResponse, location: &str) -> ForgeResponse {
    if (200..300).contains(&resp.status) {
        ForgeResponse::redirect(303, location)
    } else {
        resp
    }
}

impl ForgeService {
    /// Install the label resolver for pull requests (integration point).
    #[must_use]
    pub fn with_pull_labels(mut self, labels: Arc<dyn PullLabels>) -> Self {
        self.pr.labels = labels;
        self
    }

    fn hosted_url(&self, resource_url: &str) -> String {
        match resource_url.strip_prefix(crate::hosted::REF_SCHEME) {
            Some(rest) => format!("{}/api/hosted/{rest}", self.prefix()),
            None => resource_url.to_string(),
        }
    }

    /// The "Pull requests" link (with an open-count badge) for a repo home.
    pub(crate) async fn pulls_tab(&self, owner: &str, name: &str) -> String {
        let open = load_pull_index(self.spine.as_ref(), owner, name)
            .await
            .map(|i| {
                i.pulls
                    .values()
                    .filter(|p| p.state == IssueState::Open)
                    .count()
            })
            .unwrap_or(0);
        let badge = if open > 0 {
            format!(" <span class=\"badge\">{open}</span>")
        } else {
            String::new()
        };
        format!(
            "<nav class=\"crumbs\"><a href=\"{}/{}/{}/pulls\">Pull requests{badge}</a></nav>",
            esc(&self.prefix()),
            esc(owner),
            esc(name)
        )
    }

    /// Per-entry thread JSON: pointer fields plus the re-fetched body.
    async fn thread_json(&self, entries: &[ThreadPointer]) -> Vec<serde_json::Value> {
        let hosted: Arc<dyn HostedReader> = self.hosted.clone();
        let rendered =
            bodies::render_thread(entries, self.loopback.clone(), Some(hosted), &self.cfg).await;
        entries
            .iter()
            .zip(rendered.iter())
            .map(|(p, r)| {
                let (body, removed) = match &r.body {
                    BodyOutcome::Present(b) => (Some(b.clone()), false),
                    _ => (None, true),
                };
                serde_json::json!({
                    "author": p.author,
                    "at": p.at,
                    "resourceUrl": self.hosted_url(&p.resource_url),
                    "hosted": p.hosted,
                    "body": body,
                    "removed": removed,
                    "authorInfo": author_meta(&p.author),
                    "html": body.as_deref().map(render_body_html),
                })
            })
            .collect()
    }

    fn pull_summary(
        &self,
        defs: &[crate::spine::issues::Label],
        p: &PullEntry,
    ) -> serde_json::Value {
        serde_json::json!({
            "number": p.number,
            "title": p.title,
            "state": state_str(p.state),
            "author": p.author,
            "authorInfo": author_meta(&p.author),
            "createdAt": p.created_at,
            "base": p.base,
            "head": p.head,
            "merged": p.merged,
            "labels": crate::labels::resolve_labels(p.labels.as_deref().unwrap_or(&[]), defs),
            "comments": p.thread.len().saturating_sub(1),
        })
    }

    /// Router for `api/repos/<o>/<n>/pulls[/<num>[/<verb>]]` (JSS
    /// `apiPullsHandler`).
    pub(crate) async fn h_api_pulls(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        owner: &str,
        name: &str,
        tail: &[String],
    ) -> Result<ForgeResponse, ForgeError> {
        self.resolve_repo(owner, name).await?;
        let m = req.method.to_ascii_uppercase();
        let read = m == "GET" || m == "HEAD";
        let not_allowed = || Ok(ForgeResponse::error(405, "method not allowed"));
        let not_found = || Ok(ForgeResponse::error(404, "not found"));
        if tail.is_empty() {
            return match m.as_str() {
                "POST" => self.api_pull_create(req, agent, owner, name).await,
                _ if read => self.api_pull_list(req, owner, name).await,
                _ => not_allowed(),
            };
        }
        let Some(number) = parse_number(&tail[0]) else {
            return not_found();
        };
        match tail.get(1).map(String::as_str) {
            None if read => self.api_pull_get(owner, name, number).await,
            None => not_allowed(),
            Some("comments" | "close" | "reopen" | "merge") if m != "POST" => not_allowed(),
            Some("comments") if tail.len() == 2 => {
                self.api_pull_comment(req, agent, owner, name, number).await
            }
            Some("merge") if tail.len() == 2 => {
                let exp = parse_input(req).and_then(|i| i.expected_base);
                self.merge_pull(agent, owner, name, number, exp.as_deref())
                    .await
            }
            Some(v @ ("close" | "reopen")) if tail.len() == 2 => {
                let st = if v == "close" {
                    IssueState::Closed
                } else {
                    IssueState::Open
                };
                self.api_pull_state(agent, owner, name, number, st).await
            }
            Some("labels") if tail.len() == 2 && req.method.eq_ignore_ascii_case("PUT") => {
                self.put_item_labels(
                    req,
                    agent,
                    owner,
                    name,
                    number,
                    crate::labels::ItemKind::Pull,
                )
                .await
            }
            _ => not_found(),
        }
    }

    async fn api_pull_list(
        &self,
        req: &ForgeRequest,
        owner: &str,
        name: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        let idx = load_pull_index(self.spine.as_ref(), owner, name).await?;
        let mut all: Vec<&PullEntry> = idx.pulls.values().collect();
        all.sort_by_key(|p| std::cmp::Reverse(p.number));
        let count = |s| all.iter().filter(|p| p.state == s).count();
        let state = list_state(req);
        let label = query_decoded(req, "label");
        let page_no = list_page(req);
        let filtered: Vec<&&PullEntry> = all
            .iter()
            .filter(|p| {
                p.state == state
                    && (label.is_empty() || p.labels.as_ref().is_some_and(|l| l.contains(&label)))
            })
            .collect();
        let defs = self.label_defs(owner, name).await.unwrap_or_default();
        let pulls: Vec<_> = filtered
            .iter()
            .skip((page_no - 1) * PULLS_PER_PAGE)
            .take(PULLS_PER_PAGE)
            .map(|p| self.pull_summary(&defs, p))
            .collect();
        Ok(ForgeResponse::json(
            200,
            &serde_json::json!({
                "state": state_str(state),
                "page": page_no,
                "perPage": PULLS_PER_PAGE,
                "hasMore": filtered.len() > page_no * PULLS_PER_PAGE,
                "openCount": count(IssueState::Open),
                "mergedCount": count(IssueState::Merged),
                "closedCount": count(IssueState::Closed),
                "pulls": pulls,
            }),
        ))
    }

    async fn api_pull_get(
        &self,
        owner: &str,
        name: &str,
        number: u64,
    ) -> Result<ForgeResponse, ForgeError> {
        let idx = load_pull_index(self.spine.as_ref(), owner, name).await?;
        let Some(pr) = idx.pulls.get(&number) else {
            return Ok(ForgeResponse::error(404, "not found"));
        };
        let info = if pr.state == IssueState::Open {
            self.pull_merge_info(owner, name, pr).await?
        } else {
            let dir = repo::repo_git_dir(&self.repo_root, owner, name)?;
            let base_sha = if valid_ref(&pr.base) {
                prgit::rev_parse(&dir, &format!("refs/heads/{}", pr.base)).await
            } else {
                None
            };
            crate::merge::MergeInfo {
                base_sha,
                ..Default::default()
            }
        };
        let thread = self.thread_json(&pr.thread).await;
        let defs = self.label_defs(owner, name).await.unwrap_or_default();
        let mut v = self.pull_summary(&defs, pr);
        let obj = v.as_object_mut().expect("object");
        obj.remove("comments");
        obj.insert("baseSha".into(), serde_json::json!(info.base_sha));
        obj.insert(
            "head".into(),
            serde_json::json!({
                "owner": pr.head.owner, "repo": pr.head.repo,
                "ref": pr.head.ref_name, "sha": info.head_sha,
            }),
        );
        obj.insert("mergeable".into(), serde_json::json!(info.mergeable));
        obj.insert("conflicts".into(), serde_json::json!(info.conflicts));
        obj.insert("thread".into(), serde_json::json!(thread));
        Ok(ForgeResponse::json(200, &v))
    }

    async fn api_pull_create(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        owner: &str,
        name: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        if matches!(agent, ForgeAgent::Anonymous) {
            return Ok(ForgeResponse::error(401, "authentication required"));
        }
        let Some(inp) = parse_input(req) else {
            return Ok(ForgeResponse::error(400, "invalid JSON body"));
        };
        let title = inp.title.as_deref().map(str::trim).unwrap_or("");
        if title.is_empty() || title.chars().count() > TITLE_CAP {
            return Ok(ForgeResponse::error(
                422,
                format!("title required (1-{TITLE_CAP} chars)"),
            ));
        }
        if inp.body.as_deref().map_or(0, str::len) > BODY_CAP {
            return Ok(ForgeResponse::error(422, "body too large"));
        }
        let base_ref = inp.base.clone().unwrap_or_default();
        if !valid_ref(&base_ref) {
            return Ok(ForgeResponse::error(
                422,
                "base must be a branch of this repository",
            ));
        }
        let dir = repo::repo_git_dir(&self.repo_root, owner, name)?;
        let Some(base_sha) = prgit::rev_parse(&dir, &format!("refs/heads/{base_ref}")).await else {
            return Ok(ForgeResponse::error(
                422,
                format!("base branch {base_ref} does not exist"),
            ));
        };
        let Some(head) = self
            .resolve_head(owner, name, inp.head.as_deref().unwrap_or(""))
            .await?
        else {
            return Ok(ForgeResponse::error(
                422,
                "head must be <branch> or <owner>:<branch> of a same-named repo",
            ));
        };
        let counts = prgit::text(
            &dir,
            &[
                "rev-list",
                "--left-right",
                "--count",
                &format!("{base_sha}...{}", head.sha),
            ],
        )
        .await?;
        let ahead: u64 = counts
            .split_whitespace()
            .nth(1)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        if ahead == 0 {
            return Ok(ForgeResponse::error(
                422,
                "no commits between base and head",
            ));
        }
        let _g = prgit::pull_locks().lock(&format!("{owner}/{name}")).await;
        let mut idx = load_pull_index(self.spine.as_ref(), owner, name).await?;
        if matches!(agent, ForgeAgent::Pod { .. }) && inp.resource_url.is_none() {
            return Ok(ForgeResponse::error(422, "resourceUrl required"));
        }
        if agent.is_nostr() && inp.body.as_deref().is_none_or(|b| b.trim().is_empty()) {
            return Ok(ForgeResponse::error(422, "body required"));
        }
        let ptr = self
            .make_pointer(
                req,
                agent,
                owner,
                name,
                inp.resource_url.as_deref(),
                inp.body.as_deref(),
            )
            .await?;
        let number = idx.next;
        let hosted = ptr.hosted;
        let resource_url = self.hosted_url(&ptr.resource_url);
        idx.next = number + 1;
        idx.pulls.insert(
            number,
            PullEntry {
                number,
                title: title.to_string(),
                state: IssueState::Open,
                author: agent.author_id(),
                created_at: crate::now_secs(),
                base: base_ref,
                head: PullHead {
                    owner: head.owner,
                    repo: head.repo,
                    ref_name: head.ref_name,
                },
                merged: None,
                labels: None,
                thread: vec![ptr],
            },
        );
        save_pull_index(self.spine.as_ref(), owner, name, &idx).await?;
        let mut v = serde_json::json!({
            "number": number,
            "url": format!("{}/{owner}/{name}/pulls/{number}", self.prefix()),
            "resourceUrl": resource_url,
        });
        if hosted {
            v["hosted"] = serde_json::json!(true);
        }
        Ok(ForgeResponse::json(201, &v))
    }

    async fn api_pull_comment(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        owner: &str,
        name: &str,
        number: u64,
    ) -> Result<ForgeResponse, ForgeError> {
        if matches!(agent, ForgeAgent::Anonymous) {
            return Ok(ForgeResponse::error(401, "authentication required"));
        }
        let Some(inp) = parse_input(req) else {
            return Ok(ForgeResponse::error(400, "invalid JSON body"));
        };
        let has_body = inp.body.as_deref().is_some_and(|b| !b.trim().is_empty());
        if inp.resource_url.is_none() && !has_body {
            return Ok(ForgeResponse::error(422, "body required"));
        }
        if inp.body.as_deref().map_or(0, str::len) > BODY_CAP {
            return Ok(ForgeResponse::error(422, "body too large"));
        }
        let _g = prgit::pull_locks().lock(&format!("{owner}/{name}")).await;
        let mut idx = load_pull_index(self.spine.as_ref(), owner, name).await?;
        let Some(pr) = idx.pulls.get_mut(&number) else {
            return Ok(ForgeResponse::error(404, "not found"));
        };
        if pr.thread.len() >= THREAD_CAP {
            return Ok(ForgeResponse::error(422, "thread is full"));
        }
        let ptr = self
            .make_pointer(
                req,
                agent,
                owner,
                name,
                inp.resource_url.as_deref(),
                inp.body.as_deref(),
            )
            .await?;
        let hosted = ptr.hosted;
        let url = self.hosted_url(&ptr.resource_url);
        pr.thread.push(ptr);
        let comments = pr.thread.len() - 1;
        save_pull_index(self.spine.as_ref(), owner, name, &idx).await?;
        let mut v = serde_json::json!({"number": number, "comments": comments, "resourceUrl": url});
        if hosted {
            v["hosted"] = serde_json::json!(true);
        }
        Ok(ForgeResponse::json(201, &v))
    }

    /// close/reopen: the repository owner or the pull-request author; merged
    /// is final (JSS `apiPullState`, `mayModerate`).
    async fn api_pull_state(
        &self,
        agent: &ForgeAgent,
        owner: &str,
        name: &str,
        number: u64,
        state: IssueState,
    ) -> Result<ForgeResponse, ForgeError> {
        if matches!(agent, ForgeAgent::Anonymous) {
            return Ok(ForgeResponse::error(401, "authentication required"));
        }
        let _g = prgit::pull_locks().lock(&format!("{owner}/{name}")).await;
        let mut idx = load_pull_index(self.spine.as_ref(), owner, name).await?;
        let Some(pr) = idx.pulls.get_mut(&number) else {
            return Ok(ForgeResponse::error(404, "not found"));
        };
        if agent.owner() != Some(owner) && agent.author_id() != pr.author {
            return Ok(ForgeResponse::error(
                403,
                "only the repo owner or the pull-request author may do that",
            ));
        }
        if pr.state == IssueState::Merged {
            return Ok(ForgeResponse::error(
                422,
                "a merged pull request cannot be reopened or closed",
            ));
        }
        pr.state = state;
        save_pull_index(self.spine.as_ref(), owner, name, &idx).await?;
        Ok(ForgeResponse::json(
            200,
            &serde_json::json!({"number": number, "state": state_str(state)}),
        ))
    }

    // ---- pages ----------------------------------------------------------

    /// Pages and form posts under `<owner>/<repo>/pulls`.
    pub(crate) async fn h_pulls_page(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        owner: &str,
        name: &str,
        tail: &[String],
    ) -> Result<ForgeResponse, ForgeError> {
        self.resolve_repo(owner, name).await?;
        let base = format!("{}/{owner}/{name}", self.prefix());
        let post = req.method.eq_ignore_ascii_case("POST");
        let nf = || Ok(ForgeResponse::error(404, "not found"));
        match tail {
            [] if post => {
                let r = self.api_pull_create(req, agent, owner, name).await?;
                // Land on the new pull request.
                if r.status == 201 {
                    let n = serde_json::from_slice::<serde_json::Value>(&r.body)
                        .ok()
                        .and_then(|v| v["number"].as_u64())
                        .unwrap_or(0);
                    return Ok(ForgeResponse::redirect(303, &format!("{base}/pulls/{n}")));
                }
                Ok(r)
            }
            [] => self.pulls_list_page(req, owner, name).await,
            [n] if n == "new" => self.new_pull_page(req, owner, name).await,
            [n, rest @ ..] => {
                let Some(number) = parse_number(n) else {
                    return nf();
                };
                let loc = format!("{base}/pulls/{number}");
                match (rest, post) {
                    ([], false) => self.pull_page(owner, name, number).await,
                    ([], true) => {
                        let r = self
                            .api_pull_comment(req, agent, owner, name, number)
                            .await?;
                        Ok(redirect_on_ok(r, &loc))
                    }
                    ([v], true) if v == "merge" => {
                        let exp = parse_input(req).and_then(|i| i.expected_base);
                        let r = self
                            .merge_pull(agent, owner, name, number, exp.as_deref())
                            .await?;
                        Ok(redirect_on_ok(r, &loc))
                    }
                    ([v], true) if v == "close" || v == "reopen" => {
                        let st = if v == "close" {
                            IssueState::Closed
                        } else {
                            IssueState::Open
                        };
                        let r = self.api_pull_state(agent, owner, name, number, st).await?;
                        Ok(redirect_on_ok(r, &loc))
                    }
                    ([v], false) if v == "commits" => {
                        self.pull_diff_page(owner, name, number, true).await
                    }
                    ([v], false) if v == "files" => {
                        self.pull_diff_page(owner, name, number, false).await
                    }
                    _ => nf(),
                }
            }
        }
    }

    fn chip(state: IssueState) -> String {
        let (cls, label) = match state {
            IssueState::Open => ("pr-open state-open", "Open"),
            IssueState::Merged => ("pr-merged state-merged", "Merged"),
            IssueState::Closed => ("pr-closed state-closed", "Closed"),
        };
        format!("<span class=\"badge {cls}\">{label}</span>")
    }

    async fn pulls_list_page(
        &self,
        req: &ForgeRequest,
        owner: &str,
        name: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        let idx = load_pull_index(self.spine.as_ref(), owner, name).await?;
        let mut all: Vec<&PullEntry> = idx.pulls.values().collect();
        all.sort_by_key(|p| std::cmp::Reverse(p.number));
        let count = |s| all.iter().filter(|p| p.state == s).count();
        let state = list_state(req);
        let page_no = list_page(req);
        let base = format!("{}/{owner}/{name}", self.prefix());
        let filtered: Vec<&&PullEntry> = all.iter().filter(|p| p.state == state).collect();
        let mut body = crumbs(&[
            ("forge", Some(self.prefix())),
            (
                &agent_label(owner),
                Some(format!("{}/{owner}", self.prefix())),
            ),
            (name, Some(base.clone())),
            ("pulls", None),
        ]);
        body.push_str("<h1>Pull requests</h1><p>");
        for (s, label) in [
            (IssueState::Open, "Open"),
            (IssueState::Merged, "Merged"),
            (IssueState::Closed, "Closed"),
        ] {
            body.push_str(&format!(
                "<a href=\"{}/pulls?state={}\">{} {}</a> &middot; ",
                esc(&base),
                state_str(s),
                count(s),
                label
            ));
        }
        body.push_str("</p>");
        if filtered.is_empty() {
            body.push_str(&format!(
                "<p class=\"muted\">No {} pull requests.</p>",
                state_str(state)
            ));
        } else {
            body.push_str("<table><tbody>");
            for p in filtered
                .iter()
                .skip((page_no - 1) * PULLS_PER_PAGE)
                .take(PULLS_PER_PAGE)
            {
                let nc = p.thread.len().saturating_sub(1);
                body.push_str(&format!(
                    "<tr><td>{chip} <a href=\"{b}/pulls/{n}\">{t}</a>\
<div class=\"muted\">#{n} opened by {a} &middot; <code>{ho}:{hr} &rarr; {bs}</code></div></td>\
<td class=\"muted\">{c}</td></tr>",
                    chip = Self::chip(p.state),
                    b = esc(&base),
                    n = p.number,
                    t = esc(&p.title),
                    a = esc(&author_display(&p.author)),
                    ho = esc(&agent_label(&p.head.owner)),
                    hr = esc(&p.head.ref_name),
                    bs = esc(&p.base),
                    c = if nc > 0 {
                        format!("{nc} comment{}", if nc == 1 { "" } else { "s" })
                    } else {
                        String::new()
                    },
                ));
            }
            body.push_str("</tbody></table>");
        }
        if filtered.len() > page_no * PULLS_PER_PAGE {
            body.push_str(&format!(
                "<p><a href=\"{}/pulls?state={}&page={}\">Older</a></p>",
                esc(&base),
                state_str(state),
                page_no + 1
            ));
        }
        Ok(ForgeResponse::html(
            200,
            page(&format!("Pull requests - {owner}/{name}"), &body),
        ))
    }

    async fn new_pull_page(
        &self,
        req: &ForgeRequest,
        owner: &str,
        name: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        let (b, h) = (query_decoded(req, "base"), query_decoded(req, "head"));
        let Some(c) = self.compare_data(owner, name, &b, &h).await? else {
            return Ok(ForgeResponse::error(404, "not found"));
        };
        let base = format!("{}/{owner}/{name}", self.prefix());
        let mut body = crumbs(&[
            ("forge", Some(self.prefix())),
            (name, Some(base.clone())),
            ("new pull request", None),
        ]);
        body.push_str(&format!(
            "<h1>Open a pull request</h1><p class=\"muted\"><code>{}:{}</code> &rarr; <b>{}</b> \
&middot; {} commit{} ahead</p>\
<form method=\"post\" action=\"{base}/pulls\">\
<input type=\"hidden\" name=\"base\" value=\"{}\"><input type=\"hidden\" name=\"head\" value=\"{}\">\
<p><input type=\"text\" name=\"title\" placeholder=\"Title\" required></p>\
<p><input type=\"text\" name=\"resourceUrl\" placeholder=\"Body resource URL in your pod\"></p>\
<p><textarea name=\"body\" placeholder=\"Body (podless agents)\"></textarea></p>\
<p><button type=\"submit\">Create pull request</button></p></form>",
            esc(&agent_label(&c.head.owner)),
            esc(&c.head.ref_name),
            esc(&b),
            c.ahead_by,
            if c.ahead_by == 1 { "" } else { "s" },
            esc(&b),
            esc(&h),
            base = esc(&base),
        ));
        Ok(ForgeResponse::html(
            200,
            page(&format!("New pull request - {owner}/{name}"), &body),
        ))
    }

    fn pull_headline(pr: &PullEntry) -> String {
        let verb = if pr.state == IssueState::Merged {
            format!("merged into <b>{}</b>", esc(&pr.base))
        } else {
            format!(
                "wants to merge <code>{}:{}</code> into <b>{}</b>",
                esc(&agent_label(&pr.head.owner)),
                esc(&pr.head.ref_name),
                esc(&pr.base)
            )
        };
        format!(
            "<p>{} <span class=\"muted\"><b>{}</b> {verb}</span></p>",
            Self::chip(pr.state),
            esc(&author_display(&pr.author))
        )
    }

    fn pull_tabs(base: &str, n: u64) -> String {
        format!(
            "<nav class=\"crumbs\"><a href=\"{b}/pulls/{n}\">Conversation</a> &middot; \
<a href=\"{b}/pulls/{n}/commits\">Commits</a> &middot; \
<a href=\"{b}/pulls/{n}/files\">Files changed</a></nav>",
            b = esc(base)
        )
    }

    async fn pull_page(
        &self,
        owner: &str,
        name: &str,
        number: u64,
    ) -> Result<ForgeResponse, ForgeError> {
        let idx = load_pull_index(self.spine.as_ref(), owner, name).await?;
        let Some(pr) = idx.pulls.get(&number) else {
            return Ok(ForgeResponse::error(404, "not found"));
        };
        let base = format!("{}/{owner}/{name}", self.prefix());
        let thread = self.thread_json(&pr.thread).await;
        let mut body = crumbs(&[
            ("forge", Some(self.prefix())),
            (name, Some(base.clone())),
            ("pulls", Some(format!("{base}/pulls"))),
            (&format!("#{number}"), None),
        ]);
        body.push_str(&format!(
            "<h1>{} <span class=\"muted\">#{}</span></h1>{}{}",
            esc(&pr.title),
            pr.number,
            Self::pull_headline(pr),
            Self::pull_tabs(&base, number)
        ));
        for (i, e) in thread.iter().enumerate() {
            let who = esc(&author_display(e["author"].as_str().unwrap_or("")));
            let verb = if i == 0 {
                " opened this pull request"
            } else {
                ""
            };
            let text = match e["html"].as_str() {
                Some(h) => h.to_string(),
                None => "<p class=\"muted\">content removed by its author</p>".to_string(),
            };
            body.push_str(&format!(
                "<div class=\"cbox\"><div class=\"muted\"><b>{who}</b>{verb}</div>{text}</div>"
            ));
        }
        let post = |verb: &str| format!("{}/pulls/{number}/{verb}", esc(&base));
        match pr.state {
            IssueState::Merged => {
                let m = pr.merged.as_ref();
                body.push_str(&format!(
                    "<div class=\"mergebox\"><h3>Merged</h3><p class=\"muted\">merge commit <code>{}</code> by <b>{}</b>{}</p></div>",
                    esc(&m.map(|m| m.sha.chars().take(12).collect::<String>()).unwrap_or_default()),
                    esc(&m.map(|m| author_display(&m.merged_by)).unwrap_or_default()),
                    if m.is_some_and(|m| m.fast_forward) { " (fast-forward)" } else { "" }
                ));
            }
            IssueState::Closed => body.push_str(
                "<div class=\"mergebox\"><h3>Closed</h3>\
<p class=\"muted\">This pull request was closed without merging.</p></div>",
            ),
            IssueState::Open => {
                let info = self.pull_merge_info(owner, name, pr).await?;
                match (info.mergeable, info.up_to_date) {
                    (Some(true), _) => body.push_str(&format!(
                        "<div class=\"mergebox clean\"><h3>This branch has no conflicts with the base branch</h3>\
<p class=\"muted\">{}</p>\
<form method=\"post\" action=\"{}\"><input type=\"hidden\" name=\"expectedBase\" value=\"{}\">\
<button id=\"do-merge\" type=\"submit\">Merge pull request</button></form></div>",
                        if info.fast_forward {
                            "Fast-forward merge (no merge commit needed)."
                        } else {
                            "A merge commit will join the histories."
                        },
                        post("merge"),
                        esc(info.base_sha.as_deref().unwrap_or(""))
                    )),
                    (Some(false), true) => body.push_str(
                        "<div class=\"mergebox\"><h3>Nothing to merge</h3>\
<p class=\"muted\">The base branch already contains every commit of this branch.</p></div>",
                    ),
                    (Some(false), false) => {
                        body.push_str(&format!(
                            "<div class=\"mergebox conflict\"><h3>This branch has conflicts that must be resolved</h3>\
<p class=\"muted\">Conflicting file{}:</p><ul>",
                            if info.conflicts.len() == 1 { "" } else { "s" }
                        ));
                        for c in &info.conflicts {
                            body.push_str(&format!("<li><code>{}</code></li>", esc(c)));
                        }
                        body.push_str("</ul></div>");
                    }
                    (None, _) => body.push_str(&format!(
                        "<div class=\"mergebox\"><h3>Merge status unknown</h3><p class=\"muted\">{}</p></div>",
                        if self.pr.merge_tree_ok {
                            "The head branch (or the base branch) is no longer available.".to_string()
                        } else {
                            format!(
                                "This server's {} lacks merge-tree --write-tree (needs git 2.38 or later).",
                                esc(&self.pr.git_version)
                            )
                        }
                    )),
                }
            }
        }
        body.push_str(&format!(
            "<form method=\"post\" action=\"{b}/pulls/{number}\">\
<p><input type=\"text\" name=\"resourceUrl\" placeholder=\"Comment resource URL in your pod\"></p>\
<p><textarea name=\"body\" placeholder=\"Leave a comment (podless agents)\"></textarea></p>\
<p><button type=\"submit\">Comment</button></p></form>",
            b = esc(&base)
        ));
        if pr.state != IssueState::Merged {
            let (verb, label) = if pr.state == IssueState::Open {
                ("close", "Close pull request")
            } else {
                ("reopen", "Reopen pull request")
            };
            body.push_str(&format!(
                "<form method=\"post\" action=\"{}\"><button type=\"submit\">{label}</button></form>",
                post(verb)
            ));
        }
        Ok(ForgeResponse::html(
            200,
            page(&format!("{} - #{number} - {owner}/{name}", pr.title), &body),
        ))
    }

    async fn pull_diff_page(
        &self,
        owner: &str,
        name: &str,
        number: u64,
        commits_tab: bool,
    ) -> Result<ForgeResponse, ForgeError> {
        let idx = load_pull_index(self.spine.as_ref(), owner, name).await?;
        let Some(pr) = idx.pulls.get(&number) else {
            return Ok(ForgeResponse::error(404, "not found"));
        };
        let dir = repo::repo_git_dir(&self.repo_root, owner, name)?;
        let base = format!("{}/{owner}/{name}", self.prefix());
        // Merged pulls use the shas frozen at merge time (the objects outlive
        // the branch); open and closed ones compute live (JSS `pullDiffData`).
        let (commits, more, files) = match pr
            .merged
            .as_ref()
            .and_then(|m| m.base_sha.clone().zip(m.head_sha.clone()))
        {
            Some((b, h)) if pr.state == IssueState::Merged => {
                let mb = prgit::text(&dir, &["merge-base", &b, &h])
                    .await
                    .ok()
                    .map(|s| s.trim().to_string());
                let (c, m) = compare::commit_range(&dir, &b, &h).await?;
                (c, m, compare::diff_files(&dir, mb.as_deref(), &b, &h).await)
            }
            _ => match self
                .compare_data(owner, name, &pr.base, &pr.head_spec())
                .await?
            {
                Some(c) => (c.commits, c.has_more, c.files),
                None => (Vec::new(), false, Vec::new()),
            },
        };
        let mut body = crumbs(&[
            ("forge", Some(self.prefix())),
            (name, Some(base.clone())),
            ("pulls", Some(format!("{base}/pulls"))),
            (&format!("#{number}"), None),
        ]);
        body.push_str(&format!(
            "<h1>{} <span class=\"muted\">#{}</span></h1>{}{}",
            esc(&pr.title),
            pr.number,
            Self::pull_headline(pr),
            Self::pull_tabs(&base, number)
        ));
        if commits_tab {
            body.push_str(&commit_rows(&base, &commits, more));
        } else {
            body.push_str(&compare::render_diff(&files));
        }
        Ok(ForgeResponse::html(
            200,
            page(
                &format!(
                    "{} - #{number} - {owner}/{name}",
                    if commits_tab {
                        "Commits"
                    } else {
                        "Files changed"
                    }
                ),
                &body,
            ),
        ))
    }
}

/// JSS `ISSUE_NUM_RE`: `[1-9][0-9]{0,8}`.
fn parse_number(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    (!b.is_empty() && b.len() <= 9 && b[0] != b'0' && b.iter().all(u8::is_ascii_digit))
        .then(|| s.parse().ok())
        .flatten()
}

fn list_state(req: &ForgeRequest) -> IssueState {
    match query_decoded(req, "state").as_str() {
        "merged" => IssueState::Merged,
        "closed" => IssueState::Closed,
        _ => IssueState::Open,
    }
}

fn list_page(req: &ForgeRequest) -> usize {
    query_decoded(req, "page")
        .parse::<usize>()
        .unwrap_or(1)
        .clamp(1, 10_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn number_rules() {
        assert_eq!(parse_number("1"), Some(1));
        assert_eq!(parse_number("123456789"), Some(123_456_789));
        for bad in ["0", "01", "", "1234567890", "1a", "-1", "new"] {
            assert_eq!(parse_number(bad), None, "{bad}");
        }
    }

    #[test]
    fn author_ids() {
        let hex = "ab".repeat(32);
        assert_eq!(author_owner(&format!("did:nostr:{hex}")), Some(hex.clone()));
        assert_eq!(
            author_owner("https://pod.example/dana/profile/card#me").as_deref(),
            Some("dana")
        );
        assert_eq!(
            author_owner("https://dana.pod.example/profile/card#me").as_deref(),
            Some("dana")
        );
        assert_eq!(author_owner("did:web:x"), None);
        assert_eq!(author_meta(&format!("did:nostr:{hex}"))["kind"], "nostr");
        assert_eq!(author_meta("https://p/dana/x")["kind"], "webid");
    }

    #[test]
    fn index_roundtrips_with_jss_shape() {
        let json = r#"{"next":2,"pulls":{"1":{"number":1,"title":"t","state":"open","author":"a",
"createdAt":5,"base":"main","head":{"owner":"dana","repo":"demo","ref":"feature"},
"merged":null,"thread":[{"author":"a","resourceUrl":"u","at":5}]}}}"#;
        let idx: PullIndex = serde_json::from_str(json).unwrap();
        assert_eq!(idx.pulls[&1].head_spec(), "dana:feature");
        let back = serde_json::to_value(&idx).unwrap();
        assert_eq!(back["pulls"]["1"]["head"]["ref"], "feature");
        assert!(back["pulls"]["1"]["merged"].is_null());
    }

    #[test]
    fn body_html_escapes() {
        let h = render_body_html("<b>&\nx <script>alert(1)</script>");
        assert!(h.contains("&lt;b&gt;&amp;"), "{h}");
        assert!(!h.contains("<b>") && !h.contains("<script"), "{h}");
        assert!(h.contains('x'), "{h}");
    }
}
