//! # solid-pod-rs-forge
//!
//! A clean-room Rust reimplementation of the JavaScriptSolidServer
//! `forge` plugin — a zero-build, server-rendered Git forge (a
//! Gogs/Gitea slice) composed almost entirely from primitives
//! [`solid-pod-rs`](solid_pod_rs) already ships: git smart-HTTP
//! ([`solid_pod_rs_git`]), write-as-commit provenance and Bitcoin
//! anchoring ([`solid_pod_rs::provenance`], [`solid_pod_rs::mrc20`]),
//! NIP-98 auth ([`solid_pod_rs::auth::nip98`]), `did:nostr` identity
//! ([`solid_pod_rs::did_nostr_types`]), and WAC gating (enforced by the
//! embedding server before [`ForgeService::handle`] is reached).
//!
//! ## IP posture
//!
//! Everything here is derived from the forge plugin's *published
//! behaviour* and expressed as fresh Rust on solid-pod-rs's own
//! primitives. JSS is cited by function/section name only — no upstream
//! JavaScript is transcribed. This mirrors how [`solid_pod_rs::bitcoin_tx`]
//! and [`solid_pod_rs::auth::nip98`] cite JSS while carrying an
//! independent implementation.
//!
//! ## Architecture rule — "words in pods, metadata in the forge"
//!
//! Issue/PR/comment *bodies* live in the author's own pod (WAC-governed,
//! author-owned); the forge keeps only a **spine index** of pointers.
//! Bodies are re-fetched at read time, bounded. Podless `did:nostr`
//! agents store bodies in forge-hosted storage instead.
//!
//! ## Native-only
//!
//! The forge shells to `git`/`git-http-backend`, touches the
//! filesystem, and runs a loopback HTTP client. It is never part of a
//! `core`/wasm build and adds zero dependencies to the core crate.
//!
//! ## Entry point
//!
//! The crate is framework-agnostic: [`ForgeService::handle`] consumes a
//! [`ForgeRequest`] and produces a [`ForgeResponse`]; the embedding
//! server (actix/axum/hyper) translates its native types at the edge and
//! WAC-gates the forge scope *before* dispatch — exactly as the server's
//! `handle_git` gates before invoking [`solid_pod_rs_git::GitHttpService`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod auth;
pub mod bodies;
pub mod config;
pub mod error;
pub mod hosted;
pub mod html;
pub mod ownership;
pub mod repo;
pub mod request;
pub mod router;
pub mod spine;
pub mod token;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use solid_pod_rs_git::service::{GitHttpService, GitRequest};

pub use bodies::{HostedReader, LoopbackFetch};
pub use config::ForgeConfig;
pub use error::ForgeError;
pub use hosted::HostedStore;
pub use ownership::ForgeAgent;
pub use request::{esc, ForgeRequest, ForgeResponse};
pub use router::{parse_route, Route};
pub use spine::{FsSpineStore, SpineStore};
pub use token::TokenError;

/// Convenience import surface.
pub mod prelude {
    pub use crate::config::ForgeConfig;
    pub use crate::error::ForgeError;
    pub use crate::ownership::ForgeAgent;
    pub use crate::request::{ForgeRequest, ForgeResponse};
    pub use crate::ForgeService;
}

/// Current wall-clock time in Unix seconds.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Load the persisted forge instance HMAC key, or generate + persist a
/// fresh one (`0600`). The key is 32 bytes of OS randomness (two v4
/// UUIDs, each 122 bits of entropy from the platform RNG). Persisting it
/// keeps minted tokens valid across restarts.
fn load_or_create_token_key(plugin_dir: &Path) -> Result<[u8; 32], ForgeError> {
    let path = plugin_dir.join(".forge-token-key");
    if let Ok(bytes) = std::fs::read(&path) {
        if bytes.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return Ok(key);
        }
    }
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    key[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    std::fs::write(&path, key)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(key)
}

/// The forge service. One instance is built at server startup and shared
/// (`Arc`) across requests. All durable state lives under `plugin_dir`.
#[derive(Clone)]
pub struct ForgeService {
    cfg: ForgeConfig,
    plugin_dir: PathBuf,
    repo_root: PathBuf,
    git: Arc<GitHttpService>,
    spine: Arc<dyn SpineStore>,
    /// Loopback GET for verifying/re-fetching pod-hosted bodies. `None`
    /// until the server injects its reqwest-backed client; without it,
    /// pod-hosted issue writes are refused (fail-closed).
    loopback: Option<Arc<dyn LoopbackFetch>>,
    /// Forge-hosted body store for podless `did:nostr` agents (always
    /// available — it is local `0600` storage under the plugin dir).
    hosted: Arc<HostedStore>,
    /// Forge instance HMAC key for push tokens (persisted `0600`).
    token_key: Arc<[u8; 32]>,
}

impl std::fmt::Debug for ForgeService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForgeService")
            .field("prefix", &self.cfg.normalized_prefix())
            .field("plugin_dir", &self.plugin_dir)
            .finish()
    }
}

impl ForgeService {
    /// Build a forge rooted at `plugin_dir`. Creates the on-disk layout
    /// (`repos/`, `issues/`, `pulls/`, `hosted/`, `marks/`) if absent.
    /// The git CGI service is rooted at `plugin_dir/repos`.
    pub fn new(cfg: ForgeConfig, plugin_dir: impl Into<PathBuf>) -> Result<Self, ForgeError> {
        let plugin_dir = plugin_dir.into();
        let repo_root = plugin_dir.join("repos");
        for sub in ["repos", "issues", "pulls", "hosted", "marks"] {
            std::fs::create_dir_all(plugin_dir.join(sub))?;
        }
        let git = Arc::new(GitHttpService::new(repo_root.clone()));
        let spine: Arc<dyn SpineStore> = Arc::new(FsSpineStore::new(plugin_dir.clone()));
        let hosted = Arc::new(HostedStore::new(plugin_dir.clone()));
        let token_key = Arc::new(load_or_create_token_key(&plugin_dir)?);
        Ok(Self {
            cfg,
            plugin_dir,
            repo_root,
            git,
            spine,
            loopback: None,
            hosted,
            token_key,
        })
    }

    /// Inject the loopback fetcher (the server's reqwest client) used to
    /// verify and re-fetch pod-hosted bodies.
    #[must_use]
    pub fn with_loopback(mut self, lb: Arc<dyn LoopbackFetch>) -> Self {
        self.loopback = Some(lb);
        self
    }

    /// Override the spine store (tests inject an in-memory store).
    #[must_use]
    pub fn with_spine(mut self, spine: Arc<dyn SpineStore>) -> Self {
        self.spine = spine;
        self
    }

    /// The forge instance HMAC key (for token minting/verification).
    #[must_use]
    pub fn token_key(&self) -> &[u8; 32] {
        &self.token_key
    }

    /// Resolve the caller identity from `req`'s `Authorization` header
    /// (forge token or NIP-98). The server may instead pass a
    /// [`ForgeAgent::Pod`] directly to [`Self::handle`] when it has a pod
    /// session; this helper is for the token/NIP-98 schemes.
    #[must_use]
    pub fn resolve_agent(&self, req: &ForgeRequest) -> ForgeAgent {
        auth::resolve_agent(req, self.token_key.as_ref(), now_secs())
    }

    /// The configured, normalised URL prefix (`/forge`).
    #[must_use]
    pub fn prefix(&self) -> String {
        self.cfg.normalized_prefix()
    }

    /// The plugin data directory.
    #[must_use]
    pub fn plugin_dir(&self) -> &Path {
        &self.plugin_dir
    }

    /// Single entry point. The embedding server maps its native request
    /// to a [`ForgeRequest`], WAC-gates the scope, and calls this.
    pub async fn handle(
        &self,
        req: ForgeRequest,
        agent: ForgeAgent,
    ) -> Result<ForgeResponse, ForgeError> {
        // CORS preflight.
        if req.method.eq_ignore_ascii_case("OPTIONS") {
            return Ok(ForgeResponse {
                status: 204,
                headers: vec![
                    ("access-control-allow-origin".into(), "*".into()),
                    (
                        "access-control-allow-methods".into(),
                        "GET, POST, PUT, DELETE, OPTIONS".into(),
                    ),
                    (
                        "access-control-allow-headers".into(),
                        "Content-Type, Authorization".into(),
                    ),
                ],
                body: bytes::Bytes::new(),
            });
        }

        let prefix = self.cfg.normalized_prefix();
        let Some(rel) = router::strip_prefix(&prefix, &req.path) else {
            return Ok(ForgeResponse::error(404, "not under forge prefix"));
        };
        let route = parse_route(&rel);

        let result = self.dispatch(route, &req, &agent).await;
        Ok(result.unwrap_or_else(|e| e.to_response()))
    }

    /// Route → handler. Handlers return `Result` and errors are mapped to
    /// responses by the caller.
    async fn dispatch(
        &self,
        route: Route,
        req: &ForgeRequest,
        _agent: &ForgeAgent,
    ) -> Result<ForgeResponse, ForgeError> {
        match route {
            Route::Index => self.h_index().await,
            Route::OwnerIndex { owner } => self.h_owner(&owner).await,
            Route::GitSmart { rel_path } => self.h_git_smart(req, _agent, &rel_path).await,
            Route::RepoOverview { owner, repo } => self.h_overview(&owner, &repo).await,
            Route::Tree { owner, repo, rev, path } => {
                self.h_tree(&owner, &repo, &rev, &path).await
            }
            Route::Blob { owner, repo, rev, path } => {
                self.h_blob(&owner, &repo, &rev, &path).await
            }
            Route::Raw { owner, repo, rev, path } => {
                self.h_raw(&owner, &repo, &rev, &path).await
            }
            Route::Commits { owner, repo, rev } => {
                self.h_commits(req, &owner, &repo, &rev).await
            }
            Route::Commit { owner, repo, sha } => self.h_commit(&owner, &repo, &sha).await,
            Route::Branches { owner, repo } => self.h_branches(&owner, &repo).await,
            Route::Tags { owner, repo } => self.h_tags(&owner, &repo).await,
            Route::Issues { owner, repo } => {
                if req.method.eq_ignore_ascii_case("POST") {
                    self.h_issue_create(req, _agent, &owner, &repo).await
                } else {
                    self.h_issues_list(req, &owner, &repo).await
                }
            }
            Route::IssueNew { owner, repo } => self.h_issue_new_form(&owner, &repo).await,
            Route::IssueDetail { owner, repo, num } => {
                if req.method.eq_ignore_ascii_case("POST") {
                    self.h_issue_comment(req, _agent, &owner, &repo, num).await
                } else {
                    self.h_issue_detail(&owner, &repo, num).await
                }
            }
            Route::ApiToken => self.h_api_token(req, _agent).await,
            Route::ApiHosted { hex, id } => self.h_api_hosted(req, _agent, &hex, &id).await,
            // The remaining routes are implemented in later phases.
            _ => Err(ForgeError::NotFound("not implemented".into())),
        }
    }

    /// Resolve `<owner>/<repo>` to its bare git-dir, 404ing when the repo
    /// does not exist. Validates both segments against traversal.
    async fn resolve_repo(&self, owner: &str, repo: &str) -> Result<PathBuf, ForgeError> {
        let dir = repo::repo_git_dir(&self.repo_root, owner, repo)?;
        if !tokio::fs::metadata(&dir)
            .await
            .map(|m| m.is_dir())
            .unwrap_or(false)
        {
            return Err(ForgeError::NotFound(format!("repo {owner}/{repo}")));
        }
        Ok(dir)
    }

    // ---- Tier 1: index + git smart-HTTP ---------------------------------

    async fn h_index(&self) -> Result<ForgeResponse, ForgeError> {
        let repos = repo::list_all(&self.repo_root).await;
        Ok(ForgeResponse::html(
            200,
            html::index_page(&self.prefix(), &repos),
        ))
    }

    async fn h_owner(&self, owner: &str) -> Result<ForgeResponse, ForgeError> {
        let repos = repo::list_owner(&self.repo_root, owner).await;
        if repos.is_empty() {
            return Err(ForgeError::NotFound(format!("owner {owner}")));
        }
        Ok(ForgeResponse::html(
            200,
            html::owner_page(&self.prefix(), owner, &repos),
        ))
    }

    /// Forward a git smart-HTTP request to the reused CGI service. The
    /// server has already WAC-gated the scope; auth for the CGI itself is
    /// the pod's existing `Basic nostr:`/NIP-98 path inside the git crate.
    async fn h_git_smart(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        rel_path: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        let git_req = GitRequest {
            method: req.method.clone(),
            path: rel_path.to_string(),
            query: req.query.clone(),
            headers: req.headers.clone(),
            body: req.raw_body.clone(),
            host_url: req.host_url.clone(),
        };
        // Namespace push guard: a push (receive-pack) may only target the
        // caller's own namespace. Pushing into another owner's namespace
        // is `403` (JSS forge namespace guard). Reads are unaffected here;
        // the server's WAC gate governs private-repo read access.
        if git_req.is_write() {
            let owner = rel_path
                .trim_start_matches('/')
                .split('/')
                .next()
                .unwrap_or("");
            if !agent.can_write_namespace(owner) {
                return Err(ForgeError::Forbidden(format!(
                    "cannot push into namespace '{owner}'"
                )));
            }
        }
        let resp = self.git.handle(git_req).await?;
        Ok(ForgeResponse {
            status: resp.status,
            headers: resp.headers,
            body: resp.body,
        })
    }

    // ---- Tier 1: browse -------------------------------------------------

    async fn h_overview(&self, owner: &str, repo: &str) -> Result<ForgeResponse, ForgeError> {
        let dir = self.resolve_repo(owner, repo).await?;
        let prefix = self.prefix();
        if !repo::browse::has_commits(&dir).await {
            return Ok(ForgeResponse::html(
                200,
                html::repo_overview_page(&prefix, owner, repo, "main", &[], None),
            ));
        }
        let branch = repo::browse::default_branch(&dir).await;
        let entries = repo::browse::list_tree(&dir, &branch, "").await?;
        // README detection (case-insensitive common names).
        let readme = self.find_readme(&dir, &branch, &entries).await;
        Ok(ForgeResponse::html(
            200,
            html::repo_overview_page(
                &prefix,
                owner,
                repo,
                &branch,
                &entries,
                readme.as_deref(),
            ),
        ))
    }

    /// Read a bounded, textual README from the root tree if one exists.
    async fn find_readme(
        &self,
        dir: &Path,
        rev: &str,
        entries: &[repo::browse::TreeEntry],
    ) -> Option<String> {
        let candidate = entries.iter().find(|e| {
            e.kind == repo::browse::EntryKind::File
                && {
                    let n = e.name.to_ascii_lowercase();
                    n == "readme" || n == "readme.md" || n == "readme.txt"
                }
        })?;
        let bytes = repo::browse::read_blob(dir, rev, &candidate.name, self.cfg.max_body_bytes as u64)
            .await
            .ok()?;
        if request::looks_textual(&bytes) {
            Some(String::from_utf8_lossy(&bytes).into_owned())
        } else {
            None
        }
    }

    async fn h_tree(
        &self,
        owner: &str,
        repo: &str,
        rev: &str,
        path: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        let dir = self.resolve_repo(owner, repo).await?;
        let entries = repo::browse::list_tree(&dir, rev, path).await?;
        Ok(ForgeResponse::html(
            200,
            html::tree_page(&self.prefix(), owner, repo, rev, path, &entries),
        ))
    }

    async fn h_blob(
        &self,
        owner: &str,
        repo: &str,
        rev: &str,
        path: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        let dir = self.resolve_repo(owner, repo).await?;
        // Cap the in-browser render; oversized/binary blobs get a download
        // link instead of buffering into the page.
        const BLOB_VIEW_MAX: u64 = 1024 * 1024;
        let content = match repo::browse::read_blob(&dir, rev, path, BLOB_VIEW_MAX).await {
            Ok(bytes) => {
                if request::looks_textual(&bytes) {
                    Some(String::from_utf8_lossy(&bytes).into_owned())
                } else {
                    None
                }
            }
            // Too large to inline — offer the raw download.
            Err(ForgeError::BadRequest(_)) => None,
            Err(e) => return Err(e),
        };
        Ok(ForgeResponse::html(
            200,
            html::blob_page(&self.prefix(), owner, repo, rev, path, content.as_deref()),
        ))
    }

    async fn h_raw(
        &self,
        owner: &str,
        repo: &str,
        rev: &str,
        path: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        let dir = self.resolve_repo(owner, repo).await?;
        // Generous cap for raw downloads; still bounded to avoid OOM.
        const RAW_MAX: u64 = 25 * 1024 * 1024;
        let bytes = repo::browse::read_blob(&dir, rev, path, RAW_MAX).await?;
        let is_text = request::looks_textual(&bytes);
        let filename = path.rsplit('/').next().unwrap_or("download");
        Ok(ForgeResponse::raw_bytes(
            bytes::Bytes::from(bytes),
            is_text,
            filename,
        ))
    }

    async fn h_commits(
        &self,
        req: &ForgeRequest,
        owner: &str,
        repo: &str,
        rev: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        let dir = self.resolve_repo(owner, repo).await?;
        let page: u32 = req
            .query_param("page")
            .and_then(|p| p.parse().ok())
            .unwrap_or(1)
            .max(1);
        let (commits, has_next) = repo::browse::commit_log(&dir, rev, page, 50).await?;
        Ok(ForgeResponse::html(
            200,
            html::commits_page(&self.prefix(), owner, repo, rev, &commits, page, has_next),
        ))
    }

    async fn h_commit(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        let dir = self.resolve_repo(owner, repo).await?;
        let meta = solid_pod_rs_git::api::resolve_commit(&dir, sha).await?;
        let patch = repo::browse::commit_patch(&dir, &meta.hash).await?;
        Ok(ForgeResponse::html(
            200,
            html::commit_page(&self.prefix(), owner, repo, &meta, &patch),
        ))
    }

    async fn h_branches(&self, owner: &str, repo: &str) -> Result<ForgeResponse, ForgeError> {
        let dir = self.resolve_repo(owner, repo).await?;
        let info = solid_pod_rs_git::api::git_branches(&dir).await?;
        Ok(ForgeResponse::html(
            200,
            html::refs_page(
                &self.prefix(),
                owner,
                repo,
                "Branches",
                Some(&info.current),
                &info.local,
                "commits",
            ),
        ))
    }

    async fn h_tags(&self, owner: &str, repo: &str) -> Result<ForgeResponse, ForgeError> {
        let dir = self.resolve_repo(owner, repo).await?;
        let tags = repo::browse::list_tags(&dir).await?;
        Ok(ForgeResponse::html(
            200,
            html::refs_page(&self.prefix(), owner, repo, "Tags", None, &tags, "tree"),
        ))
    }

    // ---- Tier 2: issues + spine ----------------------------------------

    async fn h_issues_list(
        &self,
        req: &ForgeRequest,
        owner: &str,
        repo: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        self.resolve_repo(owner, repo).await?;
        let idx = spine::issues::load_issue_index(self.spine.as_ref(), owner, repo).await?;
        let filter = match req.query_param("state").as_deref() {
            Some("closed") => spine::issues::IssueState::Closed,
            _ => spine::issues::IssueState::Open,
        };
        let issues = idx.by_state(filter);
        Ok(ForgeResponse::html(
            200,
            html::issues_list_page(
                &self.prefix(),
                owner,
                repo,
                filter,
                idx.count(spine::issues::IssueState::Open),
                idx.count(spine::issues::IssueState::Closed),
                &issues,
            ),
        ))
    }

    async fn h_issue_new_form(
        &self,
        owner: &str,
        repo: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        self.resolve_repo(owner, repo).await?;
        Ok(ForgeResponse::html(
            200,
            html::issue_new_page(&self.prefix(), owner, repo),
        ))
    }

    async fn h_issue_detail(
        &self,
        owner: &str,
        repo: &str,
        num: u64,
    ) -> Result<ForgeResponse, ForgeError> {
        self.resolve_repo(owner, repo).await?;
        let idx = spine::issues::load_issue_index(self.spine.as_ref(), owner, repo).await?;
        let entry = idx
            .issues
            .get(&num)
            .ok_or_else(|| ForgeError::NotFound(format!("issue #{num}")))?;
        let truncated = entry.thread.len() > self.cfg.thread_cap;
        let hosted: Arc<dyn HostedReader> = self.hosted.clone();
        let threads = bodies::render_thread(
            &entry.thread,
            self.loopback.clone(),
            Some(hosted),
            &self.cfg,
        )
        .await;
        Ok(ForgeResponse::html(
            200,
            html::issue_detail_page(&self.prefix(), owner, repo, entry, &threads, truncated),
        ))
    }

    /// Parse `{title?, resourceUrl?, body?}` from a JSON or form-encoded
    /// body. `resourceUrl` is the pod-hosted pointer (pod agents); `body`
    /// is the inline content (podless `did:nostr` agents).
    fn parse_issue_body(req: &ForgeRequest) -> (Option<String>, Option<String>, Option<String>) {
        let ct = req.header("content-type").unwrap_or("");
        let raw = String::from_utf8_lossy(&req.raw_body);
        let field_json = |v: &serde_json::Value, k: &str| {
            v.get(k).and_then(|x| x.as_str()).map(|s| s.to_string())
        };
        if ct.contains("application/json") {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                return (
                    field_json(&v, "title"),
                    field_json(&v, "resourceUrl"),
                    field_json(&v, "body"),
                );
            }
        }
        let pairs = request::parse_form(&raw);
        let field = |k: &str| pairs.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.clone());
        (field("title"), field("resourceUrl"), field("body"))
    }

    /// Build a verified [`ThreadPointer`] for `agent`'s contribution:
    /// - **Pod agent** → validate + loopback-verify the pod `resource_url`.
    /// - **Nostr agent** → store `body` inline in forge-hosted storage.
    /// - **Anonymous** → `401`.
    async fn make_pointer(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        owner: &str,
        repo: &str,
        resource_url: Option<&str>,
        body: Option<&str>,
    ) -> Result<spine::issues::ThreadPointer, ForgeError> {
        match agent {
            ForgeAgent::Anonymous => {
                Err(ForgeError::Unauthorised("authentication required".into()))
            }
            ForgeAgent::Nostr { pubkey_hex } => {
                // Podless: the body is submitted inline and hosted 0600.
                let body = body
                    .map(str::trim)
                    .filter(|b| !b.is_empty())
                    .ok_or_else(|| ForgeError::BadRequest("body required".into()))?;
                let rref = self.hosted.write(pubkey_hex, body.as_bytes()).await?;
                Ok(spine::issues::ThreadPointer {
                    author: agent.author_id(),
                    resource_url: rref,
                    at: now_secs(),
                    hosted: true,
                })
            }
            ForgeAgent::Pod { .. } => {
                let url = resource_url
                    .ok_or_else(|| ForgeError::BadRequest("resourceUrl required".into()))?;
                self.verify_pod_pointer(req, agent, owner, repo, url).await
            }
        }
    }

    /// Verify a pod-hosted body pointer: the URL must be in the caller's
    /// own forge area (SSRF guard) and unauthenticated-readable. Returns
    /// the validated `ThreadPointer` on success.
    async fn verify_pod_pointer(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        repo_owner: &str,
        repo: &str,
        resource_url: &str,
    ) -> Result<spine::issues::ThreadPointer, ForgeError> {
        let caller = agent
            .owner()
            .ok_or_else(|| ForgeError::Unauthorised("authentication required".into()))?;
        let host = req
            .host_url
            .as_deref()
            .ok_or_else(|| ForgeError::BadRequest("missing host".into()))?;
        // SSRF + own-area guard.
        bodies::own_area_ok(resource_url, host, caller, repo_owner, repo)?;
        // Confirm public readability with a single loopback GET.
        let lb = self
            .loopback
            .as_ref()
            .ok_or_else(|| ForgeError::Unsupported("pod body verification unavailable".into()))?;
        match lb
            .get(resource_url, self.cfg.max_body_bytes, self.cfg.fetch_timeout_secs)
            .await
        {
            bodies::FetchResult::Body(_) => Ok(spine::issues::ThreadPointer {
                author: agent.author_id(),
                resource_url: resource_url.to_string(),
                at: now_secs(),
                hosted: false,
            }),
            bodies::FetchResult::Removed => Err(ForgeError::BadRequest(
                "pod body is not publicly readable".into(),
            )),
            bodies::FetchResult::TooLarge => {
                Err(ForgeError::BadRequest("pod body too large".into()))
            }
            bodies::FetchResult::Error(e) => {
                Err(ForgeError::Backend(format!("pod body fetch failed: {e}")))
            }
        }
    }

    async fn h_issue_create(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        owner: &str,
        repo: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        self.resolve_repo(owner, repo).await?;
        let (title, resource_url, body) = Self::parse_issue_body(req);
        let title = title
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .ok_or_else(|| ForgeError::BadRequest("title required".into()))?;

        // Pod agents supply a pod pointer; podless nostr agents supply an
        // inline body stored in forge-hosted storage.
        let pointer = self
            .make_pointer(req, agent, owner, repo, resource_url.as_deref(), body.as_deref())
            .await?;

        let mut idx = spine::issues::load_issue_index(self.spine.as_ref(), owner, repo).await?;
        let entry = spine::issues::IssueEntry {
            number: 0,
            title,
            state: spine::issues::IssueState::Open,
            author: agent.author_id(),
            created_at: now_secs(),
            thread: vec![pointer],
        };
        let num = idx.allocate(entry);
        spine::issues::save_issue_index(self.spine.as_ref(), owner, repo, &idx).await?;

        let location = format!("{}/{}/{}/issues/{}", self.prefix(), owner, repo, num);
        Ok(ForgeResponse::redirect(303, &location))
    }

    async fn h_issue_comment(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        owner: &str,
        repo: &str,
        num: u64,
    ) -> Result<ForgeResponse, ForgeError> {
        self.resolve_repo(owner, repo).await?;
        let (_title, resource_url, body) = Self::parse_issue_body(req);
        let pointer = self
            .make_pointer(req, agent, owner, repo, resource_url.as_deref(), body.as_deref())
            .await?;

        let mut idx = spine::issues::load_issue_index(self.spine.as_ref(), owner, repo).await?;
        let entry = idx
            .issues
            .get_mut(&num)
            .ok_or_else(|| ForgeError::NotFound(format!("issue #{num}")))?;
        entry.thread.push(pointer);
        spine::issues::save_issue_index(self.spine.as_ref(), owner, repo, &idx).await?;

        let location = format!("{}/{}/{}/issues/{}", self.prefix(), owner, repo, num);
        Ok(ForgeResponse::redirect(303, &location))
    }

    // ---- Tier 2.5: tokens + hosted storage -----------------------------

    /// `POST /api/token` — mint a forge push token for the (already
    /// authenticated) caller. The server resolves the caller via NIP-98 /
    /// pod session before calling `handle`; an anonymous caller is `401`.
    async fn h_api_token(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
    ) -> Result<ForgeResponse, ForgeError> {
        if !req.method.eq_ignore_ascii_case("POST") {
            return Err(ForgeError::NotFound("token requires POST".into()));
        }
        let iat = now_secs();
        let ttl = self.cfg.token_ttl_secs;
        let token = token::mint(self.token_key.as_ref(), agent, iat, ttl).ok_or_else(|| {
            ForgeError::Unauthorised("authentication required to mint a token".into())
        })?;
        let v = serde_json::json!({
            "token": token,
            "tokenType": "Bearer",
            "expiresIn": ttl,
            "exp": iat + ttl,
            "agent": agent.author_id(),
        });
        Ok(ForgeResponse::json(200, &v))
    }

    /// `GET/DELETE /api/hosted/<hex>/<uuid>` — the podless body store.
    /// GET is public (bodies are public by construction); DELETE is
    /// owner-only (`agent` hex must equal `hex`).
    async fn h_api_hosted(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        hex: &str,
        id: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        if req.method.eq_ignore_ascii_case("DELETE") {
            // Only the owning nostr agent may delete their hosted body.
            if agent.owner() != Some(hex) {
                return Err(ForgeError::Forbidden(
                    "only the owner may delete a hosted body".into(),
                ));
            }
            let removed = self.hosted.delete(hex, id).await?;
            if removed {
                return Ok(ForgeResponse::with_type(204, "application/json", bytes::Bytes::new()));
            }
            return Err(ForgeError::NotFound(format!("hosted {hex}/{id}")));
        }

        // GET (default).
        match self.hosted.read(hex, id, self.cfg.max_body_bytes).await? {
            Some(bytes) => Ok(ForgeResponse {
                status: 200,
                headers: vec![
                    ("content-type".into(), "application/json".into()),
                    ("x-content-type-options".into(), "nosniff".into()),
                    ("access-control-allow-origin".into(), "*".into()),
                ],
                body: bytes::Bytes::from(bytes),
            }),
            None => Err(ForgeError::NotFound(format!("hosted {hex}/{id}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use tempfile::TempDir;

    fn req(method: &str, path: &str) -> ForgeRequest {
        ForgeRequest {
            method: method.into(),
            path: path.into(),
            query: String::new(),
            headers: vec![],
            raw_body: Bytes::new(),
            host_url: Some("https://pod.example".into()),
        }
    }

    fn service() -> (TempDir, ForgeService) {
        let td = TempDir::new().unwrap();
        let svc = ForgeService::new(ForgeConfig::default(), td.path()).unwrap();
        (td, svc)
    }

    #[tokio::test]
    async fn new_creates_layout() {
        let (td, _svc) = service();
        for sub in ["repos", "issues", "pulls", "hosted", "marks"] {
            assert!(td.path().join(sub).is_dir(), "{sub} dir must exist");
        }
    }

    #[tokio::test]
    async fn index_renders_empty() {
        let (_td, svc) = service();
        let r = svc.handle(req("GET", "/forge"), ForgeAgent::Anonymous).await.unwrap();
        assert_eq!(r.status, 200);
        let body = String::from_utf8(r.body.to_vec()).unwrap();
        assert!(body.contains("No repositories yet"));
    }

    #[tokio::test]
    async fn index_lists_pushed_repo() {
        let (td, svc) = service();
        tokio::fs::create_dir_all(td.path().join("repos/alice/demo.git"))
            .await
            .unwrap();
        let r = svc.handle(req("GET", "/forge"), ForgeAgent::Anonymous).await.unwrap();
        let body = String::from_utf8(r.body.to_vec()).unwrap();
        assert!(body.contains("/forge/alice/demo"));

        // Owner page too.
        let r2 = svc
            .handle(req("GET", "/forge/alice"), ForgeAgent::Anonymous)
            .await
            .unwrap();
        assert_eq!(r2.status, 200);
    }

    #[tokio::test]
    async fn unknown_owner_is_404() {
        let (_td, svc) = service();
        let r = svc
            .handle(req("GET", "/forge/ghost"), ForgeAgent::Anonymous)
            .await
            .unwrap();
        assert_eq!(r.status, 404);
    }

    #[tokio::test]
    async fn options_preflight() {
        let (_td, svc) = service();
        let r = svc
            .handle(req("OPTIONS", "/forge/x"), ForgeAgent::Anonymous)
            .await
            .unwrap();
        assert_eq!(r.status, 204);
        assert!(r
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("access-control-allow-methods")));
    }

    #[tokio::test]
    async fn outside_prefix_is_404() {
        let (_td, svc) = service();
        let r = svc
            .handle(req("GET", "/other/thing"), ForgeAgent::Anonymous)
            .await
            .unwrap();
        assert_eq!(r.status, 404);
    }

    #[tokio::test]
    async fn unimplemented_route_is_404_for_now() {
        let (_td, svc) = service();
        let r = svc
            .handle(req("GET", "/forge/alice/repo/issues"), ForgeAgent::Anonymous)
            .await
            .unwrap();
        // Issues is implemented in Phase 2; before that it is a 404. Once
        // Phase 2 lands, an anonymous GET on a missing repo still 404s.
        assert_eq!(r.status, 404);
    }

    // ---- Phase 1 browse integration (needs the `git` binary) -----------

    fn git_available() -> bool {
        std::process::Command::new("git")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn run_git(dir: &std::path::Path, args: &[&str]) {
        let ok = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(ok, "git {args:?} failed in {}", dir.display());
    }

    /// Create `repos/<owner>/<name>.git` as a bare repo containing a
    /// README, a `src/lib.rs`, and a `v1.0` tag, via a working clone.
    fn seed_repo(td: &TempDir, owner: &str, name: &str) {
        let work = td.path().join(format!("work-{owner}-{name}"));
        std::fs::create_dir_all(&work).unwrap();
        run_git(&work, &["init", "-b", "main"]);
        std::fs::write(work.join("README.md"), "# Demo\nhello forge\n").unwrap();
        std::fs::create_dir_all(work.join("src")).unwrap();
        std::fs::write(work.join("src/lib.rs"), "pub fn f() -> u8 { 42 }\n").unwrap();
        run_git(&work, &["add", "-A"]);
        run_git(
            &work,
            &[
                "-c",
                "user.email=t@e.st",
                "-c",
                "user.name=Tester",
                "commit",
                "-m",
                "initial commit",
            ],
        );
        run_git(&work, &["tag", "v1.0"]);
        let bare = td.path().join("repos").join(owner).join(format!("{name}.git"));
        std::fs::create_dir_all(bare.parent().unwrap()).unwrap();
        run_git(
            td.path(),
            &[
                "clone",
                "--bare",
                work.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
        );
    }

    async fn body(svc: &ForgeService, path: &str) -> (u16, String) {
        let r = svc
            .handle(req("GET", path), ForgeAgent::Anonymous)
            .await
            .unwrap();
        (r.status, String::from_utf8_lossy(&r.body).into_owned())
    }

    #[tokio::test]
    async fn overview_lists_tree_and_readme() {
        if !git_available() {
            return;
        }
        let (td, svc) = service();
        seed_repo(&td, "alice", "demo");
        let (status, html) = body(&svc, "/forge/alice/demo").await;
        assert_eq!(status, 200);
        assert!(html.contains("alice/demo"));
        // Root tree entries.
        assert!(html.contains("README.md"));
        assert!(html.contains("src"));
        // README rendered.
        assert!(html.contains("hello forge"));
    }

    #[tokio::test]
    async fn tree_blob_raw_roundtrip() {
        if !git_available() {
            return;
        }
        let (td, svc) = service();
        seed_repo(&td, "alice", "demo");

        // Subdirectory listing.
        let (s1, tree) = body(&svc, "/forge/alice/demo/tree/main/src").await;
        assert_eq!(s1, 200);
        assert!(tree.contains("lib.rs"));

        // Blob view renders textual content (escaped).
        let (s2, blob) = body(&svc, "/forge/alice/demo/blob/main/src/lib.rs").await;
        assert_eq!(s2, 200);
        assert!(blob.contains("pub fn f"));

        // Raw serves text/plain with nosniff.
        let r = svc
            .handle(req("GET", "/forge/alice/demo/raw/main/src/lib.rs"), ForgeAgent::Anonymous)
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        let ct = r
            .headers
            .iter()
            .find(|(k, _)| k == "content-type")
            .map(|(_, v)| v.clone())
            .unwrap();
        assert!(ct.starts_with("text/plain"));
        assert_eq!(String::from_utf8_lossy(&r.body), "pub fn f() -> u8 { 42 }\n");
    }

    #[tokio::test]
    async fn commits_branches_tags_commit_view() {
        if !git_available() {
            return;
        }
        let (td, svc) = service();
        seed_repo(&td, "alice", "demo");

        let (s1, commits) = body(&svc, "/forge/alice/demo/commits/main").await;
        assert_eq!(s1, 200);
        assert!(commits.contains("initial commit"));

        let (s2, branches) = body(&svc, "/forge/alice/demo/branches").await;
        assert_eq!(s2, 200);
        assert!(branches.contains("main"));
        assert!(branches.contains("default"));

        let (s3, tags) = body(&svc, "/forge/alice/demo/tags").await;
        assert_eq!(s3, 200);
        assert!(tags.contains("v1.0"));

        // Resolve the HEAD sha, then view that commit.
        let dir = td.path().join("repos/alice/demo.git");
        let out = std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&dir)
            .output()
            .unwrap();
        let sha = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let (s4, commit) = body(&svc, &format!("/forge/alice/demo/commit/{sha}")).await;
        assert_eq!(s4, 200);
        assert!(commit.contains("initial commit"));
        assert!(commit.contains("README.md"));
    }

    #[tokio::test]
    async fn browse_rejects_bad_ref_and_missing_repo() {
        if !git_available() {
            return;
        }
        let (td, svc) = service();
        seed_repo(&td, "alice", "demo");

        // Missing repo → 404.
        let (s1, _) = body(&svc, "/forge/alice/ghost").await;
        assert_eq!(s1, 404);

        // Flag-injection ref → 400.
        let (s2, _) = body(&svc, "/forge/alice/demo/tree/--upload-pack/x").await;
        assert_eq!(s2, 400);

        // Unknown path in a valid ref → 404.
        let (s3, _) = body(&svc, "/forge/alice/demo/blob/main/nope.txt").await;
        assert_eq!(s3, 404);
    }

    #[tokio::test]
    async fn empty_repo_overview_renders() {
        if !git_available() {
            return;
        }
        let (td, svc) = service();
        // A bare repo with no commits.
        let bare = td.path().join("repos/bob/empty.git");
        std::fs::create_dir_all(&bare).unwrap();
        run_git(td.path(), &["init", "--bare", "-b", "main", bare.to_str().unwrap()]);
        let (status, html) = body(&svc, "/forge/bob/empty").await;
        assert_eq!(status, 200);
        assert!(html.contains("empty"));
    }

    // ---- Phase 2 issues + spine ----------------------------------------

    use std::collections::HashMap;
    use std::sync::Mutex;

    struct MockLb {
        present: Mutex<HashMap<String, Vec<u8>>>,
    }
    impl MockLb {
        fn new() -> Self {
            Self {
                present: Mutex::new(HashMap::new()),
            }
        }
        fn put(&self, url: &str, body: &[u8]) {
            self.present.lock().unwrap().insert(url.into(), body.to_vec());
        }
        fn remove(&self, url: &str) {
            self.present.lock().unwrap().remove(url);
        }
    }
    #[async_trait::async_trait]
    impl bodies::LoopbackFetch for MockLb {
        async fn get(&self, url: &str, _max: usize, _to: u64) -> bodies::FetchResult {
            match self.present.lock().unwrap().get(url) {
                Some(b) => bodies::FetchResult::Body(b.clone()),
                None => bodies::FetchResult::Removed,
            }
        }
    }

    fn pod_agent(user: &str) -> ForgeAgent {
        ForgeAgent::Pod {
            webid: format!("https://pod.example/{user}/profile/card#me"),
            username: user.to_string(),
        }
    }

    fn post_form(path: &str, form: &str) -> ForgeRequest {
        ForgeRequest {
            method: "POST".into(),
            path: path.into(),
            query: String::new(),
            headers: vec![(
                "content-type".into(),
                "application/x-www-form-urlencoded".into(),
            )],
            raw_body: Bytes::from(form.to_string()),
            host_url: Some("https://pod.example".into()),
        }
    }

    /// Build a git-seeded service with a mock loopback injected.
    fn issues_service() -> (TempDir, ForgeService, Arc<MockLb>) {
        let td = TempDir::new().unwrap();
        let mock = Arc::new(MockLb::new());
        let svc = ForgeService::new(ForgeConfig::default(), td.path())
            .unwrap()
            .with_loopback(mock.clone() as Arc<dyn bodies::LoopbackFetch>);
        (td, svc, mock)
    }

    #[tokio::test]
    async fn issue_create_list_detail_and_deletion() {
        if !git_available() {
            return;
        }
        let (td, svc, mock) = issues_service();
        seed_repo(&td, "alice", "demo");

        let url = "https://pod.example/alice/public/forge/alice--demo/issue-1.jsonld";
        mock.put(url, b"the issue body text");

        // Create.
        let r = svc
            .handle(
                post_form(
                    "/forge/alice/demo/issues",
                    &format!("title=First+bug&resourceUrl={}", url.replace(':', "%3A").replace('/', "%2F")),
                ),
                pod_agent("alice"),
            )
            .await
            .unwrap();
        assert_eq!(r.status, 303);
        let loc = r
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("location"))
            .map(|(_, v)| v.clone())
            .unwrap();
        assert_eq!(loc, "/forge/alice/demo/issues/1");

        // List shows it.
        let (s, list) = body(&svc, "/forge/alice/demo/issues").await;
        assert_eq!(s, 200);
        assert!(list.contains("First bug"));
        assert!(list.contains("1 open"));

        // Detail re-fetches the body.
        let (s2, detail) = body(&svc, "/forge/alice/demo/issues/1").await;
        assert_eq!(s2, 200);
        assert!(detail.contains("the issue body text"));

        // Author deletes the pod body → detail shows the removed notice.
        mock.remove(url);
        let (_s3, detail2) = body(&svc, "/forge/alice/demo/issues/1").await;
        assert!(detail2.contains("content removed by its author"));
    }

    #[tokio::test]
    async fn issue_create_rejects_foreign_area_and_ssrf() {
        if !git_available() {
            return;
        }
        let (td, svc, mock) = issues_service();
        seed_repo(&td, "alice", "demo");
        mock.put(
            "https://pod.example/bob/public/forge/alice--demo/x.jsonld",
            b"body",
        );

        // alice pointing at bob's pod area → 403 (own-area guard).
        let bad = "https://pod.example/bob/public/forge/alice--demo/x.jsonld";
        let r = svc
            .handle(
                post_form(
                    "/forge/alice/demo/issues",
                    &format!("title=x&resourceUrl={}", bad.replace(':', "%3A").replace('/', "%2F")),
                ),
                pod_agent("alice"),
            )
            .await
            .unwrap();
        assert_eq!(r.status, 403);

        // A cross-origin SSRF target → rejected before any fetch.
        let ssrf = "http://169.254.169.254/alice/public/forge/alice--demo/x.jsonld";
        let r2 = svc
            .handle(
                post_form(
                    "/forge/alice/demo/issues",
                    &format!("title=x&resourceUrl={}", ssrf.replace(':', "%3A").replace('/', "%2F")),
                ),
                pod_agent("alice"),
            )
            .await
            .unwrap();
        assert!(r2.status == 403 || r2.status == 400);
    }

    #[tokio::test]
    async fn comment_appends_to_thread() {
        if !git_available() {
            return;
        }
        let (td, svc, mock) = issues_service();
        seed_repo(&td, "alice", "demo");

        let open = "https://pod.example/alice/public/forge/alice--demo/i1.jsonld";
        mock.put(open, b"opening");
        svc.handle(
            post_form(
                "/forge/alice/demo/issues",
                &format!("title=t&resourceUrl={}", open.replace(':', "%3A").replace('/', "%2F")),
            ),
            pod_agent("alice"),
        )
        .await
        .unwrap();

        // bob comments — his body lives in HIS pod, namespaced by the repo.
        let c = "https://pod.example/bob/public/forge/alice--demo/c1.jsonld";
        mock.put(c, b"a helpful comment");
        let r = svc
            .handle(
                post_form(
                    "/forge/alice/demo/issues/1",
                    &format!("resourceUrl={}", c.replace(':', "%3A").replace('/', "%2F")),
                ),
                pod_agent("bob"),
            )
            .await
            .unwrap();
        assert_eq!(r.status, 303);

        let (_s, detail) = body(&svc, "/forge/alice/demo/issues/1").await;
        assert!(detail.contains("opening"));
        assert!(detail.contains("a helpful comment"));
        assert!(detail.contains("commented"));
    }

    #[tokio::test]
    async fn issue_create_without_loopback_fails_closed() {
        if !git_available() {
            return;
        }
        // No loopback injected → pod-body verification unavailable (501).
        let (td, svc) = service();
        seed_repo(&td, "alice", "demo");
        let url = "https://pod.example/alice/public/forge/alice--demo/x.jsonld";
        let r = svc
            .handle(
                post_form(
                    "/forge/alice/demo/issues",
                    &format!("title=x&resourceUrl={}", url.replace(':', "%3A").replace('/', "%2F")),
                ),
                pod_agent("alice"),
            )
            .await
            .unwrap();
        assert_eq!(r.status, 501);
    }

    // ---- Phase 3 tokens + hosted + namespace guard ---------------------

    fn hex64() -> String {
        "d".repeat(64)
    }

    fn nostr_agent(hex: &str) -> ForgeAgent {
        ForgeAgent::Nostr {
            pubkey_hex: hex.to_string(),
        }
    }

    fn post_json(path: &str, json: &str) -> ForgeRequest {
        ForgeRequest {
            method: "POST".into(),
            path: path.into(),
            query: String::new(),
            headers: vec![("content-type".into(), "application/json".into())],
            raw_body: Bytes::from(json.to_string()),
            host_url: Some("https://pod.example".into()),
        }
    }

    #[tokio::test]
    async fn token_mint_then_resolves() {
        let (_td, svc) = service();
        // Mint a token for a NIP-98-authenticated nostr caller.
        let agent = nostr_agent(&hex64());
        let r = svc
            .handle(post_form("/forge/api/token", ""), agent.clone())
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        let token = v["token"].as_str().unwrap().to_string();
        assert!(token.starts_with("f1."));

        // Present the token on a later request → same identity resolves.
        let follow = ForgeRequest {
            method: "GET".into(),
            path: "/forge/x".into(),
            query: String::new(),
            headers: vec![("authorization".into(), format!("Bearer {token}"))],
            raw_body: Bytes::new(),
            host_url: Some("https://pod.example".into()),
        };
        assert_eq!(svc.resolve_agent(&follow), agent);
    }

    #[tokio::test]
    async fn token_mint_anonymous_is_401() {
        let (_td, svc) = service();
        let r = svc
            .handle(post_form("/forge/api/token", ""), ForgeAgent::Anonymous)
            .await
            .unwrap();
        assert_eq!(r.status, 401);
    }

    #[tokio::test]
    async fn podless_nostr_issue_uses_hosted_store() {
        if !git_available() {
            return;
        }
        let (td, svc) = service();
        let hex = hex64();
        seed_repo(&td, &hex, "proj");

        // No pod: submit the body inline; the forge hosts it.
        let r = svc
            .handle(
                post_json(
                    &format!("/forge/{hex}/proj/issues"),
                    "{\"title\":\"podless bug\",\"body\":\"no pod here\"}",
                ),
                nostr_agent(&hex),
            )
            .await
            .unwrap();
        assert_eq!(r.status, 303, "podless issue create should redirect");

        // Detail re-fetches from the hosted store (no loopback needed).
        let (s, detail) = body(&svc, &format!("/forge/{hex}/proj/issues/1")).await;
        assert_eq!(s, 200);
        assert!(detail.contains("no pod here"));
        assert!(detail.contains("podless bug"));
    }

    #[tokio::test]
    async fn hosted_api_get_and_owner_only_delete() {
        let (td, svc) = service();
        let hex = hex64();
        // Write a hosted body directly through a store on the same dir.
        let store = HostedStore::new(td.path());
        let rref = store.write(&hex, b"{\"body\":\"hi\"}").await.unwrap();
        let (h, u) = HostedStore::parse_ref(&rref).unwrap();

        // Public GET.
        let (s, got) = body(&svc, &format!("/forge/api/hosted/{h}/{u}")).await;
        assert_eq!(s, 200);
        assert!(got.contains("hi"));

        // A non-owner DELETE is 403.
        let del_other = ForgeRequest {
            method: "DELETE".into(),
            path: format!("/forge/api/hosted/{h}/{u}"),
            query: String::new(),
            headers: vec![],
            raw_body: Bytes::new(),
            host_url: Some("https://pod.example".into()),
        };
        let r1 = svc
            .handle(del_other.clone(), nostr_agent(&"e".repeat(64)))
            .await
            .unwrap();
        assert_eq!(r1.status, 403);

        // The owner DELETE succeeds (204), then the body is gone (404).
        let r2 = svc.handle(del_other, nostr_agent(&hex)).await.unwrap();
        assert_eq!(r2.status, 204);
        let (s2, _) = body(&svc, &format!("/forge/api/hosted/{h}/{u}")).await;
        assert_eq!(s2, 404);
    }

    #[tokio::test]
    async fn namespace_push_guard_blocks_foreign_push() {
        let (_td, svc) = service();
        // A receive-pack (push) into alice's namespace by bob → 403,
        // before the CGI is ever invoked.
        let push = ForgeRequest {
            method: "POST".into(),
            path: "/forge/alice/demo.git/git-receive-pack".into(),
            query: String::new(),
            headers: vec![],
            raw_body: Bytes::new(),
            host_url: Some("https://pod.example".into()),
        };
        let r = svc
            .handle(push.clone(), nostr_agent(&hex64()))
            .await
            .unwrap();
        assert_eq!(r.status, 403);

        // Anonymous push is also blocked.
        let r_anon = svc.handle(push, ForgeAgent::Anonymous).await.unwrap();
        assert_eq!(r_anon.status, 403);
    }

    #[tokio::test]
    async fn namespace_push_guard_allows_own_push() {
        // A push into the caller's OWN namespace passes the guard (it then
        // reaches the CGI, which is absent here → a non-403 backend error).
        let (_td, svc) = service();
        let hex = hex64();
        let push = ForgeRequest {
            method: "POST".into(),
            path: format!("/forge/{hex}/demo.git/git-receive-pack"),
            query: String::new(),
            headers: vec![],
            raw_body: Bytes::new(),
            host_url: Some("https://pod.example".into()),
        };
        let r = svc.handle(push, nostr_agent(&hex)).await.unwrap();
        assert_ne!(r.status, 403, "own-namespace push must pass the guard");
    }
}
