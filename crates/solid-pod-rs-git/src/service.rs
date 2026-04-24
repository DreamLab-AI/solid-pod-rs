//! Binder-agnostic Git HTTP service — spawns the system
//! `git http-backend` CGI and shuttles stdin/stdout between it and
//! the HTTP layer.
//!
//! Mirrors JSS `src/handlers/git.js` lines 95-268 (`handleGit`) end
//! to end. The key design choices, all pulled straight from JSS:
//!
//! * `GIT_PROJECT_ROOT = repo_root`, `PATH_INFO = request path`. The
//!   CGI walks `GIT_PROJECT_ROOT + PATH_INFO` internally.
//! * `GIT_HTTP_EXPORT_ALL` set (empty value, just defined) so all
//!   repos under the root are read-exportable.
//! * `GIT_HTTP_RECEIVE_PACK=true` so push is enabled (JSS line 157).
//! * `GIT_CONFIG_PARAMETERS` injects `uploadpack.allowTipSHA1InWant`
//!   to match JSS line 158.
//! * For non-bare repos we set `GIT_DIR` to the `.git` child (JSS
//!   lines 168-170).
//! * We parse CGI headers from stdout, separate them from body on
//!   `\r\n\r\n` (fall back to `\n\n`), and convert the first `Status:`
//!   header into the HTTP response status.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use crate::auth::{AuthError, GitAuth};
use crate::config::{apply_write_config, find_git_dir};
use crate::error::GitError;
use crate::guard::{extract_repo_slug, path_safe};

/// Path to the CGI binary shipped with git. Configurable via
/// `GIT_HTTP_BACKEND_PATH` env var at service-startup time (the
/// default matches Debian/Ubuntu).
pub const DEFAULT_GIT_HTTP_BACKEND: &str = "/usr/lib/git-core/git-http-backend";

/// Opaque HTTP request shape consumed by the service.
///
/// The crate stays intentionally binder-agnostic — callers (axum,
/// actix-web, hyper raw, …) translate their native request type into
/// this struct before calling `handle`.
#[derive(Debug, Clone)]
pub struct GitRequest {
    /// e.g. `"GET"`, `"POST"`, `"OPTIONS"`.
    pub method: String,
    /// The URL path (`"/alice/repo/info/refs"`), already
    /// percent-decoded.
    pub path: String,
    /// The raw query string without the leading `?`.
    pub query: String,
    /// All request headers as `(name, value)` tuples. Name is
    /// compared case-insensitively by the service.
    pub headers: Vec<(String, String)>,
    /// Request body (empty for GETs).
    pub body: Bytes,
    /// Scheme + host (`"https://pod.example.com"`) — used only to
    /// reconstruct the URL that NIP-98 verification checks. If None,
    /// we fall back to `http://localhost`.
    pub host_url: Option<String>,
}

impl GitRequest {
    /// Reconstruct the canonical URL that a NIP-98 `u` tag is
    /// expected to point at.
    pub fn auth_url(&self) -> String {
        let base = self
            .host_url
            .clone()
            .unwrap_or_else(|| "http://localhost".to_string());
        if self.query.is_empty() {
            format!("{base}{}", self.path)
        } else {
            format!("{base}{}?{}", self.path, self.query)
        }
    }

    /// `true` if this request requires a successful auth check (push).
    #[must_use]
    pub fn is_write(&self) -> bool {
        self.path.contains("/git-receive-pack")
            || self.query.contains("service=git-receive-pack")
    }
}

/// CGI response to return to the HTTP layer.
#[derive(Debug, Clone)]
pub struct GitResponse {
    /// HTTP status (derived from the CGI `Status:` header, or 200 by
    /// default).
    pub status: u16,
    /// All response headers emitted by the CGI plus CORS headers.
    pub headers: Vec<(String, String)>,
    /// Body bytes — already includes the CGI body payload.
    pub body: Bytes,
}

impl GitResponse {
    /// Build a simple error response (no CGI invocation).
    #[must_use]
    pub fn error(status: u16, msg: impl Into<String>) -> Self {
        let msg = msg.into();
        let body = Bytes::from(format!("{{\"error\":\"{msg}\"}}"));
        Self {
            status,
            headers: vec![
                ("content-type".into(), "application/json".into()),
                ("access-control-allow-origin".into(), "*".into()),
            ],
            body,
        }
    }
}

/// The Git HTTP service.
#[derive(Clone)]
pub struct GitHttpService {
    repo_root: PathBuf,
    auth: Option<Arc<dyn GitAuth>>,
    backend_path: PathBuf,
}

impl std::fmt::Debug for GitHttpService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHttpService")
            .field("repo_root", &self.repo_root)
            .field("auth", &self.auth.is_some())
            .field("backend_path", &self.backend_path)
            .finish()
    }
}

impl GitHttpService {
    /// Build a service rooted at `repo_root`. All repos served must
    /// live under this directory.
    #[must_use]
    pub fn new(repo_root: PathBuf) -> Self {
        let backend = std::env::var("GIT_HTTP_BACKEND_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_GIT_HTTP_BACKEND));
        Self {
            repo_root,
            auth: None,
            backend_path: backend,
        }
    }

    /// Override the default CGI binary path.
    #[must_use]
    pub fn with_backend_path(mut self, path: PathBuf) -> Self {
        self.backend_path = path;
        self
    }

    /// Plug in an authoriser. Without one, write requests still
    /// succeed — the service becomes an anonymous-push setup, which
    /// is the behaviour JSS uses when no `handleAuth` pre-hook fires.
    #[must_use]
    pub fn with_auth<A: GitAuth + 'static>(mut self, auth: A) -> Self {
        self.auth = Some(Arc::new(auth));
        self
    }

    /// Same as [`with_auth`] but takes a pre-boxed Arc.
    #[must_use]
    pub fn with_auth_arc(mut self, auth: Arc<dyn GitAuth>) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Handle an incoming Git HTTP request.
    pub async fn handle(&self, req: GitRequest) -> Result<GitResponse, GitError> {
        // CORS preflight — JSS lines 97-102.
        if req.method.eq_ignore_ascii_case("OPTIONS") {
            return Ok(GitResponse {
                status: 200,
                headers: vec![
                    ("access-control-allow-origin".into(), "*".into()),
                    (
                        "access-control-allow-methods".into(),
                        "GET, POST, OPTIONS".into(),
                    ),
                    (
                        "access-control-allow-headers".into(),
                        "Content-Type, Authorization".into(),
                    ),
                ],
                body: Bytes::new(),
            });
        }

        // 1. Parse + guard the repo path.
        let slug = extract_repo_slug(&req.path);
        let repo_abs = if slug == "." {
            self.repo_root.canonicalize()?
        } else {
            path_safe(&self.repo_root, &slug)?
        };

        // 2. Find the git dir. Missing => 404.
        let git_dir = match find_git_dir(&repo_abs)? {
            Some(g) => g,
            None => {
                return Err(GitError::NotARepository(slug));
            }
        };

        // 3. Auth for writes (JSS: the route-level `preValidation`
        //    hook on `/git-receive-pack` calls `handleAuth`; we fold
        //    that into a single check here).
        let mut remote_user = String::new();
        if req.is_write() {
            let auth = self
                .auth
                .as_ref()
                .ok_or_else(|| GitError::Unauthorised("no auth provider configured".into()))?;
            match auth.authorise(&req).await {
                Ok(id) => remote_user = id,
                Err(AuthError::Missing) => {
                    return Err(GitError::Unauthorised("missing Authorization".into()));
                }
                Err(e) => return Err(GitError::Auth(e)),
            }
        }

        // 4. Apply the receive-pack config mutators on writes. Errors
        //    are best-effort (JSS swallows them too).
        if req.is_write() {
            let _ = apply_write_config(&git_dir, &repo_abs).await;
        }

        // 5. Spawn the CGI and shuttle request/response bytes.
        spawn_cgi(&self.backend_path, &self.repo_root, &git_dir, &remote_user, req).await
    }
}

/// Core CGI driver — shared by all routes.
async fn spawn_cgi(
    backend: &Path,
    repo_root: &Path,
    git_dir: &crate::config::GitDir,
    remote_user: &str,
    req: GitRequest,
) -> Result<GitResponse, GitError> {
    // Assemble CGI env. We deliberately start from an empty env and
    // only inherit PATH (to locate git subcommands the backend itself
    // shells out to) — this matches the spirit of JSS which spreads
    // `process.env` but we narrow it for defence-in-depth.
    let mut env: HashMap<String, String> = HashMap::new();
    if let Ok(path) = std::env::var("PATH") {
        env.insert("PATH".into(), path);
    }

    env.insert(
        "GIT_PROJECT_ROOT".into(),
        repo_root
            .canonicalize()
            .unwrap_or_else(|_| repo_root.to_path_buf())
            .to_string_lossy()
            .into_owned(),
    );
    env.insert("GIT_HTTP_EXPORT_ALL".into(), String::new());
    env.insert("GIT_HTTP_RECEIVE_PACK".into(), "true".into());
    env.insert(
        "GIT_CONFIG_PARAMETERS".into(),
        "'uploadpack.allowTipSHA1InWant=true'".into(),
    );
    env.insert("PATH_INFO".into(), req.path.clone());
    env.insert("REQUEST_METHOD".into(), req.method.to_uppercase());
    env.insert("QUERY_STRING".into(), req.query.clone());
    env.insert("REMOTE_USER".into(), remote_user.to_string());

    for (k, v) in &req.headers {
        let kl = k.to_lowercase();
        if kl == "content-type" {
            env.insert("CONTENT_TYPE".into(), v.clone());
        } else if kl == "content-length" {
            env.insert("CONTENT_LENGTH".into(), v.clone());
        }
    }
    env.entry("CONTENT_LENGTH".into())
        .or_insert_with(|| req.body.len().to_string());
    env.entry("CONTENT_TYPE".into()).or_default();

    if git_dir.is_regular {
        env.insert(
            "GIT_DIR".into(),
            git_dir.git_dir.to_string_lossy().into_owned(),
        );
    }

    let mut cmd = Command::new(backend);
    cmd.env_clear()
        .envs(&env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(GitError::BackendNotAvailable(format!(
                "spawn {}: {}",
                backend.display(),
                e
            )));
        }
        Err(e) => return Err(GitError::Io(e)),
    };

    // Write body → stdin.
    if let Some(mut stdin) = child.stdin.take() {
        if !req.body.is_empty() {
            stdin.write_all(&req.body).await?;
        }
        drop(stdin); // close stdin so git-http-backend can exit.
    }

    // Collect stdout + stderr concurrently.
    let mut stdout = child.stdout.take().expect("stdout piped");
    let mut stderr = child.stderr.take().expect("stderr piped");

    let stdout_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        stdout.read_to_end(&mut buf).await.map(|_| buf)
    });
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf).await;
        buf
    });

    let status = child.wait().await?;
    let stdout_bytes = stdout_task
        .await
        .map_err(|e| GitError::MalformedCgi(format!("stdout task: {e}")))??;
    let stderr_bytes = stderr_task.await.unwrap_or_default();

    if !status.success() && stdout_bytes.is_empty() {
        return Err(GitError::BackendFailed {
            exit_code: status.code(),
            stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
        });
    }

    parse_cgi_output(&stdout_bytes)
}

/// Split CGI headers from body and translate into a `GitResponse`.
fn parse_cgi_output(stdout: &[u8]) -> Result<GitResponse, GitError> {
    // Find the CGI header/body separator.
    let (sep_idx, sep_len) = {
        if let Some(i) = find_subsequence(stdout, b"\r\n\r\n") {
            (i, 4)
        } else if let Some(i) = find_subsequence(stdout, b"\n\n") {
            (i, 2)
        } else {
            return Err(GitError::MalformedCgi(
                "no header/body separator".into(),
            ));
        }
    };

    let header_section = std::str::from_utf8(&stdout[..sep_idx])
        .map_err(|e| GitError::MalformedCgi(format!("utf-8 in headers: {e}")))?;
    let body = Bytes::copy_from_slice(&stdout[sep_idx + sep_len..]);

    let mut status: u16 = 200;
    let mut headers: Vec<(String, String)> = Vec::new();

    for line in header_section.split(['\n', '\r']) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some(colon) = line.find(':') else { continue };
        let key = line[..colon].trim().to_string();
        let value = line[colon + 1..].trim().to_string();
        if key.eq_ignore_ascii_case("status") {
            status = value
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(200);
        } else {
            headers.push((key, value));
        }
    }

    // CORS headers (JSS lines 218-220).
    headers.push((
        "Access-Control-Allow-Origin".into(),
        "*".into(),
    ));
    headers.push((
        "Access-Control-Allow-Methods".into(),
        "GET, POST, OPTIONS".into(),
    ));
    headers.push((
        "Access-Control-Allow-Headers".into(),
        "Content-Type, Authorization".into(),
    ));

    Ok(GitResponse {
        status,
        headers,
        body,
    })
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cgi_basic() {
        let raw = b"Content-Type: application/x-git-upload-pack-advertisement\r\nStatus: 200 OK\r\n\r\nPKFILE-BODY";
        let r = parse_cgi_output(raw).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, Bytes::from_static(b"PKFILE-BODY"));
        assert!(r
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type")));
    }

    #[test]
    fn parse_cgi_lf_only_separator() {
        let raw = b"Content-Type: text/plain\n\nHELLO";
        let r = parse_cgi_output(raw).unwrap();
        assert_eq!(r.body, Bytes::from_static(b"HELLO"));
    }

    #[test]
    fn parse_cgi_status_override() {
        let raw = b"Status: 403 Forbidden\r\n\r\nNO";
        let r = parse_cgi_output(raw).unwrap();
        assert_eq!(r.status, 403);
    }

    #[test]
    fn parse_cgi_no_separator_fails() {
        let raw = b"Content-Type: text/plain\r\nonly-headers";
        assert!(parse_cgi_output(raw).is_err());
    }

    #[test]
    fn git_request_is_write_detects_receive_pack_path() {
        let req = GitRequest {
            method: "POST".into(),
            path: "/repo/git-receive-pack".into(),
            query: String::new(),
            headers: vec![],
            body: Bytes::new(),
            host_url: None,
        };
        assert!(req.is_write());
    }

    #[test]
    fn git_request_is_write_detects_receive_pack_query() {
        let req = GitRequest {
            method: "GET".into(),
            path: "/repo/info/refs".into(),
            query: "service=git-receive-pack".into(),
            headers: vec![],
            body: Bytes::new(),
            host_url: None,
        };
        assert!(req.is_write());
    }

    #[test]
    fn git_request_is_write_false_for_read() {
        let req = GitRequest {
            method: "GET".into(),
            path: "/repo/info/refs".into(),
            query: "service=git-upload-pack".into(),
            headers: vec![],
            body: Bytes::new(),
            host_url: None,
        };
        assert!(!req.is_write());
    }

    #[test]
    fn git_request_auth_url_without_query() {
        let req = GitRequest {
            method: "GET".into(),
            path: "/repo/info/refs".into(),
            query: String::new(),
            headers: vec![],
            body: Bytes::new(),
            host_url: Some("https://pod.example.com".into()),
        };
        assert_eq!(req.auth_url(), "https://pod.example.com/repo/info/refs");
    }

    #[test]
    fn git_request_auth_url_with_query() {
        let req = GitRequest {
            method: "GET".into(),
            path: "/repo/info/refs".into(),
            query: "service=git-upload-pack".into(),
            headers: vec![],
            body: Bytes::new(),
            host_url: Some("https://pod.example.com".into()),
        };
        assert_eq!(
            req.auth_url(),
            "https://pod.example.com/repo/info/refs?service=git-upload-pack"
        );
    }

    #[test]
    fn git_response_error_helper() {
        let r = GitResponse::error(404, "not found");
        assert_eq!(r.status, 404);
        assert!(!r.body.is_empty());
    }
}
