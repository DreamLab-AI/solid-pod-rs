//! remoteStorage (draft-dejong-remotestorage-22) over the pod's storage
//! (SP-PAR-283). Off unless `--remotestorage` is given.
//!
//! # Routes
//!
//! With the user name `U` (default `me`):
//!
//! * `GET|HEAD|PUT|DELETE|OPTIONS /storage/U/<path>`: documents and folders.
//! * `POST /remotestorage/tokens`: the pod owner mints a scoped bearer token.
//! * `DELETE /remotestorage/tokens`: the pod owner revokes every token.
//!
//! # Authority: what a remoteStorage token can reach
//!
//! A token is 32 random bytes (hex), shown once at minting; only its SHA-256
//! is kept (in memory, and in `<data root>/.remotestorage/tokens.json` when
//! there is a data root). It carries a list of scopes `module:r` or
//! `module:rw` (or `*:r`, `*:rw`) and an expiry, and it is checked with a
//! constant-time comparison.
//!
//! * **Which pod, which subtree**: the pod served by this process, and only
//!   the subtree `/remotestorage/` of its storage. `/storage/U/a/b` is the
//!   pod resource `/remotestorage/a/b`. Nothing else is reachable through a
//!   token: not the pod root, not any ACL or metadata document (names ending
//!   `.acl` or `.meta` are refused), not a dotfile, not `..`.
//! * **Which part of that subtree**: scope `contacts:rw` covers
//!   `/contacts/` and `/public/contacts/`; `*` covers everything under the
//!   subtree, including the root folder listing and top-level documents.
//!   `r` allows GET and HEAD, `rw` also PUT and DELETE.
//! * **Public folder**: a document under `/public/` is readable without a
//!   token. A folder listing is not, including `/public/` and
//!   `/public/<module>/`: it needs a token whose scope covers that folder.
//! * The pod's own WAC does not govern these routes (the token does), and
//!   a remoteStorage token is not accepted anywhere else: on every other
//!   route the same header is an unknown credential.
//!
//! # Not provided
//!
//! The OAuth authorisation endpoint (RFC 6749 section 4.2). A browser
//! redirect cannot carry the pod owner's NIP-98 credential, and building a
//! login and consent page is a product decision; WebFinger therefore omits
//! that property, and tokens are issued by the owner through the API above.
//! Writes here do not publish `.notifications` events, and `Last-Modified`
//! is not sent.

use std::path::PathBuf;
use std::sync::Arc;

use actix_web::http::{header, Method, StatusCode};
use actix_web::{web, HttpRequest, HttpResponse};
use bytes::Bytes;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::AppState;

/// Where remoteStorage data lives in the pod's storage.
pub const ROOT: &str = "/remotestorage";
/// Most tokens kept at once.
pub const MAX_TOKENS: usize = 64;
/// Default token lifetime (30 days).
pub const DEFAULT_TTL_SECS: u64 = 30 * 24 * 3600;
/// Longest token lifetime (one year).
pub const MAX_TTL_SECS: u64 = 365 * 24 * 3600;
const MAX_SCOPES: usize = 16;
const MAX_PATH_BYTES: usize = 1024;
const MAX_DEPTH: usize = 16;
const MAX_NAME_BYTES: usize = 255;
/// Folder entries one listing may visit (recursively, for ETags).
const WALK_BUDGET: usize = 5_000;
const MINT_BODY_CAP: usize = 4 * 1024;
const FOLDER_TYPE: &str = "application/ld+json";
const FOLDER_CONTEXT: &str = "http://remotestorage.io/spec/folder-description";

/// One granted scope: a module (`None` is `*`) and whether writes are allowed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    /// The module folder name, or `None` for `*`.
    pub module: Option<String>,
    /// `rw` rather than `r`.
    pub write: bool,
}

impl Scope {
    /// Parse a space-separated scope string such as `contacts:rw *:r`.
    ///
    /// # Errors
    ///
    /// A message when a scope is malformed, there are none, or more than 16.
    pub fn parse_list(s: &str) -> Result<Vec<Scope>, String> {
        let mut out = Vec::new();
        for item in s.split_ascii_whitespace() {
            let (name, mode) = item
                .split_once(':')
                .ok_or_else(|| format!("scope {item:?} must be module:r or module:rw"))?;
            let write = match mode {
                "r" => false,
                "rw" => true,
                _ => return Err(format!("scope {item:?} must end in :r or :rw")),
            };
            let module = if name == "*" {
                None
            } else if !name.is_empty()
                && name.len() <= 64
                && name != "public"
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            {
                Some(name.to_string())
            } else {
                return Err(format!("scope module {name:?} is not allowed"));
            };
            out.push(Scope { module, write });
        }
        if out.is_empty() || out.len() > MAX_SCOPES {
            return Err(format!("give between 1 and {MAX_SCOPES} scopes"));
        }
        Ok(out)
    }

    fn render(list: &[Scope]) -> String {
        list.iter()
            .map(|s| {
                format!(
                    "{}:{}",
                    s.module.as_deref().unwrap_or("*"),
                    if s.write { "rw" } else { "r" }
                )
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenRecord {
    /// Hex SHA-256 of the token.
    hash: String,
    scopes: Vec<Scope>,
    /// Unix seconds.
    expires: u64,
}

/// A mounted remoteStorage service and its token table.
pub struct RemoteStorage {
    user: String,
    tokens: std::sync::Mutex<Vec<TokenRecord>>,
    file: Option<PathBuf>,
}

impl std::fmt::Debug for RemoteStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteStorage")
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn hash_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

impl RemoteStorage {
    /// A service for storage user `user`, loading any tokens saved under
    /// `data_root`.
    ///
    /// # Errors
    ///
    /// A message when `user` is not `[A-Za-z0-9_-]{1,64}` or the token file
    /// exists but cannot be read.
    pub fn new(user: &str, data_root: Option<&std::path::Path>) -> Result<Arc<Self>, String> {
        if user.is_empty()
            || user.len() > 64
            || !user
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(format!("remoteStorage user {user:?} is not allowed"));
        }
        let file = data_root.map(|r| r.join(".remotestorage").join("tokens.json"));
        let mut tokens: Vec<TokenRecord> = Vec::new();
        if let Some(f) = &file {
            match std::fs::read(f) {
                Ok(bytes) => {
                    tokens = serde_json::from_slice(&bytes)
                        .map_err(|e| format!("{}: {e}", f.display()))?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("{}: {e}", f.display())),
            }
        }
        let now = now_secs();
        tokens.retain(|t| t.expires > now);
        Ok(Arc::new(Self {
            user: user.to_string(),
            tokens: std::sync::Mutex::new(tokens),
            file,
        }))
    }

    /// The storage user name (the `U` in `/storage/U/`).
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }

    fn persist(&self, tokens: &[TokenRecord]) -> std::io::Result<()> {
        use std::io::Write as _;
        let Some(f) = &self.file else { return Ok(()) };
        if let Some(dir) = f.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = f.with_extension("json.tmp");
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut out = opts.open(&tmp)?;
        out.write_all(&serde_json::to_vec(tokens).map_err(std::io::Error::other)?)?;
        out.sync_all()?;
        std::fs::rename(&tmp, f)
    }

    /// Mint a token for `scopes` valid for `ttl_secs`; returns the token
    /// (shown once) and its expiry.
    ///
    /// # Errors
    ///
    /// A message when [`MAX_TOKENS`] are held or the table cannot be saved.
    pub fn mint(&self, scopes: Vec<Scope>, ttl_secs: u64) -> Result<(String, u64), String> {
        use rand::RngCore as _;
        let mut raw = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let token = hex::encode(raw);
        let expires = now_secs() + ttl_secs.min(MAX_TTL_SECS);
        let mut tokens = self
            .tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = now_secs();
        tokens.retain(|t| t.expires > now);
        if tokens.len() >= MAX_TOKENS {
            return Err(format!(
                "{MAX_TOKENS} tokens are already held; revoke them first"
            ));
        }
        tokens.push(TokenRecord {
            hash: hex::encode(hash_token(&token)),
            scopes,
            expires,
        });
        self.persist(&tokens)
            .map_err(|e| format!("saving tokens: {e}"))?;
        Ok((token, expires))
    }

    /// Delete every token.
    ///
    /// # Errors
    ///
    /// A message when the table cannot be saved.
    pub fn revoke_all(&self) -> Result<usize, String> {
        let mut tokens = self
            .tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let n = tokens.len();
        tokens.clear();
        self.persist(&tokens)
            .map_err(|e| format!("saving tokens: {e}"))?;
        Ok(n)
    }

    /// The scopes of `token`, or `None` when it is unknown or expired. Every
    /// stored hash is compared in constant time; none is skipped on a match.
    fn lookup(&self, token: &str) -> Option<Vec<Scope>> {
        let presented = hash_token(token);
        let now = now_secs();
        let tokens = self
            .tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut found: Option<Vec<Scope>> = None;
        for rec in tokens.iter() {
            let Ok(stored) = hex::decode(&rec.hash) else {
                continue;
            };
            if bool::from(stored.as_slice().ct_eq(&presented)) && rec.expires > now {
                found = Some(rec.scopes.clone());
            }
        }
        found
    }
}

// ---------------------------------------------------------------------------
// Paths and scopes
// ---------------------------------------------------------------------------

/// A validated request path: decoded segments and whether it names a folder.
#[derive(Debug, PartialEq, Eq)]
struct RsPath {
    segments: Vec<String>,
    folder: bool,
}

impl RsPath {
    /// `/a/b/c` form (folders end in `/`).
    fn display(&self) -> String {
        let mut s = String::from("/");
        s.push_str(&self.segments.join("/"));
        if self.folder && !self.segments.is_empty() {
            s.push('/');
        }
        s
    }

    /// The pod storage key.
    fn key(&self) -> String {
        format!("{ROOT}{}", self.display())
    }

    /// The module folder the path lies in, or `None` for the root folder, the
    /// `/public/` folder and a top-level document (which `*` alone covers).
    fn module(&self) -> Option<&str> {
        let s = &self.segments;
        let idx = usize::from(s.first().is_some_and(|f| f == "public"));
        let module = s.get(idx)?;
        // The last segment of a non-folder path is a document, not a module.
        let is_leaf_document = !self.folder && s.len() == idx + 1;
        (!is_leaf_document).then_some(module.as_str())
    }

    fn is_public_document(&self) -> bool {
        !self.folder && self.segments.len() >= 2 && self.segments[0] == "public"
    }
}

/// Whether one DECODED path segment may name a stored document.
///
/// Names are compared case-folded (the way a case-insensitive filesystem would
/// see them) so `x.ACL`, `x.%41CL` (decoded to `x.ACL`) and `x.meta.j\u{17F}on`
/// are the sidecars they alias; the pod's own dotfile policy
/// ([`solid_pod_rs::security::dotfile::is_path_allowed`]) runs on the segment as
/// well, so this route can never accept a name the rest of the server refuses.
fn valid_segment(s: &str) -> bool {
    use solid_pod_rs::security::dotfile::{fold_case, is_path_allowed};
    let folded = fold_case(s);
    !s.is_empty()
        && s.len() <= MAX_NAME_BYTES
        && s != "."
        && s != ".."
        && !s.starts_with('.')
        && !s.contains(['/', '\\', '\0'])
        && !s.chars().any(char::is_control)
        && !folded.contains(".solid-pod-tmp-")
        && !folded.ends_with(".meta.json")
        && solid_pod_rs::wac::protected_resource_for_acl(&format!("/{folded}")).is_none()
        && is_path_allowed(s).is_ok()
}

/// Validate the part of the URL path after `/storage/U`, which is `/` or
/// `/a/b` or `/a/b/`.
fn parse_path(raw: &str) -> Result<RsPath, &'static str> {
    if raw.len() > MAX_PATH_BYTES * 3 {
        return Err("path too long");
    }
    let folder = raw.ends_with('/') || raw.is_empty();
    let mut segments = Vec::new();
    for part in raw.split('/').filter(|p| !p.is_empty()) {
        let decoded = percent_encoding::percent_decode_str(part)
            .decode_utf8()
            .map_err(|_| "path is not UTF-8")?
            .into_owned();
        if !valid_segment(&decoded) {
            return Err("path segment not allowed");
        }
        segments.push(decoded);
    }
    if segments.len() > MAX_DEPTH
        || segments.iter().map(String::len).sum::<usize>() > MAX_PATH_BYTES
    {
        return Err("path too long");
    }
    Ok(RsPath { segments, folder })
}

/// Whether `scopes` allow `write` (or read) of `path`.
fn scope_allows(scopes: &[Scope], path: &RsPath, write: bool) -> bool {
    let module = path.module();
    scopes.iter().any(|s| {
        (!write || s.write)
            && match (&s.module, module) {
                (None, _) => true,
                (Some(want), Some(have)) => want == have,
                (Some(_), None) => false,
            }
    })
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

fn cors(mut b: actix_web::HttpResponseBuilder) -> actix_web::HttpResponseBuilder {
    b.insert_header(("access-control-allow-origin", "*"))
        .insert_header((
            "access-control-expose-headers",
            "ETag, Content-Length, Content-Type",
        ))
        .insert_header(("cache-control", "no-cache"));
    b
}

fn reply(status: StatusCode, msg: &str) -> HttpResponse {
    cors(HttpResponse::build(status)).body(msg.to_string())
}

fn unauthorised(invalid: bool) -> HttpResponse {
    let challenge = if invalid {
        "Bearer error=\"invalid_token\""
    } else {
        "Bearer"
    };
    cors(HttpResponse::Unauthorized())
        .insert_header((header::WWW_AUTHENTICATE, challenge))
        .body("unauthorised")
}

fn quote(etag: &str) -> String {
    format!("\"{}\"", etag.trim_matches('"'))
}

/// Whether `value` (an `If-Match` / `If-None-Match` header) matches `etag`.
fn etag_matches(value: &str, etag: &str) -> bool {
    let want = etag.trim_matches('"');
    value
        .split(',')
        .map(str::trim)
        .any(|v| v == "*" || v.trim_start_matches("W/").trim_matches('"') == want)
}

// ---------------------------------------------------------------------------
// Folder walk
// ---------------------------------------------------------------------------

struct Entry {
    name: String,
    etag: String,
    /// `(content type, length)` for a document; `None` for a folder.
    doc: Option<(String, u64)>,
}

/// The visible children of folder `key` with their ETags; empty folders are
/// omitted. A folder's ETag is a hash over its entries, so it changes when
/// any document beneath it does.
async fn list_folder(
    state: &AppState,
    key: &str,
    budget: &mut usize,
    depth: usize,
) -> Result<Vec<Entry>, &'static str> {
    if depth > MAX_DEPTH {
        return Err("folder tree too deep");
    }
    let container = format!("{}/", key.trim_end_matches('/'));
    let names = state
        .storage
        .list(&container)
        .await
        .map_err(|_| "storage failure")?;
    let mut out = Vec::new();
    for raw in names {
        let is_dir = raw.ends_with('/');
        let name = raw.trim_end_matches('/').to_string();
        if !valid_segment(&name) {
            continue;
        }
        if *budget == 0 {
            return Err("folder too large");
        }
        *budget -= 1;
        let child = format!("{container}{name}");
        if is_dir {
            let inner = Box::pin(list_folder(state, &child, budget, depth + 1)).await?;
            if inner.is_empty() {
                continue;
            }
            out.push(Entry {
                name: format!("{name}/"),
                etag: folder_etag(&inner),
                doc: None,
            });
        } else if let Ok(meta) = state.storage.head(&child).await {
            out.push(Entry {
                name,
                etag: meta.etag.trim_matches('"').to_string(),
                doc: Some((meta.content_type, meta.size)),
            });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn folder_etag(entries: &[Entry]) -> String {
    let mut h = Sha256::new();
    for e in entries {
        h.update(e.name.as_bytes());
        h.update([0]);
        h.update(e.etag.as_bytes());
        h.update(b"\n");
    }
    hex::encode(h.finalize())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn read_capped(
    mut payload: web::Payload,
    cap: usize,
    declared: Option<usize>,
) -> Result<Bytes, (StatusCode, &'static str)> {
    if declared.is_some_and(|n| n > cap) {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "body too large"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk.map_err(|_| (StatusCode::BAD_REQUEST, "unreadable body"))?;
        if body.len() + chunk.len() > cap {
            return Err((StatusCode::PAYLOAD_TOO_LARGE, "body too large"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(body))
}

fn bearer(req: &HttpRequest) -> Option<&str> {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

/// Whether `content_type` (parameters and case ignored) is one a browser may
/// execute or script when it is shown: HTML, XHTML, SVG, XML in any
/// `+xml` form, and JavaScript. Such documents are also forced to download.
fn is_active_type(content_type: &str) -> bool {
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    matches!(
        essence.as_str(),
        "text/html"
            | "application/xhtml+xml"
            | "image/svg+xml"
            | "text/xml"
            | "application/xml"
            | "text/xsl"
            | "text/javascript"
            | "application/javascript"
            | "application/x-javascript"
            | "text/ecmascript"
            | "application/ecmascript"
    ) || essence.ends_with("+xml")
}

/// The Content-Security-Policy of every storage response.
///
/// `sandbox` (no `allow-*` tokens) makes a document that is opened in the
/// browser a unique, script-less origin, so nothing a token holder stores can
/// act as the pod origin; `default-src 'none'` additionally blocks any
/// sub-resource it names. Neither affects an application reading a document
/// with `fetch` or XHR (the intended use): CSP governs documents being
/// rendered, not data being read. The cost is that opening a stored PDF or
/// media file directly in a browser tab is refused by the sandbox.
const STORAGE_CSP: &str = "default-src 'none'; sandbox";

/// Mark `rsp` inert: no sniffing, sandboxed, and a download when the stored
/// type is active. Applied to every response of the storage route.
fn harden(mut rsp: HttpResponse) -> HttpResponse {
    let h = rsp.headers_mut();
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static(STORAGE_CSP),
    );
    let active = h
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(is_active_type);
    if active {
        h.insert(
            header::CONTENT_DISPOSITION,
            header::HeaderValue::from_static("attachment"),
        );
    }
    rsp
}

/// `OPTIONS /storage/U/...`: the CORS preflight.
pub(crate) async fn handle_options() -> HttpResponse {
    harden(options_response())
}

fn options_response() -> HttpResponse {
    HttpResponse::NoContent()
        .insert_header(("access-control-allow-origin", "*"))
        .insert_header((
            "access-control-allow-headers",
            "Authorization, Content-Length, Content-Type, If-Match, If-None-Match, Origin, X-Requested-With",
        ))
        .insert_header((
            "access-control-allow-methods",
            "GET, HEAD, PUT, DELETE, OPTIONS",
        ))
        .insert_header(("access-control-max-age", "7200"))
        .finish()
}

/// `GET|HEAD|PUT|DELETE /storage/U/<path>`. Every response, success or error,
/// goes through [`harden`].
pub(crate) async fn handle_storage(
    req: HttpRequest,
    payload: web::Payload,
    state: web::Data<AppState>,
) -> HttpResponse {
    harden(handle_storage_inner(req, payload, state).await)
}

async fn handle_storage_inner(
    req: HttpRequest,
    payload: web::Payload,
    state: web::Data<AppState>,
) -> HttpResponse {
    let Some(rs) = state.remotestorage.clone() else {
        return HttpResponse::NotFound().finish();
    };
    let prefix = format!("/storage/{}", rs.user);
    let Some(rest) = req.uri().path().strip_prefix(&prefix) else {
        return HttpResponse::NotFound().finish();
    };
    if !rest.is_empty() && !rest.starts_with('/') {
        return HttpResponse::NotFound().finish();
    }
    let path = match parse_path(rest) {
        Ok(p) => p,
        Err(msg) => return reply(StatusCode::NOT_FOUND, msg),
    };
    let write = matches!(*req.method(), Method::PUT | Method::DELETE);

    // Authority: a public document may be read without a token; everything
    // else needs a valid token whose scopes cover the path and the mode.
    let public_read = !write && path.is_public_document();
    match bearer(&req) {
        Some(token) => match rs.lookup(token) {
            Some(scopes) => {
                if !scope_allows(&scopes, &path, write) {
                    return reply(StatusCode::FORBIDDEN, "scope does not cover this path");
                }
            }
            None => return unauthorised(true),
        },
        None if public_read => {}
        None => return unauthorised(false),
    }

    match *req.method() {
        Method::GET | Method::HEAD => get(&req, &state, &path).await,
        Method::PUT => put(&req, payload, &state, &path).await,
        Method::DELETE => delete(&req, &state, &path).await,
        _ => reply(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
    }
}

fn if_none_match(req: &HttpRequest) -> Option<&str> {
    req.headers()
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
}

fn if_match(req: &HttpRequest) -> Option<&str> {
    req.headers()
        .get(header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
}

async fn get(req: &HttpRequest, state: &AppState, path: &RsPath) -> HttpResponse {
    let head_only = req.method() == Method::HEAD;
    if path.folder {
        let key = path.key();
        let mut budget = WALK_BUDGET;
        let entries = match list_folder(state, &key, &mut budget, 0).await {
            Ok(e) => e,
            Err(msg) => return reply(StatusCode::INSUFFICIENT_STORAGE, msg),
        };
        let mut items = serde_json::Map::new();
        for e in &entries {
            let v = match &e.doc {
                Some((ct, len)) => {
                    serde_json::json!({"ETag": e.etag, "Content-Type": ct, "Content-Length": len})
                }
                None => serde_json::json!({"ETag": e.etag}),
            };
            items.insert(e.name.clone(), v);
        }
        let body = serde_json::json!({"@context": FOLDER_CONTEXT, "items": items});
        // An empty or absent folder is an empty listing with no ETag, so a
        // client does not treat it as unchanged.
        if entries.is_empty() {
            return finish_body(
                cors(HttpResponse::Ok()),
                FOLDER_TYPE,
                body.to_string(),
                head_only,
            );
        }
        let etag = quote(&folder_etag(&entries));
        if if_none_match(req).is_some_and(|v| etag_matches(v, &etag)) {
            return cors(HttpResponse::NotModified())
                .insert_header((header::ETAG, etag))
                .finish();
        }
        let mut b = cors(HttpResponse::Ok());
        b.insert_header((header::ETAG, etag));
        return finish_body(b, FOLDER_TYPE, body.to_string(), head_only);
    }
    let key = path.key();
    let Ok((bytes, meta)) = state.storage.get(&key).await else {
        return reply(StatusCode::NOT_FOUND, "not found");
    };
    let etag = quote(&meta.etag);
    if if_none_match(req).is_some_and(|v| etag_matches(v, &etag)) {
        return cors(HttpResponse::NotModified())
            .insert_header((header::ETAG, etag))
            .finish();
    }
    let mut b = cors(HttpResponse::Ok());
    b.insert_header((header::ETAG, etag));
    if head_only {
        b.insert_header((header::CONTENT_LENGTH, bytes.len().to_string()));
        return b.content_type(meta.content_type).finish();
    }
    b.content_type(meta.content_type).body(bytes)
}

fn finish_body(
    mut b: actix_web::HttpResponseBuilder,
    content_type: &str,
    body: String,
    head_only: bool,
) -> HttpResponse {
    b.content_type(content_type.to_string());
    if head_only {
        b.insert_header((header::CONTENT_LENGTH, body.len().to_string()));
        b.finish()
    } else {
        b.body(body)
    }
}

async fn put(
    req: &HttpRequest,
    payload: web::Payload,
    state: &AppState,
    path: &RsPath,
) -> HttpResponse {
    if path.folder || path.segments.is_empty() {
        return reply(StatusCode::BAD_REQUEST, "a folder cannot be written");
    }
    let declared = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    let body = match read_capped(payload, state.body_cap, declared).await {
        Ok(b) => b,
        Err((status, msg)) => return reply(status, msg),
    };
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() <= 255)
        .unwrap_or("application/octet-stream")
        .to_string();
    let key = path.key();
    let _guard = match crate::lock_resource(&*state.storage, &key).await {
        Ok(g) => g,
        Err(_) => return reply(StatusCode::SERVICE_UNAVAILABLE, "busy"),
    };
    if state.storage.is_directory(&key).await {
        return reply(StatusCode::CONFLICT, "a folder exists at this name");
    }
    let existing = state.storage.head(&key).await.ok();
    if let Some(v) = if_match(req) {
        match &existing {
            Some(m) if etag_matches(v, &m.etag) => {}
            _ => return reply(StatusCode::PRECONDITION_FAILED, "If-Match failed"),
        }
    }
    if let Some(v) = if_none_match(req) {
        if existing.as_ref().is_some_and(|m| etag_matches(v, &m.etag)) {
            return reply(StatusCode::PRECONDITION_FAILED, "If-None-Match failed");
        }
    }
    let quota = match crate::reserve_quota_for_size(state, &key, body.len() as u64).await {
        Ok(q) => q,
        Err(e) => return HttpResponse::from_error(e),
    };
    let write = state.storage.put(&key, body, &content_type).await;
    crate::finish_quota_reservation(state, quota, write.is_ok()).await;
    match write {
        Ok(meta) => {
            let status = if existing.is_some() {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            };
            cors(HttpResponse::build(status))
                .insert_header((header::ETAG, quote(&meta.etag)))
                .finish()
        }
        // An ancestor that is a document, or a name the backend refuses.
        Err(_) => reply(StatusCode::CONFLICT, "cannot write here"),
    }
}

async fn delete(req: &HttpRequest, state: &AppState, path: &RsPath) -> HttpResponse {
    if path.folder || path.segments.is_empty() {
        return reply(StatusCode::BAD_REQUEST, "a folder cannot be deleted");
    }
    let key = path.key();
    let _guard = match crate::lock_resource(&*state.storage, &key).await {
        Ok(g) => g,
        Err(_) => return reply(StatusCode::SERVICE_UNAVAILABLE, "busy"),
    };
    let Ok(meta) = state.storage.head(&key).await else {
        return reply(StatusCode::NOT_FOUND, "not found");
    };
    if state.storage.is_directory(&key).await {
        return reply(StatusCode::NOT_FOUND, "not found");
    }
    if let Some(v) = if_match(req) {
        if !etag_matches(v, &meta.etag) {
            return reply(StatusCode::PRECONDITION_FAILED, "If-Match failed");
        }
    }
    match state.storage.delete(&key).await {
        Ok(()) => cors(HttpResponse::Ok())
            .insert_header((header::ETAG, quote(&meta.etag)))
            .finish(),
        Err(_) => reply(StatusCode::INTERNAL_SERVER_ERROR, "delete failed"),
    }
}

// ---------------------------------------------------------------------------
// Token API (owner only)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct MintRequest {
    scope: String,
    #[serde(default)]
    ttl_secs: Option<u64>,
}

async fn require_owner(
    req: &HttpRequest,
    state: &AppState,
    body: Option<&[u8]>,
) -> Result<(), actix_web::Error> {
    let agent = crate::agent_uri(crate::extract_pubkey_with_body(req, body).await.as_ref());
    crate::enforce_write_ctx(
        state,
        "/",
        crate::AccessMode::Control,
        agent.as_deref(),
        crate::req_origin(req),
    )
    .await
}

/// `POST /remotestorage/tokens`: the pod owner mints a token.
///
/// Authorised only by a NIP-98 token bound to this exact body whose signer
/// holds `acl:Control` on `/`. The response carries the token once.
pub(crate) async fn handle_mint(
    req: HttpRequest,
    payload: web::Payload,
    state: web::Data<AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    let Some(rs) = state.remotestorage.clone() else {
        return Ok(HttpResponse::NotFound().finish());
    };
    let declared = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    let body = match read_capped(payload, MINT_BODY_CAP, declared).await {
        Ok(b) => b,
        Err((status, msg)) => return Ok(reply(status, msg)),
    };
    require_owner(&req, &state, Some(&body)).await?;
    let Ok(parsed) = serde_json::from_slice::<MintRequest>(&body) else {
        return Ok(reply(
            StatusCode::BAD_REQUEST,
            "expected {\"scope\": \"module:rw\"}",
        ));
    };
    let scopes = match Scope::parse_list(&parsed.scope) {
        Ok(s) => s,
        Err(m) => return Ok(reply(StatusCode::BAD_REQUEST, &m)),
    };
    let ttl = parsed.ttl_secs.unwrap_or(DEFAULT_TTL_SECS);
    if ttl == 0 {
        return Ok(reply(StatusCode::BAD_REQUEST, "ttl_secs must be positive"));
    }
    let rendered = Scope::render(&scopes);
    match rs.mint(scopes, ttl) {
        Ok((token, expires)) => Ok(HttpResponse::Created()
            .insert_header((header::CACHE_CONTROL, "no-store"))
            .json(serde_json::json!({
                "access_token": token,
                "token_type": "Bearer",
                "scope": rendered,
                "expires_at": expires,
            }))),
        Err(m) => Ok(reply(StatusCode::CONFLICT, &m)),
    }
}

/// `DELETE /remotestorage/tokens`: the pod owner revokes every token.
pub(crate) async fn handle_revoke(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    let Some(rs) = state.remotestorage.clone() else {
        return Ok(HttpResponse::NotFound().finish());
    };
    require_owner(&req, &state, None).await?;
    match rs.revoke_all() {
        Ok(n) => Ok(HttpResponse::Ok().json(serde_json::json!({"revoked": n}))),
        Err(m) => Ok(reply(StatusCode::INTERNAL_SERVER_ERROR, &m)),
    }
}

impl RemoteStorage {
    /// The WebFinger link object for `base_url`, advertising the storage root.
    /// The OAuth endpoint property is absent (see the module documentation).
    #[must_use]
    pub fn webfinger_link(&self, base_url: &str) -> serde_json::Value {
        serde_json::json!({
            "rel": "http://tools.ietf.org/id/draft-dejong-remotestorage",
            "href": format!("{}/storage/{}/", base_url.trim_end_matches('/'), self.user),
            "properties": {
                "http://remotestorage.io/spec/version": "draft-dejong-remotestorage-22",
                "http://tools.ietf.org/html/rfc6750#section-2.3": false,
                "http://tools.ietf.org/html/rfc2616#section-14.16": false,
                "http://remotestorage.io/spec/web-authoring": false,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(raw: &str) -> RsPath {
        parse_path(raw).unwrap()
    }

    #[test]
    fn modules_and_public_documents() {
        assert_eq!(p("/contacts/a").module(), Some("contacts"));
        assert_eq!(p("/contacts/").module(), Some("contacts"));
        assert_eq!(p("/public/contacts/a").module(), Some("contacts"));
        assert_eq!(p("/public/contacts/").module(), Some("contacts"));
        assert_eq!(p("/").module(), None);
        assert_eq!(p("/public/").module(), None);
        assert_eq!(p("/readme").module(), None);
        assert_eq!(p("/public/readme").module(), None);
        assert!(p("/public/contacts/a").is_public_document());
        assert!(!p("/public/contacts/").is_public_document());
        assert!(!p("/contacts/a").is_public_document());
    }

    #[test]
    fn hostile_paths_are_refused() {
        for bad in [
            "/a/../b",
            "/a/%2e%2e/b",
            "/a/%2E%2E/b",
            "/.hidden",
            "/a/.acl",
            "/a/x.acl",
            "/a/x.meta",
            "/a/%2Fb",
            "/a/b%5Cc",
            "/a/%00",
            "/a/.solid-pod-tmp-1",
        ] {
            assert!(parse_path(bad).is_err(), "{bad}");
        }
        assert!(parse_path("/a/b c.txt").is_ok());
    }

    /// Property: the sidecar-name guard is case-folded and runs on the DECODED
    /// segment, so no spelling of `.acl`, `.meta` or `.meta.json` (mixed case,
    /// percent-encoded letters, the long s) names a sidecar on a
    /// case-insensitive filesystem.
    #[test]
    fn case_and_encoding_variants_of_guarded_names_are_refused() {
        for bad in [
            "/a/x.ACL",
            "/a/x.Acl",
            "/a/x.%41CL",
            "/a/x.%61%43l",
            "/a/X.Meta",
            "/a/X.MET%41",
            "/a/y.META.JSON",
            "/a/y.meta.JS%4fN",
            "/a/x.meta.j%C5%BFon",
            "/a/.ACL",
            "/a/.%41cl",
            "/a/.SOLID-POD-TMP-1",
        ] {
            assert!(parse_path(bad).is_err(), "{bad} was accepted");
        }
        for ok in [
            "/a/acl.txt",
            "/a/x.aclx",
            "/a/meta",
            "/a/Notes.TXT",
            "/a/b.jsonld",
        ] {
            assert!(parse_path(ok).is_ok(), "{ok} was refused");
        }
    }

    #[test]
    fn active_types_are_recognised_whatever_the_spelling() {
        for yes in [
            "text/html",
            "TEXT/HTML; charset=utf-8",
            " application/xhtml+xml ",
            "image/svg+xml",
            "application/xml",
            "text/xml;charset=x",
            "application/rss+xml",
            "application/javascript",
        ] {
            assert!(is_active_type(yes), "{yes}");
        }
        for no in [
            "application/json",
            "text/plain",
            "image/png",
            "",
            "application/octet-stream",
        ] {
            assert!(!is_active_type(no), "{no}");
        }
    }

    #[test]
    fn scopes_parse_and_cover() {
        assert!(Scope::parse_list("").is_err());
        assert!(Scope::parse_list("contacts").is_err());
        assert!(Scope::parse_list("contacts:x").is_err());
        assert!(Scope::parse_list("public:rw").is_err());
        assert!(Scope::parse_list("a/b:r").is_err());
        let s = Scope::parse_list("contacts:rw notes:r").unwrap();
        assert!(scope_allows(&s, &p("/contacts/a"), true));
        assert!(scope_allows(&s, &p("/notes/a"), false));
        assert!(!scope_allows(&s, &p("/notes/a"), true));
        assert!(!scope_allows(&s, &p("/other/a"), false));
        assert!(!scope_allows(&s, &p("/"), false));
        let all = Scope::parse_list("*:r").unwrap();
        assert!(scope_allows(&all, &p("/"), false));
        assert!(!scope_allows(&all, &p("/x/y"), true));
    }

    #[test]
    fn tokens_are_looked_up_in_constant_time_and_expire() {
        let rs = RemoteStorage::new("me", None).unwrap();
        let (t, _) = rs.mint(Scope::parse_list("a:r").unwrap(), 60).unwrap();
        assert!(rs.lookup(&t).is_some());
        assert!(rs.lookup(&format!("{t}x")).is_none());
        assert!(rs.lookup("").is_none());
        rs.tokens.lock().unwrap()[0].expires = 1;
        assert!(rs.lookup(&t).is_none());
    }

    #[test]
    fn etag_matching() {
        assert!(etag_matches("\"a\"", "a"));
        assert!(etag_matches("W/\"a\", \"b\"", "b"));
        assert!(etag_matches("*", "z"));
        assert!(!etag_matches("\"a\"", "b"));
    }
}
