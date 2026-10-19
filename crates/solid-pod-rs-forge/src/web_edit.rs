//! `POST <prefix>/api/repos/<owner>/<repo>/edit`: commit **one file** over
//! HTTP, the GitHub web-editor equivalent.
//!
//! Follows the JSS `forge` tier 3.7 (`apiRepoEdit`, `cleanEditPath`,
//! `withCors`, cited by name only; all code original). The request body is
//! `{"path", "content", "message"?, "branch"?}`.
//!
//! # Authorisation
//!
//! Owner-signed by default: no credential is `401` (with a `Bearer`
//! challenge), a credential for another namespace is `403`. With
//! [`ForgeConfig::open_edit`](crate::ForgeConfig::open_edit) (JSS
//! `openEdit`) **no authorisation check runs at all**: an anonymous caller
//! may edit **any** repository. JSS has no "demo namespace" restriction and
//! neither does this port; the flag is for throwaway demo forges only and
//! [`ForgeService::new`] logs a warning when it is on.
//!
//! # How the commit is made
//!
//! JSS clones the bare repository into a temporary working tree. This port
//! never checks anything out: it hashes the content with `git hash-object`,
//! stages it into a **private index file** (`GIT_INDEX_FILE`, seeded with
//! `read-tree`), writes the tree, creates the commit with `commit-tree` and
//! advances the branch with `update-ref <ref> <new> <old>`. The old value is
//! the tip read under the per-repository lock, so a racing push makes the
//! write fail with `409` instead of being overwritten (compare-and-swap).
//! Every git invocation goes through the hardened argv-only runner; no value
//! supplied by the caller ever reaches git as an option.
//!
//! # Path rules
//!
//! See [`clean_edit_path`]. Compared with JSS this port is deliberately
//! stricter in three places: the `.git` check is case-insensitive (so
//! `.GIT` and `.Git` are refused), segments made only of dots (`.`, `...`)
//! and NTFS spellings of `.git` (`.git.`, `git~1`) are refused, and an
//! existing symlink, submodule or directory at the target (or a symlink or
//! file on the way to it) is a `409`, never written through.
//!
//! # Examples
//!
//! ```
//! use solid_pod_rs_forge::web_edit::{clean_edit_path, clean_message};
//!
//! assert_eq!(clean_edit_path("docs/guide.md").as_deref(), Some("docs/guide.md"));
//! assert!(clean_edit_path("../x").is_none());
//! assert!(clean_edit_path("a/.GIT/config").is_none());
//! assert_eq!(clean_message(Some("  fix\n\ttypo "), "a.txt"), "fix typo");
//! assert_eq!(clean_message(None, "a.txt"), "web edit: a.txt");
//! ```

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::api::{api_err, json_resp, unauthorised};
use crate::error::ForgeError;
use crate::guard::ok_ref;
use crate::ownership::ForgeAgent;
use crate::prgit;
use crate::repo::browse;
use crate::request::{ForgeRequest, ForgeResponse};
use crate::ForgeService;

/// Largest file content accepted, in bytes (JSS `EDIT_CONTENT_CAP`, 1 MiB).
pub const EDIT_CONTENT_CAP: usize = 1024 * 1024;
/// Longest commit message kept, in characters (JSS `EDIT_MSG_CAP`).
pub const EDIT_MSG_CAP: usize = 1000;
/// Longest accepted path, in characters (JSS `EDIT_PATH_CAP`).
pub const EDIT_PATH_CAP: usize = 1024;
/// Largest request body read: content cap plus 128 KiB of JSON framing
/// (JSS `readJsonBody(request, EDIT_CONTENT_CAP + 128 * 1024)`).
pub const EDIT_BODY_CAP: usize = EDIT_CONTENT_CAP + 128 * 1024;

/// Is `seg` an acceptable path segment? JSS `EDIT_SEG`
/// (`^[A-Za-z0-9._-]+$`) plus the three tightenings described in the
/// module documentation.
fn ok_edit_segment(seg: &str) -> bool {
    if seg.is_empty()
        || !seg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return false;
    }
    // `.`, `..`, `...`: never a real file name (and `..` is traversal).
    if seg.bytes().all(|b| b == b'.') {
        return false;
    }
    let lower = seg.to_ascii_lowercase();
    // `.git`, `.GIT`, and the NTFS alias `.git.` (trailing dots are dropped).
    if lower.trim_end_matches('.') == ".git" {
        return false;
    }
    // NTFS 8.3 short name of `.git`: `git~1`, `GIT~2`, ...
    if let Some(n) = lower.strip_prefix("git~") {
        if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
    }
    true
}

/// Validate a repo-relative edit path (JSS `cleanEditPath`). Returns the
/// clean path, or `None`.
///
/// Refused: empty or longer than [`EDIT_PATH_CAP`], a leading `/`, a
/// backslash, a control character (NUL included), an empty segment, `..`,
/// any `.git` segment in any letter case, a segment outside
/// `[A-Za-z0-9._-]`, and a dotfile at the repository **root** (`.acl`,
/// `.htaccess`).
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::web_edit::clean_edit_path;
///
/// assert!(clean_edit_path("index.html").is_some());
/// assert!(clean_edit_path("docs/.hidden").is_some());
/// for bad in ["", "/etc/x", "a/../b", "a\\b", ".git/x", "a/.Git/x", ".acl", "a//b", "a\0b"] {
///     assert!(clean_edit_path(bad).is_none(), "{bad:?}");
/// }
/// ```
#[must_use]
pub fn clean_edit_path(p: &str) -> Option<String> {
    if p.is_empty() || p.chars().count() > EDIT_PATH_CAP {
        return None;
    }
    if p.starts_with('/') || p.contains('\\') || p.chars().any(|c| (c as u32) < 0x20) {
        return None;
    }
    let segs: Vec<&str> = p.split('/').collect();
    if !segs.iter().all(|s| ok_edit_segment(s)) {
        return None;
    }
    if segs[0].starts_with('.') {
        return None;
    }
    Some(segs.join("/"))
}

/// The commit message for an edit: control-character runs become one space,
/// the result is trimmed and cut to [`EDIT_MSG_CAP`] **characters** (never
/// inside a UTF-8 sequence), and an empty result becomes
/// `web edit: <path>`.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::web_edit::clean_message;
///
/// assert_eq!(clean_message(Some("a\0\0b"), "p"), "a b");
/// assert_eq!(clean_message(Some("   "), "p"), "web edit: p");
/// assert_eq!(clean_message(Some(&"x".repeat(5000)), "p").chars().count(), 1000);
/// ```
#[must_use]
pub fn clean_message(raw: Option<&str>, path: &str) -> String {
    let mut out = String::new();
    let mut in_ctl = false;
    for c in raw.unwrap_or("").chars() {
        if (c as u32) < 0x20 {
            if !in_ctl {
                out.push(' ');
            }
            in_ctl = true;
        } else {
            in_ctl = false;
            out.push(c);
        }
    }
    let t: String = out.trim().chars().take(EDIT_MSG_CAP).collect();
    if t.is_empty() {
        format!("web edit: {path}")
    } else {
        t
    }
}

/// Attach the JSS `CORS_HEADERS` (`withCors`) to a reply so a cross-origin
/// editor page can read it, error replies included.
pub(crate) fn cors(resp: ForgeResponse) -> ForgeResponse {
    resp.with_header("access-control-allow-origin", "*")
        .with_header("access-control-allow-methods", "POST, OPTIONS")
        .with_header(
            "access-control-allow-headers",
            "content-type, authorization",
        )
        .with_header("access-control-max-age", "600")
}

/// A CORS-readable JSON reply.
pub(crate) fn cors_json(status: u16, v: &Value) -> ForgeResponse {
    cors(json_resp(status, v))
}

/// A CORS-readable `{ "error": msg }` reply (JSS `corsErr`).
pub(crate) fn cors_err(status: u16, msg: &str) -> ForgeResponse {
    cors(api_err(status, msg))
}

/// A validated edit or preview request body.
#[derive(Debug)]
pub(crate) struct EditRequest {
    /// The clean repo-relative path.
    pub path: String,
    /// The file content.
    pub content: String,
    /// The commit message (already cleaned).
    pub message: String,
    /// The `branch` member exactly as sent (`None` when the key is absent).
    pub branch: Option<Value>,
    /// The authenticated namespace, if any.
    pub authed_owner: Option<String>,
}

/// The gates shared by `/edit` and `/preview`, in JSS order: authorisation,
/// body shape, path, content type, content size, message. Failures are
/// complete CORS-readable replies.
pub(crate) fn validate(
    open_edit: bool,
    req: &ForgeRequest,
    agent: &ForgeAgent,
    owner: &str,
    verb: &str,
) -> Result<EditRequest, ForgeResponse> {
    let authed_owner = agent.owner().map(str::to_string);
    if !open_edit {
        if matches!(agent, ForgeAgent::Anonymous) {
            return Err(cors(unauthorised()));
        }
        if authed_owner.as_deref() != Some(owner) {
            return Err(cors_err(
                403,
                &format!("only the repo owner may {verb} this repository"),
            ));
        }
    }
    let body: Option<Map<String, Value>> =
        if req.raw_body.is_empty() || req.raw_body.len() > EDIT_BODY_CAP {
            None
        } else {
            match serde_json::from_slice::<Value>(&req.raw_body) {
                Ok(Value::Object(m)) => Some(m),
                _ => None,
            }
        };
    let Some(p) = body else {
        return Err(cors_err(400, "invalid JSON body"));
    };
    let Some(path) = p
        .get("path")
        .and_then(Value::as_str)
        .and_then(clean_edit_path)
    else {
        return Err(cors_err(400, "invalid path"));
    };
    let Some(content) = p.get("content").and_then(Value::as_str) else {
        return Err(cors_err(400, "content must be a string"));
    };
    if content.len() > EDIT_CONTENT_CAP {
        return Err(cors_err(
            413,
            &format!("content exceeds the {EDIT_CONTENT_CAP}-byte cap"),
        ));
    }
    let message = clean_message(p.get("message").and_then(Value::as_str), &path);
    Ok(EditRequest {
        path,
        content: content.to_string(),
        message,
        branch: p.get("branch").cloned(),
        authed_owner,
    })
}

/// The git command to run once the branch is known to be valid: refuses
/// anything `check-ref-format` would, so a name like `x.lock` or `a/.b` is a
/// clean `400` rather than a late `update-ref` failure.
pub(crate) async fn resolve_branch(
    dir: &Path,
    raw: Option<&Value>,
) -> Result<String, ForgeResponse> {
    let bad = || cors_err(400, "invalid branch");
    match raw {
        Some(Value::String(b)) => {
            if !ok_ref(b) || b == "HEAD" {
                return Err(bad());
            }
            let full = format!("refs/heads/{b}");
            match prgit::run(dir, &["check-ref-format", &full]).await {
                Ok(o) if o.ok() => Ok(b.clone()),
                _ => Err(bad()),
            }
        }
        Some(_) => Err(bad()),
        None => Ok(browse::default_branch(dir).await),
    }
}

/// Scratch files for one edit, removed on every exit path.
struct Scratch(Vec<PathBuf>);

impl Drop for Scratch {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// The result of [`commit_file`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Committed {
    /// The new commit, or the unchanged parent when `changed` is false.
    pub sha: Option<String>,
    /// Whether a commit was created and the ref moved.
    pub changed: bool,
}

fn valid_oid(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `git rev-parse --verify --quiet <spec>` where `spec` is built by this
/// module from a fixed `refs/heads/` prefix.
async fn rev(dir: &Path, spec: &str) -> Option<String> {
    let o = prgit::run(dir, &["rev-parse", "--verify", "--quiet", spec])
        .await
        .ok()?;
    let s = o.text().trim().to_string();
    (o.ok() && valid_oid(&s)).then_some(s)
}

/// A git identity part without control characters or angle brackets.
fn ident(s: &str) -> String {
    let t: String = s
        .chars()
        .filter(|c| !c.is_control() && *c != '<' && *c != '>')
        .collect();
    let t = t.trim();
    if t.is_empty() {
        "anonymous".to_string()
    } else {
        t.to_string()
    }
}

/// Create the commit and advance `refs/heads/<branch>` from `old` to it.
///
/// * `parent` is the commit the new tree is built on: the branch tip, or for
///   a branch that does not exist yet the default branch's tip (JSS
///   `checkout -b`), or `None` for a root commit in an empty repository.
/// * `old` is the value the ref must still have (`None`: the branch must not
///   exist). The write is a compare-and-swap: when the ref moved the result
///   is [`ForgeError::Conflict`] and nothing is changed.
///
/// An edit that leaves the tree identical creates nothing
/// (`changed: false`, the ref is not touched).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn commit_file(
    scratch_dir: &Path,
    dir: &Path,
    branch: &str,
    parent: Option<&str>,
    old: Option<&str>,
    rel_path: &str,
    content: &[u8],
    message: &str,
    who: &str,
) -> Result<Committed, ForgeError> {
    use tokio::io::AsyncWriteExt;

    // Defence in depth: the callers validated these already.
    if clean_edit_path(rel_path).as_deref() != Some(rel_path) || !ok_ref(branch) {
        return Err(ForgeError::BadRequest("invalid path or branch".into()));
    }
    if parent.is_some_and(|p| !valid_oid(p)) || old.is_some_and(|o| !valid_oid(o)) {
        return Err(ForgeError::BadRequest("invalid commit id".into()));
    }
    tokio::fs::create_dir_all(scratch_dir).await?;
    let scratch_dir = tokio::fs::canonicalize(scratch_dir).await?;
    let token = uuid::Uuid::new_v4().simple().to_string();
    let blob_file = scratch_dir.join(format!("{token}.blob"));
    let index_file = scratch_dir.join(format!("{token}.index"));
    let _cleanup = Scratch(vec![blob_file.clone(), index_file.clone()]);

    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts.open(&blob_file).await?;
    f.write_all(content).await?;
    f.flush().await?;
    drop(f);

    let blob_arg = blob_file
        .to_str()
        .ok_or_else(|| ForgeError::Backend("non-UTF-8 scratch path".into()))?;
    let index_arg = index_file
        .to_str()
        .ok_or_else(|| ForgeError::Backend("non-UTF-8 scratch path".into()))?;

    let hashed = prgit::run(
        dir,
        &[
            "hash-object",
            "-w",
            "--no-filters",
            "-t",
            "blob",
            "--",
            blob_arg,
        ],
    )
    .await?;
    let blob = hashed.text().trim().to_string();
    if !hashed.ok() || !valid_oid(&blob) {
        return Err(ForgeError::Backend(format!(
            "git hash-object: {}",
            hashed.stderr.trim()
        )));
    }

    let idx_env = [("GIT_INDEX_FILE", index_arg)];
    let mut mode = "100644".to_string();
    if let Some(parent) = parent {
        // What is at the target and on the way to it, one prefix at a time
        // (a single `ls-tree` over several nested paths lists directory
        // contents instead of the directory entry). `GIT_LITERAL_PATHSPECS`
        // makes every operand a plain path, never a pathspec magic.
        let segs: Vec<&str> = rel_path.split('/').collect();
        for i in 1..=segs.len() {
            let spec = segs[..i].join("/");
            let lt = prgit::run_at(
                dir,
                Some(dir),
                &["ls-tree", "-z", "--full-tree", parent, "--", &spec],
                &[("GIT_LITERAL_PATHSPECS", "1")],
            )
            .await?;
            if !lt.ok() {
                return Err(ForgeError::Backend(format!(
                    "git ls-tree: {}",
                    lt.stderr.trim()
                )));
            }
            let listing = lt.text();
            let entry = listing
                .split('\0')
                .filter_map(|r| r.split_once('\t'))
                .find(|(_, name)| *name == spec);
            let Some((meta, _)) = entry else {
                // Nothing here, so nothing deeper either.
                break;
            };
            let m = meta.split(' ').next().unwrap_or("");
            if i < segs.len() {
                if m != "040000" {
                    return Err(ForgeError::Conflict(format!(
                        "{spec} is not a directory in {branch}"
                    )));
                }
            } else if m == "100644" || m == "100755" {
                mode = m.to_string();
            } else {
                return Err(ForgeError::Conflict(
                    "the target is a directory, symlink or submodule".into(),
                ));
            }
        }
        let rt = prgit::run_at(dir, Some(dir), &["read-tree", parent], &idx_env).await?;
        if !rt.ok() {
            return Err(ForgeError::Backend(format!(
                "git read-tree: {}",
                rt.stderr.trim()
            )));
        }
    }

    let cacheinfo = format!("{mode},{blob},{rel_path}");
    let ui = prgit::run_at(
        dir,
        Some(dir),
        &["update-index", "--add", "--cacheinfo", &cacheinfo],
        &idx_env,
    )
    .await?;
    if !ui.ok() {
        // git's own message can name the scratch index path: log it, never send it.
        tracing::warn!(
            "forge: web edit update-index refused {rel_path}: {}",
            ui.stderr.trim()
        );
        return Err(ForgeError::Conflict(format!(
            "cannot place {rel_path} in the tree"
        )));
    }
    let wt = prgit::run_at(dir, Some(dir), &["write-tree"], &idx_env).await?;
    let tree = wt.text().trim().to_string();
    if !wt.ok() || !valid_oid(&tree) {
        return Err(ForgeError::Backend(format!(
            "git write-tree: {}",
            wt.stderr.trim()
        )));
    }

    if let Some(parent) = parent {
        let parent_tree = rev(dir, &format!("{parent}^{{tree}}")).await;
        if parent_tree.as_deref() == Some(tree.as_str()) {
            return Ok(Committed {
                sha: Some(parent.to_string()),
                changed: false,
            });
        }
    }

    let author = ident(who);
    let email = format!("{}@forge.invalid", author.replace(' ', "-"));
    let mut args: Vec<&str> = vec!["commit-tree", &tree];
    if let Some(p) = parent {
        args.extend(["-p", p]);
    }
    args.extend(["-m", message]);
    let ct = prgit::run_at(
        dir,
        Some(dir),
        &args,
        &[
            ("GIT_AUTHOR_NAME", &author),
            ("GIT_AUTHOR_EMAIL", &email),
            ("GIT_COMMITTER_NAME", "forge web edit"),
            ("GIT_COMMITTER_EMAIL", "forge@forge.invalid"),
        ],
    )
    .await?;
    let commit = ct.text().trim().to_string();
    if !ct.ok() || !valid_oid(&commit) {
        return Err(ForgeError::Backend(format!(
            "git commit-tree: {}",
            ct.stderr.trim()
        )));
    }

    let refname = format!("refs/heads/{branch}");
    let zeros = "0".repeat(commit.len());
    let expect = old.unwrap_or(&zeros);
    let upd = prgit::run(dir, &["update-ref", &refname, &commit, expect]).await?;
    if !upd.ok() {
        // Moved under us (a push raced the lock)? Then it is a conflict the
        // caller can retry; otherwise the ref name itself was unusable.
        let now = rev(dir, &refname).await;
        if now.as_deref() != old {
            return Err(ForgeError::Conflict(
                "the branch moved during the edit, retry".into(),
            ));
        }
        return Err(ForgeError::BadRequest(
            "the branch cannot be updated".into(),
        ));
    }
    Ok(Committed {
        sha: Some(commit),
        changed: true,
    })
}

impl ForgeService {
    /// Map an internal failure to a CORS-readable reply. Details go to the
    /// log only; the temp paths and raw git stderr never reach the caller.
    fn edit_failure(e: &ForgeError, what: &str) -> ForgeResponse {
        match e {
            ForgeError::NotFound(_) | ForgeError::PathTraversal(_) => cors_err(404, "not found"),
            ForgeError::Conflict(m) => cors_err(409, m),
            ForgeError::BadRequest(m) => cors_err(400, m),
            other => {
                tracing::warn!("forge: {what} failed: {other}");
                cors_err(500, "edit failed")
            }
        }
    }

    /// `POST api/repos/<o>/<n>/edit` (JSS `apiRepoEdit`). Never returns an
    /// error: every outcome is a CORS-readable JSON reply.
    pub(crate) async fn h_api_edit(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        owner: &str,
        name: &str,
    ) -> ForgeResponse {
        if !req.method.eq_ignore_ascii_case("POST") {
            return api_err(405, "method not allowed");
        }
        let ed = match validate(self.cfg.open_edit, req, agent, owner, "edit") {
            Ok(e) => e,
            Err(resp) => return resp,
        };
        let dir = match self.resolve_repo(owner, name).await {
            Ok(d) => d,
            Err(e) => return Self::edit_failure(&e, "web edit"),
        };
        let branch = match resolve_branch(&dir, ed.branch.as_ref()).await {
            Ok(b) => b,
            Err(resp) => return resp,
        };
        let who = ed.authed_owner.as_deref().unwrap_or("anonymous");
        let outcome = {
            // One writer per repository at a time: the spine pull lock, plus
            // the lock `merge` holds while it moves a branch, so an edit and
            // a merge never interleave (the CAS still guards pushes, which
            // take neither). Order: spine lock first; `merge` takes only the
            // second, so the two cannot deadlock.
            let _spine = self.locks.pulls.lock(owner, name).await;
            let _merge = prgit::pull_locks().lock(&format!("{owner}/{name}")).await;
            self.edit_locked(&dir, &branch, &ed, who).await
        };
        let done = match outcome {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!("forge: web edit {owner}/{name}@{branch} {}: {e}", ed.path);
                return Self::edit_failure(&e, "web edit");
            }
        };
        if !done.changed {
            return cors_json(
                200,
                &json!({"ok": true, "commit": done.sha, "changed": false}),
            );
        }
        let commit = done.sha.unwrap_or_default();
        tracing::info!(
            "forge: web edit {owner}/{name}@{branch} {} -> {} by {}",
            ed.path,
            &commit[..7.min(commit.len())],
            agent.author_id()
        );
        // The tip moved: advance any anchor exactly as a push would, THEN
        // announce, so the 30618 state carries the new anchor (JSS
        // `recordTipSafe` before `announceRepoSafe`).
        self.pr.tip.record_tip(owner, name).await;
        #[cfg(feature = "anchoring")]
        if let Err(e) = self.record_tip(owner, name, &branch, &commit).await {
            tracing::warn!("forge: recording the anchor tip after a web edit failed: {e}");
        }
        #[cfg(feature = "announce")]
        {
            let origin = self.cfg.public_origin(req.host_url.as_deref());
            self.announce_repo_in_background(owner, name, &origin);
        }
        cors_json(
            200,
            &json!({
                "ok": true,
                "commit": commit,
                "changed": true,
                "url": format!("{}/{owner}/{name}", self.prefix()),
            }),
        )
    }

    /// Read the tip and commit onto it; the caller holds the repo lock.
    async fn edit_locked(
        &self,
        dir: &Path,
        branch: &str,
        ed: &EditRequest,
        who: &str,
    ) -> Result<Committed, ForgeError> {
        let own = rev(dir, &format!("refs/heads/{branch}^{{commit}}")).await;
        let (parent, old) = match &own {
            Some(tip) => (Some(tip.clone()), Some(tip.clone())),
            None => {
                // A new branch starts from the default branch (JSS `checkout -b`).
                let def = browse::default_branch(dir).await;
                (
                    rev(dir, &format!("refs/heads/{def}^{{commit}}")).await,
                    None,
                )
            }
        };
        commit_file(
            &self.plugin_dir.join("web-edit-tmp"),
            dir,
            branch,
            parent.as_deref(),
            old.as_deref(),
            &ed.path,
            ed.content.as_bytes(),
            &ed.message,
            who,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gitrun::testutil::git;

    #[test]
    fn path_rules() {
        for ok in [
            "index.html",
            "docs/guide.md",
            "a/b/c.txt",
            "docs/.hidden",
            "-n",
            "a/-n",
        ] {
            assert_eq!(clean_edit_path(ok).as_deref(), Some(ok), "{ok}");
        }
        let long = format!("{}/x", "a".repeat(1100));
        for bad in [
            "",
            "/etc/x",
            "../x",
            "a/../../b",
            "a/..",
            "a/./b",
            ".",
            "...",
            ".git/x",
            "a/.git",
            "a/.GIT/x",
            "a/.Git/x",
            "a/.git./x",
            "a/GIT~1/x",
            "a\\b",
            "a\0b",
            "a\nb",
            "a b",
            "a//b",
            "a/",
            ".acl",
            ".htaccess",
            "caf\u{e9}",
            "a;b",
            "a%2eb",
            long.as_str(),
        ] {
            assert!(clean_edit_path(bad).is_none(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn message_rules() {
        assert_eq!(clean_message(Some("x\r\ny"), "p"), "x y");
        assert_eq!(clean_message(Some("\0"), "p"), "web edit: p");
        assert_eq!(clean_message(None, "d/e.md"), "web edit: d/e.md");
        let s = "é".repeat(2000);
        assert_eq!(clean_message(Some(&s), "p").chars().count(), EDIT_MSG_CAP);
    }

    fn bare_with_main() -> (tempfile::TempDir, PathBuf, String) {
        let td = tempfile::tempdir().unwrap();
        let work = td.path().join("w");
        std::fs::create_dir_all(&work).unwrap();
        git(&work, &["init", "-q", "-b", "main"]);
        std::fs::write(work.join("a.txt"), "one\n").unwrap();
        git(&work, &["add", "-A"]);
        git(&work, &["commit", "-q", "-m", "seed"]);
        let tip = git(&work, &["rev-parse", "HEAD"]);
        let bare = td.path().join("r.git");
        git(
            td.path(),
            &[
                "clone",
                "-q",
                "--bare",
                work.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
        );
        (td, bare, tip)
    }

    #[tokio::test]
    async fn stale_tip_is_a_conflict_and_leaves_the_ref_alone() {
        let (td, bare, tip) = bare_with_main();
        let scratch = td.path().join("s");
        // A racing writer advances main after the edit read `tip`.
        let first = commit_file(
            &scratch,
            &bare,
            "main",
            Some(&tip),
            Some(&tip),
            "b.txt",
            b"b\n",
            "first",
            "u",
        )
        .await
        .unwrap();
        assert!(first.changed);
        let moved = first.sha.unwrap();
        // The stale writer still believes the tip is `tip`.
        let err = commit_file(
            &scratch,
            &bare,
            "main",
            Some(&tip),
            Some(&tip),
            "c.txt",
            b"c\n",
            "second",
            "u",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ForgeError::Conflict(_)), "{err:?}");
        assert_eq!(git(&bare, &["rev-parse", "refs/heads/main"]), moved);
        assert!(git(&bare, &["ls-tree", "-r", "--name-only", "main"])
            .lines()
            .all(|l| l != "c.txt"));
        // The scratch directory is empty afterwards.
        assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn new_branch_must_not_exist_when_old_is_none() {
        let (td, bare, tip) = bare_with_main();
        let scratch = td.path().join("s");
        let ok = commit_file(
            &scratch,
            &bare,
            "feat",
            Some(&tip),
            None,
            "n.txt",
            b"n\n",
            "m",
            "u",
        )
        .await
        .unwrap();
        assert!(ok.changed);
        // Creating it again with old = None loses the race.
        let err = commit_file(
            &scratch,
            &bare,
            "feat",
            Some(&tip),
            None,
            "o.txt",
            b"o\n",
            "m",
            "u",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ForgeError::Conflict(_)), "{err:?}");
    }
}
