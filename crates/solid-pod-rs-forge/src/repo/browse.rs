//! Repository browse porcelain — tree/blob/raw, tags, commit log, and a
//! single-commit view.
//!
//! Extends the [`solid_pod_rs_git::api`] porcelain with the read-only
//! operations the forge's views need. Every git invocation uses an argv
//! array (never a shell) with `GIT_CONFIG_NOSYSTEM=1` and no inherited
//! `HOME`, and every ref/path is validated before it reaches git — so a
//! hostile ref cannot inject a flag or escape the repo. All operations
//! run against a **bare** repo dir (`…/<name>.git`), which git treats as
//! its git-dir directly.

use std::path::Path;
use std::process::Stdio;

use serde::Serialize;
use tokio::process::Command;

use crate::error::ForgeError;

/// Kind of a tree entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    /// A subdirectory (git `tree`).
    Dir,
    /// A regular file (git `blob`).
    File,
    /// A symbolic link (mode 120000).
    Symlink,
    /// A submodule (git `commit` gitlink, mode 160000).
    Submodule,
}

/// One row of a directory listing.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeEntry {
    /// Basename within the listed directory.
    pub name: String,
    /// Entry kind.
    pub kind: EntryKind,
    /// Object sha.
    pub sha: String,
    /// Blob size in bytes (None for trees/submodules).
    pub size: Option<u64>,
}

/// Run `git` with a fixed, hardened environment and return raw stdout
/// bytes. `BackendFailed`-style errors carry stderr for diagnostics.
async fn git_bytes(git_dir: &Path, args: &[&str]) -> Result<Vec<u8>, ForgeError> {
    let output = Command::new("git")
        .args(args)
        .current_dir(git_dir)
        // Defence-in-depth: no system/global config, no HOME-based include,
        // no interactive prompt (a private submodule must never block).
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env_remove("HOME")
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ForgeError::Unsupported("git binary not found in PATH".into())
            } else {
                ForgeError::Io(e)
            }
        })?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        // Map "unknown revision"/"not a tree" family to NotFound.
        if stderr.contains("unknown revision")
            || stderr.contains("bad revision")
            || stderr.contains("Not a valid object")
            || stderr.contains("does not exist")
            || stderr.contains("exists on disk, but not in")
            || stderr.contains("bad object")
        {
            Err(ForgeError::NotFound(stderr.trim().to_string()))
        } else {
            Err(ForgeError::Backend(format!(
                "git {}: {}",
                args.first().copied().unwrap_or(""),
                stderr.trim()
            )))
        }
    }
}

/// Run `git` and return stdout as UTF-8 (lossy).
async fn git_text(git_dir: &Path, args: &[&str]) -> Result<String, ForgeError> {
    let bytes = git_bytes(git_dir, args).await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Validate a git ref / commit-ish. Rejects flag-injection (leading `-`),
/// range/parent traversal (`..`), whitespace, and shell/path metachars.
/// Branch names with `/` are allowed. Empty is rejected.
pub fn valid_rev(rev: &str) -> bool {
    if rev.is_empty() || rev.len() > 200 || rev.starts_with('-') {
        return false;
    }
    if rev.contains("..") || rev.contains("//") {
        return false;
    }
    rev.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/')
    })
}

/// Validate a repo-relative path used inside a `<rev>:<path>` object spec.
/// Empty is allowed (the repo root). No leading slash, no `..` segment,
/// no NUL/control chars.
pub fn valid_repo_path(path: &str) -> bool {
    if path.is_empty() {
        return true;
    }
    if path.starts_with('/') || path.len() > 4096 {
        return false;
    }
    for seg in path.split('/') {
        if seg == ".." || seg.chars().any(|c| c.is_control()) {
            return false;
        }
    }
    true
}

/// Build a `<rev>:<path>` tree-ish, or bare `<rev>` when `path` is empty.
fn treeish(rev: &str, path: &str) -> String {
    if path.is_empty() {
        rev.to_string()
    } else {
        format!("{rev}:{path}")
    }
}

/// Resolve the repo's default branch (the branch HEAD points at). Falls
/// back to `"main"` for an empty repo.
pub async fn default_branch(git_dir: &Path) -> String {
    match git_text(git_dir, &["symbolic-ref", "--short", "HEAD"]).await {
        Ok(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => "main".to_string(),
    }
}

/// `true` when the repo has at least one commit reachable from any ref.
pub async fn has_commits(git_dir: &Path) -> bool {
    git_text(git_dir, &["rev-list", "-n", "1", "--all"])
        .await
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
}

/// List a directory tree at `<rev>:<path>`. Returns entries sorted
/// directories-first then by name. A missing path yields `NotFound`.
pub async fn list_tree(
    git_dir: &Path,
    rev: &str,
    path: &str,
) -> Result<Vec<TreeEntry>, ForgeError> {
    if !valid_rev(rev) {
        return Err(ForgeError::BadRequest(format!("invalid ref: {rev}")));
    }
    if !valid_repo_path(path) {
        return Err(ForgeError::PathTraversal(format!("invalid path: {path}")));
    }
    let ti = treeish(rev, path);
    let raw = git_text(git_dir, &["ls-tree", "--long", &ti]).await?;
    let mut entries = parse_ls_tree(&raw);
    entries.sort_by(|a, b| {
        let ad = a.kind == EntryKind::Dir;
        let bd = b.kind == EntryKind::Dir;
        bd.cmp(&ad).then_with(|| a.name.cmp(&b.name))
    });
    Ok(entries)
}

/// Parse `git ls-tree --long` output:
/// `<mode> <type> <sha> <size-or-dash>\t<name>`
fn parse_ls_tree(raw: &str) -> Vec<TreeEntry> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let Some((meta, name)) = line.split_once('\t') else {
            continue;
        };
        let cols: Vec<&str> = meta.split_whitespace().collect();
        if cols.len() < 3 {
            continue;
        }
        let mode = cols[0];
        let typ = cols[1];
        let sha = cols[2].to_string();
        let size = cols.get(3).and_then(|s| s.parse::<u64>().ok());
        let kind = match (typ, mode) {
            ("tree", _) => EntryKind::Dir,
            ("commit", _) => EntryKind::Submodule,
            ("blob", "120000") => EntryKind::Symlink,
            _ => EntryKind::File,
        };
        out.push(TreeEntry {
            name: name.to_string(),
            kind,
            sha,
            size: if kind == EntryKind::File || kind == EntryKind::Symlink {
                size
            } else {
                None
            },
        });
    }
    out
}

/// Read a blob's raw bytes at `<rev>:<path>`. Enforces `max_bytes` by
/// checking the object size first (cheap) so an oversized blob never
/// buffers into memory.
pub async fn read_blob(
    git_dir: &Path,
    rev: &str,
    path: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, ForgeError> {
    if !valid_rev(rev) {
        return Err(ForgeError::BadRequest(format!("invalid ref: {rev}")));
    }
    if path.is_empty() || !valid_repo_path(path) {
        return Err(ForgeError::PathTraversal(format!("invalid path: {path}")));
    }
    let spec = format!("{rev}:{path}");
    // Confirm it is a blob and get its size before reading.
    let typ = git_text(git_dir, &["cat-file", "-t", &spec])
        .await?
        .trim()
        .to_string();
    if typ != "blob" {
        return Err(ForgeError::NotFound(format!("{path} is not a file")));
    }
    let size: u64 = git_text(git_dir, &["cat-file", "-s", &spec])
        .await?
        .trim()
        .parse()
        .unwrap_or(0);
    if size > max_bytes {
        return Err(ForgeError::BadRequest(format!(
            "blob too large: {size} > {max_bytes} bytes"
        )));
    }
    git_bytes(git_dir, &["cat-file", "blob", &spec]).await
}

/// Paginated commit log for `rev`. `page` is 1-based; `per_page` is
/// capped at 100. Returns `(entries, has_next)`.
pub async fn commit_log(
    git_dir: &Path,
    rev: &str,
    page: u32,
    per_page: u32,
) -> Result<(Vec<solid_pod_rs_git::api::CommitEntry>, bool), ForgeError> {
    if !valid_rev(rev) {
        return Err(ForgeError::BadRequest(format!("invalid ref: {rev}")));
    }
    let per = per_page.clamp(1, 100);
    let page = page.max(1);
    let skip = (page - 1) * per;
    // Fetch one extra to detect a next page.
    let n = per + 1;
    let fmt = "%H\x1f%h\x1f%s\x1f%an\x1f%aI\x1f%ar";
    let raw = match git_text(
        git_dir,
        &[
            "log",
            &format!("--format={fmt}"),
            "--skip",
            &skip.to_string(),
            "-n",
            &n.to_string(),
            rev,
        ],
    )
    .await
    {
        Ok(v) => v,
        Err(ForgeError::NotFound(_)) => return Ok((Vec::new(), false)),
        Err(e) => return Err(e),
    };
    let mut entries = Vec::new();
    for line in raw.lines() {
        let parts: Vec<&str> = line.splitn(6, '\x1f').collect();
        if parts.len() < 6 {
            continue;
        }
        entries.push(solid_pod_rs_git::api::CommitEntry {
            hash: parts[0].to_string(),
            short_hash: parts[1].to_string(),
            message: parts[2].to_string(),
            author: parts[3].to_string(),
            date: parts[4].to_string(),
            date_relative: parts[5].to_string(),
        });
    }
    let has_next = entries.len() as u32 > per;
    entries.truncate(per as usize);
    Ok((entries, has_next))
}

/// The unified-diff patch text for a single commit (`git show`). Rendered
/// inside an `esc()`'d `<pre>` — never as markup.
pub async fn commit_patch(git_dir: &Path, sha: &str) -> Result<String, ForgeError> {
    if !valid_rev(sha) {
        return Err(ForgeError::BadRequest(format!("invalid sha: {sha}")));
    }
    git_text(
        git_dir,
        &["show", "--no-color", "--format=", "-p", "--stat", sha],
    )
    .await
}

/// List tag names (sorted, newest-committerdate first).
pub async fn list_tags(git_dir: &Path) -> Result<Vec<String>, ForgeError> {
    let raw = git_text(
        git_dir,
        &[
            "for-each-ref",
            "--sort=-creatordate",
            "--format=%(refname:short)",
            "refs/tags",
        ],
    )
    .await?;
    Ok(raw.lines().map(str::to_string).filter(|s| !s.is_empty()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_rev_rejects_injection_and_traversal() {
        assert!(valid_rev("main"));
        assert!(valid_rev("refs/heads/feature/x"));
        assert!(valid_rev("v1.2.3"));
        assert!(valid_rev("deadbeef"));
        assert!(!valid_rev(""));
        assert!(!valid_rev("--upload-pack=evil"));
        assert!(!valid_rev("a..b"));
        assert!(!valid_rev("a b"));
        assert!(!valid_rev("a;rm -rf"));
        assert!(!valid_rev("a$(x)"));
    }

    #[test]
    fn valid_repo_path_rejects_dotdot_and_absolute() {
        assert!(valid_repo_path(""));
        assert!(valid_repo_path("src/lib.rs"));
        assert!(!valid_repo_path("/etc/passwd"));
        assert!(!valid_repo_path("a/../b"));
        assert!(!valid_repo_path(".."));
    }

    #[test]
    fn parse_ls_tree_classifies_entries() {
        let raw = "100644 blob abc123 42\tREADME.md\n\
040000 tree def456 -\tsrc\n\
120000 blob 111 12\tlink\n\
160000 commit 222 -\tsubmod\n";
        let entries = parse_ls_tree(raw);
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].name, "README.md");
        assert_eq!(entries[0].kind, EntryKind::File);
        assert_eq!(entries[0].size, Some(42));
        assert_eq!(entries[1].kind, EntryKind::Dir);
        assert_eq!(entries[1].size, None);
        assert_eq!(entries[2].kind, EntryKind::Symlink);
        assert_eq!(entries[3].kind, EntryKind::Submodule);
    }
}
