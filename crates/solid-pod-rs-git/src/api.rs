//! High-level git control-panel operations for a pod's git repository.
//!
//! Each function shells out to the `git` binary via [`tokio::process::Command`].
//! All functions take `repo: &Path` — the absolute filesystem path to the
//! pod's git repository (i.e. `data_root/{pubkey}`).
//!
//! These are wired to REST endpoints in `solid-pod-rs-server` behind
//! `#[cfg(feature = "git")]`.

use std::path::Path;

use serde::{Deserialize, Serialize};
use tokio::process::Command;

use crate::error::GitError;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Type of change reported by `git status`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ChangeType {
    /// File contents modified.
    Modified,
    /// File added to the index.
    Added,
    /// File deleted.
    Deleted,
    /// File renamed (old path is in `FileStatus::old_path`).
    Renamed,
    /// File copied (old path is in `FileStatus::old_path`).
    Copied,
}

/// A single file entry in the status report.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileStatus {
    /// Relative path within the repository.
    pub path: String,
    /// Nature of the change.
    pub change_type: ChangeType,
    /// For renames/copies: the original path before the operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_path: Option<String>,
}

/// Full status report for a repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusReport {
    /// Current branch name.
    pub branch: String,
    /// Commits ahead of the upstream tracking branch.
    pub ahead: u32,
    /// Commits behind the upstream tracking branch.
    pub behind: u32,
    /// Files staged for the next commit (index changes).
    pub staged: Vec<FileStatus>,
    /// Files with unstaged working-tree changes.
    pub unstaged: Vec<FileStatus>,
    /// Paths not tracked by git.
    pub untracked: Vec<String>,
    /// `true` when all three lists are empty.
    pub is_clean: bool,
}

/// A single commit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitEntry {
    /// Full 40-character SHA-1 hash.
    pub hash: String,
    /// 7-character abbreviated hash.
    pub short_hash: String,
    /// First line of the commit message.
    pub message: String,
    /// Author name.
    pub author: String,
    /// ISO-8601 author date.
    pub date: String,
    /// Human-readable relative date (e.g. "3 days ago").
    pub date_relative: String,
}

/// Current branch state.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BranchInfo {
    /// The currently checked-out branch.
    pub current: String,
    /// All local branches.
    pub local: Vec<String>,
}

/// Result of a successful commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitResult {
    /// Full commit hash.
    pub hash: String,
    /// Abbreviated commit hash.
    pub short_hash: String,
    /// One-line commit subject.
    pub summary: String,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Run a git command and collect stdout. Returns `GitError::BackendFailed`
/// when the exit code is non-zero.
async fn git_run(args: &[&str], repo: &Path) -> Result<String, GitError> {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                GitError::BackendNotAvailable("git binary not found in PATH".into())
            } else {
                GitError::Io(e)
            }
        })?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(GitError::BackendFailed {
            exit_code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// Same as `git_run` but tolerates a non-zero exit code, returning the
/// stdout anyway (some git commands like `reset HEAD` exit 1 on early commits).
async fn git_run_tolerant(args: &[&str], repo: &Path) -> Result<String, GitError> {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                GitError::BackendNotAvailable("git binary not found in PATH".into())
            } else {
                GitError::Io(e)
            }
        })?;

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Validate a user-supplied file path segment: must not contain `..` and must
/// not start with `/`.
fn validate_path(path: &str) -> Result<(), GitError> {
    if path.starts_with('/') || path.contains("..") {
        return Err(GitError::PathTraversal(path.to_string()));
    }
    Ok(())
}

/// Parse a `--porcelain=v1 -b` status line for the index (X) character.
fn parse_xy(x: char, y: char) -> (Option<ChangeType>, Option<ChangeType>) {
    let map_char = |c: char| match c {
        'M' => Some(ChangeType::Modified),
        'A' => Some(ChangeType::Added),
        'D' => Some(ChangeType::Deleted),
        'R' => Some(ChangeType::Renamed),
        'C' => Some(ChangeType::Copied),
        _ => None,
    };
    (map_char(x), map_char(y))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Return the working-tree and index status of `repo`.
pub async fn git_status(repo: &Path) -> Result<StatusReport, GitError> {
    let raw = git_run(&["status", "--porcelain=v1", "-b"], repo).await?;
    parse_status_output(&raw)
}

/// Pure-function status parser — split out for unit-testing.
pub fn parse_status_output(raw: &str) -> Result<StatusReport, GitError> {
    let mut lines = raw.lines();

    // ── Branch line ──────────────────────────────────────────────────────────
    let branch_line = lines.next().unwrap_or("");
    // Strip leading `## `
    let branch_line = branch_line.trim_start_matches("## ");

    let mut ahead: u32 = 0;
    let mut behind: u32 = 0;

    let branch: String;
    if branch_line.starts_with("No commits yet on ") {
        branch = branch_line
            .trim_start_matches("No commits yet on ")
            .to_string();
    } else {
        // Format: `main...origin/main [ahead 1, behind 2]`
        // or just: `main` (no tracking)
        let (branch_part, tracking_part) = if let Some(idx) = branch_line.find("...") {
            (&branch_line[..idx], Some(&branch_line[idx + 3..]))
        } else {
            (branch_line, None)
        };
        branch = branch_part.to_string();

        if let Some(tracking) = tracking_part {
            // Parse optional `[ahead N, behind M]` suffix.
            if let Some(bracket_start) = tracking.find('[') {
                let inside = &tracking[bracket_start + 1..];
                let inside = inside.trim_end_matches(']');
                for part in inside.split(',') {
                    let part = part.trim();
                    if let Some(n) = part.strip_prefix("ahead ") {
                        ahead = n.trim().parse().unwrap_or(0);
                    } else if let Some(n) = part.strip_prefix("behind ") {
                        behind = n.trim().parse().unwrap_or(0);
                    }
                }
            }
        }
    }

    // ── File lines ───────────────────────────────────────────────────────────
    let mut staged: Vec<FileStatus> = Vec::new();
    let mut unstaged: Vec<FileStatus> = Vec::new();
    let mut untracked: Vec<String> = Vec::new();

    for line in lines {
        if line.len() < 4 {
            continue;
        }
        let x = line.chars().next().unwrap_or(' ');
        let y = line.chars().nth(1).unwrap_or(' ');
        let rest = &line[3..]; // skip "XY "

        if x == '?' && y == '?' {
            untracked.push(rest.to_string());
            continue;
        }

        let (staged_change, unstaged_change) = parse_xy(x, y);

        // Renamed / Copied entries in porcelain v1 look like:
        //   `R  new_path\0old_path` but porcelain v1 uses `->` separator.
        //   `R  newpath -> oldpath`
        // Actually porcelain=v1 uses: `R  dest\toriginal` on a single line
        // separated by `\0` in -z mode. Without -z it is `dest -> origin`.
        let (path, old_path) = if (x == 'R' || x == 'C' || y == 'R' || y == 'C')
            && rest.contains(" -> ")
        {
            let mut parts = rest.splitn(2, " -> ");
            let dest = parts.next().unwrap_or(rest).to_string();
            let orig = parts.next().map(str::to_string);
            (dest, orig)
        } else {
            (rest.to_string(), None)
        };

        if let Some(ct) = staged_change {
            staged.push(FileStatus {
                path: path.clone(),
                change_type: ct,
                old_path: old_path.clone(),
            });
        }
        if let Some(ct) = unstaged_change {
            unstaged.push(FileStatus {
                path: path.clone(),
                change_type: ct,
                old_path,
            });
        }
    }

    let is_clean = staged.is_empty() && unstaged.is_empty() && untracked.is_empty();

    Ok(StatusReport {
        branch,
        ahead,
        behind,
        staged,
        unstaged,
        untracked,
        is_clean,
    })
}

/// Return the commit log for `repo`, up to `limit` entries (capped at 100).
pub async fn git_log(repo: &Path, limit: u32) -> Result<Vec<CommitEntry>, GitError> {
    let cap = limit.min(100);
    let cap_str = cap.to_string();
    let format = "%H\x1F%h\x1F%s\x1F%an\x1F%aI\x1F%ar";
    let raw = match git_run(
        &["log", &format!("--format={format}"), "-n", &cap_str],
        repo,
    )
    .await
    {
        Ok(v) => v,
        Err(GitError::BackendFailed { ref stderr, .. }) if stderr.contains("does not have any commits") || stderr.contains("bad default revision") || stderr.contains("fatal: your current branch") => {
            return Ok(Vec::new());
        }
        Err(e) => return Err(e),
    };

    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    for line in raw.lines() {
        let parts: Vec<&str> = line.splitn(6, '\x1F').collect();
        if parts.len() < 6 {
            continue;
        }
        entries.push(CommitEntry {
            hash: parts[0].to_string(),
            short_hash: parts[1].to_string(),
            message: parts[2].to_string(),
            author: parts[3].to_string(),
            date: parts[4].to_string(),
            date_relative: parts[5].to_string(),
        });
    }
    Ok(entries)
}

/// Metadata + changed files for one commit, resolved by SHA. Backs the
/// `_prov/{commit_sha}` provenance resolver (master-plan §2.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedCommit {
    /// Full 40-char commit SHA (canonicalised from the requested rev).
    pub hash: String,
    /// Commit author email — the writer's `did:nostr` (the git-mark binds the
    /// authenticated agent to commit author identity, see `mark.rs`).
    pub author_email: String,
    /// Commit author name (the committer label, e.g. `solid-pod-rs`).
    pub author_name: String,
    /// Commit subject (the LDP method + path the write recorded).
    pub subject: String,
    /// Author commit time, Unix seconds.
    pub committed_at: u64,
    /// Parent commit SHA (the append-only chain link), or `None` for the
    /// genesis commit.
    pub parent: Option<String>,
    /// Repo-relative paths the commit touched (sidecars are caller-filtered).
    pub files: Vec<String>,
}

/// Resolve a commit `sha` (any rev git accepts) to its metadata + changed
/// files. Returns [`GitError::NotARepository`] mapped from a bad-revision
/// failure so the caller can surface a 404 for an unknown commit.
///
/// Shells `git show --no-patch` (metadata) + `git show --name-only` (files),
/// mirroring the other `api` operations. Used by the `_prov/{commit_sha}`
/// route to map a git-mark back to its resource + [`ProvenanceMark`].
pub async fn resolve_commit(repo: &Path, sha: &str) -> Result<ResolvedCommit, GitError> {
    // Reject obviously-malformed revs early (defence-in-depth; the route also
    // validates). A commit-ish is hex; refuse anything with shell/path metachars.
    if sha.is_empty()
        || sha.len() > 64
        || !sha.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(GitError::PathTraversal(format!("invalid commit id: {sha}")));
    }

    // Metadata: full-hash, author-email, author-name, subject, author-unixtime,
    // parent-hashes — unit-separated, one record.
    let fmt = "%H\x1F%ae\x1F%an\x1F%s\x1F%at\x1F%P";
    let meta = match git_run(&["show", "--no-patch", &format!("--format={fmt}"), sha], repo).await {
        Ok(v) => v,
        Err(GitError::BackendFailed { ref stderr, .. })
            if stderr.contains("unknown revision")
                || stderr.contains("bad revision")
                || stderr.contains("bad object")
                || stderr.contains("ambiguous argument")
                || stderr.contains("does not have any commits") =>
        {
            return Err(GitError::NotARepository(format!("unknown commit {sha}")));
        }
        Err(e) => return Err(e),
    };
    let line = meta.lines().next().unwrap_or("");
    let parts: Vec<&str> = line.splitn(6, '\x1F').collect();
    if parts.len() < 5 {
        return Err(GitError::MalformedCgi(format!("git show metadata for {sha}")));
    }
    let committed_at = parts[4].trim().parse::<u64>().unwrap_or(0);
    let parent = parts
        .get(5)
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        // `%P` lists all parents space-separated; the first is the chain link.
        .and_then(|s| s.split_whitespace().next())
        .map(str::to_string);

    // Changed files: `--name-only` with an empty format prints only paths.
    let files_raw = git_run(&["show", "--name-only", "--format=", sha], repo)
        .await
        .unwrap_or_default();
    let files: Vec<String> = files_raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();

    Ok(ResolvedCommit {
        hash: parts[0].to_string(),
        author_email: parts[1].to_string(),
        author_name: parts[2].to_string(),
        subject: parts[3].to_string(),
        committed_at,
        parent,
        files,
    })
}

/// Return a unified diff for the repository or a specific file.
///
/// - `staged = true` produces `git diff --cached` (index vs HEAD).
/// - `staged = false` produces `git diff` (working tree vs index).
/// - `path` restricts the diff to a single file.
pub async fn git_diff(repo: &Path, path: Option<&str>, staged: bool) -> Result<String, GitError> {
    if let Some(p) = path {
        validate_path(p)?;
    }

    let mut args: Vec<&str> = vec!["diff", "-U5"];
    if staged {
        args.push("--cached");
    }
    if let Some(p) = path {
        args.push("--");
        args.push(p);
    }

    // `git diff` exits 0 even when there are no differences.
    git_run(&args, repo).await
}

/// Stage files. If `all` is true, runs `git add -A`. Otherwise stages
/// only the listed `paths`.
pub async fn git_add(repo: &Path, paths: &[String], all: bool) -> Result<(), GitError> {
    if all {
        git_run(&["add", "-A"], repo).await?;
    } else {
        for p in paths {
            validate_path(p)?;
        }
        let mut args = vec!["add", "--"];
        let path_refs: Vec<&str> = paths.iter().map(String::as_str).collect();
        args.extend_from_slice(&path_refs);
        git_run(&args, repo).await?;
    }
    Ok(())
}

/// Unstage files. If `all` is true, unstages everything. Otherwise
/// unstages only the listed `paths`.
///
/// `git reset HEAD` can exit 1 on repositories with no commits yet;
/// this is handled gracefully.
pub async fn git_unstage(repo: &Path, paths: &[String], all: bool) -> Result<(), GitError> {
    if all {
        git_run_tolerant(&["reset", "HEAD", "--", "."], repo).await?;
    } else {
        for p in paths {
            validate_path(p)?;
        }
        let mut args = vec!["reset", "HEAD", "--"];
        let path_refs: Vec<&str> = paths.iter().map(String::as_str).collect();
        args.extend_from_slice(&path_refs);
        git_run_tolerant(&args, repo).await?;
    }
    Ok(())
}

/// Create a commit with the given message. Returns the new commit hash and
/// a one-line summary.
pub async fn git_commit(
    repo: &Path,
    message: &str,
    author_name: &str,
    author_email: &str,
) -> Result<CommitResult, GitError> {
    let author_str = format!("{author_name} <{author_email}>");
    git_run(
        &["commit", "-m", message, "--author", &author_str],
        repo,
    )
    .await?;

    let hash = git_run(&["rev-parse", "HEAD"], repo).await?;
    let hash = hash.trim().to_string();
    let short_hash = if hash.len() >= 7 {
        hash[..7].to_string()
    } else {
        hash.clone()
    };

    // Extract the commit subject for the summary.
    let summary = git_run(&["log", "-1", "--format=%s", &hash], repo)
        .await
        .unwrap_or_else(|_| message.to_string());
    let summary = summary.trim().to_string();

    Ok(CommitResult {
        hash,
        short_hash,
        summary,
    })
}

/// Return the list of local branches and identify the current one.
pub async fn git_branches(repo: &Path) -> Result<BranchInfo, GitError> {
    let raw = match git_run(
        &["branch", "--format=%(HEAD) %(refname:short)"],
        repo,
    )
    .await
    {
        Ok(v) => v,
        Err(GitError::BackendFailed { ref stderr, .. })
            if stderr.contains("does not have any commits")
                || stderr.contains("bad default revision") =>
        {
            return Ok(BranchInfo {
                current: "main".to_string(),
                local: vec![],
            });
        }
        Err(e) => return Err(e),
    };

    if raw.trim().is_empty() {
        return Ok(BranchInfo {
            current: "main".to_string(),
            local: vec![],
        });
    }

    let mut current = String::from("main");
    let mut local: Vec<String> = Vec::new();

    for line in raw.lines() {
        // Format: `* main` or `  feature-x`
        let is_current = line.starts_with("* ");
        let name = line.trim_start_matches("* ").trim_start_matches("  ").trim();
        if name.is_empty() {
            continue;
        }
        if is_current {
            current = name.to_string();
        }
        local.push(name.to_string());
    }

    Ok(BranchInfo { current, local })
}

/// Create and switch to a new branch called `name`.
pub async fn git_create_branch(repo: &Path, name: &str) -> Result<(), GitError> {
    // Validate branch name: no `..`, no spaces, must not start with `-`.
    if name.contains("..") || name.contains(' ') || name.starts_with('-') {
        return Err(GitError::PathTraversal(format!(
            "invalid branch name: {name}"
        )));
    }
    git_run(&["checkout", "-b", name], repo).await?;
    Ok(())
}

/// Discard working-tree changes to the listed `paths` (equivalent to
/// `git checkout -- <paths>`).
pub async fn git_discard(repo: &Path, paths: &[String]) -> Result<(), GitError> {
    for p in paths {
        validate_path(p)?;
    }
    let mut args = vec!["checkout", "--"];
    let path_refs: Vec<&str> = paths.iter().map(String::as_str).collect();
    args.extend_from_slice(&path_refs);
    git_run(&args, repo).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_status(raw: &str) -> StatusReport {
        parse_status_output(raw).expect("parse failed")
    }

    #[test]
    fn parse_clean_repo() {
        let raw = "## main...origin/main\n";
        let s = make_status(raw);
        assert_eq!(s.branch, "main");
        assert_eq!(s.ahead, 0);
        assert_eq!(s.behind, 0);
        assert!(s.is_clean);
        assert!(s.staged.is_empty());
        assert!(s.unstaged.is_empty());
        assert!(s.untracked.is_empty());
    }

    #[test]
    fn parse_ahead_behind() {
        let raw = "## main...origin/main [ahead 3, behind 1]\n";
        let s = make_status(raw);
        assert_eq!(s.branch, "main");
        assert_eq!(s.ahead, 3);
        assert_eq!(s.behind, 1);
    }

    #[test]
    fn parse_ahead_only() {
        let raw = "## feature...origin/feature [ahead 2]\n";
        let s = make_status(raw);
        assert_eq!(s.branch, "feature");
        assert_eq!(s.ahead, 2);
        assert_eq!(s.behind, 0);
    }

    #[test]
    fn parse_no_commits_yet() {
        let raw = "## No commits yet on main\n";
        let s = make_status(raw);
        assert_eq!(s.branch, "main");
        assert_eq!(s.ahead, 0);
        assert_eq!(s.behind, 0);
        assert!(s.is_clean);
    }

    #[test]
    fn parse_no_commits_yet_with_staged() {
        let raw = "## No commits yet on main\nA  README.md\n";
        let s = make_status(raw);
        assert_eq!(s.branch, "main");
        assert_eq!(s.staged.len(), 1);
        assert_eq!(s.staged[0].change_type, ChangeType::Added);
        assert_eq!(s.staged[0].path, "README.md");
        assert!(!s.is_clean);
    }

    #[test]
    fn parse_modified_staged_and_unstaged() {
        // X=M (staged modified), Y=M (unstaged modified)
        let raw = "## main\nMM src/lib.rs\n";
        let s = make_status(raw);
        assert_eq!(s.staged.len(), 1);
        assert_eq!(s.staged[0].change_type, ChangeType::Modified);
        assert_eq!(s.unstaged.len(), 1);
        assert_eq!(s.unstaged[0].change_type, ChangeType::Modified);
    }

    #[test]
    fn parse_untracked() {
        let raw = "## main\n?? newfile.txt\n";
        let s = make_status(raw);
        assert_eq!(s.untracked, vec!["newfile.txt"]);
        assert!(!s.is_clean);
    }

    #[test]
    fn parse_deleted_staged() {
        let raw = "## main\nD  old.txt\n";
        let s = make_status(raw);
        assert_eq!(s.staged.len(), 1);
        assert_eq!(s.staged[0].change_type, ChangeType::Deleted);
        assert_eq!(s.staged[0].path, "old.txt");
    }

    #[test]
    fn parse_renamed_staged() {
        let raw = "## main\nR  new.txt -> old.txt\n";
        let s = make_status(raw);
        assert_eq!(s.staged.len(), 1);
        assert_eq!(s.staged[0].change_type, ChangeType::Renamed);
        assert_eq!(s.staged[0].path, "new.txt");
        assert_eq!(s.staged[0].old_path.as_deref(), Some("old.txt"));
    }

    #[test]
    fn parse_branch_no_tracking() {
        let raw = "## detached-head\nM  foo.rs\n";
        let s = make_status(raw);
        assert_eq!(s.branch, "detached-head");
        assert_eq!(s.ahead, 0);
        assert_eq!(s.behind, 0);
    }

    #[test]
    fn validate_path_rejects_dotdot() {
        assert!(validate_path("../etc/passwd").is_err());
        assert!(validate_path("foo/../../bar").is_err());
    }

    #[test]
    fn validate_path_rejects_absolute() {
        assert!(validate_path("/etc/passwd").is_err());
    }

    #[test]
    fn validate_path_accepts_normal() {
        assert!(validate_path("src/lib.rs").is_ok());
        assert!(validate_path("README.md").is_ok());
    }

    #[tokio::test]
    async fn resolve_commit_rejects_malformed_rev() {
        // Defence-in-depth: a non-hex / over-long / empty rev is rejected
        // before ever shelling to git (no path/shell metachars reach `git`).
        let repo = std::path::Path::new("/nonexistent");
        for bad in ["", "../etc", "deadbeef; rm -rf /", &"a".repeat(65), "g00dbeef"] {
            assert!(
                matches!(
                    resolve_commit(repo, bad).await,
                    Err(GitError::PathTraversal(_))
                ),
                "malformed rev {bad:?} must be rejected pre-git"
            );
        }
    }
}
