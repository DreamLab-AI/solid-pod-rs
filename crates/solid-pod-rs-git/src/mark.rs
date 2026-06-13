//! Native `GitMarker` implementation — the cheap, always-on provenance tier.
//!
//! Implements [`solid_pod_rs::provenance::GitMarker`] by shelling out to the
//! system `git` binary via [`tokio::process::Command`], mirroring the style of
//! [`crate::api`] (`git_commit`/`git_add`) and [`crate::service`]. This is the
//! single canonical write-provenance path: an LDP `PUT`/`POST`/`PATCH` that
//! lands in a git-backed pod is followed by a [`ShellGitMarker::mark_write`]
//! call that stages the written file and commits it, so every pod write becomes
//! a git commit whose SHA is captured and surfaced as a
//! [`GitMark`](solid_pod_rs::provenance::GitMark).
//!
//! ## Why native-only
//!
//! The pure provenance *surface* (types + `prov_ttl`) lives in
//! `solid-pod-rs::provenance` and compiles for `wasm32`. This implementor
//! spawns a subprocess, so it is native-only and lives here in
//! `solid-pod-rs-git` (which already depends on `tokio::process`). Wasm
//! consumers compile against a no-op marker, never this one
//! (ADR-059 D4).
//!
//! ## Commit identity
//!
//! Commits are authored as `solid-pod-rs <agent_did>` — the writer's
//! `did:nostr` (NIP-98 principal) becomes the commit author *email*, binding
//! the on-disk git history to the authenticated agent. Identity is injected
//! per-invocation via `git -c user.name=… -c user.email=…` so no global git
//! config is mutated and the repo needs no pre-seeded `user.*`.

use std::path::Path;

use async_trait::async_trait;
use solid_pod_rs::provenance::{GitMark, GitMarker, ProvenanceError};
use tokio::process::Command;

/// Branch the auto-init pins (`init.rs` runs `git init -b main`). Every mark
/// records this as its branch; surfacing it keeps the [`GitMark`] self-describing
/// without a second `rev-parse --abbrev-ref` round-trip per write.
const PINNED_BRANCH: &str = "main";

/// A [`GitMarker`] that commits pod writes by shelling to `git`.
///
/// Stateless and cheap to clone — it holds only the committer name used in the
/// `git -c user.name=…` override.
#[derive(Debug, Clone)]
pub struct ShellGitMarker {
    /// Value passed to `git -c user.name=…`. Defaults to `solid-pod-rs`.
    committer_name: String,
}

impl ShellGitMarker {
    /// Construct with the default committer name (`solid-pod-rs`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            committer_name: "solid-pod-rs".to_string(),
        }
    }

    /// Override the committer name written into `git -c user.name=…`.
    #[must_use]
    pub fn with_committer_name(name: impl Into<String>) -> Self {
        Self {
            committer_name: name.into(),
        }
    }
}

impl Default for ShellGitMarker {
    fn default() -> Self {
        Self::new()
    }
}

/// Run a git command in `repo`, returning trimmed stdout on success.
///
/// Maps a missing `git` binary and any non-zero exit into
/// [`ProvenanceError::Git`] so the server hook can log-and-swallow uniformly.
async fn git(repo: &Path, args: &[&str]) -> Result<String, ProvenanceError> {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ProvenanceError::Git("git binary not found in PATH".into())
            } else {
                ProvenanceError::Git(format!("spawn git {args:?}: {e}"))
            }
        })?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        // `git commit` writes its human status ("nothing to commit, working
        // tree clean") to STDOUT, not stderr, yet still exits non-zero. Fold
        // both streams into the error message so the no-op detection in
        // `mark_write` can match on it.
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = match (stderr.trim().is_empty(), stdout.trim().is_empty()) {
            (false, false) => format!("{}; {}", stderr.trim(), stdout.trim()),
            (false, true) => stderr.trim().to_string(),
            (true, false) => stdout.trim().to_string(),
            (true, true) => String::new(),
        };
        Err(ProvenanceError::Git(format!(
            "git {args:?} exited {:?}: {detail}",
            output.status.code(),
        )))
    }
}

/// Derive the pod repo slug from the repo directory's final path component
/// (the pod name / pubkey segment), matching the server's
/// `data_root/{pod}` layout. Falls back to the full lossy path when the
/// component cannot be extracted (e.g. a root path).
fn repo_slug(repo: &Path) -> String {
    repo.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| repo.to_string_lossy().into_owned())
}

/// Resolve `HEAD` to a SHA, mapping the unborn-branch case (a fresh
/// `git init` with no commits) to `Ok(None)` rather than an error.
async fn head_sha(repo: &Path) -> Result<Option<String>, ProvenanceError> {
    match git(repo, &["rev-parse", "HEAD"]).await {
        Ok(sha) if !sha.is_empty() => Ok(Some(sha)),
        Ok(_) => Ok(None),
        // `rev-parse HEAD` fails on an unborn branch (`fatal: ambiguous
        // argument 'HEAD'` / `unknown revision`). That is "no commits yet",
        // not a hard failure.
        Err(ProvenanceError::Git(msg))
            if msg.contains("unknown revision")
                || msg.contains("ambiguous argument")
                || msg.contains("bad revision")
                || msg.contains("does not have any commits") =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

#[async_trait(?Send)]
impl GitMarker for ShellGitMarker {
    async fn mark_write(
        &self,
        repo: &Path,
        path: &str,
        agent_did: &str,
        message: &str,
    ) -> Result<GitMark, ProvenanceError> {
        // Reject path escapes defensively — the server already constrains the
        // path, but a marker must never `git add` outside the repo.
        if path.starts_with('/') || path.contains("..") {
            return Err(ProvenanceError::InvalidPath(path.to_string()));
        }

        // 1. Record the pre-write HEAD — this is the parent of whatever commit
        //    we are about to create (the append-only chain link).
        let parent = head_sha(repo).await?;

        // 2. Stage the written file. `git add` materialises the index entry the
        //    commit will snapshot.
        git(repo, &["add", "--", path]).await?;

        // 3. Commit with the agent's did:nostr as the author email. Identity is
        //    injected per-invocation via `-c` overrides so no global git config
        //    is touched and the repo needs no pre-seeded `user.*`.
        //    `--allow-empty` is deliberately NOT passed: an idempotent re-write
        //    of identical bytes yields "nothing to commit", which we treat as a
        //    no-op below rather than fabricating an empty commit.
        let name_cfg = format!("user.name={}", self.committer_name);
        let email_cfg = format!("user.email={agent_did}");
        let commit_res = git(
            repo,
            &[
                "-c",
                &name_cfg,
                "-c",
                &email_cfg,
                "commit",
                "-m",
                message,
            ],
        )
        .await;

        // 4. Resolve the resulting HEAD. On success it is the new commit; on
        //    "nothing to commit" it is unchanged from `parent`.
        match commit_res {
            Ok(_) => {
                let commit_sha = head_sha(repo)
                    .await?
                    .ok_or_else(|| ProvenanceError::Git("HEAD unresolved after commit".into()))?;
                Ok(GitMark {
                    commit_sha,
                    repo: repo_slug(repo),
                    branch: PINNED_BRANCH.to_string(),
                    parent,
                })
            }
            Err(ProvenanceError::Git(msg))
                if msg.contains("nothing to commit")
                    || msg.contains("no changes added")
                    || msg.contains("working tree clean")
                    || msg.contains("nothing added to commit") =>
            {
                // Idempotent re-write: nothing changed. Surface the current
                // HEAD as the mark without erroring (the resource is already at
                // this commit). Its "parent" is HEAD's own parent.
                match &parent {
                    Some(head) => {
                        let head_parent = git(repo, &["rev-parse", &format!("{head}^")])
                            .await
                            .ok()
                            .filter(|s| !s.is_empty());
                        Ok(GitMark {
                            commit_sha: head.clone(),
                            repo: repo_slug(repo),
                            branch: PINNED_BRANCH.to_string(),
                            parent: head_parent,
                        })
                    }
                    // No prior commit AND nothing to commit: an empty add of an
                    // already-clean tree. Nothing to surface — propagate as a
                    // soft git error the caller swallows.
                    None => Err(ProvenanceError::Git(
                        "nothing to commit and no prior HEAD".into(),
                    )),
                }
            }
            Err(e) => Err(e),
        }
    }

    async fn head(&self, repo: &Path) -> Result<Option<String>, ProvenanceError> {
        head_sha(repo).await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;
    use tempfile::TempDir;

    fn git_available() -> bool {
        std::process::Command::new("git")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Initialise a non-bare repo on branch `main` with a committer identity.
    async fn init_repo() -> TempDir {
        let td = TempDir::new().unwrap();
        let run = |args: &[&str]| {
            std::process::Command::new("git")
                .args(args)
                .current_dir(td.path())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
        };
        run(&["init", "-b", "main"]);
        td
    }

    async fn write_file(repo: &Path, rel: &str, contents: &str) {
        let abs = repo.join(rel);
        if let Some(parent) = abs.parent() {
            tokio::fs::create_dir_all(parent).await.unwrap();
        }
        tokio::fs::write(abs, contents).await.unwrap();
    }

    #[tokio::test]
    async fn head_is_none_on_unborn_branch() {
        if !git_available() {
            return;
        }
        let td = init_repo().await;
        let marker = ShellGitMarker::new();
        assert_eq!(marker.head(td.path()).await.unwrap(), None);
    }

    #[tokio::test]
    async fn mark_write_creates_commit_and_captures_sha() {
        if !git_available() {
            return;
        }
        let td = init_repo().await;
        let marker = ShellGitMarker::new();

        write_file(td.path(), "notes/hello.ttl", "<a> <b> <c> .").await;
        let mark = marker
            .mark_write(td.path(), "notes/hello.ttl", "did:nostr:abcd", "PUT /notes/hello.ttl")
            .await
            .unwrap();

        // SHA is a 40-hex commit id and equals the new HEAD.
        assert_eq!(mark.commit_sha.len(), 40);
        assert!(mark.commit_sha.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(mark.branch, "main");
        assert_eq!(mark.repo, td.path().file_name().unwrap().to_string_lossy());
        // First commit of a fresh repo has no parent.
        assert_eq!(mark.parent, None);

        let head = marker.head(td.path()).await.unwrap().unwrap();
        assert_eq!(head, mark.commit_sha);

        // The agent did:nostr is the author email on the commit.
        let email = git(td.path(), &["log", "-1", "--format=%ae"]).await.unwrap();
        assert_eq!(email, "did:nostr:abcd");
        let name = git(td.path(), &["log", "-1", "--format=%an"]).await.unwrap();
        assert_eq!(name, "solid-pod-rs");
    }

    #[tokio::test]
    async fn parent_chain_links_two_writes() {
        if !git_available() {
            return;
        }
        let td = init_repo().await;
        let marker = ShellGitMarker::new();

        write_file(td.path(), "a.ttl", "first").await;
        let m1 = marker
            .mark_write(td.path(), "a.ttl", "did:nostr:a", "write a")
            .await
            .unwrap();

        write_file(td.path(), "b.ttl", "second").await;
        let m2 = marker
            .mark_write(td.path(), "b.ttl", "did:nostr:b", "write b")
            .await
            .unwrap();

        // The second mark's parent is the first mark's commit — the append-only
        // chain. SHAs differ.
        assert_ne!(m1.commit_sha, m2.commit_sha);
        assert_eq!(m1.parent, None);
        assert_eq!(m2.parent.as_deref(), Some(m1.commit_sha.as_str()));
    }

    #[tokio::test]
    async fn nothing_to_commit_returns_head_without_error() {
        if !git_available() {
            return;
        }
        let td = init_repo().await;
        let marker = ShellGitMarker::new();

        write_file(td.path(), "a.ttl", "content").await;
        let m1 = marker
            .mark_write(td.path(), "a.ttl", "did:nostr:a", "write a")
            .await
            .unwrap();

        // Re-mark the SAME path with identical content already committed: there
        // is nothing to commit. We must get a mark referencing the current HEAD,
        // not an error, and HEAD must not have advanced.
        let m2 = marker
            .mark_write(td.path(), "a.ttl", "did:nostr:a", "re-write a")
            .await
            .unwrap();
        assert_eq!(m2.commit_sha, m1.commit_sha, "HEAD must not advance");
        assert_eq!(
            marker.head(td.path()).await.unwrap().as_deref(),
            Some(m1.commit_sha.as_str())
        );
    }

    #[tokio::test]
    async fn rejects_path_traversal() {
        if !git_available() {
            return;
        }
        let td = init_repo().await;
        let marker = ShellGitMarker::new();
        assert!(matches!(
            marker
                .mark_write(td.path(), "../escape.ttl", "did:nostr:a", "x")
                .await,
            Err(ProvenanceError::InvalidPath(_))
        ));
        assert!(matches!(
            marker
                .mark_write(td.path(), "/abs.ttl", "did:nostr:a", "x")
                .await,
            Err(ProvenanceError::InvalidPath(_))
        ));
    }
}
