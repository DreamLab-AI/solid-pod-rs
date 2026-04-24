//! Repo-level `git config` mutators — mirrors JSS
//! `src/handlers/git.js` lines 133-150, which runs two `git config`
//! invocations on every write request:
//!
//! 1. `git config http.receivepack true` (always — so HTTP push is
//!    accepted even on repos that didn't set this at `init` time).
//! 2. `git config receive.denyCurrentBranch updateInstead` (only on
//!    non-bare repos — so a push to the currently checked-out branch
//!    updates the working tree instead of being rejected).
//!
//! Both invocations are idempotent; running them on every write is
//! the JSS-chosen strategy, and we replicate it here.

use std::path::Path;
use std::process::Stdio;

use tokio::process::Command;

use crate::error::GitError;

/// Information about the git directory layout for a given repo path.
#[derive(Debug, Clone)]
pub struct GitDir {
    /// The absolute path to the actual git directory (`.git` for
    /// regular repos, the repo path itself for bare repos).
    pub git_dir: std::path::PathBuf,

    /// `true` if this is a regular (non-bare) repository.
    pub is_regular: bool,
}

/// Inspect `repo_path` and determine whether it is a git repository,
/// and if so whether it is bare.
///
/// Returns `Ok(None)` if the directory exists but is not a repo; that
/// maps to a 404 at the HTTP layer.
pub fn find_git_dir(repo_path: &Path) -> std::io::Result<Option<GitDir>> {
    if !repo_path.exists() || !repo_path.is_dir() {
        return Ok(None);
    }

    let dot_git = repo_path.join(".git");
    if dot_git.exists() && dot_git.is_dir() {
        return Ok(Some(GitDir {
            git_dir: dot_git,
            is_regular: true,
        }));
    }

    // Bare-repo heuristic matches JSS: `objects/` + `refs/` present.
    let objects = repo_path.join("objects");
    let refs = repo_path.join("refs");
    if objects.exists() && refs.exists() {
        return Ok(Some(GitDir {
            git_dir: repo_path.to_path_buf(),
            is_regular: false,
        }));
    }

    Ok(None)
}

/// Apply the JSS-parity config to a repo on every write request.
///
/// Errors from the underlying `git config` invocations are **logged
/// and swallowed** — this matches JSS's `try { execSync … } catch (e)
/// { }` behaviour at lines 147-149. Rationale: config mutators
/// tripping (e.g. permissions) must not block the main CGI from
/// attempting the push; the CGI will itself surface a proper error
/// if the push truly can't proceed.
pub async fn apply_write_config(git_dir: &GitDir, cwd: &Path) -> Result<(), GitError> {
    // 1. http.receivepack = true  (always).
    let _ = run_git_config(cwd, &git_dir.git_dir, "http.receivepack", "true").await;

    // 2. receive.denyCurrentBranch = updateInstead  (non-bare only).
    if git_dir.is_regular {
        let _ = run_git_config(
            cwd,
            &git_dir.git_dir,
            "receive.denyCurrentBranch",
            "updateInstead",
        )
        .await;
    }

    Ok(())
}

/// Run `git config --local <key> <value>` with `GIT_DIR` set.
///
/// Returns `Err(GitError::BackendNotAvailable)` if the `git` binary
/// can't be spawned (test gate); otherwise returns `Err(Io)` on
/// other OS-level failures. Callers that are OK with a best-effort
/// apply swallow the error.
pub async fn run_git_config(
    cwd: &Path,
    git_dir: &Path,
    key: &str,
    value: &str,
) -> Result<(), GitError> {
    let mut cmd = Command::new("git");
    cmd.arg("config")
        .arg("--local")
        .arg(key)
        .arg(value)
        .current_dir(cwd)
        .env("GIT_DIR", git_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    let output = match cmd.output().await {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(GitError::BackendNotAvailable(format!(
                "git binary not found: {e}"
            )));
        }
        Err(e) => return Err(GitError::Io(e)),
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        tracing::debug!(
            target: "solid_pod_rs_git::config",
            "git config {key}={value} failed: {stderr}"
        );
        return Err(GitError::BackendFailed {
            exit_code: output.status.code(),
            stderr,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn find_git_dir_empty_returns_none() {
        let td = TempDir::new().unwrap();
        let res = find_git_dir(td.path()).unwrap();
        assert!(res.is_none());
    }

    #[tokio::test]
    async fn find_git_dir_regular_detected() {
        let td = TempDir::new().unwrap();
        std::fs::create_dir(td.path().join(".git")).unwrap();
        let res = find_git_dir(td.path()).unwrap().unwrap();
        assert!(res.is_regular);
        assert_eq!(res.git_dir, td.path().join(".git"));
    }

    #[tokio::test]
    async fn find_git_dir_bare_detected() {
        let td = TempDir::new().unwrap();
        std::fs::create_dir(td.path().join("objects")).unwrap();
        std::fs::create_dir(td.path().join("refs")).unwrap();
        let res = find_git_dir(td.path()).unwrap().unwrap();
        assert!(!res.is_regular);
        assert_eq!(res.git_dir, td.path());
    }

    /// Only runs when the git binary is available.
    #[tokio::test]
    async fn apply_write_config_roundtrip() {
        let td = TempDir::new().unwrap();
        let repo = td.path();
        // Init a regular repo via the system git if present.
        let status = Command::new("git")
            .arg("init")
            .arg(repo)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
        let status = match status {
            Ok(s) => s,
            Err(_) => return, // no git binary — skip.
        };
        assert!(status.success());

        let gd = find_git_dir(repo).unwrap().unwrap();
        apply_write_config(&gd, repo).await.unwrap();

        // Verify the config was applied by reading it back.
        let out = Command::new("git")
            .arg("config")
            .arg("--local")
            .arg("receive.denyCurrentBranch")
            .current_dir(repo)
            .env("GIT_DIR", &gd.git_dir)
            .output()
            .await
            .unwrap();
        assert!(out.status.success());
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "updateInstead"
        );

        let out2 = Command::new("git")
            .arg("config")
            .arg("--local")
            .arg("http.receivepack")
            .current_dir(repo)
            .env("GIT_DIR", &gd.git_dir)
            .output()
            .await
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out2.stdout).trim(), "true");
    }
}
