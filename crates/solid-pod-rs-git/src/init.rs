//! Git repository auto-initialisation at pod provisioning time.
//!
//! Implements the [`solid_pod_rs::provision::GitInitHook`] trait
//! (feature `git-auto-init` on `solid-pod-rs`) via
//! `tokio::process::Command`.
//!
//! ## Parity
//!
//! Mirrors JSS `src/handlers/git.js` `tryAutoInitRepo` (issues #466,
//! #469, #471). JSS runs:
//!
//! ```text
//! git init -b main <pod_path>
//! git -C <pod_path> config receive.denyCurrentBranch updateInstead
//! ```
//!
//! We do the same. Errors are logged and swallowed so a missing `git`
//! binary (or a CF Workers–style environment) does not fail pod
//! provisioning.

use std::path::Path;
use std::process::Stdio;

use async_trait::async_trait;
use tokio::process::Command;

use solid_pod_rs::error::PodError;
use solid_pod_rs::provision::GitInitHook;

use crate::error::GitError;

/// Runs `git init -b <branch>` + `git config receive.denyCurrentBranch
/// updateInstead` in the pod directory at provisioning time.
///
/// Mirrors JSS `tryAutoInitRepo` (#466/#469/#471).
///
/// # Usage
///
/// ```ignore
/// use std::path::PathBuf;
/// use solid_pod_rs_git::init::GitAutoInit;
/// use solid_pod_rs::provision::{provision_pod_ext, ProvisionPlan};
///
/// // storage is any type implementing solid_pod_rs::storage::Storage
/// // (e.g. FsBackend with feature "fs-backend").
/// # async fn run(storage: impl solid_pod_rs::storage::Storage) {
/// let plan = ProvisionPlan {
///     pubkey: "abcd1234".into(),
///     display_name: None,
///     pod_base: "https://pods.example".into(),
///     containers: vec![],
///     root_acl: None,
///     quota_bytes: None,
/// };
/// let hook = GitAutoInit::new();
/// let fs_root = PathBuf::from("/var/lib/pods/abcd1234");
/// provision_pod_ext(&storage, &plan, Some((&hook, fs_root.as_path()))).await.unwrap();
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct GitAutoInit {
    /// Branch name passed to `git init -b`. JSS uses `main`; configurable
    /// here so agentbox / VisionClaw can override to `trunk` etc. if
    /// desired.
    pub default_branch: String,
}

impl GitAutoInit {
    /// Create with `main` as the default branch — the JSS default.
    pub fn new() -> Self {
        Self {
            default_branch: "main".into(),
        }
    }

    /// Override the initial branch name.
    pub fn with_branch(branch: impl Into<String>) -> Self {
        Self {
            default_branch: branch.into(),
        }
    }
}

impl Default for GitAutoInit {
    fn default() -> Self {
        Self::new()
    }
}

impl GitAutoInit {
    /// Initialise a git repository at `fs_pod_root` (`git init -b <branch>` +
    /// `receive.denyCurrentBranch updateInstead`), returning a git-crate-native
    /// [`GitError`] on failure.
    ///
    /// This is the single canonical init implementation — the
    /// [`GitInitHook::try_init_repo`] trait method (provisioning-time) and the
    /// on-demand auto-init in [`crate::service::GitHttpService::handle`] (first
    /// push) both delegate here, so there is exactly one place that shells
    /// `git init`. Idempotent: re-running on an existing repo is safe (git
    /// reinitialises in place). Mirrors JSS `tryAutoInitRepo` (#466/#469/#472).
    pub async fn init_repo_at(&self, fs_pod_root: &Path) -> Result<(), GitError> {
        // ── Step 1: git init -b <branch> <path> ────────────────────────────
        let init_out = Command::new("git")
            .arg("init")
            .arg("-b")
            .arg(&self.default_branch)
            .arg(fs_pod_root)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    GitError::BackendNotAvailable("git binary not found in PATH".into())
                } else {
                    GitError::Io(e)
                }
            })?;

        if !init_out.status.success() {
            let stderr = String::from_utf8_lossy(&init_out.stderr).into_owned();
            return Err(GitError::BackendFailed {
                exit_code: init_out.status.code(),
                stderr: format!(
                    "git init -b {} {:?}: {stderr}",
                    self.default_branch, fs_pod_root,
                ),
            });
        }

        // ── Step 2: git config receive.denyCurrentBranch updateInstead ─────
        // Allows HTTP push to a non-bare repo (the checked-out branch gets
        // updated in-place). Matches JSS lines 147-149. Best-effort —
        // swallow errors so the pod is not rolled back.
        let cfg_out = Command::new("git")
            .arg("-C")
            .arg(fs_pod_root)
            .arg("config")
            .arg("receive.denyCurrentBranch")
            .arg("updateInstead")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .await;

        match cfg_out {
            Ok(o) if o.status.success() => {}
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr).into_owned();
                tracing::warn!(
                    target: "solid_pod_rs_git::init",
                    path = %fs_pod_root.display(),
                    "git config receive.denyCurrentBranch failed (non-fatal): {stderr}",
                );
            }
            Err(e) => {
                tracing::warn!(
                    target: "solid_pod_rs_git::init",
                    "git config spawn error (non-fatal): {e}",
                );
            }
        }

        tracing::debug!(
            target: "solid_pod_rs_git::init",
            path = %fs_pod_root.display(),
            branch = %self.default_branch,
            "pod git repository initialised",
        );

        Ok(())
    }
}

#[async_trait]
impl GitInitHook for GitAutoInit {
    async fn try_init_repo(&self, fs_pod_root: &Path) -> Result<(), PodError> {
        // Delegate to the single canonical init implementation, mapping the
        // git-crate error back into the provisioning `PodError` surface.
        self.init_repo_at(fs_pod_root)
            .await
            .map_err(|e| PodError::Backend(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
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

    #[tokio::test]
    async fn git_auto_init_creates_dot_git() {
        if !git_available() {
            return;
        }
        let td = TempDir::new().unwrap();
        let hook = GitAutoInit::new();
        hook.try_init_repo(td.path()).await.unwrap();
        assert!(td.path().join(".git").is_dir(), ".git directory must exist");
    }

    #[tokio::test]
    async fn git_auto_init_sets_deny_current_branch() {
        if !git_available() {
            return;
        }
        let td = TempDir::new().unwrap();
        let hook = GitAutoInit::new();
        hook.try_init_repo(td.path()).await.unwrap();

        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(td.path())
            .arg("config")
            .arg("receive.denyCurrentBranch")
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "updateInstead",);
    }

    #[tokio::test]
    async fn git_auto_init_custom_branch() {
        if !git_available() {
            return;
        }
        let td = TempDir::new().unwrap();
        let hook = GitAutoInit::with_branch("trunk");
        hook.try_init_repo(td.path()).await.unwrap();

        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(td.path())
            .arg("symbolic-ref")
            .arg("HEAD")
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "refs/heads/trunk",
        );
    }

    #[tokio::test]
    async fn git_auto_init_idempotent() {
        if !git_available() {
            return;
        }
        let td = TempDir::new().unwrap();
        let hook = GitAutoInit::new();
        hook.try_init_repo(td.path()).await.unwrap();
        // Second call must not fail (git init on an existing repo is safe).
        hook.try_init_repo(td.path()).await.unwrap();
        assert!(td.path().join(".git").is_dir());
    }
}
