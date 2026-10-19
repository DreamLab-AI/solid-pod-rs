//! Hardened git runner and keyed async locks shared by the fork, compare,
//! pull-request and merge modules.
//!
//! Every spawn goes through [`solid_pod_rs_git::hardened_git_async`] (hooks,
//! fsmonitor, ssh and gpg helpers and ambient config disabled), is argv-only
//! (never a shell), is pinned to one bare repository with `GIT_DIR`, has the
//! ambient `GIT_*` object and index variables removed, and is bounded by a
//! wall-clock timeout and an output cap. Unlike the browse helpers this runner
//! keeps the exit code, because `git merge-tree` reports a conflict as exit
//! status 1 rather than as a failure.

use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::OwnedMutexGuard;

use crate::error::ForgeError;

/// Wall-clock budget for one git invocation.
pub(crate) const GIT_TIMEOUT: Duration = Duration::from_secs(60);

/// Largest stdout the runner will buffer (JSS `MAX_EXEC_BUFFER`, 64 MiB).
pub(crate) const MAX_OUT: usize = 64 * 1024 * 1024;

/// Bytes of stderr kept for diagnostics.
const STDERR_KEEP: usize = 16 * 1024;

/// Ambient variables that would redirect git at another repository or index.
const SCRUBBED_ENV: &[&str] = &[
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_AUTHOR_NAME",
    "GIT_AUTHOR_EMAIL",
    "GIT_AUTHOR_DATE",
    "GIT_COMMITTER_NAME",
    "GIT_COMMITTER_EMAIL",
    "GIT_COMMITTER_DATE",
    "HOME",
    "XDG_CONFIG_HOME",
];

/// Result of one git invocation.
#[derive(Debug)]
pub(crate) struct Out {
    /// Exit status code (`None` when killed by a signal).
    pub code: Option<i32>,
    /// Captured stdout.
    pub stdout: Vec<u8>,
    /// First bytes of stderr, lossily decoded.
    pub stderr: String,
}

impl Out {
    /// `true` for exit status 0.
    pub fn ok(&self) -> bool {
        self.code == Some(0)
    }

    /// Stdout as lossy UTF-8.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
}

/// Read up to `cap` bytes; `Ok(None)` means the stream held more than `cap`.
async fn read_capped<R: AsyncRead + Unpin>(
    mut r: R,
    cap: usize,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let n = r.read(&mut chunk).await?;
        if n == 0 {
            return Ok(Some(buf));
        }
        if buf.len() + n > cap {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Read a stream to the end, keeping only the first [`STDERR_KEEP`] bytes.
async fn read_keep<R: AsyncRead + Unpin>(mut r: R) -> Vec<u8> {
    let mut keep = Vec::new();
    let mut chunk = vec![0u8; 8 * 1024];
    while let Ok(n) = r.read(&mut chunk).await {
        if n == 0 {
            break;
        }
        if keep.len() < STDERR_KEEP {
            let room = STDERR_KEEP - keep.len();
            keep.extend_from_slice(&chunk[..n.min(room)]);
        }
    }
    keep
}

/// Run `git <args>` with `cwd` as the working directory.
///
/// `git_dir`, when given, is exported as `GIT_DIR` so repository discovery can
/// never wander into a parent directory. `envs` are extra variables (author and
/// committer identity for `commit-tree`). Output over [`MAX_OUT`] kills the
/// child and is a [`ForgeError::Backend`]; so is a timeout.
pub(crate) async fn run_at(
    cwd: &Path,
    git_dir: Option<&Path>,
    args: &[&str],
    envs: &[(&str, &str)],
) -> Result<Out, ForgeError> {
    let mut cmd = solid_pod_rs_git::hardened_git_async();
    for k in SCRUBBED_ENV {
        cmd.env_remove(k);
    }
    cmd.env("LC_ALL", "C")
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(gd) = git_dir {
        cmd.env("GIT_DIR", gd);
    }
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ForgeError::Unsupported("git binary not found in PATH".into())
        } else {
            ForgeError::Io(e)
        }
    })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ForgeError::Backend("git stdout unavailable".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ForgeError::Backend("git stderr unavailable".into()))?;
    let sub = args.first().copied().unwrap_or("");
    let work = async {
        let (out, err) = tokio::join!(read_capped(stdout, MAX_OUT), read_keep(stderr));
        match out? {
            None => {
                let _ = child.kill().await;
                Err(ForgeError::Backend(format!("git {sub}: output too large")))
            }
            Some(stdout) => {
                let status = child.wait().await?;
                Ok(Out {
                    code: status.code(),
                    stdout,
                    stderr: String::from_utf8_lossy(&err).into_owned(),
                })
            }
        }
    };
    match tokio::time::timeout(GIT_TIMEOUT, work).await {
        Ok(r) => r,
        Err(_) => Err(ForgeError::Backend(format!("git {sub}: timed out"))),
    }
}

/// Run `git <args>` inside the bare repository `dir`.
pub(crate) async fn run(dir: &Path, args: &[&str]) -> Result<Out, ForgeError> {
    run_at(dir, Some(dir), args, &[]).await
}

/// Run `git <args>` in `dir` and return stdout, failing on a non-zero exit.
pub(crate) async fn text(dir: &Path, args: &[&str]) -> Result<String, ForgeError> {
    let out = run(dir, args).await?;
    if out.ok() {
        Ok(out.text())
    } else {
        Err(ForgeError::Backend(format!(
            "git {}: {}",
            args.first().copied().unwrap_or(""),
            out.stderr.trim()
        )))
    }
}

/// `git rev-parse --verify --quiet <spec>` as an object id, or `None`.
///
/// `spec` is always built by the caller from a fixed `refs/...` prefix or a
/// validated hexadecimal sha, so it can never be read as an option.
pub(crate) async fn rev_parse(dir: &Path, spec: &str) -> Option<String> {
    let out = run(dir, &["rev-parse", "--verify", "--quiet", spec])
        .await
        .ok()?;
    if !out.ok() {
        return None;
    }
    let t = out.text().trim().to_string();
    (!t.is_empty()).then_some(t)
}

/// `true` when `a` is an ancestor of `b` (`git merge-base --is-ancestor`).
/// Both arguments must be object ids.
pub(crate) async fn is_ancestor(dir: &Path, a: &str, b: &str) -> bool {
    run(dir, &["merge-base", "--is-ancestor", a, b])
        .await
        .map(|o| o.ok())
        .unwrap_or(false)
}

/// A map of per-key async mutexes. Cheap to clone via `Arc`; idle entries are
/// pruned so the map does not grow with the number of repositories ever seen.
#[derive(Default)]
pub(crate) struct KeyedLocks {
    map: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl KeyedLocks {
    /// Take the lock for `key`, giving up after `wait` with [`ForgeError::Busy`]
    /// so a slow holder cannot queue unbounded requests behind it.
    pub async fn lock_within(
        &self,
        key: &str,
        wait: Duration,
    ) -> Result<OwnedMutexGuard<()>, ForgeError> {
        tokio::time::timeout(wait, self.lock(key))
            .await
            .map_err(|_| ForgeError::Busy(format!("{key} is busy, retry shortly")))
    }

    /// Take the lock for `key`, waiting for any earlier holder.
    pub async fn lock(&self, key: &str) -> OwnedMutexGuard<()> {
        let m = {
            let mut map = self
                .map
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if map.len() > 1024 {
                map.retain(|_, v| Arc::strong_count(v) > 1);
            }
            map.entry(key.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        m.lock_owned().await
    }
}

/// Serialises read-modify-write cycles on a repository's pull index and merges.
pub(crate) fn pull_locks() -> &'static KeyedLocks {
    static L: OnceLock<KeyedLocks> = OnceLock::new();
    L.get_or_init(KeyedLocks::default)
}

/// Serialises cross-fork head fetches into one base repository.
pub(crate) fn fetch_locks() -> &'static KeyedLocks {
    static L: OnceLock<KeyedLocks> = OnceLock::new();
    L.get_or_init(KeyedLocks::default)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A held fetch lock gives a bounded wait and then a 503, not a queue.
    #[tokio::test]
    async fn lock_within_times_out_as_busy() {
        let locks = KeyedLocks::default();
        let held = locks.lock("a/b").await;
        let err = locks
            .lock_within("a/b", Duration::from_millis(50))
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 503);
        drop(held);
        assert!(locks
            .lock_within("a/b", Duration::from_millis(50))
            .await
            .is_ok());
    }

    fn git_available() -> bool {
        std::process::Command::new("git")
            .arg("--version")
            .output()
            .is_ok()
    }

    #[tokio::test]
    async fn run_reports_exit_code_without_erroring() {
        if !git_available() {
            return;
        }
        let td = tempfile::TempDir::new().unwrap();
        let out = run_at(
            td.path(),
            None,
            &["rev-parse", "--verify", "--quiet", "nope"],
            &[],
        )
        .await
        .unwrap();
        assert!(!out.ok());
        assert!(out.code.is_some());
    }

    #[tokio::test]
    async fn keyed_locks_serialise_same_key() {
        let locks = Arc::new(KeyedLocks::default());
        let a = locks.lock("k").await;
        let l2 = locks.clone();
        let t = tokio::spawn(async move {
            let _g = l2.lock("k").await;
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!t.is_finished(), "second holder must wait");
        // A different key is independent.
        let _b = locks.lock("other").await;
        drop(a);
        t.await.unwrap();
    }
}
