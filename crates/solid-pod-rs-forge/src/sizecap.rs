//! Directory-size measurement and a growth watchdog shared by the mirror
//! worker and the cross-fork head fetch.
//!
//! Git has no "maximum fetched bytes" setting, so callers that must bound what
//! a child process writes poll the destination directory instead (the JSS
//! plugin has no equivalent; this is a Rust-side hardening). The walk runs on
//! a separate task so it can never stall the pipe draining of the process it
//! is watching.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::ForgeError;

/// How often the watchdog measures the directory.
const POLL: Duration = Duration::from_millis(250);

/// Bytes under `path`, symlinks not followed (a repository may hold none, and
/// following one would let a repository measure something it does not own).
pub(crate) fn dir_size(path: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                stack.push(entry.path());
            } else if meta.is_file() {
                total = total.saturating_add(meta.len());
            }
        }
    }
    total
}

/// Drive `work` while watching `dir`. When `dir` grows by more than `cap`
/// bytes over its size at the start, `work` is dropped (so a child spawned
/// with `kill_on_drop` dies) and a [`ForgeError::Backend`] is returned.
pub(crate) async fn guard_growth<T, F>(dir: &Path, cap: u64, work: F) -> Result<T, ForgeError>
where
    F: Future<Output = Result<T, ForgeError>>,
{
    let d: PathBuf = dir.to_path_buf();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let watcher = tokio::spawn(async move {
        let d0 = d.clone();
        let base = tokio::task::spawn_blocking(move || dir_size(&d0))
            .await
            .unwrap_or(0);
        loop {
            tokio::time::sleep(POLL).await;
            let d1 = d.clone();
            let now = tokio::task::spawn_blocking(move || dir_size(&d1))
                .await
                .unwrap_or(0);
            if now.saturating_sub(base) > cap {
                let _ = tx.send(());
                return;
            }
        }
    });
    tokio::pin!(work);
    let out = tokio::select! {
        r = &mut work => r,
        Ok(()) = rx => Err(ForgeError::Backend(
            "fetched objects grew the repository past the size cap".into(),
        )),
    };
    watcher.abort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn growth_past_the_cap_aborts_the_work() {
        let td = tempfile::tempdir().unwrap();
        let p = td.path().to_path_buf();
        let r: Result<(), ForgeError> = guard_growth(&p, 1024, async {
            // Let the watchdog take its baseline before the directory grows.
            tokio::time::sleep(Duration::from_millis(150)).await;
            std::fs::write(p.join("big"), vec![0u8; 8192]).unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(())
        })
        .await;
        assert!(matches!(r, Err(ForgeError::Backend(_))), "{r:?}");
    }

    #[tokio::test]
    async fn work_under_the_cap_completes() {
        let td = tempfile::tempdir().unwrap();
        let r = guard_growth(td.path(), 1024, async { Ok(7) }).await;
        assert_eq!(r.unwrap(), 7);
    }
}
