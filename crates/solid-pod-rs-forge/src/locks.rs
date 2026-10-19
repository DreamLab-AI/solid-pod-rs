//! Per-repository serialisation locks for spine writes.
//!
//! JSS `forge` funnels every issue-index mutation through `serializeOn`, one
//! promise chain per `<owner>/<repo>`, so number allocation and
//! read-modify-write cycles never race (and pulls and merges ride a second
//! chain). [`RepoLocks`] is the async-mutex equivalent: one
//! [`tokio::sync::Mutex`] per repository key.
//!
//! Lock order, when both are needed: **issue lock first, then pull lock**
//! (the label rename and delete cascade does exactly this). Hold a lock only
//! across load, modify and save of the index, never across a loopback fetch.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

/// A keyed set of async mutexes, one per `<owner>/<repo>`.
///
/// # Examples
///
/// ```
/// let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
/// rt.block_on(async {
///     let locks = solid_pod_rs_forge::locks::RepoLocks::default();
///     let g = locks.lock("alice", "demo").await;
///     // A second acquisition of the same key waits; another key does not.
///     let other = locks.lock("alice", "other").await;
///     drop(other);
///     drop(g);
/// });
/// ```
#[derive(Debug, Default)]
pub struct RepoLocks {
    map: Mutex<HashMap<String, Arc<AsyncMutex<()>>>>,
}

impl RepoLocks {
    /// Acquire the lock for `<owner>/<repo>`, waiting for earlier holders.
    pub async fn lock(&self, owner: &str, repo: &str) -> OwnedMutexGuard<()> {
        let key = format!("{owner}/{repo}");
        let m = {
            let mut map = self
                .map
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Drop entries nobody holds or waits on, so the map cannot grow
            // without bound over a long-lived process.
            if map.len() > 256 {
                map.retain(|_, v| Arc::strong_count(v) > 1);
            }
            map.entry(key).or_default().clone()
        };
        m.lock_owned().await
    }
}

/// The two lock families JSS keeps: `issueLocks` and `pullLocks`.
#[derive(Debug, Default)]
pub struct ForgeLocks {
    /// Guards `issues/<owner>/<repo>.json` (labels live in the same file).
    pub issues: RepoLocks,
    /// Guards `pulls/<owner>/<repo>.json` and merges. Acquire after
    /// [`ForgeLocks::issues`] when both are needed.
    pub pulls: RepoLocks,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn same_key_serialises_and_other_keys_do_not() {
        let locks = Arc::new(RepoLocks::default());
        let counter = Arc::new(AtomicU32::new(0));
        let g = locks.lock("a", "r").await;
        // A different key is immediately available.
        let other = locks.lock("a", "s").await;
        drop(other);
        let (l2, c2) = (locks.clone(), counter.clone());
        let waiter = tokio::spawn(async move {
            let _g = l2.lock("a", "r").await;
            c2.fetch_add(1, Ordering::SeqCst);
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(counter.load(Ordering::SeqCst), 0, "still blocked");
        drop(g);
        waiter.await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn read_modify_write_does_not_lose_updates() {
        let locks = Arc::new(RepoLocks::default());
        let value = Arc::new(tokio::sync::Mutex::new(0u32));
        let mut tasks = Vec::new();
        for _ in 0..50 {
            let (l, v) = (locks.clone(), value.clone());
            tasks.push(tokio::spawn(async move {
                let _g = l.lock("o", "r").await;
                let cur = *v.lock().await;
                tokio::task::yield_now().await;
                *v.lock().await = cur + 1;
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        assert_eq!(*value.lock().await, 50);
    }
}
