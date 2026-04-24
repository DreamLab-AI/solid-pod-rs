//! Pod-level quota policy (Sprint 7 §6.4, ADR-057).
//!
//! Mirrors JSS `src/storage/quota.js` — each pod gets a `.quota.json`
//! sidecar file at its storage root carrying `{used_bytes, limit_bytes}`.
//! [`QuotaPolicy::reconcile`] re-walks the pod's directory tree and
//! rewrites the sidecar against disk truth; this is the recovery path
//! after a crash / manual edit / storage-backend swap.
//!
//! The in-memory mutation path is cooperative, not authoritative:
//! [`FsQuotaStore::record`] updates the sidecar best-effort, but
//! callers MUST invoke [`FsQuotaStore::check`] before accepting a write
//! to enforce the cap atomically relative to the policy's own view.
//!
//! # Feature gate
//!
//! The FS implementation lives behind `#[cfg(feature = "quota")]`
//! alongside the [`QuotaPolicy`] trait's sole shipped adapter. The
//! trait itself, [`QuotaUsage`], and [`QuotaExceeded`] are always
//! compiled so downstream crates can build their own backends without
//! opting in to the FS one.

#[cfg(feature = "quota")]
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Always-compiled public types
// ---------------------------------------------------------------------------

/// Snapshot of a pod's quota counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaUsage {
    /// Bytes currently attributed to the pod.
    pub used_bytes: u64,
    /// Hard cap; `0` in an on-disk sidecar is treated as "unset →
    /// apply default" by [`FsQuotaStore`].
    pub limit_bytes: u64,
}

/// Error surfaced when a pre-write check exceeds the pod's cap.
///
/// Carried through [`crate::error::PodError::QuotaExceeded`] when the
/// `quota` feature is enabled; kept as a standalone type so other
/// backends (e.g. S3-tag quota) can reuse the shape without pulling in
/// `PodError` machinery directly.
#[derive(Debug, Clone, thiserror::Error)]
#[error("quota exceeded: pod={pod} used={used} limit={limit}")]
pub struct QuotaExceeded {
    pub pod: String,
    pub used: u64,
    pub limit: u64,
}

/// Per-pod quota policy. Call [`Self::check`] on write paths and
/// [`Self::record`] after a successful write; [`Self::reconcile`] is
/// the crash-recovery entry point that re-reads disk truth.
#[async_trait]
pub trait QuotaPolicy: Send + Sync {
    /// Pre-write check: would adding `delta_bytes` push the pod over
    /// its limit? A `delta_bytes == 0` check is always allowed so
    /// HEAD/GET pre-checks never trip the quota.
    async fn check(&self, pod: &str, delta_bytes: u64) -> Result<(), QuotaExceeded>;

    /// Record an actual write. `delta_bytes` is signed to accommodate
    /// DELETE as a negative delta; implementations saturate at zero.
    async fn record(&self, pod: &str, delta_bytes: i64);

    /// Re-scan the pod's storage and reset counters to disk truth.
    async fn reconcile(&self, pod: &str) -> std::io::Result<QuotaUsage>;

    /// Inspect current counters. `None` when the pod has no quota
    /// sidecar yet (never written to, never reconciled).
    async fn usage(&self, pod: &str) -> Option<QuotaUsage>;
}

// ---------------------------------------------------------------------------
// FsQuotaStore — feature-gated.
// ---------------------------------------------------------------------------

#[cfg(feature = "quota")]
mod fs_impl {
    use super::*;
    use tokio::fs;

    const QUOTA_FILE: &str = ".quota.json";

    /// Filesystem-backed quota store. Each pod lives under `root/<pod>/`
    /// with a `.quota.json` sidecar at its root.
    pub struct FsQuotaStore {
        root: PathBuf,
        default_limit: u64,
    }

    impl FsQuotaStore {
        /// Construct a store rooted at `root` with `default_limit`
        /// applied when a pod's sidecar is absent or has
        /// `limit_bytes == 0` (parity with JSS's "uninitialised quota
        /// → seed from default" branch).
        pub fn new(root: PathBuf, default_limit: u64) -> Self {
            Self {
                root,
                default_limit,
            }
        }

        /// Filesystem path of the sidecar for a given pod.
        pub fn quota_file(&self, pod: &str) -> PathBuf {
            self.root.join(pod).join(QUOTA_FILE)
        }

        fn pod_dir(&self, pod: &str) -> PathBuf {
            self.root.join(pod)
        }

        async fn read_sidecar(&self, pod: &str) -> std::io::Result<Option<QuotaUsage>> {
            match fs::read(self.quota_file(pod)).await {
                Ok(bytes) => {
                    let parsed: QuotaUsage = serde_json::from_slice(&bytes).map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
                    })?;
                    Ok(Some(parsed))
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        }

        /// Atomic sidecar write — mirrors JSS `saveQuota` (PR #309) which
        /// closed an intermittent-500 race on concurrent PUTs. The write
        /// goes to `.quota.json.tmp-<pid>-<nanos>` first, then is
        /// renamed onto `.quota.json`; on POSIX the rename is atomic so
        /// a concurrent reader never observes a half-written document
        /// and a crash leaves at most an orphan `.tmp-*` that
        /// [`Self::reconcile`] / startup sweep can clean up.
        async fn write_sidecar(&self, pod: &str, usage: &QuotaUsage) -> std::io::Result<()> {
            let path = self.quota_file(pod);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).await?;
            }
            let body = serde_json::to_vec_pretty(usage).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, e)
            })?;
            let tmp = {
                use std::time::{SystemTime, UNIX_EPOCH};
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                let pid = std::process::id();
                let mut t = path.as_os_str().to_owned();
                t.push(format!(".tmp-{pid}-{nanos}"));
                PathBuf::from(t)
            };
            match fs::write(&tmp, &body).await {
                Ok(()) => {}
                Err(e) => {
                    let _ = fs::remove_file(&tmp).await;
                    return Err(e);
                }
            }
            if let Err(e) = fs::rename(&tmp, &path).await {
                let _ = fs::remove_file(&tmp).await;
                return Err(e);
            }
            Ok(())
        }

        /// Sweep stale tempfile orphans left by crashed writers.
        ///
        /// Called by [`Self::reconcile`] to match JSS's post-#310
        /// behaviour of ignoring (and cleaning up) half-written quota
        /// sidecars. Deletes any `.quota.json.tmp-*` under the pod root.
        async fn sweep_quota_orphans(&self, pod: &str) -> std::io::Result<()> {
            let dir = match self.quota_file(pod).parent() {
                Some(p) => p.to_path_buf(),
                None => return Ok(()),
            };
            let mut rd = match fs::read_dir(&dir).await {
                Ok(r) => r,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e),
            };
            while let Some(entry) = rd.next_entry().await? {
                if let Some(name) = entry.file_name().to_str() {
                    if name.starts_with(".quota.json.tmp-") {
                        let _ = fs::remove_file(entry.path()).await;
                    }
                }
            }
            Ok(())
        }

        /// Resolve the effective sidecar: on-disk value if present, else
        /// default seed (used=0, limit=self.default_limit).
        async fn effective(&self, pod: &str) -> std::io::Result<QuotaUsage> {
            match self.read_sidecar(pod).await? {
                Some(mut u) => {
                    // JSS parity: `limit == 0` means "apply default".
                    if u.limit_bytes == 0 {
                        u.limit_bytes = self.default_limit;
                    }
                    Ok(u)
                }
                None => Ok(QuotaUsage {
                    used_bytes: 0,
                    limit_bytes: self.default_limit,
                }),
            }
        }

        /// Recursively sum file sizes under `dir`, skipping `.quota.json`
        /// at any depth.
        fn dir_size_boxed<'a>(
            &'a self,
            dir: &'a Path,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = std::io::Result<u64>> + Send + 'a>,
        > {
            Box::pin(async move {
                let mut total: u64 = 0;
                let mut rd = match fs::read_dir(dir).await {
                    Ok(r) => r,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
                    Err(e) => return Err(e),
                };
                while let Some(entry) = rd.next_entry().await? {
                    let name = entry.file_name();
                    if name == QUOTA_FILE {
                        continue;
                    }
                    let ft = entry.file_type().await?;
                    if ft.is_dir() {
                        total = total.saturating_add(
                            self.dir_size_boxed(&entry.path()).await?,
                        );
                    } else if ft.is_file() {
                        let md = entry.metadata().await?;
                        total = total.saturating_add(md.len());
                    }
                }
                Ok(total)
            })
        }
    }

    #[async_trait]
    impl QuotaPolicy for FsQuotaStore {
        async fn check(&self, pod: &str, delta_bytes: u64) -> Result<(), QuotaExceeded> {
            if delta_bytes == 0 {
                // HEAD/GET-style zero-delta checks never reject; also
                // matches JSS `checkQuota` where `additionalBytes=0` is
                // structurally allowed (projected == used).
                return Ok(());
            }
            let u = self.effective(pod).await.unwrap_or(QuotaUsage {
                used_bytes: 0,
                limit_bytes: self.default_limit,
            });
            // `limit == 0` after applying defaults means "no cap".
            if u.limit_bytes == 0 {
                return Ok(());
            }
            let projected = u.used_bytes.saturating_add(delta_bytes);
            if projected > u.limit_bytes {
                return Err(QuotaExceeded {
                    pod: pod.to_string(),
                    used: u.used_bytes,
                    limit: u.limit_bytes,
                });
            }
            Ok(())
        }

        async fn record(&self, pod: &str, delta_bytes: i64) {
            let current = self
                .effective(pod)
                .await
                .unwrap_or(QuotaUsage {
                    used_bytes: 0,
                    limit_bytes: self.default_limit,
                });
            let new_used = if delta_bytes >= 0 {
                current
                    .used_bytes
                    .saturating_add(delta_bytes as u64)
            } else {
                current
                    .used_bytes
                    .saturating_sub((-delta_bytes) as u64)
            };
            let updated = QuotaUsage {
                used_bytes: new_used,
                limit_bytes: current.limit_bytes,
            };
            // Best-effort: swallow IO errors at record time — callers
            // should rely on reconcile() to recover.
            let _ = self.write_sidecar(pod, &updated).await;
        }

        async fn reconcile(&self, pod: &str) -> std::io::Result<QuotaUsage> {
            // JSS parity (post-#310): opportunistically clean up stale
            // `.quota.json.tmp-*` orphans left by crashed writers
            // BEFORE computing disk truth. Errors here are ignored —
            // reconcile is best-effort and the authoritative write path
            // at the bottom of this method will surface any IO failure
            // that actually matters.
            let _ = self.sweep_quota_orphans(pod).await;
            let actual = self.dir_size_boxed(&self.pod_dir(pod)).await?;
            let limit = match self.read_sidecar(pod).await? {
                Some(u) if u.limit_bytes > 0 => u.limit_bytes,
                _ => self.default_limit,
            };
            let reconciled = QuotaUsage {
                used_bytes: actual,
                limit_bytes: limit,
            };
            self.write_sidecar(pod, &reconciled).await?;
            Ok(reconciled)
        }

        async fn usage(&self, pod: &str) -> Option<QuotaUsage> {
            match self.read_sidecar(pod).await {
                Ok(Some(mut u)) => {
                    if u.limit_bytes == 0 {
                        u.limit_bytes = self.default_limit;
                    }
                    Some(u)
                }
                Ok(None) | Err(_) => None,
            }
        }
    }
}

#[cfg(feature = "quota")]
pub use fs_impl::FsQuotaStore;
