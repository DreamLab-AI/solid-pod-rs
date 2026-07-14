//! The spine — the forge's only durable non-git metadata.
//!
//! "Words in pods, metadata in the forge": issue/PR/comment *bodies* live
//! in the author's pod (or forge-hosted storage for podless agents); the
//! spine keeps only an index of pointers. This module defines the
//! [`SpineStore`] persistence trait and its filesystem implementation,
//! which writes each index atomically (`tmp` + `rename`) so a crash
//! mid-write can never corrupt a live index.

pub mod issues;

use std::path::{Path, PathBuf};

use async_trait::async_trait;

use crate::error::ForgeError;
use crate::ownership::valid_name_segment;

/// Object-safe byte-level persistence for spine indices. Typed helpers
/// (e.g. [`issues::load_issue_index`]) sit on top of this. Kept
/// byte-level so it stays `dyn`-compatible; the atomicity guarantee lives
/// in the implementation.
#[async_trait]
pub trait SpineStore: Send + Sync {
    /// Load the raw JSON bytes for `(kind, owner, repo)`, or `None` when
    /// no index has been written yet.
    async fn load(&self, kind: &str, owner: &str, repo: &str)
        -> Result<Option<Vec<u8>>, ForgeError>;

    /// Atomically persist `bytes` for `(kind, owner, repo)`.
    async fn store(
        &self,
        kind: &str,
        owner: &str,
        repo: &str,
        bytes: &[u8],
    ) -> Result<(), ForgeError>;
}

/// Filesystem-backed spine store rooted at the plugin dir. Index files
/// live at `<root>/<kind>/<owner>/<repo>.json`.
#[derive(Debug, Clone)]
pub struct FsSpineStore {
    root: PathBuf,
}

impl FsSpineStore {
    /// Create a store rooted at `plugin_dir` (the same dir passed to
    /// [`crate::ForgeService::new`]).
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Compute and validate the on-disk path for an index, rejecting any
    /// traversal in `kind`/`owner`/`repo`.
    fn index_path(&self, kind: &str, owner: &str, repo: &str) -> Result<PathBuf, ForgeError> {
        if !valid_name_segment(kind) {
            return Err(ForgeError::PathTraversal(format!("kind: {kind}")));
        }
        if !valid_name_segment(owner) {
            return Err(ForgeError::PathTraversal(format!("owner: {owner}")));
        }
        if !valid_name_segment(repo) {
            return Err(ForgeError::PathTraversal(format!("repo: {repo}")));
        }
        Ok(self.root.join(kind).join(owner).join(format!("{repo}.json")))
    }
}

#[async_trait]
impl SpineStore for FsSpineStore {
    async fn load(
        &self,
        kind: &str,
        owner: &str,
        repo: &str,
    ) -> Result<Option<Vec<u8>>, ForgeError> {
        let path = self.index_path(kind, owner, repo)?;
        match tokio::fs::read(&path).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(ForgeError::Io(e)),
        }
    }

    async fn store(
        &self,
        kind: &str,
        owner: &str,
        repo: &str,
        bytes: &[u8],
    ) -> Result<(), ForgeError> {
        let path = self.index_path(kind, owner, repo)?;
        let dir = path
            .parent()
            .ok_or_else(|| ForgeError::Backend("index path has no parent".into()))?;
        tokio::fs::create_dir_all(dir).await?;
        atomic_write(&path, bytes).await
    }
}

/// Write `bytes` to `path` atomically: write to a unique sibling temp
/// file, `fsync`, then `rename` over the target. A rename within a
/// directory is atomic on POSIX, so a reader sees either the old file or
/// the fully-written new one — never a torn write.
pub async fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), ForgeError> {
    let dir = path
        .parent()
        .ok_or_else(|| ForgeError::Backend("write path has no parent".into()))?;
    let fname = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("index.json");
    // Unique temp name; uuid avoids collisions under concurrent writers.
    let tmp = dir.join(format!(".{fname}.{}.tmp", uuid::Uuid::new_v4()));

    // Scoped so the file is closed (and its handle dropped) before rename.
    {
        use tokio::io::AsyncWriteExt;
        let mut f = tokio::fs::File::create(&tmp).await?;
        f.write_all(bytes).await?;
        f.flush().await?;
        // Best-effort durability; ignore platforms that lack fsync.
        let _ = f.sync_all().await;
    }

    match tokio::fs::rename(&tmp, path).await {
        Ok(()) => Ok(()),
        Err(e) => {
            // Clean up the temp file on failure.
            let _ = tokio::fs::remove_file(&tmp).await;
            Err(ForgeError::Io(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn load_absent_is_none() {
        let td = TempDir::new().unwrap();
        let store = FsSpineStore::new(td.path());
        let got = store.load("issues", "alice", "repo").await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn store_then_load_roundtrips() {
        let td = TempDir::new().unwrap();
        let store = FsSpineStore::new(td.path());
        store
            .store("issues", "alice", "repo", b"{\"x\":1}")
            .await
            .unwrap();
        let got = store.load("issues", "alice", "repo").await.unwrap().unwrap();
        assert_eq!(got, b"{\"x\":1}");
        // The file lives where we expect and no temp files leaked.
        let dir = td.path().join("issues/alice");
        let mut leftover = Vec::new();
        let mut rd = tokio::fs::read_dir(&dir).await.unwrap();
        while let Some(e) = rd.next_entry().await.unwrap() {
            leftover.push(e.file_name().to_string_lossy().into_owned());
        }
        assert_eq!(leftover, vec!["repo.json".to_string()]);
    }

    #[tokio::test]
    async fn store_rejects_traversal() {
        let td = TempDir::new().unwrap();
        let store = FsSpineStore::new(td.path());
        assert!(store.store("issues", "..", "r", b"{}").await.is_err());
        assert!(store.store("issues", "alice", "../x", b"{}").await.is_err());
        assert!(store.store("../etc", "a", "r", b"{}").await.is_err());
    }

    #[tokio::test]
    async fn overwrite_is_atomic_replace() {
        let td = TempDir::new().unwrap();
        let store = FsSpineStore::new(td.path());
        store.store("issues", "a", "r", b"first").await.unwrap();
        store.store("issues", "a", "r", b"second-longer").await.unwrap();
        let got = store.load("issues", "a", "r").await.unwrap().unwrap();
        assert_eq!(got, b"second-longer");
    }
}
