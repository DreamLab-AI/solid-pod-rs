//! Storage abstraction for Solid pods.
//!
//! The `Storage` trait is the sole interface between the Solid
//! protocol layer and concrete persistence backends. Implementations
//! must be `Send + Sync + 'static` and safe for concurrent access.
//!
//! Two backends ship with the crate:
//!
//! - `memory::MemoryBackend` — in-memory, ideal for tests.
//! - `fs::FsBackend` — filesystem-rooted, uses `tokio::fs` and
//!   `notify` for change events.

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::PodError;

#[cfg(feature = "fs-backend")]
pub mod fs;

#[cfg(feature = "memory-backend")]
pub mod memory;

/// Metadata describing a resource stored in a pod.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceMeta {
    /// Strong ETag (typically hex-encoded SHA-256).
    pub etag: String,
    /// Last modification time, UTC.
    pub modified: chrono::DateTime<chrono::Utc>,
    /// Size of the body in bytes.
    pub size: u64,
    /// MIME type, e.g. `"application/ld+json"`.
    pub content_type: String,
    /// `Link` header values.
    ///
    /// Each entry is a single `Link` value (no outer commas), e.g.
    /// `<http://www.w3.org/ns/ldp#Resource>; rel="type"`.
    pub links: Vec<String>,
}

impl ResourceMeta {
    /// Construct a default `ResourceMeta` with the current UTC time.
    pub fn new(etag: impl Into<String>, size: u64, content_type: impl Into<String>) -> Self {
        ResourceMeta {
            etag: etag.into(),
            modified: chrono::Utc::now(),
            size,
            content_type: content_type.into(),
            links: Vec::new(),
        }
    }
}

/// Change events emitted by storage watchers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageEvent {
    /// A resource was created at the given path.
    Created(String),
    /// A resource was updated at the given path.
    Updated(String),
    /// A resource was deleted at the given path.
    Deleted(String),
}

/// An exclusive hold on one resource key, released when dropped.
///
/// Returned by [`Storage::lock_exclusive`]. It is opaque: the backend decides
/// what it holds (an OS file lock for the filesystem backend).
pub struct StorageLock {
    _held: Box<dyn std::any::Any + Send + Sync>,
}

impl StorageLock {
    /// Wrap whatever keeps the lock alive.
    pub fn new(held: impl std::any::Any + Send + Sync) -> Self {
        Self {
            _held: Box::new(held),
        }
    }
}

impl std::fmt::Debug for StorageLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StorageLock")
    }
}

/// The storage abstraction. Implementations back a Solid pod with
/// arbitrary persistence.
///
/// All paths use forward slashes and are rooted at `/`. Container
/// paths end with `/`.
#[async_trait]
pub trait Storage: Send + Sync + 'static {
    /// Fetch a resource body + metadata.
    async fn get(&self, path: &str) -> Result<(Bytes, ResourceMeta), PodError>;

    /// Write (create-or-replace) a resource.
    ///
    /// Returns the new metadata including the computed ETag.
    async fn put(
        &self,
        path: &str,
        body: Bytes,
        content_type: &str,
    ) -> Result<ResourceMeta, PodError>;

    /// Delete a resource.
    async fn delete(&self, path: &str) -> Result<(), PodError>;

    /// List direct children of a container.
    ///
    /// Returned paths are relative to the container. A trailing `/`
    /// indicates a sub-container.
    async fn list(&self, container: &str) -> Result<Vec<String>, PodError>;

    /// Fetch metadata without the body.
    async fn head(&self, path: &str) -> Result<ResourceMeta, PodError>;

    /// Return whether a resource exists.
    async fn exists(&self, path: &str) -> Result<bool, PodError>;

    /// Take a cross-process exclusive lock on `key`, waiting at most `wait`.
    ///
    /// A write that reads, decides and writes (PATCH, a conditional PUT or
    /// DELETE) holds this around the whole sequence so that two server
    /// processes sharing one data root cannot interleave. The default returns
    /// `Ok(None)`: the backend is not shared between processes, and the
    /// caller's in-process lock is all there is. A backend that can be shared
    /// returns `Ok(Some(lock))`, or [`PodError::Conflict`] when the lock was
    /// not obtained within `wait`.
    async fn lock_exclusive(
        &self,
        _key: &str,
        _wait: std::time::Duration,
    ) -> Result<Option<StorageLock>, PodError> {
        Ok(None)
    }

    /// Whether a *directory* (not a resource) sits at exactly `path`.
    ///
    /// Only the filesystem backend can have one at a resource key (a resource
    /// named `x.acl` beside a directory of that name); the default is
    /// `false`, which makes every other backend fail closed. The WAC resolver
    /// uses it to read a directory at an ACL key as absent rather than as an
    /// error, and never for anything else.
    async fn is_directory(&self, _path: &str) -> bool {
        false
    }

    /// Create an empty container at `path`.
    ///
    /// JSS parity: `PUT` with `Link: <ldp:BasicContainer>; rel="type"`
    /// creates a container rather than a resource. The default
    /// implementation writes a `.meta` marker via [`Storage::put`];
    /// filesystem backends should create a directory instead.
    async fn create_container(&self, path: &str) -> Result<ResourceMeta, PodError> {
        let container = if path.ends_with('/') {
            path.to_string()
        } else {
            format!("{path}/")
        };
        let meta_path = format!(
            "{container}.meta",
            container = container.trim_end_matches('/')
        );
        self.put(&meta_path, Bytes::new(), "application/ld+json")
            .await
    }

    /// Register a watcher for a resource or container.
    ///
    /// The returned channel receives `StorageEvent` messages for
    /// changes under `path`. Closing the receiver detaches the
    /// watcher.
    async fn watch(
        &self,
        path: &str,
    ) -> Result<tokio::sync::mpsc::Receiver<StorageEvent>, PodError>;
}
