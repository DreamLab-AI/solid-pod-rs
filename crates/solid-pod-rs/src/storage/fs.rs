//! Filesystem storage backend.
//!
//! Persists pod resources under a root directory. Each resource body
//! is stored as a file. A sidecar file with the `.meta.json`
//! extension carries the content-type and Link header values.

use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
#[cfg(unix)]
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tokio::fs;
use tokio::sync::{mpsc, RwLock};

use crate::error::PodError;
use crate::storage::{ResourceMeta, Storage, StorageEvent};

const META_SUFFIX: &str = ".meta.json";

/// Directory under the data root that holds the cross-process lock files.
/// A dotfile, so no HTTP route reaches it, and hidden from listings.
const LOCK_DIR: &str = ".solid-pod-locks";

/// Lock files: a key maps to one of this many files by HMAC-SHA-256 under a
/// per-data-root random key (see [`FsBackend::stripe_key`]), so every process on
/// the data root agrees but a client cannot choose names that share a victim's
/// stripe. Striping keeps the lock directory bounded whatever the number of
/// resources and puts no file beside a resource.
const LOCK_STRIPES: usize = 256;

/// The stripe key's file in [`LOCK_DIR`]: 32 random bytes, mode 0600, created
/// once (atomically, by hard link) and read by every later process.
#[cfg(unix)]
const LOCK_KEY_FILE: &str = "key";

/// Lock keys that start with this name server-wide state (the payment
/// ledger), not a resource. Each such name has its own lock file, never a
/// resource stripe, so a task that holds a resource lock can take one without
/// waiting on its own file description.
const STATE_KEY_PREFIX: &str = "state:";

/// How often a waiting locker retries (the lock is taken without blocking, so
/// a waiting request never occupies a runtime thread).
const LOCK_POLL: std::time::Duration = std::time::Duration::from_millis(10);

/// Read the stripe key, creating it if absent. The candidate is written to a
/// private temporary file (mode 0600) and installed with a hard link, which
/// fails if the key already exists, so exactly one creator wins and every
/// other process reads the winner's key.
#[cfg(unix)]
fn load_or_create_lock_key(dir: &Dir) -> Result<[u8; 32], PodError> {
    use cap_std::fs::OpenOptionsExt;
    let key_rel = PathBuf::from(LOCK_DIR).join(LOCK_KEY_FILE);
    dir.create_dir_all(LOCK_DIR)?;
    for _ in 0..8 {
        match dir.read(&key_rel) {
            Ok(bytes) => {
                return <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                    PodError::Backend(format!(
                        "the lock key file {LOCK_DIR}/{LOCK_KEY_FILE} holds {} bytes, expected 32; \
                         refusing to replace it (that would split the stripes between processes)",
                        bytes.len()
                    ))
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let mut candidate = [0u8; 32];
        getrandom::getrandom(&mut candidate).map_err(|e| {
            PodError::Backend(format!("no system randomness for the lock key: {e}"))
        })?;
        let tmp =
            PathBuf::from(LOCK_DIR).join(format!("{LOCK_KEY_FILE}.tmp-{}", uuid::Uuid::new_v4()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = dir.open_with(&tmp, &options)?;
        file.write_all(&candidate)?;
        file.sync_all()?;
        drop(file);
        let linked = dir.hard_link(&tmp, dir, &key_rel);
        let _ = dir.remove_file(&tmp);
        match linked {
            Ok(()) => return Ok(candidate),
            // Another process installed its key first: read that one.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    Err(PodError::Backend("could not settle on a lock key".into()))
}

/// Filesystem-rooted `Storage` implementation.
#[derive(Clone)]
pub struct FsBackend {
    root: Arc<PathBuf>,
    dir: Arc<Dir>,
    operations: Arc<RwLock<()>>,
    /// The data root's stripe key, loaded or created on first lock.
    #[cfg(unix)]
    lock_key: Arc<tokio::sync::OnceCell<[u8; 32]>>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct MetaSidecar {
    content_type: String,
    #[serde(default)]
    links: Vec<String>,
    /// Body generation this metadata describes. Legacy sidecars omit this;
    /// they remain readable, while all new writes use it to reject a
    /// crash-interrupted body/metadata pair.
    #[serde(default)]
    etag: Option<String>,
}

impl FsBackend {
    /// Create a new backend rooted at `root`. The directory must
    /// exist or be creatable; this call ensures it exists.
    pub async fn new(root: impl Into<PathBuf>) -> Result<Self, PodError> {
        let root: PathBuf = root.into();
        fs::create_dir_all(&root).await?;
        let root = fs::canonicalize(root).await?;
        let open_root = root.clone();
        let dir = tokio::task::spawn_blocking(move || {
            Dir::open_ambient_dir(open_root, ambient_authority())
        })
        .await
        .map_err(|e| PodError::Backend(format!("open filesystem root task failed: {e}")))??;
        Ok(Self {
            root: Arc::new(root),
            dir: Arc::new(dir),
            operations: Arc::new(RwLock::new(())),
            #[cfg(unix)]
            lock_key: Arc::new(tokio::sync::OnceCell::new()),
        })
    }

    /// Return the root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The data root's stripe key: read from `.solid-pod-locks/key` or, when
    /// no process has made one yet, generated and installed atomically. Every
    /// process on the data root ends up with the same key. A key file of the
    /// wrong length is an error, never regenerated: replacing it would put two
    /// processes on different stripes and silently end their mutual exclusion.
    #[cfg(unix)]
    async fn stripe_key(&self) -> Result<[u8; 32], PodError> {
        self.lock_key
            .get_or_try_init(|| {
                let dir = self.dir.clone();
                async move {
                    tokio::task::spawn_blocking(move || load_or_create_lock_key(&dir))
                        .await
                        .map_err(|e| PodError::Backend(format!("lock key task failed: {e}")))?
                }
            })
            .await
            .copied()
    }

    fn normalize(path: &str) -> Result<String, PodError> {
        let p = if path.is_empty() {
            "/".to_string()
        } else if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        if p.contains('\0') {
            return Err(PodError::InvalidPath(p));
        }
        let rel = p.trim_start_matches('/');
        if Path::new(rel).components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        }) {
            return Err(PodError::InvalidPath(p));
        }
        Ok(p)
    }

    fn relative(path: &str) -> Result<PathBuf, PodError> {
        let norm = Self::normalize(path)?;
        Ok(PathBuf::from(norm.trim_start_matches('/')))
    }

    fn resolve(&self, path: &str) -> Result<PathBuf, PodError> {
        Ok(self.root.join(Self::relative(path)?))
    }

    fn meta_path(data_path: &Path) -> PathBuf {
        let mut p = data_path.as_os_str().to_owned();
        p.push(META_SUFFIX);
        PathBuf::from(p)
    }

    fn compute_etag(body: &[u8]) -> String {
        hex::encode(Sha256::digest(body))
    }

    fn atomic_write(dir: &Dir, path: &Path, contents: &[u8]) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                dir.create_dir_all(parent)?;
            }
        }
        let file_name = path.file_name().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "resource path has no filename",
            )
        })?;
        let tmp_name = format!(
            ".{}.solid-pod-tmp-{}",
            file_name.to_string_lossy(),
            uuid::Uuid::new_v4()
        );
        let tmp_path = path
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join(tmp_name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        let result = (|| {
            let mut file = dir.open_with(&tmp_path, &options)?;
            file.write_all(contents)?;
            file.sync_all()?;
            dir.rename(&tmp_path, dir, path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = dir.remove_file(&tmp_path);
        }
        result
    }

    fn modified_time(metadata: &cap_std::fs::Metadata) -> chrono::DateTime<chrono::Utc> {
        metadata
            .modified()
            .ok()
            .map(cap_std::time::SystemTime::into_std)
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| {
                chrono::DateTime::from_timestamp(d.as_secs() as i64, d.subsec_nanos())
                    .unwrap_or_else(chrono::Utc::now)
            })
            .unwrap_or_else(chrono::Utc::now)
    }

    fn read_meta(
        dir: &Dir,
        path: &str,
        body_len: u64,
        etag: String,
        modified: chrono::DateTime<chrono::Utc>,
    ) -> Result<ResourceMeta, PodError> {
        let data_path = Self::relative(path)?;
        let meta_path = Self::meta_path(&data_path);
        // JSS #294 + #533 parity: sidecar-absent resources resolve their
        // content-type by extension. `.acl` / `.meta` (and `*.acl` /
        // `*.meta`) have no Node-style extension and fall back to
        // `application/ld+json`; everything else (including git-extracted
        // app files under `/public/apps/`) resolves via Solid overrides →
        // the mime-types database → `application/octet-stream`, so audio,
        // video, HTML, CSS, etc. render inline instead of downloading.
        let fallback_ct: String = crate::ldp::guess_content_type(path);
        let (content_type, links) = match dir.read(&meta_path) {
            Ok(bytes) => {
                let sidecar: MetaSidecar =
                    serde_json::from_slice(&bytes).unwrap_or_else(|_| MetaSidecar {
                        content_type: fallback_ct.clone(),
                        links: Vec::new(),
                        etag: None,
                    });
                if sidecar
                    .etag
                    .as_deref()
                    .is_none_or(|expected| expected == etag)
                {
                    (sidecar.content_type, sidecar.links)
                } else {
                    (fallback_ct, Vec::new())
                }
            }
            Err(_) => (fallback_ct, Vec::new()),
        };
        Ok(ResourceMeta {
            etag,
            modified,
            size: body_len,
            content_type,
            links,
        })
    }
}

#[async_trait]
impl Storage for FsBackend {
    async fn get(&self, path: &str) -> Result<(Bytes, ResourceMeta), PodError> {
        let _guard = self.operations.read().await;
        let rel = Self::relative(path)?;
        let dir = self.dir.clone();
        let requested = path.to_string();
        tokio::task::spawn_blocking(move || {
            let body = match dir.read(&rel) {
                Ok(body) => body,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(PodError::NotFound(requested.clone()));
                }
                Err(e) => return Err(e.into()),
            };
            let metadata = dir.metadata(&rel)?;
            let modified = Self::modified_time(&metadata);
            let etag = Self::compute_etag(&body);
            let meta = Self::read_meta(&dir, &requested, body.len() as u64, etag, modified)?;
            Ok((Bytes::from(body), meta))
        })
        .await
        .map_err(|e| PodError::Backend(format!("filesystem read task failed: {e}")))?
    }

    async fn put(
        &self,
        path: &str,
        body: Bytes,
        content_type: &str,
    ) -> Result<ResourceMeta, PodError> {
        if crate::wac::path_beneath_sidecar(path) {
            return Err(PodError::BadRequest(format!(
                "nothing may be created beneath an ACL or meta document: {path}"
            )));
        }
        let _guard = self.operations.write().await;
        let data_path = Self::relative(path)?;
        if data_path.as_os_str().is_empty() {
            return Err(PodError::InvalidPath(path.to_string()));
        }
        let etag = Self::compute_etag(&body);
        let sidecar = MetaSidecar {
            content_type: content_type.to_string(),
            links: Vec::new(),
            etag: Some(etag.clone()),
        };
        let sidecar_bytes = serde_json::to_vec(&sidecar)?;
        let meta_path = Self::meta_path(&data_path);
        let dir = self.dir.clone();
        let body_to_write = body.clone();
        tokio::task::spawn_blocking(move || {
            // Publish metadata first. It is tagged with the future body ETag,
            // so readers ignore it until the body rename commits the pair.
            Self::atomic_write(&dir, &meta_path, &sidecar_bytes)?;
            Self::atomic_write(&dir, &data_path, &body_to_write)?;
            Ok::<(), PodError>(())
        })
        .await
        .map_err(|e| PodError::Backend(format!("filesystem write task failed: {e}")))??;
        Ok(ResourceMeta {
            etag,
            modified: chrono::Utc::now(),
            size: body.len() as u64,
            content_type: content_type.to_string(),
            links: Vec::new(),
        })
    }

    async fn delete(&self, path: &str) -> Result<(), PodError> {
        let _guard = self.operations.write().await;
        let data_path = Self::relative(path)?;
        let meta_path = Self::meta_path(&data_path);
        let dir = self.dir.clone();
        let requested = path.to_string();
        tokio::task::spawn_blocking(move || {
            match dir.remove_file(&data_path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(PodError::NotFound(requested));
                }
                Err(e) => return Err(e.into()),
            }
            let _ = dir.remove_file(&meta_path);
            Ok(())
        })
        .await
        .map_err(|e| PodError::Backend(format!("filesystem delete task failed: {e}")))?
    }

    async fn list(&self, container: &str) -> Result<Vec<String>, PodError> {
        let _guard = self.operations.read().await;
        let mut container_path = Self::relative(container)?;
        // The root is the empty relative path, which `read_dir` rejects.
        if container_path.as_os_str().is_empty() {
            container_path = PathBuf::from(".");
        }
        let dir = self.dir.clone();
        tokio::task::spawn_blocking(move || {
            let entries = match dir.read_dir(&container_path) {
                Ok(entries) => entries,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
                Err(e) => return Err(PodError::Io(e)),
            };
            let mut out = Vec::new();
            for entry in entries {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with(META_SUFFIX)
                    || name.contains(".solid-pod-tmp-")
                    || name == LOCK_DIR
                {
                    continue;
                }
                let is_dir = entry.metadata().map(|m| m.is_dir()).unwrap_or(false);
                out.push(if is_dir { format!("{name}/") } else { name });
            }
            out.sort();
            Ok(out)
        })
        .await
        .map_err(|e| PodError::Backend(format!("filesystem list task failed: {e}")))?
    }

    async fn head(&self, path: &str) -> Result<ResourceMeta, PodError> {
        let _guard = self.operations.read().await;
        let data_path = Self::relative(path)?;
        let dir = self.dir.clone();
        let requested = path.to_string();
        tokio::task::spawn_blocking(move || {
            let metadata = match dir.metadata(&data_path) {
                Ok(metadata) => metadata,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(PodError::NotFound(requested));
                }
                Err(e) => return Err(e.into()),
            };
            let body = dir.read(&data_path)?;
            let etag = Self::compute_etag(&body);
            let modified = Self::modified_time(&metadata);
            Self::read_meta(&dir, &requested, body.len() as u64, etag, modified)
        })
        .await
        .map_err(|e| PodError::Backend(format!("filesystem head task failed: {e}")))?
    }

    async fn exists(&self, path: &str) -> Result<bool, PodError> {
        let _guard = self.operations.read().await;
        let mut data_path = Self::relative(path)?;
        // The root is the empty relative path, which `exists` reports absent.
        if data_path.as_os_str().is_empty() {
            data_path = PathBuf::from(".");
        }
        let dir = self.dir.clone();
        tokio::task::spawn_blocking(move || Ok(dir.exists(data_path)))
            .await
            .map_err(|e| PodError::Backend(format!("filesystem exists task failed: {e}")))?
    }

    #[cfg(unix)]
    async fn lock_exclusive(
        &self,
        key: &str,
        wait: std::time::Duration,
    ) -> Result<Option<crate::storage::StorageLock>, PodError> {
        use rustix::fs::{flock, FlockOperation};
        let mac_key = self.stripe_key().await?;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&mac_key)
            .map_err(|e| PodError::Backend(format!("lock key: {e}")))?;
        mac.update(key.as_bytes());
        let digest = mac.finalize().into_bytes();
        let name = if key.starts_with(STATE_KEY_PREFIX) {
            format!("state-{}.lock", hex::encode(&digest[..4]))
        } else {
            format!("{:02x}.lock", usize::from(digest[0]) % LOCK_STRIPES)
        };
        let rel = PathBuf::from(LOCK_DIR).join(name);
        let dir = self.dir.clone();
        let file = tokio::task::spawn_blocking(move || -> std::io::Result<std::fs::File> {
            dir.create_dir_all(LOCK_DIR)?;
            let mut options = OpenOptions::new();
            options.read(true).write(true).create(true);
            Ok(dir.open_with(&rel, &options)?.into_std())
        })
        .await
        .map_err(|e| PodError::Backend(format!("lock task failed: {e}")))??;
        let deadline = std::time::Instant::now() + wait;
        loop {
            match flock(&file, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => return Ok(Some(crate::storage::StorageLock::new(file))),
                Err(rustix::io::Errno::WOULDBLOCK) => {
                    if std::time::Instant::now() >= deadline {
                        return Err(PodError::Conflict(format!(
                            "the resource is being written by another process: {key}"
                        )));
                    }
                    tokio::time::sleep(LOCK_POLL).await;
                }
                Err(e) => return Err(PodError::Io(std::io::Error::from(e))),
            }
        }
    }

    async fn is_directory(&self, path: &str) -> bool {
        let Ok(rel) = Self::relative(path) else {
            return false;
        };
        let dir = self.dir.clone();
        tokio::task::spawn_blocking(move || dir.metadata(&rel).is_ok_and(|m| m.is_dir()))
            .await
            .unwrap_or(false)
    }

    async fn create_container(&self, path: &str) -> Result<ResourceMeta, PodError> {
        if crate::wac::path_beneath_sidecar(&format!("{}/", path.trim_end_matches('/'))) {
            return Err(PodError::BadRequest(format!(
                "nothing may be created beneath an ACL or meta document: {path}"
            )));
        }
        let container = if path.ends_with('/') {
            path.to_string()
        } else {
            format!("{path}/")
        };
        let _guard = self.operations.write().await;
        let dir_path = Self::relative(&container)?;
        let dir = self.dir.clone();
        tokio::task::spawn_blocking(move || dir.create_dir_all(dir_path))
            .await
            .map_err(|e| PodError::Backend(format!("create container task failed: {e}")))??;
        Ok(ResourceMeta::new("container", 0, "application/ld+json"))
    }

    async fn watch(&self, path: &str) -> Result<mpsc::Receiver<StorageEvent>, PodError> {
        use notify::{RecursiveMode, Watcher};

        let data_path = self.resolve(path)?;
        let filter_root = data_path.clone();
        let root = self.root.clone();
        let (tx, rx) = mpsc::channel::<StorageEvent>(64);

        let (raw_tx, raw_rx) = std::sync::mpsc::channel::<notify::Result<notify::Event>>();
        let mut watcher = notify::recommended_watcher(move |res| {
            let _ = raw_tx.send(res);
        })?;
        let mode = if data_path.is_dir() {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        };
        let watch_target = if data_path.exists() {
            data_path.clone()
        } else {
            root.to_path_buf()
        };
        watcher.watch(&watch_target, mode)?;

        tokio::task::spawn_blocking(move || {
            let _keep = watcher;
            while let Ok(Ok(event)) = raw_rx.recv() {
                for path in &event.paths {
                    let s = path.to_string_lossy();
                    if s.ends_with(META_SUFFIX) {
                        continue;
                    }
                    let virt = match path.strip_prefix(root.as_path()) {
                        Ok(p) => format!("/{}", p.to_string_lossy()),
                        Err(_) => continue,
                    };
                    if !path.starts_with(&filter_root) && path != &filter_root {
                        continue;
                    }
                    use notify::EventKind;
                    let storage_event = match event.kind {
                        EventKind::Create(_) => StorageEvent::Created(virt),
                        EventKind::Modify(_) => StorageEvent::Updated(virt),
                        EventKind::Remove(_) => StorageEvent::Deleted(virt),
                        _ => continue,
                    };
                    if tx.blocking_send(storage_event).is_err() {
                        return;
                    }
                }
            }
        });

        Ok(rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn put_get_roundtrip() {
        let dir = TempDir::new().unwrap();
        let fsb = FsBackend::new(dir.path()).await.unwrap();
        fsb.put("/a/b.txt", Bytes::from_static(b"hello"), "text/plain")
            .await
            .unwrap();
        let (body, meta) = fsb.get("/a/b.txt").await.unwrap();
        assert_eq!(&body[..], b"hello");
        assert_eq!(meta.content_type, "text/plain");
        assert_eq!(meta.size, 5);
    }

    #[tokio::test]
    async fn list_skips_meta_sidecar() {
        let dir = TempDir::new().unwrap();
        let fsb = FsBackend::new(dir.path()).await.unwrap();
        fsb.put("/c/x.txt", Bytes::from_static(b"x"), "text/plain")
            .await
            .unwrap();
        let items = fsb.list("/c").await.unwrap();
        assert_eq!(items, vec!["x.txt".to_string()]);
    }

    #[tokio::test]
    async fn delete_removes_resource_and_sidecar() {
        let dir = TempDir::new().unwrap();
        let fsb = FsBackend::new(dir.path()).await.unwrap();
        fsb.put("/f.txt", Bytes::from_static(b"y"), "text/plain")
            .await
            .unwrap();
        fsb.delete("/f.txt").await.unwrap();
        assert!(!fsb.exists("/f.txt").await.unwrap());
        let sidecar = dir.path().join("f.txt.meta.json");
        assert!(!sidecar.exists());
    }

    #[tokio::test]
    async fn fs_backend_serves_acl_as_jsonld_without_sidecar() {
        // Row 167 / JSS PR #294: a `.acl` resource written without a
        // `.meta.json` sidecar must surface as `application/ld+json`,
        // not `application/octet-stream` (which conneg would reject).
        let dir = TempDir::new().unwrap();
        let fsb = FsBackend::new(dir.path()).await.unwrap();
        // Low-level write: bypass FsBackend::put so no sidecar is
        // created — simulates a resource provisioned out-of-band or
        // left behind after a sidecar crash.
        fs::write(dir.path().join(".acl"), b"{}").await.unwrap();
        let (_body, meta) = fsb.get("/.acl").await.unwrap();
        assert_eq!(meta.content_type, "application/ld+json");

        // Also cover `foo.acl` suffix form.
        fs::write(dir.path().join("foo.acl"), b"{}").await.unwrap();
        let (_, meta2) = fsb.get("/foo.acl").await.unwrap();
        assert_eq!(meta2.content_type, "application/ld+json");

        // And `.meta`.
        fs::write(dir.path().join("bar.meta"), b"{}").await.unwrap();
        let (_, meta3) = fsb.get("/bar.meta").await.unwrap();
        assert_eq!(meta3.content_type, "application/ld+json");

        // Non-dotfile still falls back to octet-stream when no sidecar.
        fs::write(dir.path().join("plain.bin"), b"\x00\x01")
            .await
            .unwrap();
        let (_, meta4) = fsb.get("/plain.bin").await.unwrap();
        assert_eq!(meta4.content_type, "application/octet-stream");
    }

    #[tokio::test]
    async fn rejects_path_traversal() {
        let dir = TempDir::new().unwrap();
        let fsb = FsBackend::new(dir.path()).await.unwrap();
        let err = fsb
            .put("/../escape.txt", Bytes::from_static(b""), "text/plain")
            .await
            .err()
            .unwrap();
        assert!(matches!(err, PodError::InvalidPath(_)));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_cannot_escape_root_for_read_write_or_delete() {
        use std::os::unix::fs::symlink;

        let root = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let outside_file = outside.path().join("secret.txt");
        std::fs::write(&outside_file, b"host-secret").unwrap();
        symlink(&outside_file, root.path().join("escape.txt")).unwrap();

        let fsb = FsBackend::new(root.path()).await.unwrap();
        assert!(fsb.get("/escape.txt").await.is_err());

        fsb.put(
            "/escape.txt",
            Bytes::from_static(b"pod-content"),
            "text/plain",
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(&outside_file).unwrap(), b"host-secret");
        assert_eq!(&fsb.get("/escape.txt").await.unwrap().0[..], b"pod-content");

        symlink(outside.path(), root.path().join("escape-dir")).unwrap();
        assert!(fsb.get("/escape-dir/secret.txt").await.is_err());
        assert!(fsb
            .put(
                "/escape-dir/new.txt",
                Bytes::from_static(b"nope"),
                "text/plain",
            )
            .await
            .is_err());
        assert!(!outside.path().join("new.txt").exists());

        fsb.delete("/escape.txt").await.unwrap();
        assert_eq!(std::fs::read(&outside_file).unwrap(), b"host-secret");
    }

    #[tokio::test]
    async fn concurrent_reads_observe_complete_body_metadata_pairs() {
        let dir = TempDir::new().unwrap();
        let fsb = FsBackend::new(dir.path()).await.unwrap();
        fsb.put("/state", Bytes::from(vec![b'a'; 128 * 1024]), "text/a")
            .await
            .unwrap();

        let writer = {
            let fsb = fsb.clone();
            tokio::spawn(async move {
                for i in 0..32 {
                    let (byte, content_type) = if i % 2 == 0 {
                        (b'a', "text/a")
                    } else {
                        (b'b', "text/b")
                    };
                    fsb.put("/state", Bytes::from(vec![byte; 128 * 1024]), content_type)
                        .await
                        .unwrap();
                }
            })
        };
        let reader = {
            let fsb = fsb.clone();
            tokio::spawn(async move {
                for _ in 0..64 {
                    let (body, meta) = fsb.get("/state").await.unwrap();
                    assert_eq!(body.len(), 128 * 1024);
                    let expected = if body[0] == b'a' { "text/a" } else { "text/b" };
                    assert!(body.iter().all(|byte| *byte == body[0]));
                    assert_eq!(meta.content_type, expected);
                    assert_eq!(meta.etag, FsBackend::compute_etag(&body));
                }
            })
        };
        writer.await.unwrap();
        reader.await.unwrap();
    }
}
