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

/// How many times key creation and the stripe-file open are retried when the
/// filesystem reports `NotFound` for an entry this process has just created or
/// is racing other processes to create, or when a step fails because the lock
/// directory was removed underneath it (see [`vanished_lock_dir_as_not_found`]).
#[cfg(unix)]
const LOCK_SETUP_ATTEMPTS: u32 = 32;

/// Pause before retry number `attempt` (0-based): 1 ms, growing to a 16 ms cap.
#[cfg(unix)]
fn lock_setup_backoff(attempt: u32) -> std::time::Duration {
    std::time::Duration::from_millis(u64::from((attempt + 1).min(16)))
}

/// Run one step of lock setup, naming it in the error so a failure is
/// diagnosable from the message alone.
#[cfg(unix)]
fn lock_step<T>(op: &str, r: std::io::Result<T>) -> Result<T, (std::io::ErrorKind, PodError)> {
    r.map_err(|e| {
        (
            e.kind(),
            PodError::Backend(format!("lock setup: {op}: {e}")),
        )
    })
}

/// The lock directory a setup step worked in, as far as the caller knows it.
#[cfg(unix)]
#[derive(Clone, Copy)]
enum LockDirSeen<'a> {
    /// A handle on it: the step ran relative to this directory. The handle
    /// keeps its inode alive, so a recreated directory cannot reuse its number.
    Held(&'a Dir),
    /// Only the `(dev, ino)` observed at [`LOCK_DIR`] before the step, which
    /// was the one opening the directory. A reused inode number can only make
    /// a replaced directory look unchanged, which surfaces the error: it can
    /// never hide a genuine one.
    Snapshot((u64, u64)),
}

/// The `(dev, ino)` of a directory's metadata.
#[cfg(unix)]
fn dir_identity(m: &cap_std::fs::Metadata) -> (u64, u64) {
    use cap_std::fs::MetadataExt;
    (m.dev(), m.ino())
}

/// Whether the lock directory `seen` is no longer the directory at
/// [`LOCK_DIR`] under `dir`: the path is now absent, or names another
/// directory. Any failure to tell reports `false`, so the caller surfaces its
/// original error.
#[cfg(unix)]
fn lock_dir_replaced(dir: &Dir, seen: LockDirSeen<'_>) -> bool {
    let now = match dir.symlink_metadata(LOCK_DIR) {
        Ok(now) => dir_identity(&now),
        Err(e) => return e.kind() == std::io::ErrorKind::NotFound,
    };
    match seen {
        LockDirSeen::Held(held) => held
            .dir_metadata()
            .is_ok_and(|was| dir_identity(&was) != now),
        LockDirSeen::Snapshot(was) => was != now,
    }
}

/// Report an `InvalidInput` (`EINVAL`) from a step in the lock directory as
/// `NotFound` when the directory was removed or replaced during the step, so
/// the setup loops retry it like any other vanished entry.
///
/// macOS can fail with `EINVAL` rather than `ENOENT` when `.solid-pod-locks`
/// is removed during an open. cap-std resolves `.solid-pod-locks/NN.lock`
/// there with two `openat` calls (the directory, then the file relative to
/// it), and the removal can land during either; a single error label could
/// not tell them apart, so both are now separate steps and both are covered
/// here. The errno comes from the kernel, not from the open flags (which are
/// valid), and APFS does not document it, so the decision rests on the
/// directory's observed identity rather than on the errno: an `EINVAL` while
/// the same directory is still in place is a genuine invalid argument and is
/// returned unchanged.
#[cfg(unix)]
fn vanished_lock_dir_as_not_found<T>(
    dir: &Dir,
    seen: LockDirSeen<'_>,
    r: std::io::Result<T>,
) -> std::io::Result<T> {
    match r {
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput && lock_dir_replaced(dir, seen) => {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{e}; the lock directory was removed during the call"),
            ))
        }
        r => r,
    }
}

/// Create the lock directory if absent and open a handle on it, for one setup
/// attempt. Every later step of the attempt works relative to this handle.
#[cfg(unix)]
fn open_lock_dir(dir: &Dir) -> Result<Dir, (std::io::ErrorKind, PodError)> {
    lock_step("create the lock directory", dir.create_dir_all(LOCK_DIR))?;
    let seen = lock_step("inspect the lock directory", dir.symlink_metadata(LOCK_DIR))?;
    lock_step(
        "open the lock directory",
        vanished_lock_dir_as_not_found(
            dir,
            LockDirSeen::Snapshot(dir_identity(&seen)),
            dir.open_dir(LOCK_DIR),
        ),
    )
}

/// Open (creating if absent) the lock file `name` in the lock directory,
/// recreating the directory and retrying when it vanishes underneath the open.
/// `open` performs the open relative to the lock directory's handle; it is a
/// parameter so tests can inject the failures the race produces.
#[cfg(unix)]
fn open_lock_file(
    dir: &Dir,
    name: &str,
    mut open: impl FnMut(&Dir, &str) -> std::io::Result<cap_std::fs::File>,
) -> Result<std::fs::File, PodError> {
    let mut last = PodError::Backend("could not open the lock file".into());
    for attempt in 0..LOCK_SETUP_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(lock_setup_backoff(attempt - 1));
        }
        let opened = open_lock_dir(dir).and_then(|lock_dir| {
            lock_step(
                "open the lock file",
                vanished_lock_dir_as_not_found(
                    dir,
                    LockDirSeen::Held(&lock_dir),
                    open(&lock_dir, name),
                ),
            )
        });
        match opened {
            Ok(f) => return Ok(f.into_std()),
            // `NotFound` after `create_dir_all` and `O_CREAT` is a creation
            // race or a removed directory (see `load_or_create_lock_key` and
            // `vanished_lock_dir_as_not_found`); the next attempt recreates it.
            Err((std::io::ErrorKind::NotFound, e)) => last = e,
            Err((_, e)) => return Err(e),
        }
    }
    Err(last)
}

/// Read the stripe key, creating it if absent. The candidate is written to a
/// private temporary file (mode 0600) and installed with a hard link, which
/// fails if the key already exists, so exactly one creator wins and every
/// other process reads the winner's key.
///
/// Every step is retried when it reports `NotFound`. The lock directory and
/// the key are created concurrently by every first user, and a creator can be
/// told that an entry is absent after another creator has made it (or that the
/// directory it just created is not yet visible to its next call): the rules
/// for concurrent `mkdir`, `open(O_CREAT)` and `link` differ between Linux and
/// macOS, so correctness must not depend on a `NotFound` meaning "really
/// absent". A step that fails because the directory was removed underneath it
/// is retried too, whatever errno the platform reports for that (see
/// [`vanished_lock_dir_as_not_found`]). A retry redoes the whole attempt from
/// `create_dir_all`, so a genuinely missing directory is recreated rather than
/// looped on, and an attempt never leaves its temporary file behind.
#[cfg(unix)]
fn load_or_create_lock_key(dir: &Dir) -> Result<[u8; 32], PodError> {
    let mut last = PodError::Backend("could not settle on a lock key".into());
    for attempt in 0..LOCK_SETUP_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(lock_setup_backoff(attempt - 1));
        }
        match try_load_or_create_lock_key(dir) {
            Ok(key) => return Ok(key),
            Err((std::io::ErrorKind::NotFound | std::io::ErrorKind::AlreadyExists, e)) => last = e,
            Err((_, e)) => return Err(e),
        }
    }
    Err(last)
}

/// One attempt at [`load_or_create_lock_key`]. The error carries the
/// `io::ErrorKind` that decides whether the caller retries.
#[cfg(unix)]
fn try_load_or_create_lock_key(dir: &Dir) -> Result<[u8; 32], (std::io::ErrorKind, PodError)> {
    use cap_std::fs::OpenOptionsExt;
    let lock_dir = open_lock_dir(dir)?;
    match vanished_lock_dir_as_not_found(
        dir,
        LockDirSeen::Held(&lock_dir),
        lock_dir.read(LOCK_KEY_FILE),
    ) {
        Ok(bytes) => {
            return <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                (
                    std::io::ErrorKind::InvalidData,
                    PodError::Backend(format!(
                        "the lock key file {LOCK_DIR}/{LOCK_KEY_FILE} holds {} bytes, expected 32; \
                         refusing to replace it (that would split the stripes between processes)",
                        bytes.len()
                    )),
                )
            });
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return lock_step("read the lock key", Err(e)),
    }
    let mut candidate = [0u8; 32];
    getrandom::getrandom(&mut candidate).map_err(|e| {
        (
            std::io::ErrorKind::Other,
            PodError::Backend(format!("no system randomness for the lock key: {e}")),
        )
    })?;
    let tmp = format!("{LOCK_KEY_FILE}.tmp-{}", uuid::Uuid::new_v4());
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = lock_step(
        "create the key candidate",
        vanished_lock_dir_as_not_found(
            dir,
            LockDirSeen::Held(&lock_dir),
            lock_dir.open_with(&tmp, &options),
        ),
    )?;
    let written = file.write_all(&candidate).and_then(|()| file.sync_all());
    drop(file);
    let linked = match written {
        Ok(()) => vanished_lock_dir_as_not_found(
            dir,
            LockDirSeen::Held(&lock_dir),
            lock_dir.hard_link(&tmp, &lock_dir, LOCK_KEY_FILE),
        ),
        Err(e) => Err(e),
    };
    // The candidate is private to this attempt: removing it cannot disturb a
    // concurrent creator, and its absence is not an error.
    let _ = lock_dir.remove_file(&tmp);
    match linked {
        Ok(()) => Ok(candidate),
        // Another process installed its key first: the next attempt reads it.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err((
            std::io::ErrorKind::AlreadyExists,
            PodError::Backend("lock key installed concurrently".into()),
        )),
        Err(e) => lock_step("install the lock key", Err(e)),
    }
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
        let dir = self.dir.clone();
        let file = tokio::task::spawn_blocking(move || {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create(true);
            open_lock_file(&dir, &name, |lock_dir, name| {
                lock_dir.open_with(name, &options)
            })
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

    /// The error macOS returns when the lock directory is removed between
    /// cap-std opening it and creating the lock file inside it.
    #[cfg(unix)]
    fn einval() -> std::io::Error {
        std::io::Error::from(rustix::io::Errno::INVAL)
    }

    #[cfg(unix)]
    fn open_root(dir: &TempDir) -> Dir {
        Dir::open_ambient_dir(dir.path(), ambient_authority()).unwrap()
    }

    #[cfg(unix)]
    fn create_lock_file(lock_dir: &Dir, name: &str) -> std::io::Result<cap_std::fs::File> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        lock_dir.open_with(name, &options)
    }

    #[cfg(unix)]
    #[test]
    fn lock_file_open_retries_einval_when_the_directory_was_removed() {
        let tmp = TempDir::new().unwrap();
        let root = open_root(&tmp);
        let locks = tmp.path().join(LOCK_DIR);
        let mut calls = 0;
        let file = open_lock_file(&root, "00.lock", |lock_dir, name| {
            calls += 1;
            if calls == 1 {
                std::fs::remove_dir_all(&locks).unwrap();
                return Err(einval());
            }
            create_lock_file(lock_dir, name)
        });
        assert!(file.is_ok(), "{file:?}");
        assert_eq!(calls, 2);
        assert!(locks.join("00.lock").is_file());
    }

    #[cfg(unix)]
    #[test]
    fn lock_file_open_retries_einval_when_the_directory_was_replaced() {
        let tmp = TempDir::new().unwrap();
        let root = open_root(&tmp);
        let locks = tmp.path().join(LOCK_DIR);
        let mut calls = 0;
        let file = open_lock_file(&root, "00.lock", |lock_dir, name| {
            calls += 1;
            if calls == 1 {
                // Another directory now stands at the path: the open used the
                // removed one, so this is the race, not a bad argument.
                std::fs::remove_dir_all(&locks).unwrap();
                std::fs::create_dir(&locks).unwrap();
                return Err(einval());
            }
            create_lock_file(lock_dir, name)
        });
        assert!(file.is_ok(), "{file:?}");
        assert_eq!(calls, 2);
    }

    #[cfg(unix)]
    #[test]
    fn lock_file_open_surfaces_einval_while_the_directory_is_intact() {
        let tmp = TempDir::new().unwrap();
        let root = open_root(&tmp);
        let mut calls = 0;
        let err = open_lock_file(&root, "00.lock", |_, _| {
            calls += 1;
            Err(einval())
        })
        .unwrap_err();
        assert_eq!(calls, 1, "a genuine EINVAL must not be retried");
        let msg = err.to_string();
        assert!(matches!(err, PodError::Backend(_)), "{err:?}");
        assert!(
            msg.contains("open the lock file: Invalid argument"),
            "{msg}"
        );
        assert!(!msg.contains("removed"), "{msg}");
    }

    #[cfg(unix)]
    #[test]
    fn lock_file_open_retries_not_found() {
        let tmp = TempDir::new().unwrap();
        let root = open_root(&tmp);
        let mut calls = 0;
        let file = open_lock_file(&root, "00.lock", |lock_dir, name| {
            calls += 1;
            if calls < 3 {
                return Err(std::io::ErrorKind::NotFound.into());
            }
            create_lock_file(lock_dir, name)
        });
        assert!(file.is_ok(), "{file:?}");
        assert_eq!(calls, 3);
    }

    #[cfg(unix)]
    #[test]
    fn lock_file_open_gives_up_after_the_bounded_attempts() {
        let tmp = TempDir::new().unwrap();
        let root = open_root(&tmp);
        let mut calls = 0;
        let err = open_lock_file(&root, "00.lock", |_, _| {
            calls += 1;
            Err(std::io::ErrorKind::NotFound.into())
        })
        .unwrap_err();
        assert_eq!(calls, LOCK_SETUP_ATTEMPTS);
        assert!(err.to_string().contains("open the lock file"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn vanished_lock_dir_rewrites_only_einval() {
        let tmp = TempDir::new().unwrap();
        let root = open_root(&tmp);
        root.create_dir_all(LOCK_DIR).unwrap();
        let held = root.open_dir(LOCK_DIR).unwrap();
        // Intact: EINVAL passes through unchanged.
        let r: std::io::Result<()> =
            vanished_lock_dir_as_not_found(&root, LockDirSeen::Held(&held), Err(einval()));
        assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
        std::fs::remove_dir(tmp.path().join(LOCK_DIR)).unwrap();
        // Removed: EINVAL becomes NotFound; other errors pass through.
        let r: std::io::Result<()> =
            vanished_lock_dir_as_not_found(&root, LockDirSeen::Held(&held), Err(einval()));
        assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::NotFound);
        let r: std::io::Result<()> = vanished_lock_dir_as_not_found(
            &root,
            LockDirSeen::Held(&held),
            Err(std::io::ErrorKind::PermissionDenied.into()),
        );
        assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[cfg(unix)]
    #[test]
    fn vanished_lock_dir_snapshot_detects_removal_and_replacement() {
        let tmp = TempDir::new().unwrap();
        let root = open_root(&tmp);
        root.create_dir_all(LOCK_DIR).unwrap();
        // Hold the original open so its inode number cannot be reused by the
        // recreated directory below, which would make the test meaningless.
        let original = root.open_dir(LOCK_DIR).unwrap();
        let seen = LockDirSeen::Snapshot(dir_identity(&original.dir_metadata().unwrap()));
        let check = |r| vanished_lock_dir_as_not_found::<()>(&root, seen, r);
        // Unchanged: EINVAL passes through.
        assert_eq!(
            check(Err(einval())).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        // Removed: EINVAL becomes NotFound.
        std::fs::remove_dir(tmp.path().join(LOCK_DIR)).unwrap();
        assert_eq!(
            check(Err(einval())).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        // Replaced by a fresh directory: still the race, still NotFound.
        root.create_dir(LOCK_DIR).unwrap();
        assert_eq!(
            check(Err(einval())).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        drop(original);
    }

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
