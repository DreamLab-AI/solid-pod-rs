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
///
/// A lock is an exclusive `flock` on a file in here, so if the directory were
/// deleted and recreated while a lock is held, a contender would lock a new
/// file at the same path and both would proceed. To prevent that, every holder
/// also holds a shared `flock` on the data root itself (which cannot be removed
/// while the data is in use), and the directory and its key are only ever
/// created under an exclusive `flock` on the data root, which waits until no
/// lock is held by any process. Deleting the directory while locks are held
/// therefore makes contenders wait (and time out with
/// [`PodError::Conflict`]) until the holders release, after which the next
/// contender recreates it. After acquiring, a holder checks that its locked
/// file is still the one at the path, and starts over if it is not. Stripe
/// files themselves are created without the exclusive lock (they are created
/// lazily, and a holder may take a state lock while holding a resource lock),
/// so deleting an individual lock file, rather than the directory, while it is
/// held is not guarded against. The guard covers only what this crate creates:
/// a directory put back from outside (say, restored from a backup with its key)
/// while a lock is held is not. Nothing in this crate removes any of these
/// files.
///
/// The root lock needs `flock` on a read-only directory descriptor, which local
/// filesystems on Linux and macOS provide. Where the exclusive form is
/// unavailable (Linux NFS emulates `flock` with POSIX locks, which refuse an
/// exclusive lock on a read-only descriptor), creating the lock directory is
/// expected to fail with `lock setup: lock the data root: …` rather than
/// proceed unguarded, so the first lock on such a data root fails.
const LOCK_DIR: &str = ".solid-pod-locks";

/// Lock files: a key maps to one of this many files by HMAC-SHA-256 under a
/// per-data-root random key ([`LOCK_KEY_FILE`]), so every process on
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

/// Every filesystem call in lock setup. Each runs through [`lock_dir_step`],
/// which names it in errors and decides whether its failure is the lock
/// directory vanishing (retried) or a real error (returned).
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LockStep {
    /// `mkdir` of [`LOCK_DIR`] (and the root, if absent) under the data root.
    CreateDir,
    /// `stat` of [`LOCK_DIR`], recording its identity before it is opened.
    InspectDir,
    /// `openat` of [`LOCK_DIR`], giving the attempt its directory handle.
    OpenDir,
    /// Read of the stripe key file.
    ReadKey,
    /// `openat(O_CREAT | O_EXCL)` of the key candidate.
    CreateCandidate,
    /// Write and `fsync` of the key candidate.
    WriteCandidate,
    /// `linkat` of the candidate to the key file name.
    InstallKey,
    /// `openat(O_CREAT)` of a stripe or state lock file.
    OpenFile,
    /// `openat` of the data root, giving the attempt its own descriptor to
    /// `flock` (see [`lock_data_root`]).
    OpenRoot,
    /// `flock` of that descriptor: shared to hold a lock, exclusive to repair.
    LockRoot,
    /// `flock` of the stripe or state lock file.
    LockFile,
    /// `fstat` of the locked file and `stat` of its path, to check that the
    /// lock is on the file every contender opens.
    VerifyFile,
}

#[cfg(unix)]
impl LockStep {
    /// The step's name in `lock setup: {name}: {error}` messages.
    fn label(self) -> &'static str {
        match self {
            Self::CreateDir => "create the lock directory",
            Self::InspectDir => "inspect the lock directory",
            Self::OpenDir => "open the lock directory",
            Self::ReadKey => "read the lock key",
            Self::CreateCandidate => "create the key candidate",
            Self::WriteCandidate => "write the key candidate",
            Self::InstallKey => "install the lock key",
            Self::OpenFile => "open the lock file",
            Self::OpenRoot => "open the data root",
            Self::LockRoot => "lock the data root",
            Self::LockFile => "lock the lock file",
            Self::VerifyFile => "verify the lock file",
        }
    }
}

/// Fault injection for lock setup: called before each step, and an error it
/// returns stands in for the step's own result. Production passes
/// [`no_lock_faults`]; tests use it to reproduce the macOS race on any
/// platform.
#[cfg(unix)]
type LockFaults<'a> = &'a mut dyn FnMut(LockStep) -> Option<std::io::Error>;

/// The production [`LockFaults`]: never injects anything.
#[cfg(unix)]
fn no_lock_faults(_: LockStep) -> Option<std::io::Error> {
    None
}

/// The lock directory a setup step worked in, as far as the caller knows it.
#[cfg(unix)]
#[derive(Clone, Copy)]
enum LockDirSeen<'a> {
    /// Nothing yet (the step creates or inspects it): only the path being
    /// absent afterwards counts as the directory vanishing.
    Unknown,
    /// Only the `(dev, ino)` observed at [`LOCK_DIR`] before the step, which
    /// was the one opening the directory. A reused inode number can only make
    /// a replaced directory look unchanged, which surfaces the error: it can
    /// never hide a genuine one.
    Snapshot((u64, u64)),
    /// A handle on it: the step ran relative to this directory. The handle
    /// keeps its inode alive, so a recreated directory cannot reuse its number.
    Held(&'a Dir),
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
        LockDirSeen::Unknown => false,
        LockDirSeen::Snapshot(was) => was != now,
        LockDirSeen::Held(held) => held
            .dir_metadata()
            .is_ok_and(|was| dir_identity(&was) != now),
    }
}

/// Report an `InvalidInput` (`EINVAL`) from a step in the lock directory as
/// `NotFound` when the directory was removed or replaced during the step, so
/// the setup loops retry it like any other vanished entry.
///
/// macOS can fail calls in `.solid-pod-locks` with `EINVAL` rather than
/// `ENOENT` when the directory is removed during them. It has been seen from
/// the lock-file create, the key-candidate create and the key `linkat`; cap-std
/// resolves each of those with two `openat`-relative calls (the directory, then
/// the entry), and the removal can land during either. The errno comes from
/// the kernel, not from the open flags (which are valid), and APFS does not
/// document it, so the decision rests on the directory's observed identity
/// rather than on the errno: an `EINVAL` while the same directory is still in
/// place is a genuine invalid argument and is returned unchanged.
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

/// Run one lock-setup step: consult `faults`, run `op` if nothing was
/// injected, treat an `EINVAL` caused by the lock directory vanishing as
/// `NotFound` (see [`vanished_lock_dir_as_not_found`]), and label the error.
/// Every filesystem call in lock setup goes through here.
#[cfg(unix)]
fn lock_dir_step<T>(
    dir: &Dir,
    seen: LockDirSeen<'_>,
    step: LockStep,
    faults: LockFaults<'_>,
    op: impl FnOnce() -> std::io::Result<T>,
) -> Result<T, (std::io::ErrorKind, PodError)> {
    let r = match faults(step) {
        Some(e) => Err(e),
        None => op(),
    };
    lock_step(step.label(), vanished_lock_dir_as_not_found(dir, seen, r))
}

/// Create the lock directory if absent and open a handle on it, for one setup
/// attempt. Every later step of the attempt works relative to this handle.
#[cfg(unix)]
fn open_lock_dir(dir: &Dir, faults: LockFaults<'_>) -> Result<Dir, (std::io::ErrorKind, PodError)> {
    use LockDirSeen::{Snapshot, Unknown};
    lock_dir_step(dir, Unknown, LockStep::CreateDir, faults, || {
        dir.create_dir_all(LOCK_DIR)
    })?;
    let seen = lock_dir_step(dir, Unknown, LockStep::InspectDir, faults, || {
        dir.symlink_metadata(LOCK_DIR)
    })?;
    let seen = Snapshot(dir_identity(&seen));
    lock_dir_step(dir, seen, LockStep::OpenDir, faults, || {
        dir.open_dir(LOCK_DIR)
    })
}

/// A held cross-process lock: the stripe's `flock`, and the shared `flock` on
/// the data root that keeps the lock directory from being recreated while it
/// is held (see [`LOCK_DIR`]). Fields drop in order, so the stripe is released
/// before the root.
#[cfg(unix)]
#[derive(Debug)]
struct HeldLock {
    _stripe: std::fs::File,
    _anchor: std::fs::File,
}

/// What one acquisition attempt found.
#[cfg(unix)]
enum Attempt {
    /// The lock is held and verified.
    Held(HeldLock),
    /// Another holder has the stripe, or the data root is being repaired.
    Busy,
    /// The lock directory or its key is missing; the error says which.
    Repair(PodError),
}

/// The `(dev, ino)` of an open file.
#[cfg(unix)]
fn file_identity(m: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (m.dev(), m.ino())
}

/// Parse the stripe key file's contents. A file of the wrong length is an
/// error, never regenerated: replacing it would put two processes on different
/// stripes and silently end their mutual exclusion.
#[cfg(unix)]
fn parse_lock_key(bytes: &[u8]) -> Result<[u8; 32], (std::io::ErrorKind, PodError)> {
    <[u8; 32]>::try_from(bytes).map_err(|_| {
        (
            std::io::ErrorKind::InvalidData,
            PodError::Backend(format!(
                "the lock key file {LOCK_DIR}/{LOCK_KEY_FILE} holds {} bytes, expected 32; \
                 refusing to replace it (that would split the stripes between processes)",
                bytes.len()
            )),
        )
    })
}

/// The lock file name of `key` under the data root's stripe key.
#[cfg(unix)]
fn lock_file_name(stripe_key: &[u8; 32], key: &str) -> Result<String, PodError> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(stripe_key)
        .map_err(|e| PodError::Backend(format!("lock key: {e}")))?;
    mac.update(key.as_bytes());
    let digest = mac.finalize().into_bytes();
    Ok(if key.starts_with(STATE_KEY_PREFIX) {
        format!("state-{}.lock", hex::encode(&digest[..4]))
    } else {
        format!("{:02x}.lock", usize::from(digest[0]) % LOCK_STRIPES)
    })
}

/// Run one lock step on the data root itself: like [`lock_dir_step`], but an
/// `EINVAL` is never read as the lock directory vanishing, since the step does
/// not touch it.
#[cfg(unix)]
fn root_step<T>(
    step: LockStep,
    faults: LockFaults<'_>,
    op: impl FnOnce() -> std::io::Result<T>,
) -> Result<T, (std::io::ErrorKind, PodError)> {
    lock_step(step.label(), faults(step).map_or_else(op, Err))
}

/// Open a new descriptor on the data root and `flock` it without waiting:
/// shared for a holder, exclusive for a repair. Each call must have its own
/// open file description (never `dir` itself or a `dup` of it): `flock` on a
/// shared description converts the lock instead of conflicting with it.
/// `Ok(None)` is "held the other way by someone else".
#[cfg(unix)]
fn lock_data_root(
    dir: &Dir,
    exclusive: bool,
    faults: LockFaults<'_>,
) -> Result<Option<std::fs::File>, (std::io::ErrorKind, PodError)> {
    use rustix::fs::{flock, FlockOperation};
    // A plain read-only open: `Dir::open_dir` gives an `O_PATH` descriptor on
    // Linux, which `flock` rejects with `EBADF`.
    let anchor = root_step(LockStep::OpenRoot, faults, || {
        dir.open(".").map(cap_std::fs::File::into_std)
    })?;
    let op = if exclusive {
        FlockOperation::NonBlockingLockExclusive
    } else {
        FlockOperation::NonBlockingLockShared
    };
    match root_step(LockStep::LockRoot, faults, || {
        flock(&anchor, op).map_err(std::io::Error::from)
    }) {
        Ok(()) => Ok(Some(anchor)),
        Err((std::io::ErrorKind::WouldBlock, _)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// One attempt to take the lock on `key`. It creates nothing but the stripe
/// file: a missing lock directory or key is reported as [`Attempt::Repair`],
/// because those may only be created under the exclusive root lock (see
/// [`repair_lock_dir`]). A `NotFound` error means the directory vanished
/// during the attempt, or the lock turned out to be on a file no longer at
/// its path; the caller retries.
#[cfg(unix)]
fn attempt_lock(
    dir: &Dir,
    key: &str,
    faults: LockFaults<'_>,
) -> Result<Attempt, (std::io::ErrorKind, PodError)> {
    use rustix::fs::{flock, FlockOperation};
    use std::io::ErrorKind::{NotFound, WouldBlock};
    use LockDirSeen::{Held, Snapshot, Unknown};
    // Look (for the directory and its key) before taking the root lock, so
    // that once either is gone newcomers stop taking (and briefly holding) the
    // shared lock, and only real holders stand between the repair and its
    // exclusive lock.
    let seen = match lock_dir_step(dir, Unknown, LockStep::InspectDir, faults, || {
        let found = dir.symlink_metadata(LOCK_DIR)?;
        dir.symlink_metadata(Path::new(LOCK_DIR).join(LOCK_KEY_FILE))?;
        Ok(found)
    }) {
        Ok(m) => Snapshot(dir_identity(&m)),
        Err((NotFound, e)) => return Ok(Attempt::Repair(e)),
        Err(e) => return Err(e),
    };
    let Some(anchor) = lock_data_root(dir, false, faults)? else {
        return Ok(Attempt::Busy);
    };
    let lock_dir = match lock_dir_step(dir, seen, LockStep::OpenDir, faults, || {
        dir.open_dir(LOCK_DIR)
    }) {
        Ok(d) => d,
        Err((NotFound, e)) => return Ok(Attempt::Repair(e)),
        Err(e) => return Err(e),
    };
    let held = Held(&lock_dir);
    let stripe_key = match lock_dir_step(dir, held, LockStep::ReadKey, faults, || {
        lock_dir.read(LOCK_KEY_FILE)
    }) {
        Ok(bytes) => parse_lock_key(&bytes)?,
        Err((NotFound, e)) => return Ok(Attempt::Repair(e)),
        Err(e) => return Err(e),
    };
    let name = lock_file_name(&stripe_key, key).map_err(|e| (std::io::ErrorKind::Other, e))?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    let stripe = lock_dir_step(dir, held, LockStep::OpenFile, faults, || {
        lock_dir.open_with(&name, &options)
    })?
    .into_std();
    match lock_dir_step(dir, held, LockStep::LockFile, faults, || {
        flock(&stripe, FlockOperation::NonBlockingLockExclusive).map_err(std::io::Error::from)
    }) {
        Ok(()) => {}
        Err((WouldBlock, _)) => return Ok(Attempt::Busy),
        Err(e) => return Err(e),
    }
    // The flock is on the file we opened; make sure that file is still the one
    // every other contender will open. It may have been unlinked (alone or
    // with its directory) between the open and the flock, in which case a
    // contender would create a new file at the path and lock that.
    let verified = lock_dir_step(dir, held, LockStep::VerifyFile, faults, || {
        use std::os::unix::fs::MetadataExt;
        let ours = stripe.metadata()?;
        let at_path = lock_dir.symlink_metadata(&name)?;
        let dir_now = dir.symlink_metadata(LOCK_DIR)?;
        Ok(ours.nlink() > 0
            && file_identity(&ours) == dir_identity(&at_path)
            && dir_identity(&lock_dir.dir_metadata()?) == dir_identity(&dir_now))
    })?;
    if !verified {
        return Err((
            NotFound,
            PodError::Backend(format!(
                "lock setup: {}: the lock file was replaced while it was being locked",
                LockStep::VerifyFile.label()
            )),
        ));
    }
    Ok(Attempt::Held(HeldLock {
        _stripe: stripe,
        _anchor: anchor,
    }))
}

/// Create the lock directory and its key, holding the data root's exclusive
/// lock, which is granted only while no lock is held on the data root by any
/// process. `Ok(false)` is "a lock is held": the caller treats it as busy.
///
/// This is what keeps a deleted lock directory from ending mutual exclusion:
/// a holder whose lock file was unlinked with the directory still holds its
/// shared root lock, so no contender can recreate the directory (or the key)
/// and lock a new file at the same path until that holder releases.
#[cfg(unix)]
fn repair_lock_dir(dir: &Dir, faults: LockFaults<'_>) -> Result<bool, PodError> {
    let Some(_anchor) = lock_data_root(dir, true, faults).map_err(|(_, e)| e)? else {
        return Ok(false);
    };
    load_or_create_lock_key(dir, faults)?;
    Ok(true)
}

/// Take the lock on `key` without waiting for another holder: `Ok(None)` when
/// it is held elsewhere (the caller polls). Repairs a missing lock directory
/// or key, and retries a directory that vanishes mid-attempt or a lock that
/// lands on a replaced file, a bounded number of times with backoff.
#[cfg(unix)]
fn try_lock(dir: &Dir, key: &str, faults: LockFaults<'_>) -> Result<Option<HeldLock>, PodError> {
    let mut last = PodError::Backend("could not open the lock file".into());
    for attempt in 0..LOCK_SETUP_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(lock_setup_backoff(attempt - 1));
        }
        match attempt_lock(dir, key, faults) {
            Ok(Attempt::Held(held)) => return Ok(Some(held)),
            Ok(Attempt::Busy) => return Ok(None),
            Ok(Attempt::Repair(e)) => {
                if !repair_lock_dir(dir, faults)? {
                    return Ok(None);
                }
                last = e;
            }
            // `NotFound` after the directory was seen is the directory
            // vanishing during the attempt (see `vanished_lock_dir_as_not_found`)
            // or a lock on a replaced file; the next attempt starts over.
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
fn load_or_create_lock_key(dir: &Dir, faults: LockFaults<'_>) -> Result<[u8; 32], PodError> {
    let mut last = PodError::Backend("could not settle on a lock key".into());
    for attempt in 0..LOCK_SETUP_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(lock_setup_backoff(attempt - 1));
        }
        match try_load_or_create_lock_key(dir, faults) {
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
fn try_load_or_create_lock_key(
    dir: &Dir,
    faults: LockFaults<'_>,
) -> Result<[u8; 32], (std::io::ErrorKind, PodError)> {
    use cap_std::fs::OpenOptionsExt;
    let lock_dir = open_lock_dir(dir, faults)?;
    let seen = LockDirSeen::Held(&lock_dir);
    match lock_dir_step(dir, seen, LockStep::ReadKey, faults, || {
        lock_dir.read(LOCK_KEY_FILE)
    }) {
        Ok(bytes) => return parse_lock_key(&bytes),
        Err((std::io::ErrorKind::NotFound, _)) => {}
        Err(e) => return Err(e),
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
    let mut file = lock_dir_step(dir, seen, LockStep::CreateCandidate, faults, || {
        lock_dir.open_with(&tmp, &options)
    })?;
    let linked = lock_dir_step(dir, seen, LockStep::WriteCandidate, faults, || {
        file.write_all(&candidate).and_then(|()| file.sync_all())
    })
    .and_then(|()| {
        drop(file);
        lock_dir_step(dir, seen, LockStep::InstallKey, faults, || {
            lock_dir.hard_link(&tmp, &lock_dir, LOCK_KEY_FILE)
        })
    });
    // The candidate is private to this attempt: removing it cannot disturb a
    // concurrent creator, and its absence is not an error.
    let _ = lock_dir.remove_file(&tmp);
    match linked {
        Ok(()) => Ok(candidate),
        // Another process installed its key first: the next attempt reads it.
        Err((std::io::ErrorKind::AlreadyExists, _)) => Err((
            std::io::ErrorKind::AlreadyExists,
            PodError::Backend("lock key installed concurrently".into()),
        )),
        Err(e) => Err(e),
    }
}

/// Filesystem-rooted `Storage` implementation.
#[derive(Clone)]
pub struct FsBackend {
    root: Arc<PathBuf>,
    dir: Arc<Dir>,
    operations: Arc<RwLock<()>>,
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
        })
    }

    /// Return the root directory.
    pub fn root(&self) -> &Path {
        &self.root
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

    /// Takes an advisory `flock` on the key's stripe file in
    /// `.solid-pod-locks`, together with a shared `flock` on the data root.
    /// Deleting `.solid-pod-locks` (or its key) while a lock is held does not
    /// end the exclusion: the directory and key are only ever recreated under
    /// an exclusive lock on the data root, so a contender gets
    /// [`PodError::Conflict`] until every holder has released. The stripe key
    /// is read under the shared lock on every acquisition, so every process
    /// agrees on the stripe even after the directory was recreated.
    #[cfg(unix)]
    async fn lock_exclusive(
        &self,
        key: &str,
        wait: std::time::Duration,
    ) -> Result<Option<crate::storage::StorageLock>, PodError> {
        let deadline = std::time::Instant::now() + wait;
        loop {
            let dir = self.dir.clone();
            let lock_key = key.to_string();
            let held =
                tokio::task::spawn_blocking(move || try_lock(&dir, &lock_key, &mut no_lock_faults))
                    .await
                    .map_err(|e| PodError::Backend(format!("lock task failed: {e}")))??;
            if let Some(held) = held {
                return Ok(Some(crate::storage::StorageLock::new(held)));
            }
            if std::time::Instant::now() >= deadline {
                return Err(PodError::Conflict(format!(
                    "the resource is being written by another process: {key}"
                )));
            }
            tokio::time::sleep(LOCK_POLL).await;
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

    /// The error macOS returns when the lock directory is removed during a
    /// call in it.
    #[cfg(unix)]
    fn einval() -> std::io::Error {
        std::io::Error::from(rustix::io::Errno::INVAL)
    }

    #[cfg(unix)]
    fn open_root(dir: &TempDir) -> Dir {
        Dir::open_ambient_dir(dir.path(), ambient_authority()).unwrap()
    }

    /// The steps the stripe-key path runs on a fresh data root, in order.
    #[cfg(unix)]
    const KEY_STEPS: [LockStep; 7] = [
        LockStep::CreateDir,
        LockStep::InspectDir,
        LockStep::OpenDir,
        LockStep::ReadKey,
        LockStep::CreateCandidate,
        LockStep::WriteCandidate,
        LockStep::InstallKey,
    ];

    /// The steps an acquisition runs on a data root whose lock directory and
    /// key exist, in order.
    #[cfg(unix)]
    const FILE_STEPS: [LockStep; 8] = [
        LockStep::InspectDir,
        LockStep::OpenRoot,
        LockStep::LockRoot,
        LockStep::OpenDir,
        LockStep::ReadKey,
        LockStep::OpenFile,
        LockStep::LockFile,
        LockStep::VerifyFile,
    ];

    /// Steps on the data root rather than in the lock directory: an `EINVAL`
    /// from them is never retried.
    #[cfg(unix)]
    fn on_root(step: LockStep) -> bool {
        matches!(step, LockStep::OpenRoot | LockStep::LockRoot)
    }

    /// A data root whose lock directory and key already exist, as after first
    /// use.
    #[cfg(unix)]
    fn set_up_root(dir: &TempDir) -> Dir {
        let root = open_root(dir);
        load_or_create_lock_key(&root, &mut no_lock_faults).unwrap();
        root
    }

    /// Every (path, step) pair: `true` is the stripe-key path.
    #[cfg(unix)]
    fn all_steps() -> impl Iterator<Item = (bool, LockStep)> {
        let key = KEY_STEPS.into_iter().map(|s| (true, s));
        key.chain(FILE_STEPS.into_iter().map(|s| (false, s)))
    }

    /// How the injected `EINVAL` relates to the lock directory.
    #[cfg(unix)]
    #[derive(Clone, Copy, Debug)]
    enum Race {
        /// The directory is removed, then the step fails.
        Removed,
        /// The directory is removed and recreated, then the step fails.
        Replaced,
        /// The step fails while the directory is untouched.
        Intact,
    }

    /// Run one setup path on a root, failing the first run of `step` with
    /// `EINVAL` after applying `race` to the lock directory: `key` selects
    /// stripe-key creation on a fresh root, otherwise an acquisition on a root
    /// set up by [`set_up_root`]. Returns the outcome and how many times `step`
    /// ran (an acquisition that repairs the directory runs some steps again
    /// inside the repair).
    #[cfg(unix)]
    fn run_with_einval(key: bool, step: LockStep, race: Race) -> (Result<(), PodError>, u32) {
        let tmp = TempDir::new().unwrap();
        let root = if key {
            open_root(&tmp)
        } else {
            set_up_root(&tmp)
        };
        let locks = tmp.path().join(LOCK_DIR);
        let mut runs = 0;
        let mut faults = |s: LockStep| {
            if s != step {
                return None;
            }
            runs += 1;
            if runs > 1 {
                return None;
            }
            match race {
                Race::Removed => {
                    let _ = std::fs::remove_dir_all(&locks);
                }
                Race::Replaced => {
                    let _ = std::fs::remove_dir_all(&locks);
                    std::fs::create_dir(&locks).unwrap();
                }
                Race::Intact => {}
            }
            Some(einval())
        };
        let r = if key {
            load_or_create_lock_key(&root, &mut faults).map(drop)
        } else {
            try_lock(&root, "/doc", &mut faults)
                .map(|held| assert!(held.is_some(), "nothing else holds a lock"))
        };
        (r, runs)
    }

    #[cfg(unix)]
    #[test]
    fn every_lock_setup_step_retries_einval_when_the_directory_was_removed() {
        for (key, step) in all_steps().filter(|(_, s)| !on_root(*s)) {
            let (r, runs) = run_with_einval(key, step, Race::Removed);
            assert!(r.is_ok(), "{step:?} (key path: {key}): {r:?}");
            if key {
                assert_eq!(runs, 2, "{step:?} (key path) must be retried once");
            } else {
                assert!(runs >= 2, "{step:?} (lock path) must be retried");
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn steps_holding_the_directory_retry_einval_when_it_was_replaced() {
        // Steps after `OpenDir` compare against the held handle, whose inode
        // stays allocated, so replacement is detected on every filesystem.
        // The snapshot taken for `OpenDir` is covered by
        // `vanished_lock_dir_snapshot_detects_removal_and_replacement`, which
        // pins the original inode so the comparison is meaningful.
        let held = all_steps().filter(|(_, s)| {
            !matches!(
                s,
                LockStep::CreateDir | LockStep::InspectDir | LockStep::OpenDir
            )
        });
        for (key, step) in held.filter(|(_, s)| !on_root(*s)) {
            let (r, runs) = run_with_einval(key, step, Race::Replaced);
            assert!(r.is_ok(), "{step:?} (key path: {key}): {r:?}");
            if key {
                assert_eq!(runs, 2, "{step:?} (key path) must be retried once");
            } else {
                assert!(runs >= 2, "{step:?} (lock path) must be retried");
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn every_lock_setup_step_surfaces_einval_while_the_directory_is_intact() {
        // `CreateDir` runs before the directory exists, so an injected failure
        // there leaves it absent, which is indistinguishable from vanishing.
        for (key, step) in all_steps().filter(|(_, s)| *s != LockStep::CreateDir) {
            let (r, runs) = run_with_einval(key, step, Race::Intact);
            assert_eq!(
                runs, 1,
                "{step:?} (key path: {key}): a genuine EINVAL must not be retried"
            );
            let err = r.unwrap_err();
            let msg = err.to_string();
            assert!(matches!(err, PodError::Backend(_)), "{err:?}");
            let want = format!("lock setup: {}: Invalid argument", step.label());
            assert!(msg.contains(&want), "{step:?}: {msg}");
            assert!(!msg.contains("removed"), "{step:?}: {msg}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn lock_setup_retries_not_found_and_gives_up_after_the_bounded_attempts() {
        let tmp = TempDir::new().unwrap();
        let root = set_up_root(&tmp);
        let mut runs = 0;
        let r = try_lock(&root, "/doc", &mut |s| {
            (s == LockStep::OpenFile).then(|| {
                runs += 1;
                std::io::ErrorKind::NotFound.into()
            })
        });
        assert_eq!(runs, LOCK_SETUP_ATTEMPTS);
        let err = r.unwrap_err();
        assert!(err.to_string().contains("open the lock file"), "{err}");
    }

    /// How the lock file is disturbed between its open and its `flock`.
    #[cfg(unix)]
    #[derive(Clone, Copy, Debug)]
    enum Unlink {
        /// The whole lock directory is removed.
        Dir,
        /// Only the lock file is removed.
        File,
        /// The lock file is removed and a new one created at its path.
        Replaced,
    }

    /// The lock must end up on the file at the path, never on one unlinked
    /// between the open and the `flock`: otherwise a contender would create a
    /// new file there, lock it, and proceed beside the holder.
    #[cfg(unix)]
    #[test]
    fn a_lock_taken_on_an_unlinked_file_is_retaken_on_the_file_at_the_path() {
        use std::os::unix::fs::MetadataExt;
        for how in [Unlink::Dir, Unlink::File, Unlink::Replaced] {
            let tmp = TempDir::new().unwrap();
            let root = set_up_root(&tmp);
            let locks = tmp.path().join(LOCK_DIR);
            let (mut flocks, mut verified) = (0, 0);
            let held = try_lock(&root, "/doc", &mut |s| {
                match s {
                    LockStep::LockFile => {
                        flocks += 1;
                        if flocks == 1 {
                            let file = std::fs::read_dir(&locks)
                                .unwrap()
                                .flatten()
                                .map(|e| e.path())
                                .find(|p| p.extension().is_some_and(|x| x == "lock"))
                                .unwrap();
                            match how {
                                Unlink::Dir => std::fs::remove_dir_all(&locks).unwrap(),
                                Unlink::File => std::fs::remove_file(&file).unwrap(),
                                Unlink::Replaced => {
                                    std::fs::remove_file(&file).unwrap();
                                    std::fs::write(&file, b"").unwrap();
                                }
                            }
                        }
                    }
                    LockStep::VerifyFile => verified += 1,
                    _ => {}
                }
                None
            })
            .unwrap()
            .expect("nothing else holds a lock");
            assert_eq!(
                flocks, 2,
                "{how:?}: the first lock must be dropped and retaken"
            );
            assert_eq!(verified, 2, "{how:?}");
            let ours = held._stripe.metadata().unwrap();
            let lock_file = std::fs::read_dir(&locks)
                .unwrap()
                .flatten()
                .map(|e| e.path())
                .find(|p| p.extension().is_some_and(|x| x == "lock"))
                .unwrap();
            let at_path = std::fs::metadata(lock_file).unwrap();
            assert!(ours.nlink() > 0, "{how:?}");
            assert_eq!(
                (ours.dev(), ours.ino()),
                (at_path.dev(), at_path.ino()),
                "{how:?}"
            );
        }
    }

    /// While a lock is held, its directory cannot be recreated: removing it
    /// leaves a contender busy (not admitted) until the holder releases.
    #[cfg(unix)]
    #[test]
    fn a_removed_lock_directory_is_not_recreated_while_a_lock_is_held() {
        let tmp = TempDir::new().unwrap();
        let root = set_up_root(&tmp);
        let held = try_lock(&root, "/doc", &mut no_lock_faults)
            .unwrap()
            .unwrap();
        std::fs::remove_dir_all(tmp.path().join(LOCK_DIR)).unwrap();
        // Any key, not only the held one: the directory is shared.
        for key in ["/doc", "/other", "state:payments"] {
            let r = try_lock(&root, key, &mut no_lock_faults).unwrap();
            assert!(r.is_none(), "{key} was admitted while a lock is held");
        }
        assert!(!tmp.path().join(LOCK_DIR).exists());
        drop(held);
        assert!(try_lock(&root, "/doc", &mut no_lock_faults)
            .unwrap()
            .is_some());
        assert!(tmp.path().join(LOCK_DIR).join(LOCK_KEY_FILE).exists());
    }

    #[cfg(unix)]
    #[test]
    fn vanished_lock_dir_rewrites_only_einval() {
        let tmp = TempDir::new().unwrap();
        let root = open_root(&tmp);
        root.create_dir_all(LOCK_DIR).unwrap();
        let held = root.open_dir(LOCK_DIR).unwrap();
        let check = |seen, r| vanished_lock_dir_as_not_found::<()>(&root, seen, r);
        // Intact: EINVAL passes through unchanged.
        let r = check(LockDirSeen::Held(&held), Err(einval()));
        assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
        let r = check(LockDirSeen::Unknown, Err(einval()));
        assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
        std::fs::remove_dir(tmp.path().join(LOCK_DIR)).unwrap();
        // Removed: EINVAL becomes NotFound; other errors pass through.
        let r = check(LockDirSeen::Held(&held), Err(einval()));
        assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::NotFound);
        let r = check(LockDirSeen::Unknown, Err(einval()));
        assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::NotFound);
        let denied = Err(std::io::ErrorKind::PermissionDenied.into());
        let r = check(LockDirSeen::Held(&held), denied);
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
        let r = check(Err(einval()));
        assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
        // Removed: EINVAL becomes NotFound.
        std::fs::remove_dir(tmp.path().join(LOCK_DIR)).unwrap();
        let r = check(Err(einval()));
        assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::NotFound);
        // Replaced by a fresh directory: still the race, still NotFound.
        root.create_dir(LOCK_DIR).unwrap();
        let r = check(Err(einval()));
        assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::NotFound);
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
