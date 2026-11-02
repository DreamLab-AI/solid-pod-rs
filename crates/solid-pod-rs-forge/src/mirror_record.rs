//! The mirror record and its store, kept outside the `mirror` feature.
//!
//! [`MirrorStore::load`] is the one reader of
//! `plugin_dir/mirror/<owner>/<name>.json`: the mirror engine uses it, and so
//! does boot migration ([`crate::migrate`]), which runs without the feature.
//! Both must reach the same verdict (missing, unreadable or valid) on the same
//! bytes, so there is one parser. The public path of every item here is
//! `crate::mirror`, which re-exports them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ownership::valid_name_segment;

pub(crate) fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A followed repository name: starts alphanumeric, then `[A-Za-z0-9._-]`,
/// at most 100 bytes, and safe as a single path segment.
pub(crate) fn is_repo_name(s: &str) -> bool {
    let first_ok = s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric());
    first_ok && valid_name_segment(s)
}

/// The mark a state carries: the latest on-chain anchor of the repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorMark {
    /// Chain name from the `chain` tag (for example `txbt4`).
    pub chain: String,
    /// TXO URI from the `txo` tag.
    pub txo: String,
    /// The marked commit (40 lowercase hex) from the `commit` tag.
    pub commit: String,
}

/// What the mirror did with the latest state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SeenAction {
    /// Nothing to do (or nothing possible); see the reason.
    Skip,
    /// The fetch failed.
    FetchFailed,
    /// At least one branch moved.
    Moved,
    /// Fetched, but no branch passed its verdict.
    Held,
}

/// The latest state seen for a repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastSeen {
    /// Event id.
    pub id: String,
    /// Event `created_at` (seconds).
    #[serde(rename = "created_at")]
    pub created_at: u64,
    /// Millisecond clock when the event was handled.
    pub at: u64,
    /// What happened.
    pub action: SeenAction,
    /// Why, in words.
    pub reason: String,
}

/// A reference to the last state acted on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRef {
    /// Event id.
    pub id: String,
    /// Event `created_at` (seconds).
    #[serde(rename = "created_at")]
    pub created_at: u64,
}

/// One branch's outcome in the last fetch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchOutcome {
    /// The sha the state named.
    pub sha: String,
    /// Whether the branch moved.
    pub moved: bool,
    /// Why, in words.
    pub verdict: String,
}

/// The last fetch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastFetch {
    /// Millisecond clock of the fetch.
    pub at: u64,
    /// The clone URL used.
    pub clone: String,
    /// Per-branch outcomes, keyed by ref.
    pub branches: BTreeMap<String, BranchOutcome>,
    /// How many branches moved.
    pub moved: usize,
    /// The mark the state carried, if any.
    pub mark: Option<MirrorMark>,
}

/// The durable record of one mirrored repository. Serialised to
/// `<plugin_dir>/mirror/<pubkey>/<name>.json` in camelCase, the shape the
/// JSS forge serves at `api/repos/<owner>/<name>/mirror`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MirrorRecord {
    /// Agent key.
    pub pubkey: String,
    /// Repository name.
    pub name: String,
    /// Clone URL from the newest kind-30617 (or the configured one).
    pub clone: Option<String>,
    /// States counted for this repository.
    pub events: u64,
    /// The latest state seen.
    pub last_seen: Option<LastSeen>,
    /// The last state acted on (advances only after a fetch).
    pub last_event: Option<EventRef>,
    /// Millisecond clock of the last fetch attempt.
    pub last_fetch_at: Option<u64>,
    /// The last completed fetch.
    pub last_fetch: Option<LastFetch>,
    /// `created_at` of the newest kind-30617 used for the clone URL.
    pub announce_at: Option<u64>,
    /// Every clone URL the newest kind-30617 offered.
    #[serde(default)]
    pub clones: Vec<String>,
    /// `created_at` of the newest verified state seen, acted on or not. A
    /// state older than this is a replay and is dropped; one equal to it is
    /// the catch-up resend of a state that was rate-limited, and is kept.
    #[serde(default)]
    pub newest_seen_at: u64,
    /// Event id of the state that set [`Self::newest_seen_at`]. Two states with
    /// the same `created_at` are ordered by id (NIP-01: the lowest id wins), so
    /// a sibling that loses the tie-break is dropped.
    #[serde(default)]
    pub newest_seen_id: String,
    /// Consecutive failed applies: a store that could not be examined, or a
    /// failed materialise, fetch or publication.
    /// The floor between fetches doubles for each, up to [`MAX_BACKOFF_MS`](crate::mirror::MAX_BACKOFF_MS),
    /// and only a completed apply resets it.
    #[serde(default)]
    pub failures: u32,
    /// Millisecond clock at which the latest state is worth applying again:
    /// set when the rate limit held it back, or when examining its store, or
    /// its materialise, fetch or publication, failed in a way that may pass
    /// on a retry (never sooner
    /// than [`backoff_delay`](crate::mirror::backoff_delay) of [`Self::failures`] after the failure).
    /// Unset when nothing is waiting, or when the refusal will not pass on a
    /// retry: a fetch past the size cap, a refused clone URL or address, a
    /// terminal [`PublishError`](crate::mirror::PublishError), or [`MAX_TIMEOUTS`](crate::mirror::MAX_TIMEOUTS) timeouts of the state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_at: Option<u64>,
    /// Whether this record was first written under publication isolation.
    /// A record without it predates this release, so its served store may
    /// hold content the old shared layout fetched but never approved.
    #[serde(default)]
    pub isolated: bool,
    /// Whether the served store was found in the pre-isolation layout and
    /// waits for migration. Persisted so the store is examined once, not on
    /// every event.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub awaits_migration: bool,
    /// Timeouts of the newest state seen, in its fetch, its publication or
    /// the examination of its store, and failed DNS lookups of its clone
    /// host; at [`MAX_TIMEOUTS`](crate::mirror::MAX_TIMEOUTS) the state is no longer retried. Reset only
    /// when a newer state arrives or an apply completes, not by another
    /// kind of failure in between (security I5). Counted only once a record
    /// is saved; see [`MAX_TIMEOUTS`](crate::mirror::MAX_TIMEOUTS).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub timeouts: u32,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if signature
fn is_zero(n: &u32) -> bool {
    *n == 0
}

impl MirrorRecord {
    #[cfg_attr(
        not(feature = "mirror"),
        expect(
            dead_code,
            reason = "the mirror engine's; migration only loads records"
        )
    )]
    pub(crate) fn new(pubkey: &str, name: &str, clone: Option<String>) -> Self {
        Self {
            pubkey: pubkey.to_string(),
            name: name.to_string(),
            clone,
            events: 0,
            last_seen: None,
            last_event: None,
            last_fetch_at: None,
            last_fetch: None,
            announce_at: None,
            clones: Vec::new(),
            newest_seen_at: 0,
            newest_seen_id: String::new(),
            failures: 0,
            retry_at: None,
            isolated: true,
            awaits_migration: false,
            timeouts: 0,
        }
    }
}

/// Reads and writes [`MirrorRecord`] files under a directory.
#[derive(Debug, Clone)]
pub struct MirrorStore {
    dir: PathBuf,
}

/// What [`MirrorStore::load`] found at a record path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredRecord {
    /// No record file: the repository is not (yet) a mirror.
    Missing,
    /// A record file exists but cannot be read or parsed. The repository is
    /// still a mirror: readers refuse it, and the engine leaves the file in
    /// place and treats the store as awaiting migration. The reason names
    /// no path.
    Unreadable(String),
    /// A valid record.
    Valid(Box<MirrorRecord>),
}

impl MirrorStore {
    /// A store rooted at `plugin_dir/mirror`.
    #[must_use]
    pub fn new(plugin_dir: impl AsRef<Path>) -> Self {
        Self {
            dir: plugin_dir.as_ref().join("mirror"),
        }
    }

    /// `plugin_dir/mirror/<owner>/<name>.json`, for a 64-hex owner and a
    /// followed repository name.
    pub(crate) fn file(&self, owner: &str, name: &str) -> Option<PathBuf> {
        if !is_hex64(owner) || !is_repo_name(name) {
            return None;
        }
        Some(self.dir.join(owner).join(format!("{name}.json")))
    }

    /// `plugin_dir/mirror-work/locks/<owner>/<name>.lock`, the cross-process
    /// advisory lock for one repository (design §3). Only a 64-hex owner and a
    /// followed repository name have one here; the path itself is
    /// [`crate::migrate::lock_path`], which boot migration shares.
    #[cfg_attr(
        not(feature = "mirror"),
        expect(
            dead_code,
            reason = "the mirror engine's; migration only loads records"
        )
    )]
    pub(crate) fn lock_file(&self, owner: &str, name: &str) -> Option<PathBuf> {
        if !is_hex64(owner) || !is_repo_name(name) {
            return None;
        }
        crate::migrate::lock_path(self.dir.parent()?, owner, name)
    }

    /// The record for `(owner, name)` when it is present and valid; `None`
    /// when it is missing *or* cannot be read or parsed. Use [`Self::load`]
    /// to tell those apart: an unreadable record still marks a mirror.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "mirror")] {
    /// use solid_pod_rs_forge::mirror::MirrorStore;
    ///
    /// let dir = tempfile::tempdir().unwrap();
    /// let store = MirrorStore::new(dir.path());
    /// assert!(store.read(&"a".repeat(64), "nobody").is_none());
    /// # }
    /// ```
    #[must_use]
    #[cfg_attr(
        not(feature = "mirror"),
        expect(
            dead_code,
            reason = "the mirror engine's; migration only loads records"
        )
    )]
    pub fn read(&self, owner: &str, name: &str) -> Option<MirrorRecord> {
        match self.load(owner, name) {
            StoredRecord::Valid(rec) => Some(*rec),
            StoredRecord::Missing | StoredRecord::Unreadable(_) => None,
        }
    }

    /// The record for `(owner, name)`, telling a missing file from one that
    /// exists but cannot be read or parsed. An owner or name that is not a
    /// safe record key (a 64-hex owner, a valid repository name) has no
    /// record path, so no record can exist for it: [`StoredRecord::Missing`],
    /// as the reader gate's own path check also finds. Otherwise `Missing`
    /// means no directory entry exists; a symlink at the path, dangling or
    /// not, is [`StoredRecord::Unreadable`].
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "mirror")] {
    /// use solid_pod_rs_forge::mirror::{MirrorStore, StoredRecord};
    ///
    /// let dir = tempfile::tempdir().unwrap();
    /// let store = MirrorStore::new(dir.path());
    /// let owner = "a".repeat(64);
    /// assert!(matches!(store.load(&owner, "x"), StoredRecord::Missing));
    /// assert!(matches!(store.load("alice", "x"), StoredRecord::Missing));
    /// std::fs::create_dir_all(dir.path().join("mirror").join(&owner)).unwrap();
    /// std::fs::write(dir.path().join("mirror").join(&owner).join("x.json"), b"{").unwrap();
    /// assert!(matches!(store.load(&owner, "x"), StoredRecord::Unreadable(_)));
    /// # }
    /// ```
    #[must_use]
    pub fn load(&self, owner: &str, name: &str) -> StoredRecord {
        let Some(path) = self.file(owner, name) else {
            return StoredRecord::Missing;
        };
        // Missing only when no directory entry exists. An entry that is a
        // symlink, dangling or not, is not a record this store wrote.
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_symlink() => {
                return StoredRecord::Unreadable("is a symbolic link".into());
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return StoredRecord::Missing,
            Err(e) => return StoredRecord::Unreadable(format!("cannot be read: {}", e.kind())),
        }
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            // The entry existed a moment ago: not "no record".
            Err(e) => return StoredRecord::Unreadable(format!("cannot be read: {}", e.kind())),
        };
        match serde_json::from_slice(&bytes) {
            Ok(rec) => StoredRecord::Valid(Box::new(rec)),
            Err(e) => StoredRecord::Unreadable(format!("is not a valid record: {e}")),
        }
    }

    /// Save a record atomically (write a temporary file, then rename).
    ///
    /// # Errors
    ///
    /// An I/O error, or `InvalidInput` when the owner or name is unsafe as
    /// a path segment.
    #[cfg_attr(
        not(feature = "mirror"),
        expect(
            dead_code,
            reason = "the mirror engine's; migration only loads records"
        )
    )]
    pub fn save(&self, rec: &MirrorRecord) -> std::io::Result<()> {
        let path = self.file(&rec.pubkey, &rec.name).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "unsafe mirror key")
        })?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(rec)?)?;
        std::fs::rename(tmp, path)
    }
}
