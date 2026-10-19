//! File-backed invite store behind the `invite` CLI.
//!
//! JSS keeps invite codes in `<data root>/.server/invites.json`
//! (`src/idp/invites.js` `loadInvites` / `saveInvites`) and exposes
//! `invite create`, `invite list` and `invite revoke <code>`
//! (`bin/jss.js` 457-540). The Rust CLI previously minted tokens into a
//! throwaway in-memory store, so nothing survived the process; this store
//! gives `create`, `list`, `revoke` and `consume` one shared, durable home.
//!
//! The file keeps the JSS field names where a counterpart exists
//! (`created`, `maxUses`, `uses`, `note`) and adds `expiresAt`. Tokens are
//! case-sensitive here (43-character base64url), so unlike JSS `revoke`
//! does not upper-case its argument.
//!
//! # Hardening (security review L7)
//!
//! * **Hashed at rest.** Records are keyed by the SHA-256 hex of the token
//!   and carry it as `tokenSha256`; the token itself is never written, so a
//!   leaked `invites.json` redeems nothing. `invite create` prints the token
//!   once. Files written by the earlier plaintext layout (records without
//!   `tokenSha256`) are migrated in place on the next write.
//! * **`max_uses` is enforced.** [`FileInviteStore::consume`] is the one
//!   operation a redemption path must call: it checks expiry and the use cap
//!   and increments `uses` atomically.
//! * **Serialised across processes.** Every read-modify-write holds an
//!   in-process mutex and an exclusive lock file (`invites.json.lock`,
//!   `create_new`, stale locks older than 30 s are broken), so a server write
//!   cannot resurrect an invite a CLI process just revoked.
//! * The file is written with mode 0600 via a uniquely named temp file and an
//!   atomic rename.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solid_pod_rs_idp::{Invite, InviteStore, InviteStoreError};
use tokio::sync::Mutex;

const DIR: &str = ".server";
const FILE: &str = "invites.json";
const LOCK: &str = "invites.json.lock";
/// A lock file older than this belongs to a dead process and is broken.
const STALE_LOCK: Duration = Duration::from_secs(30);
/// How long a writer waits for the lock before giving up.
const LOCK_WAIT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    /// SHA-256 hex of the token. Absent only in the legacy plaintext layout,
    /// where the map key is the token itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token_sha256: Option<String>,
    created: DateTime<Utc>,
    max_uses: Option<u32>,
    #[serde(default)]
    uses: u32,
    #[serde(default)]
    note: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<DateTime<Utc>>,
}

/// SHA-256 hex digest of an invite token: the at-rest key.
fn digest(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Re-key legacy plaintext records by their digest (in memory; the file is
/// rewritten by the next mutation).
fn migrate(map: BTreeMap<String, Record>) -> BTreeMap<String, Record> {
    map.into_iter()
        .map(|(k, mut r)| match r.token_sha256.clone() {
            Some(h) => (h, r),
            None => {
                let h = digest(&k);
                r.token_sha256 = Some(h.clone());
                (h, r)
            }
        })
        .collect()
}

/// One row of `invite list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteRow {
    /// Short identifier (first 12 hex characters of the token's SHA-256).
    /// The token itself is not stored, so it cannot be listed.
    pub id: String,
    /// Redemption cap (`None` = unlimited).
    pub max_uses: Option<u32>,
    /// Redemptions so far.
    pub uses: u32,
    /// Creation time.
    pub created: DateTime<Utc>,
    /// Optional expiry.
    pub expires_at: Option<DateTime<Utc>>,
}

/// Outcome of [`FileInviteStore::consume`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consume {
    /// The invite was valid; one use has been recorded.
    Granted,
    /// No such invite (or it was revoked).
    Unknown,
    /// Past its expiry.
    Expired,
    /// `max_uses` redemptions already recorded.
    Exhausted,
}

/// Invite store persisted at `<root>/.server/invites.json`.
pub struct FileInviteStore {
    path: PathBuf,
    lock: Mutex<()>,
}

/// Exclusive cross-process lock held for one read-modify-write; the lock file
/// is removed on drop.
struct FileLock {
    path: PathBuf,
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl FileInviteStore {
    /// Store rooted at the pod data directory `root`.
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            path: root.as_ref().join(DIR).join(FILE),
            lock: Mutex::new(()),
        }
    }

    /// Location of the backing file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn backend(&self, e: impl std::fmt::Display) -> InviteStoreError {
        InviteStoreError::Backend(format!("{}: {e}", self.path.display()))
    }

    /// Take the exclusive lock file, breaking one left by a dead process.
    async fn lock_file(&self) -> Result<FileLock, InviteStoreError> {
        let dir = self.path.parent().expect("invites path has a parent");
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|e| self.backend(e))?;
        let path = dir.join(LOCK);
        let started = std::time::Instant::now();
        loop {
            match tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .await
            {
                Ok(_) => return Ok(FileLock { path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let stale = tokio::fs::metadata(&path)
                        .await
                        .ok()
                        .and_then(|m| m.modified().ok())
                        .and_then(|t| t.elapsed().ok())
                        .is_some_and(|age| age > STALE_LOCK);
                    if stale {
                        let _ = tokio::fs::remove_file(&path).await;
                        continue;
                    }
                    if started.elapsed() > LOCK_WAIT {
                        return Err(self.backend("timed out waiting for the invite store lock"));
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Err(e) => return Err(self.backend(e)),
            }
        }
    }

    async fn load(&self) -> Result<BTreeMap<String, Record>, InviteStoreError> {
        match tokio::fs::read(&self.path).await {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(migrate)
                .map_err(|e| self.backend(e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(e) => Err(self.backend(e)),
        }
    }

    async fn save(&self, map: &BTreeMap<String, Record>) -> Result<(), InviteStoreError> {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = self.path.parent().expect("invites path has a parent");
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|e| self.backend(e))?;
        let body =
            serde_json::to_vec_pretty(map).map_err(|e| InviteStoreError::Backend(e.to_string()))?;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let tmp = dir.join(format!(
            ".{FILE}.{}.{}.{nanos}.tmp",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let path = self.path.clone();
        let tmp2 = tmp.clone();
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            use std::io::Write as _;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                opts.mode(0o600);
            }
            let r = opts
                .open(&tmp2)
                .and_then(|mut f| f.write_all(&body))
                .and_then(|()| std::fs::rename(&tmp2, &path));
            if r.is_err() {
                let _ = std::fs::remove_file(&tmp2);
            }
            r
        })
        .await
        .map_err(|e| InviteStoreError::Backend(e.to_string()))?
        .map_err(|e| self.backend(e))
    }

    /// Every stored invite, oldest first.
    pub async fn list(&self) -> Result<Vec<InviteRow>, InviteStoreError> {
        let _g = self.lock.lock().await;
        let mut rows: Vec<InviteRow> = self
            .load()
            .await?
            .into_iter()
            .map(|(hash, r)| InviteRow {
                id: hash.chars().take(12).collect(),
                max_uses: r.max_uses,
                uses: r.uses,
                created: r.created,
                expires_at: r.expires_at,
            })
            .collect();
        rows.sort_by(|a, b| a.created.cmp(&b.created).then(a.id.cmp(&b.id)));
        Ok(rows)
    }

    /// Delete an invite. `Ok(true)` if it existed (JSS `revokeInvite`).
    pub async fn revoke(&self, token: &str) -> Result<bool, InviteStoreError> {
        let _g = self.lock.lock().await;
        let _f = self.lock_file().await?;
        let mut map = self.load().await?;
        if map.remove(&digest(token)).is_none() {
            return Ok(false);
        }
        self.save(&map).await?;
        Ok(true)
    }

    /// Redeem one use of `token`: checks expiry and the `max_uses` cap and
    /// records the use, all under the store lock, so two concurrent
    /// redemptions of a single-use invite cannot both succeed. A redemption
    /// path must call this and proceed only on [`Consume::Granted`].
    pub async fn consume(&self, token: &str) -> Result<Consume, InviteStoreError> {
        let _g = self.lock.lock().await;
        let _f = self.lock_file().await?;
        let mut map = self.load().await?;
        let Some(rec) = map.get_mut(&digest(token)) else {
            return Ok(Consume::Unknown);
        };
        if rec.expires_at.is_some_and(|t| t <= Utc::now()) {
            return Ok(Consume::Expired);
        }
        if rec.max_uses.is_some_and(|m| rec.uses >= m) {
            return Ok(Consume::Exhausted);
        }
        rec.uses += 1;
        self.save(&map).await?;
        Ok(Consume::Granted)
    }
}

#[async_trait]
impl InviteStore for FileInviteStore {
    async fn insert(&self, invite: Invite) -> Result<(), InviteStoreError> {
        let _g = self.lock.lock().await;
        let _f = self.lock_file().await?;
        let mut map = self.load().await?;
        let hash = digest(&invite.token);
        // Idempotent on the token, as the trait requires.
        if map.contains_key(&hash) {
            return Ok(());
        }
        map.insert(
            hash.clone(),
            Record {
                token_sha256: Some(hash),
                created: Utc::now(),
                max_uses: invite.max_uses,
                uses: 0,
                note: String::new(),
                expires_at: invite.expires_at,
            },
        );
        self.save(&map).await
    }

    async fn get(&self, token: &str) -> Result<Option<Invite>, InviteStoreError> {
        let _g = self.lock.lock().await;
        Ok(self.load().await?.get(&digest(token)).map(|r| Invite {
            token: token.to_string(),
            max_uses: r.max_uses,
            expires_at: r.expires_at,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inv(t: &str, uses: Option<u32>) -> Invite {
        Invite {
            token: t.into(),
            max_uses: uses,
            expires_at: None,
        }
    }

    #[tokio::test]
    async fn create_list_revoke_round_trip_across_instances() {
        let dir = tempfile::tempdir().unwrap();
        FileInviteStore::new(dir.path())
            .insert(inv("tok-a", Some(2)))
            .await
            .unwrap();
        // A second instance (a later CLI process) sees the first's write.
        let s = FileInviteStore::new(dir.path());
        s.insert(inv("tok-b", None)).await.unwrap();
        let rows = s.list().await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(s.get("tok-a").await.unwrap().unwrap().max_uses, Some(2));
        assert!(s.revoke("tok-a").await.unwrap());
        assert!(!s.revoke("tok-a").await.unwrap());
        assert!(
            !s.revoke("TOK-B").await.unwrap(),
            "tokens are case-sensitive"
        );
        let rows = s.list().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, digest("tok-b")[..12]);
        assert_eq!(rows[0].max_uses, None);
    }

    #[tokio::test]
    async fn insert_is_idempotent_and_empty_store_lists_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let s = FileInviteStore::new(dir.path());
        assert!(s.list().await.unwrap().is_empty());
        s.insert(inv("t", Some(1))).await.unwrap();
        s.insert(inv("t", Some(9))).await.unwrap();
        assert_eq!(s.get("t").await.unwrap().unwrap().max_uses, Some(1));
    }

    #[tokio::test]
    async fn corrupt_file_is_an_error_not_a_silent_reset() {
        let dir = tempfile::tempdir().unwrap();
        let s = FileInviteStore::new(dir.path());
        std::fs::create_dir_all(dir.path().join(DIR)).unwrap();
        std::fs::write(s.path(), "{not json").unwrap();
        assert!(s.list().await.is_err());
        assert!(s.insert(inv("t", None)).await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let s = FileInviteStore::new(dir.path());
        s.insert(inv("t", None)).await.unwrap();
        let mode = std::fs::metadata(s.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// L7: `max_uses` is enforced by `consume`, and expiry too.
    #[tokio::test]
    async fn consume_enforces_the_use_cap_and_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let s = FileInviteStore::new(dir.path());
        s.insert(inv("once", Some(1))).await.unwrap();
        assert_eq!(s.consume("once").await.unwrap(), Consume::Granted);
        assert_eq!(s.consume("once").await.unwrap(), Consume::Exhausted);
        assert_eq!(s.consume("nope").await.unwrap(), Consume::Unknown);
        assert_eq!(s.list().await.unwrap()[0].uses, 1);
        s.insert(Invite {
            token: "old".into(),
            max_uses: None,
            expires_at: Some(Utc::now() - chrono::Duration::seconds(5)),
        })
        .await
        .unwrap();
        assert_eq!(s.consume("old").await.unwrap(), Consume::Expired);
    }

    /// L7: two stores (two processes) racing for a single-use invite: one wins.
    #[tokio::test]
    async fn concurrent_consumers_cannot_both_redeem_a_single_use_invite() {
        let dir = tempfile::tempdir().unwrap();
        FileInviteStore::new(dir.path())
            .insert(inv("race", Some(1)))
            .await
            .unwrap();
        let root = dir.path().to_path_buf();
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let root = root.clone();
            tasks.push(tokio::spawn(async move {
                FileInviteStore::new(root).consume("race").await.unwrap()
            }));
        }
        let mut granted = 0;
        for t in tasks {
            if t.await.unwrap() == Consume::Granted {
                granted += 1;
            }
        }
        assert_eq!(granted, 1);
    }

    /// L7: the token never reaches disk, and a revoke by one store instance is
    /// not undone by another instance's write.
    #[tokio::test]
    async fn tokens_are_hashed_at_rest() {
        let dir = tempfile::tempdir().unwrap();
        let s = FileInviteStore::new(dir.path());
        s.insert(inv("super-secret-token", None)).await.unwrap();
        let raw = std::fs::read_to_string(s.path()).unwrap();
        assert!(!raw.contains("super-secret-token"), "{raw}");
        assert!(raw.contains(&digest("super-secret-token")));
        assert!(s.get("super-secret-token").await.unwrap().is_some());
        assert!(s.revoke("super-secret-token").await.unwrap());
    }

    /// L7: a file in the old plaintext layout is still honoured and is
    /// rewritten hashed on the next write.
    #[tokio::test]
    async fn legacy_plaintext_file_is_migrated() {
        let dir = tempfile::tempdir().unwrap();
        let s = FileInviteStore::new(dir.path());
        std::fs::create_dir_all(dir.path().join(DIR)).unwrap();
        std::fs::write(
            s.path(),
            r#"{"legacy-token":{"created":"2025-01-01T00:00:00Z","maxUses":2,"uses":1,"note":""}}"#,
        )
        .unwrap();
        assert_eq!(s.consume("legacy-token").await.unwrap(), Consume::Granted);
        assert_eq!(s.consume("legacy-token").await.unwrap(), Consume::Exhausted);
        let raw = std::fs::read_to_string(s.path()).unwrap();
        assert!(!raw.contains("legacy-token"), "{raw}");
    }

    /// L7: a lock file left by a dead process is broken after the stale age.
    #[tokio::test]
    async fn stale_lock_file_is_broken() {
        let dir = tempfile::tempdir().unwrap();
        let s = FileInviteStore::new(dir.path());
        std::fs::create_dir_all(dir.path().join(DIR)).unwrap();
        let lock = dir.path().join(DIR).join(LOCK);
        std::fs::write(&lock, b"").unwrap();
        let old = std::time::SystemTime::now() - Duration::from_secs(120);
        std::fs::File::options()
            .write(true)
            .open(&lock)
            .unwrap()
            .set_modified(old)
            .unwrap();
        s.insert(inv("t", None)).await.unwrap();
        assert!(!lock.exists(), "released after use");
    }
}
