//! File-backed account store behind the `account` CLI (parity row 135).
//!
//! JSS keeps accounts in `<data root>/.idp/accounts/` (`src/idp/accounts.js`
//! `createAccount`, `findByWebId`, `updateLastLogin`, `deleteAccount`). The
//! Rust CLI used to run `account delete` against a throwaway in-memory store,
//! so it could never delete anything. This store gives `account create`,
//! `delete`, `list` and `export` one durable home and implements
//! [`solid_pod_rs_idp::UserStore`], including `find_by_webid` and
//! `update_last_login`, so the IdP can be pointed at the same file.
//!
//! One JSON file, `<root>/.server/accounts.json` (the directory the dotfile
//! guard keeps off HTTP), written with mode 0600 through a uniquely named temp
//! file and an atomic rename, and serialised across processes by an advisory file
//! lock (`flock`, held on a lock file that is never deleted). Passwords are stored only as Argon2id PHC strings
//! ([`solid_pod_rs_idp::hash_password`]); [`FileUserStore::export`] never
//! includes the hash.
//!
//! # Names
//!
//! A new account name is a pod name: it must pass the same check the HTTP
//! registration routes use (`valid_pod_name`: ASCII alphanumerics, `-` and
//! `_`, and none of the names this server serves itself, such as
//! `remotestorage`, `storage`, `api`, `pods`), compared case-insensitively.
//!
//! # Not covered
//!
//! Passkey credentials are not persisted here (the WebAuthn backend keeps them
//! in memory), so a restart forgets them; see PARITY row 135.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use solid_pod_rs_idp::{User, UserStore, UserStoreError};
use tokio::sync::Mutex;

const DIR: &str = ".server";
const FILE: &str = "accounts.json";
const LOCK: &str = "accounts.json.lock";
const LOCK_WAIT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    id: String,
    email: String,
    webid: String,
    username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    password_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nostr_pubkey: Option<String>,
    created: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_login: Option<DateTime<Utc>>,
}

impl Record {
    fn user(&self) -> User {
        User {
            id: self.id.clone(),
            email: self.email.clone(),
            webid: self.webid.clone(),
            name: self.name.clone(),
            password_hash: self.password_hash.clone(),
            username: Some(self.username.clone()),
            nostr_pubkey: self.nostr_pubkey.clone(),
        }
    }
}

/// Why [`FileUserStore::create`] refused.
#[derive(Debug)]
pub enum CreateError {
    /// The name is empty, has a character outside `[A-Za-z0-9_-]`, or is one
    /// this server serves itself.
    BadName(String),
    /// Not `local@domain` without whitespace.
    BadEmail,
    /// The username or the email already belongs to an account.
    Exists,
    /// Password policy or hashing failed.
    Password(UserStoreError),
    /// The file could not be read or written.
    Store(String),
}

impl std::fmt::Display for CreateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadName(n) => write!(f, "invalid or reserved account name {n:?}"),
            Self::BadEmail => f.write_str("invalid email address"),
            Self::Exists => f.write_str("an account with that username or email already exists"),
            Self::Password(e) => write!(f, "{e}"),
            Self::Store(e) => write!(f, "account store: {e}"),
        }
    }
}

impl std::error::Error for CreateError {}

impl From<UserStoreError> for CreateError {
    fn from(e: UserStoreError) -> Self {
        Self::Password(e)
    }
}

/// Account store persisted at `<root>/.server/accounts.json`.
pub struct FileUserStore {
    path: PathBuf,
    lock: Mutex<()>,
}

/// The cross-process lock: an advisory `flock` on a lock file that is never
/// deleted. The kernel releases it when the holder closes the file or dies, so
/// there is no stale lock to detect and nothing to remove (removing a lock
/// file one does not own races with its owner).
struct FileLock {
    _file: std::fs::File,
}

fn email_ok(e: &str) -> bool {
    e.len() <= 254
        && !e.chars().any(|c| c.is_whitespace() || c.is_control())
        && e.split_once('@')
            .is_some_and(|(l, d)| !l.is_empty() && d.contains('.') && !d.contains('@'))
}

impl FileUserStore {
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

    fn backend(&self, e: impl std::fmt::Display) -> UserStoreError {
        UserStoreError::Backend(format!("{}: {e}", self.path.display()))
    }

    async fn lock_file(&self) -> Result<FileLock, UserStoreError> {
        let dir = self.path.parent().expect("accounts path has a parent");
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|e| self.backend(e))?;
        let path = dir.join(LOCK);
        let started = std::time::Instant::now();
        loop {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)
                .map_err(|e| self.backend(e))?;
            match file.try_lock() {
                Ok(()) => return Ok(FileLock { _file: file }),
                Err(std::fs::TryLockError::WouldBlock) => {
                    if started.elapsed() > LOCK_WAIT {
                        return Err(self.backend("timed out waiting for the account store lock"));
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Err(std::fs::TryLockError::Error(e)) => return Err(self.backend(e)),
            }
        }
    }

    /// A missing file is an empty store; an unreadable or corrupt one is an
    /// error, never a silent reset (which would let a later write drop every
    /// account).
    async fn load(&self) -> Result<BTreeMap<String, Record>, UserStoreError> {
        match tokio::fs::read(&self.path).await {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| self.backend(e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(e) => Err(self.backend(e)),
        }
    }

    async fn save(&self, map: &BTreeMap<String, Record>) -> Result<(), UserStoreError> {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = self.path.parent().expect("accounts path has a parent");
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|e| self.backend(e))?;
        let body =
            serde_json::to_vec_pretty(map).map_err(|e| UserStoreError::Backend(e.to_string()))?;
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
        .map_err(|e| UserStoreError::Backend(e.to_string()))?
        .map_err(|e| self.backend(e))
    }

    /// Run `f` over the loaded map under both locks and save when it returns
    /// `Ok(true)`.
    async fn modify<T>(
        &self,
        f: impl FnOnce(&mut BTreeMap<String, Record>) -> Result<(T, bool), CreateError>,
    ) -> Result<T, CreateError> {
        let _g = self.lock.lock().await;
        let _f = self
            .lock_file()
            .await
            .map_err(|e| CreateError::Store(e.to_string()))?;
        let mut map = self
            .load()
            .await
            .map_err(|e| CreateError::Store(e.to_string()))?;
        let (out, changed) = f(&mut map)?;
        if changed {
            self.save(&map)
                .await
                .map_err(|e| CreateError::Store(e.to_string()))?;
        }
        Ok(out)
    }

    /// Create an account for `username` (also its pod name) at `base_url`,
    /// whose WebID is `<base_url>/<username>/profile/card#me`, the one
    /// `POST /api/accounts/new` mints. Does not create the pod.
    ///
    /// # Errors
    ///
    /// [`CreateError`]: a name that fails the pod-name and reserved-name check,
    /// a bad email, a duplicate, a password under the minimum, or a store
    /// failure.
    pub async fn create(
        &self,
        username: &str,
        email: &str,
        password: &str,
        name: Option<&str>,
        base_url: &str,
    ) -> Result<User, CreateError> {
        if !crate::valid_pod_name(username) {
            return Err(CreateError::BadName(username.to_string()));
        }
        if !email_ok(email) {
            return Err(CreateError::BadEmail);
        }
        let hash = solid_pod_rs_idp::hash_password(password)?;
        let mut raw = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut raw);
        let record = Record {
            id: hex::encode(raw),
            email: email.to_ascii_lowercase(),
            webid: format!(
                "{}/{username}/profile/card#me",
                base_url.trim_end_matches('/')
            ),
            username: username.to_string(),
            name: name.map(str::to_string),
            password_hash: hash,
            nostr_pubkey: None,
            created: Utc::now(),
            last_login: None,
        };
        self.modify(|map| {
            if map
                .values()
                .any(|r| r.username.eq_ignore_ascii_case(username) || r.email == record.email)
            {
                return Err(CreateError::Exists);
            }
            let user = record.user();
            map.insert(record.id.clone(), record);
            Ok((user, true))
        })
        .await
    }

    /// Every account, oldest first, without password hashes.
    pub async fn list(&self) -> Result<Vec<serde_json::Value>, UserStoreError> {
        let _g = self.lock.lock().await;
        let mut rows: Vec<Record> = self.load().await?.into_values().collect();
        rows.sort_by_key(|r| r.created);
        Ok(rows.iter().map(export_value).collect())
    }

    /// One account as JSON, without its password hash; `None` when unknown.
    pub async fn export(&self, id: &str) -> Result<Option<serde_json::Value>, UserStoreError> {
        let _g = self.lock.lock().await;
        Ok(self.load().await?.get(id).map(export_value))
    }

    async fn find(&self, pred: impl Fn(&Record) -> bool) -> Result<Option<User>, UserStoreError> {
        let _g = self.lock.lock().await;
        Ok(self
            .load()
            .await?
            .values()
            .find(|r| pred(r))
            .map(Record::user))
    }
}

fn export_value(r: &Record) -> serde_json::Value {
    serde_json::json!({
        "id": r.id,
        "username": r.username,
        "email": r.email,
        "webid": r.webid,
        "name": r.name,
        "nostrPubkey": r.nostr_pubkey,
        "created": r.created,
        "lastLogin": r.last_login,
    })
}

#[async_trait]
impl UserStore for FileUserStore {
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, UserStoreError> {
        let e = email.to_ascii_lowercase();
        self.find(|r| r.email == e).await
    }

    async fn find_by_id(&self, id: &str) -> Result<Option<User>, UserStoreError> {
        self.find(|r| r.id == id).await
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>, UserStoreError> {
        self.find(|r| r.username.eq_ignore_ascii_case(username))
            .await
    }

    async fn find_by_webid(&self, webid: &str) -> Result<Option<User>, UserStoreError> {
        self.find(|r| r.webid == webid).await
    }

    async fn delete(&self, id: &str) -> Result<bool, UserStoreError> {
        self.modify(|map| {
            let gone = map.remove(id).is_some();
            Ok((gone, gone))
        })
        .await
        .map_err(|e| self.backend(e))
    }

    async fn update_password(
        &self,
        id: &str,
        new_password_hash: String,
    ) -> Result<bool, UserStoreError> {
        self.modify(|map| match map.get_mut(id) {
            Some(r) => {
                r.password_hash = new_password_hash;
                Ok((true, true))
            }
            None => Ok((false, false)),
        })
        .await
        .map_err(|e| self.backend(e))
    }

    async fn update_last_login(&self, id: &str) -> Result<bool, UserStoreError> {
        self.modify(|map| match map.get_mut(id) {
            Some(r) => {
                r.last_login = Some(Utc::now());
                Ok((true, true))
            }
            None => Ok((false, false)),
        })
        .await
        .map_err(|e| self.backend(e))
    }

    async fn last_login(&self, id: &str) -> Result<Option<DateTime<Utc>>, UserStoreError> {
        let _g = self.lock.lock().await;
        Ok(self.load().await?.get(id).and_then(|r| r.last_login))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "https://pod.example/";

    async fn make(dir: &Path, user: &str, email: &str) -> User {
        FileUserStore::new(dir)
            .create(user, email, "correct horse", Some("Al"), BASE)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_held_lock_is_never_stolen_or_deleted_however_old_its_file_looks() {
        // Property: the store lock belongs to whoever holds it. A lock file
        // that looks stale (old mtime) but is held by a live process is not
        // removed or taken over, and the lock file is never deleted at all
        // (deleting one you do not own races with its owner).
        let d = tempfile::tempdir().unwrap();
        let store = FileUserStore::new(d.path());
        let dir = d.path().join(DIR);
        std::fs::create_dir_all(&dir).unwrap();
        let lock_path = dir.join(LOCK);
        let held = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .unwrap();
        held.lock().unwrap();
        held.set_modified(std::time::SystemTime::now() - Duration::from_secs(3600))
            .unwrap();
        // Still waiting after 400 ms (not stolen), and the file is still there.
        let waited = tokio::time::timeout(Duration::from_millis(400), store.lock_file()).await;
        assert!(waited.is_err(), "a held lock was taken over");
        assert!(lock_path.exists(), "a held lock file was deleted");
        // Once the holder lets go the lock is granted, and dropping the guard
        // leaves the file in place.
        drop(held);
        let guard = store.lock_file().await.unwrap();
        drop(guard);
        assert!(lock_path.exists(), "the lock file must never be removed");
        // The store still works after all that.
        make(d.path(), "alice", "a@example.com").await;
    }

    #[tokio::test]
    async fn accounts_survive_a_new_instance_and_delete_really_deletes() {
        let d = tempfile::tempdir().unwrap();
        let a = make(d.path(), "alice", "Alice@Example.com").await;
        assert_eq!(a.webid, "https://pod.example/alice/profile/card#me");
        assert_eq!(a.email, "alice@example.com");
        // A different instance (a different process, in effect) sees it.
        let s = FileUserStore::new(d.path());
        assert_eq!(s.find_by_id(&a.id).await.unwrap().unwrap().id, a.id);
        assert!(s
            .find_by_email("ALICE@example.com")
            .await
            .unwrap()
            .is_some());
        assert!(s.find_by_username("ALICE").await.unwrap().is_some());
        assert_eq!(
            s.find_by_webid("https://pod.example/alice/profile/card#me")
                .await
                .unwrap()
                .map(|u| u.id),
            Some(a.id.clone())
        );
        assert!(s
            .find_by_webid("https://pod.example/ALICE/profile/card#me")
            .await
            .unwrap()
            .is_none());
        // Verify the password through the trait.
        assert!(s.verify_password(&a, "correct horse").await.unwrap());
        assert!(!s.verify_password(&a, "wrong horse!").await.unwrap());
        assert!(s.delete(&a.id).await.unwrap());
        assert!(!s.delete(&a.id).await.unwrap());
        assert!(FileUserStore::new(d.path())
            .find_by_id(&a.id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn last_login_and_password_changes_persist() {
        let d = tempfile::tempdir().unwrap();
        let a = make(d.path(), "bob", "bob@example.com").await;
        let s = FileUserStore::new(d.path());
        assert_eq!(s.last_login(&a.id).await.unwrap(), None);
        assert!(s.update_last_login(&a.id).await.unwrap());
        assert!(!s.update_last_login("nobody").await.unwrap());
        let s2 = FileUserStore::new(d.path());
        assert!(s2.last_login(&a.id).await.unwrap().is_some());
        let new_hash = solid_pod_rs_idp::hash_password("another pass").unwrap();
        assert!(s2.update_password(&a.id, new_hash).await.unwrap());
        let u = FileUserStore::new(d.path())
            .find_by_id(&a.id)
            .await
            .unwrap()
            .unwrap();
        assert!(s2.verify_password(&u, "another pass").await.unwrap());
    }

    #[tokio::test]
    async fn names_the_server_serves_itself_cannot_be_registered() {
        let d = tempfile::tempdir().unwrap();
        let s = FileUserStore::new(d.path());
        for bad in [
            "remotestorage",
            "RemoteStorage",
            "storage",
            "api",
            "pods",
            "profile",
            "relay",
            "",
            "a b",
            "a/b",
            "../x",
            "x.y",
        ] {
            let r = s
                .create(bad, "x@example.com", "correct horse", None, BASE)
                .await;
            assert!(matches!(r, Err(CreateError::BadName(_))), "{bad:?}: {r:?}");
        }
        assert!(!s.path().exists(), "a refused name wrote nothing");
    }

    #[tokio::test]
    async fn duplicates_bad_email_and_short_password_are_refused() {
        let d = tempfile::tempdir().unwrap();
        make(d.path(), "carol", "carol@example.com").await;
        let s = FileUserStore::new(d.path());
        assert!(matches!(
            s.create("CAROL", "other@example.com", "correct horse", None, BASE)
                .await,
            Err(CreateError::Exists)
        ));
        assert!(matches!(
            s.create("dave", "Carol@Example.com", "correct horse", None, BASE)
                .await,
            Err(CreateError::Exists)
        ));
        for bad in ["nope", "a@b", "a b@c.d", "@c.d", "a@@c.d"] {
            assert!(
                matches!(
                    s.create("erin", bad, "correct horse", None, BASE).await,
                    Err(CreateError::BadEmail)
                ),
                "{bad}"
            );
        }
        assert!(matches!(
            s.create("erin", "erin@example.com", "short", None, BASE)
                .await,
            Err(CreateError::Password(
                UserStoreError::PasswordTooShort { .. }
            ))
        ));
        assert_eq!(s.list().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn export_and_list_never_carry_the_password_hash() {
        let d = tempfile::tempdir().unwrap();
        let a = make(d.path(), "frank", "frank@example.com").await;
        let s = FileUserStore::new(d.path());
        let v = s.export(&a.id).await.unwrap().unwrap();
        assert_eq!(v["username"], "frank");
        let text = serde_json::to_string(&(v, s.list().await.unwrap())).unwrap();
        assert!(
            !text.contains("argon2") && !text.contains("passwordHash"),
            "{text}"
        );
        assert!(s.export("nobody").await.unwrap().is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = tempfile::tempdir().unwrap();
        make(d.path(), "gina", "gina@example.com").await;
        let mode = std::fs::metadata(FileUserStore::new(d.path()).path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[tokio::test]
    async fn a_corrupt_file_is_an_error_not_a_reset() {
        let d = tempfile::tempdir().unwrap();
        make(d.path(), "hank", "hank@example.com").await;
        let s = FileUserStore::new(d.path());
        std::fs::write(s.path(), b"{ not json").unwrap();
        assert!(s.find_by_id("x").await.is_err());
        assert!(s
            .create("ivy", "ivy@example.com", "correct horse", None, BASE)
            .await
            .is_err());
        assert_eq!(std::fs::read(s.path()).unwrap(), b"{ not json");
    }

    #[tokio::test]
    async fn concurrent_creates_of_one_name_make_one_account() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().to_path_buf();
        let mut tasks = Vec::new();
        for i in 0..6 {
            let root = root.clone();
            tasks.push(tokio::spawn(async move {
                FileUserStore::new(&root)
                    .create(
                        "jules",
                        &format!("j{i}@example.com"),
                        "correct horse",
                        None,
                        BASE,
                    )
                    .await
                    .is_ok()
            }));
        }
        let mut ok = 0;
        for t in tasks {
            ok += usize::from(t.await.unwrap());
        }
        assert_eq!(ok, 1);
        assert_eq!(FileUserStore::new(&root).list().await.unwrap().len(), 1);
    }
}
