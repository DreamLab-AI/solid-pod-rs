//! File-backed invite store behind the `invite` CLI.
//!
//! JSS keeps invite codes in `<data root>/.server/invites.json`
//! (`src/idp/invites.js` `loadInvites` / `saveInvites`) and exposes
//! `invite create`, `invite list` and `invite revoke <code>`
//! (`bin/jss.js` 457-540). The Rust CLI previously minted tokens into a
//! throwaway in-memory store, so nothing survived the process; this store
//! gives `create`, `list` and `revoke` one shared, durable home.
//!
//! The file keeps the JSS field names where a counterpart exists
//! (`created`, `maxUses`, `uses`, `note`) and adds `expiresAt`. Tokens are
//! case-sensitive here (43-character base64url), so unlike JSS `revoke`
//! does not upper-case its argument. The file is written with mode 0600 via
//! a temp file and an atomic rename, because the tokens are bearer secrets.
//! Concurrent writers from separate processes are not serialised.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use solid_pod_rs_idp::{Invite, InviteStore, InviteStoreError};
use tokio::sync::Mutex;

const DIR: &str = ".server";
const FILE: &str = "invites.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    created: DateTime<Utc>,
    max_uses: Option<u32>,
    #[serde(default)]
    uses: u32,
    #[serde(default)]
    note: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<DateTime<Utc>>,
}

/// One row of `invite list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteRow {
    /// The invite token.
    pub token: String,
    /// Redemption cap (`None` = unlimited).
    pub max_uses: Option<u32>,
    /// Redemptions so far.
    pub uses: u32,
    /// Creation time.
    pub created: DateTime<Utc>,
    /// Optional expiry.
    pub expires_at: Option<DateTime<Utc>>,
}

/// Invite store persisted at `<root>/.server/invites.json`.
pub struct FileInviteStore {
    path: PathBuf,
    lock: Mutex<()>,
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

    async fn load(&self) -> Result<BTreeMap<String, Record>, InviteStoreError> {
        match tokio::fs::read(&self.path).await {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| InviteStoreError::Backend(format!("{}: {e}", self.path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(e) => Err(InviteStoreError::Backend(format!(
                "{}: {e}",
                self.path.display()
            ))),
        }
    }

    async fn save(&self, map: &BTreeMap<String, Record>) -> Result<(), InviteStoreError> {
        let backend =
            |e: std::io::Error| InviteStoreError::Backend(format!("{}: {e}", self.path.display()));
        let dir = self.path.parent().expect("invites path has a parent");
        tokio::fs::create_dir_all(dir).await.map_err(backend)?;
        let body =
            serde_json::to_vec_pretty(map).map_err(|e| InviteStoreError::Backend(e.to_string()))?;
        let tmp = dir.join(format!(".{FILE}.{}.tmp", std::process::id()));
        let path = self.path.clone();
        let tmp2 = tmp.clone();
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            use std::io::Write as _;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                opts.mode(0o600);
            }
            opts.open(&tmp2)?.write_all(&body)?;
            std::fs::rename(&tmp2, &path)
        })
        .await
        .map_err(|e| InviteStoreError::Backend(e.to_string()))?
        .map_err(backend)
    }

    /// Every stored invite, oldest first.
    pub async fn list(&self) -> Result<Vec<InviteRow>, InviteStoreError> {
        let _g = self.lock.lock().await;
        let mut rows: Vec<InviteRow> = self
            .load()
            .await?
            .into_iter()
            .map(|(token, r)| InviteRow {
                token,
                max_uses: r.max_uses,
                uses: r.uses,
                created: r.created,
                expires_at: r.expires_at,
            })
            .collect();
        rows.sort_by(|a, b| a.created.cmp(&b.created).then(a.token.cmp(&b.token)));
        Ok(rows)
    }

    /// Delete an invite. `Ok(true)` if it existed (JSS `revokeInvite`).
    pub async fn revoke(&self, token: &str) -> Result<bool, InviteStoreError> {
        let _g = self.lock.lock().await;
        let mut map = self.load().await?;
        if map.remove(token).is_none() {
            return Ok(false);
        }
        self.save(&map).await?;
        Ok(true)
    }
}

#[async_trait]
impl InviteStore for FileInviteStore {
    async fn insert(&self, invite: Invite) -> Result<(), InviteStoreError> {
        let _g = self.lock.lock().await;
        let mut map = self.load().await?;
        // Idempotent on the token, as the trait requires.
        if map.contains_key(&invite.token) {
            return Ok(());
        }
        map.insert(
            invite.token,
            Record {
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
        Ok(self.load().await?.get(token).map(|r| Invite {
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
        assert_eq!(rows[0].token, "tok-b");
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
}
