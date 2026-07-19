//! Forge-hosted body storage for podless `did:nostr` agents.
//!
//! A nostr agent has no pod, so the "words in pods" rule degrades to
//! "words in the forge": the agent submits the body inline and the forge
//! stores it at `pluginDir/hosted/<hex>/<uuid>.json` with mode `0600`.
//! The corresponding [`ThreadPointer`](crate::spine::issues::ThreadPointer)
//! carries `hosted = true` and a `hosted:<hex>/<uuid>` resource ref that
//! this store resolves at read time.

use std::path::PathBuf;

use async_trait::async_trait;

use crate::bodies::{FetchResult, HostedReader};
use crate::error::ForgeError;
use solid_pod_rs::did_nostr_types::is_valid_hex_pubkey;

/// The `hosted:` ref scheme prefix.
pub const REF_SCHEME: &str = "hosted:";

/// Local body store rooted at `pluginDir/hosted`.
#[derive(Debug, Clone)]
pub struct HostedStore {
    root: PathBuf,
}

impl HostedStore {
    /// Create a store rooted at `<plugin_dir>/hosted`.
    #[must_use]
    pub fn new(plugin_dir: impl Into<PathBuf>) -> Self {
        Self {
            root: plugin_dir.into().join("hosted"),
        }
    }

    /// Validate a uuid token: 1..=64 chars, hex/dash only (matches
    /// `uuid::Uuid` output and forbids traversal).
    fn valid_uuid(id: &str) -> bool {
        !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
    }

    /// Persist `body` for owner `hex`, returning its `hosted:<hex>/<uuid>`
    /// resource ref. The file is written `0600` (owner-only) on Unix.
    pub async fn write(&self, hex: &str, body: &[u8]) -> Result<String, ForgeError> {
        if !is_valid_hex_pubkey(hex) {
            return Err(ForgeError::BadRequest(format!("invalid pubkey: {hex}")));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let dir = self.root.join(hex);
        tokio::fs::create_dir_all(&dir).await?;
        let path = dir.join(format!("{id}.json"));
        crate::spine::atomic_write(&path, body).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await;
        }
        Ok(format!("{REF_SCHEME}{hex}/{id}"))
    }

    /// Read a stored body by `(hex, uuid)`, bounded to `max_bytes`.
    pub async fn read(
        &self,
        hex: &str,
        uuid: &str,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, ForgeError> {
        let Some(path) = self.path_for(hex, uuid) else {
            return Err(ForgeError::PathTraversal(format!("{hex}/{uuid}")));
        };
        match tokio::fs::read(&path).await {
            Ok(bytes) if bytes.len() > max_bytes => {
                Err(ForgeError::BadRequest("body too large".into()))
            }
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(ForgeError::Io(e)),
        }
    }

    /// Delete a stored body. Returns `true` if it existed.
    pub async fn delete(&self, hex: &str, uuid: &str) -> Result<bool, ForgeError> {
        let Some(path) = self.path_for(hex, uuid) else {
            return Err(ForgeError::PathTraversal(format!("{hex}/{uuid}")));
        };
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(ForgeError::Io(e)),
        }
    }

    /// Resolve and validate the on-disk path for `(hex, uuid)`.
    fn path_for(&self, hex: &str, uuid: &str) -> Option<PathBuf> {
        if !is_valid_hex_pubkey(hex) || !Self::valid_uuid(uuid) {
            return None;
        }
        Some(self.root.join(hex).join(format!("{uuid}.json")))
    }

    /// Parse a `hosted:<hex>/<uuid>` ref into its parts.
    #[must_use]
    pub fn parse_ref(resource_ref: &str) -> Option<(String, String)> {
        let rest = resource_ref.strip_prefix(REF_SCHEME)?;
        let (hex, uuid) = rest.split_once('/')?;
        if is_valid_hex_pubkey(hex) && Self::valid_uuid(uuid) {
            Some((hex.to_string(), uuid.to_string()))
        } else {
            None
        }
    }
}

#[async_trait]
impl HostedReader for HostedStore {
    async fn read_hosted(&self, resource_ref: &str, max_bytes: usize) -> FetchResult {
        let Some((hex, uuid)) = Self::parse_ref(resource_ref) else {
            return FetchResult::Error("malformed hosted ref".into());
        };
        match self.read(&hex, &uuid, max_bytes).await {
            Ok(Some(bytes)) => FetchResult::Body(bytes),
            Ok(None) => FetchResult::Removed,
            Err(ForgeError::BadRequest(_)) => FetchResult::TooLarge,
            Err(e) => FetchResult::Error(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn hex() -> String {
        "b".repeat(64)
    }

    #[tokio::test]
    async fn write_read_delete_roundtrip() {
        let td = TempDir::new().unwrap();
        let store = HostedStore::new(td.path());
        let rref = store.write(&hex(), b"hosted body").await.unwrap();
        assert!(rref.starts_with("hosted:"));
        let (h, u) = HostedStore::parse_ref(&rref).unwrap();
        assert_eq!(h, hex());

        let got = store.read(&h, &u, 1024).await.unwrap().unwrap();
        assert_eq!(got, b"hosted body");

        assert!(store.delete(&h, &u).await.unwrap());
        assert!(store.read(&h, &u, 1024).await.unwrap().is_none());
        assert!(!store.delete(&h, &u).await.unwrap());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn written_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let td = TempDir::new().unwrap();
        let store = HostedStore::new(td.path());
        let rref = store.write(&hex(), b"secret").await.unwrap();
        let (h, u) = HostedStore::parse_ref(&rref).unwrap();
        let path = td.path().join("hosted").join(&h).join(format!("{u}.json"));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "hosted body must be owner-only");
    }

    #[tokio::test]
    async fn reader_trait_maps_outcomes() {
        let td = TempDir::new().unwrap();
        let store = HostedStore::new(td.path());
        let rref = store.write(&hex(), b"x").await.unwrap();

        // Present.
        assert!(matches!(
            store.read_hosted(&rref, 1024).await,
            FetchResult::Body(_)
        ));
        // Removed after delete.
        let (h, u) = HostedStore::parse_ref(&rref).unwrap();
        store.delete(&h, &u).await.unwrap();
        assert!(matches!(
            store.read_hosted(&rref, 1024).await,
            FetchResult::Removed
        ));
        // Malformed ref.
        assert!(matches!(
            store.read_hosted("hosted:bad", 1024).await,
            FetchResult::Error(_)
        ));
    }

    #[tokio::test]
    async fn rejects_invalid_pubkey_and_traversal() {
        let td = TempDir::new().unwrap();
        let store = HostedStore::new(td.path());
        assert!(store.write("nothex", b"x").await.is_err());
        assert!(store.read(&hex(), "../escape", 1024).await.is_err());
        assert_eq!(HostedStore::parse_ref("hosted:short/uuid"), None);
    }
}
