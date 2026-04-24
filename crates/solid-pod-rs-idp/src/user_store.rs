//! Pluggable user-storage trait.
//!
//! Port of `JavaScriptSolidServer/src/idp/accounts.js` (the subset
//! the IdP itself reaches into: find-by-email + verify-password).
//! Real persistence is the consumer's responsibility; we ship an
//! in-memory store for tests and single-user dev.

use std::collections::HashMap;

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use async_trait::async_trait;
use parking_lot::RwLock;
use rand::rngs::OsRng;
use thiserror::Error;

/// Errors surfaced by [`UserStore`].
#[derive(Debug, Error)]
pub enum UserStoreError {
    /// Hashing / verification failure.
    #[error("password hash: {0}")]
    Hash(String),

    /// Store-specific back-end failure (DB down, etc).
    #[error("backend: {0}")]
    Backend(String),

    /// The store does not implement this operation. Surfaced by the
    /// default [`UserStore::delete`] so that stores opting out of
    /// Sprint-11 `account delete` still compile.
    #[error("not implemented")]
    NotImplemented,
}

/// User record. `password_hash` is an Argon2id PHC string.
#[derive(Debug, Clone)]
pub struct User {
    /// Stable internal identifier.
    pub id: String,
    /// Primary email (case-normalised before storage).
    pub email: String,
    /// Solid WebID URL — what the access-token `webid` claim surfaces.
    pub webid: String,
    /// Display name (free-form).
    pub name: Option<String>,
    /// Argon2id PHC-encoded password hash.
    pub password_hash: String,
}

/// Async user-store contract.
#[async_trait]
pub trait UserStore: Send + Sync + 'static {
    /// Look up a user by email. Returns `Ok(None)` on no-match
    /// (distinct from `Err(_)` which means the backend failed).
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, UserStoreError>;

    /// Look up a user by internal id.
    async fn find_by_id(&self, id: &str) -> Result<Option<User>, UserStoreError>;

    /// Verify `password` against the user's stored hash. This lives
    /// on the trait rather than free-function so stores that use
    /// external auth (LDAP, OAuth federation) can override the
    /// verification path.
    async fn verify_password(
        &self,
        user: &User,
        password: &str,
    ) -> Result<bool, UserStoreError> {
        let parsed = PasswordHash::new(&user.password_hash)
            .map_err(|e| UserStoreError::Hash(e.to_string()))?;
        let ok = Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
        Ok(ok)
    }

    /// Delete a user and every record they own (pods, WebID profile,
    /// sessions). Mirrors JSS commit `d9e56d8` (#292).
    ///
    /// Default impl returns [`UserStoreError::NotImplemented`] so
    /// existing stores compile unchanged; operators wire this on the
    /// concrete store they ship. Returns `Ok(false)` when the `id` is
    /// unknown (already deleted / never existed), `Ok(true)` when a
    /// row was actually removed.
    async fn delete(&self, _id: &str) -> Result<bool, UserStoreError> {
        Err(UserStoreError::NotImplemented)
    }
}

/// Reference in-memory implementation.
#[derive(Default)]
pub struct InMemoryUserStore {
    inner: RwLock<HashMap<String, User>>,
}

impl InMemoryUserStore {
    /// Construct an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a user with an Argon2id hash of `password`. Returns
    /// the inserted record. Email is case-normalised (lowercased) on
    /// storage so `find_by_email` can match case-insensitively.
    pub fn insert_user(
        &self,
        id: impl Into<String>,
        email: impl Into<String>,
        webid: impl Into<String>,
        name: Option<String>,
        password: &str,
    ) -> Result<User, UserStoreError> {
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| UserStoreError::Hash(e.to_string()))?
            .to_string();
        let user = User {
            id: id.into(),
            email: email.into().to_ascii_lowercase(),
            webid: webid.into(),
            name,
            password_hash: hash,
        };
        self.inner.write().insert(user.email.clone(), user.clone());
        Ok(user)
    }
}

#[async_trait]
impl UserStore for InMemoryUserStore {
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, UserStoreError> {
        Ok(self.inner.read().get(&email.to_ascii_lowercase()).cloned())
    }

    async fn find_by_id(&self, id: &str) -> Result<Option<User>, UserStoreError> {
        Ok(self
            .inner
            .read()
            .values()
            .find(|u| u.id == id)
            .cloned())
    }

    async fn delete(&self, id: &str) -> Result<bool, UserStoreError> {
        let mut guard = self.inner.write();
        // Find the keyed entry whose row matches this id and remove it.
        let email_key = guard
            .iter()
            .find(|(_, u)| u.id == id)
            .map(|(k, _)| k.clone());
        match email_key {
            Some(k) => {
                guard.remove(&k);
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn inmemory_stores_and_verifies() {
        let store = InMemoryUserStore::new();
        let user = store
            .insert_user(
                "u-1",
                "Ada@Example.COM",
                "https://ada.example/profile#me",
                Some("Ada".into()),
                "correct-horse-battery-staple",
            )
            .unwrap();
        assert_eq!(user.email, "ada@example.com");

        let found = store.find_by_email("ada@example.com").await.unwrap().unwrap();
        assert_eq!(found.id, "u-1");

        // Case-insensitive email lookup.
        let found2 = store.find_by_email("ADA@example.COM").await.unwrap().unwrap();
        assert_eq!(found2.id, "u-1");

        assert!(store.verify_password(&found, "correct-horse-battery-staple").await.unwrap());
        assert!(!store.verify_password(&found, "wrong-password").await.unwrap());
    }

    #[tokio::test]
    async fn inmemory_delete_removes_user() {
        let store = InMemoryUserStore::new();
        store
            .insert_user(
                "u-del",
                "del@example.com",
                "https://del.example/profile#me",
                None,
                "pw",
            )
            .unwrap();
        assert!(store.find_by_id("u-del").await.unwrap().is_some());

        let removed = store.delete("u-del").await.unwrap();
        assert!(removed, "first delete should return true");
        assert!(store.find_by_id("u-del").await.unwrap().is_none());

        let removed_again = store.delete("u-del").await.unwrap();
        assert!(!removed_again, "second delete should return false");
    }

    #[tokio::test]
    async fn inmemory_find_by_id() {
        let store = InMemoryUserStore::new();
        store
            .insert_user(
                "u-2",
                "bob@example.com",
                "https://bob.example/profile#me",
                None,
                "pw",
            )
            .unwrap();
        let found = store.find_by_id("u-2").await.unwrap().unwrap();
        assert_eq!(found.email, "bob@example.com");
        assert!(store.find_by_id("missing").await.unwrap().is_none());
    }
}
