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

use crate::credentials::MIN_PASSWORD_LENGTH;

/// Errors surfaced by [`UserStore`].
#[derive(Debug, Error)]
pub enum UserStoreError {
    /// Hashing / verification failure.
    #[error("password hash: {0}")]
    Hash(String),

    /// Store-specific back-end failure (DB down, etc).
    #[error("backend: {0}")]
    Backend(String),

    /// Password does not meet the minimum length requirement.
    /// JSS commit `1feead2` enforces >= 8 characters at registration.
    #[error("password must be at least {min_length} characters")]
    PasswordTooShort {
        /// The minimum length that was not met.
        min_length: usize,
    },

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
    /// Optional username (unique handle, case-insensitive).
    pub username: Option<String>,
    /// Optional Nostr public key (x-only, hex, 64 chars). Used by the
    /// Schnorr SSO typed-username fallback: when `did:nostr` resolution
    /// fails and a username is provided, the IdP looks up the account
    /// by username and verifies the Schnorr signature against this key
    /// (the profile's `verificationMethod`).
    pub nostr_pubkey: Option<String>,
}

/// Async user-store contract.
#[async_trait]
pub trait UserStore: Send + Sync + 'static {
    /// Look up a user by email. Returns `Ok(None)` on no-match
    /// (distinct from `Err(_)` which means the backend failed).
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, UserStoreError>;

    /// Look up a user by internal id.
    async fn find_by_id(&self, id: &str) -> Result<Option<User>, UserStoreError>;

    /// Look up a user by username (case-insensitive). Returns `Ok(None)`
    /// on no-match. Used by the Schnorr SSO typed-username fallback
    /// when `did:nostr` resolution fails.
    ///
    /// Default impl returns `Ok(None)` so existing stores that lack
    /// username support compile unchanged.
    async fn find_by_username(&self, _username: &str) -> Result<Option<User>, UserStoreError> {
        Ok(None)
    }

    /// Verify `password` against the user's stored hash. This lives
    /// on the trait rather than free-function so stores that use
    /// external auth (LDAP, OAuth federation) can override the
    /// verification path.
    async fn verify_password(&self, user: &User, password: &str) -> Result<bool, UserStoreError> {
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

    /// Update a user's password hash. The caller has already verified
    /// the current password and validated the new password length.
    /// Returns `Ok(true)` when the password was updated, `Ok(false)`
    /// when the user id was not found.
    ///
    /// Default impl returns [`UserStoreError::NotImplemented`].
    async fn update_password(
        &self,
        _id: &str,
        _new_password_hash: String,
    ) -> Result<bool, UserStoreError> {
        Err(UserStoreError::NotImplemented)
    }
}

/// Reference in-memory implementation.
#[derive(Default)]
pub struct InMemoryUserStore {
    /// Keyed by lowercase email.
    inner: RwLock<HashMap<String, User>>,
    /// Secondary index: lowercase username -> lowercase email.
    username_index: RwLock<HashMap<String, String>>,
}

impl InMemoryUserStore {
    /// Construct an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a user with an Argon2id hash of `password`. Returns
    /// the inserted record. Email is case-normalised (lowercased) on
    /// storage so `find_by_email` can match case-insensitively.
    ///
    /// Passwords shorter than [`MIN_PASSWORD_LENGTH`] (8 chars) are
    /// rejected with [`UserStoreError::PasswordTooShort`], matching
    /// JSS commit `1feead2`.
    pub fn insert_user(
        &self,
        id: impl Into<String>,
        email: impl Into<String>,
        webid: impl Into<String>,
        name: Option<String>,
        password: &str,
    ) -> Result<User, UserStoreError> {
        if password.len() < MIN_PASSWORD_LENGTH {
            return Err(UserStoreError::PasswordTooShort {
                min_length: MIN_PASSWORD_LENGTH,
            });
        }
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
            username: None,
            nostr_pubkey: None,
        };
        self.inner.write().insert(user.email.clone(), user.clone());
        Ok(user)
    }

    /// Create a user with username and optional Nostr pubkey for
    /// Schnorr SSO typed-username fallback testing.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_user_with_nostr(
        &self,
        id: impl Into<String>,
        email: impl Into<String>,
        webid: impl Into<String>,
        name: Option<String>,
        password: &str,
        username: Option<String>,
        nostr_pubkey: Option<String>,
    ) -> Result<User, UserStoreError> {
        if password.len() < MIN_PASSWORD_LENGTH {
            return Err(UserStoreError::PasswordTooShort {
                min_length: MIN_PASSWORD_LENGTH,
            });
        }
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| UserStoreError::Hash(e.to_string()))?
            .to_string();
        let lower_email = email.into().to_ascii_lowercase();
        let user = User {
            id: id.into(),
            email: lower_email.clone(),
            webid: webid.into(),
            name,
            password_hash: hash,
            username: username.clone(),
            nostr_pubkey,
        };
        if let Some(ref uname) = username {
            self.username_index
                .write()
                .insert(uname.to_ascii_lowercase(), lower_email.clone());
        }
        self.inner.write().insert(lower_email, user.clone());
        Ok(user)
    }
}

#[async_trait]
impl UserStore for InMemoryUserStore {
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, UserStoreError> {
        Ok(self.inner.read().get(&email.to_ascii_lowercase()).cloned())
    }

    async fn find_by_id(&self, id: &str) -> Result<Option<User>, UserStoreError> {
        Ok(self.inner.read().values().find(|u| u.id == id).cloned())
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>, UserStoreError> {
        let lower = username.to_ascii_lowercase();
        let email = self.username_index.read().get(&lower).cloned();
        match email {
            Some(email_key) => Ok(self.inner.read().get(&email_key).cloned()),
            None => Ok(None),
        }
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

    async fn update_password(
        &self,
        id: &str,
        new_password_hash: String,
    ) -> Result<bool, UserStoreError> {
        let mut guard = self.inner.write();
        let user = guard.values_mut().find(|u| u.id == id);
        match user {
            Some(u) => {
                u.password_hash = new_password_hash;
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

        let found = store
            .find_by_email("ada@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id, "u-1");

        // Case-insensitive email lookup.
        let found2 = store
            .find_by_email("ADA@example.COM")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found2.id, "u-1");

        assert!(store
            .verify_password(&found, "correct-horse-battery-staple")
            .await
            .unwrap());
        assert!(!store
            .verify_password(&found, "wrong-password")
            .await
            .unwrap());
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
                "password",
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
                "password",
            )
            .unwrap();
        let found = store.find_by_id("u-2").await.unwrap().unwrap();
        assert_eq!(found.email, "bob@example.com");
        assert!(store.find_by_id("missing").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn inmemory_update_password() {
        let store = InMemoryUserStore::new();
        store
            .insert_user(
                "u-pw",
                "pw@example.com",
                "https://pw.example/profile#me",
                None,
                "oldpassword123",
            )
            .unwrap();

        let user = store.find_by_id("u-pw").await.unwrap().unwrap();
        assert!(store
            .verify_password(&user, "oldpassword123")
            .await
            .unwrap());

        // Hash a new password and update.
        let salt = SaltString::generate(&mut OsRng);
        let new_hash = Argon2::default()
            .hash_password(b"newpassword456", &salt)
            .unwrap()
            .to_string();
        let updated = store.update_password("u-pw", new_hash).await.unwrap();
        assert!(updated);

        let user2 = store.find_by_id("u-pw").await.unwrap().unwrap();
        assert!(store
            .verify_password(&user2, "newpassword456")
            .await
            .unwrap());
        assert!(!store
            .verify_password(&user2, "oldpassword123")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn inmemory_update_password_unknown_user() {
        let store = InMemoryUserStore::new();
        let updated = store
            .update_password("nonexistent", "hash".into())
            .await
            .unwrap();
        assert!(!updated);
    }

    // ---- password-length validation at registration (JSS 1feead2) ----

    #[test]
    fn insert_user_rejects_7_char_password() {
        let store = InMemoryUserStore::new();
        let err = store
            .insert_user(
                "u-short",
                "short@example.com",
                "https://short.example/profile#me",
                None,
                "1234567",
            )
            .unwrap_err();
        match err {
            UserStoreError::PasswordTooShort { min_length } => {
                assert_eq!(min_length, 8);
            }
            other => panic!("expected PasswordTooShort, got {other:?}"),
        }
    }

    #[test]
    fn insert_user_accepts_8_char_password() {
        let store = InMemoryUserStore::new();
        let user = store
            .insert_user(
                "u-ok",
                "ok@example.com",
                "https://ok.example/profile#me",
                None,
                "12345678",
            )
            .unwrap();
        assert_eq!(user.id, "u-ok");
    }

    #[test]
    fn insert_user_rejects_empty_password() {
        let store = InMemoryUserStore::new();
        let err = store
            .insert_user(
                "u-empty",
                "empty@example.com",
                "https://empty.example/profile#me",
                None,
                "",
            )
            .unwrap_err();
        match err {
            UserStoreError::PasswordTooShort { min_length } => {
                assert_eq!(min_length, 8);
            }
            other => panic!("expected PasswordTooShort, got {other:?}"),
        }
    }
}
