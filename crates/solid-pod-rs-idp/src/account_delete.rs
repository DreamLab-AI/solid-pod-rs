//! `DELETE /idp/account` — self-service account deletion.
//!
//! Authenticated users delete their own account by confirming with the
//! exact string `"DELETE MY ACCOUNT"`. This mirrors the JSS
//! account-deletion safety gate — the confirmation prevents accidental
//! deletions from errant API calls or browser autofill.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::user_store::{UserStore, UserStoreError};

/// The exact confirmation string the client must send.
pub const CONFIRMATION_PHRASE: &str = "DELETE MY ACCOUNT";

/// Errors surfaced by [`delete_account`].
#[derive(Debug, Error)]
pub enum AccountDeleteError {
    /// The confirmation phrase did not match.
    #[error("confirmation mismatch: expected \"{expected}\"")]
    ConfirmationMismatch { expected: &'static str },

    /// User not found (already deleted or never existed).
    #[error("user not found")]
    NotFound,

    /// The backing store does not implement deletion.
    #[error("not implemented by this store")]
    NotImplemented,

    /// Backend failure.
    #[error("user store: {0}")]
    UserStore(String),
}

/// Request body for `DELETE /idp/account`.
#[derive(Debug, Deserialize)]
pub struct AccountDeleteRequest {
    pub confirmation: String,
}

/// Success response for `DELETE /idp/account`.
#[derive(Debug, Clone, Serialize)]
pub struct AccountDeleteResponse {
    pub message: String,
}

/// Delete the authenticated user's account.
///
/// - `user_id` — the authenticated user's internal ID (extracted from
///   the session or access token by the transport layer).
/// - `req` — the deserialized request body; `confirmation` MUST equal
///   [`CONFIRMATION_PHRASE`].
/// - `user_store` — backing store.
pub async fn delete_account(
    user_id: &str,
    req: &AccountDeleteRequest,
    user_store: &dyn UserStore,
) -> Result<AccountDeleteResponse, AccountDeleteError> {
    // --- confirmation gate ---
    if req.confirmation != CONFIRMATION_PHRASE {
        return Err(AccountDeleteError::ConfirmationMismatch {
            expected: CONFIRMATION_PHRASE,
        });
    }

    // --- delete ---
    let deleted = user_store
        .delete(user_id)
        .await
        .map_err(|e| match e {
            UserStoreError::NotImplemented => AccountDeleteError::NotImplemented,
            other => AccountDeleteError::UserStore(other.to_string()),
        })?;

    if !deleted {
        return Err(AccountDeleteError::NotFound);
    }

    Ok(AccountDeleteResponse {
        message: "account deleted".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user_store::InMemoryUserStore;

    fn seed() -> InMemoryUserStore {
        let store = InMemoryUserStore::new();
        store
            .insert_user(
                "acct-del",
                "del@example.com",
                "https://del.example/profile#me",
                None,
                "password123",
            )
            .unwrap();
        store
    }

    #[tokio::test]
    async fn delete_account_succeeds_with_correct_confirmation() {
        let store = seed();
        let req = AccountDeleteRequest {
            confirmation: "DELETE MY ACCOUNT".into(),
        };
        let resp = delete_account("acct-del", &req, &store).await.unwrap();
        assert_eq!(resp.message, "account deleted");

        // Verify user is gone.
        assert!(store.find_by_id("acct-del").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_account_rejects_wrong_confirmation() {
        let store = seed();
        let req = AccountDeleteRequest {
            confirmation: "delete my account".into(), // wrong case
        };
        let err = delete_account("acct-del", &req, &store).await.unwrap_err();
        assert!(matches!(err, AccountDeleteError::ConfirmationMismatch { .. }));

        // User should still exist.
        assert!(store.find_by_id("acct-del").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn delete_account_rejects_empty_confirmation() {
        let store = seed();
        let req = AccountDeleteRequest {
            confirmation: "".into(),
        };
        let err = delete_account("acct-del", &req, &store).await.unwrap_err();
        assert!(matches!(err, AccountDeleteError::ConfirmationMismatch { .. }));
    }

    #[tokio::test]
    async fn delete_account_returns_not_found_for_unknown_user() {
        let store = seed();
        let req = AccountDeleteRequest {
            confirmation: "DELETE MY ACCOUNT".into(),
        };
        let err = delete_account("nonexistent", &req, &store).await.unwrap_err();
        assert!(matches!(err, AccountDeleteError::NotFound));
    }

    #[tokio::test]
    async fn delete_account_idempotent() {
        let store = seed();
        let req = AccountDeleteRequest {
            confirmation: "DELETE MY ACCOUNT".into(),
        };
        // First delete succeeds.
        delete_account("acct-del", &req, &store).await.unwrap();
        // Second delete returns NotFound.
        let err = delete_account("acct-del", &req, &store).await.unwrap_err();
        assert!(matches!(err, AccountDeleteError::NotFound));
    }
}
