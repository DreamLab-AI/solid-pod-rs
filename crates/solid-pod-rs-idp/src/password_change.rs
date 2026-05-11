//! `PUT /idp/credentials` — self-service password change.
//!
//! Authenticated users change their own password by supplying the current
//! password and a new password. Rate-limited via the core crate's
//! `RateLimiter` trait to mitigate brute-force guessing of the current
//! password.

use std::net::IpAddr;

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use solid_pod_rs::security::rate_limit::{
    RateLimitDecision, RateLimitKey, RateLimitSubject, RateLimiter,
};

use crate::credentials::{validate_password_length, MIN_PASSWORD_LENGTH};
use crate::user_store::{UserStore, UserStoreError};

/// Rate-limit route name for password-change requests.
pub const RATE_LIMIT_ROUTE: &str = "idp_password_change";

/// Errors surfaced by [`change_password`].
#[derive(Debug, Error)]
pub enum PasswordChangeError {
    /// Request is rate-limited.
    #[error("rate limited, retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    /// Current password verification failed.
    #[error("invalid current password")]
    InvalidCurrentPassword,

    /// New password does not meet the minimum length requirement.
    #[error("new password must be at least {min_length} characters")]
    PasswordTooShort { min_length: usize },

    /// Input validation failed.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// Backend failure.
    #[error("user store: {0}")]
    UserStore(String),

    /// Hashing failure.
    #[error("password hash: {0}")]
    Hash(String),
}

/// Request body for `PUT /idp/credentials`.
#[derive(Debug, Deserialize)]
pub struct PasswordChangeRequest {
    pub current_password: String,
    pub new_password: String,
}

/// Success response for `PUT /idp/credentials`.
#[derive(Debug, Clone, Serialize)]
pub struct PasswordChangeResponse {
    pub message: String,
}

/// Change the authenticated user's password.
///
/// - `user_id` — the authenticated user's internal ID (extracted from
///   the session or access token by the transport layer).
/// - `req` — the deserialized request body.
/// - `user_store` — backing store.
/// - `limiter` + `ip` — rate-limit enforcement.
#[allow(clippy::too_many_arguments)]
pub async fn change_password(
    user_id: &str,
    req: &PasswordChangeRequest,
    user_store: &dyn UserStore,
    limiter: &dyn RateLimiter,
    ip: IpAddr,
) -> Result<PasswordChangeResponse, PasswordChangeError> {
    // --- rate-limit gate ---
    let key = RateLimitKey {
        route: RATE_LIMIT_ROUTE,
        subject: RateLimitSubject::Ip(ip),
    };
    match limiter.check(&key).await {
        RateLimitDecision::Allow => {}
        RateLimitDecision::Deny {
            retry_after_secs, ..
        } => return Err(PasswordChangeError::RateLimited { retry_after_secs }),
    }

    // --- input validation ---
    if req.current_password.is_empty() || req.new_password.is_empty() {
        return Err(PasswordChangeError::InvalidRequest(
            "current_password and new_password are required".into(),
        ));
    }

    validate_password_length(&req.new_password).map_err(|_| {
        PasswordChangeError::PasswordTooShort {
            min_length: MIN_PASSWORD_LENGTH,
        }
    })?;

    // --- look up user ---
    let user = user_store
        .find_by_id(user_id)
        .await
        .map_err(|e| PasswordChangeError::UserStore(e.to_string()))?
        .ok_or(PasswordChangeError::InvalidRequest("user not found".into()))?;

    // --- verify current password ---
    let ok = user_store
        .verify_password(&user, &req.current_password)
        .await
        .map_err(|e| PasswordChangeError::UserStore(e.to_string()))?;
    if !ok {
        return Err(PasswordChangeError::InvalidCurrentPassword);
    }

    // --- hash new password ---
    let salt = SaltString::generate(&mut OsRng);
    let new_hash = Argon2::default()
        .hash_password(req.new_password.as_bytes(), &salt)
        .map_err(|e| PasswordChangeError::Hash(e.to_string()))?
        .to_string();

    // --- update store ---
    let updated = user_store
        .update_password(user_id, new_hash)
        .await
        .map_err(|e| match e {
            UserStoreError::NotImplemented => {
                PasswordChangeError::UserStore("password change not supported by this store".into())
            }
            other => PasswordChangeError::UserStore(other.to_string()),
        })?;

    if !updated {
        return Err(PasswordChangeError::InvalidRequest("user not found".into()));
    }

    Ok(PasswordChangeResponse {
        message: "password changed".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use solid_pod_rs::security::rate_limit::LruRateLimiter;

    use crate::user_store::InMemoryUserStore;

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))
    }

    fn seed() -> (InMemoryUserStore, LruRateLimiter) {
        let store = InMemoryUserStore::new();
        store
            .insert_user(
                "acct-1",
                "alice@example.com",
                "https://alice.example/profile#me",
                Some("Alice".into()),
                "hunter2!",
            )
            .unwrap();
        let limiter = LruRateLimiter::with_policy(vec![(
            RATE_LIMIT_ROUTE.to_string(),
            5,
            Duration::from_secs(60),
        )]);
        (store, limiter)
    }

    #[tokio::test]
    async fn change_password_succeeds() {
        let (store, limiter) = seed();
        let req = PasswordChangeRequest {
            current_password: "hunter2!".into(),
            new_password: "newpass123".into(),
        };
        let resp = change_password("acct-1", &req, &store, &limiter, ip())
            .await
            .unwrap();
        assert_eq!(resp.message, "password changed");

        // Verify new password works.
        let user = store.find_by_id("acct-1").await.unwrap().unwrap();
        assert!(store.verify_password(&user, "newpass123").await.unwrap());
        assert!(!store.verify_password(&user, "hunter2!").await.unwrap());
    }

    #[tokio::test]
    async fn change_password_rejects_wrong_current() {
        let (store, limiter) = seed();
        let req = PasswordChangeRequest {
            current_password: "wrong".into(),
            new_password: "newpass123".into(),
        };
        let err = change_password("acct-1", &req, &store, &limiter, ip())
            .await
            .unwrap_err();
        assert!(matches!(err, PasswordChangeError::InvalidCurrentPassword));
    }

    #[tokio::test]
    async fn change_password_rejects_short_new_password() {
        let (store, limiter) = seed();
        let req = PasswordChangeRequest {
            current_password: "hunter2!".into(),
            new_password: "short".into(),
        };
        let err = change_password("acct-1", &req, &store, &limiter, ip())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            PasswordChangeError::PasswordTooShort { min_length: 8 }
        ));
    }

    #[tokio::test]
    async fn change_password_rejects_empty_fields() {
        let (store, limiter) = seed();
        let req = PasswordChangeRequest {
            current_password: "".into(),
            new_password: "newpass123".into(),
        };
        let err = change_password("acct-1", &req, &store, &limiter, ip())
            .await
            .unwrap_err();
        assert!(matches!(err, PasswordChangeError::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn change_password_rate_limited() {
        let (store, limiter) = seed();
        for _ in 0..5 {
            let req = PasswordChangeRequest {
                current_password: "wrong".into(),
                new_password: "newpass123".into(),
            };
            let _ = change_password("acct-1", &req, &store, &limiter, ip()).await;
        }
        let req = PasswordChangeRequest {
            current_password: "hunter2!".into(),
            new_password: "newpass123".into(),
        };
        let err = change_password("acct-1", &req, &store, &limiter, ip())
            .await
            .unwrap_err();
        assert!(matches!(err, PasswordChangeError::RateLimited { .. }));
    }

    #[tokio::test]
    async fn change_password_unknown_user() {
        let (store, limiter) = seed();
        let req = PasswordChangeRequest {
            current_password: "hunter2!".into(),
            new_password: "newpass123".into(),
        };
        let err = change_password("nonexistent", &req, &store, &limiter, ip())
            .await
            .unwrap_err();
        assert!(matches!(err, PasswordChangeError::InvalidRequest(_)));
    }
}
