//! `/idp/credentials` — email+password login flow (row 79).
//!
//! JSS parity: `src/idp/credentials.js:28-150`. The JSS endpoint
//! accepts `email`+`password` (or `username`+`password`), optionally
//! binds to a DPoP proof, and returns an access-token JSON body.
//!
//! Rate-limiting is bolted on via the core crate's `RateLimiter`
//! trait, keyed by `(route="idp_credentials", subject=IP)`. The
//! default policy shipped by core is 60/min which is too generous
//! for brute-force protection; this module accepts a caller-supplied
//! limiter so consumers can plug in `LruRateLimiter::with_policy`
//! with `("idp_credentials", 10, Duration::from_secs(60))` to match
//! JSS (`src/idp/index.js:255-265`).

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use solid_pod_rs::security::rate_limit::{
    RateLimitDecision, RateLimitKey, RateLimitSubject, RateLimiter,
};

use crate::jwks::Jwks;
use crate::tokens::{issue_access_token, AccessToken};
use crate::user_store::{User, UserStore};

/// Rate-limit route name we share with the rest of the crate. JSS
/// mirrors this as `/idp/credentials` — we drop the path prefix and
/// use the canonical name so operator metrics don't need to strip.
pub const RATE_LIMIT_ROUTE: &str = "idp_credentials";

/// Errors surfaced by [`login`].
#[derive(Debug, Error)]
pub enum LoginError {
    /// Request is rate-limited. The JSS handler returns 429.
    #[error("rate limited, retry after {retry_after_secs}s")]
    RateLimited {
        /// Seconds the client should wait.
        retry_after_secs: u64,
    },

    /// Unknown user, wrong password, etc. JSS returns
    /// `{"error":"invalid_grant"}` with HTTP 401.
    #[error("invalid credentials")]
    InvalidGrant,

    /// Caller passed a malformed body.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// Store backend exploded.
    #[error("user store: {0}")]
    UserStore(String),

    /// Token signing failed.
    #[error("token issuance: {0}")]
    Token(String),
}

/// Response body matching JSS `src/idp/credentials.js:138-145`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialsResponse {
    /// Signed access token (JWT).
    pub access_token: String,
    /// `"DPoP"` when a valid proof was supplied, else `"Bearer"`.
    pub token_type: String,
    /// Lifetime in seconds.
    pub expires_in: u64,
    /// Authenticated WebID.
    pub webid: String,
    /// Internal account id.
    pub id: String,
}

/// Email+password login.
///
/// - `email` / `password` — user-supplied credentials. Email is
///   case-normalised before lookup (matches [`UserStore`] contract).
/// - `user_store` — source of truth for the account record.
/// - `jwks` — signing keys; the active key is used to sign the
///   returned access token.
/// - `issuer` — issuer URL (must match discovery's `issuer`).
/// - `dpop_jkt` — when the caller has already verified a DPoP proof
///   from the Authorization-adjacent `DPoP` header, pass the proof's
///   `jkt` here. The token is then marked DPoP-bound.
/// - `limiter` + `ip` — rate-limit subject. Callers who do not want
///   rate limits can pass a `NoopRateLimiter` (tests only).
/// - `ttl_secs` — access-token TTL. JSS defaults to 3600.
#[allow(clippy::too_many_arguments)]
pub async fn login(
    email: &str,
    password: &str,
    user_store: &dyn UserStore,
    jwks: &Jwks,
    issuer: &str,
    dpop_jkt: Option<&str>,
    limiter: &dyn RateLimiter,
    ip: IpAddr,
    now: u64,
    ttl_secs: u64,
) -> Result<CredentialsResponse, LoginError> {
    // --- rate-limit gate ----------------------------------------------------
    let key = RateLimitKey {
        route: RATE_LIMIT_ROUTE,
        subject: RateLimitSubject::Ip(ip),
    };
    match limiter.check(&key).await {
        RateLimitDecision::Allow => {}
        RateLimitDecision::Deny {
            retry_after_secs, ..
        } => return Err(LoginError::RateLimited { retry_after_secs }),
    }

    // --- input validation ---------------------------------------------------
    if email.is_empty() || password.is_empty() {
        return Err(LoginError::InvalidRequest(
            "email and password are required".into(),
        ));
    }

    // --- authentication -----------------------------------------------------
    let user: Option<User> = user_store
        .find_by_email(email)
        .await
        .map_err(|e| LoginError::UserStore(e.to_string()))?;

    let Some(user) = user else {
        return Err(LoginError::InvalidGrant);
    };

    let ok = user_store
        .verify_password(&user, password)
        .await
        .map_err(|e| LoginError::UserStore(e.to_string()))?;
    if !ok {
        return Err(LoginError::InvalidGrant);
    }

    // --- token issuance -----------------------------------------------------
    let key = jwks.active_key();
    let token: AccessToken = issue_access_token(
        &key,
        issuer,
        &user.webid,
        &user.id,
        "credentials_client", // Matches JSS line 121.
        "openid webid",
        dpop_jkt,
        now,
        ttl_secs,
    )
    .map_err(|e| LoginError::Token(e.to_string()))?;

    Ok(CredentialsResponse {
        access_token: token.jwt,
        token_type: if dpop_jkt.is_some() {
            "DPoP".into()
        } else {
            "Bearer".into()
        },
        expires_in: ttl_secs,
        webid: user.webid,
        id: user.id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use solid_pod_rs::security::rate_limit::LruRateLimiter;

    use crate::jwks::Jwks;
    use crate::user_store::InMemoryUserStore;

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))
    }

    fn seed() -> (InMemoryUserStore, Jwks, LruRateLimiter) {
        let store = InMemoryUserStore::new();
        store
            .insert_user(
                "acct-1",
                "alice@example.com",
                "https://alice.example/profile#me",
                Some("Alice".into()),
                "hunter2",
            )
            .unwrap();
        let jwks = Jwks::generate_es256().unwrap();
        // JSS policy: 10 per minute.
        let limiter = LruRateLimiter::with_policy(vec![(
            RATE_LIMIT_ROUTE.to_string(),
            10,
            Duration::from_secs(60),
        )]);
        (store, jwks, limiter)
    }

    #[tokio::test]
    async fn login_succeeds_with_correct_password() {
        let (store, jwks, limiter) = seed();
        let resp = login(
            "alice@example.com",
            "hunter2",
            &store,
            &jwks,
            "https://pod.example/",
            Some("JKT-OK"),
            &limiter,
            ip(),
            1_700_000_000,
            3600,
        )
        .await
        .unwrap();
        assert_eq!(resp.token_type, "DPoP");
        assert_eq!(resp.webid, "https://alice.example/profile#me");
        assert_eq!(resp.expires_in, 3600);
        assert!(resp.access_token.contains('.'));
    }

    #[tokio::test]
    async fn login_returns_bearer_when_no_dpop() {
        let (store, jwks, limiter) = seed();
        let resp = login(
            "alice@example.com",
            "hunter2",
            &store,
            &jwks,
            "https://pod.example/",
            None,
            &limiter,
            ip(),
            1_700_000_000,
            3600,
        )
        .await
        .unwrap();
        assert_eq!(resp.token_type, "Bearer");
    }

    #[tokio::test]
    async fn login_rejects_wrong_password() {
        let (store, jwks, limiter) = seed();
        let err = login(
            "alice@example.com",
            "nope",
            &store,
            &jwks,
            "https://pod.example/",
            None,
            &limiter,
            ip(),
            1_700_000_000,
            3600,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, LoginError::InvalidGrant));
    }

    #[tokio::test]
    async fn login_rejects_unknown_user() {
        let (store, jwks, limiter) = seed();
        let err = login(
            "nobody@example.com",
            "hunter2",
            &store,
            &jwks,
            "https://pod.example/",
            None,
            &limiter,
            ip(),
            1_700_000_000,
            3600,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, LoginError::InvalidGrant));
    }

    #[tokio::test]
    async fn login_rate_limited_after_ten_attempts() {
        let (store, jwks, limiter) = seed();
        for _ in 0..10 {
            // Deliberate wrong password — we're stress-testing the
            // limiter, not the happy path.
            let _ = login(
                "alice@example.com",
                "wrong",
                &store,
                &jwks,
                "https://pod.example/",
                None,
                &limiter,
                ip(),
                1_700_000_000,
                3600,
            )
            .await;
        }
        let err = login(
            "alice@example.com",
            "hunter2",
            &store,
            &jwks,
            "https://pod.example/",
            None,
            &limiter,
            ip(),
            1_700_000_000,
            3600,
        )
        .await
        .unwrap_err();
        match err {
            LoginError::RateLimited { retry_after_secs } => {
                assert!(retry_after_secs >= 1);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn login_rejects_blank_input() {
        let (store, jwks, limiter) = seed();
        let err = login(
            "",
            "",
            &store,
            &jwks,
            "https://pod.example/",
            None,
            &limiter,
            ip(),
            0,
            3600,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, LoginError::InvalidRequest(_)));
    }
}
