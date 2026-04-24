//! Crate-wide error type for the IdP.

use thiserror::Error;

use solid_pod_rs::PodError;

/// Errors surfaced by the provider surface.
#[derive(Debug, Error)]
pub enum ProviderError {
    /// OIDC spec error: something about the request was malformed.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// OIDC spec error: the caller is not allowed to perform this
    /// action.
    #[error("invalid grant: {0}")]
    InvalidGrant(String),

    /// OIDC spec error: unknown client.
    #[error("invalid client: {0}")]
    InvalidClient(String),

    /// Missing / malformed DPoP proof.
    #[error("invalid DPoP: {0}")]
    InvalidDpop(String),

    /// Client Identifier Document fetch / validation failed.
    #[error("client document: {0}")]
    ClientDocument(String),

    /// Rate limit tripped.
    #[error("rate limited (retry after {retry_after_secs}s)")]
    RateLimited {
        /// Seconds the client should wait.
        retry_after_secs: u64,
    },

    /// User store failure (DB down, etc.).
    #[error("user store: {0}")]
    UserStore(String),

    /// Internal crypto / JWT error.
    #[error("crypto: {0}")]
    Crypto(String),

    /// Session lookup / expiry error.
    #[error("session: {0}")]
    Session(String),

    /// Propagation from core crate.
    #[error(transparent)]
    Core(#[from] PodError),

    /// I/O (file-backed stores, etc.).
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Generic "something unexpected happened".
    #[error("internal: {0}")]
    Internal(String),
}

impl ProviderError {
    /// Stable short code for wire responses (`error` field of an
    /// OAuth2 error response, RFC 6749 §5.2).
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "invalid_request",
            Self::InvalidGrant(_) => "invalid_grant",
            Self::InvalidClient(_) => "invalid_client",
            Self::InvalidDpop(_) => "invalid_dpop_proof",
            Self::ClientDocument(_) => "invalid_client",
            Self::RateLimited { .. } => "rate_limited",
            Self::UserStore(_) | Self::Session(_) | Self::Internal(_) | Self::Io(_) => {
                "server_error"
            }
            Self::Crypto(_) => "server_error",
            Self::Core(_) => "server_error",
        }
    }
}
