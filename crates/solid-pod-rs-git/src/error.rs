//! Typed error enum for the Git HTTP backend.
//!
//! Mirrors the failure shapes produced by JSS `src/handlers/git.js`:
//! 400 on path traversal, 401 on missing/invalid auth, 404 on unknown
//! repo, 500 on CGI spawn failure, and a dedicated variant for when
//! the `git-http-backend` binary is not installed (so CI without git
//! can still exercise unit tests).

use thiserror::Error;

/// All failure modes the Git HTTP service may surface.
#[derive(Debug, Error)]
pub enum GitError {
    /// Path-traversal attempt or otherwise invalid URL. JSS returns
    /// 400 for malformed requests and 403 for traversal; we fold both
    /// into a single 400 per Rust idiom (the leakage surface is
    /// identical — the client must not learn whether a repo exists
    /// via the status code).
    #[error("path traversal or invalid path: {0}")]
    PathTraversal(String),

    /// Authorisation required but missing / malformed / rejected.
    #[error("unauthorised: {0}")]
    Unauthorised(String),

    /// The request targets a path that is not a git repository.
    #[error("not a git repository: {0}")]
    NotARepository(String),

    /// `git-http-backend` (or `git`) binary not installed in PATH.
    /// Distinguished from a generic I/O error so callers can gate
    /// integration tests.
    #[error("git-http-backend binary not available: {0}")]
    BackendNotAvailable(String),

    /// The CGI process exited non-zero before emitting headers.
    #[error("git backend failed: exit={exit_code:?}, stderr={stderr}")]
    BackendFailed {
        /// Process exit code, if the child did terminate.
        exit_code: Option<i32>,
        /// Captured stderr content for diagnostics.
        stderr: String,
    },

    /// The CGI process emitted malformed output.
    #[error("malformed CGI output: {0}")]
    MalformedCgi(String),

    /// Generic underlying I/O failure.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),

    /// Underlying auth-layer error (NIP-98 decode, Schnorr mismatch, …).
    #[error("auth: {0}")]
    Auth(#[from] crate::auth::AuthError),
}

impl GitError {
    /// Recommended HTTP status code to surface to the client.
    #[must_use]
    pub fn status_code(&self) -> u16 {
        match self {
            GitError::PathTraversal(_) => 400,
            GitError::Unauthorised(_) | GitError::Auth(_) => 401,
            GitError::NotARepository(_) => 404,
            GitError::BackendNotAvailable(_)
            | GitError::BackendFailed { .. }
            | GitError::MalformedCgi(_)
            | GitError::Io(_) => 500,
        }
    }
}
