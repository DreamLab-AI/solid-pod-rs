//! Typed error enum with HTTP status mapping, mirroring the shape of
//! [`solid_pod_rs_git::error::GitError`].

use thiserror::Error;

/// All failure modes surfaced by the forge service.
#[derive(Debug, Error)]
pub enum ForgeError {
    /// Resource does not exist (404).
    #[error("not found: {0}")]
    NotFound(String),

    /// Malformed request / invalid parameter (400).
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Path traversal or otherwise unsafe path (400).
    #[error("invalid path: {0}")]
    PathTraversal(String),

    /// Authentication required but missing/invalid (401).
    #[error("unauthorised: {0}")]
    Unauthorised(String),

    /// Authenticated but not permitted — e.g. namespace-write guard (403).
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// Compare-and-swap failure: the base ref moved under a merge (409).
    #[error("conflict: {0}")]
    Conflict(String),

    /// A required host capability (git version, CGI binary) is absent
    /// or the feature is not compiled (501).
    #[error("unsupported: {0}")]
    Unsupported(String),

    /// Underlying git porcelain/CGI error — status mapped from the inner
    /// [`solid_pod_rs_git::error::GitError`].
    #[error("git: {0}")]
    Git(#[from] solid_pod_rs_git::error::GitError),

    /// Filesystem or process I/O failure (500).
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),

    /// JSON (de)serialisation failure for the spine (500).
    #[error("serialisation: {0}")]
    Serde(#[from] serde_json::Error),

    /// A generic backend failure (500).
    #[error("backend: {0}")]
    Backend(String),
}

impl ForgeError {
    /// Recommended HTTP status code.
    #[must_use]
    pub fn status_code(&self) -> u16 {
        match self {
            ForgeError::NotFound(_) => 404,
            ForgeError::BadRequest(_) | ForgeError::PathTraversal(_) => 400,
            ForgeError::Unauthorised(_) => 401,
            ForgeError::Forbidden(_) => 403,
            ForgeError::Conflict(_) => 409,
            ForgeError::Unsupported(_) => 501,
            ForgeError::Git(g) => g.status_code(),
            ForgeError::Io(_) | ForgeError::Serde(_) | ForgeError::Backend(_) => 500,
        }
    }

    /// Render this error as a [`crate::ForgeResponse`] JSON body.
    #[must_use]
    pub fn to_response(&self) -> crate::ForgeResponse {
        crate::ForgeResponse::error(self.status_code(), self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_mapping() {
        assert_eq!(ForgeError::NotFound("x".into()).status_code(), 404);
        assert_eq!(ForgeError::BadRequest("x".into()).status_code(), 400);
        assert_eq!(ForgeError::PathTraversal("x".into()).status_code(), 400);
        assert_eq!(ForgeError::Unauthorised("x".into()).status_code(), 401);
        assert_eq!(ForgeError::Forbidden("x".into()).status_code(), 403);
        assert_eq!(ForgeError::Conflict("x".into()).status_code(), 409);
        assert_eq!(ForgeError::Unsupported("x".into()).status_code(), 501);
        assert_eq!(ForgeError::Backend("x".into()).status_code(), 500);
    }

    #[test]
    fn git_error_status_propagates() {
        let g = solid_pod_rs_git::error::GitError::NotARepository("r".into());
        let e = ForgeError::Git(g);
        assert_eq!(e.status_code(), 404);
    }
}
