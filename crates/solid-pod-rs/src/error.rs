//! Crate-wide error type.
//!
//! All public APIs return `Result<T, PodError>`.

use thiserror::Error;

/// Errors emitted by solid-pod-rs.
#[derive(Debug, Error)]
pub enum PodError {
    /// The requested resource does not exist (HTTP 404).
    #[error("resource not found: {0}")]
    NotFound(String),

    /// A resource already exists at the target path (HTTP 409).
    #[error("resource already exists: {0}")]
    AlreadyExists(String),

    /// The authenticated agent lacks the required WAC access mode (HTTP 403).
    #[error("access forbidden")]
    Forbidden,

    /// No valid credentials were presented (HTTP 401).
    #[error("authentication required")]
    Unauthenticated,

    /// Filesystem or network I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The request path is syntactically invalid or escapes the pod root.
    #[error("invalid path: {0}")]
    InvalidPath(String),

    /// The supplied `Content-Type` is not acceptable for this operation.
    #[error("invalid content type: {0}")]
    InvalidContentType(String),

    /// JSON serialisation or deserialisation failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// A URL could not be parsed.
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    /// Base64 decoding failed (e.g. in a NIP-98 or DPoP token).
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// Hex decoding failed.
    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),

    /// An ACL document could not be parsed as JSON-LD or Turtle.
    #[error("ACL parse error: {0}")]
    AclParse(String),

    /// NIP-98 authentication verification failed.
    #[error("NIP-98: {0}")]
    Nip98(String),

    /// The storage watch/notification subsystem encountered an error.
    #[error("watch subsystem error: {0}")]
    Watch(String),

    /// A storage backend reported an unclassified error.
    #[error("backend error: {0}")]
    Backend(String),

    /// An `If-Match` / `If-None-Match` precondition was not satisfied (HTTP 412).
    #[error("precondition failed: {0}")]
    PreconditionFailed(String),

    /// The requested operation is not supported by this configuration.
    #[error("unsupported: {0}")]
    Unsupported(String),

    /// The request is malformed (HTTP 400).
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Request body exceeds a size limit (HTTP 413 equivalent).
    ///
    /// Used by the ACL parsers (`parse_turtle_acl`, `parse_jsonld_acl`) to
    /// reject oversized documents before parsing begins.
    #[error("payload too large: {0}")]
    PayloadTooLarge(String),

    /// Sprint 7: pod-level byte quota exceeded. Wraps the detailed
    /// [`crate::quota::QuotaExceeded`] struct so consumers can surface
    /// pod name / used / limit in their HTTP response bodies.
    #[cfg(feature = "quota")]
    #[error(transparent)]
    QuotaExceeded(#[from] crate::quota::QuotaExceeded),
}

// `notify` is an optional dep activated by `fs-backend`. Wasm32 / `core`
// consumers compile this crate without it; the `Watch` variant remains
// constructible from a string when needed by other backends.
#[cfg(feature = "fs-backend")]
impl From<notify::Error> for PodError {
    fn from(e: notify::Error) -> Self {
        PodError::Watch(e.to_string())
    }
}
