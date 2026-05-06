//! Error types for the ActivityPub sibling crate.
//!
//! The types here deliberately split by bounded context so that each
//! handler surfaces only the failures it can actually raise; this
//! keeps the `pub` API honest about what a given operation can go
//! wrong on.

use thiserror::Error;

/// Signature-layer errors raised by [`crate::http_sig`].
#[derive(Debug, Error)]
pub enum SigError {
    /// A required HTTP header (e.g. `Date`, `Digest`) is absent.
    #[error("missing required header: {0}")]
    MissingHeader(&'static str),
    /// The `Signature` header could not be parsed.
    #[error("malformed Signature header: {0}")]
    MalformedSignature(String),
    /// The `Signature` header lacks a `keyId` parameter.
    #[error("missing keyId in signature")]
    MissingKeyId,
    /// The declared algorithm is not `rsa-sha256`.
    #[error("unsupported signature algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// The `Digest` header does not match the request body.
    #[error("digest mismatch (body tampered)")]
    DigestMismatch,
    /// Failed to dereference the remote actor's public key.
    #[error("failed to fetch remote actor key at {0}: {1}")]
    ActorFetch(String, String),
    /// The fetched actor document contains no usable public key.
    #[error("actor has no usable public key")]
    NoPublicKey,
    /// RSA signature verification returned a mismatch.
    #[error("signature verification failed: {0}")]
    VerifyFailed(String),
    /// Base64 decoding of the signature value failed.
    #[error("base64 decode error: {0}")]
    Base64(String),
    /// An RSA key-parsing or padding error.
    #[error("RSA error: {0}")]
    Rsa(String),
    /// The `keyId` URL could not be parsed.
    #[error("URL parse error: {0}")]
    Url(String),
}

/// Inbox-layer errors raised by [`crate::inbox`].
#[derive(Debug, Error)]
pub enum InboxError {
    /// The request body is not valid JSON or lacks required fields.
    #[error("invalid JSON body: {0}")]
    InvalidJson(String),
    /// The activity object has no `type` field.
    #[error("missing activity type")]
    MissingType,
    /// SQLite persistence layer failure.
    #[error("storage error: {0}")]
    Storage(#[from] sqlx::Error),
    /// HTTP Signature verification failed.
    #[error("signature error: {0}")]
    Signature(#[from] SigError),
}

/// Outbox-layer errors raised by [`crate::outbox`].
#[derive(Debug, Error)]
pub enum OutboxError {
    /// The submitted activity is structurally invalid.
    #[error("invalid activity: {0}")]
    InvalidActivity(String),
    /// SQLite persistence layer failure.
    #[error("storage error: {0}")]
    Storage(#[from] sqlx::Error),
    /// Outbound HTTP Signature generation failed.
    #[error("signature error: {0}")]
    Signature(#[from] SigError),
    /// The federated delivery queue rejected the item.
    #[error("delivery queue error: {0}")]
    Delivery(String),
}
