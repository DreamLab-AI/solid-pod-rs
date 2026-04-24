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
    #[error("missing required header: {0}")]
    MissingHeader(&'static str),
    #[error("malformed Signature header: {0}")]
    MalformedSignature(String),
    #[error("missing keyId in signature")]
    MissingKeyId,
    #[error("unsupported signature algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("digest mismatch (body tampered)")]
    DigestMismatch,
    #[error("failed to fetch remote actor key at {0}: {1}")]
    ActorFetch(String, String),
    #[error("actor has no usable public key")]
    NoPublicKey,
    #[error("signature verification failed: {0}")]
    VerifyFailed(String),
    #[error("base64 decode error: {0}")]
    Base64(String),
    #[error("RSA error: {0}")]
    Rsa(String),
    #[error("URL parse error: {0}")]
    Url(String),
}

/// Inbox-layer errors raised by [`crate::inbox`].
#[derive(Debug, Error)]
pub enum InboxError {
    #[error("invalid JSON body: {0}")]
    InvalidJson(String),
    #[error("missing activity type")]
    MissingType,
    #[error("storage error: {0}")]
    Storage(#[from] sqlx::Error),
    #[error("signature error: {0}")]
    Signature(#[from] SigError),
}

/// Outbox-layer errors raised by [`crate::outbox`].
#[derive(Debug, Error)]
pub enum OutboxError {
    #[error("invalid activity: {0}")]
    InvalidActivity(String),
    #[error("storage error: {0}")]
    Storage(#[from] sqlx::Error),
    #[error("signature error: {0}")]
    Signature(#[from] SigError),
    #[error("delivery queue error: {0}")]
    Delivery(String),
}
