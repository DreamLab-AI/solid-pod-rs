//! Error type for the `did:key` crate.

use thiserror::Error;

/// Errors surfaced by every public API in this crate.
#[derive(Debug, Error)]
pub enum DidKeyError {
    /// Input was not a `did:key:z…` string.
    #[error("not a did:key identifier: {0}")]
    NotDidKey(String),

    /// Multibase header or body rejected (only base58btc 'z' accepted).
    #[error("invalid multibase encoding: {0}")]
    InvalidMultibase(String),

    /// Multicodec varint prefix did not match any supported algorithm.
    #[error("unknown multicodec codec 0x{0:04x}")]
    UnknownCodec(u64),

    /// Key bytes were the wrong length for the declared codec.
    #[error("invalid key length for {codec}: expected {expected}, got {actual}")]
    InvalidKeyLength {
        codec: &'static str,
        expected: usize,
        actual: usize,
    },

    /// JWT compact serialisation is malformed (segment count / base64).
    #[error("malformed JWT: {0}")]
    MalformedJwt(String),

    /// JWT header rejected — wrong `alg`, missing key binding, `alg`
    /// does not match the bound `did:key`, etc.
    #[error("invalid JWT header: {0}")]
    InvalidHeader(String),

    /// JWT claims rejected — `htm`/`htu`/`iat` mismatch.
    #[error("invalid JWT claims: {0}")]
    InvalidClaims(String),

    /// Cryptographic signature verification failed.
    #[error("signature verification failed: {0}")]
    BadSignature(String),

    /// Failure parsing an underlying elliptic-curve key or signature.
    #[error("key material parse error: {0}")]
    KeyParse(String),

    /// Serde / JSON decode failures.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    /// Base64 decode failures.
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
}
