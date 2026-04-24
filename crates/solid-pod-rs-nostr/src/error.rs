//! Error types for the `solid-pod-rs-nostr` crate.
//!
//! The crate surfaces three error domains:
//!
//! - [`DidError`]     — `did:nostr` parsing and DID-Document rendering.
//! - [`ResolverError`] — `did:nostr` ↔ WebID bidirectional resolution.
//! - [`RelayError`]    — NIP-01 event validation and relay lifecycle.
//!
//! Each error maps cleanly onto a NIP wire-level reject (e.g. `RelayError`
//! → `["OK", id, false, "<reason>"]`) and onto an HTTP status code when
//! the consumer serves the `.well-known/did/nostr/:pubkey.json` endpoint.

use thiserror::Error;

/// Errors encountered while parsing `did:nostr` URIs or rendering DID
/// Documents.
#[derive(Debug, Error)]
pub enum DidError {
    /// The provided hex string does not decode to 32 bytes.
    #[error("invalid pubkey hex: {0}")]
    InvalidPubkey(String),
    /// DID URI did not start with the `did:nostr:` prefix.
    #[error("not a did:nostr URI: {0}")]
    NotDidNostr(String),
}

/// Errors emitted by the `did:nostr` ↔ WebID resolver.
#[derive(Debug, Error)]
pub enum ResolverError {
    /// The URL supplied to the resolver could not be parsed.
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    /// An SSRF policy check refused the outbound request.
    #[error("ssrf: {0}")]
    Ssrf(String),
    /// The transport layer reported a failure.
    #[error("http: {0}")]
    Http(String),
    /// The remote DID document was missing, malformed, or schema-invalid.
    #[error("malformed DID document: {0}")]
    Malformed(String),
}

/// Errors emitted by the embedded Nostr relay.
#[derive(Debug, Error)]
pub enum RelayError {
    /// The event JSON could not be decoded into the NIP-01 envelope.
    #[error("invalid event: {0}")]
    InvalidEvent(String),
    /// Canonical NIP-01 id recomputation does not match the claimed id.
    #[error("event id mismatch")]
    IdMismatch,
    /// BIP-340 signature verification failed.
    #[error("bad signature: {0}")]
    BadSignature(String),
    /// The wire-level message could not be parsed (NIP-01 client→relay).
    #[error("bad wire message: {0}")]
    BadMessage(String),
}
