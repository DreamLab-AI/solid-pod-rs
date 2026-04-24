//! NIP-07 Schnorr SSO trait hook (row 81 — `partial-parity`).
//!
//! **Scope honesty:** Sprint 10 did NOT land a full NIP-07 handshake
//! in this crate. The full flow needs:
//!
//! 1. Challenge issuance (random 32-byte token keyed by session id).
//! 2. Client-side NIP-07 signing via `window.nostr.signEvent`.
//! 3. Server-side Schnorr signature verification via
//!    `solid_pod_rs::auth::nip98::*` (which lives behind the core
//!    crate's `nip98-schnorr` feature).
//! 4. Binding `account_id ↔ npub` by searching the profile
//!    `alsoKnownAs` predicate.
//!
//! All four pieces are individually <100 LOC but together need
//! careful fixture plumbing (especially the npub/WebID linking in
//! core's `interop::did_nostr`, which is gated behind `did-nostr`).
//!
//! This module ships the trait shape so a follow-up sprint can drop
//! a real impl in without breaking the `Provider` API.
//!
//! JSS parity: `src/idp/interactions.js:handleSchnorrLogin` +
//! `handleSchnorrComplete`.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from a Schnorr SSO backend.
#[derive(Debug, Error)]
pub enum SchnorrError {
    /// Backend not wired up.
    #[error("schnorr SSO backend not implemented")]
    Unimplemented,
    /// Signature verification failed.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    /// Challenge not found / expired.
    #[error("challenge: {0}")]
    Challenge(String),
    /// Profile lookup (npub ↔ WebID mapping) failed.
    #[error("no account for npub: {0}")]
    UnknownNpub(String),
}

/// A freshly-issued challenge the client must sign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// Opaque challenge token (base16 random).
    pub token: String,
    /// Unix seconds; the backend may reject signatures whose
    /// internal timestamp falls outside `[created_at, created_at+TTL]`.
    pub created_at: u64,
}

/// The client's signed response to a [`Challenge`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedChallenge {
    /// The challenge token being answered (must equal a previously
    /// issued `Challenge::token`).
    pub token: String,
    /// Nostr public key (npub or hex).
    pub pubkey: String,
    /// Schnorr signature over the challenge, hex-encoded.
    pub signature: String,
}

/// NIP-07 Schnorr SSO contract.
#[async_trait]
pub trait SchnorrBackend: Send + Sync + 'static {
    /// Mint a fresh challenge. Concrete impls persist the challenge
    /// so `verify_challenge` can look it up.
    async fn issue_challenge(&self, account_hint: Option<&str>) -> Result<Challenge, SchnorrError>;

    /// Verify a signed challenge. Returns the internal account id
    /// (derived from the pubkey's `alsoKnownAs` WebID) on success.
    async fn verify_challenge(&self, signed: SignedChallenge) -> Result<String, SchnorrError>;
}

/// Default no-op impl. Returns [`SchnorrError::Unimplemented`] on
/// every call. Exists so consumers can wire a `SchnorrBackend` into
/// their router without a real impl.
pub struct NullSchnorrBackend;

#[async_trait]
impl SchnorrBackend for NullSchnorrBackend {
    async fn issue_challenge(&self, _hint: Option<&str>) -> Result<Challenge, SchnorrError> {
        Err(SchnorrError::Unimplemented)
    }

    async fn verify_challenge(&self, _signed: SignedChallenge) -> Result<String, SchnorrError> {
        Err(SchnorrError::Unimplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn null_backend_is_callable_and_returns_unimplemented() {
        let backend = NullSchnorrBackend;
        assert!(matches!(
            backend.issue_challenge(None).await.unwrap_err(),
            SchnorrError::Unimplemented
        ));
        assert!(matches!(
            backend
                .verify_challenge(SignedChallenge {
                    token: "t".into(),
                    pubkey: "p".into(),
                    signature: "s".into(),
                })
                .await
                .unwrap_err(),
            SchnorrError::Unimplemented
        ));
    }
}
