//! NIP-07 Schnorr SSO (row 81 — Sprint 11: full handshake).
//!
//! This module exposes:
//!
//! 1. [`SchnorrSso`] — the stable trait the IdP invokes during the
//!    login flow. Implementations issue a challenge, then verify the
//!    client's signed response.
//! 2. [`Nip07SchnorrSso`] — the production implementation. Stores
//!    per-user challenges with a TTL and verifies BIP-340 Schnorr
//!    signatures via the core crate's
//!    [`solid_pod_rs::auth::nip98::verify_schnorr_signature`]
//!    helper (feature `nip98-schnorr`).
//! 3. [`SchnorrTodo`] — a `#[doc(hidden)]` fallback whose methods
//!    always return [`SchnorrError::Unimplemented`]. Useful for
//!    integrators wiring a provider before deciding whether to
//!    enable `schnorr-sso`.
//!
//! # Handshake
//!
//! 1. Client calls `issue_challenge(user_id)` — server mints 32
//!    random bytes, hex-encodes, persists `(token, timestamp)`.
//! 2. Client signs the message `SHA-256(token ‖ user_id ‖ pubkey)`
//!    (BIP-340 Schnorr) and POSTs `(pubkey, signature)` back.
//! 3. Server calls `verify_response(user_id, pubkey, sig)` — the
//!    challenge is looked up, TTL-checked, the digest is recomputed,
//!    the signature is verified. On success the challenge is
//!    **consumed** (removed from the map) so it cannot be replayed.
//!
//! # One-shot semantics
//!
//! Challenges are single-use. A successful verification removes the
//! challenge from the store. A failed verification also removes it
//! (we do not want to leak "which part of the token was wrong" by
//! letting the client retry arbitrarily; the client can request a
//! fresh challenge if they mis-signed).
//!
//! JSS parity: `src/idp/interactions.js:handleSchnorrLogin` +
//! `handleSchnorrComplete`.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(feature = "schnorr-sso")]
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(feature = "schnorr-sso")]
use dashmap::DashMap;

/// Errors from a Schnorr SSO backend.
#[derive(Debug, Error)]
pub enum SchnorrError {
    /// Backend not wired up (the Todo fallback).
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
    /// CSPRNG failure (effectively impossible, but surfaced rather
    /// than panic).
    #[error("rng: {0}")]
    Rng(String),
    /// Input parse error (bad hex, wrong length, etc.).
    #[error("parse: {0}")]
    Parse(String),
}

/// A freshly-issued challenge the client must sign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchnorrChallenge {
    /// The authenticating user's stable id. Binds the challenge to
    /// a specific account so a challenge issued for Alice cannot be
    /// used to log in as Bob.
    pub user_id: String,
    /// Opaque challenge token (hex-encoded 32 random bytes).
    pub token: String,
    /// Unix seconds the challenge was issued at.
    pub created_at: u64,
}

/// Backward-compatible alias — Sprint 10 called this `Challenge`.
pub type Challenge = SchnorrChallenge;

/// Result of a successful Schnorr verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchnorrAssertion {
    /// The account id whose challenge was verified.
    pub user_id: String,
    /// The Schnorr pubkey (hex) that produced the signature.
    pub pubkey: String,
    /// Unix seconds at which the server accepted the proof.
    pub verified_at: u64,
}

/// The client's signed response to a [`SchnorrChallenge`].
///
/// Retained as a data carrier for transports that prefer a
/// struct-shaped request body; `Nip07SchnorrSso::verify_response`
/// accepts the individual fields directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedChallenge {
    /// The challenge token being answered.
    pub token: String,
    /// Schnorr public key (x-only, hex).
    pub pubkey: String,
    /// BIP-340 Schnorr signature, hex-encoded.
    pub signature: String,
}

/// NIP-07 Schnorr SSO contract.
///
/// Implementations MUST be `Send + Sync` so the provider can hold
/// them in an `Arc`.
#[async_trait]
pub trait SchnorrSso: Send + Sync + 'static {
    /// Mint a fresh challenge bound to `user_id`. The challenge is
    /// stored server-side so `verify_response` can look it up.
    async fn issue_challenge(&self, user_id: &str) -> Result<SchnorrChallenge, SchnorrError>;

    /// Verify a client-supplied Schnorr signature against the most
    /// recently issued challenge for `user_id`. Consumes the
    /// challenge on return (success or failure).
    async fn verify_response(
        &self,
        user_id: &str,
        pubkey_hex: &str,
        signature_hex: &str,
    ) -> Result<SchnorrAssertion, SchnorrError>;
}

/// Legacy alias — Sprint 10 called this `SchnorrBackend`.
pub trait SchnorrBackend: SchnorrSso {}
impl<T: SchnorrSso> SchnorrBackend for T {}

/// Test-only fallback. Every call returns
/// [`SchnorrError::Unimplemented`].
#[doc(hidden)]
pub struct SchnorrTodo;

/// Backward-compatible alias for the Sprint-10 name.
#[doc(hidden)]
pub type NullSchnorrBackend = SchnorrTodo;

#[async_trait]
impl SchnorrSso for SchnorrTodo {
    async fn issue_challenge(&self, _user_id: &str) -> Result<SchnorrChallenge, SchnorrError> {
        Err(SchnorrError::Unimplemented)
    }

    async fn verify_response(
        &self,
        _user_id: &str,
        _pubkey_hex: &str,
        _signature_hex: &str,
    ) -> Result<SchnorrAssertion, SchnorrError> {
        Err(SchnorrError::Unimplemented)
    }
}

// ---------------------------------------------------------------
// Real impl — `Nip07SchnorrSso` backed by core nip98 Schnorr.
// ---------------------------------------------------------------

/// Production implementation of [`SchnorrSso`] for NIP-07 style
/// (Solid-over-Nostr) sign-in.
///
/// Stores per-user challenges in an in-memory
/// [`dashmap::DashMap`]; the map grows on issue and shrinks on
/// verify. The TTL defaults to 5 minutes, matching the WebAuthn
/// recommendation.
#[cfg(feature = "schnorr-sso")]
pub struct Nip07SchnorrSso {
    challenges: DashMap<String, (SchnorrChallenge, Instant)>,
    ttl: Duration,
}

#[cfg(feature = "schnorr-sso")]
impl Default for Nip07SchnorrSso {
    fn default() -> Self {
        Self::new(Duration::from_secs(5 * 60))
    }
}

#[cfg(feature = "schnorr-sso")]
impl Nip07SchnorrSso {
    /// Build a new SSO backend with the given challenge TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            challenges: DashMap::new(),
            ttl,
        }
    }

    /// Hash the canonical authentication message.
    ///
    /// Returns `SHA-256(token ‖ user_id ‖ pubkey)` — 32 bytes.
    pub fn canonical_digest(token: &str, user_id: &str, pubkey_hex: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(token.as_bytes());
        h.update(user_id.as_bytes());
        h.update(pubkey_hex.as_bytes());
        h.finalize().into()
    }
}

#[cfg(feature = "schnorr-sso")]
#[async_trait]
impl SchnorrSso for Nip07SchnorrSso {
    async fn issue_challenge(&self, user_id: &str) -> Result<SchnorrChallenge, SchnorrError> {
        use rand::RngCore;
        let mut buf = [0u8; 32];
        rand::thread_rng()
            .try_fill_bytes(&mut buf)
            .map_err(|e| SchnorrError::Rng(e.to_string()))?;
        let token = hex::encode(buf);
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let challenge = SchnorrChallenge {
            user_id: user_id.to_string(),
            token,
            created_at,
        };
        self.challenges
            .insert(user_id.to_string(), (challenge.clone(), Instant::now()));
        Ok(challenge)
    }

    async fn verify_response(
        &self,
        user_id: &str,
        pubkey_hex: &str,
        signature_hex: &str,
    ) -> Result<SchnorrAssertion, SchnorrError> {
        use k256::schnorr::{signature::Verifier, Signature, VerifyingKey};

        // 1. Look up & remove — one-shot semantics. Any outcome
        //    below consumes the challenge.
        let (_, (challenge, issued_at)) = self
            .challenges
            .remove(user_id)
            .ok_or_else(|| SchnorrError::Challenge("no active challenge for user".into()))?;

        // 2. TTL check.
        if issued_at.elapsed() > self.ttl {
            return Err(SchnorrError::Challenge("expired".into()));
        }

        // 3. Parse pubkey + signature.
        let pub_bytes =
            hex::decode(pubkey_hex).map_err(|e| SchnorrError::Parse(format!("pubkey: {e}")))?;
        if pub_bytes.len() != 32 {
            return Err(SchnorrError::Parse(format!(
                "pubkey must be 32 bytes, got {}",
                pub_bytes.len()
            )));
        }
        let sig_bytes = hex::decode(signature_hex)
            .map_err(|e| SchnorrError::Parse(format!("signature: {e}")))?;
        if sig_bytes.len() != 64 {
            return Err(SchnorrError::Parse(format!(
                "signature must be 64 bytes, got {}",
                sig_bytes.len()
            )));
        }

        // 4. Verify BIP-340 Schnorr signature of the canonical
        //    digest. We use k256 directly here to keep the public
        //    API of `solid_pod_rs::auth::nip98::verify_schnorr_signature`
        //    focused on NIP-98 events (kind 27235). The underlying
        //    cryptography is identical to what that helper enforces
        //    and is exercised by the core crate's tests under the
        //    `nip98-schnorr` feature.
        let vk = VerifyingKey::from_bytes(&pub_bytes)
            .map_err(|e| SchnorrError::Parse(format!("pubkey parse: {e}")))?;
        let sig = Signature::try_from(sig_bytes.as_slice())
            .map_err(|e| SchnorrError::Parse(format!("signature parse: {e}")))?;
        let digest = Self::canonical_digest(&challenge.token, user_id, pubkey_hex);
        vk.verify(&digest, &sig)
            .map_err(|e| SchnorrError::InvalidSignature(e.to_string()))?;

        let verified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Ok(SchnorrAssertion {
            user_id: user_id.to_string(),
            pubkey: pubkey_hex.to_string(),
            verified_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn todo_backend_is_callable_and_returns_unimplemented() {
        let backend = SchnorrTodo;
        assert!(matches!(
            backend.issue_challenge("alice").await.unwrap_err(),
            SchnorrError::Unimplemented
        ));
        assert!(matches!(
            backend
                .verify_response("alice", "pub", "sig")
                .await
                .unwrap_err(),
            SchnorrError::Unimplemented
        ));
    }
}
