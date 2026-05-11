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
use crate::user_store::UserStore;
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

    /// Typed-username VM fallback: verify a Schnorr response with a
    /// fallback that resolves the pubkey from the user's profile when
    /// `did:nostr` resolution fails.
    ///
    /// Flow:
    /// 1. Try the normal `verify_response` path (caller-supplied pubkey).
    /// 2. If that fails and `username` is `Some`, look up the account by
    ///    username, fetch `nostr_pubkey` from the profile's
    ///    `verificationMethod`, and re-verify the signature against that
    ///    key.
    ///
    /// This prevents the typed-username fallback from being used as a
    /// pubkey oracle: the challenge is consumed on the first attempt, so
    /// the fallback operates on the same one-shot challenge.
    pub async fn verify_response_with_username_fallback(
        &self,
        user_id: &str,
        pubkey_hex: &str,
        signature_hex: &str,
        username: Option<&str>,
        user_store: &dyn UserStore,
    ) -> Result<SchnorrAssertion, SchnorrError> {
        use k256::schnorr::{signature::Verifier, Signature, VerifyingKey};

        // 1. Look up & remove challenge — one-shot semantics.
        let (_, (challenge, issued_at)) = self
            .challenges
            .remove(user_id)
            .ok_or_else(|| SchnorrError::Challenge("no active challenge for user".into()))?;

        if issued_at.elapsed() > self.ttl {
            return Err(SchnorrError::Challenge("expired".into()));
        }

        // Parse signature (shared across both paths).
        let sig_bytes = hex::decode(signature_hex)
            .map_err(|e| SchnorrError::Parse(format!("signature: {e}")))?;
        if sig_bytes.len() != 64 {
            return Err(SchnorrError::Parse(format!(
                "signature must be 64 bytes, got {}",
                sig_bytes.len()
            )));
        }
        let sig = Signature::try_from(sig_bytes.as_slice())
            .map_err(|e| SchnorrError::Parse(format!("signature parse: {e}")))?;

        // 2. Try caller-supplied pubkey first.
        let pub_bytes =
            hex::decode(pubkey_hex).map_err(|e| SchnorrError::Parse(format!("pubkey: {e}")))?;
        if pub_bytes.len() == 32 {
            if let Ok(vk) = VerifyingKey::from_bytes(&pub_bytes) {
                let digest = Self::canonical_digest(&challenge.token, user_id, pubkey_hex);
                if vk.verify(&digest, &sig).is_ok() {
                    let verified_at = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    return Ok(SchnorrAssertion {
                        user_id: user_id.to_string(),
                        pubkey: pubkey_hex.to_string(),
                        verified_at,
                    });
                }
            }
        }

        // 3. Fallback: look up by username, get profile verificationMethod key.
        let username = username.ok_or_else(|| {
            SchnorrError::InvalidSignature(
                "caller-supplied pubkey verification failed and no username provided for fallback"
                    .into(),
            )
        })?;

        let user = user_store
            .find_by_username(username)
            .await
            .map_err(|e| SchnorrError::UnknownNpub(format!("user store error: {e}")))?
            .ok_or_else(|| {
                SchnorrError::UnknownNpub(format!("no account for username: {username}"))
            })?;

        let profile_pubkey_hex = user.nostr_pubkey.ok_or_else(|| {
            SchnorrError::UnknownNpub(format!(
                "account '{}' has no nostr_pubkey verificationMethod",
                username
            ))
        })?;

        // 4. Verify the signature against the profile's verificationMethod key.
        let profile_pub_bytes = hex::decode(&profile_pubkey_hex)
            .map_err(|e| SchnorrError::Parse(format!("profile pubkey: {e}")))?;
        if profile_pub_bytes.len() != 32 {
            return Err(SchnorrError::Parse(format!(
                "profile pubkey must be 32 bytes, got {}",
                profile_pub_bytes.len()
            )));
        }
        let profile_vk = VerifyingKey::from_bytes(&profile_pub_bytes)
            .map_err(|e| SchnorrError::Parse(format!("profile pubkey parse: {e}")))?;

        // The digest uses the *profile* pubkey, not the caller-supplied one,
        // because the client signed against the key they hold (which should
        // match the profile's verificationMethod).
        let digest = Self::canonical_digest(&challenge.token, user_id, &profile_pubkey_hex);
        profile_vk
            .verify(&digest, &sig)
            .map_err(|e| SchnorrError::InvalidSignature(e.to_string()))?;

        let verified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Ok(SchnorrAssertion {
            user_id: user_id.to_string(),
            pubkey: profile_pubkey_hex,
            verified_at,
        })
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

    #[cfg(feature = "schnorr-sso")]
    mod username_fallback {
        use super::*;
        use crate::user_store::InMemoryUserStore;
        use k256::schnorr::{signature::Signer, SigningKey};
        use std::time::Duration;

        fn make_sso() -> Nip07SchnorrSso {
            Nip07SchnorrSso::new(Duration::from_secs(300))
        }

        fn make_signing_key() -> SigningKey {
            SigningKey::from_bytes(&[0x42; 32]).unwrap()
        }

        fn pubkey_hex(sk: &SigningKey) -> String {
            hex::encode(sk.verifying_key().to_bytes())
        }

        #[tokio::test]
        async fn fallback_resolves_pubkey_from_username() {
            let sso = make_sso();
            let sk = make_signing_key();
            let pk_hex = pubkey_hex(&sk);

            // Store a user with username and nostr_pubkey.
            let store = InMemoryUserStore::new();
            store
                .insert_user_with_nostr(
                    "u-1",
                    "alice@example.com",
                    "https://alice.example/profile#me",
                    Some("Alice".into()),
                    "password123",
                    Some("alice".into()),
                    Some(pk_hex.clone()),
                )
                .unwrap();

            // Issue challenge.
            let challenge = sso.issue_challenge("u-1").await.unwrap();

            // Client signs with the profile key.
            let digest = Nip07SchnorrSso::canonical_digest(&challenge.token, "u-1", &pk_hex);
            let sig: k256::schnorr::Signature = sk.sign(&digest);
            let sig_hex = hex::encode(sig.to_bytes());

            // Verify with a WRONG caller-supplied pubkey but correct username.
            let wrong_pk = "a".repeat(64);
            let result = sso
                .verify_response_with_username_fallback(
                    "u-1",
                    &wrong_pk,
                    &sig_hex,
                    Some("alice"),
                    &store,
                )
                .await
                .unwrap();

            assert_eq!(result.user_id, "u-1");
            assert_eq!(result.pubkey, pk_hex);
        }

        #[tokio::test]
        async fn fallback_succeeds_with_direct_pubkey() {
            let sso = make_sso();
            let sk = make_signing_key();
            let pk_hex = pubkey_hex(&sk);

            let store = InMemoryUserStore::new();

            let challenge = sso.issue_challenge("u-2").await.unwrap();
            let digest = Nip07SchnorrSso::canonical_digest(&challenge.token, "u-2", &pk_hex);
            let sig: k256::schnorr::Signature = sk.sign(&digest);
            let sig_hex = hex::encode(sig.to_bytes());

            // Direct pubkey verification succeeds without needing fallback.
            let result = sso
                .verify_response_with_username_fallback("u-2", &pk_hex, &sig_hex, None, &store)
                .await
                .unwrap();

            assert_eq!(result.user_id, "u-2");
            assert_eq!(result.pubkey, pk_hex);
        }

        #[tokio::test]
        async fn fallback_fails_when_no_username_and_bad_pubkey() {
            let sso = make_sso();
            let sk = make_signing_key();
            let pk_hex = pubkey_hex(&sk);

            let store = InMemoryUserStore::new();

            let challenge = sso.issue_challenge("u-3").await.unwrap();
            let digest = Nip07SchnorrSso::canonical_digest(&challenge.token, "u-3", &pk_hex);
            let sig: k256::schnorr::Signature = sk.sign(&digest);
            let sig_hex = hex::encode(sig.to_bytes());

            let wrong_pk = "b".repeat(64);
            let err = sso
                .verify_response_with_username_fallback(
                    "u-3", &wrong_pk, &sig_hex, None, // no username
                    &store,
                )
                .await
                .unwrap_err();

            assert!(matches!(err, SchnorrError::InvalidSignature(_)));
        }

        #[tokio::test]
        async fn fallback_fails_when_username_not_found() {
            let sso = make_sso();
            let sk = make_signing_key();
            let pk_hex = pubkey_hex(&sk);

            let store = InMemoryUserStore::new();

            let challenge = sso.issue_challenge("u-4").await.unwrap();
            let digest = Nip07SchnorrSso::canonical_digest(&challenge.token, "u-4", &pk_hex);
            let sig: k256::schnorr::Signature = sk.sign(&digest);
            let sig_hex = hex::encode(sig.to_bytes());

            let wrong_pk = "c".repeat(64);
            let err = sso
                .verify_response_with_username_fallback(
                    "u-4",
                    &wrong_pk,
                    &sig_hex,
                    Some("nonexistent"),
                    &store,
                )
                .await
                .unwrap_err();

            assert!(matches!(err, SchnorrError::UnknownNpub(_)));
        }

        #[tokio::test]
        async fn fallback_fails_when_user_has_no_nostr_pubkey() {
            let sso = make_sso();
            let sk = make_signing_key();
            let pk_hex = pubkey_hex(&sk);

            let store = InMemoryUserStore::new();
            // User exists but has no nostr_pubkey.
            store
                .insert_user_with_nostr(
                    "u-5",
                    "bob@example.com",
                    "https://bob.example/profile#me",
                    None,
                    "password123",
                    Some("bob".into()),
                    None, // no nostr_pubkey
                )
                .unwrap();

            let challenge = sso.issue_challenge("u-5").await.unwrap();
            let digest = Nip07SchnorrSso::canonical_digest(&challenge.token, "u-5", &pk_hex);
            let sig: k256::schnorr::Signature = sk.sign(&digest);
            let sig_hex = hex::encode(sig.to_bytes());

            let wrong_pk = "d".repeat(64);
            let err = sso
                .verify_response_with_username_fallback(
                    "u-5",
                    &wrong_pk,
                    &sig_hex,
                    Some("bob"),
                    &store,
                )
                .await
                .unwrap_err();

            assert!(matches!(err, SchnorrError::UnknownNpub(_)));
        }

        #[tokio::test]
        async fn challenge_consumed_even_on_fallback_failure() {
            let sso = make_sso();
            let store = InMemoryUserStore::new();

            let _challenge = sso.issue_challenge("u-6").await.unwrap();

            // First attempt fails (bad sig, no username).
            let _ = sso
                .verify_response_with_username_fallback(
                    "u-6",
                    &"e".repeat(64),
                    &"f".repeat(128),
                    None,
                    &store,
                )
                .await;

            // Second attempt must fail with "no active challenge" since
            // the challenge was consumed on the first attempt.
            let err = sso
                .verify_response_with_username_fallback(
                    "u-6",
                    &"e".repeat(64),
                    &"f".repeat(128),
                    None,
                    &store,
                )
                .await
                .unwrap_err();

            assert!(matches!(err, SchnorrError::Challenge(_)));
        }

        #[tokio::test]
        async fn fallback_case_insensitive_username() {
            let sso = make_sso();
            let sk = make_signing_key();
            let pk_hex = pubkey_hex(&sk);

            let store = InMemoryUserStore::new();
            store
                .insert_user_with_nostr(
                    "u-7",
                    "carol@example.com",
                    "https://carol.example/profile#me",
                    None,
                    "password123",
                    Some("Carol".into()),
                    Some(pk_hex.clone()),
                )
                .unwrap();

            let challenge = sso.issue_challenge("u-7").await.unwrap();
            let digest = Nip07SchnorrSso::canonical_digest(&challenge.token, "u-7", &pk_hex);
            let sig: k256::schnorr::Signature = sk.sign(&digest);
            let sig_hex = hex::encode(sig.to_bytes());

            // Use different casing for username.
            let wrong_pk = "a".repeat(64);
            let result = sso
                .verify_response_with_username_fallback(
                    "u-7",
                    &wrong_pk,
                    &sig_hex,
                    Some("CAROL"),
                    &store,
                )
                .await
                .unwrap();

            assert_eq!(result.user_id, "u-7");
            assert_eq!(result.pubkey, pk_hex);
        }
    }
}
