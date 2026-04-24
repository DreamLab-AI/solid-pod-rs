//! WebAuthn / passkey support (row 80 — Sprint 11: full wiring).
//!
//! This module exposes:
//!
//! 1. The [`PasskeyBackend`] trait — the stable contract the IdP
//!    uses to issue and verify passkey ceremonies.
//! 2. [`WebauthnPasskey`] — a production-leaning implementation
//!    backed by [`webauthn-rs`] 0.5. It covers the happy path a
//!    Solid-OIDC passkey flow needs: register-options /
//!    register-verify / login-options / login-verify.
//! 3. [`NullPasskeyBackend`] — retained as a `#[doc(hidden)]`
//!    test fallback so integrators can wire the provider before
//!    bringing in `webauthn-rs`.
//!
//! # Scope honesty
//!
//! `webauthn-rs` carries roughly thirty configuration knobs
//! (attestation CA lists, attachment hints, residency preferences,
//! subdomain policies, timeouts, etc.). [`WebauthnPasskey::new`]
//! picks a sensible default: single-step registration, `ES256` +
//! `EdDSA` as the preferred COSE algorithms, user-verification
//! required (the 0.5 default), no subdomain relaxation. Integrators
//! with stricter requirements (e.g. attestation pinning) should
//! drop `WebauthnPasskey` and plumb their own
//! `Arc<webauthn_rs::Webauthn>` into a custom [`PasskeyBackend`]
//! impl — the trait is deliberately small enough to make that
//! trivial.
//!
//! We also ship the per-user challenge state in an in-memory
//! [`dashmap::DashMap`]. That is appropriate for single-node
//! deployments and short-lived ceremonies (the WebAuthn spec
//! recommends 5-minute challenges). Multi-node deployments should
//! externalise the state (Redis, sticky sessions, etc) and
//! implement [`PasskeyBackend`] directly.
//!
//! JSS parity: `src/idp/passkey.js` (~180 LOC built on
//! `@simplewebauthn/server`).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(feature = "passkey")]
use std::sync::Arc;

#[cfg(feature = "passkey")]
use dashmap::DashMap;

#[cfg(feature = "passkey")]
use url::Url;

#[cfg(feature = "passkey")]
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Uuid,
};
#[cfg(feature = "passkey")]
use webauthn_rs::{Webauthn, WebauthnBuilder};

/// Errors surfaced by a [`PasskeyBackend`].
#[derive(Debug, Error)]
pub enum PasskeyError {
    /// Backend not implemented (the `PasskeyTodo` / Null impl).
    #[error("passkey backend not implemented")]
    Unimplemented,
    /// Attestation / assertion verification failed.
    #[error("verification failed: {0}")]
    Verification(String),
    /// Backing store error (credential lookup, etc.).
    #[error("backend: {0}")]
    Backend(String),
    /// Configuration failure on [`WebauthnPasskey`] construction.
    #[error("configuration: {0}")]
    Config(String),
    /// The supplied challenge token (e.g. `account_id`) has no in-
    /// flight registration / authentication state. Either never
    /// started, already consumed, or evicted.
    #[error("no in-flight ceremony for user: {0}")]
    NoCeremony(String),
    /// Incoming response failed JSON deserialisation into the shape
    /// `webauthn-rs` expects.
    #[error("response parse: {0}")]
    Parse(String),
}

/// Registration options returned to the browser navigator API.
/// Matches the shape that `@simplewebauthn/browser` expects in
/// `startRegistration(options)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationOptions {
    /// Opaque JSON blob the browser hands back on assertion.
    #[serde(flatten)]
    pub raw: serde_json::Value,
}

/// Registration response from the browser (the attestation bundle).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationResponse {
    /// Credential id (base64url).
    pub id: String,
    /// Attestation object + clientDataJSON.
    #[serde(flatten)]
    pub raw: serde_json::Value,
}

/// Authentication options (sign-in challenge).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationOptions {
    #[serde(flatten)]
    pub raw: serde_json::Value,
}

/// Authentication response (the assertion bundle from the navigator).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationResponse {
    pub id: String,
    #[serde(flatten)]
    pub raw: serde_json::Value,
}

/// Minimal WebAuthn contract for the IdP.
#[async_trait]
pub trait PasskeyBackend: Send + Sync + 'static {
    /// Start a passkey registration ceremony for the given account.
    async fn registration_options(
        &self,
        account_id: &str,
    ) -> Result<RegistrationOptions, PasskeyError>;

    /// Verify an attestation response, persisting the resulting
    /// public-key credential against `account_id`.
    async fn registration_verify(
        &self,
        account_id: &str,
        resp: RegistrationResponse,
    ) -> Result<(), PasskeyError>;

    /// Start an assertion ceremony for `account_id`.
    async fn authentication_options(
        &self,
        account_id: &str,
    ) -> Result<AuthenticationOptions, PasskeyError>;

    /// Verify an assertion response. Returns the account id on
    /// success (lets the backend confirm or choose the user).
    async fn authentication_verify(
        &self,
        resp: AuthenticationResponse,
    ) -> Result<String, PasskeyError>;
}

/// Test-only fallback. Every call returns
/// [`PasskeyError::Unimplemented`]. Kept so integrators who have not
/// yet wired a real backend can still instantiate the provider in
/// unit tests.
#[doc(hidden)]
pub struct PasskeyTodo;

/// Backward-compatible alias for the Sprint-10 name.
#[doc(hidden)]
pub type NullPasskeyBackend = PasskeyTodo;

#[async_trait]
impl PasskeyBackend for PasskeyTodo {
    async fn registration_options(
        &self,
        _account_id: &str,
    ) -> Result<RegistrationOptions, PasskeyError> {
        Err(PasskeyError::Unimplemented)
    }

    async fn registration_verify(
        &self,
        _account_id: &str,
        _resp: RegistrationResponse,
    ) -> Result<(), PasskeyError> {
        Err(PasskeyError::Unimplemented)
    }

    async fn authentication_options(
        &self,
        _account_id: &str,
    ) -> Result<AuthenticationOptions, PasskeyError> {
        Err(PasskeyError::Unimplemented)
    }

    async fn authentication_verify(
        &self,
        _resp: AuthenticationResponse,
    ) -> Result<String, PasskeyError> {
        Err(PasskeyError::Unimplemented)
    }
}

// ---------------------------------------------------------------
// Real impl — webauthn-rs 0.5 backed.
// ---------------------------------------------------------------

/// Production-leaning WebAuthn backend built on [`webauthn-rs`] 0.5.
///
/// # Defaults
///
/// * `rp_id` / `rp_name` / `origin` come from [`WebauthnPasskey::new`].
/// * Single-step registration (no attestation CA pinning).
/// * COSE algorithms preferred: `EdDSA`, `ES256` — the webauthn-rs
///   default set.
/// * User-verification required (webauthn-rs 0.5 default).
/// * No subdomain wildcarding.
///
/// For stricter policies (attestation CA pinning, `PreferredAuthenticatorAttachment`,
/// etc) implement [`PasskeyBackend`] against your own
/// `webauthn_rs::Webauthn` instance.
#[cfg(feature = "passkey")]
pub struct WebauthnPasskey {
    webauthn: Arc<Webauthn>,
    registration_state: DashMap<String, PasskeyRegistration>,
    authentication_state: DashMap<String, PasskeyAuthentication>,
    /// Per-account list of registered passkeys. Production
    /// deployments MUST replace this with a persistent store;
    /// `WebauthnPasskey` persists to memory to keep the wrapper
    /// self-contained for tests and single-node demos.
    credentials: DashMap<String, Vec<Passkey>>,
}

#[cfg(feature = "passkey")]
impl WebauthnPasskey {
    /// Build a fresh [`WebauthnPasskey`] for the given relying-party
    /// identity.
    ///
    /// * `rp_id` — the registrable domain part of the IdP origin
    ///   (e.g. `example.com`). **This cannot be changed without
    ///   invalidating every registered credential.**
    /// * `rp_name` — human-readable display name the authenticator
    ///   may show to the user during ceremonies.
    /// * `origin` — the full origin URL (scheme + host + optional
    ///   port) the browser will send as `clientDataJSON.origin`.
    pub fn new(rp_id: &str, rp_name: &str, origin: &Url) -> Result<Self, PasskeyError> {
        let builder = WebauthnBuilder::new(rp_id, origin)
            .map_err(|e| PasskeyError::Config(e.to_string()))?
            .rp_name(rp_name);
        let webauthn = builder
            .build()
            .map_err(|e| PasskeyError::Config(e.to_string()))?;
        Ok(Self {
            webauthn: Arc::new(webauthn),
            registration_state: DashMap::new(),
            authentication_state: DashMap::new(),
            credentials: DashMap::new(),
        })
    }

    /// Deterministically hash an opaque `account_id` string to the
    /// 16-byte UUID that `webauthn-rs` requires as `user_unique_id`.
    /// Using a hash keeps the user handle stable across ceremonies
    /// without persisting a separate mapping.
    fn account_uuid(account_id: &str) -> Uuid {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(account_id.as_bytes());
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        // Force RFC 4122 v4 layout so the Uuid is well-formed.
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Uuid::from_bytes(bytes)
    }

    /// Read-only access to the stored credentials for `account_id`.
    /// Mainly intended for tests that want to assert the finish
    /// step actually persisted something.
    pub fn credentials_for(&self, account_id: &str) -> Vec<Passkey> {
        self.credentials
            .get(account_id)
            .map(|v| v.clone())
            .unwrap_or_default()
    }
}

#[cfg(feature = "passkey")]
#[async_trait]
impl PasskeyBackend for WebauthnPasskey {
    async fn registration_options(
        &self,
        account_id: &str,
    ) -> Result<RegistrationOptions, PasskeyError> {
        let uuid = Self::account_uuid(account_id);
        let existing: Vec<_> = self
            .credentials_for(account_id)
            .iter()
            .map(|p| p.cred_id().clone())
            .collect();
        let exclude = if existing.is_empty() {
            None
        } else {
            Some(existing)
        };
        let (ccr, state): (CreationChallengeResponse, PasskeyRegistration) = self
            .webauthn
            .start_passkey_registration(uuid, account_id, account_id, exclude)
            .map_err(|e| PasskeyError::Verification(e.to_string()))?;
        self.registration_state
            .insert(account_id.to_string(), state);
        let raw = serde_json::to_value(&ccr)
            .map_err(|e| PasskeyError::Backend(format!("serialise ccr: {e}")))?;
        Ok(RegistrationOptions { raw })
    }

    async fn registration_verify(
        &self,
        account_id: &str,
        resp: RegistrationResponse,
    ) -> Result<(), PasskeyError> {
        let (_, state) = self
            .registration_state
            .remove(account_id)
            .ok_or_else(|| PasskeyError::NoCeremony(account_id.to_string()))?;
        // The entire `resp` value (including the flattened `id`)
        // deserialises into `RegisterPublicKeyCredential`. Rebuild
        // the full JSON view first so we don't drop `id`.
        let mut value = resp.raw.clone();
        if let serde_json::Value::Object(ref mut map) = value {
            map.insert("id".into(), serde_json::Value::String(resp.id.clone()));
        }
        let reg: RegisterPublicKeyCredential = serde_json::from_value(value)
            .map_err(|e| PasskeyError::Parse(e.to_string()))?;
        let passkey = self
            .webauthn
            .finish_passkey_registration(&reg, &state)
            .map_err(|e| PasskeyError::Verification(e.to_string()))?;
        self.credentials
            .entry(account_id.to_string())
            .or_default()
            .push(passkey);
        Ok(())
    }

    async fn authentication_options(
        &self,
        account_id: &str,
    ) -> Result<AuthenticationOptions, PasskeyError> {
        let creds = self.credentials_for(account_id);
        if creds.is_empty() {
            return Err(PasskeyError::NoCeremony(format!(
                "no passkeys registered for {account_id}"
            )));
        }
        let (rcr, state): (RequestChallengeResponse, PasskeyAuthentication) = self
            .webauthn
            .start_passkey_authentication(&creds)
            .map_err(|e| PasskeyError::Verification(e.to_string()))?;
        self.authentication_state
            .insert(account_id.to_string(), state);
        let raw = serde_json::to_value(&rcr)
            .map_err(|e| PasskeyError::Backend(format!("serialise rcr: {e}")))?;
        Ok(AuthenticationOptions { raw })
    }

    async fn authentication_verify(
        &self,
        resp: AuthenticationResponse,
    ) -> Result<String, PasskeyError> {
        // Find the in-flight authentication. The AuthenticationResponse
        // carries the credential id; we scan for the account whose
        // registered credentials include it. In real deployments the
        // consumer supplies the account_id out-of-band (cookie,
        // login form), so this scan is a convenience fallback.
        let mut matched: Option<String> = None;
        for cred_entry in self.credentials.iter() {
            if cred_entry
                .value()
                .iter()
                .any(|p| base64url_matches(p.cred_id().as_ref(), &resp.id))
            {
                matched = Some(cred_entry.key().clone());
                break;
            }
        }
        let account_id = matched
            .ok_or_else(|| PasskeyError::Verification(format!("unknown credential {}", resp.id)))?;
        let (_, state) = self
            .authentication_state
            .remove(&account_id)
            .ok_or_else(|| PasskeyError::NoCeremony(account_id.clone()))?;

        let mut value = resp.raw.clone();
        if let serde_json::Value::Object(ref mut map) = value {
            map.insert("id".into(), serde_json::Value::String(resp.id.clone()));
        }
        let cred: PublicKeyCredential = serde_json::from_value(value)
            .map_err(|e| PasskeyError::Parse(e.to_string()))?;
        self.webauthn
            .finish_passkey_authentication(&cred, &state)
            .map_err(|e| PasskeyError::Verification(e.to_string()))?;
        Ok(account_id)
    }
}

/// base64url comparator that tolerates padded / unpadded encodings.
#[cfg(feature = "passkey")]
fn base64url_matches(bin: &[u8], txt: &str) -> bool {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let encoded = URL_SAFE_NO_PAD.encode(bin);
    encoded == txt.trim_end_matches('=')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn passkey_todo_is_callable_and_returns_unimplemented() {
        let backend = PasskeyTodo;
        let err = backend.registration_options("acct-1").await.unwrap_err();
        assert!(matches!(err, PasskeyError::Unimplemented));
        let err = backend
            .authentication_options("acct-1")
            .await
            .unwrap_err();
        assert!(matches!(err, PasskeyError::Unimplemented));
    }

    #[cfg(feature = "passkey")]
    #[tokio::test]
    async fn webauthn_passkey_constructs_with_reasonable_defaults() {
        let origin = Url::parse("https://idp.example.com").unwrap();
        let _pk = WebauthnPasskey::new("idp.example.com", "Example IdP", &origin)
            .expect("WebauthnPasskey::new with defaults");
    }

    #[cfg(feature = "passkey")]
    #[tokio::test]
    async fn start_registration_returns_non_empty_challenge() {
        let origin = Url::parse("https://idp.example.com").unwrap();
        let pk = WebauthnPasskey::new("idp.example.com", "Example IdP", &origin).unwrap();
        let opts = pk.registration_options("alice").await.unwrap();
        // webauthn-rs surfaces the challenge under publicKey.challenge.
        let challenge = opts
            .raw
            .pointer("/publicKey/challenge")
            .and_then(|v| v.as_str())
            .expect("challenge string present");
        assert!(!challenge.is_empty(), "challenge should be non-empty");

        // State must have been stored for the user.
        assert!(
            pk.registration_state.contains_key("alice"),
            "registration state recorded for alice"
        );
    }

    #[cfg(feature = "passkey")]
    #[tokio::test]
    async fn start_registration_is_isolated_per_user() {
        let origin = Url::parse("https://idp.example.com").unwrap();
        let pk = WebauthnPasskey::new("idp.example.com", "Example IdP", &origin).unwrap();
        pk.registration_options("alice").await.unwrap();
        pk.registration_options("bob").await.unwrap();
        assert!(pk.registration_state.contains_key("alice"));
        assert!(pk.registration_state.contains_key("bob"));
        assert_eq!(
            pk.registration_state.len(),
            2,
            "per-user isolation retains both states"
        );
    }

    #[cfg(feature = "passkey")]
    #[tokio::test]
    async fn registration_verify_without_start_is_rejected() {
        let origin = Url::parse("https://idp.example.com").unwrap();
        let pk = WebauthnPasskey::new("idp.example.com", "Example IdP", &origin).unwrap();
        let err = pk
            .registration_verify(
                "ghost",
                RegistrationResponse {
                    id: "abc".into(),
                    raw: serde_json::json!({}),
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, PasskeyError::NoCeremony(_)));
    }

    #[cfg(feature = "passkey")]
    #[tokio::test]
    async fn authentication_options_rejects_user_with_no_credentials() {
        let origin = Url::parse("https://idp.example.com").unwrap();
        let pk = WebauthnPasskey::new("idp.example.com", "Example IdP", &origin).unwrap();
        let err = pk
            .authentication_options("never-registered")
            .await
            .unwrap_err();
        assert!(matches!(err, PasskeyError::NoCeremony(_)));
    }

    #[cfg(feature = "passkey")]
    #[tokio::test]
    async fn account_uuid_is_deterministic_and_v4() {
        let a = WebauthnPasskey::account_uuid("alice");
        let a2 = WebauthnPasskey::account_uuid("alice");
        let b = WebauthnPasskey::account_uuid("bob");
        assert_eq!(a, a2, "deterministic");
        assert_ne!(a, b, "per-user unique");
        assert_eq!(a.get_version_num(), 4, "RFC 4122 v4");
    }
}
