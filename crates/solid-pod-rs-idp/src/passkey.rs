//! WebAuthn trait hook (row 80 — `partial-parity`).
//!
//! **Scope honesty:** Sprint 10 did NOT land a full WebAuthn flow.
//! A real implementation needs `webauthn-rs` (or equivalent) to
//! handle attestation statement parsing, RP-ID binding, counter
//! validation, credential-id storage, user-handle mapping, etc.
//! That's ~400 LOC of fixture-heavy code.
//!
//! What we DO ship in this crate:
//!
//! 1. A trait [`PasskeyBackend`] with the four operation types a
//!    Solid-OIDC passkey flow needs (register-options,
//!    register-verify, login-options, login-verify).
//! 2. A no-op [`NullPasskeyBackend`] that returns `Err(Unimplemented)`
//!    on every call. Consumers enabling the `passkey` feature
//!    before plugging in a real backend get a typed "this is not
//!    wired up yet" error rather than a silent pass.
//!
//! When a host app adds `webauthn-rs`, it implements
//! [`PasskeyBackend`] in its own crate and hands the
//! implementation to the IdP consumer wiring. No `solid-pod-rs-idp`
//! API change is required — that's the whole point of shipping the
//! trait now.
//!
//! JSS parity: `src/idp/passkey.js` (~180 LOC using
//! `@simplewebauthn/server`).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors surfaced by a [`PasskeyBackend`].
#[derive(Debug, Error)]
pub enum PasskeyError {
    /// Backend not implemented (typical of the Null impl).
    #[error("passkey backend not implemented")]
    Unimplemented,
    /// Attestation / assertion verification failed.
    #[error("verification failed: {0}")]
    Verification(String),
    /// Backing store error (credential lookup, etc.).
    #[error("backend: {0}")]
    Backend(String),
}

/// Registration options returned to the browser navigator API.
/// Matches the shape that `@simplewebauthn/browser` expects in
/// `startRegistration(options)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationOptions {
    /// Opaque JSON blob the browser hands back on assertion. We
    /// surface as serde JSON so the consumer can either pass it
    /// through verbatim or adapt to its framework's response type.
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
///
/// Implementations MUST be `Send + Sync` so the provider can hold
/// them in an `Arc`.
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

/// No-op implementation. Every call returns
/// [`PasskeyError::Unimplemented`]. Exists so downstream integrators
/// can wire `PasskeyBackend` into their `Provider` before a real
/// implementation lands.
pub struct NullPasskeyBackend;

#[async_trait]
impl PasskeyBackend for NullPasskeyBackend {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn null_backend_is_callable_and_returns_unimplemented() {
        let backend = NullPasskeyBackend;
        let err = backend.registration_options("acct-1").await.unwrap_err();
        assert!(matches!(err, PasskeyError::Unimplemented));
        let err = backend
            .authentication_options("acct-1")
            .await
            .unwrap_err();
        assert!(matches!(err, PasskeyError::Unimplemented));
    }
}
