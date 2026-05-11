//! # solid-pod-rs-idp
//!
//! Solid-OIDC identity provider for
//! [`solid-pod-rs`](https://crates.io/crates/solid-pod-rs) --
//! authorization-code flow, DPoP-bound tokens, JWKS publication,
//! dynamic client registration, and credentials login.
//!
//! ## Feature flags
//!
//! | Flag           | Purpose                                               |
//! |----------------|-------------------------------------------------------|
//! | `axum-binder`  | Ready-made axum `Router` that wires all IdP endpoints.|
//! | `passkey`      | WebAuthn/passkey authentication via `webauthn-rs`.    |
//! | `schnorr-sso`  | NIP-07 Schnorr SSO (Nostr key login).                 |
//!
//! ## Modules
//!
//! - [`provider`]     — [`Provider`] orchestrator: `/auth`, `/token`, `/me` endpoints.
//! - [`discovery`]    — OIDC discovery document builder (`/.well-known/openid-configuration`).
//! - [`jwks`]         — JWKS key management and `/.well-known/jwks.json` publication.
//! - [`credentials`]  — Email + password login flow with rate limiting.
//! - [`registration`] — Dynamic Client Registration and Client Identifier Documents.
//! - [`tokens`]       — DPoP-bound access-token issuance.
//! - [`session`]      — Opaque-token session store.
//! - [`user_store`]   — Pluggable [`UserStore`] trait with [`InMemoryUserStore`] for tests.
//! - [`invites`]      — Invite-token minting, storage, and validation.
//! - [`error`]        — [`ProviderError`] with RFC 6749 error codes.
//! - [`passkey`]      — *(feature `passkey`)* WebAuthn registration and authentication.
//! - [`schnorr`]      — *(feature `schnorr-sso`)* NIP-07 Schnorr challenge/response.
//! - [`axum_binder`]  — *(feature `axum-binder`)* Pre-built axum router.
//!
//! ## Quick start
//!
//! ```rust,ignore
//! use solid_pod_rs_idp::{Provider, ProviderConfig, Jwks, SessionStore,
//!     registration::ClientStore, user_store::InMemoryUserStore};
//! use std::sync::Arc;
//!
//! let user_store = Arc::new(InMemoryUserStore::new());
//! let jwks = Jwks::generate_es256().unwrap();
//! let provider = Provider::new(
//!     ProviderConfig::new("https://pod.example/"),
//!     ClientStore::new(), SessionStore::new(), user_store, jwks,
//! );
//! let _disco = provider.discovery_document();
//! ```
//!
//! ## Design boundaries
//!
//! - This crate owns **protocol logic** only. Transport framing is the
//!   consumer's job: plug [`Provider`] into your own router, or enable
//!   the `axum-binder` feature for a ready-made `Router`.
//! - Storage is pluggable via [`UserStore`]. The built-in
//!   [`InMemoryUserStore`] exists for tests and single-user
//!   development; production deployments should ship a persistent store.
//! - DPoP verification delegates to `solid_pod_rs::oidc::verify_dpop_proof`.
//! - SSRF protection on Client Identifier Document fetches delegates to
//!   `solid_pod_rs::security::is_safe_url`.
//! - Rate-limiting uses the core `RateLimiter` trait.

#![doc = include_str!("../README.md")]
#![warn(rust_2018_idioms)]
#![forbid(unsafe_code)]

pub mod account_delete;
pub mod credentials;
pub mod discovery;
pub mod error;
pub mod invites;
pub mod jwks;
pub mod password_change;
pub mod provider;
pub mod registration;
pub mod session;
pub mod tokens;
pub mod user_store;

#[cfg(feature = "passkey")]
pub mod passkey;

#[cfg(feature = "schnorr-sso")]
pub mod schnorr;

#[cfg(feature = "axum-binder")]
pub mod axum_binder;

pub use account_delete::{
    delete_account, AccountDeleteError, AccountDeleteRequest, AccountDeleteResponse,
    CONFIRMATION_PHRASE,
};
pub use credentials::{
    login, validate_password_length, CredentialsResponse, LoginError, MIN_PASSWORD_LENGTH,
};
pub use discovery::{build_discovery, DiscoveryDocument};
pub use error::ProviderError;
pub use invites::{
    mint_token as mint_invite_token, parse_duration as parse_invite_duration, InMemoryInviteStore,
    Invite, InviteStore, InviteStoreError,
};
pub use jwks::{Jwks, JwksError, SigningKey};
pub use password_change::{
    change_password, PasswordChangeError, PasswordChangeRequest, PasswordChangeResponse,
};
pub use provider::{
    AuthorizeRequest, AuthorizeResponse, Provider, ProviderConfig, TokenRequest, TokenResponse,
    UserInfo,
};
pub use registration::{
    register_client, ClientDocument, ClientStore, RegError, RegistrationRequest,
};
pub use session::{SessionError, SessionId, SessionStore};
pub use tokens::{issue_access_token, AccessToken, TokenError};
pub use user_store::{InMemoryUserStore, User, UserStore, UserStoreError};
