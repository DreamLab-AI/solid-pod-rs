//! # solid-pod-rs-idp
//!
//! Minimum-viable Solid-OIDC identity provider. Port of the JSS IdP
//! (`JavaScriptSolidServer/src/idp/*`). Target parity rows:
//!
//! | Row | JSS ref                     | Status        |
//! |-----|-----------------------------|---------------|
//! | 74  | `/auth` endpoint            | present       |
//! | 75  | Dynamic Client Registration | present       |
//! | 76  | OIDC discovery              | present       |
//! | 77  | `/.well-known/jwks.json`    | present       |
//! | 78  | Client Identifier Documents | present       |
//! | 79  | Credentials flow + rate-lim | present       |
//! | 80  | Passkeys / WebAuthn         | partial-parity (trait hook behind `passkey` feature) |
//! | 81  | Schnorr SSO (NIP-07)        | partial-parity (trait hook behind `schnorr-sso`)     |
//! | 82  | HTML interaction pages      | wontfix-in-crate (operator view-layer choice; see README) |
//! | 130 | JWKS publication (IdP side) | present       |
//!
//! ## Design boundaries
//!
//! - This crate owns **protocol logic**. Transport framing is the
//!   consumer's problem: either plug `Provider` into your own
//!   router, or enable the `axum-binder` feature for a ready-made
//!   Router.
//! - Storage is pluggable via [`UserStore`]. The built-in
//!   [`InMemoryUserStore`] exists for tests and single-user
//!   development; production deployments MUST ship their own
//!   persistent store.
//! - DPoP verification is delegated to
//!   `solid_pod_rs::oidc::verify_dpop_proof`, so we never duplicate
//!   the RFC 9449 alg-dispatch rules that already ship in core.
//! - SSRF protection on Client Identifier Document fetches is
//!   delegated to `solid_pod_rs::security::is_safe_url`.
//! - Rate-limiting uses the core `RateLimiter` trait; callers can
//!   substitute any implementation (Redis, sharded, etc).
//!
//! ## What this crate deliberately does NOT do
//!
//! - **HTML pages** — row 82. JSS bundles handlebars templates; this
//!   crate leaves the view layer to the consumer. A minimal Askama /
//!   Leptos adapter is trivially < 300 LOC on top of this crate.
//! - **Full WebAuthn flow** — row 80. The `webauthn-rs` integration is
//!   ~400 LOC of fixture wiring; we ship the trait shape so it can
//!   be added in a follow-up sprint without breaking API.
//! - **Full NIP-07 handshake** — row 81. Same story: trait hook now,
//!   real verification lives behind the `schnorr-sso` feature in a
//!   follow-up.

#![warn(rust_2018_idioms)]
#![forbid(unsafe_code)]

pub mod credentials;
pub mod discovery;
pub mod error;
pub mod jwks;
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

pub use credentials::{login, CredentialsResponse, LoginError};
pub use discovery::{build_discovery, DiscoveryDocument};
pub use error::ProviderError;
pub use jwks::{Jwks, JwksError, SigningKey};
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
