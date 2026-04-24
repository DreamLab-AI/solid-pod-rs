//! # solid-pod-rs-didkey
//!
//! W3C `did:key` (Ed25519 / P-256 / secp256k1) support for solid-pod-rs:
//!
//! - [`pubkey`] — codec-aware parse / encode for the three supported
//!   key types.
//! - [`did`]    — `did:key:z…` multibase identifier encoder / decoder.
//! - [`jwt`]    — self-signed compact JWT verifier that binds to an
//!   embedded `did:key` via the header's `kid` or `jwk` member.
//! - [`verifier`] — [`crate::verifier::DidKeyVerifier`] — a
//!   [`solid_pod_rs::SelfSignedVerifier`] impl that plugs into the
//!   [`solid_pod_rs::CidVerifier`] dispatcher.
//!
//! Spec references:
//! - W3C DID Method `key` (Working Draft):
//!   <https://w3c-ccg.github.io/did-method-key/>
//! - Multicodec table: <https://github.com/multiformats/multicodec/blob/master/table.csv>
//! - RFC 7519 (JWT), RFC 7515 (JWS), RFC 8037 (EdDSA JOSE).
//!
//! Sprint 11 — row 153.

#![deny(unsafe_code)]
#![warn(rust_2018_idioms)]

pub mod did;
pub mod error;
pub mod jwt;
pub mod pubkey;
pub mod verifier;

pub use did::{decode as decode_did_key, encode as encode_did_key};
pub use error::DidKeyError;
pub use jwt::{verify_self_signed_jwt, VerifiedJwt};
pub use pubkey::DidKeyPubkey;
pub use verifier::DidKeyVerifier;
