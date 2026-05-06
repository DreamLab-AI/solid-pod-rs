//! # solid-pod-rs-didkey
//!
//! `did:key` resolver and self-signed JWT verifier for
//! [`solid-pod-rs`](https://crates.io/crates/solid-pod-rs).
//! Supports Ed25519, P-256, and secp256k1 key types.
//!
//! ## Modules
//!
//! - [`did`]      — `did:key:z...` multibase identifier encoding and decoding.
//! - [`pubkey`]   — Codec-aware public-key representation ([`DidKeyPubkey`]).
//! - [`jwt`]      — Self-signed compact JWT (JWS) verifier bound to a `did:key`.
//! - [`verifier`] — [`DidKeyVerifier`] implementing `solid_pod_rs::SelfSignedVerifier`.
//! - [`error`]    — [`DidKeyError`] covering parse, crypto, and JWT failures.
//!
//! ## Quick start
//!
//! ```no_run
//! use solid_pod_rs_didkey::{decode_did_key, encode_did_key, verify_self_signed_jwt};
//!
//! // Resolve a did:key identifier to its public key.
//! let did = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";
//! let pubkey = decode_did_key(did).unwrap();
//!
//! // Round-trip back to the canonical did:key string.
//! assert_eq!(encode_did_key(&pubkey), did);
//! ```
//!
//! ## Spec references
//!
//! - W3C DID Method `key`: <https://w3c-ccg.github.io/did-method-key/>
//! - Multicodec table: <https://github.com/multiformats/multicodec/blob/master/table.csv>
//! - RFC 7519 (JWT), RFC 7515 (JWS), RFC 8037 (EdDSA JOSE).

#![doc = include_str!("../README.md")]

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
