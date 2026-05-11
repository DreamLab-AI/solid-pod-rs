//! # solid-pod-rs-activitypub
//!
//! ActivityPub federation (Actor, inbox, outbox, HTTP Signatures,
//! NodeInfo) for [`solid-pod-rs`](https://crates.io/crates/solid-pod-rs).
//!
//! ## Modules
//!
//! - [`actor`]     — Actor document rendering and RSA keypair generation.
//! - [`inbox`]     — Inbox handler with HTTP-Signature verification dispatch.
//! - [`outbox`]    — Outbox handler with Create/Follow/Delete activity persistence.
//! - [`delivery`]  — Background federated-delivery worker with exponential-backoff retry.
//! - [`http_sig`]  — Draft-cavage-12 `rsa-sha256` HTTP Signature sign/verify.
//! - [`discovery`] — NodeInfo 2.1 and WebFinger discovery endpoints.
//! - [`store`]     — SQLite-backed persistence for followers, inbox, outbox, delivery queue.
//! - [`error`]     — [`SigError`], [`InboxError`], [`OutboxError`].
//!
//! ## Quick start
//!
//! ```rust,ignore
//! use solid_pod_rs_activitypub::store::Store;
//!
//! // Connect to (or create) the SQLite-backed AP store.
//! let store = Store::connect("sqlite:ap.db").await?;
//!
//! // Check if a remote actor follows the local pod.
//! let is_following = store.is_follower("local-pod", "https://remote.example/actor").await?;
//! ```
//!
//! ## Relationship to core
//!
//! AP federation pulls in RSA (2048-bit keypairs, `rsa-sha256`
//! signatures) and a persistent follower store, neither of which the
//! core `solid-pod-rs` crate needs for pods that don't federate.
//! Keeping federation in a sibling crate keeps the core lean.
//!
//! HTTP Signatures use draft-cavage v12 (what the fediverse actually
//! speaks), not RFC 9421. Core's Ed25519-based
//! `solid_pod_rs::notifications::signing` is a different protocol.

#![doc = include_str!("../README.md")]

pub mod actor;
pub mod delivery;
pub mod discovery;
pub mod error;
pub mod http_sig;
pub mod inbox;
pub mod outbox;
pub mod ssrf;
pub mod store;

// ---- Flat re-export surface -------------------------------------------------
pub use actor::{
    generate_actor_keypair, negotiate_actor_format, render_actor, with_also_known_as, Actor,
    ActorFormat, Endpoints, PublicKey,
};
pub use delivery::{DeliveryConfig, DeliveryOutcome, DeliveryWorker};
pub use discovery::{
    nodeinfo_2_1, nodeinfo_wellknown, webfinger_response, WebFingerJrd, WebFingerLink,
};
pub use error::{InboxError, OutboxError, SigError};
pub use http_sig::{
    digest_header, sign_request, verify_request_signature, ActorKeyResolver, HttpActorKeyResolver,
    OutboundRequest, SignedRequest, VerifiedActor,
};
pub use inbox::{build_accept, handle_inbox, InboxOutcome};
pub use outbox::{handle_outbox, handle_outbox_post, OutboundDelivery};
pub use ssrf::assert_ssrf_safe;
pub use store::{DeliveryItem, InboxRow, OutboxRow, Store};
