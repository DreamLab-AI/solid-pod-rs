//! # solid-pod-rs-nostr
//!
//! `did:nostr` DID documents, WebID ↔ did:nostr resolver, and an
//! embedded Nostr relay (NIP-01, NIP-11, NIP-16) for solid-pod-rs.
//!
//! This sibling crate rounds out the Solid / Nostr bridge introduced in
//! the library core:
//!
//! - The core [`solid_pod_rs::auth::nip98`] verifies NIP-98 HTTP auth
//!   signatures.
//! - The core [`solid_pod_rs::interop::did_nostr`] (feature `did-nostr`)
//!   ships a low-level Tier-1 DID Doc renderer and a TTL-cached WebID
//!   resolver for server-side lookup of outside pubkeys.
//! - **This crate** adds the full operator surface: Tier-3 DID Docs
//!   with `alsoKnownAs` + service entries, bidirectional
//!   WebID ↔ did:nostr resolution (including HTML JSON-LD islands and
//!   Turtle fallback), and a self-contained NIP-01/11/16 relay with a
//!   pluggable event store and a `tokio-tungstenite` WebSocket wire
//!   handler.
//!
//! PARITY-CHECKLIST targets: rows 89, 90, 101, 132.
//!
//! ## Module layout
//!
//! - [`did`]      — `did:nostr` URIs + Tier 1 / Tier 3 document renderers.
//! - [`resolver`] — bidirectional `did:nostr` ↔ WebID resolver with SSRF guard.
//! - [`relay`]    — NIP-01 event envelope, filter matching, replaceable-event
//!   semantics (NIP-16), broadcast-channel live dispatch, NIP-11
//!   relay-info document.
//! - [`ws`]       — WebSocket wire protocol on top of `tokio-tungstenite`.
//! - [`error`]    — error types for each domain.
//!
//! ## Quick-start
//!
//! ```no_run
//! use std::sync::Arc;
//! use solid_pod_rs_nostr::{
//!     NostrPubkey, render_did_document_tier1, well_known_path, Relay,
//! };
//!
//! // DID Document publication.
//! let pk = NostrPubkey::from_hex(
//!     "1111111111111111111111111111111111111111111111111111111111111111",
//! )
//! .unwrap();
//! let doc = render_did_document_tier1(&pk);
//! let path = well_known_path(&pk); // "/.well-known/did/nostr/…json"
//! let _ = (doc, path);
//!
//! // Relay.
//! let relay = Arc::new(Relay::in_memory());
//! let _info = relay.info().clone(); // serve at GET / (Accept: application/nostr+json)
//! ```

#![forbid(unsafe_code)]

pub mod did;
pub mod error;
pub mod relay;
pub mod resolver;
pub mod ws;

pub use did::{
    did_nostr_uri, render_did_document_tier1, render_did_document_tier3, well_known_path,
    NostrPubkey, ServiceEntry,
};
pub use error::{DidError, RelayError, ResolverError};
pub use relay::{
    is_ephemeral, is_parameterised_replaceable, is_replaceable, Event, EventStore, Filter,
    InMemoryEventStore, Relay, RelayInfo,
};
pub use resolver::{DefaultSsrfCheck, NostrWebIdResolver, SsrfCheck};
pub use ws::{dispatch_message, serve_relay_ws, serve_relay_ws_stream};
