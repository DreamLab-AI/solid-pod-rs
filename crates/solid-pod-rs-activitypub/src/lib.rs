//! # solid-pod-rs-activitypub
//!
//! ActivityPub federation for `solid-pod-rs`, JSS `src/ap/*` parity.
//!
//! ## Scope (this sibling crate)
//!
//! * **Actor document** (`/profile/card` with Accept negotiation)
//! * **Inbox** handler with RSA HTTP Signature verification
//!   (draft-cavage v12)
//! * **Outbox** handler with Create/Follow/Delete and federated
//!   delivery
//! * **Followers/Following/Inbox/Outbox** persistence (SQLite via
//!   `sqlx`)
//! * **Federated delivery worker** with exponential-backoff retry
//! * **NodeInfo 2.1** discovery at `/.well-known/nodeinfo` +
//!   `/.well-known/nodeinfo/2.1`
//! * **WebFinger** re-export of `solid_pod_rs::interop::webfinger_response`
//!
//! Targets PARITY-CHECKLIST rows 102-108 and 131.
//!
//! ## Why a sibling crate?
//!
//! AP federation pulls in RSA (2048-bit keypairs, rsa-sha256
//! signatures) and a persistent follower store, neither of which the
//! core `solid-pod-rs` crate needs to carry for pods that don't
//! federate. Gating via a sibling crate keeps the core lean.
//!
//! ## HTTP Signatures: we speak draft-cavage v12
//!
//! The fediverse hasn't migrated to RFC 9421 yet. Mastodon, Pleroma,
//! Misskey and GoToSocial all sign their outbound POSTs with
//! `rsa-sha256` over the `(request-target)`, `host`, `date`, `digest`
//! header set. Our [`http_sig`] module verifies those shapes and
//! signs outgoing deliveries in the same style. Core's Ed25519-based
//! `solid_pod_rs::notifications::signing` is a different protocol and
//! not wire-compatible.

pub mod actor;
pub mod delivery;
pub mod discovery;
pub mod error;
pub mod http_sig;
pub mod inbox;
pub mod outbox;
pub mod store;

// ---- Flat re-export surface -------------------------------------------------
pub use actor::{
    generate_actor_keypair, render_actor, with_also_known_as, Actor, Endpoints, PublicKey,
};
pub use delivery::{DeliveryConfig, DeliveryOutcome, DeliveryWorker};
pub use discovery::{
    nodeinfo_2_1, nodeinfo_wellknown, webfinger_response, WebFingerJrd, WebFingerLink,
};
pub use error::{InboxError, OutboxError, SigError};
pub use http_sig::{
    digest_header, sign_request, verify_request_signature, ActorKeyResolver,
    HttpActorKeyResolver, OutboundRequest, SignedRequest, VerifiedActor,
};
pub use inbox::{build_accept, handle_inbox, InboxOutcome};
pub use outbox::{handle_outbox, OutboundDelivery};
pub use store::{DeliveryItem, InboxRow, OutboxRow, Store};
