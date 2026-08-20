//! The `ReplayStore` seam (ADR-060 Decision 2).
//!
//! A NIP-98 `Authorization` token is a signed, time-boxed, one-shot
//! credential. The structural verifier in [`crate::auth::nip98`] proves a token is
//! well-formed, in-window and correctly signed, but holds no state — so a
//! captured token can be **replayed** for the whole tolerance window. Closing
//! that window needs a single-use nonce store keyed on the canonical NIP-01
//! event id. `trait ReplayStore` is that store's contract, extracted from the
//! process-local reference implementation
//! (`crate::auth::replay::Nip98ReplayCache`) so the nonce semantics are named once
//! and reused rather than re-derived per tier.
//!
//! # Why the trait lives here, not inside the reference cache
//!
//! The reference cache pulls `lru` + the tokio runtime (async mutex) behind
//! the `nip98-replay` feature. This module carries neither: the trait and its
//! error are compiled on every build of the crate (including the pure-logic
//! `core` surface the wasm32 / CF-Workers consumers use, per ADR-076/078). A
//! tier that cannot afford the in-process LRU — a forum/edge deployment
//! backed by a shared KV or Redis store — can therefore depend on this
//! crate's nonce contract and supply its own implementor, instead of
//! re-deriving replay handling and reintroducing the duplication the NIP-98
//! consolidation exists to remove.
//!
//! # Edge-local exception (ADR-060 Decision 2)
//!
//! In THIS repository every tier consumes the trait: the native
//! single-process server drives `crate::auth::replay::Nip98ReplayCache` through
//! it. The out-of-repo forum/CF tier keeps a different datastore
//! (`crate::auth::replay` "Tier persistence limit") and lives in a sibling
//! repository, so it cannot be consolidated or verified from here. It is the
//! documented **edge-local exception**: it would implement `ReplayStore`
//! against its own store if and when it is wired, and only then does the
//! cross-tier seam reach `integrated`. Until a second tier consumes the
//! trait, the seam is `standalone` — a published contract with one reference
//! implementor — and the per-replica replay-window caveat
//! (`crate::auth::replay`) holds, so no cross-ecosystem claim may assume one
//! shared verification boundary.

use std::time::Duration;

use async_trait::async_trait;
use thiserror::Error;

/// Error returned by [`ReplayStore::check_and_record`] when a credential id is
/// re-presented inside its replay window. Fail closed: treat the request as
/// unauthenticated.
#[derive(Debug, Error)]
pub enum ReplayError {
    /// The event id was already recorded within the TTL window — a client
    /// re-presented a NIP-98 token.
    #[error("NIP-98 token already used within replay window ({ttl:?})")]
    Replayed { ttl: Duration },
}

/// Single-use nonce store for one-shot credentials.
///
/// An implementor remembers a credential id (the canonical NIP-01 event id
/// for NIP-98) for a bounded window and rejects a second sighting of the same
/// id inside that window. `crate::auth::replay::Nip98ReplayCache` is the reference
/// implementor: a process-local bounded LRU with per-entry TTL. Other tiers
/// (a KV/Redis-backed edge tier) implement the same contract over shared
/// storage.
///
/// The `Send + Sync` bound lets a single store instance be shared across every
/// request path of an async server.
#[async_trait]
pub trait ReplayStore: Send + Sync {
    /// Check whether `event_id` has been seen within the store's window; if
    /// not, record it and return `Ok(())`. If already seen within the window,
    /// return [`ReplayError::Replayed`] without refreshing the entry (so a
    /// flood of replays cannot pin an id past its natural expiry).
    async fn check_and_record(&self, event_id: &str) -> Result<(), ReplayError>;
}
