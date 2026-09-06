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

/// Error returned by [`ReplayStore::check_and_record`]. Fail closed: treat the
/// request as unauthenticated for every variant.
///
/// Marked `#[non_exhaustive]` so a future store can report a new refusal mode
/// without breaking downstream `match` arms.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ReplayError {
    /// The event id was already recorded within the TTL window — a client
    /// re-presented a NIP-98 token.
    #[error("NIP-98 token already used within replay window ({ttl:?})")]
    Replayed { ttl: Duration },

    /// The store is full of entries that are **still inside** their replay
    /// window, so a new id cannot be recorded without forgetting one that is
    /// still needed (ADR-2006).
    ///
    /// A bounded store has only two ways to answer this: evict an unexpired
    /// entry — which reopens the replay window for whichever token was
    /// evicted — or refuse the new credential. Refusing is the fail-closed
    /// answer, and the one this contract requires: **an implementor MUST NOT
    /// accept a replay within the window in order to stay under capacity.**
    ///
    /// Reaching this means the store is undersized for the offered request
    /// rate. Size it for `peak_rps × ttl_secs` entries (see
    /// `crate::auth::replay::sizing_floor`).
    #[error(
        "replay store at capacity ({capacity} unexpired entries, ttl {ttl:?}); \
             cannot record a new credential without reopening the replay window"
    )]
    CapacityExhausted { capacity: usize, ttl: Duration },
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
    ///
    /// # Contract
    ///
    /// 1. **Atomic.** The check and the record are one indivisible operation.
    ///    Two concurrent calls with the same `event_id` must yield exactly one
    ///    `Ok`; the loser gets [`ReplayError::Replayed`]. An implementor that
    ///    reads, then writes, under separate locks violates this and leaves a
    ///    race in which a token is accepted twice.
    /// 2. **No replay inside the window, ever** (ADR-2006). A bounded
    ///    implementor MUST NOT evict an entry that is still inside its TTL in
    ///    order to make room. If the store is full of unexpired entries it
    ///    must return [`ReplayError::CapacityExhausted`] and refuse the new
    ///    credential, because forgetting an unexpired id would let that id be
    ///    replayed. Expired entries may of course be reclaimed first.
    /// 3. **No refresh on rejection.** A rejected replay must not extend the
    ///    original entry's expiry, or a flood of replays could pin an id
    ///    indefinitely.
    ///
    /// # Restart semantics
    ///
    /// A process-local store loses every entry on restart, so each restart
    /// reopens the replay window for the length of the TTL. A store that must
    /// survive restarts (or span replicas) has to be backed by shared,
    /// durable state; see `crate::auth::replay` for the reference store's
    /// documented tier limit.
    async fn check_and_record(&self, event_id: &str) -> Result<(), ReplayError>;
}
