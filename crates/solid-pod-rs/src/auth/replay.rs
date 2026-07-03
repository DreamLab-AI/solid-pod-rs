//! NIP-98 single-use replay guard (F3).
//!
//! A NIP-98 `Authorization` token is a signed, time-boxed, one-shot
//! credential: it authorises exactly one HTTP request. The structural
//! verifier in [`super::nip98`] proves the token is well-formed, in-window
//! (±[`super::nip98`] `TIMESTAMP_TOLERANCE`) and correctly signed, but it
//! holds no state — so a captured token can be **replayed** for the whole
//! ~120s tolerance window. This module closes that window with a
//! single-use nonce store keyed on the canonical NIP-01 event id
//! ([`super::nip98::Nip98Verified::event_id`]).
//!
//! It mirrors the DPoP `jti` replay cache ([`crate::oidc::replay`]) but is
//! deliberately decoupled from the OIDC feature: a NIP-98-only pod (no
//! Solid-OIDC) still gets replay protection. Gated behind `nip98-replay`.
//!
//! # Tier persistence limit
//!
//! The store is **process-local** — an in-memory bounded LRU with per-entry
//! TTL. This is the correct guard for the native single-process pod tier
//! (which has no shared datastore the way the forum/CF tier does). Two
//! consequences the operator must size for:
//!
//! * **Multi-replica**: replicas share no state. HA deployments must either
//!   stick a signer to one replica or accept a per-replica replay window.
//! * **Capacity-driven window**: once `max_size` entries are live, the
//!   oldest is evicted and could be replayed. Size the cache for the
//!   worst-case request rate (default 10_000 entries ≈ 166 rps at 60s TTL).
//!
//! A shared/Redis-backed store is out of scope for this tier; the ceiling
//! above is the documented, deliberate limit — replay is nonetheless made
//! to *fail* within a single process for the whole tolerance window.

#![cfg(feature = "nip98-replay")]

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lru::LruCache;
use thiserror::Error;
use tokio::sync::Mutex;

/// Default TTL for a remembered event id. Must be at least the NIP-98
/// timestamp tolerance so an id can never expire from the cache while the
/// same token would still pass the freshness check (which would reopen the
/// replay window). `2 * TIMESTAMP_TOLERANCE` (= 120s) covers the full
/// accept window symmetrically around `now`.
pub const DEFAULT_TTL_SECS: u64 = 120;

/// Default capacity: 10_000 event ids. At ~150 bytes/entry (64-hex id
/// string + `Instant`) this bounds worst-case memory to ~1.5 MB.
pub const DEFAULT_MAX_SIZE: usize = 10_000;

/// Environment variables consumed by [`Nip98ReplayCache::from_env`].
pub const ENV_TTL_SECS: &str = "SOLID_POD_NIP98_REPLAY_TTL_SECS";
pub const ENV_MAX_SIZE: &str = "SOLID_POD_NIP98_REPLAY_MAX_SIZE";

/// Error returned by [`Nip98ReplayCache::check_and_record`].
#[derive(Debug, Error)]
pub enum ReplayError {
    /// The event id was already recorded within the TTL window — a client
    /// re-presented a NIP-98 token. Fail closed (treat as unauthenticated).
    #[error("NIP-98 token already used within replay window ({ttl:?})")]
    Replayed { ttl: Duration },
}

/// Bounded LRU tracking recently-seen NIP-98 event ids.
///
/// Cheap to [`Clone`]: the state lives behind `Arc<Mutex<…>>`, so clones
/// share storage. Construct once at startup, hand a clone to each request
/// path.
#[derive(Debug, Clone)]
pub struct Nip98ReplayCache {
    inner: Arc<Mutex<Inner>>,
    ttl: Duration,
    max_size: usize,
}

#[derive(Debug)]
struct Inner {
    /// `event_id` → first-seen `Instant`. Entries older than `ttl` are
    /// treated as expired and overwritten on the next sighting.
    entries: LruCache<String, Instant>,
}

impl Nip98ReplayCache {
    /// Construct with defaults, optionally overridden by the environment
    /// variables [`ENV_TTL_SECS`] / [`ENV_MAX_SIZE`].
    pub fn from_env() -> Self {
        let ttl_secs = std::env::var(ENV_TTL_SECS)
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(DEFAULT_TTL_SECS);
        let max_size = std::env::var(ENV_MAX_SIZE)
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(DEFAULT_MAX_SIZE);
        Self::with_config(Duration::from_secs(ttl_secs), max_size)
    }

    /// Construct with an explicit TTL and maximum entry count. `max_size`
    /// is clamped to at least 1 (a zero-capacity LRU cannot detect replay).
    pub fn with_config(ttl: Duration, max_size: usize) -> Self {
        let cap = NonZeroUsize::new(max_size.max(1)).expect("clamped to >= 1 above");
        Self {
            inner: Arc::new(Mutex::new(Inner {
                entries: LruCache::new(cap),
            })),
            ttl,
            max_size: max_size.max(1),
        }
    }

    /// Configured TTL.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Configured maximum entry count.
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Current entry count (approximate; briefly holds the mutex).
    pub async fn len(&self) -> usize {
        self.inner.lock().await.entries.len()
    }

    /// `true` when no entries are tracked.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Check whether `event_id` has been seen within TTL; if not, record it
    /// and return `Ok(())`. If already seen within TTL, return
    /// [`ReplayError::Replayed`] **without** refreshing the entry (so a
    /// flood of replays cannot keep an id pinned past its natural expiry).
    ///
    /// Entries whose first-seen is strictly older than `ttl` are expired
    /// and overwritten as a fresh sighting.
    pub async fn check_and_record(&self, event_id: &str) -> Result<(), ReplayError> {
        let now = Instant::now();
        let mut guard = self.inner.lock().await;

        // `peek` does not promote LRU position — order reflects insertion
        // age, not check age.
        if let Some(first_seen) = guard.entries.peek(event_id).copied() {
            if now.saturating_duration_since(first_seen) < self.ttl {
                return Err(ReplayError::Replayed { ttl: self.ttl });
            }
            // Expired: fall through and overwrite as a fresh sighting.
        }
        // First sighting (or expired). `put` evicts the LRU entry at
        // capacity.
        guard.entries.put(event_id.to_string(), now);
        Ok(())
    }

    /// Evict all entries whose first-seen is strictly older than the TTL.
    /// Returns the number removed. Eviction is otherwise lazy (driven by
    /// [`Self::check_and_record`]); call periodically to bound idle memory.
    pub async fn evict_expired(&self) -> usize {
        let now = Instant::now();
        let mut guard = self.inner.lock().await;
        let expired: Vec<String> = guard
            .entries
            .iter()
            .filter_map(|(id, seen)| {
                if now.saturating_duration_since(*seen) >= self.ttl {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();
        let removed = expired.len();
        for id in expired {
            guard.entries.pop(&id);
        }
        removed
    }

    /// Spawn a background task that calls [`Self::evict_expired`] every
    /// `period`. The returned handle can be aborted to stop the evictor;
    /// the cache itself is unaffected.
    pub fn spawn_evictor(self, period: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(period);
            ticker.tick().await; // consume the immediate first tick
            loop {
                ticker.tick().await;
                let _ = self.evict_expired().await;
            }
        })
    }
}

impl Default for Nip98ReplayCache {
    fn default() -> Self {
        Self::with_config(Duration::from_secs(DEFAULT_TTL_SECS), DEFAULT_MAX_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn first_sighting_accepts_replay_rejects() {
        let cache = Nip98ReplayCache::with_config(Duration::from_secs(60), 8);
        let id = "a".repeat(64);
        assert!(cache.check_and_record(&id).await.is_ok());
        let err = cache.check_and_record(&id).await.unwrap_err();
        assert!(matches!(err, ReplayError::Replayed { .. }));
        // A distinct id is unaffected.
        assert!(cache.check_and_record(&"b".repeat(64)).await.is_ok());
    }

    #[tokio::test]
    async fn expired_entry_treated_as_fresh() {
        // Zero TTL: any prior sighting is already strictly older than TTL,
        // so the same id is accepted again (expired → overwritten).
        let cache = Nip98ReplayCache::with_config(Duration::from_secs(0), 8);
        let id = "c".repeat(64);
        assert!(cache.check_and_record(&id).await.is_ok());
        assert!(cache.check_and_record(&id).await.is_ok());
    }

    #[tokio::test]
    async fn clones_share_storage() {
        let a = Nip98ReplayCache::with_config(Duration::from_secs(60), 8);
        let b = a.clone();
        let id = "d".repeat(64);
        assert!(a.check_and_record(&id).await.is_ok());
        // The clone sees the sighting recorded through `a`.
        assert!(b.check_and_record(&id).await.is_err());
    }

    #[tokio::test]
    async fn capacity_eviction_is_bounded() {
        let cache = Nip98ReplayCache::with_config(Duration::from_secs(600), 2);
        cache.check_and_record("id-1").await.unwrap();
        cache.check_and_record("id-2").await.unwrap();
        // Inserting a third evicts the LRU (id-1); len stays at capacity.
        cache.check_and_record("id-3").await.unwrap();
        assert_eq!(cache.len().await, 2);
        // id-1 was evicted, so it is now accepted again (the documented
        // capacity-driven replay window).
        assert!(cache.check_and_record("id-1").await.is_ok());
    }
}
