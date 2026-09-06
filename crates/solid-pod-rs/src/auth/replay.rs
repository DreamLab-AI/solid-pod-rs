//! NIP-98 single-use replay guard (F3).
//!
//! A NIP-98 `Authorization` token is a signed, time-boxed, one-shot
//! credential: it authorises exactly one HTTP request. The structural
//! verifier in [`crate::auth::nip98`] proves the token is well-formed, in-window
//! (±[`crate::auth::nip98`] `TIMESTAMP_TOLERANCE`) and correctly signed, but it
//! holds no state — so a captured token can be **replayed** for the whole
//! ~120s tolerance window. This module closes that window with a
//! single-use nonce store keyed on the canonical NIP-01 event id
//! ([`crate::auth::nip98::Nip98Verified::event_id`]).
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
//! * **Restart**: the cache is in memory only. A restart forgets every id, so
//!   the replay window reopens for one TTL. Durable replay defence needs a
//!   shared store behind the same [`crate::auth::replay_store::ReplayStore`] seam.
//!
//! A shared/Redis-backed store is out of scope for this tier; the ceilings
//! above are the documented, deliberate limits — replay is nonetheless made
//! to *fail* within a single process for the whole tolerance window.
//!
//! # Capacity policy (ADR-2006)
//!
//! Capacity is **not** a third way to lose replay protection. The cache is
//! bounded, so a full cache must answer one of two ways:
//!
//! * evict the oldest entry even though it is still inside its TTL — which
//!   silently reopens the replay window for exactly that id; or
//! * refuse to record the new credential.
//!
//! This store does the second. `check_and_record` first reclaims entries that
//! have genuinely expired (they can no longer be replayed, because the NIP-98
//! freshness check would reject the token anyway); if every live entry is
//! still inside its window it returns [`crate::auth::replay_store::ReplayError::CapacityExhausted`] and
//! the request is treated as unauthenticated. **An unexpired entry is never
//! evicted**, so a capacity-one cache cannot be made to accept the same token
//! twice inside the window — the probe that previously demonstrated the gap.
//!
//! The trade-off is deliberate and stated plainly: an attacker who can offer
//! unique valid-looking ids faster than the TTL drains them can push the cache
//! to capacity and cause legitimate requests to be refused. That is a
//! availability failure, which is recoverable; accepting a replayed
//! credential is an authentication failure, which is not. Size the cache with
//! [`crate::auth::replay::sizing_floor()`] so the refusal path is not reached in normal operation.

#![cfg(feature = "nip98-replay")]

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use lru::LruCache;
use tokio::sync::Mutex;

// The single-use-nonce contract and its error live in the runtime-free seam
// module so an out-of-repo tier can depend on them without pulling `lru` /
// tokio (ADR-060 Decision 2). Re-exported here so the historical
// `auth::replay::ReplayError` path keeps resolving.
pub use super::replay_store::{ReplayError, ReplayStore};

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

/// The smallest capacity that can hold every credential presentable inside one
/// replay window at `peak_rps` — i.e. `ceil(peak_rps × ttl)`.
///
/// Sizing at or above this floor means the cache never reaches
/// [`ReplayError::CapacityExhausted`] under the modelled load, so the
/// fail-closed refusal path stays a safety net rather than a routine outcome.
/// The default pairing ([`DEFAULT_MAX_SIZE`] at [`DEFAULT_TTL_SECS`]) covers
/// roughly 83 rps.
///
/// Saturates rather than overflowing on absurd inputs.
#[must_use]
pub fn sizing_floor(peak_rps: u64, ttl: Duration) -> usize {
    let secs = ttl.as_secs_f64().max(0.0);
    let needed = (peak_rps as f64 * secs).ceil();
    if !needed.is_finite() || needed <= 0.0 {
        return 1;
    }
    if needed >= usize::MAX as f64 {
        return usize::MAX;
    }
    (needed as usize).max(1)
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

    /// Evict all entries whose first-seen is strictly older than the TTL.
    /// Returns the number removed. Eviction is otherwise lazy (driven by
    /// [`Self::check_and_record`]); call periodically to bound idle memory.
    pub async fn evict_expired(&self) -> usize {
        let now = Instant::now();
        let mut guard = self.inner.lock().await;
        Self::reclaim_expired(&mut guard, now, self.ttl)
    }

    /// Drop every entry whose first-seen is at least `ttl` old, returning the
    /// count removed. Caller holds the lock.
    ///
    /// Shared by [`Self::evict_expired`] and the capacity path of
    /// `check_and_record`, so both agree on exactly which entries are
    /// reclaimable — only genuinely expired ones.
    fn reclaim_expired(inner: &mut Inner, now: Instant, ttl: Duration) -> usize {
        let expired: Vec<String> = inner
            .entries
            .iter()
            .filter_map(|(id, seen)| {
                if now.saturating_duration_since(*seen) >= ttl {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();
        let removed = expired.len();
        for id in expired {
            inner.entries.pop(&id);
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

/// Reference implementor of the [`ReplayStore`] seam (ADR-060 Decision 2).
/// Every in-repo tier drives the cache through this contract; the out-of-repo
/// forum/CF tier is the documented edge-local exception (it supplies its own
/// datastore-backed implementor). Callers must bring [`ReplayStore`] into
/// scope to invoke [`Nip98ReplayCache::check_and_record`].
#[async_trait]
impl ReplayStore for Nip98ReplayCache {
    /// Check whether `event_id` has been seen within TTL; if not, record it
    /// and return `Ok(())`. If already seen within TTL, return
    /// [`ReplayError::Replayed`] **without** refreshing the entry (so a
    /// flood of replays cannot keep an id pinned past its natural expiry).
    ///
    /// Entries whose first-seen is strictly older than `ttl` are expired
    /// and overwritten as a fresh sighting.
    async fn check_and_record(&self, event_id: &str) -> Result<(), ReplayError> {
        let now = Instant::now();
        // ONE lock spans the check and the record, so the operation is atomic:
        // two concurrent calls for the same id cannot both observe "unseen".
        let mut guard = self.inner.lock().await;

        // `peek` does not promote LRU position — order reflects insertion
        // age, not check age.
        if let Some(first_seen) = guard.entries.peek(event_id).copied() {
            if now.saturating_duration_since(first_seen) < self.ttl {
                // Deliberately no refresh: a flood of replays must not pin an
                // id past its natural expiry.
                return Err(ReplayError::Replayed { ttl: self.ttl });
            }
            // Expired: overwrite in place as a fresh sighting. This reuses the
            // existing slot, so it cannot be refused for capacity.
            guard.entries.put(event_id.to_string(), now);
            return Ok(());
        }

        // A genuinely new id needs a slot. ADR-2006: never take that slot from
        // an entry that is still inside its replay window.
        if guard.entries.len() >= self.max_size {
            // Reclaim anything that has actually expired — an expired id is no
            // longer replayable (the NIP-98 freshness check rejects the token),
            // so forgetting it costs nothing.
            Self::reclaim_expired(&mut guard, now, self.ttl);
            if guard.entries.len() >= self.max_size {
                // Every live entry is unexpired. Evicting one would reopen the
                // replay window for that credential, so refuse this one
                // instead — fail closed on authentication, not on replay.
                return Err(ReplayError::CapacityExhausted {
                    capacity: self.max_size,
                    ttl: self.ttl,
                });
            }
        }
        guard.entries.put(event_id.to_string(), now);
        Ok(())
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
    async fn trait_object_dispatch_rejects_replay() {
        // The seam is consumed through `trait ReplayStore`, including as a
        // trait object — an out-of-repo tier can hold `Arc<dyn ReplayStore>`
        // over its own datastore-backed implementor (ADR-060 Decision 2).
        let store: Arc<dyn ReplayStore> =
            Arc::new(Nip98ReplayCache::with_config(Duration::from_secs(60), 8));
        let id = "e".repeat(64);
        assert!(store.check_and_record(&id).await.is_ok());
        assert!(matches!(
            store.check_and_record(&id).await.unwrap_err(),
            ReplayError::Replayed { .. }
        ));
    }

    // -----------------------------------------------------------------
    // ADR-2006: capacity policy. The store must never accept a replay
    // inside the window in order to stay under its bound.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn capacity_pressure_refuses_new_ids_and_never_evicts_unexpired() {
        let cache = Nip98ReplayCache::with_config(Duration::from_secs(600), 2);
        cache.check_and_record("id-1").await.unwrap();
        cache.check_and_record("id-2").await.unwrap();
        assert_eq!(cache.len().await, 2);

        // A third distinct id cannot be recorded without forgetting an
        // unexpired one, so it is REFUSED rather than making room.
        let err = cache.check_and_record("id-3").await.unwrap_err();
        assert!(
            matches!(err, ReplayError::CapacityExhausted { capacity: 2, .. }),
            "expected CapacityExhausted, got {err:?}"
        );
        // The store stayed at capacity and forgot nothing.
        assert_eq!(cache.len().await, 2);

        // The decisive regression assertion: id-1 is still remembered, so
        // re-presenting it is still a replay. Under the old evict-the-LRU
        // policy this returned Ok — the capacity-one probe in the estate
        // review that accepted the original event again inside its window.
        assert!(matches!(
            cache.check_and_record("id-1").await.unwrap_err(),
            ReplayError::Replayed { .. }
        ));
        assert!(matches!(
            cache.check_and_record("id-2").await.unwrap_err(),
            ReplayError::Replayed { .. }
        ));
    }

    #[tokio::test]
    async fn capacity_one_cannot_be_made_to_accept_a_replay() {
        // The exact shape of the reproduced finding: capacity 1, one event,
        // re-presented inside the replay window.
        let cache = Nip98ReplayCache::with_config(Duration::from_secs(600), 1);
        let id = "f".repeat(64);
        assert!(cache.check_and_record(&id).await.is_ok());
        // Any amount of unrelated traffic must not dislodge it...
        for n in 0..64 {
            let filler = format!("filler-{n:064}");
            assert!(matches!(
                cache.check_and_record(&filler).await.unwrap_err(),
                ReplayError::CapacityExhausted { .. }
            ));
        }
        // ...so the original event is STILL rejected as a replay.
        assert!(matches!(
            cache.check_and_record(&id).await.unwrap_err(),
            ReplayError::Replayed { .. }
        ));
    }

    #[tokio::test]
    async fn expired_entries_are_reclaimed_to_admit_a_new_id() {
        // Zero TTL: the first entry is expired the moment it is written, so
        // it is reclaimable and the new id is admitted rather than refused.
        let cache = Nip98ReplayCache::with_config(Duration::from_secs(0), 1);
        assert!(cache.check_and_record("old").await.is_ok());
        assert!(
            cache.check_and_record("new").await.is_ok(),
            "an expired entry must be reclaimed, not cause a refusal"
        );
        assert_eq!(cache.len().await, 1);
    }

    #[tokio::test]
    async fn re_presenting_an_expired_id_reuses_its_slot_at_capacity() {
        // A full cache whose entries have expired must still accept the SAME
        // id again (fresh sighting), not refuse it for capacity.
        let cache = Nip98ReplayCache::with_config(Duration::from_secs(0), 1);
        let id = "g".repeat(64);
        assert!(cache.check_and_record(&id).await.is_ok());
        assert!(cache.check_and_record(&id).await.is_ok());
        assert_eq!(cache.len().await, 1);
    }

    #[tokio::test]
    async fn concurrent_first_sightings_admit_exactly_one() {
        // Atomicity: N tasks race on the SAME id against a store with ample
        // capacity. Exactly one may win; every other must see Replayed.
        let cache = Nip98ReplayCache::with_config(Duration::from_secs(600), 128);
        let id = "h".repeat(64);
        let mut tasks = Vec::new();
        for _ in 0..32 {
            let c = cache.clone();
            let id = id.clone();
            tasks.push(tokio::spawn(async move { c.check_and_record(&id).await }));
        }
        let mut accepted = 0usize;
        for t in tasks {
            match t.await.expect("task panicked") {
                Ok(()) => accepted += 1,
                Err(ReplayError::Replayed { .. }) => {}
                Err(e) => panic!("unexpected error: {e:?}"),
            }
        }
        assert_eq!(accepted, 1, "check-and-record must be atomic");
        assert_eq!(cache.len().await, 1);
    }

    #[tokio::test]
    async fn concurrent_distinct_ids_never_exceed_capacity() {
        // Capacity is a hard bound under concurrency: some tasks are refused,
        // but the store never overshoots and never forgets an unexpired id.
        let cache = Nip98ReplayCache::with_config(Duration::from_secs(600), 8);
        let mut tasks = Vec::new();
        for n in 0..64 {
            let c = cache.clone();
            tasks.push(tokio::spawn(async move {
                c.check_and_record(&format!("id-{n:064}")).await
            }));
        }
        let mut accepted = 0usize;
        let mut refused = 0usize;
        for t in tasks {
            match t.await.expect("task panicked") {
                Ok(()) => accepted += 1,
                Err(ReplayError::CapacityExhausted { .. }) => refused += 1,
                Err(e) => panic!("unexpected error: {e:?}"),
            }
        }
        assert_eq!(
            accepted, 8,
            "exactly `capacity` distinct ids may be admitted"
        );
        assert_eq!(refused, 56);
        assert_eq!(cache.len().await, 8);
    }

    #[tokio::test]
    async fn evict_expired_frees_the_store_for_reuse() {
        let cache = Nip98ReplayCache::with_config(Duration::from_secs(0), 2);
        cache.check_and_record("a").await.unwrap();
        cache.check_and_record("b").await.unwrap();
        assert_eq!(cache.evict_expired().await, 2);
        assert!(cache.is_empty().await);
    }

    #[test]
    fn sizing_floor_covers_the_offered_rate() {
        // ceil(rps × ttl), so the refusal path is unreachable at that load.
        assert_eq!(sizing_floor(100, Duration::from_secs(120)), 12_000);
        assert_eq!(sizing_floor(0, Duration::from_secs(120)), 1);
        assert_eq!(sizing_floor(1, Duration::from_millis(1500)), 2);
        // The shipped defaults cover ~83 rps.
        assert!(
            sizing_floor(83, Duration::from_secs(DEFAULT_TTL_SECS)) <= DEFAULT_MAX_SIZE,
            "documented default sizing claim must hold"
        );
        assert!(sizing_floor(84, Duration::from_secs(DEFAULT_TTL_SECS)) > DEFAULT_MAX_SIZE);
    }

    #[tokio::test]
    async fn restart_semantics_reopen_the_window() {
        // Documented tier limit, pinned as a test so it cannot be mistaken
        // for durability: a fresh store shares no state with the old one.
        let before = Nip98ReplayCache::with_config(Duration::from_secs(600), 8);
        let id = "i".repeat(64);
        assert!(before.check_and_record(&id).await.is_ok());
        assert!(before.check_and_record(&id).await.is_err());

        // "Restart" — construct a new store, as the process would on boot.
        let after = Nip98ReplayCache::with_config(Duration::from_secs(600), 8);
        assert!(
            after.check_and_record(&id).await.is_ok(),
            "a process-local store cannot survive a restart; this is the \
             documented limit, not a regression"
        );
    }
}
