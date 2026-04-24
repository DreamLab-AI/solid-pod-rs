//! Sprint 9 row 64 — synchronous `JtiReplayCache` primitive.
//!
//! Covers the contract in `src/oidc/replay.rs`:
//!
//!   * First insert of a `jti` succeeds.
//!   * Second insert of the same `jti` within TTL returns
//!     [`ReplayError::Replayed`].
//!   * Expired entries may be re-used.
//!   * Capacity-driven eviction: oldest entry evicted on overflow.
//!   * Thread-safe under concurrent insert load.

#![cfg(feature = "dpop-replay-cache")]

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use solid_pod_rs::oidc::{JtiReplayCache, ReplayError};

#[test]
fn first_insert_succeeds() {
    let cache = JtiReplayCache::new(64, Duration::from_secs(300));
    assert!(cache
        .check_and_insert("jti-fresh-1", SystemTime::now())
        .is_ok());
    assert_eq!(cache.len(), 1);
}

#[test]
fn second_insert_same_jti_fails_with_replay_error() {
    let cache = JtiReplayCache::new(64, Duration::from_secs(300));
    let now = SystemTime::now();
    cache.check_and_insert("jti-dupe-2", now).unwrap();

    let err = cache
        .check_and_insert("jti-dupe-2", now + Duration::from_secs(1))
        .unwrap_err();
    assert!(matches!(err, ReplayError::Replayed { .. }));
    // Replay must not duplicate the entry.
    assert_eq!(cache.len(), 1);
}

#[test]
fn expired_jti_allows_reuse() {
    let cache = JtiReplayCache::new(64, Duration::from_millis(1));
    let t0 = SystemTime::now();
    cache.check_and_insert("jti-expire-3", t0).unwrap();

    std::thread::sleep(Duration::from_millis(5));
    // Re-submit with a "now" well past TTL; must be accepted.
    cache
        .check_and_insert("jti-expire-3", t0 + Duration::from_millis(50))
        .expect("post-TTL reuse must be accepted");
    // Still one entry — overwrite, not append.
    assert_eq!(cache.len(), 1);
}

#[test]
fn capacity_evicts_oldest() {
    let cap = 4;
    let cache = JtiReplayCache::new(cap, Duration::from_secs(300));
    let t0 = SystemTime::now();
    // Insert cap + 1 distinct jtis; the first is evicted.
    for i in 0..=cap {
        let jti = format!("jti-cap-{i:03}");
        cache
            .check_and_insert(&jti, t0 + Duration::from_millis(i as u64))
            .unwrap();
    }
    assert_eq!(cache.len(), cap);
    // The oldest jti was evicted; re-inserting it succeeds.
    cache
        .check_and_insert("jti-cap-000", t0 + Duration::from_millis(1_000))
        .expect("evicted jti should be accepted again");
    // Cache stays at capacity — another eviction took place.
    assert_eq!(cache.len(), cap);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn thread_safe_concurrent_inserts() {
    let cache = Arc::new(JtiReplayCache::new(1024, Duration::from_secs(300)));
    let n = 32usize;
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        let c = Arc::clone(&cache);
        let jti = format!("jti-conc-{i:03}");
        handles.push(tokio::task::spawn_blocking(move || {
            c.check_and_insert(&jti, SystemTime::now())
        }));
    }
    for h in handles {
        let res = h.await.unwrap();
        assert!(res.is_ok(), "distinct jtis must all succeed: {res:?}");
    }
    assert_eq!(cache.len(), n);
}
