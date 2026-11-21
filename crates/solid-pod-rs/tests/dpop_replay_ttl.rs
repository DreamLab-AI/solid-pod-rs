//! The DPoP `jti` lifetime must outlast the window in which a proof is
//! acceptable (same defect class as SP-ID-02 for NIP-98).
//!
//! A proof is accepted with `iat` anywhere in `now +/- skew`, so a single
//! proof stays acceptable for `2 * skew` seconds. An entry that expires
//! sooner lets a future-dated proof be replayed after the entry is gone, and a
//! lifetime of 0 turns replay protection off.
//!
//! One test owns the environment variable, so there is no race.

#![cfg(feature = "dpop-replay-cache")]

use std::time::Duration;

use solid_pod_rs::oidc::replay::{
    min_ttl_for_skew, DEFAULT_TTL_SECS, DPOP_DEFAULT_SKEW_SECS, ENV_TTL_SECS, MIN_TTL_SECS,
};
use solid_pod_rs::oidc::DpopReplayCache;

#[test]
fn the_floor_covers_the_whole_acceptance_window() {
    // A proof minted `skew` seconds in the future is first seen at `iat - skew`
    // and is still acceptable at `iat + skew`: 2 * skew later.
    assert!(MIN_TTL_SECS > 2 * DPOP_DEFAULT_SKEW_SECS);
    assert_eq!(MIN_TTL_SECS, 122);
    assert_eq!(DEFAULT_TTL_SECS, MIN_TTL_SECS);
    assert_eq!(min_ttl_for_skew(120), 242);
    // The old 60 s default was inside the window, which is the defect.
    assert!(60 < 2 * DPOP_DEFAULT_SKEW_SECS);
}

#[tokio::test]
async fn from_env_never_goes_below_the_floor() {
    let floor = Duration::from_secs(MIN_TTL_SECS);

    std::env::remove_var(ENV_TTL_SECS);
    assert_eq!(DpopReplayCache::from_env().ttl(), floor, "default");

    for raw in ["0", "1", "60", "121", "not-a-number", ""] {
        std::env::set_var(ENV_TTL_SECS, raw);
        assert_eq!(DpopReplayCache::from_env().ttl(), floor, "{raw:?}");
    }

    // A zero lifetime from the environment must still detect a replay.
    std::env::set_var(ENV_TTL_SECS, "0");
    let cache = DpopReplayCache::from_env();
    cache.check_and_record("j").await.unwrap();
    assert!(cache.check_and_record("j").await.is_err());

    std::env::set_var(ENV_TTL_SECS, "300");
    assert_eq!(DpopReplayCache::from_env().ttl(), Duration::from_secs(300));
    std::env::remove_var(ENV_TTL_SECS);
}
