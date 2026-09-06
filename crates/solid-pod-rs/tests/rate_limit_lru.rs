//! Integration tests for Sprint 7 A — LRU-backed rate-limit primitive.
//!
//! Verifies the sliding-window semantics of [`LruRateLimiter`]:
//!
//! 1. under-threshold requests are allowed
//! 2. the N+1th request within the window is denied with a correct
//!    `retry_after_secs`
//! 3. recovery occurs once the window elapses, and partial expiry frees
//!    exactly the slots that have aged out (the window really slides)
//! 4. independent subjects keep independent quota
//! 5. independent routes keep independent quota
//!
//! # Determinism
//!
//! Window behaviour is driven through `LruRateLimiter::check_at`, which takes
//! the observation instant as a parameter, rather than through `sleep` +
//! `Instant::now()`. Sleeping is not a correctness test of a sliding window:
//! it asserts that the machine scheduled two calls closer together than the
//! window, which is false under load and routinely false under coverage
//! instrumentation (tarpaulin's ptrace stepping stretched a 120 ms window far
//! enough that a "second hit inside the window" landed outside it). Injecting
//! the clock tests the actual algorithm, cannot flake, and runs instantly.
//!
//! `lru_limiter_async_check_delegates` still exercises the real
//! `RateLimiter::check` entry point so the wall-clock path stays covered; it
//! uses a window wide enough that no plausible scheduling delay can cross it.

#![cfg(all(feature = "jss-v04", feature = "rate-limit"))]

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use solid_pod_rs::security::rate_limit::{
    LruRateLimiter, RateLimitDecision, RateLimitKey, RateLimitSubject, RateLimiter,
};

fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn policy(route: &str, max: u32, window_ms: u64) -> LruRateLimiter {
    LruRateLimiter::with_policy(vec![(
        route.to_string(),
        max,
        Duration::from_millis(window_ms),
    )])
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

#[test]
fn lru_limiter_allows_under_threshold() {
    let limiter = policy("pod_create", 3, 1_000);
    let key = RateLimitKey {
        route: "pod_create",
        subject: RateLimitSubject::Ip(ip(10, 0, 0, 1)),
    };
    let t0 = Instant::now();

    for i in 0..3 {
        let decision = limiter.check_at(&key, t0 + ms(i * 10));
        assert_eq!(
            decision,
            RateLimitDecision::Allow,
            "request #{i} should be allowed (max=3)"
        );
    }
}

#[test]
fn lru_limiter_denies_at_threshold() {
    let limiter = policy("write", 2, 10_000);
    let key = RateLimitKey {
        route: "write",
        subject: RateLimitSubject::Ip(ip(10, 0, 0, 2)),
    };
    let t0 = Instant::now();

    assert_eq!(limiter.check_at(&key, t0), RateLimitDecision::Allow);
    assert_eq!(limiter.check_at(&key, t0 + ms(1)), RateLimitDecision::Allow);

    // Third hit, still at the head of the window: retry-after is the whole
    // window, because the oldest hit has not aged at all.
    match limiter.check_at(&key, t0) {
        RateLimitDecision::Deny {
            retry_after_secs,
            limit,
            window_secs,
        } => {
            assert_eq!(limit, 2);
            assert_eq!(window_secs, 10);
            assert_eq!(retry_after_secs, 10);
        }
        other => panic!("expected Deny, got {other:?}"),
    }

    // 3.5 s later the oldest hit has aged by 3.5 s, so 6.5 s remain, which
    // ceils to 7. Clients must never be told to retry slightly too early.
    match limiter.check_at(&key, t0 + ms(3_500)) {
        RateLimitDecision::Deny {
            retry_after_secs, ..
        } => assert_eq!(retry_after_secs, 7),
        other => panic!("expected Deny, got {other:?}"),
    }
}

#[test]
fn lru_limiter_recovers_after_window() {
    let limiter = policy("idp_credentials", 1, 120);
    let key = RateLimitKey {
        route: "idp_credentials",
        subject: RateLimitSubject::Ip(ip(10, 0, 0, 3)),
    };
    let t0 = Instant::now();

    // First hit consumes the quota.
    assert_eq!(limiter.check_at(&key, t0), RateLimitDecision::Allow);
    // Second hit inside the window is denied.
    matches_deny(&limiter.check_at(&key, t0 + ms(1)));
    // Still denied on the last instant the first hit remains in the window.
    // Pruning retains hits strictly newer than `now - window`, so the hit at
    // `t0` is still live at `t0 + 119 ms` and has aged out at `t0 + 120 ms`.
    matches_deny(&limiter.check_at(&key, t0 + ms(119)));
    // Once the window has fully elapsed the quota has rolled over.
    assert_eq!(
        limiter.check_at(&key, t0 + ms(120)),
        RateLimitDecision::Allow,
        "request after window should be allowed again"
    );
}

#[test]
fn lru_limiter_window_slides_per_hit() {
    // The window is sliding, not fixed: each hit expires on its own schedule,
    // freeing exactly one slot. A sleep-based test cannot state this.
    let limiter = policy("write", 2, 100);
    let key = RateLimitKey {
        route: "write",
        subject: RateLimitSubject::Ip(ip(10, 0, 0, 4)),
    };
    let t0 = Instant::now();

    assert_eq!(limiter.check_at(&key, t0), RateLimitDecision::Allow);
    assert_eq!(
        limiter.check_at(&key, t0 + ms(60)),
        RateLimitDecision::Allow
    );
    matches_deny(&limiter.check_at(&key, t0 + ms(61)));

    // At t0+101 the first hit has aged out but the second (t0+60) has not:
    // exactly one slot is free.
    assert_eq!(
        limiter.check_at(&key, t0 + ms(101)),
        RateLimitDecision::Allow
    );
    matches_deny(&limiter.check_at(&key, t0 + ms(102)));
}

#[test]
fn lru_limiter_denies_per_subject_independently() {
    let limiter = policy("pod_create", 1, 5_000);
    let a = RateLimitKey {
        route: "pod_create",
        subject: RateLimitSubject::Ip(ip(10, 0, 0, 10)),
    };
    let b = RateLimitKey {
        route: "pod_create",
        subject: RateLimitSubject::Ip(ip(10, 0, 0, 11)),
    };
    let t0 = Instant::now();

    // Each subject gets its own bucket.
    assert_eq!(limiter.check_at(&a, t0), RateLimitDecision::Allow);
    assert_eq!(limiter.check_at(&b, t0), RateLimitDecision::Allow);

    // Both subjects should now be over quota — but independently.
    matches_deny(&limiter.check_at(&a, t0 + ms(1)));
    matches_deny(&limiter.check_at(&b, t0 + ms(1)));
}

#[test]
fn lru_limiter_route_isolation() {
    let limiter = LruRateLimiter::with_policy(vec![
        ("write".to_string(), 1, Duration::from_secs(5)),
        ("read".to_string(), 5, Duration::from_secs(5)),
    ]);
    let subject = RateLimitSubject::Ip(ip(10, 0, 0, 20));
    let t0 = Instant::now();

    let write_key = RateLimitKey {
        route: "write",
        subject: subject.clone(),
    };
    let read_key = RateLimitKey {
        route: "read",
        subject,
    };

    // Burn the write quota.
    assert_eq!(limiter.check_at(&write_key, t0), RateLimitDecision::Allow);
    matches_deny(&limiter.check_at(&write_key, t0 + ms(1)));

    // Read bucket must be unaffected.
    for i in 0..5 {
        assert_eq!(
            limiter.check_at(&read_key, t0 + ms(i)),
            RateLimitDecision::Allow
        );
    }
}

#[tokio::test]
async fn lru_limiter_async_check_delegates() {
    // Covers the real `RateLimiter::check` path (which reads the wall clock).
    // The window is 1 h, so no scheduling delay — instrumented or not — can
    // reach it; the assertion is about delegation, not about timing.
    let limiter = policy("pod_create", 2, 3_600_000);
    let key = RateLimitKey {
        route: "pod_create",
        subject: RateLimitSubject::Ip(ip(10, 0, 0, 30)),
    };

    assert_eq!(limiter.check(&key).await, RateLimitDecision::Allow);
    assert_eq!(limiter.check(&key).await, RateLimitDecision::Allow);
    matches_deny(&limiter.check(&key).await);
}

// --- helpers -------------------------------------------------------------

#[track_caller]
fn matches_deny(decision: &RateLimitDecision) {
    match decision {
        RateLimitDecision::Deny { .. } => {}
        other => panic!("expected Deny, got {other:?}"),
    }
}
