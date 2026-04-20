//! Integration tests for Sprint 7 A — LRU-backed rate-limit primitive.
//!
//! Verifies the sliding-window semantics of [`LruRateLimiter`]:
//!
//! 1. under-threshold requests are allowed
//! 2. the N+1th request within the window is denied with a correct
//!    `retry_after_secs`
//! 3. recovery occurs once the window elapses
//! 4. independent subjects keep independent quota
//! 5. independent routes keep independent quota

#![cfg(all(feature = "jss-v04", feature = "rate-limit"))]

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

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

#[tokio::test]
async fn lru_limiter_allows_under_threshold() {
    let limiter = policy("pod_create", 3, 1_000);
    let subject = ip(10, 0, 0, 1);
    let key = RateLimitKey {
        route: "pod_create",
        subject: RateLimitSubject::Ip(subject),
    };

    for i in 0..3 {
        let decision = limiter.check(&key).await;
        assert_eq!(
            decision,
            RateLimitDecision::Allow,
            "request #{i} should be allowed (max=3)"
        );
    }
}

#[tokio::test]
async fn lru_limiter_denies_at_threshold() {
    let limiter = policy("write", 2, 10_000);
    let subject = ip(10, 0, 0, 2);
    let key = RateLimitKey {
        route: "write",
        subject: RateLimitSubject::Ip(subject),
    };

    assert_eq!(limiter.check(&key).await, RateLimitDecision::Allow);
    assert_eq!(limiter.check(&key).await, RateLimitDecision::Allow);

    match limiter.check(&key).await {
        RateLimitDecision::Deny {
            retry_after_secs,
            limit,
            window_secs,
        } => {
            assert_eq!(limit, 2);
            assert_eq!(window_secs, 10);
            assert!(
                (1..=10).contains(&retry_after_secs),
                "retry_after must be in (0,window]; got {retry_after_secs}"
            );
        }
        other => panic!("expected Deny, got {other:?}"),
    }
}

#[tokio::test]
async fn lru_limiter_recovers_after_window() {
    let limiter = policy("idp_credentials", 1, 120);
    let subject = ip(10, 0, 0, 3);
    let key = RateLimitKey {
        route: "idp_credentials",
        subject: RateLimitSubject::Ip(subject),
    };

    // First hit consumes the quota.
    assert_eq!(limiter.check(&key).await, RateLimitDecision::Allow);
    // Second hit inside the window is denied.
    matches_deny(&limiter.check(&key).await);

    // Sleep just past the window.
    tokio::time::sleep(Duration::from_millis(180)).await;

    // Quota should have fully rolled over.
    assert_eq!(
        limiter.check(&key).await,
        RateLimitDecision::Allow,
        "request after window should be allowed again"
    );
}

#[tokio::test]
async fn lru_limiter_denies_per_subject_independently() {
    let limiter = policy("pod_create", 1, 5_000);
    let a = RateLimitKey {
        route: "pod_create",
        subject: RateLimitSubject::Ip(ip(10, 0, 0, 10)),
    };
    let b = RateLimitKey {
        route: "pod_create",
        subject: RateLimitSubject::Ip(ip(10, 0, 0, 11)),
    };

    // Each subject gets its own bucket.
    assert_eq!(limiter.check(&a).await, RateLimitDecision::Allow);
    assert_eq!(limiter.check(&b).await, RateLimitDecision::Allow);

    // Both subjects should now be over quota — but independently.
    matches_deny(&limiter.check(&a).await);
    matches_deny(&limiter.check(&b).await);
}

#[tokio::test]
async fn lru_limiter_route_isolation() {
    let limiter = LruRateLimiter::with_policy(vec![
        ("write".to_string(), 1, Duration::from_secs(5)),
        ("read".to_string(), 5, Duration::from_secs(5)),
    ]);
    let subject = RateLimitSubject::Ip(ip(10, 0, 0, 20));

    let write_key = RateLimitKey {
        route: "write",
        subject: subject.clone(),
    };
    let read_key = RateLimitKey {
        route: "read",
        subject,
    };

    // Burn the write quota.
    assert_eq!(limiter.check(&write_key).await, RateLimitDecision::Allow);
    matches_deny(&limiter.check(&write_key).await);

    // Read bucket must be unaffected.
    for _ in 0..5 {
        assert_eq!(limiter.check(&read_key).await, RateLimitDecision::Allow);
    }
}

// --- helpers -------------------------------------------------------------

fn matches_deny(decision: &RateLimitDecision) {
    match decision {
        RateLimitDecision::Deny { .. } => {}
        other => panic!("expected Deny, got {other:?}"),
    }
}
