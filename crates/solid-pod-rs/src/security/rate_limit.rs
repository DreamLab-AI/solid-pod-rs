//! Pluggable rate-limit primitive (Sprint 7 §6.1, ADR-057).
//!
//! The library exposes a transport-agnostic [`RateLimiter`] trait plus a
//! reference in-process [`LruRateLimiter`] implementation. Consumer
//! binders (actix-web, axum, tower) adapt the trait to their middleware
//! surface — this crate never mounts routes itself (F7 boundary).
//!
//! ## Algorithm
//!
//! Sliding-window counter keyed by `(route, subject)`. Each bucket
//! stores the monotonic `Instant` of every hit inside the current
//! window. On each [`RateLimiter::check`]:
//!
//! 1. Prune entries older than `window`.
//! 2. If the remaining count `>= max`, deny with
//!    `retry_after_secs = ceil(window - (now - oldest_hit))`.
//! 3. Otherwise, record `now` and allow.
//!
//! ## Storage
//!
//! An LRU cache bounds memory under pathological key churn. The cache
//! capacity defaults to `DEFAULT_LRU_CAPACITY` (4096). Entries that are
//! evicted lose their history — a deliberate trade-off: the bound is
//! hard, and real-world adversaries cannot force forgiveness of their
//! own recent hits without also flushing their own bucket.
//!
//! ## Subject identity
//!
//! [`RateLimitSubject`] distinguishes per-IP (anonymous requests) from
//! per-WebID (authenticated requests). Consumers SHOULD prefer WebID
//! keying for authenticated endpoints: it is stable across NAT churn.
//!
//! ## Concurrency
//!
//! The limiter uses `parking_lot::Mutex` (already in the dep graph via
//! `reqwest`). Contention is O(1) per check; the critical section is
//! the prune-and-push on a single bucket.

#[cfg(feature = "rate-limit")]
use std::time::Duration;

use async_trait::async_trait;

/// Rate-limit subject — the entity whose quota is being counted.
///
/// Variants deliberately borrow `&str` / `&IpAddr` rather than owning;
/// the limiter computes a canonical string key at check time and drops
/// the borrow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitSubject<'a> {
    /// Anonymous client keyed by source IP.
    Ip(std::net::IpAddr),
    /// Authenticated client keyed by WebID URL.
    WebId(&'a str),
    /// Opaque caller-supplied key (e.g. API-key fingerprint).
    Custom(&'a str),
}

#[cfg(feature = "rate-limit")]
impl RateLimitSubject<'_> {
    /// Canonical string representation, used as the bucket key.
    fn canonical(&self) -> String {
        match self {
            RateLimitSubject::Ip(ip) => format!("ip:{ip}"),
            RateLimitSubject::WebId(w) => format!("webid:{w}"),
            RateLimitSubject::Custom(c) => format!("custom:{c}"),
        }
    }
}

/// Composite key for a limiter bucket. Bundles the logical route name
/// with the subject; buckets never cross routes.
#[derive(Debug, Clone)]
pub struct RateLimitKey<'a> {
    /// Logical route name (e.g. `pod_create`, `write`, `idp_credentials`).
    pub route: &'a str,
    /// Subject identity.
    pub subject: RateLimitSubject<'a>,
}

#[cfg(feature = "rate-limit")]
impl RateLimitKey<'_> {
    fn canonical(&self) -> String {
        format!("{}|{}", self.route, self.subject.canonical())
    }
}

/// Outcome of a single [`RateLimiter::check`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitDecision {
    /// Request is permitted. The hit was recorded.
    Allow,
    /// Request exceeds the configured quota for this key. Caller
    /// SHOULD return `429 Too Many Requests` with a `Retry-After`
    /// header equal to `retry_after_secs`.
    Deny {
        /// Seconds the client should wait before retrying.
        retry_after_secs: u64,
        /// Configured maximum for this route.
        limit: u32,
        /// Configured window in seconds for this route.
        window_secs: u64,
    },
}

/// Transport-agnostic rate-limit contract.
///
/// Implementations MUST be `Send + Sync + 'static` so consumer binders
/// can wrap them in a shared `Arc<dyn RateLimiter>` inside their
/// middleware stack.
#[async_trait]
pub trait RateLimiter: Send + Sync + 'static {
    /// Check and record a single hit for `key`. Returns
    /// [`RateLimitDecision::Allow`] if the request is permitted (and
    /// records the hit), or [`RateLimitDecision::Deny`] otherwise
    /// (without recording).
    async fn check(&self, key: &RateLimitKey<'_>) -> RateLimitDecision;
}

// -- reference implementation ---------------------------------------------

#[cfg(feature = "rate-limit")]
mod lru_impl {
    use super::*;

    use std::num::NonZeroUsize;
    use std::time::Instant;

    use lru::LruCache;
    use parking_lot::Mutex;

    /// Default LRU capacity. Bounds memory under key churn.
    pub const DEFAULT_LRU_CAPACITY: usize = 4096;

    /// Default policy when no per-route policy is supplied: 60 hits
    /// per 60 s. Deliberately generous — binders SHOULD configure
    /// tighter policies per route.
    const DEFAULT_MAX: u32 = 60;
    const DEFAULT_WINDOW: Duration = Duration::from_secs(60);

    /// Sliding-window bucket: the hit timestamps inside the current
    /// window. Stored oldest-first so prune + retry-after are O(window).
    #[derive(Debug, Default)]
    struct SlidingWindow {
        hits: Vec<Instant>,
    }

    impl SlidingWindow {
        fn prune(&mut self, now: Instant, window: Duration) {
            let cutoff = now.checked_sub(window);
            match cutoff {
                Some(c) => self.hits.retain(|t| *t > c),
                None => self.hits.clear(),
            }
        }
    }

    /// LRU-cached sliding-window rate limiter.
    pub struct LruRateLimiter {
        buckets: Mutex<LruCache<String, SlidingWindow>>,
        policies: Vec<RoutePolicy>,
        default_policy: RoutePolicy,
    }

    #[derive(Debug, Clone)]
    struct RoutePolicy {
        route: String,
        max: u32,
        window: Duration,
    }

    impl LruRateLimiter {
        /// Construct a limiter with no per-route policies and the
        /// default fall-back (60 hits / 60 s).
        pub fn new() -> Self {
            Self::with_capacity_and_policies(DEFAULT_LRU_CAPACITY, Vec::new())
        }

        /// Construct a limiter with explicit per-route policies.
        /// Routes not present in `policies` fall back to the default
        /// (60 hits / 60 s).
        ///
        /// Panics if any `max` is zero or any `window` is zero — a zero
        /// limit is non-sensical (would deny every request) and a zero
        /// window would divide by zero when computing retry-after.
        pub fn with_policy(policies: Vec<(String, u32, Duration)>) -> Self {
            Self::with_capacity_and_policies(DEFAULT_LRU_CAPACITY, policies)
        }

        /// Construct with an explicit LRU capacity.
        pub fn with_capacity_and_policies(
            capacity: usize,
            policies: Vec<(String, u32, Duration)>,
        ) -> Self {
            let capacity =
                NonZeroUsize::new(capacity.max(1)).unwrap_or(NonZeroUsize::new(1).unwrap());

            let policies = policies
                .into_iter()
                .map(|(route, max, window)| {
                    assert!(max > 0, "rate-limit max must be non-zero");
                    assert!(!window.is_zero(), "rate-limit window must be non-zero");
                    RoutePolicy {
                        route,
                        max,
                        window,
                    }
                })
                .collect();

            Self {
                buckets: Mutex::new(LruCache::new(capacity)),
                policies,
                default_policy: RoutePolicy {
                    route: String::new(),
                    max: DEFAULT_MAX,
                    window: DEFAULT_WINDOW,
                },
            }
        }

        fn policy_for(&self, route: &str) -> &RoutePolicy {
            self.policies
                .iter()
                .find(|p| p.route == route)
                .unwrap_or(&self.default_policy)
        }

        fn check_sync(&self, key: &RateLimitKey<'_>, now: Instant) -> RateLimitDecision {
            let policy = self.policy_for(key.route);
            let canonical = key.canonical();

            let mut buckets = self.buckets.lock();
            let bucket = buckets.get_or_insert_mut(canonical, SlidingWindow::default);

            bucket.prune(now, policy.window);

            let window_secs = policy.window.as_secs().max(1);

            if bucket.hits.len() as u32 >= policy.max {
                // Retry-after = time until the oldest hit falls out of
                // the window. Ceil to whole seconds so clients never
                // retry slightly too early.
                let oldest = bucket.hits.first().copied().unwrap_or(now);
                let elapsed = now.saturating_duration_since(oldest);
                let remaining = policy.window.saturating_sub(elapsed);
                let retry_after_secs = ceil_secs(remaining).max(1);

                return RateLimitDecision::Deny {
                    retry_after_secs,
                    limit: policy.max,
                    window_secs,
                };
            }

            bucket.hits.push(now);
            RateLimitDecision::Allow
        }
    }

    impl Default for LruRateLimiter {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl RateLimiter for LruRateLimiter {
        async fn check(&self, key: &RateLimitKey<'_>) -> RateLimitDecision {
            // Synchronous under the hood — the mutex section is O(1)
            // amortised. Exposed async so future backends (Redis,
            // sharded) slot in without a trait change.
            self.check_sync(key, Instant::now())
        }
    }

    fn ceil_secs(d: Duration) -> u64 {
        let whole = d.as_secs();
        if d.subsec_nanos() > 0 {
            whole.saturating_add(1)
        } else {
            whole
        }
    }

    // --- unit tests ------------------------------------------------------

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::net::{IpAddr, Ipv4Addr};

        fn ip() -> RateLimitSubject<'static> {
            RateLimitSubject::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        }

        #[test]
        fn ceil_secs_rounds_up_fractional() {
            assert_eq!(ceil_secs(Duration::from_millis(500)), 1);
            assert_eq!(ceil_secs(Duration::from_secs(1)), 1);
            assert_eq!(ceil_secs(Duration::from_millis(1500)), 2);
            assert_eq!(ceil_secs(Duration::from_secs(0)), 0);
        }

        #[test]
        fn default_policy_used_when_route_unknown() {
            let limiter =
                LruRateLimiter::with_policy(vec![("foo".into(), 1, Duration::from_secs(5))]);
            let key = RateLimitKey {
                route: "bar",
                subject: ip(),
            };
            // First 60 should pass under the default policy.
            let now = Instant::now();
            for _ in 0..60 {
                assert_eq!(limiter.check_sync(&key, now), RateLimitDecision::Allow);
            }
            // 61st denies.
            let d = limiter.check_sync(&key, now);
            assert!(matches!(d, RateLimitDecision::Deny { .. }));
        }

        #[test]
        fn canonical_keys_separate_subjects() {
            let a = RateLimitKey {
                route: "r",
                subject: RateLimitSubject::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            };
            let b = RateLimitKey {
                route: "r",
                subject: RateLimitSubject::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 5))),
            };
            assert_ne!(a.canonical(), b.canonical());
        }

        #[test]
        fn canonical_keys_separate_routes() {
            let a = RateLimitKey {
                route: "r1",
                subject: ip(),
            };
            let b = RateLimitKey {
                route: "r2",
                subject: ip(),
            };
            assert_ne!(a.canonical(), b.canonical());
        }
    }
}

#[cfg(feature = "rate-limit")]
pub use lru_impl::{LruRateLimiter, DEFAULT_LRU_CAPACITY};
