//! Sprint 6 C — webhook delivery semantics: status-code policy,
//! `Retry-After` honouring, circuit breaker, and back-off jitter.
//!
//! Tests drive [`solid_pod_rs::notifications::WebhookChannelManager`]
//! against a wiremock HTTP endpoint.

#![cfg(feature = "webhook-signing")]

use std::time::{Duration, Instant};

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use solid_pod_rs::notifications::{
    ChangeNotification, WebhookChannelManager, WebhookDelivery,
};

fn sample_note(object: &str) -> ChangeNotification {
    ChangeNotification {
        context: "https://www.w3.org/ns/activitystreams".into(),
        id: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        kind: "Create".into(),
        object: object.into(),
        published: chrono::Utc::now().to_rfc3339(),
    }
}

/// 4xx responses *except* 410 Gone retain the subscription. 410 drops
/// the subscription immediately.
#[tokio::test]
async fn webhook_4xx_retains_subscription_except_410() {
    let server_401 = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook-401"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server_401)
        .await;

    let server_410 = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook-410"))
        .respond_with(ResponseTemplate::new(410))
        .mount(&server_410)
        .await;

    // max_attempts(1) means 4xx falls through to TransientRetry
    // immediately without wasting test time on back-off.
    let mgr = WebhookChannelManager::new()
        .with_max_attempts(1)
        .with_circuit_threshold(100); // don't interfere

    let sub_401 = mgr
        .subscribe(
            "/public/",
            &format!("{}/hook-401", server_401.uri()),
        )
        .await;
    let sub_410 = mgr
        .subscribe(
            "/public/",
            &format!("{}/hook-410", server_410.uri()),
        )
        .await;
    assert_eq!(mgr.active_subscriptions().await, 2);

    let note = sample_note("https://pod.example/public/a.ttl");
    let outcomes = mgr.deliver_all(&note, |t| t == "/public/").await;
    assert_eq!(outcomes.len(), 2);

    // 401 → transient, subscription retained.
    let out_401 = outcomes
        .iter()
        .find(|(id, _)| id == &sub_401.id)
        .expect("401 sub must be in outcomes")
        .1
        .clone();
    assert!(
        matches!(out_401, WebhookDelivery::TransientRetry { .. }),
        "401 should be TransientRetry, got {out_401:?}"
    );

    // 410 → fatal, subscription dropped.
    let out_410 = outcomes
        .iter()
        .find(|(id, _)| id == &sub_410.id)
        .expect("410 sub must be in outcomes")
        .1
        .clone();
    assert!(
        matches!(out_410, WebhookDelivery::FatalDrop { status: 410 }),
        "410 should be FatalDrop, got {out_410:?}"
    );

    // 401 stayed, 410 was removed.
    assert_eq!(
        mgr.active_subscriptions().await,
        1,
        "only the 410 subscription should have been dropped"
    );
}

/// 503 responses with a `Retry-After: 1` header make the manager sleep
/// at least ~1s between attempts, then a final 200 yields a successful
/// delivery. Max 3 attempts total.
#[tokio::test]
async fn webhook_5xx_retry_honours_retry_after_then_succeeds() {
    let server = MockServer::start().await;
    // Two 503s with Retry-After: 1, then a 200.
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(
            ResponseTemplate::new(503).insert_header("Retry-After", "1"),
        )
        .up_to_n_times(2)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let mgr = WebhookChannelManager::new()
        .with_max_attempts(3)
        .with_max_backoff(Duration::from_secs(10))
        .with_circuit_threshold(100);

    let note = sample_note("https://pod.example/public/a.ttl");
    let url = format!("{}/hook", server.uri());

    let start = Instant::now();
    let outcome = mgr.deliver_one(&url, &note).await;
    let elapsed = start.elapsed();

    assert!(
        matches!(outcome, WebhookDelivery::Delivered { status: 200 }),
        "expected Delivered{{status:200}}, got {outcome:?}"
    );
    // Two 1-second sleeps should have elapsed between the three
    // attempts; allow a little slack under load but require clearly
    // more than one second of total wait.
    assert!(
        elapsed >= Duration::from_millis(1800),
        "Retry-After not honoured: only slept {elapsed:?}"
    );
    // Success must reset the failure counter.
    assert_eq!(mgr.consecutive_failures(), 0);
}

/// After `circuit_threshold` consecutive TransientRetry outcomes the
/// breaker opens and subsequent calls short-circuit without touching
/// the network.
#[tokio::test]
async fn webhook_circuit_breaker_opens_after_threshold() {
    let server = MockServer::start().await;
    // Every POST returns 500.
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let threshold = 3_u32;
    let mgr = WebhookChannelManager::new()
        .with_max_attempts(1) // one attempt per deliver_one → fast test
        .with_max_backoff(Duration::from_millis(10))
        .with_circuit_threshold(threshold);

    let note = sample_note("https://pod.example/public/a.ttl");
    let url = format!("{}/hook", server.uri());

    // Drive the breaker to OPEN by accumulating `threshold` failures.
    for _ in 0..threshold {
        let outcome = mgr.deliver_one(&url, &note).await;
        assert!(matches!(outcome, WebhookDelivery::TransientRetry { .. }));
    }
    assert!(mgr.circuit_open(), "breaker should be OPEN after threshold");

    // Further calls must short-circuit with `circuit open` reason.
    let blocked = mgr.deliver_one(&url, &note).await;
    match blocked {
        WebhookDelivery::TransientRetry { reason } => {
            assert!(
                reason.contains("circuit open"),
                "expected circuit-open reason, got {reason}"
            );
        }
        other => panic!("expected TransientRetry(circuit open), got {other:?}"),
    }

    // Manual reset restores normal operation.
    mgr.reset_circuit();
    assert!(!mgr.circuit_open());
}

/// Over 100 trials the jittered back-off is both (a) bounded above by
/// the deterministic cap and (b) varies by at least ±20% relative to
/// that cap — i.e. the distribution is not degenerate.
#[test]
fn webhook_jitter_within_window() {
    let mgr = WebhookChannelManager::new()
        .with_max_backoff(Duration::from_secs(10));
    // Cap at attempt=2 is retry_base * 4 = 2s. We assert all samples
    // lie within [0.8 * cap, cap] (±20% window) and span at least
    // ~10% of that window.
    let cap = Duration::from_millis(500) * 4;
    let mut min = Duration::from_secs(u64::MAX / 2);
    let mut max = Duration::ZERO;
    for _ in 0..100 {
        let d = mgr.compute_backoff(2);
        assert!(
            d <= cap,
            "back-off {d:?} exceeded cap {cap:?}"
        );
        let floor = Duration::from_nanos(
            (cap.as_nanos() as f64 * 0.8) as u64,
        );
        assert!(
            d >= floor,
            "back-off {d:?} below 80% floor {floor:?}"
        );
        if d < min {
            min = d;
        }
        if d > max {
            max = d;
        }
    }
    // Spread across ~10% of the cap so we know jitter is actually
    // active rather than stuck on one value.
    let spread = max.saturating_sub(min);
    assert!(
        spread >= Duration::from_nanos((cap.as_nanos() as f64 * 0.05) as u64),
        "jitter spread {spread:?} too narrow — suggests constant back-off"
    );
}
