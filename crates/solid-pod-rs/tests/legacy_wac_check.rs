//! P0-3 (Sprint 5): WAC read enforcement on the legacy `solid-0.1`
//! WebSocket `sub` path. These tests are the RED phase — they assert
//! the authorizer + same-origin + fail-closed-default guarantees that
//! close CVE-NOTIF-001 (un-authenticated cross-origin subscription to
//! arbitrary pod resources).
//!
//! Gated behind the `legacy-notifications` feature so it compiles
//! alongside the existing `legacy_notifications_test.rs`.

#![cfg(feature = "legacy-notifications")]

use std::sync::Arc;

use solid_pod_rs::notifications::legacy::{
    AllowAllAuthorizer, DenyReason, LegacyNotificationChannel, SubscriptionAuthorizer,
};
use solid_pod_rs::storage::StorageEvent;
use tokio::sync::broadcast;

/// Authorizer that allows exactly the URIs in its allow-list and
/// rejects everything else with `DenyReason::Forbidden`. Simulates a
/// WAC evaluator without pulling the full WAC stack into this test.
struct WacAuthz {
    allowed: Vec<String>,
}

impl SubscriptionAuthorizer for WacAuthz {
    fn check(&self, target: &str, _: Option<&str>) -> Result<(), DenyReason> {
        if self.allowed.iter().any(|a| a == target) {
            Ok(())
        } else {
            Err(DenyReason::Forbidden)
        }
    }
}

/// WAC denies the target URI → server must emit the JSS-recognised
/// `err <uri> forbidden` frame and MUST NOT store the subscription.
#[test]
fn legacy_wac_denial_emits_forbidden_frame() {
    let (_tx, rx) = broadcast::channel::<StorageEvent>(16);
    let mut chan = LegacyNotificationChannel::new(rx)
        .with_authorizer(Arc::new(WacAuthz { allowed: vec![] }))
        .with_server_origin("https://pod.example.org".into());

    let err = chan
        .subscribe("https://pod.example.org/private".into())
        .unwrap_err();

    assert_eq!(err, "err https://pod.example.org/private forbidden");
    assert_eq!(chan.subscription_count(), 0);
}

/// WAC permits the target → subscription stored, no error.
#[test]
fn legacy_wac_allowed_subscription_succeeds() {
    let (_tx, rx) = broadcast::channel::<StorageEvent>(16);
    let mut chan = LegacyNotificationChannel::new(rx)
        .with_authorizer(Arc::new(WacAuthz {
            allowed: vec!["https://pod.example.org/public".into()],
        }))
        .with_server_origin("https://pod.example.org".into());

    chan.subscribe("https://pod.example.org/public".into())
        .expect("allowed target should subscribe");

    assert_eq!(chan.subscription_count(), 1);
}

/// A cross-origin target (different host to `server_origin`) is
/// rejected with `forbidden` regardless of the authorizer's opinion.
/// The same-origin check runs before the WAC check so the authorizer
/// is never consulted for foreign origins.
#[test]
fn legacy_cross_origin_subscription_rejected() {
    let (_tx, rx) = broadcast::channel::<StorageEvent>(16);
    let mut chan = LegacyNotificationChannel::new(rx)
        .with_authorizer(Arc::new(AllowAllAuthorizer))
        .with_server_origin("https://pod.example.org".into());

    let err = chan
        .subscribe("https://other.example/x".into())
        .unwrap_err();

    assert!(
        err.ends_with("forbidden"),
        "cross-origin should deny with forbidden, got: {err}"
    );
    assert_eq!(chan.subscription_count(), 0);
}

/// No authorizer configured → default is `DenyAllAuthorizer`
/// (fail-closed). Any subscription attempt must be rejected.
#[test]
fn legacy_default_authorizer_is_deny_all_failclosed() {
    let (_tx, rx) = broadcast::channel::<StorageEvent>(16);
    let mut chan = LegacyNotificationChannel::new(rx);

    let err = chan
        .subscribe("https://anything.example/x".into())
        .unwrap_err();

    assert!(
        err.ends_with("forbidden"),
        "default authorizer must be deny-all, got: {err}"
    );
    assert_eq!(chan.subscription_count(), 0);
}
