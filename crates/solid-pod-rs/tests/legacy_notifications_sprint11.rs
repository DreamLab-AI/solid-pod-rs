//! Sprint 11, row 91 — full `solid-0.1` WebSocket protocol tests.
//!
//! Exercises `LegacyWebSocketSession` end-to-end against a stub WAC
//! Read checker. Distinct from `tests/legacy_notifications_test.rs`
//! (which covers the Sprint 4 broadcast-driver surface) — this file
//! locks in the session state machine that mirrors JSS
//! `websocket.js:1-147` line-by-line.
//!
//! Gated behind `legacy-notifications` to match the module.

#![cfg(feature = "legacy-notifications")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use solid_pod_rs::notifications::legacy::{
    ancestor_containers, LegacyFrame, LegacyWacRead, LegacyWebSocketSession,
};

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

/// Stub WAC checker that returns a fixed allow/deny verdict and counts
/// calls. Lets tests assert (a) re-check is invoked on fan-out and
/// (b) the decision reflects the stored verdict.
#[derive(Default)]
struct StubWac {
    allow: bool,
    calls: AtomicUsize,
}

impl StubWac {
    fn allow() -> Arc<Self> {
        Arc::new(Self {
            allow: true,
            calls: AtomicUsize::new(0),
        })
    }

    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl LegacyWacRead for StubWac {
    async fn can_read(&self, _webid: Option<&str>, _uri: &str) -> bool {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.allow
    }
}

// ---------------------------------------------------------------------------
// Row 91 spec tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sub_registers_subscription_and_acks() {
    let wac = StubWac::allow();
    let mut s = LegacyWebSocketSession::new(wac.clone(), Some("https://alice.example/#me".into()));

    let r = s.handle_message("sub https://pod.example/alice/").await;
    assert_eq!(r.frames.len(), 1);
    assert_eq!(
        r.frames[0],
        LegacyFrame::Ack("https://pod.example/alice/".into())
    );
    assert!(s.is_subscribed("https://pod.example/alice/"));
    assert_eq!(s.subscription_count(), 1);
    assert_eq!(wac.call_count(), 1, "WAC checked once on subscribe");
}

#[tokio::test]
async fn unsub_removes_subscription_and_acks() {
    let wac = StubWac::allow();
    let mut s = LegacyWebSocketSession::new(wac, None);

    let r = s.handle_message("sub https://p/x").await;
    assert_eq!(r.frames, vec![LegacyFrame::Ack("https://p/x".into())]);

    // JSS semantics: `unsub` has no positive ack. We mirror that by
    // emitting zero frames, but the subscription must be gone.
    let r = s.handle_message("unsub https://p/x").await;
    assert!(r.frames.is_empty());
    assert!(!s.is_subscribed("https://p/x"));
    assert_eq!(s.subscription_count(), 0);
}

#[tokio::test]
async fn pub_emits_for_exact_match() {
    let wac = StubWac::allow();
    let mut s = LegacyWebSocketSession::new(wac, None);
    s.handle_message("sub /pods/alice/posts/hello.ttl").await;

    let frames = s
        .on_resource_change("/pods/alice/posts/hello.ttl")
        .await;
    assert_eq!(
        frames,
        vec![LegacyFrame::Pub("/pods/alice/posts/hello.ttl".into())]
    );
}

#[tokio::test]
async fn pub_fans_out_to_ancestor_containers() {
    let wac = StubWac::allow();
    let mut s = LegacyWebSocketSession::new(wac, None);

    // Subscriber only has the container.
    s.handle_message("sub /pods/alice/").await;

    // Child resource changes — subscriber on `/pods/alice/` should see
    // a `pub` frame for the child URI.
    let frames = s
        .on_resource_change("/pods/alice/posts/hello.ttl")
        .await;
    assert_eq!(
        frames,
        vec![LegacyFrame::Pub("/pods/alice/posts/hello.ttl".into())]
    );
}

#[tokio::test]
async fn per_sub_wac_read_check_denies_forbidden() {
    // Subscribe-time WAC returns allow, but the re-check on fan-out
    // returns deny — simulates an ACL revocation between subscribe
    // and publish. Resulting frame must be `err`, not `pub`.
    struct Flipping {
        allow_on_call: Vec<bool>,
        idx: AtomicUsize,
    }

    #[async_trait]
    impl LegacyWacRead for Flipping {
        async fn can_read(&self, _webid: Option<&str>, _uri: &str) -> bool {
            let i = self.idx.fetch_add(1, Ordering::SeqCst);
            self.allow_on_call
                .get(i)
                .copied()
                .unwrap_or(*self.allow_on_call.last().unwrap_or(&false))
        }
    }

    let wac = Arc::new(Flipping {
        allow_on_call: vec![true, false], // subscribe: allow, fanout: deny
        idx: AtomicUsize::new(0),
    });
    let mut s = LegacyWebSocketSession::new(wac, None);

    let r = s.handle_message("sub /secret/").await;
    assert_eq!(r.frames, vec![LegacyFrame::Ack("/secret/".into())]);

    let frames = s.on_resource_change("/secret/file.ttl").await;
    assert_eq!(
        frames,
        vec![LegacyFrame::Err("/secret/file.ttl forbidden".into())],
        "revoked read must emit err, not silent-drop, per JSS semantics"
    );
}

#[tokio::test]
async fn caps_at_100_subs_per_connection() {
    let wac = StubWac::allow();
    let mut s = LegacyWebSocketSession::new(wac, None);

    // Fill to the hard limit (100).
    for i in 0..100 {
        let r = s.handle_message(&format!("sub /r/{i}")).await;
        assert_eq!(r.frames, vec![LegacyFrame::Ack(format!("/r/{i}"))]);
    }
    assert_eq!(s.subscription_count(), 100);

    // The 101st must be refused with the exact JSS-phrased message.
    let r = s.handle_message("sub /r/100").await;
    assert_eq!(
        r.frames,
        vec![LegacyFrame::Err("subscription limit reached".into())]
    );
    assert_eq!(s.subscription_count(), 100, "cap is hard");
}

#[tokio::test]
async fn rejects_url_over_2kib() {
    let wac = StubWac::allow();
    let mut s = LegacyWebSocketSession::new(wac, None);

    // 2049 bytes total URI — over the 2048 cap.
    let long_uri: String = "https://p/".chars().chain(std::iter::repeat('a').take(2049 - 10)).collect();
    assert_eq!(long_uri.len(), 2049);

    let r = s.handle_message(&format!("sub {long_uri}")).await;
    assert_eq!(r.frames, vec![LegacyFrame::Err("uri too long".into())]);
    assert_eq!(s.subscription_count(), 0);
}

#[tokio::test]
async fn unknown_command_returns_err() {
    let wac = StubWac::allow();
    let mut s = LegacyWebSocketSession::new(wac, None);

    let r = s.handle_message("gibberish /x").await;
    assert_eq!(r.frames, vec![LegacyFrame::Err("unknown command".into())]);

    let r = s.handle_message("PUB /x").await; // case-sensitive
    assert_eq!(r.frames, vec![LegacyFrame::Err("unknown command".into())]);
}

#[test]
fn ancestor_containers_handles_root() {
    assert!(ancestor_containers("/").is_empty());
    assert!(ancestor_containers("").is_empty());
    assert!(ancestor_containers("https://pod.example/").is_empty());
}

#[test]
fn ancestor_containers_handles_leaf() {
    let got = ancestor_containers("/a/b/c");
    assert_eq!(
        got,
        vec!["/a/b/".to_string(), "/a/".to_string(), "/".to_string()]
    );

    let got = ancestor_containers("https://pod.example/a/b/c.ttl");
    assert_eq!(
        got,
        vec![
            "https://pod.example/a/b/".to_string(),
            "https://pod.example/a/".to_string(),
            "https://pod.example/".to_string(),
        ]
    );
}

#[test]
fn ancestor_containers_dedups_trailing_slash() {
    // Container input `/a/b/` must yield the same list as `/a/b` —
    // the input container is never emitted as its own ancestor.
    let with_slash = ancestor_containers("/a/b/");
    let without_slash = ancestor_containers("/a/b");
    assert_eq!(with_slash, without_slash);
    assert_eq!(with_slash, vec!["/a/".to_string(), "/".to_string()]);
}
