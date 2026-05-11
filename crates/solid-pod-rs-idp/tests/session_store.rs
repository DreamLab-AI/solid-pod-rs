//! Integration tests for `SessionStore` — opaque-token session management
//! and single-use authorisation-code lifecycle.
//!
//! These tests exercise the public API surface of `session.rs` from the
//! perspective of an external consumer (integration boundary), covering
//! edge cases not reached by the inline unit tests: concurrent creation,
//! `from_raw` round-trips, code field integrity, and TTL boundary
//! conditions.

use std::collections::HashSet;
use std::time::Duration;

use solid_pod_rs_idp::session::{SessionError, SessionId, SessionStore};

// ---------------------------------------------------------------------------
// SessionId generation + construction
// ---------------------------------------------------------------------------

#[test]
fn session_id_generate_produces_64_hex_chars() {
    let id = SessionId::generate();
    let s = id.as_str();
    assert_eq!(s.len(), 64, "32 bytes hex-encoded = 64 chars");
    assert!(
        s.chars().all(|c| c.is_ascii_hexdigit()),
        "session id must be pure hex"
    );
}

#[test]
fn session_id_generate_is_unique_across_100_ids() {
    let ids: HashSet<String> = (0..100)
        .map(|_| SessionId::generate().as_str().to_string())
        .collect();
    assert_eq!(ids.len(), 100, "100 generated ids must all be distinct");
}

#[test]
fn session_id_from_raw_round_trips() {
    let raw = "deadbeefcafe01234567890abcdef01234567890abcdef01234567890abcdef0";
    let id = SessionId::from_raw(raw);
    assert_eq!(id.as_str(), raw);
}

#[test]
fn session_id_equality_works() {
    let a = SessionId::from_raw("aaa");
    let b = SessionId::from_raw("aaa");
    let c = SessionId::from_raw("bbb");
    assert_eq!(a, b);
    assert_ne!(a, c);
}

// ---------------------------------------------------------------------------
// SessionStore: create + lookup + revoke
// ---------------------------------------------------------------------------

#[test]
fn create_session_returns_unique_ids_for_same_account() {
    let store = SessionStore::new();
    let id1 = store.create_session("acct-1");
    let id2 = store.create_session("acct-1");
    assert_ne!(
        id1.as_str(),
        id2.as_str(),
        "two sessions for the same account must have distinct ids"
    );
}

#[test]
fn lookup_returns_correct_account_id() {
    let store = SessionStore::new();
    let id = store.create_session("acct-alpha");
    let rec = store.lookup(&id).unwrap();
    assert_eq!(rec.account_id, "acct-alpha");
}

#[test]
fn lookup_unknown_session_returns_unknown_error() {
    let store = SessionStore::new();
    let fake = SessionId::from_raw("nonexistent");
    let err = store.lookup(&fake).unwrap_err();
    assert!(
        matches!(err, SessionError::Unknown),
        "expected Unknown, got {err:?}"
    );
}

#[test]
fn lookup_expired_session_returns_expired_error() {
    let store = SessionStore::new().with_ttls(Duration::from_millis(1), Duration::from_secs(600));
    let id = store.create_session("acct-exp");
    std::thread::sleep(Duration::from_millis(15));
    let err = store.lookup(&id).unwrap_err();
    assert!(
        matches!(err, SessionError::Expired),
        "expected Expired, got {err:?}"
    );
}

#[test]
fn revoke_makes_subsequent_lookup_fail() {
    let store = SessionStore::new();
    let id = store.create_session("acct-rev");
    store.revoke(&id);
    let err = store.lookup(&id).unwrap_err();
    assert!(
        matches!(err, SessionError::Unknown),
        "revoked session should return Unknown, got {err:?}"
    );
}

#[test]
fn revoke_is_idempotent() {
    let store = SessionStore::new();
    let id = store.create_session("acct-idem");
    store.revoke(&id);
    // Second revoke must not panic.
    store.revoke(&id);
    assert!(store.lookup(&id).is_err());
}

#[test]
fn revoke_nonexistent_session_is_noop() {
    let store = SessionStore::new();
    let fake = SessionId::from_raw("does-not-exist");
    // Must not panic.
    store.revoke(&fake);
}

// ---------------------------------------------------------------------------
// SessionStore: authorisation-code lifecycle
// ---------------------------------------------------------------------------

#[test]
fn issue_code_produces_64_hex_char_code() {
    let store = SessionStore::new();
    let rec = store.issue_code("client-a", "acct-1", "https://app/cb", None, None);
    assert_eq!(rec.code.len(), 64, "32 bytes hex-encoded = 64 chars");
    assert!(rec.code.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn issue_code_preserves_all_fields() {
    let store = SessionStore::new();
    let rec = store.issue_code(
        "client-b",
        "acct-2",
        "https://app.example/callback",
        Some("challenge-hash".to_string()),
        Some("openid webid".to_string()),
    );
    assert_eq!(rec.client_id, "client-b");
    assert_eq!(rec.account_id, "acct-2");
    assert_eq!(rec.redirect_uri, "https://app.example/callback");
    assert_eq!(rec.code_challenge.as_deref(), Some("challenge-hash"));
    assert_eq!(rec.requested_scope.as_deref(), Some("openid webid"));
}

#[test]
fn take_code_roundtrips_successfully() {
    let store = SessionStore::new();
    let rec = store.issue_code("c-1", "a-1", "https://app/cb", None, None);
    let taken = store.take_code(&rec.code).unwrap();
    assert_eq!(taken.client_id, "c-1");
    assert_eq!(taken.account_id, "a-1");
    assert_eq!(taken.redirect_uri, "https://app/cb");
}

#[test]
fn take_code_is_single_use() {
    let store = SessionStore::new();
    let rec = store.issue_code("c-2", "a-2", "https://app/cb", None, None);
    let first = store.take_code(&rec.code);
    assert!(first.is_some(), "first take must succeed");
    let second = store.take_code(&rec.code);
    assert!(
        second.is_none(),
        "second take must return None (single-use)"
    );
}

#[test]
fn take_code_returns_none_for_unknown_code() {
    let store = SessionStore::new();
    assert!(store.take_code("totally-unknown-code-string").is_none());
}

#[test]
fn take_code_returns_none_for_expired_code() {
    let store = SessionStore::new().with_ttls(Duration::from_secs(86400), Duration::from_millis(1));
    let rec = store.issue_code("c-exp", "a-exp", "https://app/cb", None, None);
    std::thread::sleep(Duration::from_millis(15));
    assert!(
        store.take_code(&rec.code).is_none(),
        "expired code must return None"
    );
}

#[test]
fn multiple_codes_are_independent() {
    let store = SessionStore::new();
    let r1 = store.issue_code("c-1", "a-1", "https://app/cb1", None, None);
    let r2 = store.issue_code("c-2", "a-2", "https://app/cb2", None, None);
    // Taking code1 must not affect code2.
    let t1 = store.take_code(&r1.code).unwrap();
    assert_eq!(t1.client_id, "c-1");
    let t2 = store.take_code(&r2.code).unwrap();
    assert_eq!(t2.client_id, "c-2");
}

// ---------------------------------------------------------------------------
// Concurrent session creation
// ---------------------------------------------------------------------------

#[test]
fn concurrent_session_creation_produces_distinct_ids() {
    let store = SessionStore::new();
    let handles: Vec<_> = (0..50)
        .map(|i| {
            let s = store.clone();
            std::thread::spawn(move || s.create_session(format!("acct-{i}")).as_str().to_string())
        })
        .collect();

    let ids: HashSet<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(
        ids.len(),
        50,
        "50 concurrent creates must yield 50 distinct session ids"
    );
}

// ---------------------------------------------------------------------------
// TTL boundary: with_ttls builder
// ---------------------------------------------------------------------------

#[test]
fn with_ttls_overrides_both_session_and_code_ttl() {
    let store = SessionStore::new().with_ttls(Duration::from_secs(1), Duration::from_secs(1));

    // Session with 1s TTL — immediate lookup succeeds.
    let id = store.create_session("acct-ttl");
    assert!(store.lookup(&id).is_ok());

    // Code with 1s TTL — immediate take succeeds.
    let rec = store.issue_code("c", "a", "https://app/cb", None, None);
    assert!(store.take_code(&rec.code).is_some());
}
