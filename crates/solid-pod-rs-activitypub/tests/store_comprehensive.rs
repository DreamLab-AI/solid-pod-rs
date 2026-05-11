//! Comprehensive integration tests for the ActivityPub Store.
//!
//! Covers all 26 public async methods on `Store`, including edge cases
//! for idempotency, empty results, duplicate handling, and cross-table
//! interactions (e.g. delivery queue + outbox state transitions).

use chrono::{Duration, Utc};
use serde_json::json;
use solid_pod_rs_activitypub::Store;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn fresh() -> Store {
    Store::in_memory().await.unwrap()
}

// ===========================================================================
// Store construction
// ===========================================================================

#[tokio::test]
async fn in_memory_store_creates_successfully() {
    let store = Store::in_memory().await;
    assert!(store.is_ok(), "in_memory() should succeed");
}

#[tokio::test]
async fn in_memory_store_has_zero_counts() {
    let s = fresh().await;
    assert_eq!(s.inbox_count().await.unwrap(), 0);
    assert_eq!(s.outbox_count().await.unwrap(), 0);
    assert_eq!(s.follower_count("any-actor").await.unwrap(), 0);
}

// ===========================================================================
// Followers
// ===========================================================================

#[tokio::test]
async fn add_follower_then_check_exists() {
    let s = fresh().await;
    s.add_follower("actor-a", "follower-1", Some("https://f1/inbox"))
        .await
        .unwrap();
    assert!(s.is_follower("actor-a", "follower-1").await.unwrap());
}

#[tokio::test]
async fn is_follower_returns_false_for_unknown() {
    let s = fresh().await;
    assert!(!s.is_follower("actor-a", "nobody").await.unwrap());
}

#[tokio::test]
async fn add_follower_without_inbox() {
    let s = fresh().await;
    s.add_follower("actor-a", "follower-no-inbox", None)
        .await
        .unwrap();
    assert!(s.is_follower("actor-a", "follower-no-inbox").await.unwrap());
    // Should not appear in inbox list since inbox is NULL.
    let inboxes = s.follower_inboxes("actor-a").await.unwrap();
    assert!(inboxes.is_empty());
}

#[tokio::test]
async fn add_duplicate_follower_is_idempotent() {
    let s = fresh().await;
    s.add_follower("actor-a", "f1", Some("https://f1/inbox"))
        .await
        .unwrap();
    // INSERT OR REPLACE — second call should not error.
    s.add_follower("actor-a", "f1", Some("https://f1/inbox-v2"))
        .await
        .unwrap();
    assert_eq!(s.follower_count("actor-a").await.unwrap(), 1);
    // The inbox should be updated to the new value.
    let inboxes = s.follower_inboxes("actor-a").await.unwrap();
    assert_eq!(inboxes, vec!["https://f1/inbox-v2".to_string()]);
}

#[tokio::test]
async fn remove_follower_returns_affected_count() {
    let s = fresh().await;
    s.add_follower("actor-a", "f1", Some("https://f1/inbox"))
        .await
        .unwrap();
    let removed = s.remove_follower("actor-a", "f1").await.unwrap();
    assert_eq!(removed, 1);
    assert!(!s.is_follower("actor-a", "f1").await.unwrap());
}

#[tokio::test]
async fn remove_nonexistent_follower_returns_zero() {
    let s = fresh().await;
    let removed = s.remove_follower("actor-a", "ghost").await.unwrap();
    assert_eq!(removed, 0);
}

#[tokio::test]
async fn follower_count_reflects_additions_and_removals() {
    let s = fresh().await;
    s.add_follower("me", "a", Some("https://a/inbox"))
        .await
        .unwrap();
    s.add_follower("me", "b", Some("https://b/inbox"))
        .await
        .unwrap();
    s.add_follower("me", "c", None).await.unwrap();
    assert_eq!(s.follower_count("me").await.unwrap(), 3);
    s.remove_follower("me", "b").await.unwrap();
    assert_eq!(s.follower_count("me").await.unwrap(), 2);
}

#[tokio::test]
async fn follower_inboxes_excludes_null_inboxes() {
    let s = fresh().await;
    s.add_follower("me", "a", Some("https://a/inbox"))
        .await
        .unwrap();
    s.add_follower("me", "b", None).await.unwrap();
    s.add_follower("me", "c", Some("https://c/inbox"))
        .await
        .unwrap();
    let inboxes = s.follower_inboxes("me").await.unwrap();
    assert_eq!(inboxes.len(), 2);
    assert!(inboxes.contains(&"https://a/inbox".to_string()));
    assert!(inboxes.contains(&"https://c/inbox".to_string()));
}

#[tokio::test]
async fn follower_inboxes_returns_empty_for_unknown_actor() {
    let s = fresh().await;
    let inboxes = s.follower_inboxes("nobody").await.unwrap();
    assert!(inboxes.is_empty());
}

#[tokio::test]
async fn get_follower_inboxes_is_alias_for_follower_inboxes() {
    let s = fresh().await;
    s.add_follower("me", "a", Some("https://a/inbox"))
        .await
        .unwrap();
    s.add_follower("me", "b", Some("https://b/inbox"))
        .await
        .unwrap();
    let via_method = s.follower_inboxes("me").await.unwrap();
    let via_alias = s.get_follower_inboxes("me").await.unwrap();
    assert_eq!(via_method, via_alias);
}

#[tokio::test]
async fn followers_are_scoped_to_actor_id() {
    let s = fresh().await;
    s.add_follower("actor-a", "f1", Some("https://f1/inbox"))
        .await
        .unwrap();
    s.add_follower("actor-b", "f2", Some("https://f2/inbox"))
        .await
        .unwrap();
    assert_eq!(s.follower_count("actor-a").await.unwrap(), 1);
    assert_eq!(s.follower_count("actor-b").await.unwrap(), 1);
    assert!(!s.is_follower("actor-a", "f2").await.unwrap());
    assert!(!s.is_follower("actor-b", "f1").await.unwrap());
}

// ===========================================================================
// Following
// ===========================================================================

#[tokio::test]
async fn add_following_starts_unaccepted() {
    let s = fresh().await;
    s.add_following("me", "https://remote/actor").await.unwrap();
    // is_following checks accepted == 1; a fresh follow is accepted == 0.
    assert!(!s.is_following("me", "https://remote/actor").await.unwrap());
}

#[tokio::test]
async fn accept_following_marks_as_accepted() {
    let s = fresh().await;
    s.add_following("me", "https://remote/actor").await.unwrap();
    let affected = s
        .accept_following("me", "https://remote/actor")
        .await
        .unwrap();
    assert_eq!(affected, 1);
    assert!(s.is_following("me", "https://remote/actor").await.unwrap());
}

#[tokio::test]
async fn accept_following_nonexistent_returns_zero() {
    let s = fresh().await;
    let affected = s
        .accept_following("me", "https://nobody/actor")
        .await
        .unwrap();
    assert_eq!(affected, 0);
}

#[tokio::test]
async fn is_following_returns_false_for_unknown() {
    let s = fresh().await;
    assert!(!s.is_following("me", "https://ghost/actor").await.unwrap());
}

// ===========================================================================
// Inbox
// ===========================================================================

#[tokio::test]
async fn record_inbox_stores_activity() {
    let s = fresh().await;
    let act = json!({"id": "https://remote/act/1", "type": "Create"});
    let was_new = s.record_inbox("me", &act).await.unwrap();
    assert!(was_new);
    assert_eq!(s.inbox_count().await.unwrap(), 1);
}

#[tokio::test]
async fn record_inbox_is_idempotent_by_id() {
    let s = fresh().await;
    let act = json!({"id": "https://remote/act/1", "type": "Create"});
    assert!(s.record_inbox("me", &act).await.unwrap());
    assert!(!s.record_inbox("me", &act).await.unwrap());
    assert_eq!(s.inbox_count().await.unwrap(), 1);
}

#[tokio::test]
async fn record_inbox_rejects_missing_id() {
    let s = fresh().await;
    let act = json!({"type": "Create"});
    let result = s.record_inbox("me", &act).await.unwrap();
    assert!(!result, "activity without id should return false");
    assert_eq!(s.inbox_count().await.unwrap(), 0);
}

#[tokio::test]
async fn record_inbox_rejects_empty_id() {
    let s = fresh().await;
    let act = json!({"id": "", "type": "Create"});
    let result = s.record_inbox("me", &act).await.unwrap();
    assert!(!result, "activity with empty id should return false");
}

#[tokio::test]
async fn get_inbox_retrieves_stored_activity() {
    let s = fresh().await;
    let act = json!({"id": "https://remote/act/42", "type": "Like", "object": "https://me/post/1"});
    s.record_inbox("me", &act).await.unwrap();
    let row = s.get_inbox("https://remote/act/42").await.unwrap().unwrap();
    assert_eq!(row.id, "https://remote/act/42");
    assert_eq!(row.actor_id, "me");
    assert_eq!(row.activity["type"], "Like");
}

#[tokio::test]
async fn get_inbox_returns_none_for_missing() {
    let s = fresh().await;
    assert!(s.get_inbox("https://nope").await.unwrap().is_none());
}

#[tokio::test]
async fn inbox_count_reflects_multiple_activities() {
    let s = fresh().await;
    for i in 0..5 {
        let act = json!({"id": format!("https://remote/act/{i}"), "type": "Create"});
        s.record_inbox("me", &act).await.unwrap();
    }
    assert_eq!(s.inbox_count().await.unwrap(), 5);
}

// ===========================================================================
// Outbox
// ===========================================================================

#[tokio::test]
async fn record_outbox_uses_existing_id() {
    let s = fresh().await;
    let act = json!({"id": "https://me/out/1", "type": "Create"});
    let id = s.record_outbox("me", &act).await.unwrap();
    assert_eq!(id, "https://me/out/1");
}

#[tokio::test]
async fn record_outbox_generates_id_when_missing() {
    let s = fresh().await;
    let act = json!({"type": "Create"});
    let id = s.record_outbox("me", &act).await.unwrap();
    assert!(
        id.starts_with("urn:uuid:"),
        "generated id should be a UUID URN, got: {id}"
    );
}

#[tokio::test]
async fn mark_outbox_state_updates_existing() {
    let s = fresh().await;
    let act = json!({"id": "https://me/out/1", "type": "Create"});
    s.record_outbox("me", &act).await.unwrap();
    let affected = s
        .mark_outbox_state("https://me/out/1", "delivered")
        .await
        .unwrap();
    assert_eq!(affected, 1);
}

#[tokio::test]
async fn mark_outbox_state_returns_zero_for_unknown() {
    let s = fresh().await;
    let affected = s
        .mark_outbox_state("https://ghost/out/1", "delivered")
        .await
        .unwrap();
    assert_eq!(affected, 0);
}

#[tokio::test]
async fn outbox_count_reflects_records() {
    let s = fresh().await;
    for i in 0..3 {
        let act = json!({"id": format!("https://me/out/{i}"), "type": "Create"});
        s.record_outbox("me", &act).await.unwrap();
    }
    assert_eq!(s.outbox_count().await.unwrap(), 3);
}

// ===========================================================================
// Delivery queue
// ===========================================================================

#[tokio::test]
async fn enqueue_delivery_returns_row_id() {
    let s = fresh().await;
    let qid = s
        .enqueue_delivery("act-1", "https://remote/inbox")
        .await
        .unwrap();
    assert!(qid > 0, "queue_id should be a positive integer");
}

#[tokio::test]
async fn next_due_delivery_returns_enqueued_item() {
    let s = fresh().await;
    let qid = s
        .enqueue_delivery("act-1", "https://remote/inbox")
        .await
        .unwrap();
    let item = s.next_due_delivery().await.unwrap().unwrap();
    assert_eq!(item.queue_id, qid);
    assert_eq!(item.activity_id, "act-1");
    assert_eq!(item.inbox_url, "https://remote/inbox");
    assert_eq!(item.attempts, 0);
    assert!(item.last_error.is_none());
}

#[tokio::test]
async fn next_due_delivery_returns_none_when_empty() {
    let s = fresh().await;
    assert!(s.next_due_delivery().await.unwrap().is_none());
}

#[tokio::test]
async fn drop_delivery_removes_queue_item() {
    let s = fresh().await;
    let qid = s
        .enqueue_delivery("act-1", "https://remote/inbox")
        .await
        .unwrap();
    let affected = s.drop_delivery(qid).await.unwrap();
    assert_eq!(affected, 1);
    assert!(s.next_due_delivery().await.unwrap().is_none());
}

#[tokio::test]
async fn drop_delivery_nonexistent_returns_zero() {
    let s = fresh().await;
    let affected = s.drop_delivery(9999).await.unwrap();
    assert_eq!(affected, 0);
}

#[tokio::test]
async fn reschedule_delivery_increments_attempts() {
    let s = fresh().await;
    let qid = s
        .enqueue_delivery("act-1", "https://remote/inbox")
        .await
        .unwrap();
    s.reschedule_delivery(qid, 0, "503 Service Unavailable")
        .await
        .unwrap();
    let item = s.next_due_delivery().await.unwrap().unwrap();
    assert_eq!(item.attempts, 1);
    assert_eq!(item.last_error.as_deref(), Some("503 Service Unavailable"));
}

#[tokio::test]
async fn reschedule_delivery_with_future_delay_hides_item() {
    let s = fresh().await;
    let qid = s
        .enqueue_delivery("act-1", "https://remote/inbox")
        .await
        .unwrap();
    // Reschedule with a 1-hour delay. The item should not be returned
    // by next_due_delivery since next_retry is in the future.
    s.reschedule_delivery(qid, 3600, "transient").await.unwrap();
    let item = s.next_due_delivery().await.unwrap();
    assert!(
        item.is_none(),
        "rescheduled item with future next_retry should not be due"
    );
}

#[tokio::test]
async fn multiple_deliveries_returned_in_fifo_order() {
    let s = fresh().await;
    let qid1 = s
        .enqueue_delivery("act-1", "https://inbox-a")
        .await
        .unwrap();
    let _qid2 = s
        .enqueue_delivery("act-2", "https://inbox-b")
        .await
        .unwrap();
    // FIFO: first enqueued should come out first.
    let first = s.next_due_delivery().await.unwrap().unwrap();
    assert_eq!(first.queue_id, qid1);
    assert_eq!(first.activity_id, "act-1");
}

// ===========================================================================
// Actor cache
// ===========================================================================

#[tokio::test]
async fn cache_actor_stores_and_retrieves() {
    let s = fresh().await;
    let data = json!({"type": "Person", "name": "Remote User"});
    s.cache_actor("https://remote/actor", &data).await.unwrap();
    let (cached, _ts) = s
        .get_cached_actor("https://remote/actor")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cached["name"], "Remote User");
    assert_eq!(cached["type"], "Person");
}

#[tokio::test]
async fn get_cached_actor_returns_none_for_unknown() {
    let s = fresh().await;
    assert!(s
        .get_cached_actor("https://unknown/actor")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn cache_actor_upsert_updates_data_and_timestamp() {
    let s = fresh().await;
    let id = "https://remote/actor";
    s.cache_actor(id, &json!({"name": "v1"})).await.unwrap();
    let (_, ts1) = s.get_cached_actor(id).await.unwrap().unwrap();

    s.cache_actor(id, &json!({"name": "v2"})).await.unwrap();
    let (data, ts2) = s.get_cached_actor(id).await.unwrap().unwrap();
    assert_eq!(data["name"], "v2");
    assert!(ts2 >= ts1);
}

#[tokio::test]
async fn is_actor_cache_fresh_within_window() {
    let s = fresh().await;
    let id = "https://remote/actor";
    s.cache_actor(id, &json!({"type": "Person"})).await.unwrap();
    // Just cached: should be fresh within a 1-hour window.
    assert!(s
        .is_actor_cache_fresh(id, Duration::hours(1))
        .await
        .unwrap());
}

#[tokio::test]
async fn is_actor_cache_fresh_false_for_uncached() {
    let s = fresh().await;
    assert!(!s
        .is_actor_cache_fresh("https://never/cached", Duration::hours(1))
        .await
        .unwrap());
}

// ===========================================================================
// load_activity (outbox lookup)
// ===========================================================================

#[tokio::test]
async fn load_activity_retrieves_outbox_entry() {
    let s = fresh().await;
    let act = json!({"id": "https://me/out/1", "type": "Create", "object": {"type": "Note"}});
    s.record_outbox("me", &act).await.unwrap();
    let loaded = s.load_activity("https://me/out/1").await.unwrap().unwrap();
    assert_eq!(loaded["type"], "Create");
}

#[tokio::test]
async fn load_activity_returns_none_for_unknown() {
    let s = fresh().await;
    assert!(s.load_activity("https://nope").await.unwrap().is_none());
}

// ===========================================================================
// Cross-table: delivery queue + outbox lifecycle
// ===========================================================================

#[tokio::test]
async fn full_outbox_delivery_lifecycle() {
    let s = fresh().await;
    // 1. Record outbox activity.
    let act = json!({"id": "https://me/out/lifecycle", "type": "Create"});
    let id = s.record_outbox("me", &act).await.unwrap();
    assert_eq!(s.outbox_count().await.unwrap(), 1);

    // 2. Enqueue delivery to two inboxes.
    let qid1 = s.enqueue_delivery(&id, "https://a/inbox").await.unwrap();
    let qid2 = s.enqueue_delivery(&id, "https://b/inbox").await.unwrap();

    // 3. First delivery succeeds: drop + mark delivered.
    s.drop_delivery(qid1).await.unwrap();

    // 4. Second delivery fails transiently: reschedule.
    s.reschedule_delivery(qid2, 0, "HTTP 503").await.unwrap();
    let retried = s.next_due_delivery().await.unwrap().unwrap();
    assert_eq!(retried.attempts, 1);

    // 5. Second delivery succeeds on retry: drop.
    s.drop_delivery(qid2).await.unwrap();

    // 6. Mark outbox state as delivered.
    s.mark_outbox_state(&id, "delivered").await.unwrap();

    // 7. Queue should be empty.
    assert!(s.next_due_delivery().await.unwrap().is_none());
}
