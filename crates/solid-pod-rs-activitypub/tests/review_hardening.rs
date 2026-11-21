//! Review hardening (parity4-review A1): what a remote sender can make the
//! store hold is bounded, per sender, and a repeated `Follow` is idempotent.
//!
//! Each test names the property it preserves.

use solid_pod_rs_activitypub::inbox::{MAX_ACTIVITY_ID_BYTES, MAX_INBOX_ROWS_PER_SENDER};
use solid_pod_rs_activitypub::{build_accept, handle_inbox, InboxOutcome, Store, VerifiedActor};

const ME: &str = "https://pod.example/profile/card.jsonld#me";

async fn file_store() -> (Store, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::connect(&format!(
        "sqlite://{}?mode=rwc",
        dir.path().join("ap.db").display()
    ))
    .await
    .unwrap();
    (store, dir)
}

fn verified(actor: &str) -> VerifiedActor {
    VerifiedActor {
        key_id: format!("{actor}#main-key"),
        actor_url: actor.to_string(),
        inbox_url: Some(format!("{}/inbox", actor.trim_end_matches("/actor"))),
        public_key_pem: String::new(),
    }
}

fn follow(actor: &str, id: &str) -> serde_json::Value {
    serde_json::json!({"id": id, "type": "Follow", "actor": actor, "object": ME})
}

/// Property: one sender's flood never removes another sender's rows and never
/// exceeds the per-sender bound.
#[tokio::test]
async fn one_sender_cannot_evict_another_sender() {
    let (store, _dir) = file_store().await;
    let victim = "https://victim.example/actor";
    let flooder = "https://flood.example/actor";
    let note = |actor: &str, n: usize| serde_json::json!({"id": format!("{actor}/n/{n}"), "type": "Create", "actor": actor});
    handle_inbox(&store, ME, &verified(victim), &note(victim, 0))
        .await
        .unwrap();
    for n in 0..(MAX_INBOX_ROWS_PER_SENDER as usize + 50) {
        handle_inbox(&store, ME, &verified(flooder), &note(flooder, n))
            .await
            .unwrap();
    }
    let total = store.inbox_count().await.unwrap();
    assert_eq!(
        total,
        MAX_INBOX_ROWS_PER_SENDER + 1,
        "flooder bounded, victim kept"
    );
    assert!(store
        .get_inbox(&format!("{victim}/n/0"))
        .await
        .unwrap()
        .is_some());
}

/// Property: a Follow from an existing follower, with a fresh id, adds no
/// inbox row, no Accept and no delivery (the outcome is not `FollowAccepted`).
#[tokio::test]
async fn a_refollow_from_an_existing_follower_is_idempotent() {
    let (store, _dir) = file_store().await;
    let who = "https://remote.example/actor";
    let first = handle_inbox(
        &store,
        ME,
        &verified(who),
        &follow(who, "https://remote.example/f/0"),
    )
    .await
    .unwrap();
    assert!(matches!(first, InboxOutcome::FollowAccepted { .. }));
    let rows = store.inbox_count().await.unwrap();
    for n in 1..300 {
        let again = handle_inbox(
            &store,
            ME,
            &verified(who),
            &follow(who, &format!("https://remote.example/f/{n}")),
        )
        .await
        .unwrap();
        assert!(
            !matches!(again, InboxOutcome::FollowAccepted { .. }),
            "follow {n} produced another Accept"
        );
    }
    assert_eq!(store.inbox_count().await.unwrap(), rows);
    assert_eq!(store.follower_count(ME).await.unwrap(), 1);
}

/// Property: the Accept carries only values the server verified or minted,
/// never the sender's body.
#[test]
fn the_accept_never_embeds_the_senders_body() {
    let mut f = follow("https://remote.example/actor", "https://remote.example/f/1");
    f["padding"] = serde_json::Value::String("x".repeat(200_000));
    f["content"] = serde_json::json!({"nested": "<script>"});
    let accept = build_accept(ME, &f);
    let text = accept.to_string();
    assert!(text.len() < 1_024, "accept is {} bytes", text.len());
    assert_eq!(accept["object"]["id"], "https://remote.example/f/1");
    assert_eq!(accept["object"]["type"], "Follow");
    assert_eq!(accept["object"]["actor"], "https://remote.example/actor");
    assert_eq!(accept["object"]["object"], ME);
    assert!(accept["object"].get("padding").is_none());
}

/// Property: an oversized activity id is refused before anything is stored.
#[tokio::test]
async fn an_oversized_activity_id_is_refused() {
    let (store, _dir) = file_store().await;
    let who = "https://remote.example/actor";
    let id = format!(
        "https://remote.example/{}",
        "a".repeat(MAX_ACTIVITY_ID_BYTES)
    );
    let err = handle_inbox(&store, ME, &verified(who), &follow(who, &id)).await;
    assert!(err.is_err());
    assert_eq!(store.inbox_count().await.unwrap(), 0);
}

/// Property: the delivery queue refuses work past its cap and the refusal
/// does not queue anything.
#[tokio::test]
async fn the_delivery_queue_is_capped() {
    let (store, _dir) = file_store().await;
    for n in 0..5 {
        let q = store
            .try_enqueue_delivery(&format!("a{n}"), "https://h.example/inbox", 5)
            .await
            .unwrap();
        assert!(q.is_some());
    }
    for n in 0..20 {
        let q = store
            .try_enqueue_delivery(&format!("b{n}"), "https://h.example/inbox", 5)
            .await
            .unwrap();
        assert!(q.is_none());
    }
    assert_eq!(store.delivery_queue_len().await.unwrap(), 5);
}

/// Property: server-generated `Accept` rows are trimmed to a bound while the
/// owner's own activities are untouched.
#[tokio::test]
async fn accept_rows_are_trimmed_and_owner_rows_kept() {
    let (store, _dir) = file_store().await;
    store
        .record_outbox(ME, &serde_json::json!({"id": "urn:o:1", "type": "Create"}))
        .await
        .unwrap();
    for n in 0..30 {
        store
            .record_outbox(
                ME,
                &serde_json::json!({"id": format!("urn:a:{n}"), "type": "Accept"}),
            )
            .await
            .unwrap();
    }
    store.trim_outbox_kind(ME, "Accept", 10).await.unwrap();
    assert_eq!(store.outbox_count().await.unwrap(), 11);
    assert!(store.load_activity("urn:o:1").await.unwrap().is_some());
}

/// Property: an `inbox` table from before rows carried a sender is upgraded in
/// place without losing rows.
#[tokio::test]
async fn a_legacy_inbox_table_is_migrated() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}?mode=rwc", dir.path().join("old.db").display());
    {
        let pool = sqlx::SqlitePool::connect(&url).await.unwrap();
        sqlx::query(
            "CREATE TABLE inbox (id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, \
             activity TEXT NOT NULL, received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO inbox (id, actor_id, activity) VALUES ('urn:x', 'me', ?1)")
            .bind(r#"{"id":"urn:x","actor":"https://s.example/a"}"#)
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
    }
    let store = Store::connect(&url).await.unwrap();
    assert_eq!(store.inbox_count().await.unwrap(), 1);
    let (sender,): (String,) = sqlx::query_as("SELECT sender FROM inbox")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(sender, "https://s.example/a");
}
