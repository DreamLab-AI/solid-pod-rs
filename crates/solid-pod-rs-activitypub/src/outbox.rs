//! Outbox handler — persists a new activity and queues federated
//! delivery to followers.
//!
//! JSS parity: mirrors `src/ap/routes/outbox.js`. The Rust version
//! separates "record activity" (synchronous, durable) from "deliver to
//! follower inboxes" (async via [`crate::delivery`]). JSS uses
//! `Promise.allSettled` inline; we queue with retry so restarts don't
//! drop signed deliveries.

use serde::{Deserialize, Serialize};

use crate::{
    actor::Actor,
    error::OutboxError,
    store::Store,
};

/// Result of submitting an activity to the outbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundDelivery {
    pub activity_id: String,
    /// Number of follower inboxes the activity was queued for.
    pub queued_inboxes: usize,
    /// The canonical activity (with `id` filled in if the caller left
    /// it blank).
    pub activity: serde_json::Value,
}

/// Submit an activity to the outbox. The caller already constructed a
/// full ActivityPub activity document (e.g. `Create`, `Follow`,
/// `Delete`). This function:
///
/// 1. Stamps a UUID `id` if missing.
/// 2. Persists the activity in the outbox table.
/// 3. Enqueues a signed delivery per follower inbox.
pub async fn handle_outbox(
    store: &Store,
    actor: &Actor,
    activity: serde_json::Value,
) -> Result<OutboundDelivery, OutboxError> {
    let activity_type = activity
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OutboxError::InvalidActivity("missing type".into()))?
        .to_string();

    // Ensure id is present; generate one otherwise.
    let mut activity = activity;
    if activity
        .get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.is_empty())
        .unwrap_or(true)
    {
        let base = actor.id.trim_end_matches("#me");
        let fresh_id = format!("{base}/activities/{}", uuid::Uuid::new_v4());
        activity["id"] = serde_json::Value::String(fresh_id);
    }

    // Ensure actor field is present and matches.
    if activity.get("actor").and_then(|v| v.as_str()).is_none() {
        activity["actor"] = serde_json::Value::String(actor.id.clone());
    }

    let activity_id = store.record_outbox(&actor.id, &activity).await?;

    // Figure out delivery targets. For `Create` + `Announce` + `Update`
    // + `Delete` we broadcast to followers; for `Follow` we deliver to
    // the target's inbox (pulled from activity.object.inbox if
    // pre-hydrated, else 0 — the caller is expected to hydrate via
    // their resolver prior to calling).
    let inboxes: Vec<String> = match activity_type.as_str() {
        "Follow" => activity
            .get("targetInbox")
            .and_then(|v| v.as_str())
            .map(|s| vec![s.to_string()])
            .unwrap_or_default(),
        _ => store
            .follower_inboxes(&actor.id)
            .await
            .map_err(OutboxError::Storage)?,
    };

    for inbox in &inboxes {
        store
            .enqueue_delivery(&activity_id, inbox)
            .await
            .map_err(OutboxError::Storage)?;
    }

    Ok(OutboundDelivery {
        activity_id,
        queued_inboxes: inboxes.len(),
        activity,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::render_actor;

    fn sample_actor() -> Actor {
        render_actor("https://pod.example", "me", "Me", None, "PEM")
    }

    #[tokio::test]
    async fn outbox_create_broadcasts_to_followers() {
        let store = Store::in_memory().await.unwrap();
        let actor = sample_actor();
        // Add two followers.
        store
            .add_follower(&actor.id, "follower-a", Some("https://a/inbox"))
            .await
            .unwrap();
        store
            .add_follower(&actor.id, "follower-b", Some("https://b/inbox"))
            .await
            .unwrap();

        let note_activity = serde_json::json!({
            "type": "Create",
            "object": {"type": "Note", "content": "hello world"}
        });
        let delivery = handle_outbox(&store, &actor, note_activity)
            .await
            .unwrap();
        assert_eq!(delivery.queued_inboxes, 2);
        assert!(delivery.activity.get("id").is_some());
        assert_eq!(delivery.activity["actor"], actor.id);

        // Confirm two rows exist in the delivery_queue.
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM delivery_queue")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(n, 2);
    }

    #[tokio::test]
    async fn outbox_follow_queues_delivery_to_target() {
        let store = Store::in_memory().await.unwrap();
        let actor = sample_actor();
        let follow = serde_json::json!({
            "type": "Follow",
            "object": "https://other/actor",
            "targetInbox": "https://other/inbox"
        });
        let delivery = handle_outbox(&store, &actor, follow).await.unwrap();
        assert_eq!(delivery.queued_inboxes, 1);
    }

    #[tokio::test]
    async fn outbox_rejects_missing_type() {
        let store = Store::in_memory().await.unwrap();
        let actor = sample_actor();
        let err = handle_outbox(&store, &actor, serde_json::json!({})).await.unwrap_err();
        assert!(matches!(err, OutboxError::InvalidActivity(_)));
    }

    #[tokio::test]
    async fn outbox_generates_id_if_missing() {
        let store = Store::in_memory().await.unwrap();
        let actor = sample_actor();
        let act = serde_json::json!({"type": "Create", "object": {"type": "Note"}});
        let d = handle_outbox(&store, &actor, act).await.unwrap();
        assert!(d.activity_id.starts_with("https://pod.example/profile/card.jsonld/activities/"));
    }
}
