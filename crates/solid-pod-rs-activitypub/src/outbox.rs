//! Outbox handler — persists a new activity and queues federated
//! delivery to followers.
//!
//! JSS parity: mirrors `src/ap/routes/outbox.js`. The Rust version
//! separates "record activity" (synchronous, durable) from "deliver to
//! follower inboxes" (async via [`crate::delivery`]). JSS uses
//! `Promise.allSettled` inline; we queue with retry so restarts don't
//! drop signed deliveries.

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{actor::Actor, error::OutboxError, store::Store};

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

/// Wrap a raw Note (or content-only object) in a `Create` activity.
///
/// JSS v0.0.67 accepts both raw Notes and pre-wrapped Create activities
/// on the outbox POST endpoint. This helper normalises the former into
/// the latter so downstream processing always sees a proper activity.
fn wrap_note_in_create(actor: &Actor, note: serde_json::Value) -> serde_json::Value {
    let base = actor.id.trim_end_matches("#me");
    let activity_id = format!("{base}/activities/{}", uuid::Uuid::new_v4());
    let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    // Ensure the Note itself has an id.
    let mut note = note;
    if note
        .get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.is_empty())
        .unwrap_or(true)
    {
        let note_id = format!("{base}/posts/{}", uuid::Uuid::new_v4());
        note["id"] = serde_json::Value::String(note_id);
    }
    // Stamp attributedTo on the Note if missing.
    if note.get("attributedTo").is_none() {
        note["attributedTo"] = serde_json::Value::String(actor.id.clone());
    }
    // Stamp published on the Note if missing.
    if note.get("published").is_none() {
        note["published"] = serde_json::Value::String(now.clone());
    }

    serde_json::json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "type": "Create",
        "id": activity_id,
        "actor": actor.id,
        "published": now,
        "object": note,
    })
}

/// Handle a POST to the outbox endpoint. Accepts either:
///
/// 1. A pre-formed Activity (has `type` == `Create`/`Follow`/etc.) — passed
///    through to [`handle_outbox`].
/// 2. A raw Note (`type` == `"Note"`, or has `content` but no `type`) —
///    wrapped in a `Create` activity first, matching JSS v0.0.67 behaviour.
///
/// Returns the created/submitted activity via [`OutboundDelivery`].
pub async fn handle_outbox_post(
    store: &Store,
    actor: &Actor,
    body: serde_json::Value,
) -> Result<OutboundDelivery, OutboxError> {
    let activity_type = body.get("type").and_then(|v| v.as_str()).unwrap_or("");

    let activity = match activity_type {
        // Already a well-formed activity — pass through.
        "Create" | "Follow" | "Update" | "Delete" | "Announce" | "Like" | "Undo" | "Accept"
        | "Reject" | "Add" | "Remove" | "Block" => body,
        // Raw Note — wrap in Create.
        "Note" => wrap_note_in_create(actor, body),
        // No type but has content — treat as implicit Note.
        "" if body.get("content").is_some() => {
            let mut note = body;
            note["type"] = serde_json::Value::String("Note".into());
            wrap_note_in_create(actor, note)
        }
        // Unknown type — try wrapping in Create as a best-effort.
        other => {
            return Err(OutboxError::InvalidActivity(format!(
                "unsupported activity type for outbox POST: {other}"
            )));
        }
    };

    handle_outbox(store, actor, activity).await
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
        let delivery = handle_outbox(&store, &actor, note_activity).await.unwrap();
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
        let err = handle_outbox(&store, &actor, serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, OutboxError::InvalidActivity(_)));
    }

    #[tokio::test]
    async fn outbox_generates_id_if_missing() {
        let store = Store::in_memory().await.unwrap();
        let actor = sample_actor();
        let act = serde_json::json!({"type": "Create", "object": {"type": "Note"}});
        let d = handle_outbox(&store, &actor, act).await.unwrap();
        assert!(d
            .activity_id
            .starts_with("https://pod.example/profile/card.jsonld/activities/"));
    }

    // --- handle_outbox_post tests ---

    #[tokio::test]
    async fn outbox_post_wraps_raw_note_in_create() {
        let store = Store::in_memory().await.unwrap();
        let actor = sample_actor();
        let note = serde_json::json!({
            "type": "Note",
            "content": "Hello from outbox POST"
        });
        let delivery = handle_outbox_post(&store, &actor, note).await.unwrap();
        assert_eq!(delivery.activity["type"], "Create");
        assert_eq!(delivery.activity["object"]["type"], "Note");
        assert_eq!(
            delivery.activity["object"]["content"],
            "Hello from outbox POST"
        );
        // The Note should have attributedTo and published stamped.
        assert_eq!(delivery.activity["object"]["attributedTo"], actor.id);
        assert!(delivery.activity["object"]["published"].as_str().is_some());
        // The Create should have an id and published.
        assert!(delivery.activity["id"].as_str().is_some());
        assert!(delivery.activity["published"].as_str().is_some());
    }

    #[tokio::test]
    async fn outbox_post_passes_through_create_activity() {
        let store = Store::in_memory().await.unwrap();
        let actor = sample_actor();
        let create = serde_json::json!({
            "type": "Create",
            "object": {"type": "Note", "content": "pre-wrapped"}
        });
        let delivery = handle_outbox_post(&store, &actor, create).await.unwrap();
        assert_eq!(delivery.activity["type"], "Create");
        assert_eq!(delivery.activity["object"]["content"], "pre-wrapped");
    }

    #[tokio::test]
    async fn outbox_post_wraps_content_only_body_as_note() {
        let store = Store::in_memory().await.unwrap();
        let actor = sample_actor();
        // No type, but has content — should be treated as an implicit Note.
        let body = serde_json::json!({"content": "implicit note"});
        let delivery = handle_outbox_post(&store, &actor, body).await.unwrap();
        assert_eq!(delivery.activity["type"], "Create");
        assert_eq!(delivery.activity["object"]["type"], "Note");
        assert_eq!(delivery.activity["object"]["content"], "implicit note");
    }

    #[tokio::test]
    async fn outbox_post_rejects_unsupported_type() {
        let store = Store::in_memory().await.unwrap();
        let actor = sample_actor();
        let body = serde_json::json!({"type": "TentacleWiggle"});
        let err = handle_outbox_post(&store, &actor, body).await.unwrap_err();
        assert!(matches!(err, OutboxError::InvalidActivity(_)));
    }

    #[tokio::test]
    async fn outbox_post_note_delivers_to_followers() {
        let store = Store::in_memory().await.unwrap();
        let actor = sample_actor();
        store
            .add_follower(&actor.id, "f1", Some("https://f1/inbox"))
            .await
            .unwrap();
        store
            .add_follower(&actor.id, "f2", Some("https://f2/inbox"))
            .await
            .unwrap();

        let note = serde_json::json!({"type": "Note", "content": "fan-out test"});
        let delivery = handle_outbox_post(&store, &actor, note).await.unwrap();
        assert_eq!(delivery.queued_inboxes, 2);
    }
}
