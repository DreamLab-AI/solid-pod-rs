//! Inbox handler — dispatches verified inbound AP activities.
//!
//! JSS parity: mirrors `src/ap/routes/inbox.js` semantics. The handler
//! dispatches `Follow`, `Undo(Follow)`, `Accept(Follow)`, `Create`,
//! `Delete`, `Like`, and `Announce`; unknown activity types are
//! recorded but not acted on.
//!
//! Design: the transport (HTTP framework) is the caller's concern. We
//! take an already-verified request (see [`crate::http_sig`]) plus the
//! decoded JSON activity and return an outcome the caller can map to
//! an HTTP status.

use serde::{Deserialize, Serialize};

use crate::{error::InboxError, http_sig::VerifiedActor, store::Store};

/// The outcome of processing an inbox activity. The HTTP layer maps
/// this to status codes and any extra response side-effects
/// (e.g. enqueue an Accept reply).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InboxOutcome {
    /// Activity accepted and stored. Return 202.
    Accepted,
    /// Activity was a duplicate (already stored). Return 202.
    Duplicate,
    /// Activity was ignored (unknown type, or no-op). Return 202.
    Ignored,
    /// Follow request accepted — the caller should queue and deliver
    /// an `Accept` activity back to `follower_inbox`.
    FollowAccepted {
        follower_id: String,
        follower_inbox: Option<String>,
        accept_object: serde_json::Value,
    },
    /// Undo(Follow) — follower removed.
    FollowRemoved { follower_id: String },
    /// Accept(Follow) — our follow was accepted.
    FollowAcknowledged { target_id: String },
}

/// Handle a single inbound activity.
///
/// `local_actor_id` is the pod's own Actor ID (e.g.
/// `https://pod.example/profile/card.jsonld#me`).
///
/// The `verified_actor` argument must already have passed HTTP
/// Signature verification. If signature verification is being
/// soft-logged (JSS's default posture) callers may still hand through
/// an attested [`VerifiedActor`].
pub async fn handle_inbox(
    store: &Store,
    local_actor_id: &str,
    verified_actor: &VerifiedActor,
    activity: &serde_json::Value,
) -> Result<InboxOutcome, InboxError> {
    let activity_type = activity
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or(InboxError::MissingType)?;

    let was_new = store.record_inbox(local_actor_id, activity).await?;
    if !was_new {
        return Ok(InboxOutcome::Duplicate);
    }

    match activity_type {
        "Follow" => {
            let follower_id = activity
                .get("actor")
                .and_then(|v| v.as_str())
                .unwrap_or(&verified_actor.actor_url)
                .to_string();
            // Per JSS — the follower's inbox is looked up from the
            // actor document. That fetch is the caller's responsibility
            // (we'd pull it in via [`crate::http_sig::ActorKeyResolver`]
            // if this were a blocking op); we surface the follower_id
            // here and let the caller hydrate the inbox URL before
            // persisting if they want to.
            let follower_inbox = activity
                .get("actorInbox")
                .and_then(|v| v.as_str())
                .map(String::from);
            store
                .add_follower(
                    local_actor_id,
                    &follower_id,
                    follower_inbox.as_deref(),
                )
                .await?;
            let accept = build_accept(local_actor_id, activity);
            Ok(InboxOutcome::FollowAccepted {
                follower_id,
                follower_inbox,
                accept_object: accept,
            })
        }
        "Undo" => {
            let inner_type = activity
                .get("object")
                .and_then(|v| v.get("type"))
                .and_then(|v| v.as_str());
            if inner_type == Some("Follow") {
                let follower_id = activity
                    .get("actor")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&verified_actor.actor_url)
                    .to_string();
                store.remove_follower(local_actor_id, &follower_id).await?;
                return Ok(InboxOutcome::FollowRemoved { follower_id });
            }
            Ok(InboxOutcome::Ignored)
        }
        "Accept" => {
            let inner = activity.get("object");
            let inner_type = inner.and_then(|v| v.get("type")).and_then(|v| v.as_str());
            if inner_type == Some("Follow") {
                let target_id = inner
                    .and_then(|v| v.get("object"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(local_actor_id)
                    .to_string();
                store.accept_following(local_actor_id, &target_id).await?;
                return Ok(InboxOutcome::FollowAcknowledged { target_id });
            }
            Ok(InboxOutcome::Ignored)
        }
        "Create" | "Like" | "Announce" | "Delete" => Ok(InboxOutcome::Accepted),
        _ => Ok(InboxOutcome::Ignored),
    }
}

/// Build an `Accept(Follow)` activity to send back to a follower,
/// matching JSS's `outbox.createAccept` structure.
pub fn build_accept(local_actor_id: &str, follow: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{}/accept/{}", local_actor_id.trim_end_matches("#me"), uuid::Uuid::new_v4()),
        "type": "Accept",
        "actor": local_actor_id,
        "object": follow,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_verified(actor_url: &str) -> VerifiedActor {
        VerifiedActor {
            key_id: format!("{actor_url}#main-key"),
            actor_url: actor_url.to_string(),
            public_key_pem: "PEM".to_string(),
        }
    }

    #[tokio::test]
    async fn inbox_follow_accepts_and_stores_follower() {
        let store = Store::in_memory().await.unwrap();
        let me = "https://pod.example/profile/card.jsonld#me";
        let follow = serde_json::json!({
            "id": "https://remote.example/follows/1",
            "type": "Follow",
            "actor": "https://remote.example/actor",
            "actorInbox": "https://remote.example/inbox",
            "object": me
        });
        let outcome = handle_inbox(
            &store,
            me,
            &sample_verified("https://remote.example/actor"),
            &follow,
        )
        .await
        .unwrap();
        match outcome {
            InboxOutcome::FollowAccepted {
                follower_id,
                follower_inbox,
                accept_object,
            } => {
                assert_eq!(follower_id, "https://remote.example/actor");
                assert_eq!(
                    follower_inbox.as_deref(),
                    Some("https://remote.example/inbox")
                );
                assert_eq!(accept_object["type"], "Accept");
                assert_eq!(accept_object["object"]["id"], follow["id"]);
            }
            other => panic!("expected FollowAccepted, got {other:?}"),
        }
        assert!(store
            .is_follower(me, "https://remote.example/actor")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn inbox_undo_follow_removes_follower() {
        let store = Store::in_memory().await.unwrap();
        let me = "https://pod.example/profile/card.jsonld#me";
        store
            .add_follower(me, "https://remote.example/actor", Some("https://r/inbox"))
            .await
            .unwrap();
        let undo = serde_json::json!({
            "id": "https://remote.example/undos/1",
            "type": "Undo",
            "actor": "https://remote.example/actor",
            "object": {"type": "Follow", "actor": "https://remote.example/actor", "object": me}
        });
        let outcome = handle_inbox(
            &store,
            me,
            &sample_verified("https://remote.example/actor"),
            &undo,
        )
        .await
        .unwrap();
        assert!(matches!(outcome, InboxOutcome::FollowRemoved { .. }));
        assert!(!store
            .is_follower(me, "https://remote.example/actor")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn inbox_accept_marks_following() {
        let store = Store::in_memory().await.unwrap();
        let me = "https://pod.example/profile/card.jsonld#me";
        store
            .add_following(me, "https://remote.example/actor")
            .await
            .unwrap();
        let accept = serde_json::json!({
            "id": "https://remote.example/accepts/1",
            "type": "Accept",
            "actor": "https://remote.example/actor",
            "object": {
                "type": "Follow",
                "actor": me,
                "object": "https://remote.example/actor"
            }
        });
        let outcome = handle_inbox(
            &store,
            me,
            &sample_verified("https://remote.example/actor"),
            &accept,
        )
        .await
        .unwrap();
        assert!(matches!(outcome, InboxOutcome::FollowAcknowledged { .. }));
        assert!(store
            .is_following(me, "https://remote.example/actor")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn inbox_create_is_idempotent_by_id() {
        let store = Store::in_memory().await.unwrap();
        let me = "https://pod.example/profile/card.jsonld#me";
        let create = serde_json::json!({
            "id": "https://remote.example/notes/42/activity",
            "type": "Create",
            "actor": "https://remote.example/actor",
            "object": {"type": "Note", "content": "hi"}
        });
        let first = handle_inbox(
            &store,
            me,
            &sample_verified("https://remote.example/actor"),
            &create,
        )
        .await
        .unwrap();
        assert_eq!(first, InboxOutcome::Accepted);
        let second = handle_inbox(
            &store,
            me,
            &sample_verified("https://remote.example/actor"),
            &create,
        )
        .await
        .unwrap();
        assert_eq!(second, InboxOutcome::Duplicate);
    }

    #[tokio::test]
    async fn inbox_unknown_type_is_ignored() {
        let store = Store::in_memory().await.unwrap();
        let me = "https://pod.example/profile/card.jsonld#me";
        let weird = serde_json::json!({
            "id": "https://remote.example/x/1",
            "type": "Move",
            "actor": "https://remote.example/actor"
        });
        let outcome = handle_inbox(
            &store,
            me,
            &sample_verified("https://remote.example/actor"),
            &weird,
        )
        .await
        .unwrap();
        assert_eq!(outcome, InboxOutcome::Ignored);
    }

    #[tokio::test]
    async fn inbox_missing_type_errors() {
        let store = Store::in_memory().await.unwrap();
        let me = "https://pod.example/profile/card.jsonld#me";
        let bad = serde_json::json!({ "id": "x" });
        let err = handle_inbox(
            &store,
            me,
            &sample_verified("https://remote.example/actor"),
            &bad,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, InboxError::MissingType));
    }

    #[test]
    fn build_accept_has_expected_shape() {
        let follow = serde_json::json!({
            "id": "https://r/f/1",
            "type": "Follow",
            "actor": "https://r/a"
        });
        let accept = build_accept("https://pod.example/profile/card.jsonld#me", &follow);
        assert_eq!(accept["type"], "Accept");
        assert_eq!(accept["object"]["id"], "https://r/f/1");
        assert_eq!(
            accept["actor"],
            "https://pod.example/profile/card.jsonld#me"
        );
        assert!(accept.get("id").is_some());
    }
}
