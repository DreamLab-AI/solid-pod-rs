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

use crate::{
    error::InboxError,
    http_sig::VerifiedActor,
    store::{host_of, Store},
};

/// Most followers one actor keeps; a further `Follow` is refused with
/// [`InboxError::Limit`] (an existing follower may still re-follow).
pub const MAX_FOLLOWERS: i64 = 5_000;

/// Most inbox rows kept per store; older rows are deleted first.
pub const MAX_INBOX_ROWS: i64 = 10_000;

/// Most inbox rows kept per sender; that sender's older rows are deleted
/// first, so one sender cannot evict another's rows.
pub const MAX_INBOX_ROWS_PER_SENDER: i64 = 200;

/// Most `Accept` replies kept in the outbox (one per follower is the
/// legitimate ceiling); older ones are deleted first.
pub const MAX_ACCEPT_ROWS: i64 = MAX_FOLLOWERS;

/// Most deliveries waiting in the queue. An owner post queues one row per
/// follower (at most [`MAX_FOLLOWERS`]), so this holds a few such posts; past
/// it new deliveries are refused rather than queued.
pub const MAX_DELIVERY_QUEUE: i64 = 4 * MAX_FOLLOWERS;

/// Most followers one remote host (by hostname, any port) may have. Many
/// actors on a shared instance are legitimate, so this is not tiny, but it is
/// small enough that one host cannot take the whole [`MAX_FOLLOWERS`] budget
/// or make the delivery worker's per-host queue deep.
pub const DEFAULT_MAX_FOLLOWERS_PER_HOST: i64 = 50;

/// Longest activity `id` accepted (bytes).
pub const MAX_ACTIVITY_ID_BYTES: usize = 2_048;

/// Operator-tunable inbox limits. [`Default`] is what [`handle_inbox`] uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InboxLimits {
    /// Most followers one remote host may have (see
    /// [`DEFAULT_MAX_FOLLOWERS_PER_HOST`]). A further new follower from that
    /// host is refused with [`InboxError::Limit`].
    pub max_followers_per_host: i64,
}

impl Default for InboxLimits {
    fn default() -> Self {
        Self {
            max_followers_per_host: DEFAULT_MAX_FOLLOWERS_PER_HOST,
        }
    }
}

/// Whether `a` and `b` are URLs with the same origin (scheme, host, port).
pub(crate) fn same_origin(a: &str, b: &str) -> bool {
    match (url::Url::parse(a), url::Url::parse(b)) {
        (Ok(a), Ok(b)) => a.origin().is_tuple() && a.origin() == b.origin(),
        _ => false,
    }
}

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
    handle_inbox_with(
        store,
        local_actor_id,
        verified_actor,
        activity,
        &InboxLimits::default(),
    )
    .await
}

/// [`handle_inbox`] with explicit [`InboxLimits`].
///
/// A `Follow` is refused unless the follower's inbox (and shared inbox) lie on
/// the same origin as its actor document: the follower cannot aim our
/// deliveries at a host it does not control.
pub async fn handle_inbox_with(
    store: &Store,
    local_actor_id: &str,
    verified_actor: &VerifiedActor,
    activity: &serde_json::Value,
    limits: &InboxLimits,
) -> Result<InboxOutcome, InboxError> {
    let activity_type = activity
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or(InboxError::MissingType)?;

    let claimed_actor = activity
        .get("actor")
        .and_then(|v| v.as_str())
        .ok_or_else(|| InboxError::ActorMismatch("missing actor".into()))?;
    if claimed_actor != verified_actor.actor_url {
        return Err(InboxError::ActorMismatch(format!(
            "claimed {claimed_actor}, verified {}",
            verified_actor.actor_url
        )));
    }

    if let Some(id) = activity.get("id").and_then(|v| v.as_str()) {
        if id.len() > MAX_ACTIVITY_ID_BYTES {
            return Err(InboxError::InvalidJson("activity id too long".into()));
        }
        // An id is minted by its actor's server: one on another origin would
        // let a sender claim identifiers it does not own.
        if !same_origin(id, &verified_actor.actor_url) {
            return Err(InboxError::ActorMismatch(
                "activity id is not on the actor's origin".into(),
            ));
        }
    }

    // Every Follow check runs before anything is stored, so a refused Follow
    // leaves no trace. A Follow from someone who already follows is
    // idempotent: nothing is stored, no Accept is built and no delivery is
    // queued, however many times (and under however many fresh ids) it is sent.
    if activity_type == "Follow" {
        if activity.get("object").and_then(|v| v.as_str()) != Some(local_actor_id) {
            return Err(InboxError::ActorMismatch(
                "Follow object is not the local actor".into(),
            ));
        }
        let follower_id = &verified_actor.actor_url;
        if store.is_follower(local_actor_id, follower_id).await? {
            return Ok(InboxOutcome::Duplicate);
        }
        if let Some(inbox) = &verified_actor.inbox_url {
            if !same_origin(inbox, follower_id) {
                return Err(InboxError::ActorMismatch(
                    "the follower's inbox is not on its actor's origin".into(),
                ));
            }
        }
        if store.follower_count(local_actor_id).await? >= MAX_FOLLOWERS {
            return Err(InboxError::Limit(format!(
                "more than {MAX_FOLLOWERS} followers"
            )));
        }
        if store
            .follower_count_for_host(local_actor_id, &host_of(follower_id))
            .await?
            >= limits.max_followers_per_host
        {
            return Err(InboxError::Limit(format!(
                "more than {} followers from one host",
                limits.max_followers_per_host
            )));
        }
    }

    let was_new = store
        .record_inbox_from(local_actor_id, &verified_actor.actor_url, activity)
        .await?;
    if !was_new {
        return Ok(InboxOutcome::Duplicate);
    }
    store
        .trim_inbox_for_sender(&verified_actor.actor_url, MAX_INBOX_ROWS_PER_SENDER)
        .await?;
    store.trim_inbox(MAX_INBOX_ROWS).await?;

    match activity_type {
        "Follow" => {
            let follower_id = verified_actor.actor_url.clone();
            // Per JSS — the follower's inbox is looked up from the
            // actor document. That fetch is the caller's responsibility
            // (we'd pull it in via [`crate::http_sig::ActorKeyResolver`]
            // if this were a blocking op); we surface the follower_id
            // here and let the caller hydrate the inbox URL before
            // persisting if they want to.
            // Never trust a caller-supplied `actorInbox`. The transport may
            // hydrate this from the already verified actor document.
            let follower_inbox = verified_actor.inbox_url.clone();
            store
                .add_follower(local_actor_id, &follower_id, follower_inbox.as_deref())
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
                let inner_actor = activity
                    .get("object")
                    .and_then(|v| v.get("actor"))
                    .and_then(|v| v.as_str());
                let inner_object = activity
                    .get("object")
                    .and_then(|v| v.get("object"))
                    .and_then(|v| v.as_str());
                if inner_actor != Some(verified_actor.actor_url.as_str())
                    || inner_object != Some(local_actor_id)
                {
                    return Err(InboxError::ActorMismatch(
                        "Undo(Follow) is not bound to signer and local actor".into(),
                    ));
                }
                let follower_id = verified_actor.actor_url.clone();
                store.remove_follower(local_actor_id, &follower_id).await?;
                return Ok(InboxOutcome::FollowRemoved { follower_id });
            }
            Ok(InboxOutcome::Ignored)
        }
        "Accept" => {
            let inner = activity.get("object");
            let inner_type = inner.and_then(|v| v.get("type")).and_then(|v| v.as_str());
            if inner_type == Some("Follow") {
                let inner_actor = inner.and_then(|v| v.get("actor")).and_then(|v| v.as_str());
                let target_id = inner
                    .and_then(|v| v.get("object"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(local_actor_id)
                    .to_string();
                if inner_actor != Some(local_actor_id) || target_id != verified_actor.actor_url {
                    return Err(InboxError::ActorMismatch(
                        "Accept(Follow) does not match the verified remote actor".into(),
                    ));
                }
                store.accept_following(local_actor_id, &target_id).await?;
                return Ok(InboxOutcome::FollowAcknowledged { target_id });
            }
            Ok(InboxOutcome::Ignored)
        }
        "Create" | "Like" | "Announce" | "Delete" => Ok(InboxOutcome::Accepted),
        _ => Ok(InboxOutcome::Ignored),
    }
}

/// Build an `Accept(Follow)` activity to send back to a follower, matching
/// JSS's `outbox.createAccept` structure.
///
/// The embedded `object` is rebuilt from the Follow's `id`, `actor` and
/// `object` strings only (each bounded); the sender's body is never copied,
/// so a remote cannot make the server store or send anything it chose.
pub fn build_accept(local_actor_id: &str, follow: &serde_json::Value) -> serde_json::Value {
    let text = |k: &str| {
        follow
            .get(k)
            .and_then(|v| v.as_str())
            .filter(|s| s.len() <= MAX_ACTIVITY_ID_BYTES)
            .map(|s| serde_json::Value::String(s.to_string()))
    };
    let mut embedded = serde_json::Map::new();
    embedded.insert("type".into(), "Follow".into());
    for k in ["id", "actor", "object"] {
        if let Some(v) = text(k) {
            embedded.insert(k.into(), v);
        }
    }
    let follow = serde_json::Value::Object(embedded);
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
            inbox_url: Some("https://remote.example/inbox".into()),
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
    async fn inbox_rejects_actor_claim_not_bound_to_signature() {
        let store = Store::in_memory().await.unwrap();
        let me = "https://pod.example/profile/card.jsonld#me";
        let forged = serde_json::json!({
            "id": "https://attacker.example/follows/forged",
            "type": "Follow",
            "actor": "https://victim.example/actor",
            "object": me
        });
        let result = handle_inbox(
            &store,
            me,
            &sample_verified("https://attacker.example/actor"),
            &forged,
        )
        .await;
        assert!(matches!(result, Err(InboxError::ActorMismatch(_))));
        assert!(!store
            .is_follower(me, "https://victim.example/actor")
            .await
            .unwrap());
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
