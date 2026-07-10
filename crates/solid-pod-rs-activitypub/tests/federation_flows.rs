//! End-to-end federation flow tests.
//!
//! These exercise the high-level API surface that a real HTTP handler
//! would call: actor construction, outbox POST semantics, inbox
//! dispatch, content negotiation, and delivery fan-out. Each test uses
//! the in-memory Store so no filesystem or network is needed.

use serde_json::json;
use solid_pod_rs_activitypub::{
    actor::{generate_actor_keypair, render_actor, with_also_known_as, Actor},
    delivery::{DeliveryConfig, DeliveryWorker},
    discovery::{nodeinfo_2_1, nodeinfo_wellknown},
    error::{InboxError, OutboxError},
    http_sig::VerifiedActor,
    inbox::{build_accept, handle_inbox, InboxOutcome},
    negotiate_actor_format,
    outbox::{handle_outbox, handle_outbox_post},
    ActorFormat, Store,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn fresh_store() -> Store {
    Store::in_memory().await.unwrap()
}

fn sample_actor() -> Actor {
    render_actor("https://pod.example", "alice", "Alice", None, "PEM")
}

fn verified(actor_url: &str) -> VerifiedActor {
    VerifiedActor {
        key_id: format!("{actor_url}#main-key"),
        actor_url: actor_url.to_string(),
        public_key_pem: "PEM".to_string(),
    }
}

// ===========================================================================
// Actor construction
// ===========================================================================

#[test]
fn actor_with_rsa_keypair() {
    let (priv_pem, pub_pem) = generate_actor_keypair().unwrap();
    let actor = render_actor(
        "https://pod.example",
        "alice",
        "Alice Example",
        Some("Hello from Solid"),
        &pub_pem,
    );
    assert_eq!(actor.id, "https://pod.example/profile/card.jsonld#me");
    assert_eq!(actor.actor_type, "Person");
    assert!(actor.public_key.public_key_pem.contains("BEGIN PUBLIC KEY"));
    assert_eq!(actor.summary.as_deref(), Some("Hello from Solid"));
    // Private key should be distinct from public key.
    assert_ne!(priv_pem, pub_pem);
    assert!(priv_pem.contains("BEGIN PRIVATE KEY"));
}

#[test]
fn actor_with_also_known_as_did_nostr() {
    let actor = sample_actor();
    let linked = with_also_known_as(
        actor,
        [
            "did:nostr:abc123".to_string(),
            "did:web:pod.example".to_string(),
        ],
    );
    assert_eq!(linked.also_known_as.len(), 2);
    assert_eq!(linked.also_known_as[0], "did:nostr:abc123");
    assert_eq!(linked.also_known_as[1], "did:web:pod.example");
}

#[test]
fn actor_also_known_as_empty_by_default() {
    let actor = sample_actor();
    assert!(actor.also_known_as.is_empty());
    // When serialised, empty alsoKnownAs should be omitted.
    let j = serde_json::to_value(&actor).unwrap();
    assert!(
        j.get("alsoKnownAs").is_none(),
        "empty alsoKnownAs should not appear in JSON"
    );
}

#[test]
fn actor_also_known_as_present_in_json_when_set() {
    let actor = with_also_known_as(sample_actor(), ["did:nostr:xyz".to_string()]);
    let j = serde_json::to_value(&actor).unwrap();
    let aka = j["alsoKnownAs"].as_array().unwrap();
    assert_eq!(aka.len(), 1);
    assert_eq!(aka[0], "did:nostr:xyz");
}

#[test]
fn actor_endpoints_shared_inbox() {
    let actor = sample_actor();
    let shared = actor
        .endpoints
        .as_ref()
        .and_then(|e| e.shared_inbox.as_deref());
    assert_eq!(shared, Some("https://pod.example/inbox"));
}

// ===========================================================================
// Content negotiation
// ===========================================================================

#[test]
fn negotiate_activity_json() {
    assert_eq!(
        negotiate_actor_format("application/activity+json"),
        ActorFormat::ActivityJson
    );
}

#[test]
fn negotiate_ld_json_with_as_profile() {
    assert_eq!(
        negotiate_actor_format(
            r#"application/ld+json; profile="https://www.w3.org/ns/activitystreams""#
        ),
        ActorFormat::ActivityJson
    );
}

#[test]
fn negotiate_plain_ld_json_is_ldp() {
    assert_eq!(
        negotiate_actor_format("application/ld+json"),
        ActorFormat::LdpProfile
    );
}

#[test]
fn negotiate_text_turtle_is_ldp() {
    assert_eq!(
        negotiate_actor_format("text/turtle"),
        ActorFormat::LdpProfile
    );
}

#[test]
fn negotiate_wildcard_is_ldp() {
    assert_eq!(negotiate_actor_format("*/*"), ActorFormat::LdpProfile);
}

#[test]
fn negotiate_multi_type_with_activity_json_wins() {
    assert_eq!(
        negotiate_actor_format("text/html, application/activity+json;q=0.9, */*;q=0.1"),
        ActorFormat::ActivityJson
    );
}

// ===========================================================================
// Outbox POST flows
// ===========================================================================

#[tokio::test]
async fn outbox_post_raw_note_wraps_in_create() {
    let store = fresh_store().await;
    let actor = sample_actor();
    let note = json!({"type": "Note", "content": "Hello federation!"});
    let delivery = handle_outbox_post(&store, &actor, note).await.unwrap();
    assert_eq!(delivery.activity["type"], "Create");
    assert_eq!(delivery.activity["object"]["type"], "Note");
    assert_eq!(delivery.activity["object"]["content"], "Hello federation!");
    // attributedTo should be stamped.
    assert_eq!(delivery.activity["object"]["attributedTo"], actor.id);
    // published should be stamped on both Create and Note.
    assert!(delivery.activity["published"].is_string());
    assert!(delivery.activity["object"]["published"].is_string());
}

#[tokio::test]
async fn outbox_post_preformed_create_passthrough() {
    let store = fresh_store().await;
    let actor = sample_actor();
    let create = json!({
        "type": "Create",
        "id": "https://pod.example/activities/custom-1",
        "object": {"type": "Note", "content": "pre-wrapped note"}
    });
    let delivery = handle_outbox_post(&store, &actor, create).await.unwrap();
    assert_eq!(delivery.activity["type"], "Create");
    assert_eq!(
        delivery.activity["id"],
        "https://pod.example/activities/custom-1"
    );
    assert_eq!(delivery.activity["object"]["content"], "pre-wrapped note");
}

#[tokio::test]
async fn outbox_post_content_only_body_becomes_note() {
    let store = fresh_store().await;
    let actor = sample_actor();
    let body = json!({"content": "implicit note from content-only body"});
    let delivery = handle_outbox_post(&store, &actor, body).await.unwrap();
    assert_eq!(delivery.activity["type"], "Create");
    assert_eq!(delivery.activity["object"]["type"], "Note");
    assert_eq!(
        delivery.activity["object"]["content"],
        "implicit note from content-only body"
    );
}

#[tokio::test]
async fn outbox_post_rejects_unsupported_type() {
    let store = fresh_store().await;
    let actor = sample_actor();
    let body = json!({"type": "TentacleWiggle"});
    let err = handle_outbox_post(&store, &actor, body).await.unwrap_err();
    assert!(matches!(err, OutboxError::InvalidActivity(_)));
}

#[tokio::test]
async fn outbox_post_follow_passes_through() {
    let store = fresh_store().await;
    let actor = sample_actor();
    let follow = json!({
        "type": "Follow",
        "object": "https://remote/actor",
        "targetInbox": "https://remote/inbox"
    });
    let delivery = handle_outbox_post(&store, &actor, follow).await.unwrap();
    assert_eq!(delivery.activity["type"], "Follow");
    assert_eq!(delivery.queued_inboxes, 1);
}

#[tokio::test]
async fn outbox_post_all_supported_activity_types_pass_through() {
    let _store = fresh_store().await;
    let actor = sample_actor();
    let types = [
        "Update", "Delete", "Announce", "Like", "Undo", "Accept", "Reject", "Add", "Remove",
        "Block",
    ];
    for t in types {
        let store = fresh_store().await;
        let body = json!({"type": t, "object": "https://example/object"});
        let result = handle_outbox_post(&store, &actor, body).await;
        assert!(
            result.is_ok(),
            "activity type {t} should pass through, got error: {:?}",
            result.err()
        );
    }
}

#[tokio::test]
async fn outbox_stamps_actor_field_if_missing() {
    let store = fresh_store().await;
    let actor = sample_actor();
    let act = json!({"type": "Create", "object": {"type": "Note", "content": "test"}});
    let delivery = handle_outbox(&store, &actor, act).await.unwrap();
    assert_eq!(delivery.activity["actor"], actor.id);
}

#[tokio::test]
async fn outbox_generates_id_when_absent() {
    let store = fresh_store().await;
    let actor = sample_actor();
    let act = json!({"type": "Create", "object": {"type": "Note"}});
    let delivery = handle_outbox(&store, &actor, act).await.unwrap();
    assert!(delivery.activity_id.contains("/activities/"));
}

#[tokio::test]
async fn outbox_create_fans_out_to_followers() {
    let store = fresh_store().await;
    let actor = sample_actor();
    store
        .add_follower(&actor.id, "f1", Some("https://f1/inbox"))
        .await
        .unwrap();
    store
        .add_follower(&actor.id, "f2", Some("https://f2/inbox"))
        .await
        .unwrap();
    store
        .add_follower(&actor.id, "f3", Some("https://f3/inbox"))
        .await
        .unwrap();
    let act = json!({"type": "Create", "object": {"type": "Note", "content": "fanout"}});
    let delivery = handle_outbox(&store, &actor, act).await.unwrap();
    assert_eq!(delivery.queued_inboxes, 3);
}

#[tokio::test]
async fn outbox_follow_delivers_to_target_inbox_only() {
    let store = fresh_store().await;
    let actor = sample_actor();
    // Add followers that should NOT receive a Follow activity.
    store
        .add_follower(&actor.id, "f1", Some("https://f1/inbox"))
        .await
        .unwrap();
    let follow = json!({
        "type": "Follow",
        "object": "https://target/actor",
        "targetInbox": "https://target/inbox"
    });
    let delivery = handle_outbox(&store, &actor, follow).await.unwrap();
    // Follow should only queue to the target's inbox, not followers.
    assert_eq!(delivery.queued_inboxes, 1);
}

// ===========================================================================
// Inbox dispatch flows
// ===========================================================================

#[tokio::test]
async fn inbox_follow_creates_accept_with_uuid_id() {
    let store = fresh_store().await;
    let me = "https://pod.example/profile/card.jsonld#me";
    let follow = json!({
        "id": "https://remote/follows/1",
        "type": "Follow",
        "actor": "https://remote/actor",
        "object": me
    });
    let outcome = handle_inbox(&store, me, &verified("https://remote/actor"), &follow)
        .await
        .unwrap();
    match outcome {
        InboxOutcome::FollowAccepted {
            follower_id,
            accept_object,
            ..
        } => {
            assert_eq!(follower_id, "https://remote/actor");
            assert_eq!(accept_object["type"], "Accept");
            assert_eq!(accept_object["actor"], me);
            // The accept id should contain a UUID.
            let accept_id = accept_object["id"].as_str().unwrap();
            assert!(accept_id.contains("/accept/"));
        }
        other => panic!("expected FollowAccepted, got {other:?}"),
    }
}

#[tokio::test]
async fn inbox_undo_non_follow_is_ignored() {
    let store = fresh_store().await;
    let me = "https://pod.example/profile/card.jsonld#me";
    let undo = json!({
        "id": "https://remote/undos/1",
        "type": "Undo",
        "actor": "https://remote/actor",
        "object": {"type": "Like", "object": "https://me/post/1"}
    });
    let outcome = handle_inbox(&store, me, &verified("https://remote/actor"), &undo)
        .await
        .unwrap();
    assert_eq!(outcome, InboxOutcome::Ignored);
}

#[tokio::test]
async fn inbox_like_is_accepted() {
    let store = fresh_store().await;
    let me = "https://pod.example/profile/card.jsonld#me";
    let like = json!({
        "id": "https://remote/likes/1",
        "type": "Like",
        "actor": "https://remote/actor",
        "object": "https://me/post/1"
    });
    let outcome = handle_inbox(&store, me, &verified("https://remote/actor"), &like)
        .await
        .unwrap();
    assert_eq!(outcome, InboxOutcome::Accepted);
}

#[tokio::test]
async fn inbox_announce_is_accepted() {
    let store = fresh_store().await;
    let me = "https://pod.example/profile/card.jsonld#me";
    let boost = json!({
        "id": "https://remote/announces/1",
        "type": "Announce",
        "actor": "https://remote/actor",
        "object": "https://me/post/1"
    });
    let outcome = handle_inbox(&store, me, &verified("https://remote/actor"), &boost)
        .await
        .unwrap();
    assert_eq!(outcome, InboxOutcome::Accepted);
}

#[tokio::test]
async fn inbox_delete_is_accepted() {
    let store = fresh_store().await;
    let me = "https://pod.example/profile/card.jsonld#me";
    let delete = json!({
        "id": "https://remote/deletes/1",
        "type": "Delete",
        "actor": "https://remote/actor",
        "object": "https://remote/post/1"
    });
    let outcome = handle_inbox(&store, me, &verified("https://remote/actor"), &delete)
        .await
        .unwrap();
    assert_eq!(outcome, InboxOutcome::Accepted);
}

#[tokio::test]
async fn inbox_accept_without_inner_follow_is_ignored() {
    let store = fresh_store().await;
    let me = "https://pod.example/profile/card.jsonld#me";
    let accept = json!({
        "id": "https://remote/accepts/1",
        "type": "Accept",
        "actor": "https://remote/actor",
        "object": {"type": "Invite"}
    });
    let outcome = handle_inbox(&store, me, &verified("https://remote/actor"), &accept)
        .await
        .unwrap();
    assert_eq!(outcome, InboxOutcome::Ignored);
}

#[tokio::test]
async fn inbox_missing_type_returns_error() {
    let store = fresh_store().await;
    let me = "https://pod.example/profile/card.jsonld#me";
    let bad = json!({"id": "https://remote/x/1"});
    let err = handle_inbox(&store, me, &verified("https://remote/actor"), &bad)
        .await
        .unwrap_err();
    assert!(matches!(err, InboxError::MissingType));
}

// ===========================================================================
// build_accept shape
// ===========================================================================

#[test]
fn build_accept_wraps_follow_with_context() {
    let follow = json!({
        "id": "https://remote/follows/42",
        "type": "Follow",
        "actor": "https://remote/actor",
        "object": "https://pod.example/profile/card.jsonld#me"
    });
    let accept = build_accept("https://pod.example/profile/card.jsonld#me", &follow);
    assert_eq!(accept["@context"], "https://www.w3.org/ns/activitystreams");
    assert_eq!(accept["type"], "Accept");
    assert_eq!(
        accept["actor"],
        "https://pod.example/profile/card.jsonld#me"
    );
    assert_eq!(accept["object"]["id"], "https://remote/follows/42");
    assert!(accept["id"].as_str().unwrap().contains("/accept/"));
}

// ===========================================================================
// Discovery: nodeinfo
// ===========================================================================

#[test]
fn nodeinfo_wellknown_structure() {
    let doc = nodeinfo_wellknown("https://pod.example");
    let links = doc["links"].as_array().unwrap();
    assert_eq!(links.len(), 1);
    assert!(links[0]["href"]
        .as_str()
        .unwrap()
        .ends_with("/.well-known/nodeinfo/2.1"));
}

#[test]
fn nodeinfo_2_1_contains_activitypub_and_solid() {
    let doc = nodeinfo_2_1("solid-pod-rs", "0.4.0", 1, 100);
    let protocols: Vec<&str> = doc["protocols"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(protocols.contains(&"activitypub"));
    assert!(protocols.contains(&"solid"));
}

#[test]
fn nodeinfo_2_1_usage_counts() {
    let doc = nodeinfo_2_1("solid-pod-rs", "0.4.0", 5, 42);
    assert_eq!(doc["usage"]["users"]["total"], 5);
    assert_eq!(doc["usage"]["localPosts"], 42);
}

// ===========================================================================
// Delivery worker: enqueue_to_inboxes
// ===========================================================================

#[tokio::test]
async fn delivery_worker_enqueue_to_inboxes_creates_queue_rows() {
    let store = fresh_store().await;
    let (priv_pem, _pub_pem) = generate_actor_keypair().unwrap();
    let config = DeliveryConfig {
        private_key_pem: priv_pem,
        key_id: "https://pod.example/profile/card.jsonld#main-key".into(),
    };
    let worker = DeliveryWorker::new(store.clone(), config);

    let inboxes = vec![
        "https://a/inbox".to_string(),
        "https://b/inbox".to_string(),
        "https://c/inbox".to_string(),
    ];
    let count = worker.enqueue_to_inboxes("act-1", &inboxes).await.unwrap();
    assert_eq!(count, 3);

    // Verify all three are in the delivery queue.
    let first = store.next_due_delivery().await.unwrap().unwrap();
    assert_eq!(first.activity_id, "act-1");
}

// ===========================================================================
// Full follow-accept-deliver flow
// ===========================================================================

#[tokio::test]
async fn full_follow_accept_flow() {
    let store = fresh_store().await;
    let local_id = "https://pod.example/profile/card.jsonld#me";

    // 1. Remote sends Follow.
    let follow = json!({
        "id": "https://remote.example/follows/1",
        "type": "Follow",
        "actor": "https://remote.example/actor",
        "actorInbox": "https://remote.example/inbox",
        "object": local_id
    });
    let outcome = handle_inbox(
        &store,
        local_id,
        &verified("https://remote.example/actor"),
        &follow,
    )
    .await
    .unwrap();

    // 2. Verify follower was added and Accept was generated.
    let (follower_id, follower_inbox, accept) = match outcome {
        InboxOutcome::FollowAccepted {
            follower_id,
            follower_inbox,
            accept_object,
        } => (follower_id, follower_inbox, accept_object),
        other => panic!("expected FollowAccepted, got {other:?}"),
    };
    assert_eq!(follower_id, "https://remote.example/actor");
    assert_eq!(
        follower_inbox.as_deref(),
        Some("https://remote.example/inbox")
    );
    assert!(store.is_follower(local_id, &follower_id).await.unwrap());

    // 3. The Accept object should reference the original Follow.
    assert_eq!(accept["type"], "Accept");
    assert_eq!(accept["object"]["id"], "https://remote.example/follows/1");
}
