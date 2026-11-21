//! The bounds the server's ActivityPub routes rely on (SP-PAR-281): the
//! address guard, the actor-fetch limits, the signed `Host` value, and the
//! outbox's handling of caller-supplied fields.

use std::time::Duration;

use solid_pod_rs_activitypub::{
    generate_actor_keypair, handle_outbox, render_actor, sign_request, ActorKeyResolver,
    DeliveryConfig, DeliveryOutcome, DeliveryWorker, HttpActorKeyResolver, OutboundRequest,
    SigError, SsrfGuard, Store,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn actor_doc(pem: &str) -> serde_json::Value {
    serde_json::json!({
        "id": "http://x/actor",
        "inbox": "http://x/inbox",
        "publicKey": {"publicKeyPem": pem}
    })
}

#[tokio::test]
async fn the_default_resolver_refuses_loopback() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(actor_doc("PEM")))
        .expect(0)
        .mount(&server)
        .await;
    let r = HttpActorKeyResolver::default();
    let err = r
        .resolve(&format!("{}/actor#main-key", server.uri()))
        .await
        .unwrap_err();
    assert!(matches!(err, SigError::SsrfBlocked(_)), "{err:?}");
}

#[tokio::test]
async fn the_loopback_allowance_is_explicit_and_fetches() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/actor"))
        .respond_with(ResponseTemplate::new(200).set_body_json(actor_doc("PEM")))
        .mount(&server)
        .await;
    let r = HttpActorKeyResolver::default().with_guard(SsrfGuard::permit_loopback_for_tests());
    let v = r
        .resolve(&format!("{}/actor#main-key", server.uri()))
        .await
        .unwrap();
    assert_eq!(v.public_key_pem, "PEM");
    assert_eq!(v.inbox_url.as_deref(), Some("http://x/inbox"));
}

#[tokio::test]
async fn the_actor_id_is_the_documents_id_only_when_it_names_the_fetched_document() {
    let server = MockServer::start().await;
    let own = format!("{}/actor#me", server.uri());
    Mock::given(method("GET"))
        .and(path("/actor"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": own, "inbox": "http://x/inbox", "publicKey": {"publicKeyPem": "PEM"}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/liar"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "https://victim.example/actor", "publicKey": {"publicKeyPem": "PEM"}
        })))
        .mount(&server)
        .await;
    let r = HttpActorKeyResolver::default().with_guard(SsrfGuard::permit_loopback_for_tests());
    let ok = r
        .resolve(&format!("{}/actor#main-key", server.uri()))
        .await
        .unwrap();
    assert_eq!(ok.actor_url, own);
    let liar = r
        .resolve(&format!("{}/liar#main-key", server.uri()))
        .await
        .unwrap();
    assert_eq!(liar.actor_url, format!("{}/liar", server.uri()));
}

#[tokio::test]
async fn the_loopback_allowance_does_not_unlock_private_or_metadata_ranges() {
    let r = HttpActorKeyResolver::default().with_guard(SsrfGuard::permit_loopback_for_tests());
    for url in [
        "http://10.0.0.1/actor",
        "http://192.168.1.1/actor",
        "http://169.254.169.254/actor",
    ] {
        let err = r.fetch_document(url).await.unwrap_err();
        assert!(matches!(err, SigError::SsrfBlocked(_)), "{url}: {err:?}");
    }
}

#[tokio::test]
async fn an_oversized_actor_document_is_refused() {
    let server = MockServer::start().await;
    let big = "a".repeat(4096);
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"summary": big})))
        .mount(&server)
        .await;
    let r = HttpActorKeyResolver::default()
        .with_guard(SsrfGuard::permit_loopback_for_tests())
        .with_limits(1024, Duration::from_secs(5));
    let err = r
        .fetch_document(&format!("{}/a", server.uri()))
        .await
        .unwrap_err();
    assert!(matches!(err, SigError::ActorFetch(..)), "{err:?}");
}

#[tokio::test]
async fn a_slow_actor_server_is_cut_off() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(actor_doc("PEM"))
                .set_delay(Duration::from_secs(3)),
        )
        .mount(&server)
        .await;
    let r = HttpActorKeyResolver::default()
        .with_guard(SsrfGuard::permit_loopback_for_tests())
        .with_limits(1024, Duration::from_millis(300));
    let started = std::time::Instant::now();
    let err = r
        .fetch_document(&format!("{}/a", server.uri()))
        .await
        .unwrap_err();
    assert!(matches!(err, SigError::ActorFetch(..)), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn the_signed_host_carries_a_non_default_port() {
    let (private_pem, _) = generate_actor_keypair().unwrap();
    let mut req = OutboundRequest {
        method: "POST".into(),
        url: "http://127.0.0.1:4321/inbox".into(),
        headers: vec![],
        body: b"{}".to_vec(),
    };
    sign_request(&mut req, &private_pem, "http://127.0.0.1:1/a#k").unwrap();
    let host = req
        .headers
        .iter()
        .find(|(n, _)| n == "Host")
        .map(|(_, v)| v.as_str());
    assert_eq!(host, Some("127.0.0.1:4321"));
    let mut plain = OutboundRequest {
        url: "https://pod.example/inbox".into(),
        ..req.clone()
    };
    sign_request(&mut plain, &private_pem, "k").unwrap();
    let host = plain
        .headers
        .iter()
        .find(|(n, _)| n == "Host")
        .map(|(_, v)| v.as_str());
    assert_eq!(host, Some("pod.example"));
}

async fn worker_for(store: &Store, guard: SsrfGuard) -> DeliveryWorker {
    let (private_pem, _) = generate_actor_keypair().unwrap();
    DeliveryWorker::new(
        store.clone(),
        DeliveryConfig {
            private_key_pem: private_pem,
            key_id: "https://pod.example/profile/card.jsonld#main-key".into(),
        },
    )
    .with_guard(guard)
}

#[tokio::test]
async fn delivery_is_refused_to_loopback_by_default_and_made_with_the_allowance() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/inbox"))
        .respond_with(ResponseTemplate::new(202))
        .expect(1)
        .mount(&server)
        .await;
    let actor = render_actor("https://pod.example", "me", "Me", None, "PEM");
    let inbox = format!("{}/inbox", server.uri());

    let store = Store::connect("sqlite::memory:").await.unwrap();
    store
        .add_follower(&actor.id, "f", Some(&inbox))
        .await
        .unwrap();
    let note = serde_json::json!({"type": "Create", "object": {"type": "Note", "content": "x"}});
    handle_outbox(&store, &actor, note.clone()).await.unwrap();
    let strict = worker_for(&store, SsrfGuard::strict()).await;
    assert_eq!(strict.drain_once().await.unwrap(), DeliveryOutcome::Dropped);

    handle_outbox(&store, &actor, note).await.unwrap();
    let relaxed = worker_for(&store, SsrfGuard::permit_loopback_for_tests()).await;
    assert_eq!(
        relaxed.drain_once().await.unwrap(),
        DeliveryOutcome::Delivered
    );
}

#[tokio::test]
async fn the_outbox_owns_the_actor_and_the_id_and_does_not_store_the_target_inbox() {
    let store = Store::connect("sqlite::memory:").await.unwrap();
    let actor = render_actor("https://pod.example", "me", "Me", None, "PEM");
    let d = handle_outbox(
        &store,
        &actor,
        serde_json::json!({
            "type": "Follow",
            "id": "https://evil.example/steal/1",
            "actor": "https://victim.example/actor",
            "object": "https://other.example/actor",
            "targetInbox": "https://other.example/inbox"
        }),
    )
    .await
    .unwrap();
    assert_eq!(d.queued_inboxes, 1);
    assert_eq!(d.activity["actor"], actor.id);
    assert!(d
        .activity_id
        .starts_with("https://pod.example/profile/card.jsonld/activities/"));
    assert!(d.activity.get("targetInbox").is_none());
    let stored = store.load_activity(&d.activity_id).await.unwrap().unwrap();
    assert!(stored.get("targetInbox").is_none());
    // The follow is recorded as requested, so a later Accept has a row.
    assert!(!store
        .is_following(&actor.id, "https://other.example/actor")
        .await
        .unwrap());
    assert_eq!(
        store
            .accept_following(&actor.id, "https://other.example/actor")
            .await
            .unwrap(),
        1
    );
    assert!(store
        .is_following(&actor.id, "https://other.example/actor")
        .await
        .unwrap());
}

#[tokio::test]
async fn bounded_listings() {
    let store = Store::connect("sqlite::memory:").await.unwrap();
    for i in 0..5 {
        store
            .add_follower("me", &format!("https://r/{i}"), Some("https://r/inbox"))
            .await
            .unwrap();
    }
    assert_eq!(store.list_followers("me", 3).await.unwrap().len(), 3);
    store.add_following("me", "https://t/1").await.unwrap();
    assert!(store.list_following("me", 10).await.unwrap().is_empty());
    store.accept_following("me", "https://t/1").await.unwrap();
    assert_eq!(
        store.list_following("me", 10).await.unwrap(),
        vec!["https://t/1"]
    );
    assert_eq!(store.following_count("me").await.unwrap(), 1);
    for i in 0..4 {
        store
            .record_inbox(
                "me",
                &serde_json::json!({"id": format!("https://r/a/{i}"), "type": "Like"}),
            )
            .await
            .unwrap();
    }
    assert_eq!(store.trim_inbox(2).await.unwrap(), 2);
    assert_eq!(store.inbox_count().await.unwrap(), 2);
}
