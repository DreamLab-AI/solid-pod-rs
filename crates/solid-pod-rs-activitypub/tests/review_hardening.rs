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

// ---------------------------------------------------------------------------
// A2: origin rule, per-host cap, concurrent delivery
// ---------------------------------------------------------------------------

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use solid_pod_rs_activitypub::{generate_actor_keypair, DeliveryConfig, DeliveryWorker, SsrfGuard};

/// Property: a Follow whose actor names an inbox on another origin is refused
/// (a follower cannot aim our deliveries at a host it does not control), and
/// nothing is stored.
#[tokio::test]
async fn a_follow_with_a_cross_origin_inbox_is_refused() {
    let (store, _dir) = file_store().await;
    let who = "https://remote.example/actor";
    for bad in [
        "https://victim.example/inbox",
        "http://remote.example/inbox",
        "https://remote.example:8443/inbox",
    ] {
        let mut v = verified(who);
        v.inbox_url = Some(bad.into());
        let r = handle_inbox(&store, ME, &v, &follow(who, "https://remote.example/f/1")).await;
        assert!(r.is_err(), "{bad} was accepted");
    }
    assert_eq!(store.inbox_count().await.unwrap(), 0);
    assert_eq!(store.follower_count(ME).await.unwrap(), 0);
    let mut ok = verified(who);
    ok.inbox_url = Some("https://remote.example/users/a/inbox".into());
    assert!(
        handle_inbox(&store, ME, &ok, &follow(who, "https://remote.example/f/2"))
            .await
            .is_ok()
    );
}

fn worker(store: &Store) -> Arc<DeliveryWorker> {
    let (private_key_pem, _) = generate_actor_keypair().unwrap();
    Arc::new(
        DeliveryWorker::new(
            store.clone(),
            DeliveryConfig {
                private_key_pem,
                key_id: format!("{ME}-key"),
            },
        )
        .with_guard(SsrfGuard::permit_loopback_for_tests()),
    )
}

/// Property: a host that accepts connections and never answers delays only its
/// own deliveries: another host's delivery completes while the first is stuck.
#[tokio::test]
async fn a_stalled_host_does_not_block_delivery_to_another_host() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let (store, _dir) = file_store().await;
    // Host A: accepts, reads nothing, never replies, keeps the sockets open.
    let stalled = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stalled_url = format!("http://{}/inbox", stalled.local_addr().unwrap());
    let held = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let held2 = held.clone();
    tokio::spawn(async move {
        while let Ok((sock, _)) = stalled.accept().await {
            held2.lock().await.push(sock);
        }
    });
    // Host B (a different loopback address, so a different host): healthy.
    let l = std::net::TcpListener::bind("127.0.0.2:0").unwrap();
    let healthy = MockServer::builder().listener(l).start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(202))
        .expect(1..)
        .mount(&healthy)
        .await;
    let healthy_url = format!("{}/inbox", healthy.uri());

    let activity = serde_json::json!({"id": "urn:a:1", "type": "Create", "actor": ME});
    let id = store.record_outbox(ME, &activity).await.unwrap();
    // Several rows for A first (oldest), then one for B.
    for _ in 0..4 {
        store.enqueue_delivery(&id, &stalled_url).await.unwrap();
    }
    let b_queue = store.enqueue_delivery(&id, &healthy_url).await.unwrap();

    let w = worker(&store);
    let task = tokio::spawn(w.clone().run(Duration::from_millis(50)));
    let mut delivered = false;
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if healthy
            .received_requests()
            .await
            .is_some_and(|r| !r.is_empty())
        {
            delivered = true;
            break;
        }
    }
    task.abort();
    assert!(
        delivered,
        "B was not delivered while A was stalled (queue id {b_queue})"
    );
    assert!(!held.lock().await.is_empty(), "A was actually contacted");
}

/// Property: after repeated failures a host's circuit opens and queued rows
/// for it stop being attempted, so a dead host costs a bounded number of
/// attempts however many rows are queued.
#[tokio::test]
async fn a_failing_host_is_backed_off_by_a_circuit_breaker() {
    let (store, _dir) = file_store().await;
    let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    dead.set_nonblocking(true).unwrap();
    let url = format!("http://{}/inbox", dead.local_addr().unwrap());
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();
    // Accept and hang up at once: every attempt is a transport failure.
    std::thread::spawn(move || {
        dead.set_nonblocking(false).unwrap();
        while let Ok((s, _)) = dead.accept() {
            counter.fetch_add(1, Ordering::SeqCst);
            drop(s);
        }
    });
    let activity = serde_json::json!({"id": "urn:a:2", "type": "Create", "actor": ME});
    let id = store.record_outbox(ME, &activity).await.unwrap();
    for _ in 0..30 {
        store.enqueue_delivery(&id, &url).await.unwrap();
    }
    let task = tokio::spawn(worker(&store).run(Duration::from_millis(50)));
    tokio::time::sleep(Duration::from_secs(3)).await;
    task.abort();
    let n = accepted.load(Ordering::SeqCst);
    assert!(n >= 5, "the breaker opened too early ({n} attempts)");
    assert!(n <= 10, "{n} attempts for one dead host: no breaker");
}

/// Property: no host may hold more than its share of followers, whatever port
/// or path its actors use; other hosts, and an existing follower's re-Follow,
/// are unaffected; the cap is configurable.
#[tokio::test]
async fn followers_per_host_are_capped() {
    use solid_pod_rs_activitypub::{handle_inbox_with, InboxLimits};
    let (store, _dir) = file_store().await;
    let limits = InboxLimits {
        max_followers_per_host: 2,
    };
    let actor_of = |host: &str, n: usize| format!("https://{host}:{}/users/{n}", 8000 + n);
    let follow_from = |host: &str, n: usize| {
        let a = actor_of(host, n);
        let mut v = verified(&a);
        v.inbox_url = Some(format!("{a}/inbox"));
        let act = follow(&a, &format!("{a}/f"));
        (v, act)
    };
    for n in 0..2 {
        let (v, act) = follow_from("busy.example", n);
        let r = handle_inbox_with(&store, ME, &v, &act, &limits)
            .await
            .unwrap();
        assert!(matches!(r, InboxOutcome::FollowAccepted { .. }));
    }
    let (v, act) = follow_from("busy.example", 2);
    let r = handle_inbox_with(&store, ME, &v, &act, &limits).await;
    assert!(matches!(
        r,
        Err(solid_pod_rs_activitypub::InboxError::Limit(_))
    ));
    let (v, act) = follow_from("other.example", 0);
    assert!(handle_inbox_with(&store, ME, &v, &act, &limits)
        .await
        .is_ok());
    assert_eq!(store.follower_count(ME).await.unwrap(), 3);
    // The default is small but not tiny.
    assert!(InboxLimits::default().max_followers_per_host > 2);
}

/// Property: an actor whose `sharedInbox` (or `inbox`) is on another origin is
/// refused as a follower through the real resolver path, even when the other
/// field is on its own origin.
#[tokio::test]
async fn a_cross_origin_shared_inbox_is_refused_through_the_resolver() {
    use solid_pod_rs_activitypub::{ActorKeyResolver, HttpActorKeyResolver};
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let (store, _dir) = file_store().await;
    let server = MockServer::start().await;
    let actor = format!("{}/actor", server.uri());
    let (_, public_pem) = generate_actor_keypair().unwrap();
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": actor,
            "inbox": format!("{actor}/inbox"),
            "endpoints": {"sharedInbox": "https://victim.example/inbox"},
            "publicKey": {"id": format!("{actor}#main-key"), "owner": actor, "publicKeyPem": public_pem},
        })))
        .mount(&server)
        .await;
    let resolver =
        HttpActorKeyResolver::default().with_guard(SsrfGuard::permit_loopback_for_tests());
    let v = resolver
        .resolve(&format!("{actor}#main-key"))
        .await
        .unwrap();
    let r = handle_inbox(&store, ME, &v, &follow(&actor, &format!("{actor}/f"))).await;
    assert!(r.is_err(), "cross-origin sharedInbox accepted");
    assert_eq!(store.follower_count(ME).await.unwrap(), 0);
}

/// Property: `followers` and `delivery_queue` tables from before the host
/// column existed are upgraded in place and the host is filled from the URL.
#[tokio::test]
async fn legacy_followers_and_queue_get_a_host_column() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}?mode=rwc", dir.path().join("old.db").display());
    {
        let pool = sqlx::SqlitePool::connect(&url).await.unwrap();
        for q in [
            "CREATE TABLE followers (actor_id TEXT NOT NULL, follower_id TEXT NOT NULL, inbox TEXT, \
             accepted_at DATETIME, PRIMARY KEY (actor_id, follower_id))",
            "CREATE TABLE delivery_queue (id INTEGER PRIMARY KEY AUTOINCREMENT, activity_id TEXT NOT NULL, \
             inbox_url TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, \
             next_retry DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, last_error TEXT)",
            "INSERT INTO followers (actor_id, follower_id) VALUES ('me', 'https://Old.Example:9/a')",
            "INSERT INTO delivery_queue (activity_id, inbox_url) VALUES ('x', 'https://old.example/inbox')",
        ] {
            sqlx::query(q).execute(&pool).await.unwrap();
        }
        pool.close().await;
    }
    let store = Store::connect(&url).await.unwrap();
    assert_eq!(
        store
            .follower_count_for_host("me", "old.example")
            .await
            .unwrap(),
        1
    );
    let (h,): (String,) = sqlx::query_as("SELECT host FROM delivery_queue")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(h, "old.example");
}

// ---------------------------------------------------------------------------
// A3: actor key cache
// ---------------------------------------------------------------------------

use solid_pod_rs_activitypub::{
    verify_request_signature, HttpActorKeyResolver, KeyCachePolicy, OutboundRequest, SignedRequest,
};
use wiremock::matchers::method as http_method;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A signed inbound POST to `inbox_url` from `key_id`, as the server sees it.
fn inbound(inbox_url: &str, private_pem: &str, key_id: &str) -> SignedRequest {
    let body = br#"{"type":"Create"}"#.to_vec();
    let mut out = OutboundRequest {
        method: "POST".into(),
        url: inbox_url.into(),
        headers: vec![("Content-Type".into(), "application/activity+json".into())],
        body: body.clone(),
    };
    solid_pod_rs_activitypub::sign_request(&mut out, private_pem, key_id).unwrap();
    let url = url::Url::parse(inbox_url).unwrap();
    let mut req = SignedRequest::new("POST", url.path(), body);
    for (k, v) in &out.headers {
        req = req.with_header(k.to_ascii_lowercase(), v.clone());
    }
    req
}

async fn actor_server(public_pem: &str) -> (MockServer, String) {
    let server = MockServer::start().await;
    let actor = format!("{}/actor", server.uri());
    Mock::given(http_method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": actor, "inbox": format!("{actor}/inbox"),
            "publicKey": {"id": format!("{actor}#main-key"), "owner": actor, "publicKeyPem": public_pem},
        })))
        .mount(&server)
        .await;
    (server, actor)
}

fn loopback_resolver() -> HttpActorKeyResolver {
    HttpActorKeyResolver::default().with_guard(SsrfGuard::permit_loopback_for_tests())
}

/// Property: a second request from the same actor does not fetch the key again.
#[tokio::test]
async fn a_resolved_actor_key_is_cached() {
    let (private, public) = generate_actor_keypair().unwrap();
    let (server, actor) = actor_server(&public).await;
    let resolver = loopback_resolver();
    let key_id = format!("{actor}#main-key");
    for _ in 0..3 {
        let req = inbound("https://pod.example/inbox", &private, &key_id);
        verify_request_signature(&req, &resolver).await.unwrap();
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

/// Property: a failed key fetch is remembered briefly, so repeated requests
/// naming a dead `keyId` cost one fetch.
#[tokio::test]
async fn a_failed_key_fetch_is_negatively_cached() {
    let server = MockServer::start().await;
    Mock::given(http_method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let (private, _) = generate_actor_keypair().unwrap();
    let key_id = format!("{}/actor#main-key", server.uri());
    let resolver = loopback_resolver();
    for _ in 0..5 {
        let req = inbound("https://pod.example/inbox", &private, &key_id);
        assert!(verify_request_signature(&req, &resolver).await.is_err());
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

/// Property: after a key rotation the first request fails against the cached
/// key, the key is re-fetched once, and the new signature verifies.
#[tokio::test]
async fn a_rotated_key_is_picked_up_by_one_refetch() {
    let (old_private, old_public) = generate_actor_keypair().unwrap();
    let (new_private, new_public) = generate_actor_keypair().unwrap();
    let (server, actor) = actor_server(&old_public).await;
    let resolver = loopback_resolver().with_cache_policy(KeyCachePolicy {
        min_refresh: Duration::ZERO,
        ..KeyCachePolicy::default()
    });
    let key_id = format!("{actor}#main-key");
    verify_request_signature(
        &inbound("https://pod.example/inbox", &old_private, &key_id),
        &resolver,
    )
    .await
    .unwrap();
    server.reset().await;
    Mock::given(http_method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": actor, "inbox": format!("{actor}/inbox"),
            "publicKey": {"id": key_id, "owner": actor, "publicKeyPem": new_public},
        })))
        .mount(&server)
        .await;
    verify_request_signature(
        &inbound("https://pod.example/inbox", &new_private, &key_id),
        &resolver,
    )
    .await
    .expect("rotated key accepted");
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "exactly one refetch"
    );
}

/// Property: bad signatures under a valid `keyId` cannot make the server
/// refetch the key more than once per refresh interval.
#[tokio::test]
async fn bad_signatures_do_not_amplify_into_fetches() {
    let (_, public) = generate_actor_keypair().unwrap();
    let (wrong_private, _) = generate_actor_keypair().unwrap();
    let (server, actor) = actor_server(&public).await;
    let resolver = loopback_resolver();
    let key_id = format!("{actor}#main-key");
    for _ in 0..10 {
        let req = inbound("https://pod.example/inbox", &wrong_private, &key_id);
        assert!(verify_request_signature(&req, &resolver).await.is_err());
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

/// Property: the cache never holds more than its bound.
#[tokio::test]
async fn the_key_cache_is_bounded() {
    let (_, public) = generate_actor_keypair().unwrap();
    let (server, actor) = actor_server(&public).await;
    let resolver = loopback_resolver().with_cache_policy(KeyCachePolicy {
        max_entries: 2,
        ..KeyCachePolicy::default()
    });
    use solid_pod_rs_activitypub::ActorKeyResolver;
    // Distinct document URLs (query strings) fill and then churn the cache.
    for n in 0..6 {
        resolver.resolve(&format!("{actor}?n={n}#k")).await.unwrap();
    }
    // The newest is cached (no extra fetch); an evicted early one is fetched again.
    let before = server.received_requests().await.unwrap().len();
    resolver.resolve(&format!("{actor}?n=5#k")).await.unwrap();
    assert_eq!(server.received_requests().await.unwrap().len(), before);
    resolver.resolve(&format!("{actor}?n=0#k")).await.unwrap();
    assert_eq!(server.received_requests().await.unwrap().len(), before + 1);
}
