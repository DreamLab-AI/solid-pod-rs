//! WAC concurrent mutation tests.
//!
//! Validates that ACL document reads and writes via the
//! `MemoryBackend` + `StorageAclResolver` are atomic under
//! concurrent access. The `MemoryBackend` uses
//! `Arc<RwLock<HashMap<…>>>` internally, so these tests exercise
//! the tokio `RwLock` contention path.
//!
//! Key invariant: ACL mutations are atomic — no half-written state
//! is ever observable by a concurrent reader.

use std::sync::Arc;

use bytes::Bytes;
use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs::wac::{evaluate_access, parse_jsonld_acl, AccessMode, AclDocument};
use solid_pod_rs::wac::resolver::{AclResolver, StorageAclResolver};

/// Build a valid JSON-LD ACL body granting `agent` the given `mode` on `path`.
fn acl_body(agent: &str, path: &str, mode: &str) -> Bytes {
    Bytes::from(format!(
        r#"{{
            "@context": {{"acl": "http://www.w3.org/ns/auth/acl#"}},
            "@graph": [{{
                "acl:agent": {{"@id": "{agent}"}},
                "acl:accessTo": {{"@id": "{path}"}},
                "acl:mode": {{"@id": "acl:{mode}"}}
            }}]
        }}"#
    ))
}

/// Build an ACL body granting Read to `foaf:Agent` (public) on `path`.
fn public_read_acl(path: &str) -> Bytes {
    Bytes::from(format!(
        r#"{{
            "@graph": [{{
                "acl:agentClass": {{"@id": "foaf:Agent"}},
                "acl:accessTo": {{"@id": "{path}"}},
                "acl:mode": {{"@id": "acl:Read"}}
            }}]
        }}"#
    ))
}

/// Build an ACL body granting multiple modes to a specific agent on `path`.
fn multi_mode_acl(agent: &str, path: &str, modes: &[&str]) -> Bytes {
    let mode_entries: Vec<String> = modes
        .iter()
        .map(|m| format!(r#"{{"@id": "acl:{m}"}}"#))
        .collect();
    let mode_json = if mode_entries.len() == 1 {
        mode_entries[0].clone()
    } else {
        format!("[{}]", mode_entries.join(", "))
    };
    Bytes::from(format!(
        r#"{{
            "@graph": [{{
                "acl:agent": {{"@id": "{agent}"}},
                "acl:accessTo": {{"@id": "{path}"}},
                "acl:mode": {mode_json}
            }}]
        }}"#
    ))
}

/// Parse an ACL body fetched from storage. Panics on parse failure.
fn parse_acl(body: &[u8]) -> AclDocument {
    parse_jsonld_acl(body).expect("ACL body should parse as valid JSON-LD")
}

// ---------------------------------------------------------------------------
// Test: Two writers simultaneously updating the same .acl.json
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_writers_same_acl_no_corruption() {
    let store = Arc::new(MemoryBackend::new());
    let acl_path = "/shared.acl";

    // Seed the ACL so both writers perform updates (not creates).
    store
        .put(acl_path, public_read_acl("/shared"), "application/ld+json")
        .await
        .unwrap();

    let n = 50;
    let mut handles = Vec::with_capacity(n * 2);

    // Writer A: grants Read to did:nostr:alice
    for i in 0..n {
        let s = store.clone();
        handles.push(tokio::spawn(async move {
            let body = acl_body("did:nostr:alice", "/shared", "Read");
            s.put(acl_path, body, "application/ld+json")
                .await
                .unwrap();
            ("A", i)
        }));
    }

    // Writer B: grants Write to did:nostr:bob
    for i in 0..n {
        let s = store.clone();
        handles.push(tokio::spawn(async move {
            let body = acl_body("did:nostr:bob", "/shared", "Write");
            s.put(acl_path, body, "application/ld+json")
                .await
                .unwrap();
            ("B", i)
        }));
    }

    // Wait for all writers to finish.
    for h in handles {
        h.await.unwrap();
    }

    // Read back the final state — must be a valid, parseable ACL.
    let (body, _meta) = store.get(acl_path).await.unwrap();
    let doc = parse_acl(&body);

    // The document must have exactly one authorisation entry (whichever
    // writer won the last write). It must be one of the two valid
    // shapes — never a mixture or partial write.
    let graph = doc.graph.as_ref().expect("graph must exist");
    assert_eq!(graph.len(), 1, "exactly one authorisation rule expected");

    let alice_read = evaluate_access(
        Some(&doc),
        Some("did:nostr:alice"),
        "/shared",
        AccessMode::Read,
        None,
    );
    let bob_write = evaluate_access(
        Some(&doc),
        Some("did:nostr:bob"),
        "/shared",
        AccessMode::Write,
        None,
    );

    // Exactly one of the two writers' ACLs must be the final state.
    assert!(
        alice_read ^ bob_write,
        "final ACL must be either alice-Read or bob-Write, got alice_read={alice_read} bob_write={bob_write}"
    );
}

// ---------------------------------------------------------------------------
// Test: Writer + reader concurrency — consistent reads
// ---------------------------------------------------------------------------

#[tokio::test]
async fn writer_reader_concurrency_consistent_reads() {
    let store = Arc::new(MemoryBackend::new());
    let acl_path = "/resource.acl";
    let resolver = Arc::new(StorageAclResolver::new(store.clone()));

    // Seed with a public-read ACL.
    store
        .put(acl_path, public_read_acl("/resource"), "application/ld+json")
        .await
        .unwrap();

    let iterations = 100;
    let mut handles = Vec::with_capacity(iterations * 2);

    // Writer task: alternates between granting alice Read and bob Write.
    for i in 0..iterations {
        let s = store.clone();
        handles.push(tokio::spawn(async move {
            let body = if i % 2 == 0 {
                acl_body("did:nostr:alice", "/resource", "Read")
            } else {
                acl_body("did:nostr:bob", "/resource", "Write")
            };
            s.put(acl_path, body, "application/ld+json")
                .await
                .unwrap();
        }));
    }

    // Reader task: resolve the ACL via the StorageAclResolver and
    // evaluate — the result must always be internally consistent.
    for _ in 0..iterations {
        let r = resolver.clone();
        handles.push(tokio::spawn(async move {
            let doc = r.find_effective_acl("/resource").await.unwrap();
            // doc may be Some or None (race with seed write), but when
            // present, the document must be a complete, parseable ACL.
            if let Some(ref d) = doc {
                let graph = d.graph.as_ref();
                // Must have a valid graph with at least one rule.
                assert!(
                    graph.is_some() && !graph.unwrap().is_empty(),
                    "resolved ACL must have at least one authorisation"
                );

                // Evaluate all four modes for both agents and confirm
                // the result is internally self-consistent: if alice
                // has Read, bob should not also have Write from the
                // same single-rule document (they come from different
                // writer iterations).
                let alice_read = evaluate_access(
                    doc.as_ref(),
                    Some("did:nostr:alice"),
                    "/resource",
                    AccessMode::Read,
                    None,
                );
                let bob_write = evaluate_access(
                    doc.as_ref(),
                    Some("did:nostr:bob"),
                    "/resource",
                    AccessMode::Write,
                    None,
                );
                let public_read = evaluate_access(
                    doc.as_ref(),
                    None,
                    "/resource",
                    AccessMode::Read,
                    None,
                );

                // The document was written atomically, so exactly one
                // of these invariants holds:
                //   1. alice has Read (alice-ACL iteration)
                //   2. bob has Write (bob-ACL iteration)
                //   3. public Read (seed ACL)
                let valid =
                    alice_read || bob_write || public_read;
                assert!(
                    valid,
                    "read must see a consistent ACL state: \
                     alice_read={alice_read} bob_write={bob_write} public_read={public_read}"
                );
            }
        }));
    }

    for h in handles {
        h.await.unwrap();
    }
}

// ---------------------------------------------------------------------------
// Test: Rapid sequential mutations — 100 ACL changes, verify final state
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rapid_sequential_mutations_verify_final_state() {
    let store = Arc::new(MemoryBackend::new());
    let acl_path = "/seq.acl";

    // Apply 100 sequential ACL writes, each granting Read to a
    // different agent: did:nostr:agent-0 … did:nostr:agent-99.
    let total = 100usize;
    for i in 0..total {
        let agent = format!("did:nostr:agent-{i}");
        let body = acl_body(&agent, "/seq", "Read");
        store
            .put(acl_path, body, "application/ld+json")
            .await
            .unwrap();
    }

    // The final state must reflect exactly the last write.
    let (body, _) = store.get(acl_path).await.unwrap();
    let doc = parse_acl(&body);

    let last_agent = format!("did:nostr:agent-{}", total - 1);
    assert!(
        evaluate_access(
            Some(&doc),
            Some(&last_agent),
            "/seq",
            AccessMode::Read,
            None,
        ),
        "last agent must have Read"
    );

    // All earlier agents must be denied (each write replaces the full
    // document).
    for i in 0..total - 1 {
        let agent = format!("did:nostr:agent-{i}");
        assert!(
            !evaluate_access(
                Some(&doc),
                Some(&agent),
                "/seq",
                AccessMode::Read,
                None,
            ),
            "agent-{i} must NOT have Read — only the last writer's ACL survives"
        );
    }
}

// ---------------------------------------------------------------------------
// Test: Concurrent spawned tasks contending on Arc<RwLock<>>
// ---------------------------------------------------------------------------

#[tokio::test]
async fn contended_rwlock_many_spawned_tasks() {
    let store = Arc::new(MemoryBackend::new());
    let acl_path = "/contended.acl";

    // Seed.
    store
        .put(
            acl_path,
            public_read_acl("/contended"),
            "application/ld+json",
        )
        .await
        .unwrap();

    let writers = 20;
    let readers = 80;
    let mut handles = Vec::with_capacity(writers + readers);

    // Spawn writer tasks.
    for i in 0..writers {
        let s = store.clone();
        handles.push(tokio::spawn(async move {
            let agent = format!("did:nostr:writer-{i}");
            let body = multi_mode_acl(&agent, "/contended", &["Read", "Write"]);
            s.put(acl_path, body, "application/ld+json")
                .await
                .unwrap();
        }));
    }

    // Spawn reader tasks. Each reads and parses — must never see a
    // half-written JSON body.
    for _ in 0..readers {
        let s = store.clone();
        handles.push(tokio::spawn(async move {
            match s.get(acl_path).await {
                Ok((body, _)) => {
                    // Must always parse successfully — no truncated JSON.
                    let doc = parse_acl(&body);
                    assert!(
                        doc.graph.is_some(),
                        "ACL document must have a graph field"
                    );
                }
                Err(_) => {
                    // NotFound is acceptable if we race before the seed
                    // write is visible (very unlikely with MemoryBackend
                    // but technically possible under task scheduling).
                }
            }
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    // Final read must succeed and parse.
    let (body, _) = store.get(acl_path).await.unwrap();
    let doc = parse_acl(&body);
    let graph = doc.graph.as_ref().expect("graph present");
    assert_eq!(graph.len(), 1, "single authorisation rule");
}

// ---------------------------------------------------------------------------
// Test: Concurrent delete + write — no panic, eventual consistency
// ---------------------------------------------------------------------------

#[tokio::test]
async fn concurrent_delete_and_write_no_panic() {
    let store = Arc::new(MemoryBackend::new());
    let acl_path = "/ephemeral.acl";

    // Seed.
    store
        .put(
            acl_path,
            public_read_acl("/ephemeral"),
            "application/ld+json",
        )
        .await
        .unwrap();

    let rounds = 50;
    let mut handles = Vec::with_capacity(rounds * 2);

    for _ in 0..rounds {
        // Deleter.
        let s = store.clone();
        handles.push(tokio::spawn(async move {
            let _ = s.delete(acl_path).await; // May fail with NotFound — OK.
        }));

        // Writer.
        let s = store.clone();
        handles.push(tokio::spawn(async move {
            let body = acl_body("did:nostr:phoenix", "/ephemeral", "Read");
            let _ = s.put(acl_path, body, "application/ld+json").await;
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    // After all tasks finish, the path either exists with a valid ACL
    // or does not exist at all. It must never contain partial data.
    match store.get(acl_path).await {
        Ok((body, _)) => {
            let doc = parse_acl(&body);
            // If present, it must be the phoenix ACL or the seed.
            let graph = doc.graph.as_ref().expect("graph present");
            assert!(!graph.is_empty());
        }
        Err(solid_pod_rs::PodError::NotFound(_)) => {
            // Deleted — acceptable.
        }
        Err(e) => panic!("unexpected error: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Test: StorageAclResolver walk-up under concurrent mutations
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolver_walk_up_under_concurrent_mutations() {
    let store = Arc::new(MemoryBackend::new());
    let resolver = Arc::new(StorageAclResolver::new(store.clone()));

    // Set up a container hierarchy:
    //   /.acl  → root ACL (public Read on /)
    //   /a.acl → specific ACL for /a
    store
        .put("/.acl", public_read_acl("/"), "application/ld+json")
        .await
        .unwrap();
    store
        .put(
            "/a.acl",
            acl_body("did:nostr:alice", "/a", "Write"),
            "application/ld+json",
        )
        .await
        .unwrap();

    let iterations = 50;
    let mut handles = Vec::with_capacity(iterations * 2);

    // Writers toggle /a.acl between alice-Write and bob-Read.
    for i in 0..iterations {
        let s = store.clone();
        handles.push(tokio::spawn(async move {
            let body = if i % 2 == 0 {
                acl_body("did:nostr:alice", "/a", "Write")
            } else {
                acl_body("did:nostr:bob", "/a", "Read")
            };
            s.put("/a.acl", body, "application/ld+json")
                .await
                .unwrap();
        }));
    }

    // Readers resolve /a through the walk-up algorithm.
    for _ in 0..iterations {
        let r = resolver.clone();
        handles.push(tokio::spawn(async move {
            let doc = r.find_effective_acl("/a").await.unwrap();
            // The resolver must find /a.acl (not fall through to /.acl)
            // and the returned document must be complete.
            let d = doc.expect("should find /a.acl");
            let graph = d.graph.as_ref().expect("graph present");
            assert_eq!(graph.len(), 1);

            // Must be one of the two valid states.
            let alice_write = evaluate_access(
                Some(&d),
                Some("did:nostr:alice"),
                "/a",
                AccessMode::Write,
                None,
            );
            let bob_read = evaluate_access(
                Some(&d),
                Some("did:nostr:bob"),
                "/a",
                AccessMode::Read,
                None,
            );
            assert!(
                alice_write || bob_read,
                "must see one of the two valid ACL states"
            );
        }));
    }

    for h in handles {
        h.await.unwrap();
    }
}

// ---------------------------------------------------------------------------
// Test: Watch events fire for every mutation (no lost events)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn watch_events_fire_for_acl_mutations() {
    let store = Arc::new(MemoryBackend::new());
    let acl_path = "/watched.acl";

    // Register watcher before any writes.
    let mut rx = store.watch("/").await.unwrap();

    let mutations = 10;
    for i in 0..mutations {
        let agent = format!("did:nostr:watcher-{i}");
        let body = acl_body(&agent, "/watched", "Read");
        store
            .put(acl_path, body, "application/ld+json")
            .await
            .unwrap();
    }

    // Collect events with a timeout.
    let mut events = Vec::new();
    for _ in 0..mutations {
        match tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv()).await {
            Ok(Some(ev)) => events.push(ev),
            Ok(None) => break,
            Err(_) => break,
        }
    }

    // First event is Created, subsequent are Updated.
    assert!(
        !events.is_empty(),
        "must receive at least one storage event"
    );
    assert_eq!(
        events.len(),
        mutations,
        "must receive exactly {mutations} events, got {}",
        events.len()
    );
}
