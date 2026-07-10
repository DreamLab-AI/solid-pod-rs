//! Provenance composition + `_prov` API integration tests (ADR-059 Phase 5).
//!
//! Exercises the capstone: the two tiers composed into one
//! [`solid_pod_rs::provenance::ProvenanceLog`] via the rewired LDP write hook,
//! the `ProvenanceAnchor` WAC condition driving the policy, epoch
//! Merkle-root batching, and the `_prov` routes.
//!
//! No live chain: a throwaway fixture `HttpServer` serves the mempool (the same
//! shape `pay_phase4_routes.rs` uses), so `MempoolBlockAnchorer`'s anchor
//! round-trip (build → broadcast → persist) runs deterministically. Pods are
//! FS-backed with an initialised git repo so the git-mark tier fires.
//!
//! Needs the `git` binary; short-circuits to a pass when it is absent.
//! Run with: `cargo test -p solid-pod-rs-server --features git`.
#![cfg(feature = "git")]

use std::process::Stdio;
use std::sync::Arc;

use actix_web::{test, web, App, HttpResponse};
use serde_json::{json, Value};
use solid_pod_rs::auth::nip98;
use solid_pod_rs::storage::fs::FsBackend;
use solid_pod_rs_server::trail_store::{save_trail, StoredTrail};
use solid_pod_rs_server::{build_app, AppState};

const NETWORK: &str = "testnet4";
const TICKER: &str = "PROV";
// The pod-owner / trail-issuer key. NIP-98 identity (and the pod name) is its
// x-only pubkey; the trail's issuer pubkey is its compressed (66-hex) form.
const OWNER_SK: &str = "0000000000000000000000000000000000000000000000000000000000000007";

fn git_available() -> bool {
    std::process::Command::new("git")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Compressed (66-hex) issuer pubkey — the trail's `issuer` / `pubkeyBase`.
fn issuer_pubkey() -> String {
    let sk = k256::SecretKey::from_slice(&hex::decode(OWNER_SK).unwrap()).unwrap();
    hex::encode(sk.public_key().to_sec1_bytes())
}

/// X-only (64-hex) owner pubkey — the NIP-98 identity AND the pod-name segment
/// (pod paths must be 64-hex for `pod_repo_path`).
fn owner_xonly() -> String {
    let sk = k256::schnorr::SigningKey::from_bytes(&hex::decode(OWNER_SK).unwrap()).unwrap();
    hex::encode(sk.verifying_key().to_bytes())
}

/// Mint a NIP-98 `Authorization` header for the owner over `method`+`path`.
fn owner_nip98(method: &str, path: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;
    // Each token MUST be a distinct NIP-98 event: the server's single-use replay
    // guard (`NIP98_REPLAY`, a process-global `LazyLock`) rejects a repeated
    // event_id with 401, and tokens minted in the same second with the same
    // key/url/method are otherwise identical. Anchor `created_at` to a base
    // captured once (30s in the past) + a monotonic per-call counter — strictly
    // unique regardless of wall-clock drift, within the ±60s tolerance window.
    static BASE: OnceLock<u64> = OnceLock::new();
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let base = *BASE.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(30)
    });
    let now = base + SEQ.fetch_add(1, Ordering::Relaxed);
    let url = format!("http://localhost:8080{path}");
    let token = nip98::mint(&url, method, OWNER_SK, now).expect("nip98 mint");
    format!("Nostr {token}")
}

/// ACL granting the owner (and the public, to keep anonymous writes simple)
/// read+write+append over `container`, OPTIONALLY carrying a `ProvenanceAnchor`
/// condition with `mode` (`"always"` ⇒ inline anchor, `"epoch"` ⇒ batched).
fn acl(container: &str, anchor_mode: Option<&str>) -> String {
    let cond = match anchor_mode {
        Some(m) => format!(
            r#", "acl:condition": [{{"@type": "acl:ProvenanceAnchor", "acl:anchorMode": "{m}"}}]"#
        ),
        None => String::new(),
    };
    format!(
        r##"{{
            "@context": {{
                "acl": "http://www.w3.org/ns/auth/acl#",
                "foaf": "http://xmlns.com/foaf/0.1/"
            }},
            "@graph": [{{
                "@id": "#public",
                "acl:agentClass": {{"@id": "foaf:Agent"}},
                "acl:accessTo": {{"@id": "{container}"}},
                "acl:default": {{"@id": "{container}"}},
                "acl:mode": [
                    {{"@id": "acl:Read"}},
                    {{"@id": "acl:Write"}},
                    {{"@id": "acl:Append"}}
                ]{cond}
            }}]
        }}"##
    )
}

/// Genesis chained-key scriptPubKey (`5120<xonly>`) for the single-state PROV
/// trail — what the trail's current UTXO pays.
fn genesis_state() -> solid_pod_rs::mrc20::Mrc20State {
    use solid_pod_rs::mrc20::{Mrc20State, MRC20_PROFILE};
    Mrc20State {
        profile: MRC20_PROFILE.into(),
        prev: "0".repeat(64),
        seq: 0,
        ticker: Some(TICKER.into()),
        name: Some("Prov Trail".into()),
        decimals: Some(0),
        supply: Some(1000),
        balances: Some(std::collections::BTreeMap::from([(issuer_pubkey(), 1000)])),
        ops: vec![],
        anchor: None,
    }
}

fn genesis_spk_hex() -> String {
    use solid_pod_rs::mrc20::{bt_derive_chained_pubkey, jcs};
    let genesis_jcs = jcs(&serde_json::to_value(genesis_state()).unwrap());
    let chained = bt_derive_chained_pubkey(&issuer_pubkey(), &[genesis_jcs]).unwrap();
    format!("5120{}", hex::encode(&chained[1..]))
}

/// Fixture mempool (tx lookup + empty UTXO set + broadcast echo). Identical
/// shape to `pay_phase4_routes::spawn_fixture`.
async fn spawn_fixture() -> (String, actix_web::dev::ServerHandle) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let spk = web::Data::new(genesis_spk_hex());

    let server = actix_web::HttpServer::new(move || {
        App::new()
            .app_data(spk.clone())
            .route(
                "/api/tx/{txid}",
                web::get().to(|_p: web::Path<String>, spk: web::Data<String>| async move {
                    let body = json!({
                        "txid": "aa".repeat(32),
                        "vout": [ { "value": 50000, "scriptpubkey": spk.get_ref() } ],
                        "status": { "confirmed": true, "block_height": 42000 }
                    });
                    HttpResponse::Ok()
                        .content_type("application/json")
                        .body(body.to_string())
                }),
            )
            .route(
                "/api/address/{addr}/utxo",
                web::get().to(|_p: web::Path<String>| async {
                    HttpResponse::Ok()
                        .content_type("application/json")
                        .body("[]")
                }),
            )
            .route(
                "/api/tx",
                web::post().to(|body: bytes::Bytes| async move {
                    let txid = solid_pod_rs::mrc20::sha256_hex(&String::from_utf8_lossy(&body));
                    HttpResponse::Ok().content_type("text/plain").body(txid)
                }),
            )
    })
    .listen(listener)
    .unwrap()
    .workers(1)
    .run();

    let handle = server.handle();
    tokio::spawn(server);
    (format!("http://127.0.0.1:{port}"), handle)
}

/// Build an FS-backed, git-initialised pod named after the owner's x-only
/// pubkey, with: the pay-token configured (issuer = owner), a minted PROV
/// trail, the owner's sat balance seeded, the resource container ACL (optionally
/// carrying a ProvenanceAnchor), and `mempool_url` pointing at the fixture.
async fn git_pod_with_trail(
    mempool_url: String,
    container: &str,
    anchor_mode: Option<&str>,
    owner_balance: u64,
) -> (AppState, tempfile::TempDir, String) {
    let pod = owner_xonly();
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().to_path_buf();

    std::fs::create_dir_all(root.join(&pod)).expect("pod dir");
    // Sibling ACL governs the whole pod container; carries the anchor marker.
    std::fs::write(root.join(format!("{pod}.acl")), acl(container, anchor_mode)).expect("acl");

    let init = std::process::Command::new("git")
        .args(["init", "-b", "main"])
        .current_dir(root.join(&pod))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("git init");
    assert!(init.success());

    let fs = FsBackend::new(root.clone()).await.expect("fs backend");
    let mut state = AppState::new(Arc::new(fs));
    state.data_root = Some(root);
    state.mempool_url = Some(mempool_url);
    state.pay_config.token = Some(solid_pod_rs::payments::TokenConfig {
        ticker: TICKER.into(),
        rate: 5, // anchor price defaults to the token rate (5 sats)
        supply: 1000,
        issuer: issuer_pubkey(),
    });

    // Seed the owner's ledger balance.
    let did = format!("did:nostr:{}", owner_xonly());
    let mut ledger = solid_pod_rs::payments::WebLedger::new("Pod Credits");
    ledger.credit(&did, owner_balance);
    state
        .storage
        .put(
            "/.well-known/webledgers/webledgers.json",
            bytes::Bytes::from(serde_json::to_vec(&ledger).unwrap()),
            "application/json",
        )
        .await
        .unwrap();

    // Mint the genesis trail (single state) controlled by the owner key.
    use solid_pod_rs::mrc20::jcs;
    let genesis = genesis_state();
    let genesis_jcs = jcs(&serde_json::to_value(&genesis).unwrap());
    let stored = StoredTrail {
        ticker: TICKER.into(),
        name: "Prov Trail".into(),
        supply: 1000,
        privkey: OWNER_SK.into(),
        pubkey_base: issuer_pubkey(),
        states: vec![genesis],
        state_strings: vec![genesis_jcs],
        current_txid: "aa".repeat(32),
        current_vout: 0,
        current_amount: 50_000,
        network: NETWORK.into(),
        date_created: "2026-06-13T00:00:00Z".into(),
    };
    save_trail(&state.storage, &stored).await.unwrap();

    (state, tmp, pod)
}

fn read_sidecar(repo: &std::path::Path, rel: &str) -> Option<String> {
    std::fs::read_to_string(repo.join(format!("{rel}.prov.ttl"))).ok()
}

fn last_commit_sha(repo: &std::path::Path) -> String {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo)
        .output()
        .expect("git rev-parse");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

// ===========================================================================
// 1. Composition: HighValue write ⇒ git-mark + anchor; cheap write ⇒ git only
// ===========================================================================

#[actix_web::test]
async fn high_value_write_records_both_tiers() {
    if !git_available() {
        return;
    }
    let (mempool_url, handle) = spawn_fixture().await;
    // Container `/{pod}/hi/` carries ProvenanceAnchor "always" ⇒ inline anchor.
    let (state, tmp, pod) = git_pod_with_trail(
        mempool_url,
        &format!("/{}/hi/", owner_xonly()),
        Some("always"),
        100,
    )
    .await;
    let repo = tmp.path().join(&pod);
    let app = test::init_service(build_app(state)).await;

    let uri = format!("/{pod}/hi/receipt.ttl");
    let req = test::TestRequest::put()
        .uri(&uri)
        .insert_header(("content-type", "text/turtle"))
        .set_payload(web::Bytes::from_static(b"<#r> <#paid> true ."))
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(rsp.status().as_u16(), 201, "PUT must succeed");

    // The sidecar carries BOTH the git-mark (git:commit) and the block-trail
    // anchor (bt:txid) — the two tiers composed.
    let ttl = read_sidecar(&repo, "hi/receipt.ttl").expect("sidecar written");
    assert!(ttl.contains("git:commit"), "git-mark tier missing:\n{ttl}");
    assert!(
        ttl.contains("bt:txid"),
        "anchor tier missing (HighValue):\n{ttl}"
    );
    assert!(
        ttl.contains("prov:wasDerivedFrom"),
        "anchor↔commit binding missing"
    );

    handle.stop(false).await;
}

#[actix_web::test]
async fn cheap_write_records_git_mark_only() {
    if !git_available() {
        return;
    }
    let (mempool_url, handle) = spawn_fixture().await;
    // Container `/{pod}/lo/` has NO ProvenanceAnchor ⇒ git-mark only.
    let (state, tmp, pod) =
        git_pod_with_trail(mempool_url, &format!("/{}/lo/", owner_xonly()), None, 100).await;
    let repo = tmp.path().join(&pod);
    let app = test::init_service(build_app(state)).await;

    let uri = format!("/{pod}/lo/note.ttl");
    let req = test::TestRequest::put()
        .uri(&uri)
        .insert_header(("content-type", "text/turtle"))
        .set_payload(web::Bytes::from_static(b"<#n> <#k> <#v> ."))
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(rsp.status().as_u16(), 201);

    let ttl = read_sidecar(&repo, "lo/note.ttl").expect("sidecar written");
    assert!(ttl.contains("git:commit"), "git-mark tier must be present");
    assert!(
        !ttl.contains("bt:txid"),
        "a cheap write must NOT carry a block-trail anchor:\n{ttl}"
    );

    handle.stop(false).await;
}

// ===========================================================================
// 2. GET /{pod}/_prov/{commit_sha} — resolve a git-mark to its resource
// ===========================================================================

#[actix_web::test]
async fn prov_resolve_maps_commit_to_resource() {
    if !git_available() {
        return;
    }
    let (mempool_url, handle) = spawn_fixture().await;
    let (state, tmp, pod) =
        git_pod_with_trail(mempool_url, &format!("/{}/r/", owner_xonly()), None, 100).await;
    let repo = tmp.path().join(&pod);
    let app = test::init_service(build_app(state)).await;

    let uri = format!("/{pod}/r/doc.ttl");
    let put = test::TestRequest::put()
        .uri(&uri)
        .insert_header(("content-type", "text/turtle"))
        .set_payload(web::Bytes::from_static(b"<#x> <#y> <#z> ."))
        .to_request();
    assert_eq!(test::call_service(&app, put).await.status().as_u16(), 201);

    let sha = last_commit_sha(&repo);
    assert_eq!(sha.len(), 40);

    // Resolve the commit → resource + mark.
    let get = test::TestRequest::get()
        .uri(&format!("/{pod}/_prov/{sha}"))
        .to_request();
    let rsp = test::call_service(&app, get).await;
    assert_eq!(rsp.status().as_u16(), 200, "resolve must 200");
    let body: Value = test::read_body_json(rsp).await;
    assert_eq!(body["resource"], json!(format!("/{pod}/r/doc.ttl")));
    assert_eq!(body["commit"]["sha"], json!(sha));
    assert_eq!(
        body["anchored"],
        json!(false),
        "git-only mark is not anchored"
    );
    assert!(body["prov_ttl"].as_str().unwrap().contains("git:commit"));

    // An unknown commit → 404.
    let bad = test::TestRequest::get()
        .uri(&format!("/{pod}/_prov/{}", "ab".repeat(20)))
        .to_request();
    assert_eq!(test::call_service(&app, bad).await.status().as_u16(), 404);

    // The Phase-2 `.prov.ttl` sidecar GET is still served by the ordinary LDP
    // read path (the new `_prov/{sha}` route must not shadow it) — §2.4.
    let sidecar_get = test::TestRequest::get()
        .uri(&format!("/{pod}/r/doc.ttl.prov.ttl"))
        .to_request();
    let sc = test::call_service(&app, sidecar_get).await;
    assert_eq!(
        sc.status().as_u16(),
        200,
        "the .prov.ttl sidecar must be GETtable"
    );
    let sc_body = test::read_body(sc).await;
    assert!(
        String::from_utf8_lossy(&sc_body).contains("a prov:Activity"),
        "sidecar GET must return the PROV-O turtle"
    );

    handle.stop(false).await;
}

// ===========================================================================
// 3. POST /{pod}/_prov/anchor — explicit, payment-gated git-mark → anchor
// ===========================================================================

#[actix_web::test]
async fn prov_anchor_upgrade_is_payment_gated_and_owner_only() {
    if !git_available() {
        return;
    }
    let (mempool_url, handle) = spawn_fixture().await;
    // Owner starts with enough balance to pay the 5-sat anchor price.
    let (state, tmp, pod) =
        git_pod_with_trail(mempool_url, &format!("/{}/up/", owner_xonly()), None, 100).await;
    let repo = tmp.path().join(&pod);
    let app = test::init_service(build_app(state)).await;

    // First produce a git-mark (cheap PUT, no anchor).
    let uri = format!("/{pod}/up/settle.ttl");
    let put = test::TestRequest::put()
        .uri(&uri)
        .insert_header(("content-type", "text/turtle"))
        .set_payload(web::Bytes::from_static(b"<#s> <#amount> 1000 ."))
        .to_request();
    assert_eq!(test::call_service(&app, put).await.status().as_u16(), 201);
    let sha = last_commit_sha(&repo);
    assert!(!read_sidecar(&repo, "up/settle.ttl")
        .unwrap()
        .contains("bt:txid"));

    let anchor_path = format!("/{pod}/_prov/anchor");
    let body = json!({"commit_sha": sha}).to_string();

    // (a) Anonymous → 401.
    let anon = test::TestRequest::post()
        .uri(&anchor_path)
        .insert_header(("content-type", "application/json"))
        .set_payload(body.clone())
        .to_request();
    assert_eq!(test::call_service(&app, anon).await.status().as_u16(), 401);

    // (b) Owner, sufficient balance → 200, anchor produced + sidecar upgraded.
    let ok = test::TestRequest::post()
        .uri(&anchor_path)
        .insert_header(("content-type", "application/json"))
        .insert_header(("authorization", owner_nip98("POST", &anchor_path)))
        .set_payload(body.clone())
        .to_request();
    let rsp = test::call_service(&app, ok).await;
    assert_eq!(rsp.status().as_u16(), 200, "owner anchor upgrade must 200");
    let out: Value = test::read_body_json(rsp).await;
    assert_eq!(out["commit_sha"], json!(sha));
    assert_eq!(
        out["anchor"]["state_hash"],
        json!(sha),
        "anchor commits to the git SHA"
    );
    assert_eq!(out["charged_sats"], json!(5));

    // The sidecar now carries the anchor.
    let ttl = read_sidecar(&repo, "up/settle.ttl").unwrap();
    assert!(
        ttl.contains("bt:txid"),
        "sidecar must be upgraded with the anchor:\n{ttl}"
    );

    // And `_prov/{sha}` now reports anchored=true.
    let resolve = test::TestRequest::get()
        .uri(&format!("/{pod}/_prov/{sha}"))
        .to_request();
    let rbody: Value = test::read_body_json(test::call_service(&app, resolve).await).await;
    assert_eq!(rbody["anchored"], json!(true));

    handle.stop(false).await;
}

#[actix_web::test]
async fn prov_anchor_upgrade_402_on_insufficient_balance() {
    if !git_available() {
        return;
    }
    let (mempool_url, handle) = spawn_fixture().await;
    // Owner has only 1 sat; the anchor price is 5 → 402.
    let (state, tmp, pod) =
        git_pod_with_trail(mempool_url, &format!("/{}/poor/", owner_xonly()), None, 1).await;
    let repo = tmp.path().join(&pod);
    let app = test::init_service(build_app(state)).await;

    let uri = format!("/{pod}/poor/x.ttl");
    let put = test::TestRequest::put()
        .uri(&uri)
        .insert_header(("content-type", "text/turtle"))
        .set_payload(web::Bytes::from_static(b"<#x> <#y> <#z> ."))
        .to_request();
    assert_eq!(test::call_service(&app, put).await.status().as_u16(), 201);
    let sha = last_commit_sha(&repo);

    let anchor_path = format!("/{pod}/_prov/anchor");
    let req = test::TestRequest::post()
        .uri(&anchor_path)
        .insert_header(("content-type", "application/json"))
        .insert_header(("authorization", owner_nip98("POST", &anchor_path)))
        .set_payload(json!({"commit_sha": sha}).to_string())
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(rsp.status().as_u16(), 402, "insufficient balance must 402");

    // No anchor was written (the gate ran before the on-chain action).
    assert!(!read_sidecar(&repo, "poor/x.ttl")
        .unwrap()
        .contains("bt:txid"));

    handle.stop(false).await;
}

// ===========================================================================
// 4. Epoch: N commits ⇒ one anchor on close (one tx notarises many commits)
// ===========================================================================

#[actix_web::test]
async fn epoch_policy_batches_then_anchors_once() {
    if !git_available() {
        return;
    }
    // Small epoch so a handful of writes closes it.
    std::env::set_var("JSS_PROV_EPOCH_SIZE", "3");

    let (mempool_url, handle) = spawn_fixture().await;
    let (state, tmp, pod) = git_pod_with_trail(
        mempool_url,
        &format!("/{}/ep/", owner_xonly()),
        Some("epoch"),
        100,
    )
    .await;
    let repo = tmp.path().join(&pod);
    let storage = state.storage.clone();
    let app = test::init_service(build_app(state)).await;

    // Two writes — below the threshold of 3: epoch accumulates, no anchor yet.
    for i in 0..2 {
        let uri = format!("/{pod}/ep/n{i}.ttl");
        let put = test::TestRequest::put()
            .uri(&uri)
            .insert_header(("content-type", "text/turtle"))
            .set_payload(web::Bytes::from(format!("<#n{i}> <#k> <#v> .")))
            .to_request();
        assert_eq!(test::call_service(&app, put).await.status().as_u16(), 201);
        // Per-write sidecars are git-only (epoch defers anchoring).
        let ttl = read_sidecar(&repo, &format!("ep/n{i}.ttl")).unwrap();
        assert!(
            !ttl.contains("bt:txid"),
            "epoch write {i} must not anchor inline"
        );
    }
    // The pending epoch batch holds the two commit SHAs.
    let (pending, _) = storage.get("/.well-known/prov/epoch.json").await.unwrap();
    let batch: Vec<String> = serde_json::from_slice(&pending).unwrap();
    assert_eq!(batch.len(), 2, "two commits accumulated, not yet anchored");

    // Third write closes the epoch → the trail gains exactly ONE anchoring
    // state for the whole batch, and the on-disk epoch resets to empty.
    let put = test::TestRequest::put()
        .uri(&format!("/{pod}/ep/n2.ttl"))
        .insert_header(("content-type", "text/turtle"))
        .set_payload(web::Bytes::from_static(b"<#n2> <#k> <#v> ."))
        .to_request();
    assert_eq!(test::call_service(&app, put).await.status().as_u16(), 201);

    let (pending2, _) = storage.get("/.well-known/prov/epoch.json").await.unwrap();
    let batch2: Vec<String> = serde_json::from_slice(&pending2).unwrap();
    assert!(
        batch2.is_empty(),
        "epoch must reset after anchoring the batch root"
    );

    // The trail advanced by exactly one state (the single batch anchor) —
    // proving ONE Bitcoin tx notarised all three commits.
    let (trail_bytes, _) = storage.get("/.well-known/token/prov.json").await.unwrap();
    let trail: Value = serde_json::from_slice(&trail_bytes).unwrap();
    let states = trail["states"].as_array().unwrap();
    assert_eq!(
        states.len(),
        2,
        "genesis + ONE epoch anchor (not one per commit)"
    );
    // The anchor's state notarises the epoch Merkle root, not a single SHA.
    assert!(
        states[1]["anchor"].is_string(),
        "the appended state carries the batch-root anchor"
    );

    std::env::remove_var("JSS_PROV_EPOCH_SIZE");
    handle.stop(false).await;
}
