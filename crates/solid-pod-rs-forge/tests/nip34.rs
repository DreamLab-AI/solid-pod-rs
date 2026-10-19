//! NIP-34 emission: differential vectors against the JSS forge plugin and the
//! route and publisher behaviour (feature `announce`).
//!
//! The vectors in `tests/jss-vectors/nip34-vectors.json` were produced by
//! `gen-nip34.mjs`, which boots the JSS plugin and records the events its
//! `GET api/repos/<o>/<n>/nostr` returns for the repositories described in
//! `nip34-spec.json`. These tests rebuild those repositories with the same
//! deterministic git identities and dates, feed the recorded `created_at`
//! into the Rust builders and require byte-identical ids and tags. Expected
//! values come from JSS, never from this crate.
#![cfg(feature = "announce")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use solid_pod_rs_forge::config::AnnounceKey;
use solid_pod_rs_forge::gitmark::AnchorFacts;
use solid_pod_rs_forge::nip34::{
    build_repo_event, build_state_event, gather_facts, AnnounceSigner, TrailState,
};
use solid_pod_rs_forge::{ForgeAgent, ForgeConfig, ForgeRequest, ForgeService};
use solid_pod_rs_nostr::SsrfCheck;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

const SPEC: &str = include_str!("jss-vectors/nip34-spec.json");
const VECTORS: &str = include_str!("jss-vectors/nip34-vectors.json");
const ORIGIN: &str = "https://forge.example";

// ---------------------------------------------------------------------------
// Repository fixtures built exactly as gen-nip34.mjs builds them
// ---------------------------------------------------------------------------

fn git(cwd: &Path, home: &Path, tick: &mut u64, args: &[&str]) -> String {
    *tick += 1;
    let date = format!("{} +0000", 1_700_000_000 + *tick * 60);
    let out = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_NAME", "Casey Coder")
        .env("GIT_AUTHOR_EMAIL", "casey@example.org")
        .env("GIT_COMMITTER_NAME", "Casey Coder")
        .env("GIT_COMMITTER_EMAIL", "casey@example.org")
        .env("GIT_AUTHOR_DATE", &date)
        .env("GIT_COMMITTER_DATE", &date)
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Materialise one spec repository as a bare repo under `repos_root`.
fn build_repo(spec: &Value, trail: &str, repos_root: &Path, scratch: &Path) -> PathBuf {
    let owner = spec["owner"].as_str().unwrap();
    let name = spec["name"].as_str().unwrap();
    let bare = repos_root.join(owner).join(format!("{name}.git"));
    std::fs::create_dir_all(bare.parent().unwrap()).unwrap();
    let work = scratch.join(format!("work-{owner}-{name}"));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();
    let mut tick = 0u64;
    let steps = spec["steps"].as_array().unwrap();
    if steps.is_empty() {
        git(
            bare.parent().unwrap(),
            scratch,
            &mut tick,
            &[
                "init",
                "--quiet",
                "--bare",
                "-b",
                "main",
                bare.to_str().unwrap(),
            ],
        );
    } else {
        git(
            &work,
            scratch,
            &mut tick,
            &["init", "--quiet", "-b", "main"],
        );
        for s in steps {
            if let Some(b) = s.get("branch").and_then(Value::as_str) {
                git(&work, scratch, &mut tick, &["checkout", "--quiet", "-B", b]);
            } else if let Some(b) = s.get("switch").and_then(Value::as_str) {
                git(&work, scratch, &mut tick, &["checkout", "--quiet", b]);
            } else {
                for (p, c) in s["files"].as_object().unwrap() {
                    let c = if c == "@TRAIL@" {
                        trail
                    } else {
                        c.as_str().unwrap()
                    };
                    let path = work.join(p);
                    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                    std::fs::write(path, c).unwrap();
                }
                git(&work, scratch, &mut tick, &["add", "-A"]);
                let msg = s["message"].as_str().unwrap();
                git(&work, scratch, &mut tick, &["commit", "--quiet", "-m", msg]);
            }
        }
        git(
            bare.parent().unwrap(),
            scratch,
            &mut tick,
            &[
                "clone",
                "--quiet",
                "--bare",
                work.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
        );
    }
    if let Some(d) = spec.get("description").and_then(Value::as_str) {
        std::fs::write(bare.join("description"), d).unwrap();
    }
    bare
}

/// The forge-held trail state the spec describes, following the JSS
/// `anchorTags` rule: a marked genesis anchors at the last marked frontier,
/// a forge-held trail with nothing on-chain is `Unanchored` (no fallback to
/// the repository), no trail is `Absent`.
fn spec_trail_state(held: Option<&Value>, trail_url: &str, tip: &str) -> TrailState {
    let Some(held) = held else {
        return TrailState::Absent;
    };
    let chain = held["chain"].as_str().unwrap().to_string();
    let marks = held["marks"].as_array().unwrap();
    if marks[0]["status"] != "marked" {
        return TrailState::Unanchored;
    }
    let frontier = marks.iter().rfind(|m| m["status"] == "marked").unwrap();
    TrailState::Anchored(AnchorFacts {
        chain,
        genesis_txid: marks[0]["txid"].as_str().unwrap().to_string(),
        frontier_txid: frontier["txid"].as_str().unwrap().to_string(),
        frontier_vout: u32::try_from(frontier["vout"].as_u64().unwrap()).unwrap(),
        // the spec's forge-held marks all commit the repository tip
        frontier_commit: tip.to_string(),
        trail_url: trail_url.to_string(),
    })
}

fn tags_of(ev: &Value) -> Vec<Vec<String>> {
    serde_json::from_value(ev["tags"].clone()).unwrap()
}

// ---------------------------------------------------------------------------
// Differential vectors
// ---------------------------------------------------------------------------

#[tokio::test]
async fn builders_reproduce_the_jss_events_byte_for_byte() {
    let spec: Value = serde_json::from_str(SPEC).unwrap();
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let trail = spec["trail"].as_str().unwrap();
    let signer = AnnounceSigner::from_secret_hex(spec["announceKey"].as_str().unwrap()).unwrap();
    let relays: Vec<String> = serde_json::from_value(spec["relays"].clone()).unwrap();
    let td = tempfile::tempdir().unwrap();
    let mut checked = 0;

    for case in vectors["cases"].as_array().unwrap() {
        let (owner, name) = (
            case["owner"].as_str().unwrap(),
            case["name"].as_str().unwrap(),
        );
        let repo_spec = spec["repos"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["owner"] == owner && r["name"] == name)
            .unwrap();
        // one scratch directory per mode so 'relays' and 'none' do not collide
        let mode = case["mode"].as_str().unwrap();
        let root = td.path().join(mode);
        let bare = build_repo(repo_spec, trail, &root.join("repos"), td.path());

        let want_relays = if mode == "relays" {
            relays.clone()
        } else {
            vec![]
        };
        let tip = Command::new("git")
            .args([
                "--git-dir",
                bare.to_str().unwrap(),
                "rev-parse",
                "refs/heads/main",
            ])
            .output()
            .unwrap();
        let tip = String::from_utf8_lossy(&tip.stdout).trim().to_string();
        let base = format!("{ORIGIN}/forge/{owner}/{name}");
        let forge_trail = spec_trail_state(
            repo_spec.get("forgeHeld"),
            &format!("{base}/blocktrails.json"),
            &tip,
        );
        let facts = gather_facts(&bare, owner, name, &base, &want_relays, forge_trail)
            .await
            .unwrap();

        let ev = build_repo_event(
            &signer,
            &facts,
            case["event"]["created_at"].as_u64().unwrap(),
        )
        .unwrap();
        let st = build_state_event(
            &signer,
            &facts,
            case["state"]["created_at"].as_u64().unwrap(),
        )
        .unwrap();
        assert_eq!(
            ev.pubkey,
            case["pubkey"].as_str().unwrap(),
            "{name}: pubkey"
        );
        for (ours, theirs, label) in [
            (&ev, &case["event"], "30617"),
            (&st, &case["state"], "30618"),
        ] {
            assert_eq!(
                ours.kind,
                theirs["kind"].as_u64().unwrap(),
                "{name} {label} kind"
            );
            assert_eq!(ours.tags, tags_of(theirs), "{name} {label} tags");
            assert_eq!(
                ours.content,
                theirs["content"].as_str().unwrap(),
                "{name} {label} content"
            );
            assert_eq!(ours.id, theirs["id"].as_str().unwrap(), "{name} {label} id");
            assert!(ours.verify().is_ok(), "{name} {label} signature");
            // the JSS signature verifies under the Rust verifier too
            let theirs_ev: solid_pod_rs_nostr::Event =
                serde_json::from_value(theirs.clone()).unwrap();
            assert!(
                theirs_ev.verify().is_ok(),
                "{name} {label}: JSS event verifies in Rust"
            );
            assert_eq!(theirs_ev.canonical_id(), theirs_ev.id);
        }
        checked += 1;
    }
    assert_eq!(checked, 10, "every recorded case was compared");
}

#[tokio::test]
async fn the_service_path_emits_the_same_tags_as_jss() {
    let spec: Value = serde_json::from_str(SPEC).unwrap();
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let trail = spec["trail"].as_str().unwrap();
    let td = tempfile::tempdir().unwrap();
    let cfg = ForgeConfig {
        announce_key: Some(AnnounceKey::new(spec["announceKey"].as_str().unwrap())),
        announce_relays: serde_json::from_value(spec["relays"].clone()).unwrap(),
        ..Default::default()
    };
    let svc = ForgeService::new(cfg, td.path().join("plugin")).unwrap();
    for case in vectors["cases"].as_array().unwrap().iter().filter(|c| {
        c["mode"] == "relays" && ["demo", "agent", "plain"].contains(&c["name"].as_str().unwrap())
    }) {
        let (owner, name) = (
            case["owner"].as_str().unwrap(),
            case["name"].as_str().unwrap(),
        );
        let repo_spec = spec["repos"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["owner"] == owner && r["name"] == name)
            .unwrap();
        build_repo(repo_spec, trail, &svc.plugin_dir().join("repos"), td.path());
        let built = svc
            .build_announce_events(owner, name, ORIGIN)
            .await
            .unwrap();
        assert_eq!(built.event.tags, tags_of(&case["event"]), "{name}");
        assert_eq!(built.state.tags, tags_of(&case["state"]), "{name}");
        assert_eq!(built.event.pubkey, svc.announce_pubkey());
    }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

fn request(method: &str, path: &str) -> ForgeRequest {
    ForgeRequest {
        method: method.into(),
        path: path.into(),
        query: String::new(),
        headers: vec![],
        raw_body: Bytes::from_static(b"{}"),
        host_url: Some(ORIGIN.into()),
    }
}

fn pod(user: &str) -> ForgeAgent {
    ForgeAgent::Pod {
        webid: format!("{ORIGIN}/{user}/profile/card#me"),
        username: user.into(),
    }
}

/// A service with the spec's `casey/demo` repository and the given relays.
fn service_with_demo(relays: Vec<String>) -> (ForgeService, tempfile::TempDir) {
    let spec: Value = serde_json::from_str(SPEC).unwrap();
    let td = tempfile::tempdir().unwrap();
    let cfg = ForgeConfig {
        announce_relays: relays,
        ..Default::default()
    };
    let svc = ForgeService::new(cfg, td.path().join("plugin")).unwrap();
    let demo = spec["repos"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "demo")
        .unwrap();
    build_repo(
        demo,
        spec["trail"].as_str().unwrap(),
        &svc.plugin_dir().join("repos"),
        td.path(),
    );
    (svc, td)
}

fn body_json(resp: &solid_pod_rs_forge::ForgeResponse) -> Value {
    serde_json::from_slice(&resp.body).unwrap()
}

// JSS "GET /nostr returns a valid signed kind-30617 ..." through the route.
#[tokio::test]
async fn get_nostr_returns_both_signed_events_and_a_stable_persisted_identity() {
    let (svc, _td) = service_with_demo(vec![]);
    let get = || {
        svc.handle(
            request("GET", "/forge/api/repos/casey/demo/nostr"),
            ForgeAgent::Anonymous,
        )
    };
    let resp = get().await.unwrap();
    assert_eq!(resp.status, 200);
    let j = body_json(&resp);
    let pubkey = j["pubkey"].as_str().unwrap();
    assert_eq!(pubkey.len(), 64);
    assert!(j["npub"].as_str().unwrap().starts_with("npub1"));
    assert_eq!(j["relaysConfigured"], false);
    assert_eq!(j["relays"], json!([]));
    assert_eq!(j["events"].as_array().unwrap().len(), 2);
    assert_eq!(j["events"][0]["kind"], 30617);
    assert_eq!(j["events"][1]["kind"], 30618);
    assert_eq!(j["event"], j["events"][0]);
    assert_eq!(j["state"], j["events"][1]);
    let ev: solid_pod_rs_nostr::Event = serde_json::from_value(j["event"].clone()).unwrap();
    assert!(ev.verify().is_ok());
    assert_eq!(ev.pubkey, pubkey);
    // the pubkey derives from the persisted 0600 key
    let secret = std::fs::read_to_string(svc.plugin_dir().join("announce-key")).unwrap();
    assert_eq!(
        AnnounceSigner::from_secret_hex(secret.trim())
            .unwrap()
            .pubkey_hex(),
        pubkey
    );
    // stable identity across calls
    assert_eq!(body_json(&get().await.unwrap())["pubkey"], pubkey);
    // the clone URL uses the request origin and the forge prefix
    let tags = tags_of(&j["event"]);
    assert!(tags.contains(&vec![
        "clone".to_string(),
        format!("{ORIGIN}/forge/casey/demo.git")
    ]));
}

#[tokio::test]
async fn get_nostr_404s_for_unknown_or_unsafe_repos_and_405s_for_writes() {
    let (svc, _td) = service_with_demo(vec![]);
    for path in [
        "/forge/api/repos/casey/missing/nostr",
        "/forge/api/repos/nobody/demo/nostr",
        "/forge/api/repos/../demo/nostr",
    ] {
        let r = svc
            .handle(request("GET", path), ForgeAgent::Anonymous)
            .await
            .unwrap();
        // A `..` segment is now refused outright (400) by the percent guard.
        assert!(matches!(r.status, 400 | 404), "{path}: {}", r.status);
    }
    let r = svc
        .handle(
            request("POST", "/forge/api/repos/casey/demo/nostr"),
            pod("casey"),
        )
        .await
        .unwrap();
    assert_eq!(r.status, 405);
}

// JSS "POST /announce is owner-only, and with no relays configured is a
// clear no-op".
#[tokio::test]
async fn post_announce_is_owner_only_and_a_no_op_without_relays() {
    let (svc, _td) = service_with_demo(vec![]);
    let path = "/forge/api/repos/casey/demo/announce";
    let anon = svc
        .handle(request("POST", path), ForgeAgent::Anonymous)
        .await
        .unwrap();
    assert_eq!(anon.status, 401, "anonymous is 401");
    assert!(anon
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("www-authenticate")));
    let other = svc
        .handle(request("POST", path), pod("rival"))
        .await
        .unwrap();
    assert_eq!(other.status, 403, "a non-owner is 403");
    let mine = svc
        .handle(request("POST", path), pod("casey"))
        .await
        .unwrap();
    assert_eq!(mine.status, 200);
    let j = body_json(&mine);
    assert_eq!(j["published"], false);
    assert!(j["reason"]
        .as_str()
        .unwrap()
        .to_lowercase()
        .contains("no relays configured"));
    assert_eq!(j["relays"], json!([]));
    assert!(
        j.get("stateRelays").is_none(),
        "JSS omits stateRelays in the no-op"
    );
    assert_eq!(j["event"]["kind"], 30617);
    assert_eq!(j["state"]["kind"], 30618);
    assert_eq!(j["state"]["tags"][0], json!(["d", "casey/demo"]));
    assert!(
        j["event"].get("sig").is_none(),
        "the view carries id, pubkey, kind, tags only"
    );
    // a nostr agent owns its hex namespace only
    let hex_agent = ForgeAgent::Nostr {
        pubkey_hex: "ab".repeat(32),
    };
    assert_eq!(
        svc.handle(request("POST", path), hex_agent)
            .await
            .unwrap()
            .status,
        403
    );
    // method and repository checks
    assert_eq!(
        svc.handle(request("GET", path), pod("casey"))
            .await
            .unwrap()
            .status,
        405
    );
    let missing = svc
        .handle(
            request("POST", "/forge/api/repos/casey/nope/announce"),
            ForgeAgent::Anonymous,
        )
        .await
        .unwrap();
    assert_eq!(missing.status, 404);
}

// ---------------------------------------------------------------------------
// Publishing against a local relay
// ---------------------------------------------------------------------------

struct AllowAll;
#[async_trait]
impl SsrfCheck for AllowAll {
    async fn verify_host(&self, _host: &str) -> Result<Option<std::net::IpAddr>, String> {
        Ok(None)
    }
}

/// A relay that answers every EVENT with OK true and records what it saw.
async fn local_relay() -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let sink = Arc::clone(&sink);
            tokio::spawn(async move {
                let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
                while let Some(Ok(Message::Text(t))) = ws.next().await {
                    let v: Value = serde_json::from_str(&t).unwrap();
                    if v[0] == "EVENT" {
                        let id = v[1]["id"].clone();
                        sink.lock().unwrap().push(v[1].clone());
                        let _ = ws
                            .send(Message::text(json!(["OK", id, true, ""]).to_string()))
                            .await;
                    }
                }
            });
        }
    });
    (url, seen)
}

async fn until<T>(mut f: impl FnMut() -> Option<T>) -> T {
    for _ in 0..100 {
        if let Some(v) = f() {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("condition not reached");
}

// JSS "POST /announce publishes BOTH the signed 30617 and the 30618 state to
// the relay and parses the OKs".
#[tokio::test]
async fn post_announce_publishes_both_events_and_parses_the_oks() {
    let (relay, seen) = local_relay().await;
    let (svc, _td) = service_with_demo(vec![relay.clone()]);
    let svc = svc.with_announce_ssrf(Arc::new(AllowAll));
    let resp = svc
        .handle(
            request("POST", "/forge/api/repos/casey/demo/announce"),
            pod("casey"),
        )
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
    let j = body_json(&resp);
    assert_eq!(j["published"], true);
    assert_eq!(j["relays"], json!([{"relay": relay, "ok": true}]));
    assert_eq!(j["stateRelays"], json!([{"relay": relay, "ok": true}]));

    let events = seen.lock().unwrap().clone();
    assert_eq!(events.len(), 2);
    // 30617 first, then 30618
    assert_eq!(events[0]["kind"], 30617);
    assert_eq!(events[1]["kind"], 30618);
    assert_eq!(events[0]["id"], j["event"]["id"]);
    assert_eq!(events[1]["id"], j["state"]["id"]);
    for e in &events {
        let ev: solid_pod_rs_nostr::Event = serde_json::from_value(e.clone()).unwrap();
        assert!(ev.verify().is_ok(), "the delivered event is validly signed");
    }
    let t0 = tags_of(&events[0]);
    assert!(t0.iter().any(|t| t[0] == "relays" && t.contains(&relay)));
    assert!(t0.contains(&vec![
        "clone".into(),
        format!("{ORIGIN}/forge/casey/demo.git")
    ]));
    let t1 = tags_of(&events[1]);
    assert!(t1
        .iter()
        .any(|t| t[0] == "HEAD" && t[1] == "ref: refs/heads/main"));
    assert!(t1
        .iter()
        .any(|t| t[0] == "refs/heads/main" && t[1].len() == 40));
    assert_eq!(t1[0], vec!["d".to_string(), "casey/demo".to_string()]);
}

#[tokio::test]
async fn the_default_ssrf_policy_keeps_the_forge_from_dialling_a_loopback_relay() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay = format!("ws://{}", listener.local_addr().unwrap());
    let (svc, _td) = service_with_demo(vec![relay.clone()]);
    // no with_announce_ssrf: the workspace default applies
    let resp = svc
        .handle(
            request("POST", "/forge/api/repos/casey/demo/announce"),
            pod("casey"),
        )
        .await
        .unwrap();
    let j = body_json(&resp);
    assert_eq!(j["published"], true, "it tried");
    assert_eq!(j["relays"][0]["ok"], false);
    assert!(j["relays"][0]["error"]
        .as_str()
        .unwrap()
        .starts_with("relay host refused"));
    let accepted = tokio::time::timeout(Duration::from_millis(250), listener.accept()).await;
    assert!(accepted.is_err(), "nothing connected to the loopback relay");
}

#[tokio::test]
async fn announce_repo_is_a_no_op_without_relays_and_the_background_hook_delivers() {
    let (svc, _td) = service_with_demo(vec![]);
    let out = svc.announce_repo("casey", "demo", ORIGIN).await.unwrap();
    assert!(!out.published && out.events.is_none() && out.relays.is_empty());
    svc.announce_repo_in_background("casey", "demo", ORIGIN); // must not panic or spawn work

    let (relay, seen) = local_relay().await;
    let (svc, _td2) =
        service_with_demo(vec![relay, "http://not-a-relay".into(), "wss://a b".into()]);
    assert_eq!(
        svc.announce_relays().len(),
        1,
        "non-ws and malformed relays are filtered"
    );
    let svc = svc.with_announce_ssrf(Arc::new(AllowAll));
    svc.announce_repo_in_background("casey", "demo", ORIGIN);
    let state = until(|| {
        seen.lock()
            .unwrap()
            .iter()
            .find(|e| e["kind"] == 30618)
            .cloned()
    })
    .await;
    assert!(tags_of(&state).iter().any(|t| t[0] == "HEAD"));
    // an unknown repository is reported, not published
    assert!(svc.announce_repo("casey", "missing", ORIGIN).await.is_err());
}

// A forge-held trail takes precedence over a repo-held one, and when the forge
// holds one with nothing on-chain the repository is NOT consulted (JSS
// `anchorTags`: `if (trail) return tags`).
#[cfg(feature = "anchoring")]
#[tokio::test]
async fn forge_held_trail_wins_and_never_falls_back_to_the_repo_held_one() {
    let spec: Value = serde_json::from_str(SPEC).unwrap();
    let td = tempfile::tempdir().unwrap();
    let svc = ForgeService::new(ForgeConfig::default(), td.path().join("plugin")).unwrap();
    let agent = spec["repos"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "agent")
        .unwrap();
    let bare = build_repo(
        agent,
        spec["trail"].as_str().unwrap(),
        &svc.plugin_dir().join("repos"),
        td.path(),
    );
    let tags_for = |svc: &ForgeService| {
        let svc = svc.clone();
        async move {
            let b = svc
                .build_announce_events("casey", "agent", ORIGIN)
                .await
                .unwrap();
            (b.event.tags, b.state.tags)
        }
    };
    // repo-held only: the committed trail's txo anchors the events
    let (ev, st) = tags_for(&svc).await;
    for tags in [&ev, &st] {
        assert!(tags
            .iter()
            .any(|t| t[0] == "anchor" && t[2] == "ab".repeat(32)));
    }
    // forge-held enabled, nothing on-chain: no anchor tags at all
    let tip = Command::new("git")
        .args([
            "--git-dir",
            bare.to_str().unwrap(),
            "rev-parse",
            "refs/heads/main",
        ])
        .output()
        .unwrap();
    let tip = String::from_utf8_lossy(&tip.stdout).trim().to_string();
    svc.trails()
        .enable("casey", "agent", "main", &tip)
        .await
        .unwrap();
    let (ev, st) = tags_for(&svc).await;
    for tags in [&ev, &st] {
        assert!(
            !tags
                .iter()
                .any(|t| matches!(t[0].as_str(), "anchor" | "r" | "chain" | "txo" | "commit")),
            "no fallback to the repo-held trail: {tags:?}"
        );
    }
    // mark 0 recorded: the forge-held genesis is the anchor
    let txid = "c".repeat(64);
    svc.trails()
        .record_txo("casey", "agent", 0, &txid, 2, 9000)
        .await
        .unwrap();
    let (ev, st) = tags_for(&svc).await;
    for tags in [&ev, &st] {
        assert!(tags.contains(&vec!["anchor".into(), "tbtc4".into(), txid.clone()]));
        assert!(tags.contains(&vec!["txo".into(), format!("txo:tbtc4:{txid}:2")]));
        assert!(tags.contains(&vec!["commit".into(), tip.clone()]));
        assert!(tags.contains(&vec![
            "r".into(),
            format!("{ORIGIN}/forge/casey/agent/blocktrails.json")
        ]));
    }
}
