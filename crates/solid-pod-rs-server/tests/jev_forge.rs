//! SP-08-S1-01 (forge half): Jev reranks only what the forge's own
//! authorisation already returned. Run with
//! `cargo test -p solid-pod-rs-server --features "jev forge"`.
#![cfg(all(feature = "jev", feature = "forge"))]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{json, Value};
use solid_pod_rs_forge::{ForgeAgent, ForgeConfig, ForgeRequest, ForgeService};
use solid_pod_rs_server::jev::{
    rerank_forge_listing, Fallback, JevConfig, JevRuntime, JevTransport, DEADLINE,
};

struct Spy {
    reply: Result<(u16, Vec<u8>), Fallback>,
    seen: Mutex<Vec<String>>,
}
#[async_trait]
impl JevTransport for Spy {
    async fn post(&self, _c: &JevConfig, body: Vec<u8>) -> Result<(u16, Vec<u8>), Fallback> {
        self.seen
            .lock()
            .unwrap()
            .push(String::from_utf8(body).unwrap());
        self.reply.clone()
    }
}
fn rt(reply: Result<(u16, Vec<u8>), Fallback>) -> (JevRuntime, Arc<Spy>) {
    let spy = Arc::new(Spy {
        reply,
        seen: Mutex::new(vec![]),
    });
    let cfg = JevConfig {
        endpoint: "http://mock".into(),
        model: "jev-latest".into(),
        bearer: None,
        timeout: DEADLINE,
        rank_min_confidence: 0.25,
        op_min_confidence: None,
    };
    (
        JevRuntime {
            config: Ok(cfg),
            transport: spy.clone(),
        },
        spy,
    )
}
fn ok(v: Value) -> Result<(u16, Vec<u8>), Fallback> {
    Ok((200, serde_json::to_vec(&v).unwrap()))
}

fn bare(root: &std::path::Path, owner: &str, name: &str) {
    let d = root.join("repos").join(owner).join(format!("{name}.git"));
    std::fs::create_dir_all(&d).unwrap();
    let st = std::process::Command::new("git")
        .args(["init", "--bare", "-q"])
        .arg(&d)
        .status()
        .unwrap();
    assert!(st.success());
}

fn alice() -> ForgeAgent {
    ForgeAgent::Pod {
        webid: "https://pod.example/alice/profile/card#me".into(),
        username: "alice".into(),
    }
}

async fn forge_get(svc: &ForgeService, path: &str, query: &str) -> (u16, Vec<u8>) {
    let r = svc
        .handle(
            ForgeRequest {
                method: "GET".into(),
                path: path.into(),
                query: query.into(),
                headers: vec![],
                raw_body: bytes::Bytes::new(),
                host_url: Some("https://pod.example".into()),
            },
            alice(),
        )
        .await
        .unwrap();
    (r.status, r.body.to_vec())
}

fn repo_scores() -> Value {
    // alice's listing is sorted by last push (equal here), so order is stable;
    // make the second candidate the clear best.
    json!({"answers":{
        "rel_c0":{"type":"score","score":0.2,"confidence":0.9},
        "rel_c1":{"type":"score","score":1.9,"confidence":0.9},
        "no_suitable":{"type":"noul","noul":0.05}}})
}

#[tokio::test]
async fn unauthorised_repos_never_reach_jev_and_fallbacks_equal_forge_output() {
    let td = tempfile::tempdir().unwrap();
    for (o, n) in [
        ("alice", "notes"),
        ("alice", "ledger"),
        ("bob", "secret-plans"),
    ] {
        bare(td.path(), o, n);
    }
    let cfg = ForgeConfig {
        private_repos: true,
        ..ForgeConfig::default()
    };
    let svc = ForgeService::new(cfg, td.path()).unwrap();
    let q = "jev_query=accounting%20books";
    let (status, original) = forge_get(&svc, "/forge/api/repos", q).await;
    assert_eq!(status, 200);
    let names: Vec<String> = serde_json::from_slice::<Value>(&original).unwrap()["repos"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            format!(
                "{}/{}",
                r["owner"].as_str().unwrap(),
                r["name"].as_str().unwrap()
            )
        })
        .collect();
    assert_eq!(
        names.len(),
        2,
        "private_repos limits alice to her namespace: {names:?}"
    );

    // Accept path: reranked, annotated, and the spy saw only authorised repos.
    let (rt_ok, spy) = rt(ok(repo_scores()));
    let new = rerank_forge_listing(&rt_ok, "GET", "/forge/api/repos", q, status, &original)
        .await
        .expect("accepted");
    let doc: Value = serde_json::from_slice(&new).unwrap();
    let got: Vec<String> = doc["repos"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            format!(
                "{}/{}",
                r["owner"].as_str().unwrap(),
                r["name"].as_str().unwrap()
            )
        })
        .collect();
    assert_eq!(got, vec![names[1].clone(), names[0].clone()]);
    assert_eq!(doc["jev"]["reranked"], true);
    let seen = spy.seen.lock().unwrap().join("\n");
    assert!(
        !seen.contains("bob") && !seen.contains("secret-plans"),
        "leak: {seen}"
    );
    assert!(seen.contains("accounting books"));

    // Every fallback serves the forge's bytes unchanged.
    let triggers: Vec<(JevRuntime, &str)> = vec![
        (rt(Err(Fallback::Timeout)).0, "timeout"),
        (rt(Ok((500, b"{}".to_vec()))).0, "http-500"),
        (rt(Ok((429, b"{}".to_vec()))).0, "http-429"),
        (rt(Ok((200, b"not json".to_vec()))).0, "malformed"),
        (
            rt(ok(
                json!({"answers":{"rel_c0":{"type":"score","score":1.0,"confidence":0.01},
            "rel_c1":{"type":"score","score":1.0,"confidence":0.01},
            "no_suitable":{"type":"noul","noul":0.5}}}),
            ))
            .0,
            "low-confidence",
        ),
        (
            JevRuntime {
                config: Err(Fallback::FlagOff),
                transport: rt(ok(json!({}))).1,
            },
            "flag-off",
        ),
        (
            JevRuntime {
                config: Err(Fallback::NoEndpoint),
                transport: rt(ok(json!({}))).1,
            },
            "no-endpoint",
        ),
    ];
    for (r, label) in triggers {
        let out = rerank_forge_listing(&r, "GET", "/forge/api/repos", q, status, &original).await;
        assert!(
            out.is_none(),
            "{label}: must serve the forge bytes unchanged"
        );
    }
    // No jev_query => no request at all.
    let (rt_idle, idle) = rt(ok(repo_scores()));
    assert!(
        rerank_forge_listing(&rt_idle, "GET", "/forge/api/repos", "", status, &original)
            .await
            .is_none()
    );
    assert!(idle.seen.lock().unwrap().is_empty());
    // Non-GET and non-200 are never touched.
    assert!(
        rerank_forge_listing(&rt_idle, "POST", "/forge/api/repos", q, 200, &original)
            .await
            .is_none()
    );
    assert!(
        rerank_forge_listing(&rt_idle, "GET", "/forge/api/repos", q, 401, &original)
            .await
            .is_none()
    );
    assert!(idle.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn issues_listing_is_reranked_from_the_forge_response_only() {
    // The forge's issue-list body shape (api_issues.rs `api_issue_list`).
    let body = serde_json::to_vec(&json!({
        "state":"open","page":1,"perPage":25,"hasMore":false,"openCount":2,"closedCount":0,
        "issues":[
            {"number":2,"title":"Crash on login","state":"open"},
            {"number":1,"title":"Add dark mode","state":"open"}]
    }))
    .unwrap();
    let (r, spy) = rt(ok(repo_scores()));
    let path = "/forge/api/repos/alice/notes/issues";
    let q = "state=open&jev_query=theme";
    let new = rerank_forge_listing(&r, "GET", path, q, 200, &body)
        .await
        .expect("accepted");
    let doc: Value = serde_json::from_slice(&new).unwrap();
    assert_eq!(doc["issues"][0]["number"], 1, "dark mode ranks first");
    assert_eq!(doc["openCount"], 2, "other fields untouched");
    let seen = spy.seen.lock().unwrap().join("\n");
    assert!(seen.contains("Add dark mode") && seen.contains("forge issue"));
    // A listing that is not a rerankable path is never touched.
    assert!(
        rerank_forge_listing(&r, "GET", "/forge/api/repos/alice/notes", q, 200, &body)
            .await
            .is_none()
    );
}

#[tokio::test]
async fn full_page_reranks_head_of_twenty_and_leaves_the_tail() {
    let issues: Vec<Value> = (1..=25)
        .map(|n| json!({"number": n, "title": format!("issue {n}"), "state": "open"}))
        .collect();
    let body = serde_json::to_vec(&json!({"issues": issues, "openCount": 25})).unwrap();
    // Reverse the head: later candidates score higher.
    let mut answers = serde_json::Map::new();
    for i in 0..20 {
        answers.insert(
            format!("rel_c{i}"),
            json!({"type":"score","score": i as f64 / 10.0,"confidence":0.9}),
        );
    }
    answers.insert("no_suitable".into(), json!({"type":"noul","noul":0.05}));
    let (r, spy) = rt(ok(json!({ "answers": answers })));
    let path = "/forge/api/repos/alice/notes/issues";
    let new = rerank_forge_listing(&r, "GET", path, "jev_query=x", 200, &body)
        .await
        .expect("accepted");
    let doc: Value = serde_json::from_slice(&new).unwrap();
    let nums: Vec<u64> = doc["issues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["number"].as_u64().unwrap())
        .collect();
    let mut head: Vec<u64> = (1..=20).rev().collect();
    assert_eq!(&nums[..20], head.as_slice(), "head reranked");
    assert_eq!(
        &nums[20..],
        &[21, 22, 23, 24, 25],
        "tail untouched, in order"
    );
    head.sort_unstable();
    assert_eq!(
        head,
        (1..=20).collect::<Vec<u64>>(),
        "permutation of the head"
    );
    let seen = spy.seen.lock().unwrap().join("\n");
    assert!(
        seen.contains("issue 20") && !seen.contains("issue 21"),
        "tail never sent"
    );
    // Fallback on the same page serves the forge's bytes.
    let (bad, _) = rt(Err(Fallback::Timeout));
    assert!(
        rerank_forge_listing(&bad, "GET", path, "jev_query=x", 200, &body)
            .await
            .is_none()
    );
}
