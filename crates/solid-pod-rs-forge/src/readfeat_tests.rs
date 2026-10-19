//! Service-level tests for the read features that span several modules
//! (CSP on pages, the xlogin route, `base_url`, the percent guard, spine
//! serialisation under concurrency).

use crate::api::tests::{fixture, get_json, rq};
use crate::gitrun::testutil::demo_repo;
use crate::spine::issues::load_issue_index;
use crate::{ForgeAgent, ForgeConfig, ForgeResponse, ForgeService};

fn header(r: &ForgeResponse, name: &str) -> String {
    r.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

#[tokio::test]
async fn html_pages_carry_the_csp_and_json_does_not() {
    let (_td, svc, _) = fixture();
    let page = svc
        .handle(
            rq("GET", "/forge/casey/demo", "", ""),
            ForgeAgent::Anonymous,
        )
        .await
        .unwrap();
    let csp = header(&page, "content-security-policy");
    assert!(csp.contains("script-src 'unsafe-inline' 'self' https://esm.sh"));
    assert!(csp.contains("connect-src 'self';"));
    assert_eq!(header(&page, "x-content-type-options"), "nosniff");
    let api = svc
        .handle(rq("GET", "/forge/api/repos", "", ""), ForgeAgent::Anonymous)
        .await
        .unwrap();
    assert_eq!(header(&api, "content-security-policy"), "");
}

#[tokio::test]
async fn csp_connect_config_is_honoured_and_xlogin_route_works() {
    let td = tempfile::TempDir::new().unwrap();
    let cfg = ForgeConfig {
        csp_connect: vec!["https://idp.example".into(), "bad origin".into()],
        ..Default::default()
    };
    let svc = ForgeService::new(cfg, td.path()).unwrap();
    let page = svc
        .handle(rq("GET", "/forge/", "", ""), ForgeAgent::Anonymous)
        .await
        .unwrap();
    assert!(header(&page, "content-security-policy")
        .contains("connect-src 'self' https://idp.example;"));
    let x = svc
        .handle(rq("GET", "/forge/xlogin.js", "", ""), ForgeAgent::Anonymous)
        .await
        .unwrap();
    assert_eq!(x.status, 200);
    assert_eq!(x.body.as_ref(), crate::xlogin::XLOGIN_JS);
    assert_eq!(
        header(&x, "content-security-policy"),
        "",
        "a script needs no page CSP"
    );
    let post = svc
        .handle(
            rq("POST", "/forge/xlogin.js", "", ""),
            ForgeAgent::Anonymous,
        )
        .await
        .unwrap();
    assert_eq!(post.status, 405);
}

#[tokio::test]
async fn base_url_overrides_the_request_host_and_the_guard_runs_first() {
    let td = tempfile::TempDir::new().unwrap();
    demo_repo(td.path());
    let cfg = ForgeConfig {
        base_url: Some("https://forge.public.example".into()),
        ..Default::default()
    };
    let svc = ForgeService::new(cfg, td.path()).unwrap();
    let (_, m) = get_json(
        &svc,
        "/forge/api/repos/casey/demo",
        "",
        ForgeAgent::Anonymous,
    )
    .await;
    assert_eq!(
        m["cloneUrl"],
        "https://forge.public.example/forge/casey/demo.git"
    );
    for p in [
        "/forge/api/repos/casey/demo/blob/main/%2e%2e/x",
        "/forge/casey/demo/raw/main/a%2Fb",
        "/forge/casey/demo.git/info/refs%00",
        "/forge/casey/demo/tree/main/a%5cb",
    ] {
        let r = svc
            .handle(rq("GET", p, "", ""), ForgeAgent::Anonymous)
            .await
            .unwrap();
        assert_eq!(r.status, 400, "{p}");
    }
}

// JSS serializeOn: concurrent writers never lose an update or reuse a number.
#[tokio::test]
async fn concurrent_creates_and_comments_do_not_race() {
    let td = tempfile::TempDir::new().unwrap();
    demo_repo(td.path());
    let svc = ForgeService::new(ForgeConfig::default(), td.path()).unwrap();
    let agent = ForgeAgent::Nostr {
        pubkey_hex: "c".repeat(64),
    };
    let mut tasks = Vec::new();
    for i in 0..20 {
        let (svc, agent) = (svc.clone(), agent.clone());
        tasks.push(tokio::spawn(async move {
            let body = format!(r#"{{"title":"issue {i}","body":"b"}}"#);
            svc.handle(
                rq("POST", "/forge/api/repos/casey/demo/issues", "", &body),
                agent,
            )
            .await
            .unwrap()
            .status
        }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap(), 201);
    }
    let idx = load_issue_index(svc.spine.as_ref(), "casey", "demo")
        .await
        .unwrap();
    assert_eq!(idx.issues.len(), 20, "no lost update");
    assert_eq!(idx.next, 21);
    let mut comments = Vec::new();
    for i in 0..20 {
        let (svc, agent) = (svc.clone(), agent.clone());
        comments.push(tokio::spawn(async move {
            let body = format!(r#"{{"body":"c{i}"}}"#);
            svc.handle(
                rq(
                    "POST",
                    "/forge/api/repos/casey/demo/issues/1/comments",
                    "",
                    &body,
                ),
                agent,
            )
            .await
            .unwrap()
            .status
        }));
    }
    for t in comments {
        assert_eq!(t.await.unwrap(), 201);
    }
    let idx = load_issue_index(svc.spine.as_ref(), "casey", "demo")
        .await
        .unwrap();
    assert_eq!(idx.issues[&1].thread.len(), 21);
}

#[tokio::test]
async fn config_file_defaults_drive_a_private_service() {
    let td = tempfile::TempDir::new().unwrap();
    demo_repo(td.path());
    let f = td.path().join("forge.json");
    std::fs::write(
        &f,
        r#"{"privateRepos": true, "baseUrl": "https://f.example"}"#,
    )
    .unwrap();
    let cfg = ForgeConfig::from_layers(serde_json::json!({}), Some(&f));
    let svc = ForgeService::new(cfg, td.path()).unwrap();
    let r = svc
        .handle(
            rq("GET", "/forge/casey/demo", "", ""),
            ForgeAgent::Anonymous,
        )
        .await
        .unwrap();
    assert_eq!(r.status, 401);
}
