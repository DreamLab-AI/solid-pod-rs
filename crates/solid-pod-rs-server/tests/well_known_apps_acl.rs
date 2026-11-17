//! `/.well-known/apps` lists pod app manifests, but only those an anonymous
//! caller could read through an ordinary `GET`.

use std::sync::Arc;

use solid_pod_rs::storage::fs::FsBackend;
use solid_pod_rs_server::{build_app, AppState};

const OWNER: &str = "did:nostr:6e1cf6...owner";

fn acl(target: &str, public: bool) -> String {
    let who = if public {
        r#""acl:agentClass": {"@id": "foaf:Agent"}"#.to_string()
    } else {
        format!(r#""acl:agent": {{"@id": "{OWNER}"}}"#)
    };
    format!(
        r##"{{
            "@context": {{"acl": "http://www.w3.org/ns/auth/acl#", "foaf": "http://xmlns.com/foaf/0.1/"}},
            "@graph": [{{
                "@id": "#r",
                {who},
                "acl:accessTo": {{"@id": "{target}"}},
                "acl:default": {{"@id": "{target}"}},
                "acl:mode": {{"@id": "acl:Read"}}
            }}]
        }}"##
    )
}

#[actix_web::test]
async fn only_publicly_readable_manifests_are_listed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    for (pod, public) in [("openpod", true), ("closedpod", false)] {
        std::fs::create_dir_all(root.join(pod).join("apps")).unwrap();
        std::fs::write(
            root.join(pod).join("apps/manifest.json"),
            format!(r#"{{"name":"{pod}-app"}}"#),
        )
        .unwrap();
        std::fs::write(
            root.join(format!("{pod}.acl")),
            acl(&format!("/{pod}/"), public),
        )
        .unwrap();
    }
    let fs = FsBackend::new(root.clone()).await.unwrap();
    let mut state = AppState::new(Arc::new(fs));
    state.data_root = Some(root);
    let app = actix_web::test::init_service(build_app(state)).await;

    let req = actix_web::test::TestRequest::get()
        .uri("/.well-known/apps")
        .to_request();
    let rsp = actix_web::test::call_service(&app, req).await;
    assert_eq!(rsp.status().as_u16(), 200);
    let body: serde_json::Value = actix_web::test::read_body_json(rsp).await;
    let text = body.to_string();
    assert!(
        text.contains("openpod-app"),
        "public manifest missing: {text}"
    );
    assert!(
        !text.contains("closedpod-app"),
        "private manifest leaked: {text}"
    );
    assert_eq!(body["count"], 1);
}
