//! `GET` on a container with `Accept: text/html` serves the child
//! `index.html`. That child has its own ACL: reading the container does not
//! entitle the caller to the child (ER-22).

use std::sync::Arc;

use solid_pod_rs::storage::fs::FsBackend;
use solid_pod_rs_server::{build_app, AppState};

const OWNER: &str = "did:nostr:6e1cf6...owner";

fn acl(target: &str, owner_only: bool) -> String {
    let who = if owner_only {
        format!(r#""acl:agent": {{"@id": "{OWNER}"}}"#)
    } else {
        r#""acl:agentClass": {"@id": "foaf:Agent"}"#.to_string()
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

async fn app_with(
    index_acl: Option<String>,
) -> (
    impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>,
        Error = actix_web::Error,
    >,
    tempfile::TempDir,
) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    std::fs::create_dir_all(root.join("pub")).unwrap();
    std::fs::write(root.join("pub.acl"), acl("/pub/", false)).unwrap();
    std::fs::write(root.join("pub/index.html"), "<html>SECRET-INDEX</html>").unwrap();
    std::fs::write(root.join("pub/other.txt"), "other").unwrap();
    if let Some(a) = index_acl {
        std::fs::write(root.join("pub/index.html.acl"), a).unwrap();
    }
    let fs = FsBackend::new(root.clone()).await.unwrap();
    let mut state = AppState::new(Arc::new(fs));
    state.data_root = Some(root);
    (actix_web::test::init_service(build_app(state)).await, tmp)
}

async fn get_html(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>,
        Error = actix_web::Error,
    >,
) -> (u16, String) {
    let req = actix_web::test::TestRequest::get()
        .uri("/pub/")
        .insert_header(("accept", "text/html"))
        .to_request();
    let rsp = actix_web::test::call_service(app, req).await;
    let status = rsp.status().as_u16();
    let body = actix_web::body::to_bytes(rsp.into_body())
        .await
        .ok()
        .unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[actix_web::test]
async fn owner_only_index_is_not_served_to_a_container_reader() {
    let (app, _t) = app_with(Some(acl("/pub/index.html", true))).await;
    let (status, body) = get_html(&app).await;
    assert_eq!(status, 200, "the container listing is still readable");
    assert!(!body.contains("SECRET-INDEX"), "index.html leaked: {body}");
    assert!(
        body.contains("other.txt"),
        "expected the RDF listing: {body}"
    );
}

#[actix_web::test]
async fn readable_index_is_still_served() {
    let (app, _t) = app_with(None).await;
    let (status, body) = get_html(&app).await;
    assert_eq!(status, 200);
    assert!(body.contains("SECRET-INDEX"), "{body}");
}
