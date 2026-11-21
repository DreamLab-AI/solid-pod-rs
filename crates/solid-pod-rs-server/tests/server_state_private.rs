//! `<root>/.server/accounts.json` (Argon2 hashes) and `.server/invites.json`
//! are never served over HTTP, whatever the root ACL grants: not by direct
//! GET in any spelling, not in a container listing, not by glob.

use std::sync::Arc;

use actix_web::test;
use solid_pod_rs::storage::fs::FsBackend;
use solid_pod_rs_server::{build_app, AppState};

const PUBLIC_READ_ACL: &str = "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
<#p> a acl:Authorization ; acl:agentClass foaf:Agent ; acl:accessTo </> ; \
acl:default </> ; acl:mode acl:Read .\n";

async fn get(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>,
        Error = actix_web::Error,
    >,
    uri: &str,
) -> (u16, String) {
    let rsp = test::call_service(app, test::TestRequest::get().uri(uri).to_request()).await;
    let status = rsp.status().as_u16();
    let body = test::read_body(rsp).await;
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[actix_web::test]
async fn account_and_invite_stores_are_not_served() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    for (rel, body) in [
        (".acl", PUBLIC_READ_ACL),
        (".server/accounts.json", "MARKER-ACCOUNTS $argon2id$"),
        (".server/invites.json", "MARKER-INVITES"),
        ("alice/public.txt", "PUBLIC-CONTROL"),
    ] {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }
    let fs = FsBackend::new(root.clone()).await.unwrap();
    let mut state = AppState::new(Arc::new(fs));
    state.data_root = Some(root);
    let app = test::init_service(build_app(state)).await;

    // Control: ordinary files are served, so a refusal below is the guard's.
    assert_eq!(
        get(&app, "/alice/public.txt").await,
        (200, "PUBLIC-CONTROL".into())
    );

    for uri in [
        "/.server/accounts.json",
        "/.server/invites.json",
        "/.server/",
        "/.server",
        "/.server/*",
        "/.SERVER/accounts.json",
        "/%2eserver/accounts.json",
        "/.server%2faccounts.json",
        "/alice/../.server/accounts.json",
        "/alice/%2e%2e/.server/accounts.json",
        "/",
        "/*",
    ] {
        for accept in ["*/*", "text/html", "text/turtle", "application/ld+json"] {
            let rsp = test::call_service(
                &app,
                test::TestRequest::get()
                    .uri(uri)
                    .insert_header(("accept", accept))
                    .to_request(),
            )
            .await;
            let status = rsp.status().as_u16();
            let body = String::from_utf8_lossy(&test::read_body(rsp).await).into_owned();
            assert!(
                !body.contains("MARKER-")
                    && !body.contains("argon2id")
                    && !body.contains(".server"),
                "{uri} ({accept}) exposed server state ({status}): {body}"
            );
        }
    }
}
