//! A `Slug` may not mint a name the dotfile guard refuses for every other
//! method: POST used to create `/c/.git` and `/c/x.meta.json` that no later
//! request could read or remove through the guard. JSS accepts such slugs;
//! we refuse them (a deliberate, stricter difference, row 6).

use std::sync::Arc;

use actix_web::test;
use bytes::Bytes;
use solid_pod_rs::storage::fs::FsBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::{build_app, AppState};

const OPEN_ACL: &str = "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
     @prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
     <#all> a acl:Authorization ; acl:agentClass foaf:Agent ;\n\
       acl:accessTo </> ; acl:default </> ;\n\
       acl:mode acl:Read, acl:Write, acl:Control .\n";

#[actix_web::test]
async fn post_slug_cannot_mint_a_refused_name() {
    let dir = tempfile::tempdir().unwrap();
    let s: Arc<dyn Storage> = Arc::new(FsBackend::new(dir.path()).await.unwrap());
    s.put("/.acl", Bytes::from(OPEN_ACL), "text/turtle")
        .await
        .unwrap();
    let app = test::init_service(build_app(AppState::new(s))).await;
    for slug in [".git", ".env", "x.meta.json", ".hidden"] {
        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/c/")
                .insert_header(("slug", slug))
                .insert_header(("content-type", "text/plain"))
                .set_payload("x")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status().as_u16(), 400, "slug {slug}");
        assert!(!dir.path().join("c").join(slug).exists(), "slug {slug}");
    }
    // Ordinary slugs, including one that merely contains a dot, still work.
    for slug in ["note", "a.b.txt", "v1.2.config"] {
        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/c/")
                .insert_header(("slug", slug))
                .insert_header(("content-type", "text/plain"))
                .set_payload("x")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status().as_u16(), 201, "slug {slug}");
    }
}
