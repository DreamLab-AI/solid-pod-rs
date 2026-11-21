//! Regression tests for the behaviour JSS added between 0.0.224 and 0.0.231
//! that this server already has: percent-encoded dot segments (JSS #639) and
//! atomic conditional writes (JSS #600). Written against the filesystem
//! backend, whose I/O yields to the runtime so the requests really interleave.

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

async fn fs_storage(dir: &tempfile::TempDir) -> Arc<dyn Storage> {
    let s: Arc<dyn Storage> = Arc::new(FsBackend::new(dir.path()).await.unwrap());
    s.put("/.acl", Bytes::from(OPEN_ACL), "text/turtle")
        .await
        .unwrap();
    s
}

fn exists_on_disk(dir: &tempfile::TempDir, rel: &str) -> bool {
    dir.path().join(rel).exists()
}

/// A percent-encoded leading dot never reaches a real dotfile: the encoded
/// spelling is one literal name, so `%2Egit` cannot address `.git`, and the
/// literal spelling is refused by the dotfile guard (JSS #639).
#[actix_web::test]
async fn encoded_dot_segments_never_reach_a_dotfile() {
    let dir = tempfile::tempdir().unwrap();
    let storage = fs_storage(&dir).await;
    storage
        .put("/.git/config", Bytes::from("SECRET"), "text/plain")
        .await
        .unwrap();
    let app = test::init_service(build_app(AppState::new(storage.clone()))).await;

    // Reads: the literal spelling is a 403, the encoded ones never serve it.
    for uri in [
        "/.git/config",
        "/%2Egit/config",
        "/%2egit/config",
        "/%2E%67it/config",
    ] {
        let resp = test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
        let status = resp.status().as_u16();
        let body = test::read_body(resp).await;
        assert_ne!(status, 200, "{uri}");
        assert!(!String::from_utf8_lossy(&body).contains("SECRET"), "{uri}");
    }
    let resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/.git/config").to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 403);

    // Writes: an encoded spelling creates a literal name, never a dotfile.
    for uri in ["/%2Egit/hooks/x", "/%2Eacl", "/c/%2Eacl", "/c/%2Emeta"] {
        let resp = test::call_service(
            &app,
            test::TestRequest::put()
                .uri(uri)
                .insert_header(("content-type", "text/plain"))
                .set_payload("x")
                .to_request(),
        )
        .await;
        assert!(resp.status().is_success(), "{uri}: {}", resp.status());
    }
    assert!(!exists_on_disk(&dir, ".git/hooks"));
    assert!(!exists_on_disk(&dir, "c/.acl"));
    assert!(!exists_on_disk(&dir, "c/.meta"));
    let (acl, _) = storage.get("/.acl").await.unwrap();
    assert_eq!(
        &acl[..],
        OPEN_ACL.as_bytes(),
        "the real root ACL is untouched"
    );
}

async fn etag_of_put(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>,
        Error = actix_web::Error,
    >,
    uri: &str,
    body: &str,
) -> String {
    let resp = test::call_service(
        app,
        test::TestRequest::put()
            .uri(uri)
            .insert_header(("content-type", "text/plain"))
            .set_payload(body.to_string())
            .to_request(),
    )
    .await;
    assert!(resp.status().is_success());
    resp.headers()
        .get("etag")
        .expect("PUT returns an ETag")
        .to_str()
        .unwrap()
        .to_string()
}

/// Several PUTs racing with one still-valid `If-Match` end with exactly one
/// success; the rest see the new ETag and get 412 (JSS #600).
#[actix_web::test]
async fn racing_conditional_puts_have_exactly_one_winner() {
    let dir = tempfile::tempdir().unwrap();
    let storage = fs_storage(&dir).await;
    let app = test::init_service(build_app(AppState::new(storage.clone()))).await;
    let etag = etag_of_put(&app, "/public/race.txt", "v0").await;

    let reqs = (1..=5).map(|i| {
        test::call_service(
            &app,
            test::TestRequest::put()
                .uri("/public/race.txt")
                .insert_header(("content-type", "text/plain"))
                .insert_header(("if-match", etag.clone()))
                .set_payload(format!("winner-{i}-{}", "x".repeat(i * 7)))
                .to_request(),
        )
    });
    let statuses: Vec<u16> = futures_util::future::join_all(reqs)
        .await
        .iter()
        .map(|r| r.status().as_u16())
        .collect();
    let wins = statuses.iter().filter(|s| (200..300).contains(*s)).count();
    let refused = statuses.iter().filter(|s| **s == 412).count();
    assert_eq!(wins, 1, "{statuses:?}");
    assert_eq!(refused, 4, "{statuses:?}");
}

/// Racing `If-None-Match: *` creates give exactly one 201 (JSS #600).
#[actix_web::test]
async fn racing_if_none_match_creates_have_exactly_one_winner() {
    let dir = tempfile::tempdir().unwrap();
    let storage = fs_storage(&dir).await;
    let app = test::init_service(build_app(AppState::new(storage.clone()))).await;
    let reqs = (1..=3).map(|i| {
        test::call_service(
            &app,
            test::TestRequest::put()
                .uri("/public/create.txt")
                .insert_header(("content-type", "text/plain"))
                .insert_header(("if-none-match", "*"))
                .set_payload(format!("c{i}"))
                .to_request(),
        )
    });
    let statuses: Vec<u16> = futures_util::future::join_all(reqs)
        .await
        .iter()
        .map(|r| r.status().as_u16())
        .collect();
    assert_eq!(
        statuses.iter().filter(|s| **s == 201).count(),
        1,
        "{statuses:?}"
    );
    assert_eq!(
        statuses.iter().filter(|s| **s == 412).count(),
        2,
        "{statuses:?}"
    );
}

/// A DELETE racing a PUT with the same `If-Match`: exactly one wins.
#[actix_web::test]
async fn racing_delete_and_put_have_exactly_one_winner() {
    let dir = tempfile::tempdir().unwrap();
    let storage = fs_storage(&dir).await;
    let app = test::init_service(build_app(AppState::new(storage.clone()))).await;
    let etag = etag_of_put(&app, "/public/dp.txt", "v0").await;
    let del = test::call_service(
        &app,
        test::TestRequest::delete()
            .uri("/public/dp.txt")
            .insert_header(("if-match", etag.clone()))
            .to_request(),
    );
    let put = test::call_service(
        &app,
        test::TestRequest::put()
            .uri("/public/dp.txt")
            .insert_header(("content-type", "text/plain"))
            .insert_header(("if-match", etag))
            .set_payload("v1")
            .to_request(),
    );
    let (d, p) = futures_util::future::join(del, put).await;
    let (d, p) = (d.status().as_u16(), p.status().as_u16());
    assert_eq!(
        [d, p].iter().filter(|s| (200..300).contains(*s)).count(),
        1,
        "{d}/{p}"
    );
    assert!([d, p].contains(&412), "{d}/{p}");
}

/// A failed conditional PUT into a container that does not exist creates
/// nothing (JSS #600).
#[actix_web::test]
async fn failed_if_match_put_into_a_missing_container_creates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let storage = fs_storage(&dir).await;
    let app = test::init_service(build_app(AppState::new(storage.clone()))).await;
    let resp = test::call_service(
        &app,
        test::TestRequest::put()
            .uri("/public/nodir/x.txt")
            .insert_header(("content-type", "text/plain"))
            .insert_header(("if-match", "\"nope\""))
            .set_payload("x")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 412);
    assert!(!exists_on_disk(&dir, "public/nodir"));
    let resp = test::call_service(
        &app,
        test::TestRequest::delete()
            .uri("/public/nodir2/x.txt")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 404);
    assert!(!exists_on_disk(&dir, "public/nodir2"));
}
