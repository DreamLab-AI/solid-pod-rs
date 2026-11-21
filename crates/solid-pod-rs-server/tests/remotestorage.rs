//! SP-PAR-283: remoteStorage over the pod's storage behind `--remotestorage`.
//!
//! Properties, each with the check that fails if it is violated:
//!
//! * nothing is mounted by default;
//! * only the pod owner mints tokens (NIP-98 bound to the body, Control on `/`);
//! * a token reaches only the modules in its scopes, read-only unless `rw`,
//!   and only under `/remotestorage/` in the pod: never an ACL, a dotfile, a
//!   parent path, or another subtree;
//! * public documents are readable without a token, public listings are not;
//! * conditional requests behave as the draft says (304, 412);
//! * a token is no credential anywhere else and is stored only as a hash.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use actix_web::dev::{Service, ServiceResponse};
use actix_web::http::StatusCode;
use actix_web::test;
use bytes::Bytes;
use serde_json::{json, Value};
use solid_pod_rs::auth::nip98;
use solid_pod_rs::storage::fs::FsBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::remotestorage::RemoteStorage;
use solid_pod_rs_server::{build_app, AppState};

const ACL: &str = "http://www.w3.org/ns/auth/acl#";
const BASE: &str = "http://localhost:8080";
const OWNER: u8 = 0x11;

fn did_of(sk: u8) -> String {
    let key = k256::schnorr::SigningKey::from_slice(&[sk; 32]).unwrap();
    format!("did:nostr:{}", hex::encode(key.verifying_key().to_bytes()))
}

fn nostr(method: &str, path: &str, body: Option<&[u8]>, sk: u8) -> String {
    static BASE_T: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let base = *BASE_T.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(30)
    });
    let now = base + SEQ.fetch_add(1, Ordering::Relaxed);
    let t = nip98::mint_with_payload(
        &format!("{BASE}{path}"),
        method,
        body,
        &hex::encode([sk; 32]),
        now,
    )
    .unwrap();
    format!("Nostr {t}")
}

struct Pod {
    dir: tempfile::TempDir,
    storage: Arc<FsBackend>,
    state: AppState,
}

async fn pod(mounted: bool) -> Pod {
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(FsBackend::new(dir.path()).await.unwrap());
    storage
        .put(
            "/.acl",
            Bytes::from(format!(
                "@prefix acl: <{ACL}> .\n<#o> a acl:Authorization ; acl:agent <{}> ; \
                 acl:accessTo </> ; acl:default </> ; acl:mode acl:Read, acl:Write, acl:Control .\n",
                did_of(OWNER)
            )),
            "text/turtle",
        )
        .await
        .unwrap();
    let mut state = AppState::new(storage.clone());
    state.public_base_url = Some(BASE.into());
    state.nodeinfo.base_url = BASE.into();
    state.data_root = Some(dir.path().to_path_buf());
    if mounted {
        state.remotestorage = Some(RemoteStorage::new("me", Some(dir.path())).unwrap());
    }
    Pod {
        dir,
        storage,
        state,
    }
}

async fn call<S, B>(
    app: &S,
    req: test::TestRequest,
) -> (StatusCode, actix_web::http::header::HeaderMap, Vec<u8>)
where
    S: Service<actix_http::Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: actix_web::body::MessageBody,
{
    let rsp = test::call_service(app, req.to_request()).await;
    let status = rsp.status();
    let headers = rsp.headers().clone();
    let body = test::read_body(rsp).await.to_vec();
    (status, headers, body)
}

async fn mint<S, B>(app: &S, scope: &str, ttl: Option<u64>) -> String
where
    S: Service<actix_http::Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: actix_web::body::MessageBody,
{
    let body = serde_json::to_vec(&json!({"scope": scope, "ttl_secs": ttl})).unwrap();
    let (status, _, out) = call(
        app,
        test::TestRequest::post()
            .uri("/remotestorage/tokens")
            .insert_header((
                "authorization",
                nostr("POST", "/remotestorage/tokens", Some(&body), OWNER),
            ))
            .set_payload(body),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&out)
    );
    let v: Value = serde_json::from_slice(&out).unwrap();
    v["access_token"].as_str().unwrap().to_string()
}

fn with(method: &str, uri: &str, token: Option<&str>) -> test::TestRequest {
    let mut r = test::TestRequest::default()
        .method(method.parse().unwrap())
        .uri(uri);
    if let Some(t) = token {
        r = r.insert_header(("authorization", format!("Bearer {t}")));
    }
    r
}

#[actix_web::test]
async fn nothing_is_mounted_by_default() {
    let p = pod(false).await;
    let app = test::init_service(build_app(p.state)).await;
    for (m, uri) in [
        ("GET", "/storage/me/public/notes/a"),
        ("PUT", "/storage/me/notes/a"),
        ("POST", "/remotestorage/tokens"),
    ] {
        let (status, _, _) = call(&app, with(m, uri, None).set_payload("x")).await;
        assert!(
            matches!(status.as_u16(), 401 | 403 | 404 | 405),
            "{m} {uri}: {status}"
        );
        assert_ne!(status.as_u16(), 201);
    }
    let (_, _, w) = call(
        &app,
        test::TestRequest::get().uri("/.well-known/webfinger?resource=acct:me@localhost:8080"),
    )
    .await;
    assert!(!String::from_utf8_lossy(&w).contains("remotestorage"));
}

#[actix_web::test]
async fn only_the_owner_mints_tokens_and_they_are_stored_hashed() {
    let p = pod(true).await;
    let dir = p.dir.path().to_path_buf();
    let app = test::init_service(build_app(p.state)).await;
    let body = serde_json::to_vec(&json!({"scope": "notes:rw"})).unwrap();

    let (s, _, _) = call(
        &app,
        test::TestRequest::post()
            .uri("/remotestorage/tokens")
            .set_payload(body.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _, _) = call(
        &app,
        test::TestRequest::post()
            .uri("/remotestorage/tokens")
            .insert_header((
                "authorization",
                nostr("POST", "/remotestorage/tokens", Some(&body), 0x33),
            ))
            .set_payload(body.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // A token minted for another body does not authorise this one.
    let (s, _, _) = call(
        &app,
        test::TestRequest::post()
            .uri("/remotestorage/tokens")
            .insert_header((
                "authorization",
                nostr("POST", "/remotestorage/tokens", Some(b"{}"), OWNER),
            ))
            .set_payload(body.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // Bad scopes are refused.
    for bad in ["", "notes", "notes:x", "public:rw", "../x:r"] {
        let b = serde_json::to_vec(&json!({"scope": bad})).unwrap();
        let (s, _, _) = call(
            &app,
            test::TestRequest::post()
                .uri("/remotestorage/tokens")
                .insert_header((
                    "authorization",
                    nostr("POST", "/remotestorage/tokens", Some(&b), OWNER),
                ))
                .set_payload(b),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad:?}");
    }

    let token = mint(&app, "notes:rw", None).await;
    let saved = std::fs::read_to_string(dir.join(".remotestorage/tokens.json")).unwrap();
    assert!(
        !saved.contains(&token),
        "the token itself must not be stored"
    );
    assert!(saved.len() > 40);
}

#[actix_web::test]
async fn scopes_confine_a_token_to_its_modules_and_mode() {
    let p = pod(true).await;
    let storage = p.storage.clone();
    let app = test::init_service(build_app(p.state)).await;
    let rw = mint(&app, "notes:rw", None).await;
    let ro = mint(&app, "notes:r other:rw", None).await;
    let all_r = mint(&app, "*:r", None).await;

    let (s, h, _) = call(
        &app,
        with("PUT", "/storage/me/notes/a.txt", Some(&rw))
            .insert_header(("content-type", "text/plain"))
            .set_payload("hello"),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    assert!(h.get("etag").is_some());
    // It lands under /remotestorage/ in the pod, and nowhere else.
    assert!(storage.exists("/remotestorage/notes/a.txt").await.unwrap());
    assert!(!storage.exists("/notes/a.txt").await.unwrap());

    let (s, _, b) = call(&app, with("GET", "/storage/me/notes/a.txt", Some(&rw))).await;
    assert_eq!((s, b.as_slice()), (StatusCode::OK, &b"hello"[..]));

    // Read-only scope cannot write or delete; other modules are out of reach.
    let (s, _, _) = call(
        &app,
        with("PUT", "/storage/me/notes/b.txt", Some(&ro)).set_payload("x"),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = call(&app, with("DELETE", "/storage/me/notes/a.txt", Some(&ro))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = call(&app, with("GET", "/storage/me/notes/a.txt", Some(&ro))).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = call(&app, with("GET", "/storage/me/contacts/a", Some(&rw))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // `*:r` reads everywhere (root listing included) but never writes.
    let (s, _, _) = call(&app, with("GET", "/storage/me/", Some(&all_r))).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = call(
        &app,
        with("PUT", "/storage/me/notes/c", Some(&all_r)).set_payload("x"),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // A module token cannot list the root or write a top-level document.
    let (s, _, _) = call(&app, with("GET", "/storage/me/", Some(&rw))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = call(
        &app,
        with("PUT", "/storage/me/readme", Some(&rw)).set_payload("x"),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // No token, and an unknown token, are 401.
    let (s, _, _) = call(&app, with("GET", "/storage/me/notes/a.txt", None)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, h, _) = call(
        &app,
        with(
            "GET",
            "/storage/me/notes/a.txt",
            Some("0".repeat(64).as_str()),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(h
        .get("www-authenticate")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("invalid_token"));
}

#[actix_web::test]
async fn a_token_cannot_reach_acls_dotfiles_parents_or_other_subtrees() {
    let p = pod(true).await;
    let storage = p.storage.clone();
    let app = test::init_service(build_app(p.state)).await;
    let all = mint(&app, "*:rw", None).await;
    let acl_before = storage.get("/.acl").await.unwrap().0;

    for uri in [
        "/storage/me/notes/x.acl",
        "/storage/me/notes/x.meta",
        "/storage/me/.acl",
        "/storage/me/notes/.hidden",
        "/storage/me/notes/../../.acl",
        "/storage/me/notes/%2e%2e/%2e%2e/.acl",
        "/storage/me/notes/%2E%2E%2F%2E%2E%2F.acl",
        "/storage/me/%2e%2e/.acl",
    ] {
        let (s, _, _) = call(&app, with("PUT", uri, Some(&all)).set_payload("x")).await;
        assert!(s.is_client_error(), "{uri}: {s}");
        assert_ne!(s, StatusCode::CREATED, "{uri}");
    }
    assert_eq!(storage.get("/.acl").await.unwrap().0, acl_before);
    assert!(!storage.exists("/notes/x.acl").await.unwrap());
    assert!(!storage.exists("/remotestorage/notes/x.acl").await.unwrap());
    // A folder cannot be written, and writing under a document is a conflict.
    let (s, _, _) = call(
        &app,
        with("PUT", "/storage/me/notes/", Some(&all)).set_payload("x"),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _, _) = call(
        &app,
        with("PUT", "/storage/me/doc", Some(&all)).set_payload("x"),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, _, _) = call(
        &app,
        with("PUT", "/storage/me/doc/child", Some(&all)).set_payload("x"),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    // The pod's own LDP route does not accept a remoteStorage token.
    let (s, _, _) = call(&app, with("GET", "/remotestorage/doc", Some(&all))).await;
    assert!(matches!(s.as_u16(), 401 | 403), "{s}");
    let (s, _, _) = call(&app, with("PUT", "/anywhere", Some(&all)).set_payload("x")).await;
    assert!(matches!(s.as_u16(), 401 | 403), "{s}");
}

#[actix_web::test]
async fn public_documents_are_readable_but_public_listings_are_not() {
    let p = pod(true).await;
    let app = test::init_service(build_app(p.state)).await;
    let rw = mint(&app, "notes:rw", None).await;
    let other = mint(&app, "other:r", None).await;
    let (s, _, _) = call(
        &app,
        with("PUT", "/storage/me/public/notes/a.txt", Some(&rw)).set_payload("pub"),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);

    let (s, _, b) = call(&app, with("GET", "/storage/me/public/notes/a.txt", None)).await;
    assert_eq!((s, b.as_slice()), (StatusCode::OK, &b"pub"[..]));
    let (s, _, _) = call(&app, with("HEAD", "/storage/me/public/notes/a.txt", None)).await;
    assert_eq!(s, StatusCode::OK);
    for uri in [
        "/storage/me/public/notes/",
        "/storage/me/public/",
        "/storage/me/notes/a.txt",
    ] {
        let (s, _, _) = call(&app, with("GET", uri, None)).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{uri}");
    }
    // Writes are never public.
    let (s, _, _) = call(
        &app,
        with("PUT", "/storage/me/public/notes/b.txt", None).set_payload("x"),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // A listing needs a token covering that module.
    let (s, _, _) = call(&app, with("GET", "/storage/me/public/notes/", Some(&other))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, b) = call(&app, with("GET", "/storage/me/public/notes/", Some(&rw))).await;
    assert_eq!(s, StatusCode::OK);
    let v: Value = serde_json::from_slice(&b).unwrap();
    assert!(v["items"]["a.txt"]["ETag"].is_string());
}

#[actix_web::test]
async fn conditional_requests_and_listings_follow_the_draft() {
    let p = pod(true).await;
    let app = test::init_service(build_app(p.state)).await;
    let t = mint(&app, "notes:rw", None).await;

    let (s, h, _) = call(
        &app,
        with("PUT", "/storage/me/notes/a.txt", Some(&t))
            .insert_header(("content-type", "text/plain"))
            .set_payload("one"),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    let etag1 = h.get("etag").unwrap().to_str().unwrap().to_string();
    // If-None-Match: * refuses to overwrite.
    let (s, _, _) = call(
        &app,
        with("PUT", "/storage/me/notes/a.txt", Some(&t))
            .insert_header(("if-none-match", "*"))
            .set_payload("x"),
    )
    .await;
    assert_eq!(s, StatusCode::PRECONDITION_FAILED);
    // A stale If-Match is 412; the current one succeeds with 200.
    let (s, _, _) = call(
        &app,
        with("PUT", "/storage/me/notes/a.txt", Some(&t))
            .insert_header(("if-match", "\"stale\""))
            .set_payload("x"),
    )
    .await;
    assert_eq!(s, StatusCode::PRECONDITION_FAILED);
    let (s, h2, _) = call(
        &app,
        with("PUT", "/storage/me/notes/a.txt", Some(&t))
            .insert_header(("if-match", etag1.as_str()))
            .insert_header(("content-type", "text/plain"))
            .set_payload("two"),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let etag2 = h2.get("etag").unwrap().to_str().unwrap().to_string();
    assert_ne!(etag1, etag2);
    // 304 on a matching If-None-Match.
    let (s, _, _) = call(
        &app,
        with("GET", "/storage/me/notes/a.txt", Some(&t))
            .insert_header(("if-none-match", etag2.as_str())),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_MODIFIED);

    // The listing is JSON-LD with ETags, and the folder ETag moves with its content.
    let (s, h, b) = call(&app, with("GET", "/storage/me/notes/", Some(&t))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h.get("content-type").unwrap(), "application/ld+json");
    let folder_etag = h.get("etag").unwrap().to_str().unwrap().to_string();
    let v: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(
        v["@context"],
        "http://remotestorage.io/spec/folder-description"
    );
    assert_eq!(v["items"]["a.txt"]["Content-Type"], "text/plain");
    assert_eq!(v["items"]["a.txt"]["Content-Length"], 3);
    let (s, _, _) = call(
        &app,
        with("GET", "/storage/me/notes/", Some(&t))
            .insert_header(("if-none-match", folder_etag.as_str())),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_MODIFIED);
    let (s, _, _) = call(
        &app,
        with("PUT", "/storage/me/notes/sub/b.txt", Some(&t)).set_payload("b"),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    let (_, h, b) = call(&app, with("GET", "/storage/me/notes/", Some(&t))).await;
    assert_ne!(h.get("etag").unwrap().to_str().unwrap(), folder_etag);
    let v: Value = serde_json::from_slice(&b).unwrap();
    assert!(v["items"]["sub/"]["ETag"].is_string());

    // DELETE: stale If-Match is 412, then a plain delete answers 200 and the
    // now-empty folder drops out of the listing.
    let (s, _, _) = call(
        &app,
        with("DELETE", "/storage/me/notes/sub/b.txt", Some(&t))
            .insert_header(("if-match", "\"stale\"")),
    )
    .await;
    assert_eq!(s, StatusCode::PRECONDITION_FAILED);
    let (s, _, _) = call(
        &app,
        with("DELETE", "/storage/me/notes/sub/b.txt", Some(&t)),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = call(
        &app,
        with("DELETE", "/storage/me/notes/sub/b.txt", Some(&t)),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (_, _, b) = call(&app, with("GET", "/storage/me/notes/", Some(&t))).await;
    let v: Value = serde_json::from_slice(&b).unwrap();
    assert!(v["items"].get("sub/").is_none(), "{v}");
    // An absent folder is an empty listing, and the CORS preflight is answered.
    let (s, _, b) = call(&app, with("GET", "/storage/me/notes/none/", Some(&t))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&b).unwrap()["items"],
        json!({})
    );
    let (s, h, _) = call(&app, with("OPTIONS", "/storage/me/notes/a.txt", None)).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(h.get("access-control-allow-origin").unwrap(), "*");
}

#[actix_web::test]
async fn expired_and_revoked_tokens_stop_working_and_webfinger_links_the_storage() {
    let p = pod(true).await;
    let app = test::init_service(build_app(p.state)).await;
    let t = mint(&app, "notes:rw", None).await;
    let (s, _, _) = call(
        &app,
        with("PUT", "/storage/me/notes/a", Some(&t)).set_payload("x"),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, _, w) = call(
        &app,
        test::TestRequest::get().uri("/.well-known/webfinger?resource=acct:me@localhost:8080"),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let jrd: Value = serde_json::from_slice(&w).unwrap();
    let link = jrd["links"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["rel"] == "http://tools.ietf.org/id/draft-dejong-remotestorage")
        .unwrap();
    assert_eq!(link["href"], format!("{BASE}/storage/me/"));
    assert_eq!(
        link["properties"]["http://remotestorage.io/spec/version"],
        "draft-dejong-remotestorage-22"
    );

    // Revocation is owner-only and immediate.
    let (s, _, _) = call(&app, with("DELETE", "/remotestorage/tokens", None)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _, _) = call(
        &app,
        test::TestRequest::delete()
            .uri("/remotestorage/tokens")
            .insert_header((
                "authorization",
                nostr("DELETE", "/remotestorage/tokens", None, OWNER),
            )),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = call(&app, with("GET", "/storage/me/notes/a", Some(&t))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}
