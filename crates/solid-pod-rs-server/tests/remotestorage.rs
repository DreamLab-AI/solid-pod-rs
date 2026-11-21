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
        "/storage/me/notes/a.txt.meta.json",
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
    assert!(!storage
        .exists("/remotestorage/notes/a.txt.meta.json")
        .await
        .unwrap());
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

#[actix_web::test]
async fn webfinger_uses_the_public_origin_not_the_bind_address() {
    let mut p = pod(true).await;
    p.state.nodeinfo.base_url = "http://0.0.0.0:9".into();
    let app = test::init_service(build_app(p.state)).await;
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
}

// ---------------------------------------------------------------------------
// Review B1/B2: documents are served inert; guarded names in any spelling
// ---------------------------------------------------------------------------

fn header<'a>(h: &'a actix_web::http::header::HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

/// Every response of the storage route must carry these two.
fn assert_inert(h: &actix_web::http::header::HeaderMap, what: &str) {
    assert_eq!(
        header(h, "x-content-type-options"),
        Some("nosniff"),
        "{what}: nosniff"
    );
    let csp = header(h, "content-security-policy").unwrap_or("");
    assert!(
        csp.contains("sandbox") && csp.contains("default-src 'none'"),
        "{what}: CSP was {csp:?}"
    );
}

#[actix_web::test]
async fn stored_active_content_is_served_inert_on_every_method_and_status() {
    // Property: whatever a token holder stores, the pod origin never executes
    // it: every storage response (GET, HEAD, 304, PUT, DELETE, OPTIONS, and
    // 401/403/404/412 bodies) is nosniff and sandboxed, and script-capable
    // types are additionally forced to download.
    let p = pod(true).await;
    let app = test::init_service(build_app(p.state)).await;
    let rw = mint(&app, "m:rw", None).await;
    let ro = mint(&app, "other:r", None).await;

    let active = [
        ("page.html", "text/html"),
        ("page2.html", "TEXT/HTML; charset=utf-8"),
        ("x.xhtml", "application/xhtml+xml"),
        ("img.svg", "image/svg+xml"),
        ("d.xml", "application/xml"),
        ("e.xml", "text/xml"),
        ("f.atom", "application/atom+xml"),
        ("s.js", "text/javascript"),
    ];
    for (name, ct) in active {
        let uri = format!("/storage/me/public/m/{name}");
        let (s, h, _) = call(
            &app,
            with("PUT", &uri, Some(&rw))
                .insert_header(("content-type", ct))
                .set_payload("<script>alert(1)</script>"),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{uri}");
        assert_inert(&h, &format!("PUT {name}"));

        // Anonymous GET and HEAD of the public document.
        for method in ["GET", "HEAD"] {
            let (s, h, _) = call(&app, with(method, &uri, None)).await;
            assert_eq!(s, StatusCode::OK, "{method} {uri}");
            assert_inert(&h, &format!("{method} {name}"));
            assert_eq!(
                header(&h, "content-disposition"),
                Some("attachment"),
                "{method} {name} must download, not render"
            );
        }
        // 304 on a matching ETag.
        let (_, h, _) = call(&app, with("GET", &uri, None)).await;
        let etag = header(&h, "etag").unwrap().to_string();
        let (s, h, _) = call(
            &app,
            with("GET", &uri, None).insert_header(("if-none-match", etag)),
        )
        .await;
        assert_eq!(s, StatusCode::NOT_MODIFIED);
        assert_inert(&h, &format!("304 {name}"));
    }

    // Inert types are not forced to download.
    let (s, _, _) = call(
        &app,
        with("PUT", "/storage/me/public/m/data.json", Some(&rw))
            .insert_header(("content-type", "application/json"))
            .set_payload("{}"),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    let (_, h, _) = call(&app, with("GET", "/storage/me/public/m/data.json", None)).await;
    assert_inert(&h, "json");
    assert_eq!(header(&h, "content-disposition"), None);

    // Error bodies, authorisation failures, preflight, folder listings, DELETE.
    let (s, h, _) = call(&app, with("GET", "/storage/me/public/m/none", None)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_inert(&h, "404");
    let (s, h, _) = call(&app, with("GET", "/storage/me/m/x", None)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_inert(&h, "401");
    let (s, h, _) = call(
        &app,
        with("PUT", "/storage/me/m/x", Some(&ro)).set_payload("x"),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_inert(&h, "403");
    let (s, h, _) = call(
        &app,
        with("PUT", "/storage/me/m/x", Some(&rw))
            .insert_header(("if-match", "\"nope\""))
            .set_payload("x"),
    )
    .await;
    assert_eq!(s, StatusCode::PRECONDITION_FAILED);
    assert_inert(&h, "412");
    let (s, h, _) = call(&app, with("GET", "/storage/me/m/", Some(&rw))).await;
    assert_eq!(s, StatusCode::OK);
    assert_inert(&h, "folder listing");
    let (_, h, _) = call(&app, with("OPTIONS", "/storage/me/m/x", None)).await;
    assert_inert(&h, "OPTIONS");
    let (s, h, _) = call(
        &app,
        with("DELETE", "/storage/me/public/m/page.html", Some(&rw)),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_inert(&h, "DELETE");
}

#[actix_web::test]
async fn ldp_responses_carry_nosniff() {
    // Property: a stored document served over LDP is never content-sniffed
    // into something else (the writer chose its type). The LDP side is NOT
    // sandboxed: the pod serves `index.html` pages and live-reload HTML from
    // storage by design (owner decision recorded in the CHANGELOG).
    let p = pod(true).await;
    p.storage
        .put(
            "/.acl",
            Bytes::from(format!(
                "@prefix acl: <{ACL}> .\n<#o> a acl:Authorization ; acl:agent <{}> ; \
                 acl:accessTo </> ; acl:default </> ; acl:mode acl:Read, acl:Write, acl:Control .\n\
                 <#p> a acl:Authorization ; acl:agentClass <http://xmlns.com/foaf/0.1/Agent> ; \
                 acl:accessTo </> ; acl:default </> ; acl:mode acl:Read .\n",
                did_of(OWNER)
            )),
            "text/turtle",
        )
        .await
        .unwrap();
    p.storage
        .put("/site/page.html", Bytes::from("<p>hi</p>"), "text/html")
        .await
        .unwrap();
    p.storage
        .put("/site/notes.txt", Bytes::from("hi"), "text/plain")
        .await
        .unwrap();
    let app = test::init_service(build_app(p.state)).await;
    for uri in [
        "/site/page.html",
        "/site/notes.txt",
        "/site/",
        "/site/missing",
    ] {
        for method in ["GET", "HEAD"] {
            let (_, h, _) = call(&app, with(method, uri, None)).await;
            assert_eq!(
                header(&h, "x-content-type-options"),
                Some("nosniff"),
                "{method} {uri}"
            );
        }
    }
}

#[actix_web::test]
async fn guarded_names_are_refused_in_every_spelling_over_http() {
    // Property (review B2): over the wire, no spelling of a sidecar name is
    // writable by a token, and nothing is created.
    let p = pod(true).await;
    let dir = p.dir.path().to_path_buf();
    let app = test::init_service(build_app(p.state)).await;
    let all = mint(&app, "*:rw", None).await;
    for uri in [
        "/storage/me/m/x.ACL",
        "/storage/me/m/x.%41CL",
        "/storage/me/m/X.Meta",
        "/storage/me/m/y.META.JSON",
        "/storage/me/m/y.meta.j%C5%BFon",
    ] {
        let (s, _, _) = call(&app, with("PUT", uri, Some(&all)).set_payload("x")).await;
        assert!(
            s.is_client_error() && s != StatusCode::CREATED,
            "{uri}: {s}"
        );
    }
    let entries = std::fs::read_dir(dir.join("remotestorage/m")).map_or(0, Iterator::count);
    assert_eq!(entries, 0, "something was written under the module");
}

// ---------------------------------------------------------------------------
// Review B3: /remotestorage/ does not inherit the root ACL over LDP
// ---------------------------------------------------------------------------

async fn public_read_root(p: &Pod) {
    p.storage
        .put(
            "/.acl",
            Bytes::from(format!(
                "@prefix acl: <{ACL}> .\n<#o> a acl:Authorization ; acl:agent <{}> ; \
                 acl:accessTo </> ; acl:default </> ; acl:mode acl:Read, acl:Write, acl:Control .\n\
                 <#p> a acl:Authorization ; acl:agentClass <http://xmlns.com/foaf/0.1/Agent> ; \
                 acl:accessTo </> ; acl:default </> ; acl:mode acl:Read .\n",
                did_of(OWNER)
            )),
            "text/turtle",
        )
        .await
        .unwrap();
}

#[actix_web::test]
async fn a_public_read_root_does_not_expose_private_remotestorage_documents() {
    use solid_pod_rs_server::remotestorage::{secure_container, ContainerAcl};
    // Property: with a root ACL that grants the public Read, an anonymous LDP
    // GET of a private remoteStorage document (and of the container listing)
    // is refused once the container has its own ACL, while the owner can
    // still read it and the token API is unaffected.
    let p = pod(true).await;
    public_read_root(&p).await;
    let storage = p.storage.clone();
    let layout = p.state.acl_layout;
    let app = test::init_service(build_app(p.state)).await;
    let rw = mint(&app, "notes:rw", None).await;
    let (s, _, _) = call(
        &app,
        with("PUT", "/storage/me/notes/secret", Some(&rw)).set_payload("private"),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);

    // Baseline: without the mount-time ACL the document IS exposed over LDP.
    let (s, _, body) = call(&app, with("GET", "/remotestorage/notes/secret", None)).await;
    assert_eq!(
        s,
        StatusCode::OK,
        "baseline: the exposure this test guards against"
    );
    assert_eq!(body, b"private");

    assert_eq!(
        secure_container(&*storage, layout).await.unwrap(),
        ContainerAcl::Created
    );
    for uri in [
        "/remotestorage/notes/secret",
        "/remotestorage/notes/",
        "/remotestorage/",
    ] {
        let (s, _, _) = call(&app, with("GET", uri, None)).await;
        assert!(matches!(s.as_u16(), 401 | 403), "{uri}: {s}");
    }
    // The owner keeps access over LDP.
    let uri = "/remotestorage/notes/secret";
    let (s, _, body) = call(
        &app,
        with("GET", uri, None).insert_header(("authorization", nostr("GET", uri, None, OWNER))),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body, b"private");
    // And the remoteStorage API still serves the token holder.
    let (s, _, body) = call(&app, with("GET", "/storage/me/notes/secret", Some(&rw))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body, b"private");
    // The rest of the pod is unchanged: the public can still read the root.
    let (s, _, _) = call(&app, with("GET", "/", None)).await;
    assert_eq!(s, StatusCode::OK);
    // The ACL document is not itself a listed remoteStorage document.
    let (_, _, body) = call(
        &app,
        with("GET", "/storage/me/", Some(&mint(&app, "*:r", None).await)),
    )
    .await;
    assert!(!String::from_utf8_lossy(&body).contains(".acl"));
}

#[actix_web::test]
async fn an_existing_container_acl_is_never_overwritten_and_creation_is_idempotent() {
    use solid_pod_rs::wac::AclLayout;
    use solid_pod_rs_server::remotestorage::{secure_container, ContainerAcl};
    // Property: an owner's own policy for /remotestorage/ survives restarts.
    let p = pod(true).await;
    public_read_root(&p).await;
    let mine = Bytes::from("# the owner's own policy\n");
    p.storage
        .put("/remotestorage.acl", mine.clone(), "text/turtle")
        .await
        .unwrap();
    assert_eq!(
        secure_container(&*p.storage, AclLayout::Sidecar)
            .await
            .unwrap(),
        ContainerAcl::Existing
    );
    assert_eq!(p.storage.get("/remotestorage.acl").await.unwrap().0, mine);
    // Idempotent when the file is ours.
    let q = pod(true).await;
    public_read_root(&q).await;
    assert_eq!(
        secure_container(&*q.storage, AclLayout::Sidecar)
            .await
            .unwrap(),
        ContainerAcl::Created
    );
    let first = q.storage.get("/remotestorage.acl").await.unwrap().0;
    assert_eq!(
        secure_container(&*q.storage, AclLayout::Sidecar)
            .await
            .unwrap(),
        ContainerAcl::Existing
    );
    assert_eq!(q.storage.get("/remotestorage.acl").await.unwrap().0, first);
}

#[actix_web::test]
async fn the_acl_is_written_in_the_form_the_active_layout_reads() {
    use solid_pod_rs::wac::AclLayout;
    use solid_pod_rs_server::remotestorage::{secure_container, ContainerAcl};
    // Property: Sidecar writes /remotestorage.acl, Inner writes
    // /remotestorage/.acl, and neither writes the form the layout ignores; an
    // ACL in the ignored form does not count as existing.
    for (layout, written, absent) in [
        (
            AclLayout::Sidecar,
            "/remotestorage.acl",
            "/remotestorage/.acl",
        ),
        (
            AclLayout::Inner,
            "/remotestorage/.acl",
            "/remotestorage.acl",
        ),
    ] {
        let p = pod(true).await;
        public_read_root(&p).await;
        assert_eq!(
            secure_container(&*p.storage, layout).await.unwrap(),
            ContainerAcl::Created
        );
        assert!(p.storage.exists(written).await.unwrap(), "{layout:?}");
        assert!(!p.storage.exists(absent).await.unwrap(), "{layout:?}");
    }
    let p = pod(true).await;
    public_read_root(&p).await;
    p.storage
        .put(
            "/remotestorage/.acl",
            Bytes::from("# ignored by sidecar\n"),
            "text/turtle",
        )
        .await
        .unwrap();
    assert_eq!(
        secure_container(&*p.storage, AclLayout::Sidecar)
            .await
            .unwrap(),
        ContainerAcl::Created,
        "an inner ACL is ignored by the sidecar layout"
    );
}

#[actix_web::test]
async fn with_no_owner_in_the_root_acl_nothing_is_written() {
    use solid_pod_rs::wac::AclLayout;
    use solid_pod_rs_server::remotestorage::{secure_container, ContainerAcl};
    // Property: no owner is invented. A root ACL with no Control agent leaves
    // /remotestorage/ without an ACL of its own.
    let p = pod(true).await;
    p.storage
        .put(
            "/.acl",
            Bytes::from(format!(
                "@prefix acl: <{ACL}> .\n<#p> a acl:Authorization ; \
                 acl:agentClass <http://xmlns.com/foaf/0.1/Agent> ; \
                 acl:accessTo </> ; acl:default </> ; acl:mode acl:Read .\n"
            )),
            "text/turtle",
        )
        .await
        .unwrap();
    assert_eq!(
        secure_container(&*p.storage, AclLayout::Sidecar)
            .await
            .unwrap(),
        ContainerAcl::NoOwner
    );
    assert!(!p.storage.exists("/remotestorage.acl").await.unwrap());
}
