//! ER-22 regression tests: well-known trail secrecy, COPY Source authorisation
//! and ACL propagation, and glob-GET per-child authorisation.
//!
//! Each test drives the full `build_app` stack with a development bearer
//! token (`TOKEN_SECRET`), so the WAC gate runs exactly as in production.

use std::sync::Arc;

use actix_web::test;
use base64::Engine as _;
use bytes::Bytes;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use solid_pod_rs::storage::{fs::FsBackend, memory::MemoryBackend, Storage};
use solid_pod_rs_server::{build_app, AppState};

const SECRET: &str = "01234567890123456789012345678901";
const OWNER: &str = "https://owner.example/profile/card#me";
const WRITER: &str = "https://writer.example/profile/card#me";
const STRANGER: &str = "https://stranger.example/profile/card#me";
const TRAIL: &str = r#"{"ticker":"x","privkey":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}"#;

fn bearer(web_id: &str) -> String {
    std::env::set_var("TOKEN_SECRET", SECRET);
    let data = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::json!({"webId": web_id, "iat": 1, "exp": u64::MAX / 2}).to_string());
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
    mac.update(data.as_bytes());
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("Bearer {data}.{sig}")
}

/// Turtle ACL: `OWNER` has everything; each `(agent, modes)` extra rule is
/// added for `target` (and, as `acl:default`, its descendants).
fn acl(target: &str, extra: &[(&str, &str)]) -> String {
    let mut t = format!(
        "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
         @prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
         <#owner> a acl:Authorization ; acl:agent <{OWNER}> ;\n\
           acl:accessTo <{target}> ; acl:default <{target}> ;\n\
           acl:mode acl:Read, acl:Write, acl:Control .\n"
    );
    for (i, (agent, modes)) in extra.iter().enumerate() {
        let who = if *agent == "*" {
            "acl:agentClass foaf:Agent".to_string()
        } else {
            format!("acl:agent <{agent}>")
        };
        t.push_str(&format!(
            "<#x{i}> a acl:Authorization ; {who} ;\n\
               acl:accessTo <{target}> ; acl:default <{target}> ; acl:mode {modes} .\n"
        ));
    }
    t
}

async fn put(s: &dyn Storage, path: &str, body: &str, ct: &str) {
    s.put(path, Bytes::from(body.to_string()), ct)
        .await
        .unwrap();
}

async fn status_and_body(
    storage: Arc<dyn Storage>,
    method: &str,
    uri: &str,
    who: Option<&str>,
    source: Option<&str>,
) -> (u16, String) {
    let app = test::init_service(build_app(AppState::new(storage))).await;
    let mut req = match method {
        "COPY" => test::TestRequest::default()
            .method(actix_web::http::Method::from_bytes(b"COPY").unwrap()),
        _ => test::TestRequest::get(),
    }
    .uri(uri);
    if let Some(w) = who {
        req = req.insert_header(("Authorization", bearer(w)));
    }
    if let Some(s) = source {
        req = req.insert_header(("Source", s));
    }
    let resp = test::call_service(&app, req.to_request()).await;
    let status = resp.status().as_u16();
    let body = test::read_body(resp).await;
    (status, String::from_utf8_lossy(&body).into_owned())
}

// ---------------------------------------------------------------------------
// STEP 0: trail files under /.well-known/
// ---------------------------------------------------------------------------

async fn trail_storage(root_acl: &str) -> Arc<dyn Storage> {
    let s = Arc::new(MemoryBackend::new());
    put(s.as_ref(), "/.acl", root_acl, "text/turtle").await;
    put(
        s.as_ref(),
        "/.well-known/token/x.json",
        TRAIL,
        "application/json",
    )
    .await;
    put(
        s.as_ref(),
        "/.well-known/gitmark/prov.json",
        TRAIL,
        "application/json",
    )
    .await;
    s
}

#[actix_web::test]
async fn step0_trail_files_unreadable_under_owner_only_root_acl() {
    let s = trail_storage(&acl("/", &[])).await;
    for path in [
        "/.well-known/token/x.json",
        "/.well-known/gitmark/prov.json",
    ] {
        for who in [None, Some(STRANGER)] {
            let (st, body) = status_and_body(s.clone(), "GET", path, who, None).await;
            assert!(matches!(st, 401 | 403), "{path} {who:?} -> {st}");
            assert!(!body.contains("deadbeef"));
        }
    }
}

async fn assert_trail_secret_hidden(root_acl: Option<&str>, path: &str) {
    let s = Arc::new(MemoryBackend::new());
    if let Some(a) = root_acl {
        put(s.as_ref(), "/.acl", a, "text/turtle").await;
    }
    put(s.as_ref(), path, TRAIL, "application/json").await;
    for who in [None, Some(STRANGER)] {
        let (st, body) = status_and_body(s.clone(), "GET", path, who, None).await;
        assert!(
            !body.contains("deadbeef") && matches!(st, 401 | 403 | 404),
            "{path} {who:?} leaked the trail secret: {st}"
        );
    }
}

/// A pod whose root is public-read (a common "public site" configuration)
/// must still never serve the issuer private key in a trail file.
#[actix_web::test]
async fn step0_token_trail_secret_not_served_under_public_read_root_acl() {
    assert_trail_secret_hidden(
        Some(&acl("/", &[("*", "acl:Read")])),
        "/.well-known/token/x.json",
    )
    .await;
}

#[actix_web::test]
async fn step0_gitmark_trail_secret_not_served_under_public_read_root_acl() {
    assert_trail_secret_hidden(
        Some(&acl("/", &[("*", "acl:Read")])),
        "/.well-known/gitmark/prov.json",
    )
    .await;
}

/// No root ACL at all (the server seeds none): record the behaviour.
#[actix_web::test]
async fn step0_trail_secret_not_served_with_no_root_acl() {
    assert_trail_secret_hidden(None, "/.well-known/token/x.json").await;
    assert_trail_secret_hidden(None, "/.well-known/gitmark/prov.json").await;
}

/// The owner (Control holder) can still read a trail; the public
/// `blocktrails.json` stays world-readable under a public-read root.
#[actix_web::test]
async fn step0_owner_reads_trail_and_blocktrails_stays_public() {
    let s = trail_storage(&acl("/", &[("*", "acl:Read")])).await;
    put(
        s.as_ref(),
        "/.well-known/gitmark/prov/blocktrails.json",
        "{\"public\":true}",
        "application/json",
    )
    .await;
    let (st, body) = status_and_body(
        s.clone(),
        "GET",
        "/.well-known/token/x.json",
        Some(OWNER),
        None,
    )
    .await;
    assert_eq!((st, body.contains("deadbeef")), (200, true));
    let (st, body) = status_and_body(
        s,
        "GET",
        "/.well-known/gitmark/prov/blocktrails.json",
        None,
        None,
    )
    .await;
    assert_eq!((st, body.as_str()), (200, "{\"public\":true}"));
}

// ---------------------------------------------------------------------------
// Finding 1: COPY
// ---------------------------------------------------------------------------

async fn copy_storage() -> Arc<MemoryBackend> {
    let s = Arc::new(MemoryBackend::new());
    put(s.as_ref(), "/.acl", &acl("/", &[]), "text/turtle").await;
    put(
        s.as_ref(),
        "/private.acl",
        &acl("/private/", &[]),
        "text/turtle",
    )
    .await;
    put(s.as_ref(), "/private/x", "TOP-SECRET", "text/plain").await;
    put(
        s.as_ref(),
        "/drop.acl",
        &acl("/drop/", &[(WRITER, "acl:Read, acl:Write")]),
        "text/turtle",
    )
    .await;
    put(
        s.as_ref(),
        "/.well-known/token/x.json",
        TRAIL,
        "application/json",
    )
    .await;
    s
}

async fn assert_copy_denied(source: &str) {
    let s = copy_storage().await;
    let (st, _) = status_and_body(s.clone(), "COPY", "/drop/y", Some(WRITER), Some(source)).await;
    assert!(!(200..300).contains(&st), "Source {source:?} -> {st}");
    assert!(
        s.get("/drop/y").await.is_err(),
        "Source {source:?} was copied"
    );
}

#[actix_web::test]
async fn copy_without_source_read_is_denied() {
    let s = copy_storage().await;
    let (st, _) = status_and_body(
        s.clone(),
        "COPY",
        "/drop/y",
        Some(WRITER),
        Some("/private/x"),
    )
    .await;
    assert_eq!(st, 403);
    let (st, body) = status_and_body(s, "GET", "/drop/y", Some(WRITER), None).await;
    assert_eq!(st, 404, "{body}");
}

#[actix_web::test]
async fn copy_source_traversal_is_denied() {
    assert_copy_denied("/drop/../private/x").await;
    assert_copy_denied("../private/x").await;
}

#[actix_web::test]
async fn copy_source_same_host_absolute_url_is_denied() {
    assert_copy_denied("http://localhost:8080/private/x").await;
}

/// "Strip same-origin" must work, not merely fail closed: a readable source
/// named by an absolute same-host URL is copied.
#[actix_web::test]
async fn copy_source_same_host_absolute_url_readable_is_copied() {
    let s = copy_storage().await;
    put(s.as_ref(), "/drop/src", "hello", "text/plain").await;
    let (st, _) = status_and_body(
        s.clone(),
        "COPY",
        "/drop/y",
        Some(WRITER),
        Some("http://localhost:8080/drop/src"),
    )
    .await;
    assert_eq!(st, 201);
    assert_eq!(s.get("/drop/y").await.unwrap().0, Bytes::from("hello"));
}

#[actix_web::test]
async fn copy_source_other_host_is_rejected() {
    let s = copy_storage().await;
    let (st, _) = status_and_body(
        s,
        "COPY",
        "/drop/y",
        Some(WRITER),
        Some("http://evil.example/private/x"),
    )
    .await;
    assert_eq!(st, 400);
}

#[actix_web::test]
async fn copy_acl_source_is_denied() {
    assert_copy_denied("/drop.acl").await;
    assert_copy_denied("/private.acl").await;
}

#[actix_web::test]
async fn copy_well_known_trail_source_is_denied() {
    assert_copy_denied("/.well-known/token/x.json").await;
}

#[actix_web::test]
async fn copy_by_owner_still_works() {
    let s = copy_storage().await;
    let (st, _) = status_and_body(
        s.clone(),
        "COPY",
        "/drop/y",
        Some(OWNER),
        Some("/private/x"),
    )
    .await;
    assert_eq!(st, 201);
    assert_eq!(s.get("/drop/y").await.unwrap().0, Bytes::from("TOP-SECRET"));
}

/// A writer without Control on the destination must not be able to install
/// an ACL there by copying a source that has a sidecar.
#[actix_web::test]
async fn copy_does_not_install_acl_without_control() {
    let s = copy_storage().await;
    put(s.as_ref(), "/drop/src", "hello", "text/plain").await;
    put(
        s.as_ref(),
        "/drop/src.acl",
        &format!(
            "{}<#w> a acl:Authorization ; acl:agent <{WRITER}> ;\n\
               acl:accessTo </drop/src> ; acl:mode acl:Read .\n\
             <#c> a acl:Authorization ; acl:agent <{WRITER}> ;\n\
               acl:accessTo </drop/dst> ; acl:mode acl:Read, acl:Write, acl:Control .\n",
            acl("/drop/src", &[])
        ),
        "text/turtle",
    )
    .await;
    let (st, _) = status_and_body(
        s.clone(),
        "COPY",
        "/drop/dst",
        Some(WRITER),
        Some("/drop/src"),
    )
    .await;
    assert_eq!(st, 201, "plain copy of a readable source still succeeds");
    assert_eq!(s.get("/drop/dst").await.unwrap().0, Bytes::from("hello"));
    assert!(
        s.get("/drop/dst.acl").await.is_err(),
        "writer without Control planted an ACL on the destination"
    );
}

/// The Control holder keeps JSS-style ACL propagation.
#[actix_web::test]
async fn copy_installs_acl_for_control_holder() {
    let s = copy_storage().await;
    put(s.as_ref(), "/drop/src", "hello", "text/plain").await;
    put(
        s.as_ref(),
        "/drop/src.acl",
        &acl("/drop/src", &[]),
        "text/turtle",
    )
    .await;
    let (st, _) = status_and_body(
        s.clone(),
        "COPY",
        "/drop/dst",
        Some(OWNER),
        Some("/drop/src"),
    )
    .await;
    assert_eq!(st, 201);
    assert!(s.get("/drop/dst.acl").await.is_ok());
}

// ---------------------------------------------------------------------------
// Finding 2: glob GET
// ---------------------------------------------------------------------------

async fn seed_glob(s: &dyn Storage) {
    put(s, "/.acl", &acl("/", &[]), "text/turtle").await;
    put(
        s,
        "/g.acl",
        &acl("/g/", &[(WRITER, "acl:Read")]),
        "text/turtle",
    )
    .await;
    put(s, "/g/open.ttl", "<#a> <#p> \"OPEN\" .", "text/turtle").await;
    put(s, "/g/secret.ttl", "<#a> <#p> \"SECRET\" .", "text/turtle").await;
    // Per-resource ACL: owner only (overrides the container default).
    put(
        s,
        "/g/secret.ttl.acl",
        &acl("/g/secret.ttl", &[]),
        "text/turtle",
    )
    .await;
    put(
        s,
        "/g/open.ttl.prov.ttl",
        "<#a> <#p> \"PROV\" .",
        "text/turtle",
    )
    .await;
}

async fn glob_check(storage: Arc<dyn Storage>) {
    seed_glob(storage.as_ref()).await;
    let app = test::init_service(build_app(AppState::new(storage))).await;
    let req = test::TestRequest::get()
        .uri("/g/*")
        .insert_header(("Authorization", bearer(WRITER)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let cc = resp
        .headers()
        .get("cache-control")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    let vary = resp
        .headers()
        .get("vary")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    let body = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
    assert!(body.contains("OPEN"), "{body}");
    assert!(!body.contains("SECRET"), "unreadable child merged: {body}");
    assert!(
        !body.contains("acl:Authorization"),
        "ACL sidecar merged: {body}"
    );
    assert!(!body.contains("PROV"), "provenance sidecar merged: {body}");
    assert!(cc.contains("no-store"), "audience not applied: {cc:?}");
    assert!(
        vary.to_ascii_lowercase().contains("authorization"),
        "{vary:?}"
    );
}

#[actix_web::test]
async fn glob_get_filters_children_memory_backend() {
    glob_check(Arc::new(MemoryBackend::new())).await;
}

#[actix_web::test]
async fn glob_get_filters_children_fs_backend() {
    let dir = tempfile::tempdir().unwrap();
    glob_check(Arc::new(FsBackend::new(dir.path()).await.unwrap())).await;
}
