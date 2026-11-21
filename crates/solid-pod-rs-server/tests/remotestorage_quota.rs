//! Review B4: deleting a remoteStorage document returns its bytes to the quota.
#![cfg(feature = "quota")]
#![allow(dead_code, unused_imports)]

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
async fn deleting_a_document_returns_its_bytes_to_the_quota() {
    // Property: the quota bucket never counts bytes that no longer exist, so a
    // token holder cannot fill the quota by writing and deleting.
    use solid_pod_rs::quota::{FsQuotaStore, QuotaPolicy};
    let mut p = pod(true).await;
    let quota_dir = tempfile::tempdir().unwrap();
    let quota = Arc::new(FsQuotaStore::new(quota_dir.path().to_path_buf(), 100));
    p.state.quota = Some(quota.clone());
    let app = test::init_service(build_app(p.state)).await;
    let rw = mint(&app, "m:rw", None).await;
    let payload = "x".repeat(60);

    let (s, _, _) = call(
        &app,
        with("PUT", "/storage/me/m/a", Some(&rw)).set_payload(payload.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(quota.usage("remotestorage").await.unwrap().used_bytes, 60);
    let (s, _, _) = call(&app, with("DELETE", "/storage/me/m/a", Some(&rw))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        quota.usage("remotestorage").await.unwrap().used_bytes,
        0,
        "the deleted bytes were not returned"
    );
    // The freed space is usable again (60 + 60 would exceed the limit of 100).
    let (s, _, _) = call(
        &app,
        with("PUT", "/storage/me/m/b", Some(&rw)).set_payload(payload),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
}
