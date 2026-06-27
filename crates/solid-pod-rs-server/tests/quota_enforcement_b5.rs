//! B5 — per-pod storage quota enforced on the write path.
//!
//! Uses a mock `QuotaPolicy` (the trait is always compiled; `FsQuotaStore`
//! itself is covered by the core crate) to assert the handler wiring: a PUT
//! that would exceed the cap is rejected with 507 before the write, and an
//! overwrite is charged only its net growth.

use std::sync::Arc;
use std::sync::Mutex;

use actix_web::test;
use async_trait::async_trait;
use bytes::Bytes;

use solid_pod_rs::quota::{QuotaExceeded, QuotaPolicy, QuotaUsage};
use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::{build_app, AppState};

const PUBLIC_RW_ACL: &str = r#"
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<#public> a acl:Authorization ;
    acl:agentClass foaf:Agent ;
    acl:accessTo </> ;
    acl:default </> ;
    acl:mode acl:Read, acl:Write, acl:Append .
"#;

/// Minimal in-memory quota: a single global counter and cap. Mirrors the
/// `FsQuotaStore` semantics the handlers depend on (check before, record
/// after; saturating signed delta).
struct CappedQuota {
    limit: u64,
    used: Mutex<u64>,
}

impl CappedQuota {
    fn new(limit: u64) -> Self {
        Self {
            limit,
            used: Mutex::new(0),
        }
    }
}

#[async_trait]
impl QuotaPolicy for CappedQuota {
    async fn check(&self, pod: &str, delta_bytes: u64) -> Result<(), QuotaExceeded> {
        let used = *self.used.lock().unwrap();
        if used.saturating_add(delta_bytes) > self.limit {
            return Err(QuotaExceeded {
                pod: pod.to_string(),
                used,
                limit: self.limit,
            });
        }
        Ok(())
    }

    async fn record(&self, _pod: &str, delta_bytes: i64) {
        let mut used = self.used.lock().unwrap();
        *used = if delta_bytes >= 0 {
            used.saturating_add(delta_bytes as u64)
        } else {
            used.saturating_sub((-delta_bytes) as u64)
        };
    }

    async fn reconcile(&self, _pod: &str) -> std::io::Result<QuotaUsage> {
        Ok(QuotaUsage {
            used_bytes: *self.used.lock().unwrap(),
            limit_bytes: self.limit,
        })
    }

    async fn usage(&self, _pod: &str) -> Option<QuotaUsage> {
        Some(QuotaUsage {
            used_bytes: *self.used.lock().unwrap(),
            limit_bytes: self.limit,
        })
    }
}

async fn state_with_cap(limit: u64) -> AppState {
    let storage = Arc::new(MemoryBackend::new());
    storage
        .put("/.acl", Bytes::from(PUBLIC_RW_ACL), "text/turtle")
        .await
        .unwrap();
    let mut state = AppState::new(storage);
    state.quota = Some(Arc::new(CappedQuota::new(limit)));
    state
}

fn put(uri: &str, bytes: &'static [u8]) -> actix_web::test::TestRequest {
    test::TestRequest::put()
        .uri(uri)
        .insert_header(("content-type", "text/plain"))
        .set_payload(Bytes::from_static(bytes))
}

#[actix_web::test]
async fn put_exceeding_quota_is_rejected_with_507() {
    let app = test::init_service(build_app(state_with_cap(10).await)).await;

    // 8 bytes fit under the 10-byte cap.
    let resp = test::call_service(&app, put("/a.txt", b"AAAAAAAA").to_request()).await;
    assert_eq!(resp.status().as_u16(), 201, "first write within cap");

    // A further 5 bytes (total 13) must be refused before the write lands.
    let resp = test::call_service(&app, put("/b.txt", b"BBBBB").to_request()).await;
    assert_eq!(
        resp.status().as_u16(),
        507,
        "write exceeding the pod cap must be 507 Insufficient Storage"
    );
}

#[actix_web::test]
async fn overwrite_is_charged_only_net_growth() {
    let app = test::init_service(build_app(state_with_cap(10).await)).await;

    // Fill 8 of 10 bytes.
    let resp = test::call_service(&app, put("/a.txt", b"AAAAAAAA").to_request()).await;
    assert_eq!(resp.status().as_u16(), 201);

    // Overwrite the same resource with 2 bytes: net delta is -6, so usage
    // drops to 2 and a subsequent 7-byte write (total 9) fits.
    let resp = test::call_service(&app, put("/a.txt", b"AA").to_request()).await;
    assert_eq!(resp.status().as_u16(), 201, "shrinking overwrite allowed");

    let resp = test::call_service(&app, put("/c.txt", b"CCCCCCC").to_request()).await;
    assert_eq!(
        resp.status().as_u16(),
        201,
        "after the shrink, 7 more bytes fit under the cap"
    );
}
