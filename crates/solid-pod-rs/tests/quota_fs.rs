//! Sprint 7 — FS-backed quota sidecar (JSS parity `src/storage/quota.js`).

#![cfg(feature = "quota")]

use solid_pod_rs::quota::{FsQuotaStore, QuotaPolicy};
use std::fs;
use tempfile::TempDir;

fn store(tmp: &TempDir, limit: u64) -> FsQuotaStore {
    FsQuotaStore::new(tmp.path().to_path_buf(), limit)
}

#[tokio::test]
async fn quota_fs_records_first_write() {
    let tmp = TempDir::new().unwrap();
    let s = store(&tmp, 1_000);
    fs::create_dir_all(tmp.path().join("alice")).unwrap();

    s.check("alice", 200).await.unwrap();
    s.record("alice", 200).await;

    let u = s.usage("alice").await.unwrap();
    assert_eq!(u.used_bytes, 200);
    assert_eq!(u.limit_bytes, 1_000);
}

#[tokio::test]
async fn quota_fs_rejects_when_over_limit() {
    let tmp = TempDir::new().unwrap();
    let s = store(&tmp, 500);
    fs::create_dir_all(tmp.path().join("alice")).unwrap();

    s.check("alice", 300).await.unwrap();
    s.record("alice", 300).await;

    let err = s.check("alice", 300).await.unwrap_err();
    assert_eq!(err.pod, "alice");
    assert_eq!(err.used, 300);
    assert_eq!(err.limit, 500);
}

#[tokio::test]
async fn quota_fs_reconcile_restores_from_disk() {
    let tmp = TempDir::new().unwrap();
    let pod_dir = tmp.path().join("alice");
    fs::create_dir_all(&pod_dir).unwrap();
    fs::write(pod_dir.join("a.txt"), [0u8; 100]).unwrap();
    fs::write(pod_dir.join("b.txt"), [0u8; 200]).unwrap();
    fs::create_dir_all(pod_dir.join("sub")).unwrap();
    fs::write(pod_dir.join("sub/c.txt"), [0u8; 50]).unwrap();

    let s = store(&tmp, 10_000);
    // Corrupt the sidecar — wrong used value.
    fs::write(
        pod_dir.join(".quota.json"),
        r#"{"used_bytes": 999999, "limit_bytes": 10000}"#,
    )
    .unwrap();

    let reconciled = s.reconcile("alice").await.unwrap();
    assert_eq!(reconciled.used_bytes, 350, "100 + 200 + 50 = 350");
    assert_eq!(reconciled.limit_bytes, 10_000);

    // Usage reads back reconciled value.
    let u = s.usage("alice").await.unwrap();
    assert_eq!(u.used_bytes, 350);
}

#[tokio::test]
async fn quota_fs_per_pod_isolation() {
    let tmp = TempDir::new().unwrap();
    let s = store(&tmp, 1_000);
    fs::create_dir_all(tmp.path().join("alice")).unwrap();
    fs::create_dir_all(tmp.path().join("bob")).unwrap();

    s.check("alice", 900).await.unwrap();
    s.record("alice", 900).await;

    // Bob's check is unaffected by Alice's usage.
    s.check("bob", 900).await.unwrap();
    s.record("bob", 900).await;

    let ua = s.usage("alice").await.unwrap();
    let ub = s.usage("bob").await.unwrap();
    assert_eq!(ua.used_bytes, 900);
    assert_eq!(ub.used_bytes, 900);
}

#[tokio::test]
async fn quota_check_zero_delta_always_allowed() {
    let tmp = TempDir::new().unwrap();
    let s = store(&tmp, 100);
    fs::create_dir_all(tmp.path().join("alice")).unwrap();

    // Pre-populate over-limit usage on disk.
    fs::write(
        tmp.path().join("alice/.quota.json"),
        r#"{"used_bytes": 999, "limit_bytes": 100}"#,
    )
    .unwrap();

    // Zero-delta check (HEAD/GET style) must not reject.
    s.check("alice", 0).await.unwrap();
}
