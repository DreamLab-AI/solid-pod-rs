#![cfg(all(feature = "fs-backend", unix))]
//! Cross-process resource lock of the filesystem backend (SP-PAR-275). Two
//! `FsBackend` handles on one directory stand in for two server processes:
//! the lock is an OS file lock, so it excludes across open file descriptions
//! whether they live in one process or two.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use solid_pod_rs::storage::fs::FsBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs::PodError;

async fn two_handles() -> (tempfile::TempDir, Arc<FsBackend>, Arc<FsBackend>) {
    let dir = tempfile::tempdir().unwrap();
    let a = Arc::new(FsBackend::new(dir.path()).await.unwrap());
    let b = Arc::new(FsBackend::new(dir.path()).await.unwrap());
    (dir, a, b)
}

#[tokio::test]
async fn a_second_handle_waits_then_gets_the_lock_after_release() {
    let (_d, a, b) = two_handles().await;
    let held = a
        .lock_exclusive("/doc", Duration::from_secs(1))
        .await
        .unwrap()
        .expect("the filesystem backend locks");
    // Held: the other handle times out with a conflict.
    let t = Instant::now();
    let err = b
        .lock_exclusive("/doc", Duration::from_millis(150))
        .await
        .unwrap_err();
    assert!(matches!(err, PodError::Conflict(_)), "{err:?}");
    assert!(t.elapsed() >= Duration::from_millis(140));
    drop(held);
    assert!(b
        .lock_exclusive("/doc", Duration::from_millis(500))
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn two_handles_cannot_interleave_a_read_modify_write() {
    let (_d, a, b) = two_handles().await;
    a.put("/counter", Bytes::from("0"), "text/plain")
        .await
        .unwrap();
    async fn bump(s: Arc<FsBackend>, n: usize) {
        for _ in 0..n {
            let _lock = s
                .lock_exclusive("/counter", Duration::from_secs(30))
                .await
                .unwrap();
            let (body, _) = s.get("/counter").await.unwrap();
            let v: u64 = std::str::from_utf8(&body).unwrap().parse().unwrap();
            tokio::task::yield_now().await;
            s.put("/counter", Bytes::from((v + 1).to_string()), "text/plain")
                .await
                .unwrap();
        }
    }
    let (x, y) = (tokio::spawn(bump(a.clone(), 40)), tokio::spawn(bump(b, 40)));
    x.await.unwrap();
    y.await.unwrap();
    let (body, _) = a.get("/counter").await.unwrap();
    assert_eq!(&body[..], b"80", "no increment was lost");
}

#[tokio::test]
async fn different_keys_do_not_share_a_stripe_for_ever_and_the_lock_file_is_hidden() {
    let (d, a, _b) = two_handles().await;
    let _l = a
        .lock_exclusive("/one", Duration::from_secs(1))
        .await
        .unwrap();
    a.put("/x.txt", Bytes::from("x"), "text/plain")
        .await
        .unwrap();
    // Nothing is written beside a resource, and the lock directory is not listed.
    assert!(!d.path().join(".x.txt.lock").exists());
    assert_eq!(a.list("/").await.unwrap(), vec!["x.txt".to_string()]);
    assert!(d.path().join(".solid-pod-locks").is_dir());
}
