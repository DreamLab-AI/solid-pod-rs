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

// ---- keyed stripe selection (storage-lock review, D2) ----------------------

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// The stripe lock file each of `paths` maps to, found by locking one at a
/// time in a fresh data root and seeing which lock file appears.
async fn stripe_map(
    root: &Path,
    backend: &FsBackend,
    paths: &[String],
) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for p in paths {
        let before: Vec<_> = lock_files(root);
        let lock = backend
            .lock_exclusive(p, Duration::from_secs(1))
            .await
            .unwrap();
        drop(lock);
        let after = lock_files(root);
        let file = after
            .iter()
            .find(|f| !before.contains(f))
            .cloned()
            .unwrap_or_else(|| "(seen already)".to_string());
        map.insert(p.clone(), file);
    }
    map
}

fn lock_files(root: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(root.join(".solid-pod-locks"))
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .filter(|n| n.ends_with(".lock"))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

#[tokio::test]
async fn stripe_selection_is_keyed_per_data_root() {
    let paths: Vec<String> = (0..96).map(|i| format!("/probe/{i}")).collect();
    // Same names in two data roots: with an unkeyed hash the maps are equal,
    // so a client could aim at a victim's stripe from the outside.
    let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (b1, b2) = (
        FsBackend::new(d1.path()).await.unwrap(),
        FsBackend::new(d2.path()).await.unwrap(),
    );
    let (m1, m2) = (
        stripe_map(d1.path(), &b1, &paths).await,
        stripe_map(d2.path(), &b2, &paths).await,
    );
    // Compare file names by position in the sorted-by-path order only for the
    // first lock of each stripe: use the stripe set produced instead.
    assert_ne!(
        lock_files(d1.path()),
        lock_files(d2.path()),
        "two data roots must not share one stripe mapping\n{m1:?}\n{m2:?}"
    );
}

#[tokio::test]
async fn every_handle_on_a_root_shares_one_key_with_mode_0600() {
    let dir = tempfile::tempdir().unwrap();
    let a = FsBackend::new(dir.path()).await.unwrap();
    let b = FsBackend::new(dir.path()).await.unwrap();
    let held = a
        .lock_exclusive("/k", Duration::from_secs(1))
        .await
        .unwrap();
    // The second handle reads the key the first created: same stripe, so it
    // really is excluded.
    assert!(matches!(
        b.lock_exclusive("/k", Duration::from_millis(100)).await,
        Err(PodError::Conflict(_))
    ));
    drop(held);
    let key = dir.path().join(".solid-pod-locks/key");
    let meta = std::fs::metadata(&key).unwrap();
    assert_eq!(meta.len(), 32);
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
}

#[tokio::test]
async fn concurrent_first_use_settles_on_one_key() {
    let dir = tempfile::tempdir().unwrap();
    let mut joins = Vec::new();
    for _ in 0..8 {
        let root = dir.path().to_path_buf();
        joins.push(tokio::spawn(async move {
            let b = FsBackend::new(root).await.unwrap();
            drop(
                b.lock_exclusive("/c", Duration::from_secs(5))
                    .await
                    .unwrap(),
            );
        }));
    }
    for j in joins {
        j.await.unwrap();
    }
    // Every creator linked its candidate; exactly one key file remains and no
    // temporary files are left behind.
    let names: Vec<String> = std::fs::read_dir(dir.path().join(".solid-pod-locks"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| !n.ends_with(".lock"))
        .collect();
    assert_eq!(names, vec!["key".to_string()], "{names:?}");
    // All handles used the one key: a fresh handle excludes one that holds.
    let a = FsBackend::new(dir.path()).await.unwrap();
    let b = FsBackend::new(dir.path()).await.unwrap();
    let held = a
        .lock_exclusive("/c", Duration::from_secs(1))
        .await
        .unwrap();
    assert!(b
        .lock_exclusive("/c", Duration::from_millis(100))
        .await
        .is_err());
    drop(held);
}

#[tokio::test]
async fn a_key_file_of_the_wrong_length_is_refused_not_regenerated() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".solid-pod-locks")).unwrap();
    std::fs::write(dir.path().join(".solid-pod-locks/key"), b"short").unwrap();
    let a = FsBackend::new(dir.path()).await.unwrap();
    let err = a
        .lock_exclusive("/x", Duration::from_millis(100))
        .await
        .unwrap_err();
    assert!(matches!(err, PodError::Backend(_)), "{err:?}");
    // The file is untouched: regenerating it would split the stripes
    // between processes.
    assert_eq!(
        std::fs::read(dir.path().join(".solid-pod-locks/key")).unwrap(),
        b"short"
    );
}

// ---- state locks never share a file with a resource (D4) -------------------

#[tokio::test]
async fn a_state_lock_does_not_collide_with_a_resource_lock_in_one_task() {
    let (_d, a, _b) = two_handles().await;
    // The same task takes a resource lock and then a state lock: if both could
    // map to one stripe file, the second would wait on the first's own file
    // description until the timeout.
    for i in 0..64 {
        let r = a
            .lock_exclusive(&format!("/r/{i}"), Duration::from_secs(1))
            .await
            .unwrap();
        let s = a
            .lock_exclusive("state:payments", Duration::from_millis(200))
            .await
            .unwrap_or_else(|e| panic!("state lock blocked behind /r/{i}: {e}"));
        drop((s, r));
    }
}

/// First use must tolerate the lock directory appearing and disappearing under
/// it: a creator can be told `NotFound` for an entry another creator has just
/// made (or removed), and that must never surface as an error. Here a thread
/// removes the whole lock directory repeatedly while eight handles take their
/// first lock; every handle must still get a lock. (Linux reports `NotFound`
/// for the removed directory; macOS can report it for a creation race.)
#[tokio::test]
async fn first_use_survives_the_lock_directory_vanishing_underneath_it() {
    let dir = tempfile::tempdir().unwrap();
    let locks = dir.path().join(".solid-pod-locks");
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let chaos = {
        let (locks, stop) = (locks.clone(), stop.clone());
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = std::fs::remove_dir_all(&locks);
                std::thread::sleep(Duration::from_micros(200));
            }
        })
    };
    let mut joins = Vec::new();
    for i in 0..8 {
        let root = dir.path().to_path_buf();
        joins.push(tokio::spawn(async move {
            let b = FsBackend::new(root).await.unwrap();
            drop(
                b.lock_exclusive(&format!("/v{i}"), Duration::from_secs(5))
                    .await
                    .unwrap_or_else(|e| panic!("first lock {i} failed: {e}")),
            );
        }));
    }
    // Let the disturbance run for a while, then stop it so the retries can
    // settle (they are bounded, as the filesystem here is not).
    tokio::time::sleep(Duration::from_millis(15)).await;
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    chaos.join().unwrap();
    for j in joins {
        j.await.unwrap();
    }
}
