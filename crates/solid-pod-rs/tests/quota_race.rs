//! Sprint 8 Row 159 follow-up — concurrent-race regression for atomic
//! quota-sidecar writes and the `reconcile()` orphan sweep.
//!
//! JSS PR #309 (`saveQuota`) closed an intermittent-500 race on
//! overlapping PUTs where two writers could interleave and leave a
//! half-written `.quota.json`. Rust parity: `FsQuotaStore::write_sidecar`
//! now writes to `.quota.json.tmp-<pid>-<nanos>` then renames onto the
//! real file (atomic on POSIX). PR #310 added orphan cleanup.
//!
//! These tests prove both invariants hold under stress.
#![cfg(feature = "quota")]

use solid_pod_rs::quota::{FsQuotaStore, QuotaPolicy, QuotaUsage};
use std::fs;
use std::sync::Arc;
use tempfile::TempDir;

const POD: &str = "alice";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quota_concurrent_writes_never_corrupt_sidecar() {
    let tmp = TempDir::new().unwrap();
    fs::create_dir_all(tmp.path().join(POD)).unwrap();
    let store = Arc::new(FsQuotaStore::new(
        tmp.path().to_path_buf(),
        10_000_000,
    ));

    // Pre-seed a known baseline sidecar so we can reason about the
    // final state. reconcile() later will rewrite against disk truth
    // (which is empty of data files) so the concurrent path owns the
    // value we assert on.
    store.record(POD, 0).await;

    // Spawn 32 concurrent +1 records. Each call is a full
    // read-modify-write of the sidecar; without the tempfile+rename
    // shim any interleaving could yield half-written JSON.
    let mut handles = Vec::with_capacity(32);
    for _ in 0..32 {
        let s = Arc::clone(&store);
        handles.push(tokio::spawn(async move {
            s.record(POD, 1).await;
        }));
    }
    for h in handles {
        h.await.expect("record task panicked");
    }

    // Invariant 1: the sidecar exists.
    let quota_path = store.quota_file(POD);
    assert!(
        quota_path.exists(),
        "quota sidecar missing after concurrent writes"
    );

    // Invariant 2: whatever's on disk is a fully-formed QuotaUsage —
    // i.e. no partial / torn write ever became visible. Last-writer
    // wins on the value, so we can't pin used_bytes to 32; but it
    // must be within [1, 32] and parse cleanly.
    let bytes = fs::read(&quota_path).expect("sidecar unreadable");
    let parsed: QuotaUsage = serde_json::from_slice(&bytes)
        .expect("sidecar JSON torn / malformed — atomic write contract broken");
    assert!(
        parsed.used_bytes >= 1 && parsed.used_bytes <= 32,
        "unexpected used_bytes {} after 32 concurrent +1 writes",
        parsed.used_bytes
    );
    assert_eq!(parsed.limit_bytes, 10_000_000);

    // Invariant 3: reconcile() is callable afterwards and produces a
    // coherent result. With zero real data files on disk the
    // reconciled `used_bytes` must be 0.
    let reconciled = store.reconcile(POD).await.expect("reconcile failed");
    assert_eq!(reconciled.used_bytes, 0, "no data files should mean 0 usage");
    assert_eq!(reconciled.limit_bytes, 10_000_000);
}

#[tokio::test]
async fn reconcile_sweeps_tempfile_orphans() {
    // Pre-seed a stale orphan left by a crashed writer. reconcile()
    // must remove it as its first step (before the dir-size walk).
    let tmp = TempDir::new().unwrap();
    let pod_dir = tmp.path().join(POD);
    fs::create_dir_all(&pod_dir).unwrap();

    let orphan = pod_dir.join(".quota.json.tmp-99999-111");
    fs::write(&orphan, b"{\"used_bytes\":0,\"limit_bytes\":0}").unwrap();
    assert!(orphan.exists(), "precondition: orphan seeded");

    // Also plant a plausible second orphan to prove the sweep isn't
    // single-entry.
    let orphan2 = pod_dir.join(".quota.json.tmp-42-999");
    fs::write(&orphan2, b"garbage").unwrap();

    let store = FsQuotaStore::new(tmp.path().to_path_buf(), 1_000);
    let reconciled = store.reconcile(POD).await.expect("reconcile failed");

    // Orphans gone.
    assert!(
        !orphan.exists(),
        "reconcile did not sweep .tmp-* orphan #1"
    );
    assert!(
        !orphan2.exists(),
        "reconcile did not sweep .tmp-* orphan #2"
    );
    // And the canonical sidecar is now present with a coherent value.
    assert_eq!(reconciled.used_bytes, 0);
    assert_eq!(reconciled.limit_bytes, 1_000);
    assert!(store.quota_file(POD).exists());
}
