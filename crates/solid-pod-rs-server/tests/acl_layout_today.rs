//! SP-PAR-290 baseline: two default-mode behaviours that the opt-in layout
//! change deliberately alters, pinned as they were before it. The "after"
//! assertions replace these in the same file when the change lands (see the
//! CHANGELOG upgrade notes): a directory at an ACL key stops locking a
//! subtree out, and nothing can be created beneath an ACL or meta document.

mod common;
use common::acl_harness::*;

use solid_pod_rs::storage::fs::FsBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::AppState;
use std::sync::Arc;

async fn fs_state(disk: Disk, o: &Agent, b: &Agent) -> (Arc<FsBackend>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let fs = Arc::new(FsBackend::new(dir.path()).await.unwrap());
    let mem = storage(disk, o, b).await;
    for key in [
        "/.acl",
        "/docs.acl",
        "/docs/.acl",
        "/docs/a.txt",
        "/docs/sub/b.txt",
    ] {
        if let Ok((body, meta)) = mem.get(key).await {
            fs.put(key, body, &meta.content_type).await.unwrap();
        }
    }
    (fs, dir)
}

#[actix_web::test]
async fn today_a_directory_at_the_sidecar_key_locks_the_subtree_out() {
    let (o, b) = (agent(1), agent(2));
    let (fs, _dir) = fs_state(Disk::None, &o, &b).await;
    let st = || AppState::new(fs.clone());
    let ctl = call(st(), Some(&o), "GET", "/docs/a.txt", "").await.0;
    assert_eq!(ctl, 200, "control: the owner reads normally");
    // An agent with Write on the parent creates a directory at the sidecar
    // key by writing beneath it.
    let made = call(st(), Some(&b), "PUT", "/docs.acl/x", "<#a> <#b> <#c> .")
        .await
        .0;
    let after = call(st(), Some(&o), "GET", "/docs/a.txt", "").await.0;
    println!("TODAY made={made} owner_read_after={after}");
    assert_eq!(
        (made, after),
        (201, 503),
        "today: accepted, then the subtree answers 503 to everyone"
    );
}

#[actix_web::test]
async fn today_a_resource_can_be_created_beneath_an_inner_acl_key() {
    let (o, b) = (agent(1), agent(2));
    let (fs, _dir) = fs_state(Disk::None, &o, &b).await;
    let made = call(
        AppState::new(fs.clone()),
        Some(&b),
        "PUT",
        "/docs/.acl/x",
        "<#a> <#b> <#c> .",
    )
    .await
    .0;
    println!("TODAY inner beneath={made}");
    assert_eq!(made, 201, "today: accepted");
}
