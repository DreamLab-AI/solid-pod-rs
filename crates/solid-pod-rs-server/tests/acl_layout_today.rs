//! SP-PAR-290: the two default-mode behaviours the layout change deliberately
//! alters (named in the CHANGELOG upgrade notes). Before: an agent with Write
//! could create `/docs.acl/x` (a directory at the sidecar key, answered 201)
//! after which everything under `/docs/` answered 503 even to the owner, and
//! `/docs/.acl/x` was accepted (201). After: both are refused with 400 and
//! the subtree is never locked out; a directory planted at the key reads as
//! absent.

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
async fn a_directory_at_the_sidecar_key_cannot_be_made_and_does_not_lock_out() {
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
    assert_eq!(made, 400, "refused: nothing is created beneath an ACL key");
    assert_eq!(after, 200, "so the subtree is never locked out");
    // A directory planted on disk (as an earlier release allowed) reads as
    // absent: the owner still reads, the parent grant applies.
    std::fs::create_dir_all(_dir.path().join("docs.acl")).unwrap();
    std::fs::write(_dir.path().join("docs.acl/x"), b"junk").unwrap();
    let planted = call(st(), Some(&o), "GET", "/docs/a.txt", "").await.0;
    assert_eq!(
        planted, 200,
        "a directory at the sidecar key reads as absent"
    );
}

#[actix_web::test]
async fn nothing_can_be_created_beneath_an_inner_acl_key() {
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
    assert_eq!(made, 400, "refused: nothing is created beneath an ACL key");
}
