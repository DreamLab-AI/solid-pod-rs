//! The export walk skips what the dotfile guard refuses and, when the caller
//! says so, server state (storage-lock review, D1). `FsBackend::list("/")`
//! now lists the whole data root, so without a filter `GET /api/exports/all`
//! would walk `.git/`, `.forge/`, the lock directory and every dotfile.

#![cfg(all(feature = "export-jsonld", feature = "fs-backend"))]

use bytes::Bytes;
use solid_pod_rs::export::{export_pod_jsonld, export_pod_jsonld_filtered, ExportOptions};
use solid_pod_rs::storage::fs::FsBackend;
use solid_pod_rs::storage::Storage;

async fn pod() -> (tempfile::TempDir, FsBackend) {
    let dir = tempfile::tempdir().unwrap();
    let fs = FsBackend::new(dir.path()).await.unwrap();
    for (path, body) in [
        ("/public.txt", "p"),
        ("/docs/a.txt", "a"),
        ("/.acl", "acl"),
        ("/.well-known/webledgers/state.json", "{}"),
        ("/.well-known/jwks.json", "{}"),
    ] {
        fs.put(path, Bytes::from(body), "text/plain").await.unwrap();
    }
    // Server and tool state that a pod writer never creates through Storage.
    for (path, body) in [
        (".git/config", "g"),
        (".forge/repo/x", "f"),
        (".env", "SECRET"),
        (".solid-pod-locks/00.lock", ""),
        ("tenant/.git/HEAD", "h"),
    ] {
        let p = dir.path().join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }
    (dir, fs)
}

fn paths(b: &solid_pod_rs::export::PodExportBundle) -> Vec<String> {
    b.entries.iter().map(|e| e.path.clone()).collect()
}

#[actix_web::test]
async fn the_default_walk_skips_dotfiles_and_tool_state() {
    let (_d, fs) = pod().await;
    let b = export_pod_jsonld(&fs, "https://pod.example/", ExportOptions::default())
        .await
        .unwrap();
    let p = paths(&b);
    assert!(p.contains(&"/public.txt".to_string()), "{p:?}");
    assert!(p.contains(&"/docs/a.txt".to_string()), "{p:?}");
    for guarded in [".git", ".forge", ".env", ".solid-pod-locks"] {
        assert!(
            !p.iter().any(|x| x.contains(guarded)),
            "{guarded} exported: {p:?}"
        );
    }
}

#[actix_web::test]
async fn a_caller_predicate_removes_server_state_too() {
    let (_d, fs) = pod().await;
    let b = export_pod_jsonld_filtered(
        &fs,
        "https://pod.example/",
        ExportOptions::default(),
        &|p: &str| !p.starts_with("/.well-known/webledgers/"),
    )
    .await
    .unwrap();
    let p = paths(&b);
    assert!(p.contains(&"/.well-known/jwks.json".to_string()), "{p:?}");
    assert!(!p.iter().any(|x| x.contains("webledgers")), "{p:?}");
    assert!(!p.iter().any(|x| x.contains(".git")), "{p:?}");
}
