//! Root and container listings, and the export walk, name no dotfile the
//! request guard refuses and none of the server's own state. `FsBackend::list`
//! of the root now lists the whole data root, so the names under it must be
//! filtered exactly as in any other container.

use std::sync::Arc;

use actix_web::test;
use bytes::Bytes;
use solid_pod_rs::storage::fs::FsBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::{build_app, AppState};

const PUBLIC: &str = "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n<#r> a acl:Authorization ; acl:agentClass foaf:Agent ; acl:accessTo </> ; acl:default </> ; acl:mode acl:Read, acl:Control .\n";

const GUARDED: [&str; 7] = [
    ".git",
    ".forge",
    ".env",
    ".solid-pod-locks",
    "webledgers",
    "gitmark",
    "token",
];

async fn data_root() -> (tempfile::TempDir, Arc<dyn Storage>) {
    let dir = tempfile::tempdir().unwrap();
    let fs = FsBackend::new(dir.path()).await.unwrap();
    for (p, b) in [
        ("/.acl", PUBLIC),
        ("/public.txt", "p"),
        ("/.well-known/jwks.json", "{}"),
        ("/.well-known/webledgers/state.json", "{}"),
        ("/.well-known/token/t.json", "{}"),
        ("/.well-known/gitmark/x/blocktrails.json", "{}"),
    ] {
        fs.put(p, Bytes::from(b), "text/plain").await.unwrap();
    }
    for p in [
        ".git/config",
        ".forge/r/x",
        ".env",
        ".solid-pod-locks/00.lock",
    ] {
        let f = dir.path().join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, "x").unwrap();
    }
    (dir, Arc::new(fs))
}

async fn get(state: AppState, uri: &str) -> String {
    let app = test::init_service(build_app(state)).await;
    let rsp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(uri)
            .insert_header(("accept", "application/ld+json"))
            .to_request(),
    )
    .await;
    assert_eq!(rsp.status().as_u16(), 200, "{uri}");
    String::from_utf8(test::read_body(rsp).await.to_vec()).unwrap()
}

#[actix_web::test]
async fn root_and_well_known_listings_name_no_guarded_entry() {
    let (_d, storage) = data_root().await;
    let root = get(AppState::new(storage.clone()), "/").await;
    assert!(root.contains("public.txt"), "{root}");
    assert!(
        root.contains(".well-known"),
        "the served discovery container stays: {root}"
    );
    for g in GUARDED {
        assert!(!root.contains(g), "root listing names {g}: {root}");
    }
    let wk = get(AppState::new(storage), "/.well-known/").await;
    assert!(wk.contains("jwks.json"), "{wk}");
    for g in GUARDED {
        assert!(!wk.contains(g), ".well-known listing names {g}: {wk}");
    }
}

#[cfg(feature = "export-jsonld")]
#[actix_web::test]
async fn the_export_walk_contains_no_guarded_name() {
    let (_d, storage) = data_root().await;
    let body = get(AppState::new(storage), "/api/exports/all").await;
    assert!(body.contains("/public.txt"), "{body}");
    assert!(body.contains("jwks.json"), "{body}");
    for g in GUARDED {
        assert!(!body.contains(g), "export names {g}");
    }
}
