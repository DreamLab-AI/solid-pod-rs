//! git-marks integration tests (ADR-059 D1, Phase 2).
//!
//! Every LDP write (PUT/POST/PATCH) to a **git-backed** pod must, after the
//! write succeeds, produce a git commit and a PROV-O sidecar at
//! `<resource>.prov.ttl`. The hook is *additive* and *best-effort*: it runs
//! after the storage write and never changes the response status, and it only
//! fires for pods that have a `.git` directory (non-git pods are untouched).
//!
//! These assertions need the `git` binary (for `git init` / `git log`); they
//! short-circuit to a pass when it is absent so CI without git still runs.
//!
//! Run with: `cargo test -p solid-pod-rs-server --features git`.
#![cfg(feature = "git")]

use std::process::Stdio;
use std::sync::Arc;

use actix_web::{test, web};
use solid_pod_rs::storage::fs::FsBackend;
use solid_pod_rs_server::{build_app, AppState};

fn git_available() -> bool {
    std::process::Command::new("git")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Public read+write ACL so an anonymous PUT/POST/PATCH lands (keeps the test
/// free of NIP-98 token minting — the hook behaviour is identical regardless of
/// the authenticated principal, only the recorded `agent_did` differs).
fn public_write_acl(container: &str) -> String {
    format!(
        r##"{{
            "@context": {{
                "acl": "http://www.w3.org/ns/auth/acl#",
                "foaf": "http://xmlns.com/foaf/0.1/"
            }},
            "@graph": [{{
                "@id": "#public",
                "acl:agentClass": {{"@id": "foaf:Agent"}},
                "acl:accessTo": {{"@id": "{container}"}},
                "acl:default": {{"@id": "{container}"}},
                "acl:mode": [
                    {{"@id": "acl:Read"}},
                    {{"@id": "acl:Write"}},
                    {{"@id": "acl:Append"}}
                ]
            }}]
        }}"##
    )
}

/// Build an fs-backed state with a single pod `alice`, a public-write sibling
/// ACL, and an initialised git repo at `data_root/alice` (so the pod is
/// git-backed). Returns the state + the tempdir (kept alive by the caller).
async fn git_backed_state() -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().to_path_buf();

    // Pod container dir + sibling ACL (the resolver reads `/{pod}.acl`).
    std::fs::create_dir_all(root.join("alice")).expect("create pod dir");
    std::fs::write(
        root.join("alice.acl"),
        public_write_acl("/alice/"),
    )
    .expect("write acl");

    // Initialise the pod git repo so the git-mark hook recognises it as
    // git-backed (`data_root/alice/.git` must be a dir).
    let init = std::process::Command::new("git")
        .args(["init", "-b", "main"])
        .current_dir(root.join("alice"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("git init");
    assert!(init.success(), "git init must succeed");

    let fs = FsBackend::new(root.clone()).await.expect("fs backend");
    let mut state = AppState::new(Arc::new(fs));
    state.data_root = Some(root);
    (state, tmp)
}

/// Read the first-line commit subjects from the pod repo, newest first.
fn git_log_subjects(repo: &std::path::Path) -> Vec<String> {
    let out = std::process::Command::new("git")
        .args(["log", "--format=%s"])
        .current_dir(repo)
        .output()
        .expect("git log");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|s| s.to_string())
        .collect()
}

#[actix_web::test]
async fn put_to_git_backed_pod_commits_and_writes_prov_sidecar() {
    if !git_available() {
        return;
    }
    let (state, tmp) = git_backed_state().await;
    let repo = tmp.path().join("alice");
    let app = test::init_service(build_app(state)).await;

    // PUT a resource into the git-backed pod.
    let req = test::TestRequest::put()
        .uri("/alice/notes/hello.ttl")
        .insert_header(("content-type", "text/turtle"))
        .set_payload(web::Bytes::from_static(b"<#a> <#b> <#c> ."))
        .to_request();
    let rsp = test::call_service(&app, req).await;
    // The write itself must succeed (the hook is additive — it cannot change
    // this status).
    assert_eq!(rsp.status().as_u16(), 201, "PUT must return 201 Created");

    // 1. A commit was produced (cheap tier).
    let subjects = git_log_subjects(&repo);
    assert!(
        subjects.iter().any(|s| s == "PUT"),
        "a 'PUT' commit must exist in the pod repo; got {subjects:?}"
    );

    // 2. The PROV-O sidecar exists at <resource>.prov.ttl with core triples.
    let sidecar = repo.join("notes/hello.ttl.prov.ttl");
    assert!(sidecar.is_file(), "provenance sidecar must be written");
    let ttl = std::fs::read_to_string(&sidecar).expect("read sidecar");
    assert!(ttl.contains("a prov:Activity"), "PROV-O activity missing:\n{ttl}");
    assert!(ttl.contains("prov:wasGeneratedBy"), "wasGeneratedBy missing");
    assert!(ttl.contains("git:commit"), "git:commit literal missing");
    assert!(
        ttl.contains("prov:generated </alice/notes/hello.ttl>"),
        "generated resource triple missing:\n{ttl}"
    );

    // 3. The resource is retrievable.
    let get = test::TestRequest::get()
        .uri("/alice/notes/hello.ttl")
        .to_request();
    let get_rsp = test::call_service(&app, get).await;
    assert_eq!(get_rsp.status().as_u16(), 200);
}

#[actix_web::test]
async fn sidecar_write_is_not_recursively_marked() {
    if !git_available() {
        return;
    }
    let (state, tmp) = git_backed_state().await;
    let repo = tmp.path().join("alice");
    let app = test::init_service(build_app(state)).await;

    let req = test::TestRequest::put()
        .uri("/alice/doc.ttl")
        .insert_header(("content-type", "text/turtle"))
        .set_payload(web::Bytes::from_static(b"<#x> <#y> <#z> ."))
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(rsp.status().as_u16(), 201);

    // Exactly ONE content commit — the sidecar write must NOT itself be marked
    // (no recursion). The repo has a single "PUT" commit, not two.
    let subjects = git_log_subjects(&repo);
    let put_commits = subjects.iter().filter(|s| *s == "PUT").count();
    assert_eq!(
        put_commits, 1,
        "the .prov.ttl sidecar write must not be recursively committed; got {subjects:?}"
    );
    // The sidecar exists but has no sidecar-of-its-own.
    assert!(repo.join("doc.ttl.prov.ttl").is_file());
    assert!(
        !repo.join("doc.ttl.prov.ttl.prov.ttl").exists(),
        "no recursive .prov.ttl.prov.ttl may be produced"
    );
}

#[actix_web::test]
async fn acl_write_is_not_marked() {
    if !git_available() {
        return;
    }
    let (state, tmp) = git_backed_state().await;
    let repo = tmp.path().join("alice");
    let app = test::init_service(build_app(state)).await;

    // PUT an `.acl` resource — control-plane, must be skipped by the marker.
    let req = test::TestRequest::put()
        .uri("/alice/notes/.acl")
        .insert_header(("content-type", "text/turtle"))
        .set_payload(web::Bytes::from_static(
            b"@prefix acl: <http://www.w3.org/ns/auth/acl#> .",
        ))
        .to_request();
    let rsp = test::call_service(&app, req).await;
    // The write may be 201 or refused by the ACL-lockout guard; either way no
    // commit/sidecar may be produced for an `.acl` path.
    let _ = rsp.status();

    let subjects = git_log_subjects(&repo);
    assert!(
        !subjects.iter().any(|s| s == "PUT"),
        "an .acl write must not be git-marked; commits: {subjects:?}"
    );
    assert!(
        !repo.join("notes/.acl.prov.ttl").exists(),
        "no provenance sidecar may be written for an .acl resource"
    );
}

#[actix_web::test]
async fn non_git_pod_write_is_unaffected() {
    // A pod WITHOUT a `.git` dir must be completely unaffected: the write
    // succeeds and NO `.prov.ttl` sidecar is produced (git-backed-only).
    if !git_available() {
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().to_path_buf();
    std::fs::create_dir_all(root.join("bob")).expect("create pod dir");
    std::fs::write(root.join("bob.acl"), public_write_acl("/bob/")).expect("acl");
    // NOTE: deliberately no `git init` — bob is not git-backed.
    let fs = FsBackend::new(root.clone()).await.expect("fs backend");
    let mut state = AppState::new(Arc::new(fs));
    state.data_root = Some(root);
    let app = test::init_service(build_app(state)).await;

    let req = test::TestRequest::put()
        .uri("/bob/note.ttl")
        .insert_header(("content-type", "text/turtle"))
        .set_payload(web::Bytes::from_static(b"<#a> <#b> <#c> ."))
        .to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(rsp.status().as_u16(), 201, "non-git pod write must still succeed");

    assert!(
        !tmp.path().join("bob/note.ttl.prov.ttl").exists(),
        "a non-git-backed pod must not produce a provenance sidecar"
    );
}
