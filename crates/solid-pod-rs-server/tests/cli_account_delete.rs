//! `account delete` operates on the real storage root (SP-02.13).
//!
//! Drives both the runner and `dispatch`, the binary's own wiring, which is
//! where the command once reached an empty in-memory store and did nothing.

use std::path::Path;

use clap::Parser;
use solid_pod_rs_server::cli::{dispatch, run_account_delete, AccountDeleteArgs, OperatorCommand};

struct Scripted(Vec<Option<String>>);

impl solid_pod_rs_server::cli::Prompt for Scripted {
    fn ask(&mut self, _prompt: &str) -> std::io::Result<Option<String>> {
        Ok(if self.0.is_empty() {
            None
        } else {
            self.0.remove(0)
        })
    }
}

#[derive(Parser)]
struct Harness {
    #[command(subcommand)]
    op: OperatorCommand,
}

/// A root holding two pods laid out as `POST /.pods` writes them, plus a
/// root-level file that must survive.
fn make_root() -> tempfile::TempDir {
    let tmp = tempfile::TempDir::new().unwrap();
    for pod in ["alice", "bob"] {
        let d = tmp.path().join(pod);
        std::fs::create_dir_all(d.join("profile")).unwrap();
        std::fs::create_dir_all(d.join("private")).unwrap();
        std::fs::write(d.join("profile/card"), "<html/>").unwrap();
        std::fs::write(d.join("private/secret.txt"), "s").unwrap();
        std::fs::write(tmp.path().join(format!("{pod}.acl")), "acl").unwrap();
        std::fs::write(tmp.path().join(format!("{pod}.meta")), "{}").unwrap();
        std::fs::write(tmp.path().join(format!("{pod}.meta.meta.json")), "{}").unwrap();
    }
    std::fs::write(tmp.path().join("root.txt"), "keep").unwrap();
    tmp
}

fn args(root: &Path, name: &str, yes: bool) -> AccountDeleteArgs {
    AccountDeleteArgs {
        user_id: name.into(),
        root: root.to_path_buf(),
        yes,
    }
}

#[tokio::test]
async fn dispatch_removes_the_pod_and_its_webid_from_the_root() {
    let tmp = make_root();
    let root = tmp.path().to_str().unwrap();
    let parsed =
        Harness::try_parse_from(["t", "account", "delete", "alice", "--yes", "--root", root])
            .unwrap();
    dispatch(parsed.op).await.unwrap();

    assert!(!tmp.path().join("alice").exists(), "pod tree removed");
    for gone in ["alice.acl", "alice.meta", "alice.meta.meta.json"] {
        assert!(!tmp.path().join(gone).exists(), "{gone} removed");
    }
    assert!(tmp.path().join("bob/profile/card").is_file(), "sibling pod");
    assert!(tmp.path().join("bob.acl").is_file());
    assert!(tmp.path().join("root.txt").is_file(), "root files survive");
}

#[tokio::test]
async fn unknown_pod_is_an_error_not_a_quiet_no_op() {
    let tmp = make_root();
    let parsed = Harness::try_parse_from([
        "t",
        "account",
        "delete",
        "nobody",
        "--yes",
        "--root",
        tmp.path().to_str().unwrap(),
    ])
    .unwrap();
    let err = dispatch(parsed.op).await.unwrap_err().to_string();
    assert!(err.contains("no such pod"), "{err}");
    assert!(tmp.path().join("alice").is_dir());
}

#[tokio::test]
async fn confirmation_is_required_without_yes() {
    let tmp = make_root();
    let a = args(tmp.path(), "alice", false);
    let err = run_account_delete(&a, &mut Scripted(vec![]))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("stdin closed"), "{err}");
    let err = run_account_delete(&a, &mut Scripted(vec![Some("nope".into())]))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("did not match"), "{err}");
    assert!(tmp.path().join("alice/profile/card").is_file());

    run_account_delete(&a, &mut Scripted(vec![Some(" alice \n".into())]))
        .await
        .unwrap();
    assert!(!tmp.path().join("alice").exists());
}

#[tokio::test]
async fn unsafe_names_and_non_pods_are_refused() {
    let tmp = make_root();
    for bad in [
        "",
        ".",
        "..",
        "../alice",
        "a/b",
        ".well-known",
        "alice\\x",
        "profile",
    ] {
        let err = run_account_delete(&args(tmp.path(), bad, true), &mut Scripted(vec![]))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("invalid pod name") || err.contains("no such pod"),
            "{bad:?}: {err}"
        );
    }
    // `profile` is a root-level container name, not a pod, even where
    // `profile/card` exists (a single-pod layout).
    std::fs::create_dir_all(tmp.path().join("profile")).unwrap();
    std::fs::write(tmp.path().join("profile/card"), "<html/>").unwrap();
    let err = run_account_delete(&args(tmp.path(), "profile", true), &mut Scripted(vec![]))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("not a pod"), "{err}");
    assert!(tmp.path().join("profile/card").is_file(), "survives");

    // A directory with no WebID profile is not a pod.
    std::fs::create_dir(tmp.path().join("plain")).unwrap();
    let err = run_account_delete(&args(tmp.path(), "plain", true), &mut Scripted(vec![]))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("not a pod"), "{err}");
    assert!(tmp.path().join("plain").is_dir());

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(tmp.path().join("bob"), tmp.path().join("link")).unwrap();
        let err = run_account_delete(&args(tmp.path(), "link", true), &mut Scripted(vec![]))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a pod directory"), "{err}");
        assert!(tmp.path().join("bob/profile/card").is_file());
    }
}

#[tokio::test]
async fn missing_root_is_an_error() {
    let tmp = tempfile::TempDir::new().unwrap();
    let err = run_account_delete(
        &args(&tmp.path().join("absent"), "alice", true),
        &mut Scripted(vec![]),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("storage root does not exist"), "{err}");
}

#[actix_web::test]
async fn a_deleted_pod_name_stays_reserved_against_re_registration() {
    use actix_web::test;
    use solid_pod_rs::storage::memory::MemoryBackend;
    use solid_pod_rs_server::{build_app, AppState};

    let tmp = make_root();
    run_account_delete(&args(tmp.path(), "alice", true), &mut Scripted(vec![]))
        .await
        .unwrap();
    assert!(solid_pod_rs_server::cli::pod_name_is_tombstoned(
        tmp.path(),
        "ALICE"
    ));
    assert!(!solid_pod_rs_server::cli::pod_name_is_tombstoned(
        tmp.path(),
        "bob"
    ));

    let mut state = AppState::new(std::sync::Arc::new(MemoryBackend::new()));
    state.nodeinfo.open_registrations = true;
    state.data_root = Some(tmp.path().to_path_buf());
    let app = test::init_service(build_app(state)).await;
    let create = |name: &str| {
        test::TestRequest::post()
            .uri("/.pods")
            .set_json(serde_json::json!({ "name": name }))
            .to_request()
    };
    let rsp = test::call_service(&app, create("alice")).await;
    assert_eq!(rsp.status().as_u16(), 409, "a deleted name is reserved");
    let rsp = test::call_service(&app, create("carol")).await;
    assert_eq!(rsp.status().as_u16(), 201, "other names are unaffected");

    // The operator releases the name by removing its tombstone.
    std::fs::remove_file(tmp.path().join(".server/deleted-pods/alice")).unwrap();
    assert!(!solid_pod_rs_server::cli::pod_name_is_tombstoned(
        tmp.path(),
        "alice"
    ));
}

#[cfg(unix)]
#[test]
fn an_unreadable_tombstone_means_reserved_not_free() {
    let tmp = tempfile::TempDir::new().unwrap();
    // `.server` is a file, so looking inside it fails with something other
    // than "not found": the name must be treated as reserved.
    std::fs::write(tmp.path().join(".server"), "x").unwrap();
    assert!(solid_pod_rs_server::cli::pod_name_is_tombstoned(
        tmp.path(),
        "alice"
    ));
    // Only a clean "not found" frees a name.
    let clean = tempfile::TempDir::new().unwrap();
    assert!(!solid_pod_rs_server::cli::pod_name_is_tombstoned(
        clean.path(),
        "alice"
    ));
}
