//! Parity row 135: `account create/delete/list/export` over a durable store.
//!
//! Properties, each with the test that fails if it is violated:
//!
//! * `account delete` deletes a real, persisted account (it used to run
//!   against a throwaway store and could delete nothing);
//! * a name the server serves itself is refused before any password is read,
//!   and nothing is written;
//! * the password is read from the prompt (stdin), is stored only as an
//!   Argon2id hash, and never appears in `list` or `export`.

use solid_pod_rs_idp::UserStore;
use solid_pod_rs_server::cli::{
    run_account_command, run_account_create, run_account_delete, AccountCommand, AccountCreateArgs,
    AccountDeleteArgs, AccountExportArgs, FileUserStore, Prompt,
};

struct Scripted(Vec<Option<String>>, usize);

impl Prompt for Scripted {
    fn ask(&mut self, _prompt: &str) -> std::io::Result<Option<String>> {
        self.1 += 1;
        Ok(if self.0.is_empty() {
            None
        } else {
            self.0.remove(0)
        })
    }
}

fn args(user: &str) -> AccountCreateArgs {
    AccountCreateArgs {
        username: user.to_string(),
        email: format!("{user}@example.com"),
        name: Some("Name".into()),
        base_url: "https://pod.example".into(),
    }
}

#[tokio::test]
async fn account_delete_removes_a_persisted_account() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileUserStore::new(dir.path());
    let mut pw = Scripted(vec![Some("correct horse".into())], 0);
    let user = run_account_create(&args("alice"), &store, &mut pw)
        .await
        .unwrap();
    assert_eq!(pw.1, 1, "the password was read from the prompt");

    // A second process: the account is there, and `account delete` removes it.
    let again = FileUserStore::new(dir.path());
    assert!(again.find_by_id(&user.id).await.unwrap().is_some());
    let mut none = Scripted(vec![], 0);
    let gone = run_account_delete(
        &AccountDeleteArgs {
            user_id: user.id.clone(),
            yes: true,
        },
        &again,
        &mut none,
    )
    .await
    .unwrap();
    assert!(gone);
    assert!(FileUserStore::new(dir.path())
        .find_by_id(&user.id)
        .await
        .unwrap()
        .is_none());

    // Through the command dispatcher, an unknown id is an error, not a quiet success.
    let err = run_account_command(
        dir.path(),
        AccountCommand::Delete(AccountDeleteArgs {
            user_id: user.id,
            yes: true,
        }),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("no such user"), "{err}");
}

#[tokio::test]
async fn a_reserved_name_is_refused_before_the_password_is_read() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileUserStore::new(dir.path());
    for bad in ["remotestorage", "Storage", "api", "pods", "x y", ""] {
        let mut pw = Scripted(vec![Some("correct horse".into())], 0);
        let err = run_account_create(&args(bad), &store, &mut pw)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("not a valid account name"),
            "{bad}: {err}"
        );
        assert_eq!(pw.1, 0, "{bad}: a secret was requested for a refused name");
    }
    assert!(!store.path().exists(), "nothing written");
}

#[tokio::test]
async fn no_password_on_stdin_creates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileUserStore::new(dir.path());
    let mut pw = Scripted(vec![], 0);
    assert!(run_account_create(&args("bob"), &store, &mut pw)
        .await
        .is_err());
    assert!(!store.path().exists());
}

#[tokio::test]
async fn list_and_export_work_and_never_leak_the_hash() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileUserStore::new(dir.path());
    let mut pw = Scripted(vec![Some("correct horse".into())], 0);
    let user = run_account_create(&args("carol"), &store, &mut pw)
        .await
        .unwrap();
    run_account_command(dir.path(), AccountCommand::List)
        .await
        .unwrap();
    run_account_command(
        dir.path(),
        AccountCommand::Export(AccountExportArgs {
            user_id: user.id.clone(),
        }),
    )
    .await
    .unwrap();
    let exported = store.export(&user.id).await.unwrap().unwrap().to_string();
    assert!(!exported.contains("argon2") && !exported.contains("correct horse"));
    // The password is on disk only as an Argon2id PHC string.
    let raw = std::fs::read_to_string(store.path()).unwrap();
    assert!(raw.contains("$argon2id$") && !raw.contains("correct horse"));
    let err = run_account_command(
        dir.path(),
        AccountCommand::Export(AccountExportArgs {
            user_id: "nobody".into(),
        }),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("no such user"));
}
