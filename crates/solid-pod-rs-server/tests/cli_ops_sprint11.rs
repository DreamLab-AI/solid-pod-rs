//! Sprint 11 — operator CLI subcommand coverage (rows 138, 163, 168).
//!
//! Drives the `cli::run_*` surface directly; the binary wrapper just
//! forwards to the same functions and needs no separate harness.

use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use solid_pod_rs_idp::{
    InMemoryInviteStore, InMemoryUserStore, InviteStore, User, UserStore, UserStoreError,
};
use solid_pod_rs_server::cli::{
    run_account_delete, run_invite_create, run_quota_reconcile, AccountDeleteArgs,
    InviteCreateArgs, Prompt, QuotaReconcileArgs,
};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// row 138 — quota reconcile
// ---------------------------------------------------------------------------

#[cfg(feature = "quota")]
#[tokio::test]
async fn cli_quota_reconcile_calls_quota_policy() {
    use solid_pod_rs::quota::{FsQuotaStore, QuotaPolicy};
    use tokio::fs;

    let tmp = TempDir::new().unwrap();
    let pod_dir = tmp.path().join("alice");
    fs::create_dir_all(&pod_dir).await.unwrap();
    fs::write(pod_dir.join("a.txt"), [0u8; 128]).await.unwrap();
    fs::write(pod_dir.join("b.txt"), [0u8; 256]).await.unwrap();

    let args = QuotaReconcileArgs {
        pod_id: Some("alice".into()),
        all: false,
        root: tmp.path().to_path_buf(),
        default_limit: 10_000,
    };

    let outcomes = run_quota_reconcile(&args).await.unwrap();
    assert_eq!(outcomes.len(), 1, "expected one pod outcome");
    assert_eq!(outcomes[0].pod, "alice");
    assert_eq!(outcomes[0].used_bytes, 128 + 256);
    assert_eq!(outcomes[0].limit_bytes, 10_000);

    // Sidecar must be on disk with the recomputed bytes (parity with
    // JSS bin/jss.js quota reconcile post-condition).
    let store = FsQuotaStore::new(tmp.path().to_path_buf(), 10_000);
    let got = store.usage("alice").await.expect("sidecar written");
    assert_eq!(got.used_bytes, 128 + 256);
    assert_eq!(got.limit_bytes, 10_000);
}

#[cfg(feature = "quota")]
#[tokio::test]
async fn cli_quota_reconcile_all_iterates_pods() {
    use tokio::fs;

    let tmp = TempDir::new().unwrap();
    for (pod, size) in [("alice", 100usize), ("bob", 500usize), ("carol", 1)] {
        let pd = tmp.path().join(pod);
        fs::create_dir_all(&pd).await.unwrap();
        fs::write(pd.join("x"), vec![0u8; size]).await.unwrap();
    }

    let args = QuotaReconcileArgs {
        pod_id: None,
        all: true,
        root: tmp.path().to_path_buf(),
        default_limit: 10_000,
    };

    let outcomes = run_quota_reconcile(&args).await.unwrap();
    let mut pods: Vec<_> = outcomes.iter().map(|o| o.pod.clone()).collect();
    pods.sort();
    assert_eq!(pods, vec!["alice", "bob", "carol"]);
    let alice = outcomes
        .iter()
        .find(|o| o.pod == "alice")
        .expect("alice outcome present");
    assert_eq!(alice.used_bytes, 100);
    let bob = outcomes
        .iter()
        .find(|o| o.pod == "bob")
        .expect("bob outcome present");
    assert_eq!(bob.used_bytes, 500);
}

// ---------------------------------------------------------------------------
// row 168 — account delete
// ---------------------------------------------------------------------------

/// Scripted [`Prompt`] that dequeues pre-seeded answers. Returns
/// `Ok(None)` (EOF) once the queue is empty.
struct ScriptedPrompt {
    answers: Vec<Option<String>>,
    asked: Arc<Mutex<Vec<String>>>,
}

impl ScriptedPrompt {
    fn new(answers: Vec<Option<String>>) -> Self {
        Self {
            answers,
            asked: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn asked(&self) -> Vec<String> {
        self.asked.lock().clone()
    }
}

impl Prompt for ScriptedPrompt {
    fn ask(&mut self, prompt: &str) -> std::io::Result<Option<String>> {
        self.asked.lock().push(prompt.to_string());
        if self.answers.is_empty() {
            Ok(None)
        } else {
            Ok(self.answers.remove(0))
        }
    }
}

/// Recording user store — exposes `deletes` so tests can assert on
/// the exact id that was forwarded to the store.
#[derive(Default)]
struct RecordingUserStore {
    inner: InMemoryUserStore,
    deletes: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl UserStore for RecordingUserStore {
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, UserStoreError> {
        self.inner.find_by_email(email).await
    }

    async fn find_by_id(&self, id: &str) -> Result<Option<User>, UserStoreError> {
        self.inner.find_by_id(id).await
    }

    async fn delete(&self, id: &str) -> Result<bool, UserStoreError> {
        self.deletes.lock().push(id.to_string());
        self.inner.delete(id).await
    }
}

#[tokio::test]
async fn cli_account_delete_requires_confirmation_without_yes_flag() {
    let store = RecordingUserStore::default();
    store
        .inner
        .insert_user(
            "u-42",
            "alice@example.com",
            "https://alice.example/profile#me",
            None,
            "pw",
        )
        .unwrap();

    // EOF — stdin closed with no answer.
    let mut prompt = ScriptedPrompt::new(vec![]);
    let args = AccountDeleteArgs {
        user_id: "u-42".into(),
        yes: false,
    };

    let err = run_account_delete(&args, &store, &mut prompt)
        .await
        .expect_err("must not delete without confirmation");
    let msg = format!("{err}");
    assert!(
        msg.contains("stdin closed") || msg.contains("confirmation"),
        "unexpected error: {msg}"
    );
    assert!(
        !prompt.asked().is_empty(),
        "should have emitted at least one confirmation prompt"
    );
    assert_eq!(
        store.deletes.lock().len(),
        0,
        "store.delete must not run without confirmation"
    );
    // Also: the wrong confirmation string rejects.
    let mut prompt2 = ScriptedPrompt::new(vec![Some("nope".into())]);
    let err2 = run_account_delete(&args, &store, &mut prompt2)
        .await
        .expect_err("wrong answer must abort");
    assert!(format!("{err2}").contains("did not match"));
}

#[tokio::test]
async fn cli_account_delete_with_yes_removes_account() {
    let store = RecordingUserStore::default();
    store
        .inner
        .insert_user(
            "u-99",
            "zed@example.com",
            "https://zed.example/profile#me",
            None,
            "pw",
        )
        .unwrap();

    let mut prompt = ScriptedPrompt::new(vec![]);
    let args = AccountDeleteArgs {
        user_id: "u-99".into(),
        yes: true,
    };

    let deleted = run_account_delete(&args, &store, &mut prompt)
        .await
        .unwrap();
    assert!(deleted, "first delete returns true");
    assert_eq!(store.deletes.lock().as_slice(), &["u-99".to_string()]);
    assert!(
        prompt.asked().is_empty(),
        "`--yes` must skip the interactive prompt"
    );
    assert!(store.find_by_id("u-99").await.unwrap().is_none());

    // Idempotent: second call is a no-op returning false.
    let deleted_again = run_account_delete(&args, &store, &mut prompt)
        .await
        .unwrap();
    assert!(!deleted_again);
}

// ---------------------------------------------------------------------------
// row 163 — invite create
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cli_invite_create_stores_max_uses() {
    let store = InMemoryInviteStore::new();
    let args = InviteCreateArgs {
        uses: Some(3),
        expires_in: None,
        base_url: "https://pod.test".into(),
    };

    let (invite, _url) = run_invite_create(&args, &store).await.unwrap();
    assert_eq!(invite.max_uses, Some(3));
    assert!(invite.expires_at.is_none());
    let snapshot = store.snapshot();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].max_uses, Some(3));
    let got = store.get(&invite.token).await.unwrap().unwrap();
    assert_eq!(got.max_uses, Some(3));
}

#[tokio::test]
async fn cli_invite_create_without_uses_stores_none() {
    let store = InMemoryInviteStore::new();
    let args = InviteCreateArgs {
        uses: None,
        expires_in: None,
        base_url: "https://pod.test".into(),
    };

    let (invite, _url) = run_invite_create(&args, &store).await.unwrap();
    assert_eq!(invite.max_uses, None);
    let got = store.get(&invite.token).await.unwrap().unwrap();
    assert_eq!(got.max_uses, None);
}

#[tokio::test]
async fn cli_invite_create_prints_token_url() {
    let store = InMemoryInviteStore::new();
    let args = InviteCreateArgs {
        uses: Some(1),
        expires_in: Some("7d".into()),
        base_url: "https://pod.test/".into(),
    };

    let (invite, url) = run_invite_create(&args, &store).await.unwrap();
    assert_eq!(invite.token.len(), 43, "32 bytes => 43 chars base64url");
    assert!(url.starts_with("https://pod.test/invite?token="));
    assert!(url.ends_with(&invite.token));
    assert!(invite.expires_at.is_some(), "7d must parse and stamp");

    // Bad duration surfaces a clear error.
    let bad = InviteCreateArgs {
        uses: None,
        expires_in: Some("1y".into()),
        base_url: "https://pod.test".into(),
    };
    let err = run_invite_create(&bad, &store)
        .await
        .expect_err("1y is rejected");
    assert!(format!("{err}").contains("--expires-in"));
}
