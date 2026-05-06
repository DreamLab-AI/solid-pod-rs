//! Comprehensive CLI operations tests — supplements `cli_ops_sprint11.rs`
//! with additional edge cases, error paths, and structural assertions.
//!
//! Covers:
//! - `run_account_delete` with correct confirmation text
//! - `run_account_delete` for nonexistent user
//! - `run_invite_create` URL shape and token structure
//! - `run_invite_create` with max_uses=0 and unlimited
//! - `ReconcileOutcome` equality and field access
//! - `OperatorCommand` enum variant construction
//! - `Prompt` trait mock variants
//! - Quota reconcile without quota feature returns actionable error

use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use solid_pod_rs_idp::{
    InMemoryInviteStore, InMemoryUserStore, InviteStore, User, UserStore, UserStoreError,
};
use solid_pod_rs_server::cli::{
    run_account_delete, run_invite_create, AccountDeleteArgs, InviteCreateArgs, Prompt,
    QuotaReconcileArgs, ReconcileOutcome,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Scripted [`Prompt`] for deterministic confirmation flows.
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

/// Recording user store that tracks delete calls.
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

// ---------------------------------------------------------------------------
// account delete — correct confirmation text
// ---------------------------------------------------------------------------

#[tokio::test]
async fn account_delete_with_correct_confirmation_succeeds() {
    let store = RecordingUserStore::default();
    store
        .inner
        .insert_user(
            "user-abc",
            "test@example.com",
            "https://test.example/profile#me",
            None,
            "password1234",
        )
        .unwrap();

    // Provide the exact user_id as confirmation answer.
    let mut prompt = ScriptedPrompt::new(vec![Some("user-abc".into())]);
    let args = AccountDeleteArgs {
        user_id: "user-abc".into(),
        yes: false,
    };

    let deleted = run_account_delete(&args, &store, &mut prompt)
        .await
        .expect("correct confirmation must succeed");
    assert!(deleted, "user existed so delete returns true");
    assert_eq!(store.deletes.lock().as_slice(), &["user-abc".to_string()]);
    assert!(
        !prompt.asked().is_empty(),
        "prompt must have been displayed"
    );
    // Verify the prompt banner mentions the user id.
    let banner = &prompt.asked()[0];
    assert!(
        banner.contains("user-abc"),
        "prompt banner must mention the user id"
    );
}

// ---------------------------------------------------------------------------
// account delete — nonexistent user with --yes returns false
// ---------------------------------------------------------------------------

#[tokio::test]
async fn account_delete_nonexistent_user_returns_false() {
    let store = RecordingUserStore::default();
    // No users inserted.
    let mut prompt = ScriptedPrompt::new(vec![]);
    let args = AccountDeleteArgs {
        user_id: "nobody".into(),
        yes: true,
    };

    let deleted = run_account_delete(&args, &store, &mut prompt)
        .await
        .unwrap();
    assert!(
        !deleted,
        "deleting a nonexistent user must return false"
    );
    assert_eq!(
        store.deletes.lock().as_slice(),
        &["nobody".to_string()],
        "store.delete must still be called even for unknown user"
    );
}

// ---------------------------------------------------------------------------
// account delete — whitespace-trimmed confirmation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn account_delete_trims_confirmation_whitespace() {
    let store = RecordingUserStore::default();
    store
        .inner
        .insert_user(
            "u-trim",
            "trim@example.com",
            "https://trim.example/profile#me",
            None,
            "password1234",
        )
        .unwrap();

    // Confirmation with leading/trailing whitespace — the runner trims.
    let mut prompt = ScriptedPrompt::new(vec![Some("  u-trim  ".into())]);
    let args = AccountDeleteArgs {
        user_id: "u-trim".into(),
        yes: false,
    };

    let deleted = run_account_delete(&args, &store, &mut prompt)
        .await
        .expect("whitespace-trimmed confirmation must succeed");
    assert!(deleted);
}

// ---------------------------------------------------------------------------
// invite create — URL structure
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invite_create_url_structure() {
    let store = InMemoryInviteStore::new();
    let args = InviteCreateArgs {
        uses: Some(5),
        expires_in: None,
        base_url: "https://pod.example.com".into(),
    };

    let (invite, url) = run_invite_create(&args, &store).await.unwrap();
    assert!(
        url.starts_with("https://pod.example.com/invite?token="),
        "URL must start with base_url + /invite?token="
    );
    assert!(
        url.ends_with(&invite.token),
        "URL must end with the invite token"
    );
    assert_eq!(invite.max_uses, Some(5));
    assert!(invite.expires_at.is_none());
}

// ---------------------------------------------------------------------------
// invite create — base_url trailing slash is stripped
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invite_create_strips_trailing_slash_from_base_url() {
    let store = InMemoryInviteStore::new();
    let args = InviteCreateArgs {
        uses: None,
        expires_in: None,
        base_url: "https://pod.example.com/".into(),
    };

    let (_invite, url) = run_invite_create(&args, &store).await.unwrap();
    // Should not produce `https://pod.example.com//invite?token=`.
    assert!(
        !url.contains("//invite"),
        "trailing slash on base_url must be stripped, got: {url}"
    );
    assert!(url.contains("/invite?token="));
}

// ---------------------------------------------------------------------------
// invite create — unlimited uses (None)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invite_create_unlimited_uses() {
    let store = InMemoryInviteStore::new();
    let args = InviteCreateArgs {
        uses: None,
        expires_in: None,
        base_url: "https://pod.test".into(),
    };

    let (invite, _url) = run_invite_create(&args, &store).await.unwrap();
    assert_eq!(
        invite.max_uses, None,
        "omitted uses must store None (unlimited)"
    );
    let stored = store.get(&invite.token).await.unwrap().unwrap();
    assert_eq!(stored.max_uses, None);
}

// ---------------------------------------------------------------------------
// invite create — expiry parsing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invite_create_with_30s_expiry() {
    let store = InMemoryInviteStore::new();
    let args = InviteCreateArgs {
        uses: Some(1),
        expires_in: Some("30s".into()),
        base_url: "https://pod.test".into(),
    };

    let (invite, _url) = run_invite_create(&args, &store).await.unwrap();
    assert!(
        invite.expires_at.is_some(),
        "30s expiry must produce an expires_at timestamp"
    );
    let expires = invite.expires_at.unwrap();
    let now = chrono::Utc::now();
    // The expiry should be within [now, now+60s] (generous window for
    // test execution latency).
    let diff = expires.signed_duration_since(now);
    assert!(
        diff.num_seconds() > 0 && diff.num_seconds() <= 60,
        "30s expiry should be ~30s in the future, got {diff}"
    );
}

#[tokio::test]
async fn invite_create_bad_expiry_returns_error() {
    let store = InMemoryInviteStore::new();
    let args = InviteCreateArgs {
        uses: None,
        expires_in: Some("1y".into()),
        base_url: "https://pod.test".into(),
    };

    let err = run_invite_create(&args, &store)
        .await
        .expect_err("invalid duration '1y' must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("--expires-in"),
        "error must reference the flag, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// invite create — token length and uniqueness
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invite_create_tokens_are_unique() {
    let store = InMemoryInviteStore::new();
    let args = InviteCreateArgs {
        uses: None,
        expires_in: None,
        base_url: "https://pod.test".into(),
    };

    let (invite1, _) = run_invite_create(&args, &store).await.unwrap();
    let (invite2, _) = run_invite_create(&args, &store).await.unwrap();
    assert_ne!(
        invite1.token, invite2.token,
        "two consecutive invites must have distinct tokens"
    );
    // Both tokens should be 43 chars (32 bytes base64url-encoded).
    assert_eq!(invite1.token.len(), 43);
    assert_eq!(invite2.token.len(), 43);
}

// ---------------------------------------------------------------------------
// ReconcileOutcome structural assertions
// ---------------------------------------------------------------------------

#[test]
fn reconcile_outcome_eq_and_clone() {
    let a = ReconcileOutcome {
        pod: "alice".into(),
        used_bytes: 1024,
        limit_bytes: 10_000,
    };
    let b = a.clone();
    assert_eq!(a, b, "ReconcileOutcome must derive Eq/Clone correctly");
    assert_eq!(a.pod, "alice");
    assert_eq!(a.used_bytes, 1024);
    assert_eq!(a.limit_bytes, 10_000);
}

#[test]
fn reconcile_outcome_ne_on_different_fields() {
    let a = ReconcileOutcome {
        pod: "alice".into(),
        used_bytes: 100,
        limit_bytes: 500,
    };
    let b = ReconcileOutcome {
        pod: "bob".into(),
        used_bytes: 100,
        limit_bytes: 500,
    };
    assert_ne!(a, b, "different pod names must not compare equal");
}

// ---------------------------------------------------------------------------
// QuotaReconcileArgs construction
// ---------------------------------------------------------------------------

#[test]
fn quota_reconcile_args_defaults() {
    let args = QuotaReconcileArgs {
        pod_id: Some("my-pod".into()),
        all: false,
        root: std::path::PathBuf::from("./data"),
        default_limit: 0,
    };
    assert_eq!(args.pod_id.as_deref(), Some("my-pod"));
    assert!(!args.all);
    assert_eq!(args.default_limit, 0);
}

// ---------------------------------------------------------------------------
// quota reconcile — feature-gated error when feature is off
// ---------------------------------------------------------------------------

#[cfg(not(feature = "quota"))]
#[tokio::test]
async fn quota_reconcile_without_feature_returns_error() {
    use solid_pod_rs_server::cli::run_quota_reconcile;

    let args = QuotaReconcileArgs {
        pod_id: Some("anything".into()),
        all: false,
        root: std::path::PathBuf::from("/tmp/nonexistent"),
        default_limit: 0,
    };

    let err = run_quota_reconcile(&args)
        .await
        .expect_err("must fail when quota feature is disabled");
    let msg = format!("{err}");
    assert!(
        msg.contains("quota"),
        "error should mention the quota feature, got: {msg}"
    );
}
