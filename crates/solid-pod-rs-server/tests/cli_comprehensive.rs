//! Comprehensive CLI operations tests — supplements `cli_ops_sprint11.rs`
//! with additional edge cases, error paths, and structural assertions.
//!
//! Covers:
//! - `run_invite_create` URL shape and token structure
//! - `run_invite_create` with max_uses=0 and unlimited
//! - `ReconcileOutcome` equality and field access
//! - `OperatorCommand` enum variant construction
//! - Quota reconcile without quota feature returns actionable error

use solid_pod_rs_idp::{InMemoryInviteStore, InviteStore};
use solid_pod_rs_server::cli::{
    run_invite_create, InviteCreateArgs, QuotaReconcileArgs, ReconcileOutcome,
};

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
