//! ADR-2004 acceptance corpus — provenance receipts.
//!
//! The gap these tests close: the resource write succeeded, then git marking
//! and anchoring ran afterwards, and a marking failure was only ever logged.
//! The caller received `201 Created` whether or not any provenance existed, so
//! "stored" and "stored and provably marked" were indistinguishable from
//! outside the process.
//!
//! [`ProvenanceReceipt`] makes the three tiers distinct results:
//! resource-stored, local-mark-committed, anchor-confirmed — with a fourth,
//! anchor-submitted, for an anchor that exists but is not yet confirmed.
//!
//! These tests drive the pure composition surface with stub markers/anchorers,
//! so they run under the crate's default features (no git binary, no network).
//! The git-backed end of the same contract is covered by the server crate's
//! `git_marks` integration test.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;

use solid_pod_rs::provenance::{
    AnchorPolicy, BlockAnchorer, BlockTrailAnchor, GitMark, GitMarker, ProvenanceError,
    ProvenanceLog, ProvenanceReceipt, ProvenanceSkip, ProvenanceStage, WriteRecord,
};

// ---------------------------------------------------------------------------
// Stubs
// ---------------------------------------------------------------------------

/// A marker that either commits or fails, and counts its invocations.
struct StubMarker {
    fail: Option<String>,
    calls: AtomicUsize,
}

impl StubMarker {
    fn ok() -> Self {
        Self {
            fail: None,
            calls: AtomicUsize::new(0),
        }
    }
    fn failing(msg: &str) -> Self {
        Self {
            fail: Some(msg.to_string()),
            calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait(?Send)]
impl GitMarker for StubMarker {
    async fn mark_write(
        &self,
        _repo: &Path,
        path: &str,
        _agent_did: &str,
        _message: &str,
    ) -> Result<GitMark, ProvenanceError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(msg) = &self.fail {
            return Err(ProvenanceError::Git(msg.clone()));
        }
        Ok(GitMark {
            commit_sha: format!("{:040x}", path.len()),
            repo: "pod".to_string(),
            branch: "main".to_string(),
            parent: None,
        })
    }

    async fn head(&self, _repo: &Path) -> Result<Option<String>, ProvenanceError> {
        Ok(None)
    }
}

/// An anchorer that succeeds (confirmed or unconfirmed) or fails.
struct StubAnchorer {
    outcome: AnchorOutcome,
}

enum AnchorOutcome {
    Confirmed(u64),
    Unconfirmed,
    Failed(String),
}

#[async_trait(?Send)]
impl BlockAnchorer for StubAnchorer {
    async fn anchor(
        &self,
        ticker: &str,
        state_hash: &str,
        network: &str,
    ) -> Result<BlockTrailAnchor, ProvenanceError> {
        let blockheight = match &self.outcome {
            AnchorOutcome::Failed(m) => return Err(ProvenanceError::Anchor(m.clone())),
            AnchorOutcome::Confirmed(h) => Some(*h),
            AnchorOutcome::Unconfirmed => None,
        };
        Ok(BlockTrailAnchor {
            ticker: ticker.to_string(),
            state_hash: state_hash.to_string(),
            txid: "f".repeat(64),
            vout: 0,
            address: "bcrt1qexample".to_string(),
            network: network.to_string(),
            blockheight,
            state_strings: vec![state_hash.to_string()],
            pubkey: None,
        })
    }

    async fn verify(&self, _anchor: &BlockTrailAnchor) -> Result<bool, ProvenanceError> {
        Ok(true)
    }
}

fn record_for(policy: AnchorPolicy, high_value: bool) -> WriteRecord<'static> {
    WriteRecord {
        repo: Path::new("/tmp/pod"),
        path: "notes/today.ttl",
        agent_did: "did:nostr:alice",
        message: "PUT",
        policy,
        high_value,
        ticker: "TRAIL",
        network: "testnet4",
        created: 1_757_000_000,
    }
}

// ---------------------------------------------------------------------------
// The three tiers are distinct results.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn default_build_reaches_local_mark_committed() {
    // The default pod: git-mark always, no anchorer wired. The strongest claim
    // available is a local commit — NOT an anchor.
    let marker = Arc::new(StubMarker::ok());
    let log = ProvenanceLog::new(marker.clone());
    let receipt = log
        .record_receipt(record_for(AnchorPolicy::Never, false))
        .await;

    assert_eq!(
        marker.calls.load(Ordering::SeqCst),
        1,
        "the cheap tier runs exactly once per write"
    );

    assert_eq!(receipt.stage(), ProvenanceStage::LocalMarkCommitted);
    assert!(!receipt.has_failure());
    assert!(receipt.commit_sha().is_some());
    assert!(receipt.anchor.is_none());
    assert_eq!(receipt.resource, "/notes/today.ttl");
    assert_eq!(receipt.summary(), "local-mark-committed");
}

#[tokio::test]
async fn a_confirmed_anchor_is_a_distinct_stronger_result() {
    let log = ProvenanceLog::with_anchorer(
        Arc::new(StubMarker::ok()),
        Arc::new(StubAnchorer {
            outcome: AnchorOutcome::Confirmed(880_001),
        }),
    );
    let receipt = log
        .record_receipt(record_for(AnchorPolicy::Always, false))
        .await;

    assert_eq!(receipt.stage(), ProvenanceStage::AnchorConfirmed);
    assert!(!receipt.has_failure());
    assert_eq!(receipt.anchor.as_ref().unwrap().blockheight, Some(880_001));
    // Ordering is meaningful: a confirmed anchor outranks a local commit.
    assert!(receipt.stage() > ProvenanceStage::LocalMarkCommitted);
    assert!(ProvenanceStage::LocalMarkCommitted > ProvenanceStage::ResourceStored);
}

#[tokio::test]
async fn an_unconfirmed_anchor_is_not_reported_as_confirmed() {
    // An anchoring transaction with no block height can still be replaced, so
    // claiming "anchor-confirmed" for it would overstate the provenance.
    let log = ProvenanceLog::with_anchorer(
        Arc::new(StubMarker::ok()),
        Arc::new(StubAnchorer {
            outcome: AnchorOutcome::Unconfirmed,
        }),
    );
    let receipt = log
        .record_receipt(record_for(AnchorPolicy::Always, false))
        .await;

    assert_eq!(receipt.stage(), ProvenanceStage::AnchorSubmitted);
    assert!(receipt.stage() < ProvenanceStage::AnchorConfirmed);
    assert!(receipt.anchor.is_some());
}

// ---------------------------------------------------------------------------
// Failed marking is surfaced, typed.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_failed_mark_is_surfaced_not_swallowed() {
    // This is the finding: the resource is stored, the mark failed, and the
    // caller must be able to tell.
    let log = ProvenanceLog::new(Arc::new(StubMarker::failing("git binary not found")));
    let receipt = log
        .record_receipt(record_for(AnchorPolicy::Never, false))
        .await;

    assert_eq!(
        receipt.stage(),
        ProvenanceStage::ResourceStored,
        "a failed mark must report the weakest tier, not the one it aimed for"
    );
    assert!(receipt.has_failure());
    assert!(receipt.mark.is_none());
    assert!(receipt.commit_sha().is_none());
    let err = receipt.mark_error.as_deref().expect("typed mark error");
    assert!(err.contains("git binary not found"), "got {err}");
    // The summary is what rides in the response header.
    assert!(receipt.summary().starts_with("resource-stored"));
    assert!(receipt.summary().contains("mark-error="));
}

#[tokio::test]
async fn a_failed_anchor_never_suppresses_a_successful_mark() {
    let log = ProvenanceLog::with_anchorer(
        Arc::new(StubMarker::ok()),
        Arc::new(StubAnchorer {
            outcome: AnchorOutcome::Failed("mempool unreachable".into()),
        }),
    );
    let receipt = log
        .record_receipt(record_for(AnchorPolicy::Always, false))
        .await;

    // The mark stands...
    assert_eq!(receipt.stage(), ProvenanceStage::LocalMarkCommitted);
    assert!(receipt.commit_sha().is_some());
    assert!(receipt.mark_error.is_none());
    // ...and the anchor failure is reported alongside it rather than
    // downgrading the result to a plain "marked" with no explanation.
    assert!(receipt.has_failure());
    assert!(receipt
        .anchor_error
        .as_deref()
        .unwrap()
        .contains("mempool unreachable"));
    assert!(receipt.summary().contains("anchor-error="));
}

#[tokio::test]
async fn an_anchor_policy_with_no_anchorer_is_reported_not_silently_degraded() {
    // Previously this degraded to git-mark-only "silently". The receipt says
    // so, so an operator who configured `Always` learns it is not in effect.
    let log = ProvenanceLog::new(Arc::new(StubMarker::ok()));
    let receipt = log
        .record_receipt(record_for(AnchorPolicy::Always, false))
        .await;

    assert_eq!(receipt.stage(), ProvenanceStage::LocalMarkCommitted);
    assert!(receipt.has_failure());
    assert!(receipt
        .anchor_error
        .as_deref()
        .unwrap()
        .contains("no anchorer is configured"));
}

#[tokio::test]
async fn the_anchor_is_not_attempted_when_the_policy_does_not_ask_for_it() {
    for (policy, high_value) in [
        (AnchorPolicy::Never, true),
        (AnchorPolicy::Epoch, true),
        (AnchorPolicy::HighValue, false),
    ] {
        let log = ProvenanceLog::with_anchorer(
            Arc::new(StubMarker::ok()),
            Arc::new(StubAnchorer {
                outcome: AnchorOutcome::Failed("must not be called".into()),
            }),
        );
        let receipt = log.record_receipt(record_for(policy, high_value)).await;
        assert_eq!(
            receipt.stage(),
            ProvenanceStage::LocalMarkCommitted,
            "policy {policy:?} (high_value={high_value}) must not anchor inline"
        );
        assert!(
            !receipt.has_failure(),
            "policy {policy:?} must not report an anchor failure it never attempted"
        );
    }
}

#[tokio::test]
async fn high_value_anchors_only_when_flagged() {
    let log = ProvenanceLog::with_anchorer(
        Arc::new(StubMarker::ok()),
        Arc::new(StubAnchorer {
            outcome: AnchorOutcome::Confirmed(900_000),
        }),
    );
    let flagged = log
        .record_receipt(record_for(AnchorPolicy::HighValue, true))
        .await;
    assert_eq!(flagged.stage(), ProvenanceStage::AnchorConfirmed);

    let unflagged = log
        .record_receipt(record_for(AnchorPolicy::HighValue, false))
        .await;
    assert_eq!(unflagged.stage(), ProvenanceStage::LocalMarkCommitted);
}

// ---------------------------------------------------------------------------
// Excluded paths and skip reasons.
// ---------------------------------------------------------------------------

#[test]
fn skipped_receipts_are_not_failures() {
    // A pod that is not git-backed has not *failed* to record provenance; it
    // was never asked to. Conflating the two would make every in-memory pod
    // look broken.
    for why in [
        ProvenanceSkip::NotConfigured,
        ProvenanceSkip::NotGitBacked,
        ProvenanceSkip::ExcludedPath,
        ProvenanceSkip::Container,
        ProvenanceSkip::UnresolvablePath,
    ] {
        let receipt = ProvenanceReceipt::skipped("/pod/thing.ttl", why);
        assert_eq!(receipt.stage(), ProvenanceStage::Skipped);
        assert!(!receipt.has_failure(), "{why:?} must not read as a failure");
        assert!(receipt.commit_sha().is_none());
        assert_eq!(receipt.summary(), format!("skipped; skipped={why}"));
    }
}

#[test]
fn excluded_control_plane_paths_have_their_own_skip_reason() {
    // `.acl` / `.meta` / `.prov.ttl` are control-plane, and marking a
    // `.prov.ttl` would recurse. The reason must be distinguishable from a
    // non-git pod so an operator can tell why nothing was recorded.
    let receipt = ProvenanceReceipt::skipped("/pod/secret.acl", ProvenanceSkip::ExcludedPath);
    assert_eq!(receipt.summary(), "skipped; skipped=excluded-path");
    assert_ne!(
        receipt.summary(),
        ProvenanceReceipt::skipped("/pod/secret.acl", ProvenanceSkip::NotGitBacked).summary()
    );
}

// ---------------------------------------------------------------------------
// The header summary must be safe to put in an HTTP header value.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_summary_is_header_safe() {
    let log = ProvenanceLog::new(Arc::new(StubMarker::failing(
        "line one\nline two\r\n\tand a ; semicolon, plus a comma and \u{1b}[31m escape",
    )));
    let receipt = log
        .record_receipt(record_for(AnchorPolicy::Never, false))
        .await;
    let summary = receipt.summary();

    assert!(!summary.contains('\n'), "no CR/LF: {summary:?}");
    assert!(!summary.contains('\r'), "no CR/LF: {summary:?}");
    assert!(!summary.contains('\t'));
    assert!(!summary.contains('\u{1b}'));
    assert!(
        summary.chars().all(|c| ('\x20'..='\x7e').contains(&c)),
        "printable US-ASCII only: {summary:?}"
    );
    // The structural separator survives exactly once per field.
    assert_eq!(summary.matches("mark-error=").count(), 1);
    assert!(summary.starts_with("resource-stored; mark-error="));
}

#[tokio::test]
async fn the_summary_is_bounded() {
    let log = ProvenanceLog::new(Arc::new(StubMarker::failing(&"x".repeat(4096))));
    let receipt = log
        .record_receipt(record_for(AnchorPolicy::Never, false))
        .await;
    assert!(
        receipt.summary().len() < 512,
        "an unbounded error must not be able to blow the header: {}",
        receipt.summary().len()
    );
}

#[test]
fn stage_identifiers_are_stable() {
    // These strings are a wire contract (the `X-Provenance` header).
    assert_eq!(ProvenanceStage::Skipped.as_str(), "skipped");
    assert_eq!(ProvenanceStage::ResourceStored.as_str(), "resource-stored");
    assert_eq!(
        ProvenanceStage::LocalMarkCommitted.as_str(),
        "local-mark-committed"
    );
    assert_eq!(
        ProvenanceStage::AnchorSubmitted.as_str(),
        "anchor-submitted"
    );
    assert_eq!(
        ProvenanceStage::AnchorConfirmed.as_str(),
        "anchor-confirmed"
    );
}

#[tokio::test]
async fn the_receipt_round_trips_through_json() {
    // The receipt is the machine-readable record a manifest or audit log
    // stores, so it must serialise losslessly.
    let log = ProvenanceLog::with_anchorer(
        Arc::new(StubMarker::ok()),
        Arc::new(StubAnchorer {
            outcome: AnchorOutcome::Confirmed(870_123),
        }),
    );
    let receipt = log
        .record_receipt(record_for(AnchorPolicy::Always, false))
        .await;
    let json = serde_json::to_string(&receipt).expect("serialise");
    let back: ProvenanceReceipt = serde_json::from_str(&json).expect("deserialise");
    assert_eq!(back, receipt);
    assert_eq!(back.stage(), ProvenanceStage::AnchorConfirmed);
}
