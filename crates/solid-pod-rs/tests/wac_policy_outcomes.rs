//! ADR-2005 acceptance corpus — typed policy outcomes in the ACL resolver.
//!
//! The gap these tests close: the resolver reported every non-success as
//! "no ACL at this level" and carried on walking upward. A malformed
//! `/secret.acl` therefore inherited a permissive `/.acl` and the caller was
//! **granted** the ancestor's broader rights; a storage read failure behaved
//! identically. The restrictive policy an operator wrote was silently replaced
//! by the very policy it existed to override.
//!
//! Each test below maps onto one item of the ADR-2005 acceptance list:
//!
//! 1. valid missing-policy inheritance (the legitimate path — must still work)
//! 2. denied invalid specific policy despite a permissive ancestor
//! 3. bounded oversized input
//! 4. backend read failure
//! 5. revocation with ancestor / legacy fallback

#![cfg(all(feature = "memory-backend", feature = "tokio-runtime"))]

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

use solid_pod_rs::error::PodError;
use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::{ResourceMeta, Storage, StorageEvent};
use solid_pod_rs::wac::{
    classify_policy_read, evaluate_access, resolve_policy_from_storage, AccessMode, AclResolver,
    InvalidPolicyReason, PolicyOutcome, PolicyRead, PolicyStep, StorageAclResolver,
};

const JSONLD: &str = "application/ld+json";

/// A permissive root ACL granting every agent Read on everything below `/`.
/// This is the ancestor an invalid child policy must NOT be allowed to inherit.
const PERMISSIVE_ROOT: &str = r#"{
    "@graph": [{
        "@type": "acl:Authorization",
        "acl:agentClass": {"@id": "foaf:Agent"},
        "acl:default": {"@id": "/"},
        "acl:mode": [{"@id": "acl:Read"}, {"@id": "acl:Write"}]
    }]
}"#;

/// A restrictive ACL naming exactly one agent on exactly one resource.
const RESTRICTIVE_SECRET: &str = r#"{
    "@graph": [{
        "@type": "acl:Authorization",
        "acl:agent": {"@id": "did:nostr:owner"},
        "acl:accessTo": {"@id": "/secret"},
        "acl:mode": {"@id": "acl:Read"}
    }]
}"#;

async fn pod_with(entries: &[(&str, &str)]) -> Arc<MemoryBackend> {
    let store = Arc::new(MemoryBackend::new());
    for (path, body) in entries {
        store
            .put(path, Bytes::from(body.to_string()), JSONLD)
            .await
            .expect("seed write");
    }
    store
}

// ---------------------------------------------------------------------------
// A storage backend that can be made to fail specific reads, so the
// "unavailable" branch is exercised against a real fault rather than a stub.
// ---------------------------------------------------------------------------

struct FaultyBackend {
    inner: Arc<MemoryBackend>,
    /// Paths whose `get` returns a backend fault instead of a body.
    failing: HashSet<String>,
}

impl FaultyBackend {
    fn new(inner: Arc<MemoryBackend>, failing: &[&str]) -> Self {
        Self {
            inner,
            failing: failing.iter().map(|s| (*s).to_string()).collect(),
        }
    }
}

#[async_trait]
impl Storage for FaultyBackend {
    async fn get(&self, path: &str) -> Result<(Bytes, ResourceMeta), PodError> {
        if self.failing.contains(path) {
            // Deliberately NOT `NotFound` — this is the "I cannot tell you
            // what the policy says" case, which must never be read as "there
            // is no policy here".
            return Err(PodError::Backend(format!(
                "simulated backend fault reading {path}"
            )));
        }
        self.inner.get(path).await
    }
    async fn put(
        &self,
        path: &str,
        body: Bytes,
        content_type: &str,
    ) -> Result<ResourceMeta, PodError> {
        self.inner.put(path, body, content_type).await
    }
    async fn delete(&self, path: &str) -> Result<(), PodError> {
        self.inner.delete(path).await
    }
    async fn list(&self, container: &str) -> Result<Vec<String>, PodError> {
        self.inner.list(container).await
    }
    async fn head(&self, path: &str) -> Result<ResourceMeta, PodError> {
        self.inner.head(path).await
    }
    async fn exists(&self, path: &str) -> Result<bool, PodError> {
        self.inner.exists(path).await
    }
    async fn watch(
        &self,
        path: &str,
    ) -> Result<tokio::sync::mpsc::Receiver<StorageEvent>, PodError> {
        self.inner.watch(path).await
    }
}

// ---------------------------------------------------------------------------
// 1. Valid missing-policy inheritance — the legitimate path.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn missing_specific_policy_inherits_from_the_ancestor() {
    // No `/docs/report.ttl.acl` and no `/docs.acl`: the walk legitimately
    // ascends to the permissive root and inherits its `acl:default`.
    let store = pod_with(&[("/.acl", PERMISSIVE_ROOT)]).await;
    let outcome = resolve_policy_from_storage(&*store, "/docs/report.ttl").await;

    let doc = match &outcome {
        PolicyOutcome::Found(doc) => doc,
        other => panic!("expected Found, got {other:?}"),
    };
    assert!(
        doc.inherited,
        "a document resolved from an ancestor must be tagged inherited so the \
         evaluator honours only acl:default (WAC §4.2)"
    );
    assert!(
        evaluate_access(
            Some(doc),
            Some("did:nostr:anyone"),
            "/docs/report.ttl",
            AccessMode::Read,
            None,
        ),
        "legitimate inheritance must still grant"
    );
}

#[tokio::test]
async fn no_policy_anywhere_is_missing_not_a_failure() {
    let store = pod_with(&[]).await;
    let outcome = resolve_policy_from_storage(&*store, "/a/b/c.ttl").await;
    assert!(matches!(outcome, PolicyOutcome::Missing));
    assert!(outcome.may_inherit(), "absence is the inheritable outcome");
    assert!(!outcome.is_failure());
    // Legacy shape: a clean `Ok(None)`, so deny-by-default at the evaluator.
    assert!(outcome
        .into_result()
        .expect("missing is not an error")
        .is_none());
}

#[tokio::test]
async fn a_direct_policy_is_not_tagged_inherited() {
    let store = pod_with(&[
        ("/.acl", PERMISSIVE_ROOT),
        ("/secret.acl", RESTRICTIVE_SECRET),
    ])
    .await;
    let outcome = resolve_policy_from_storage(&*store, "/secret").await;
    let doc = outcome.document().expect("direct policy found");
    assert!(!doc.inherited);
    // The restrictive policy governs: its named agent is granted...
    assert!(evaluate_access(
        Some(doc),
        Some("did:nostr:owner"),
        "/secret",
        AccessMode::Read,
        None,
    ));
    // ...and nobody else is, despite the permissive root above it.
    assert!(!evaluate_access(
        Some(doc),
        Some("did:nostr:mallory"),
        "/secret",
        AccessMode::Read,
        None,
    ));
}

// ---------------------------------------------------------------------------
// 2. Denied invalid specific policy despite a permissive ancestor.
//    This is the reproduced finding.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn malformed_specific_policy_denies_and_never_inherits() {
    // The exact shape from the estate-review probe: a malformed
    // `/secret.acl` beneath a permissive root ACL.
    let store = pod_with(&[("/.acl", PERMISSIVE_ROOT)]).await;
    store
        .put(
            "/secret.acl",
            Bytes::from_static(b"{ \"@graph\": [ this is not valid JSON-LD"),
            JSONLD,
        )
        .await
        .unwrap();

    let outcome = resolve_policy_from_storage(&*store, "/secret").await;

    match &outcome {
        PolicyOutcome::Invalid {
            policy_path,
            reason,
        } => {
            assert_eq!(policy_path, "/secret.acl");
            assert!(matches!(reason, InvalidPolicyReason::Malformed(_)));
        }
        other => {
            panic!("a malformed specific policy must be Invalid, not inherited. Got {other:?}")
        }
    }
    assert!(outcome.is_failure());
    assert!(
        !outcome.may_inherit(),
        "REGRESSION GUARD: this is the bug — an invalid policy must never \
         fall through to the permissive ancestor"
    );
    assert!(
        outcome.document().is_none(),
        "no document may be handed to the evaluator from an invalid policy"
    );
    // And the legacy adapter is fail-closed too: an Err can never be a grant.
    assert!(outcome.into_result().is_err());
}

#[tokio::test]
async fn broken_turtle_policy_denies_and_never_inherits() {
    // `parse_turtle_acl` is LENIENT: it skips statements it cannot read and
    // returns a document with no authorisations rather than an error. This
    // test pins that real behaviour, and — the part that matters for
    // ADR-2005 — proves it is still fail-closed:
    //
    //   * the walk TERMINATES here (outcome is Found, not Ascend), so the
    //     permissive ancestor is never reached; and
    //   * the resulting document grants nothing, so every agent is denied.
    //
    // The security property therefore holds by a different route than the
    // malformed-JSON case: deny-by-empty-grant rather than deny-by-Invalid.
    // The cost is diagnostic, not authorisation — a corrupt Turtle ACL reads
    // as a deliberate deny-all and is not logged as a fault. That residual
    // gap is recorded in the ADR-2005 progress note.
    let store = pod_with(&[("/.acl", PERMISSIVE_ROOT)]).await;
    store
        .put(
            "/secret.acl",
            Bytes::from_static(b"@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n<<<< broken"),
            "text/turtle",
        )
        .await
        .unwrap();

    let outcome = resolve_policy_from_storage(&*store, "/secret").await;
    let doc = match &outcome {
        PolicyOutcome::Found(doc) => doc,
        other => panic!("expected a terminating Found, got {other:?}"),
    };
    assert!(
        !doc.inherited,
        "REGRESSION GUARD: the walk must stop at the broken child policy and \
         never reach the permissive root"
    );
    assert!(
        doc.graph.as_ref().is_none_or(|g| g.is_empty()),
        "a broken Turtle body must yield no authorisations"
    );
    for agent in ["did:nostr:owner", "did:nostr:mallory"] {
        assert!(
            !evaluate_access(Some(doc), Some(agent), "/secret", AccessMode::Read, None),
            "{agent} must be denied — the permissive ancestor must not leak through"
        );
    }
}

#[tokio::test]
async fn non_utf8_policy_denies_and_never_inherits() {
    let store = pod_with(&[("/.acl", PERMISSIVE_ROOT)]).await;
    store
        .put(
            "/secret.acl",
            Bytes::from_static(&[0xff, 0xfe, 0x00, 0x01, 0x02]),
            "text/turtle",
        )
        .await
        .unwrap();

    let outcome = resolve_policy_from_storage(&*store, "/secret").await;
    match outcome {
        PolicyOutcome::Invalid { reason, .. } => {
            assert_eq!(reason, InvalidPolicyReason::NotUtf8);
        }
        other => panic!("expected Invalid/NotUtf8, got {other:?}"),
    }
}

#[tokio::test]
async fn an_invalid_ancestor_policy_also_stops_the_walk() {
    // The invalid document sits on the ANCESTOR rather than the resource.
    // It still terminates the walk: we cannot know whether it would have
    // granted or denied, so we must not skip past it to the root.
    let store = pod_with(&[("/.acl", PERMISSIVE_ROOT)]).await;
    store
        .put(
            "/docs.acl",
            Bytes::from_static(b"not a policy at all"),
            JSONLD,
        )
        .await
        .unwrap();

    let outcome = resolve_policy_from_storage(&*store, "/docs/report.ttl").await;
    match &outcome {
        PolicyOutcome::Invalid { policy_path, .. } => assert_eq!(policy_path, "/docs.acl"),
        other => panic!("expected Invalid at /docs.acl, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 3. Bounded oversized / over-deep input.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn oversized_policy_is_invalid_not_inherited() {
    let store = pod_with(&[("/.acl", PERMISSIVE_ROOT)]).await;
    // Exceed MAX_ACL_BYTES (1 MiB) with a syntactically plausible body.
    let mut body = String::from("{\"@graph\":[{\"@id\":\"");
    body.push_str(&"a".repeat(solid_pod_rs::wac::MAX_ACL_BYTES + 1));
    body.push_str("\"}]}");
    store
        .put("/secret.acl", Bytes::from(body), JSONLD)
        .await
        .unwrap();

    let outcome = resolve_policy_from_storage(&*store, "/secret").await;
    match &outcome {
        PolicyOutcome::Invalid { reason, .. } => {
            assert!(
                matches!(reason, InvalidPolicyReason::TooLarge(_)),
                "expected TooLarge, got {reason:?}"
            );
        }
        other => panic!("an oversized policy must be Invalid, got {other:?}"),
    }
    // The bound still maps onto HTTP 413 for legacy callers.
    assert!(matches!(
        outcome.into_result(),
        Err(PodError::PayloadTooLarge(_))
    ));
}

#[tokio::test]
async fn depth_bombed_policy_is_invalid_not_inherited() {
    let store = pod_with(&[("/.acl", PERMISSIVE_ROOT)]).await;
    let depth = solid_pod_rs::wac::MAX_ACL_JSON_DEPTH + 8;
    let body = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
    store
        .put("/secret.acl", Bytes::from(body), JSONLD)
        .await
        .unwrap();

    let outcome = resolve_policy_from_storage(&*store, "/secret").await;
    match &outcome {
        PolicyOutcome::Invalid { reason, .. } => {
            assert!(
                matches!(reason, InvalidPolicyReason::TooDeep(_)),
                "expected TooDeep, got {reason:?}"
            );
        }
        other => panic!("a depth-bombed policy must be Invalid, got {other:?}"),
    }
    // Depth violations stay HTTP 400 for legacy callers.
    assert!(matches!(
        outcome.into_result(),
        Err(PodError::BadRequest(_))
    ));
}

// ---------------------------------------------------------------------------
// 4. Backend read failure.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn backend_read_failure_is_unavailable_not_a_miss() {
    let inner = pod_with(&[
        ("/.acl", PERMISSIVE_ROOT),
        ("/secret.acl", RESTRICTIVE_SECRET),
    ])
    .await;
    // The restrictive policy exists but cannot be read.
    let store = FaultyBackend::new(inner, &["/secret.acl"]);

    let outcome = resolve_policy_from_storage(&store, "/secret").await;
    match &outcome {
        PolicyOutcome::Unavailable {
            policy_path,
            detail,
        } => {
            assert_eq!(policy_path, "/secret.acl");
            assert!(detail.contains("simulated backend fault"));
        }
        other => panic!(
            "a failed read must be Unavailable — reading it as a miss inherits \
             the permissive root. Got {other:?}"
        ),
    }
    assert!(outcome.is_failure());
    assert!(!outcome.may_inherit());
    assert!(outcome.document().is_none());
    assert!(matches!(outcome.into_result(), Err(PodError::Backend(_))));
}

#[tokio::test]
async fn a_failing_ancestor_read_also_denies() {
    // Nothing at the resource; the ancestor read faults. The walk must stop
    // rather than continue to a policy further up (or to Missing).
    let inner = pod_with(&[("/.acl", PERMISSIVE_ROOT)]).await;
    let store = FaultyBackend::new(inner, &["/docs.acl"]);

    let outcome = resolve_policy_from_storage(&store, "/docs/report.ttl").await;
    match &outcome {
        PolicyOutcome::Unavailable { policy_path, .. } => assert_eq!(policy_path, "/docs.acl"),
        other => panic!("expected Unavailable at /docs.acl, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 5. Revocation with ancestor / legacy fallback.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn revoking_a_specific_policy_falls_back_to_the_ancestor() {
    // Revocation = deleting the resource's own `.acl`. That is a genuine
    // absence, so inheritance resumes. The distinction that matters: an
    // absent policy inherits, a broken one does not.
    let store = pod_with(&[
        ("/.acl", PERMISSIVE_ROOT),
        ("/secret.acl", RESTRICTIVE_SECRET),
    ])
    .await;

    // Before revocation: the restrictive policy governs and excludes mallory.
    let before = resolve_policy_from_storage(&*store, "/secret").await;
    let before_doc = before.document().expect("direct policy");
    assert!(!before_doc.inherited);
    assert!(!evaluate_access(
        Some(before_doc),
        Some("did:nostr:mallory"),
        "/secret",
        AccessMode::Read,
        None,
    ));

    store.delete("/secret.acl").await.expect("revoke");

    // After revocation: absence, so the ancestor's default applies.
    let after = resolve_policy_from_storage(&*store, "/secret").await;
    let after_doc = after.document().expect("ancestor policy");
    assert!(after_doc.inherited, "the fallback document is inherited");
    assert!(
        evaluate_access(
            Some(after_doc),
            Some("did:nostr:mallory"),
            "/secret",
            AccessMode::Read,
            None,
        ),
        "revocation legitimately restores the ancestor's default grant"
    );
}

#[tokio::test]
async fn revocation_to_no_policy_at_all_denies_by_default() {
    let store = pod_with(&[("/secret.acl", RESTRICTIVE_SECRET)]).await;
    store.delete("/secret.acl").await.expect("revoke");

    let outcome = resolve_policy_from_storage(&*store, "/secret").await;
    assert!(matches!(outcome, PolicyOutcome::Missing));
    assert!(
        !evaluate_access(
            None,
            Some("did:nostr:owner"),
            "/secret",
            AccessMode::Read,
            None
        ),
        "no ACL anywhere must deny by default"
    );
}

#[tokio::test]
async fn legacy_find_effective_acl_stays_fail_closed() {
    // The historical entry point must not become a bypass: the same malformed
    // policy that yields Invalid above must yield Err here, never Ok(Some) of
    // the permissive ancestor.
    let store = pod_with(&[("/.acl", PERMISSIVE_ROOT)]).await;
    store
        .put("/secret.acl", Bytes::from_static(b"{ broken"), JSONLD)
        .await
        .unwrap();

    let resolver = StorageAclResolver::new(store.clone());
    let legacy = resolver.find_effective_acl("/secret").await;
    assert!(
        legacy.is_err(),
        "legacy API must surface an error, not the inherited ancestor: {legacy:?}"
    );

    // The legacy path and the typed path agree.
    let typed = resolver.resolve_policy("/secret").await;
    assert!(matches!(typed, PolicyOutcome::Invalid { .. }));

    // And the legitimate inheritance case still returns the ancestor.
    let inherited = resolver
        .find_effective_acl("/other")
        .await
        .expect("missing policy inherits")
        .expect("ancestor found");
    assert!(inherited.inherited);
}

#[tokio::test]
async fn trait_default_resolve_policy_adapts_a_legacy_implementor() {
    // An out-of-repo implementor that only supplies `find_effective_acl` keeps
    // compiling and still reports fail-closed typed outcomes.
    struct LegacyOnly(Result<Option<solid_pod_rs::wac::AclDocument>, PodError>);
    #[async_trait]
    impl AclResolver for LegacyOnly {
        async fn find_effective_acl(
            &self,
            _resource_path: &str,
        ) -> Result<Option<solid_pod_rs::wac::AclDocument>, PodError> {
            match &self.0 {
                Ok(Some(d)) => Ok(Some(d.clone())),
                Ok(None) => Ok(None),
                Err(e) => Err(PodError::Backend(e.to_string())),
            }
        }
    }

    let missing = LegacyOnly(Ok(None)).resolve_policy("/x").await;
    assert!(matches!(missing, PolicyOutcome::Missing));

    let failed = LegacyOnly(Err(PodError::Backend("boom".into())))
        .resolve_policy("/x")
        .await;
    assert!(matches!(failed, PolicyOutcome::Unavailable { .. }));
    assert!(failed.is_failure());
}

// ---------------------------------------------------------------------------
// The pure classifier — the surface the edge/WASM tier reuses so the two
// tiers cannot drift apart on these semantics again.
// ---------------------------------------------------------------------------

#[test]
fn classifier_ascends_only_on_absence() {
    assert!(matches!(
        classify_policy_read("/a.acl", PolicyRead::Absent, false),
        PolicyStep::Ascend
    ));
}

#[test]
fn classifier_settles_on_a_failed_read() {
    match classify_policy_read("/a.acl", PolicyRead::Failed("kv timeout".into()), false) {
        PolicyStep::Settled(PolicyOutcome::Unavailable {
            policy_path,
            detail,
        }) => {
            assert_eq!(policy_path, "/a.acl");
            assert_eq!(detail, "kv timeout");
        }
        other => panic!("a failed read must never ascend: {other:?}"),
    }
}

#[test]
fn classifier_settles_on_an_unparseable_body() {
    match classify_policy_read(
        "/a.acl",
        PolicyRead::Present {
            body: b"\x00\x01 garbage",
            content_type: "application/octet-stream",
        },
        false,
    ) {
        PolicyStep::Settled(PolicyOutcome::Invalid { .. }) => {}
        other => panic!("an unparseable body must never ascend: {other:?}"),
    }
}

#[test]
fn classifier_stamps_the_inherited_flag() {
    let step = classify_policy_read(
        "/.acl",
        PolicyRead::Present {
            body: PERMISSIVE_ROOT.as_bytes(),
            content_type: "application/ld+json",
        },
        true,
    );
    match step {
        PolicyStep::Settled(PolicyOutcome::Found(doc)) => assert!(doc.inherited),
        other => panic!("expected Found, got {other:?}"),
    }
}

#[test]
fn classifier_accepts_turtle_by_content_type_and_by_sniff() {
    let turtle = "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
                  <#owner> a acl:Authorization ;\n\
                    acl:agent <did:nostr:owner> ;\n\
                    acl:accessTo </secret> ;\n\
                    acl:mode acl:Read .\n";
    for ct in ["text/turtle", "application/octet-stream"] {
        let step = classify_policy_read(
            "/secret.acl",
            PolicyRead::Present {
                body: turtle.as_bytes(),
                content_type: ct,
            },
            false,
        );
        assert!(
            matches!(step, PolicyStep::Settled(PolicyOutcome::Found(_))),
            "Turtle must still parse with content-type {ct}: {step:?}"
        );
    }
}
