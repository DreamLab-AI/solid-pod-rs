//! Pod provisioning — seeded containers, WebID + account scaffolding,
//! admin override, quota enforcement.
//!
//! The provisioning surface is intentionally declarative: callers
//! describe what the pod should look like (containers, ACLs, a WebID
//! profile document) and the module wires them into a `Storage`
//! backend. Admin-mode callers bypass ownership checks.
//!
//! Parity note (rows 14/164/166, JSS #301 + #297): provisioning also
//! drops `settings/publicTypeIndex.jsonld` (typed
//! `solid:TypeIndex + solid:ListedDocument`),
//! `settings/privateTypeIndex.jsonld` (typed
//! `solid:TypeIndex + solid:UnlistedDocument`) and a public-read ACL
//! carve-out `settings/publicTypeIndex.jsonld.acl` so Solid clients
//! can discover a freshly bootstrapped pod's public profile without
//! fighting the default-private `/settings/.acl`.

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::PodError;
use crate::ldp::is_container;
use crate::storage::Storage;
use crate::wac::{serialize_turtle_acl, AclAuthorization, AclDocument, IdOrIds, IdRef};
use crate::webid::generate_webid_html;

/// Seed plan applied to a fresh pod.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProvisionPlan {
    /// Pubkey (hex) that owns the pod.
    pub pubkey: String,
    /// Optional display name for the WebID profile.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Public pod base URL (used to render the WebID).
    pub pod_base: String,
    /// Containers to create (paths must end with `/`).
    #[serde(default)]
    pub containers: Vec<String>,
    /// ACL document to drop at the pod root.
    #[serde(default)]
    pub root_acl: Option<AclDocument>,
    /// Bytes quota. `None` means unlimited (but a real consumer crate
    /// is strongly encouraged to set one).
    #[serde(default)]
    pub quota_bytes: Option<u64>,
}

/// Result of provisioning a pod.
#[derive(Debug, Clone)]
pub struct ProvisionOutcome {
    pub webid: String,
    pub pod_root: String,
    pub containers_created: Vec<String>,
    pub quota_bytes: Option<u64>,
    /// Storage path of the public type-index resource
    /// (`/settings/publicTypeIndex.jsonld`).
    pub public_type_index: String,
    /// Storage path of the private type-index resource
    /// (`/settings/privateTypeIndex.jsonld`).
    pub private_type_index: String,
    /// Storage path of the ACL carve-out that grants public read on
    /// the public type index (`/settings/publicTypeIndex.jsonld.acl`).
    pub public_type_index_acl: String,
}

// ---------------------------------------------------------------------------
// Type-index bootstrap helpers
// ---------------------------------------------------------------------------

/// Storage path of the public type-index document.
pub const PUBLIC_TYPE_INDEX_PATH: &str = "/settings/publicTypeIndex.jsonld";

/// Storage path of the private type-index document.
pub const PRIVATE_TYPE_INDEX_PATH: &str = "/settings/privateTypeIndex.jsonld";

/// Storage path of the sibling ACL for the public type-index document.
pub const PUBLIC_TYPE_INDEX_ACL_PATH: &str = "/settings/publicTypeIndex.jsonld.acl";

/// Render the JSON-LD body for a type-index document.
///
/// JSS writes the body literally (commit 54e4433, #301) with:
/// - `@context` binding the `solid` namespace,
/// - `@id` as the empty string (relative self-reference),
/// - `@type` listing `solid:TypeIndex` plus either
///   `solid:ListedDocument` (public) or `solid:UnlistedDocument`
///   (private).
fn render_type_index_body(visibility_marker: &str) -> String {
    let body = serde_json::json!({
        "@context": { "solid": "http://www.w3.org/ns/solid/terms#" },
        "@id": "",
        "@type": ["solid:TypeIndex", visibility_marker],
    });
    // Pretty-printed for human-readability on disk; clients parse either way.
    serde_json::to_string_pretty(&body).expect("static type-index JSON always serialises")
}

/// Build the ACL document for `publicTypeIndex.jsonld` that grants:
/// - the pod owner (`WebID`) `acl:Read`, `acl:Write`, `acl:Control`,
/// - the public (`foaf:Agent`) `acl:Read` only.
///
/// The ACL sits on the resource itself (not the parent container), so
/// it overrides the default-private `/settings/.acl`.
fn build_public_type_index_acl(webid: &str, resource_path: &str) -> AclDocument {
    let owner = AclAuthorization {
        id: Some("#owner".into()),
        r#type: Some("acl:Authorization".into()),
        agent: Some(IdOrIds::Single(IdRef { id: webid.into() })),
        agent_class: None,
        agent_group: None,
        origin: None,
        access_to: Some(IdOrIds::Single(IdRef {
            id: resource_path.into(),
        })),
        default: None,
        mode: Some(IdOrIds::Multiple(vec![
            IdRef { id: "acl:Read".into() },
            IdRef {
                id: "acl:Write".into(),
            },
            IdRef {
                id: "acl:Control".into(),
            },
        ])),
        condition: None,
    };
    let public = AclAuthorization {
        id: Some("#public".into()),
        r#type: Some("acl:Authorization".into()),
        agent: None,
        agent_class: Some(IdOrIds::Single(IdRef {
            id: "foaf:Agent".into(),
        })),
        agent_group: None,
        origin: None,
        access_to: Some(IdOrIds::Single(IdRef {
            id: resource_path.into(),
        })),
        default: None,
        mode: Some(IdOrIds::Single(IdRef { id: "acl:Read".into() })),
        condition: None,
    };
    AclDocument {
        context: None,
        graph: Some(vec![owner, public]),
    }
}

/// Seed a pod on the provided storage.
///
/// * Creates every container in `plan.containers` (idempotent — the
///   function treats `AlreadyExists` as success).
/// * Writes a WebID profile HTML at `<pod_base>/pods/<pubkey>/profile/card`.
/// * Writes a root ACL document if `plan.root_acl` is supplied.
pub async fn provision_pod<S: Storage>(
    storage: &S,
    plan: &ProvisionPlan,
) -> Result<ProvisionOutcome, PodError> {
    let pod_root = format!(
        "{}/pods/{}/",
        plan.pod_base.trim_end_matches('/'),
        plan.pubkey
    );
    let webid = format!("{pod_root}profile/card#me");

    // Ensure the pod root + default containers exist.
    let mut all_containers: Vec<String> = plan.containers.to_vec();
    all_containers.push("/".into());
    all_containers.push("/profile/".into());
    all_containers.push("/settings/".into());
    // Deduplicate.
    all_containers.sort();
    all_containers.dedup();

    let mut created = Vec::new();
    for c in &all_containers {
        if !is_container(c) {
            return Err(PodError::InvalidPath(format!("not a container: {c}")));
        }
        // Create the `.meta` sidecar — this is the idiomatic way to
        // materialise a bare container without a body.
        let meta_key = format!("{}.meta", c.trim_end_matches('/'));
        match storage
            .put(
                &meta_key,
                Bytes::from_static(b"{}"),
                "application/ld+json",
            )
            .await
        {
            Ok(_) => created.push(c.clone()),
            Err(PodError::AlreadyExists(_)) => {}
            Err(e) => return Err(e),
        }
    }

    // Write WebID profile.
    let webid_html = generate_webid_html(
        &plan.pubkey,
        plan.display_name.as_deref(),
        &plan.pod_base,
    );
    storage
        .put(
            "/profile/card",
            Bytes::from(webid_html.into_bytes()),
            "text/html",
        )
        .await?;

    // Write root ACL if supplied.
    if let Some(acl) = &plan.root_acl {
        let body = serde_json::to_vec(acl)?;
        storage
            .put("/.acl", Bytes::from(body), "application/ld+json")
            .await?;
    }

    // -------------------------------------------------------------------
    // Type-index bootstrap (rows 14/164/166 — JSS #301 + #297).
    // The two `*.jsonld` bodies differ only in the visibility marker.
    // The public one gets a sibling ACL granting `foaf:Agent` read and
    // the owner full control; the private one inherits the default
    // (owner-only) ACL from `/settings/.acl`, so we deliberately do
    // *not* emit a sibling for it.
    // -------------------------------------------------------------------
    let public_body = render_type_index_body("solid:ListedDocument");
    storage
        .put(
            PUBLIC_TYPE_INDEX_PATH,
            Bytes::from(public_body.into_bytes()),
            "application/ld+json",
        )
        .await?;

    let private_body = render_type_index_body("solid:UnlistedDocument");
    storage
        .put(
            PRIVATE_TYPE_INDEX_PATH,
            Bytes::from(private_body.into_bytes()),
            "application/ld+json",
        )
        .await?;

    // Use an absolute resource IRI so the Turtle serialiser wraps the
    // target in `<>` (otherwise a `.` inside the path — e.g. in
    // `.jsonld` — trips the statement splitter on round-trip).
    let public_acl_resource_iri = format!(
        "{}{}",
        pod_root.trim_end_matches('/'),
        PUBLIC_TYPE_INDEX_PATH,
    );
    let public_acl_doc = build_public_type_index_acl(&webid, &public_acl_resource_iri);
    let public_acl_ttl = serialize_turtle_acl(&public_acl_doc);
    storage
        .put(
            PUBLIC_TYPE_INDEX_ACL_PATH,
            Bytes::from(public_acl_ttl.into_bytes()),
            "text/turtle",
        )
        .await?;

    Ok(ProvisionOutcome {
        webid,
        pod_root,
        containers_created: created,
        quota_bytes: plan.quota_bytes,
        public_type_index: PUBLIC_TYPE_INDEX_PATH.to_string(),
        private_type_index: PRIVATE_TYPE_INDEX_PATH.to_string(),
        public_type_index_acl: PUBLIC_TYPE_INDEX_ACL_PATH.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Quota enforcement
// ---------------------------------------------------------------------------

/// Tracks per-pod byte usage against a configurable quota.
#[derive(Debug, Clone)]
pub struct QuotaTracker {
    quota_bytes: Option<u64>,
    used_bytes: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl QuotaTracker {
    pub fn new(quota_bytes: Option<u64>) -> Self {
        Self {
            quota_bytes,
            used_bytes: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    pub fn with_initial_used(quota_bytes: Option<u64>, used: u64) -> Self {
        Self {
            quota_bytes,
            used_bytes: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(used)),
        }
    }

    /// Bytes currently accounted for.
    pub fn used(&self) -> u64 {
        self.used_bytes.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Configured quota, if any.
    pub fn quota(&self) -> Option<u64> {
        self.quota_bytes
    }

    /// Reserve `size` bytes. Returns `Err(PodError::PreconditionFailed)`
    /// when the operation would exceed the quota, without mutating the
    /// tracker.
    pub fn reserve(&self, size: u64) -> Result<(), PodError> {
        if let Some(q) = self.quota_bytes {
            let cur = self.used();
            if cur.saturating_add(size) > q {
                return Err(PodError::PreconditionFailed(format!(
                    "quota exceeded: {cur}+{size} > {q}"
                )));
            }
        }
        self.used_bytes
            .fetch_add(size, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Release `size` bytes previously reserved (e.g. on DELETE).
    pub fn release(&self, size: u64) {
        self.used_bytes
            .fetch_sub(size, std::sync::atomic::Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Admin override
// ---------------------------------------------------------------------------

/// A verified admin-override marker. The consumer crate constructs this
/// only after validating a shared-secret header against configuration;
/// the marker carries no data beyond its own existence.
#[derive(Debug, Clone, Copy)]
pub struct AdminOverride;

/// Match an admin-secret header value against the configured secret.
/// Both sides are compared with constant-time equality to avoid
/// timing leaks. Returns `Some(AdminOverride)` on match.
pub fn check_admin_override(
    header: Option<&str>,
    configured: Option<&str>,
) -> Option<AdminOverride> {
    let header = header?;
    let configured = configured?;
    if header.len() != configured.len() {
        return None;
    }
    let mut acc = 0u8;
    for (a, b) in header.bytes().zip(configured.bytes()) {
        acc |= a ^ b;
    }
    if acc == 0 {
        Some(AdminOverride)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_tracker_respects_limit() {
        let q = QuotaTracker::new(Some(100));
        q.reserve(40).unwrap();
        q.reserve(40).unwrap();
        let err = q.reserve(40).unwrap_err();
        assert!(matches!(err, PodError::PreconditionFailed(_)));
        assert_eq!(q.used(), 80);
    }

    #[test]
    fn quota_tracker_release_frees_space() {
        let q = QuotaTracker::new(Some(100));
        q.reserve(60).unwrap();
        q.release(30);
        q.reserve(60).unwrap();
        assert_eq!(q.used(), 90);
    }

    #[test]
    fn quota_tracker_none_means_unlimited() {
        let q = QuotaTracker::new(None);
        q.reserve(u64::MAX / 2).unwrap();
        q.reserve(u64::MAX / 2).unwrap();
    }

    #[test]
    fn admin_override_matches_only_exact() {
        let ok = check_admin_override(Some("topsecret"), Some("topsecret"));
        assert!(ok.is_some());
        assert!(check_admin_override(Some("topsecret "), Some("topsecret")).is_none());
        assert!(check_admin_override(None, Some("topsecret")).is_none());
        assert!(check_admin_override(Some("a"), None).is_none());
    }

    // -------------------------------------------------------------------
    // Type-index bootstrap tests (rows 14/164/166).
    // -------------------------------------------------------------------
    #[cfg(feature = "memory-backend")]
    mod type_index_bootstrap {
        use super::*;
        use crate::storage::memory::MemoryBackend;
        use crate::wac::{evaluate_access, parse_turtle_acl, AccessMode};
        use serde_json::Value;

        async fn provision_default_pod() -> (MemoryBackend, ProvisionOutcome) {
            let pod = MemoryBackend::new();
            let plan = ProvisionPlan {
                pubkey: "0123".into(),
                display_name: Some("Alice".into()),
                pod_base: "https://pod.example".into(),
                containers: vec!["/media/".into()],
                root_acl: None,
                quota_bytes: Some(10_000),
            };
            let outcome = provision_pod(&pod, &plan).await.unwrap();
            (pod, outcome)
        }

        #[tokio::test]
        async fn provision_writes_public_type_index_with_listed_document() {
            let (pod, outcome) = provision_default_pod().await;
            assert_eq!(
                outcome.public_type_index, PUBLIC_TYPE_INDEX_PATH,
                "outcome must surface the public type-index path",
            );

            let (body, meta) = pod.get(PUBLIC_TYPE_INDEX_PATH).await.unwrap();
            assert_eq!(meta.content_type, "application/ld+json");

            let parsed: Value = serde_json::from_slice(&body).expect("valid JSON-LD");
            assert_eq!(parsed["@id"], Value::String(String::new()));
            assert_eq!(
                parsed["@context"]["solid"],
                "http://www.w3.org/ns/solid/terms#"
            );
            let types = parsed["@type"].as_array().expect("@type is array");
            let type_strs: Vec<&str> = types.iter().filter_map(Value::as_str).collect();
            assert!(type_strs.contains(&"solid:TypeIndex"), "{type_strs:?}");
            assert!(
                type_strs.contains(&"solid:ListedDocument"),
                "public type index missing solid:ListedDocument visibility marker: {type_strs:?}",
            );
            assert!(
                !type_strs.contains(&"solid:UnlistedDocument"),
                "public type index must not carry solid:UnlistedDocument",
            );
        }

        #[tokio::test]
        async fn provision_writes_private_type_index_with_unlisted_document() {
            let (pod, outcome) = provision_default_pod().await;
            assert_eq!(outcome.private_type_index, PRIVATE_TYPE_INDEX_PATH);

            let (body, meta) = pod.get(PRIVATE_TYPE_INDEX_PATH).await.unwrap();
            assert_eq!(meta.content_type, "application/ld+json");

            let parsed: Value = serde_json::from_slice(&body).expect("valid JSON-LD");
            assert_eq!(parsed["@id"], Value::String(String::new()));
            let types = parsed["@type"].as_array().expect("@type is array");
            let type_strs: Vec<&str> = types.iter().filter_map(Value::as_str).collect();
            assert!(type_strs.contains(&"solid:TypeIndex"));
            assert!(
                type_strs.contains(&"solid:UnlistedDocument"),
                "private type index missing solid:UnlistedDocument marker: {type_strs:?}",
            );
            assert!(
                !type_strs.contains(&"solid:ListedDocument"),
                "private type index must not carry solid:ListedDocument",
            );
        }

        #[tokio::test]
        async fn provision_writes_public_read_acl_on_public_type_index() {
            let (pod, outcome) = provision_default_pod().await;
            assert_eq!(outcome.public_type_index_acl, PUBLIC_TYPE_INDEX_ACL_PATH);

            let (body, meta) = pod.get(PUBLIC_TYPE_INDEX_ACL_PATH).await.unwrap();
            assert_eq!(meta.content_type, "text/turtle");
            let text = std::str::from_utf8(&body).expect("UTF-8 turtle");
            assert!(text.contains("@prefix acl:"));
            assert!(text.contains("acl:Authorization"));
            assert!(text.contains("acl:Control"));
            assert!(text.contains("foaf:Agent"));
        }

        #[tokio::test]
        async fn public_type_index_acl_grants_foaf_agent_read() {
            let (pod, outcome) = provision_default_pod().await;
            let (body, _) = pod.get(PUBLIC_TYPE_INDEX_ACL_PATH).await.unwrap();
            let ttl = std::str::from_utf8(&body).unwrap();
            let doc = parse_turtle_acl(ttl).expect("ACL parses");
            // The ACL `accessTo` is the absolute IRI of the resource.
            // Evaluate against that same string; WAC `path_matches`
            // normalises both sides identically.
            let resource_iri = format!(
                "{}{}",
                outcome.pod_root.trim_end_matches('/'),
                PUBLIC_TYPE_INDEX_PATH,
            );

            assert!(
                evaluate_access(
                    Some(&doc),
                    None,
                    &resource_iri,
                    AccessMode::Read,
                    None,
                ),
                "public/anonymous read must be granted on publicTypeIndex.jsonld",
            );
            assert!(
                !evaluate_access(
                    Some(&doc),
                    None,
                    &resource_iri,
                    AccessMode::Write,
                    None,
                ),
                "anonymous must not be granted write",
            );
        }

        #[tokio::test]
        async fn private_type_index_has_no_sibling_acl() {
            let (pod, _) = provision_default_pod().await;
            let missing = "/settings/privateTypeIndex.jsonld.acl";
            assert!(
                !pod.exists(missing).await.unwrap(),
                "private type index must not have a sibling ACL; must inherit /settings/.acl",
            );
        }
    }
}
