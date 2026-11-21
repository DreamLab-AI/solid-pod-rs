//! ACL resolver — locates the effective ACL document for a given path.
//!
//! `find_effective_acl` walks the storage tree from the resource path
//! up to the root, returning the first `*.acl` sibling that parses as
//! JSON-LD or Turtle.
//!
//! # Typed policy outcomes (ADR-2005)
//!
//! The walk-up algorithm has three materially different terminal states, and
//! collapsing them is an authorisation bug. Before the typed outcomes below
//! existed, this resolver reported *every* non-success as "no ACL here" and
//! carried on walking upward. A malformed `/secret.acl` therefore fell
//! through to a permissive `/.acl` and the caller was **granted** the
//! ancestor's broader rights — the restrictive policy the operator wrote was
//! silently replaced by the inherited one it was meant to override. A storage
//! read failure behaved identically.
//!
//! [`PolicyOutcome`] names the three states so a caller can no longer confuse
//! them:
//!
//! | Outcome | Meaning | Required handling |
//! |---------|---------|-------------------|
//! | [`Missing`](PolicyOutcome::Missing) | No `.acl` exists at this level | **Inherit** — continue the walk to the ancestor. This is the legitimate WAC §4.2 inheritance path. |
//! | [`Found`](PolicyOutcome::Found) | A `.acl` exists and parsed | Evaluate it. |
//! | [`Invalid`](PolicyOutcome::Invalid) | A `.acl` exists but is unparseable or exceeds the parser bounds | **Deny. Never inherit.** A policy the operator authored is present but unreadable; inheriting past it would grant more than the author intended. |
//! | [`Unavailable`](PolicyOutcome::Unavailable) | The backend could not be read | **Deny / error. Never inherit.** The policy's content is unknown, so no grant can be justified. |
//!
//! The distinction that matters is between *absence* (a fact: nothing governs
//! this level, so the ancestor does) and *failure* (an unknown: something may
//! govern this level and we cannot read it). Only absence may inherit.
//!
//! # Reuse across tiers
//!
//! [`classify_policy_read`] is the pure, runtime-free, single-level decision
//! function. It compiles on the `core` surface, so an edge/WASM tier backed by
//! KV or R2 rather than [`Storage`] implements the *same* semantics by feeding
//! it each read instead of re-deriving the rules — which is how the two tiers
//! drifted apart in the first place. [`resolve_policy_from_storage`] is the
//! native walk built on top of it.

use async_trait::async_trait;

use crate::error::PodError;
// `Storage` lives behind `tokio-runtime`; the storage-backed resolver
// impl below is gated to match. The `AclResolver` trait is pure and
// remains available under `core` so wasm32 consumers can implement
// their own KV-backed resolver against the same contract.
#[cfg(feature = "tokio-runtime")]
use crate::storage::Storage;
use crate::wac::document::AclDocument;
use crate::wac::parse_jsonld_acl_at;
use crate::wac::parser::parse_turtle_acl;

// ---------------------------------------------------------------------------
// Typed policy outcomes (ADR-2005)
// ---------------------------------------------------------------------------

/// Why a located policy document could not be turned into an [`AclDocument`].
///
/// Every variant is terminal: the document exists, so the walk must **not**
/// continue to an ancestor. Carrying the reason lets a caller distinguish an
/// operator authoring mistake (`Malformed`) from a resource-exhaustion guard
/// firing (`TooLarge` / `TooDeep`), which have different operational fixes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidPolicyReason {
    /// The body parsed as neither JSON-LD nor Turtle.
    Malformed(String),
    /// The body exceeded the parser's byte cap ([`crate::wac::MAX_ACL_BYTES`]).
    TooLarge(String),
    /// The body exceeded the JSON nesting cap
    /// ([`crate::wac::MAX_ACL_JSON_DEPTH`]).
    TooDeep(String),
    /// The body is not valid UTF-8, so it can be neither JSON-LD nor Turtle.
    NotUtf8,
}

impl std::fmt::Display for InvalidPolicyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidPolicyReason::Malformed(m) => write!(f, "malformed ACL document: {m}"),
            InvalidPolicyReason::TooLarge(m) => write!(f, "ACL document too large: {m}"),
            InvalidPolicyReason::TooDeep(m) => write!(f, "ACL document too deeply nested: {m}"),
            InvalidPolicyReason::NotUtf8 => write!(f, "ACL document is not valid UTF-8"),
        }
    }
}

/// The terminal result of resolving the effective policy for a resource.
///
/// See the [module docs](self) for the handling contract. The key invariant:
/// **only [`Missing`](Self::Missing) may inherit.**
#[derive(Debug, Clone)]
pub enum PolicyOutcome {
    /// A policy document was located and parsed. `inherited` on the document
    /// records whether it came from an ancestor container.
    Found(AclDocument),
    /// No policy exists at the resource or at any ancestor up to the root.
    ///
    /// This is *absence*, not failure: the walk completed and found nothing.
    /// The evaluator still denies by default (no ACL grants nothing), but the
    /// resolution itself succeeded.
    Missing,
    /// A policy document exists at `policy_path` but could not be parsed.
    ///
    /// Deny. Never inherit past it.
    Invalid {
        /// Storage key of the offending `.acl` sidecar.
        policy_path: String,
        /// Why the parse failed.
        reason: InvalidPolicyReason,
    },
    /// The backend could not be read at `policy_path`.
    ///
    /// Deny or surface an error. Never inherit past it — the policy's content
    /// is unknown, so no grant can be justified from an ancestor.
    Unavailable {
        /// Storage key whose read failed.
        policy_path: String,
        /// Backend error detail.
        detail: String,
    },
}

impl PolicyOutcome {
    /// The parsed document, if one was found.
    ///
    /// Returns `None` for every non-`Found` outcome — including the failure
    /// outcomes. Callers that feed this straight into the evaluator get
    /// deny-by-default, but they lose the distinction between "nothing governs
    /// this" and "we could not read what governs this"; prefer matching on the
    /// outcome directly, or gate on [`Self::is_failure`] first.
    #[must_use]
    pub fn document(&self) -> Option<&AclDocument> {
        match self {
            PolicyOutcome::Found(doc) => Some(doc),
            _ => None,
        }
    }

    /// `true` for [`Invalid`](Self::Invalid) and [`Unavailable`](Self::Unavailable)
    /// — the outcomes that must deny rather than inherit.
    #[must_use]
    pub fn is_failure(&self) -> bool {
        matches!(
            self,
            PolicyOutcome::Invalid { .. } | PolicyOutcome::Unavailable { .. }
        )
    }

    /// `true` when the walk may legitimately fall back to an ancestor or legacy
    /// policy — i.e. only for [`Missing`](Self::Missing).
    #[must_use]
    pub fn may_inherit(&self) -> bool {
        matches!(self, PolicyOutcome::Missing)
    }

    /// Collapse to the historical `Result<Option<AclDocument>, PodError>` shape.
    ///
    /// `Found` → `Ok(Some)`, `Missing` → `Ok(None)`, and both failure outcomes
    /// → `Err`. The error mapping keeps the HTTP status the bounded parsers
    /// already produced (413 for `TooLarge`, 400 for `TooDeep`) so existing
    /// callers see no status change; `Malformed` / `NotUtf8` become
    /// [`PodError::AclParse`] and `Unavailable` becomes [`PodError::Backend`].
    ///
    /// This is a **lossy but fail-closed** adapter: an `Err` can never be
    /// mistaken for a grant. New code should match on the outcome instead.
    pub fn into_result(self) -> Result<Option<AclDocument>, PodError> {
        match self {
            PolicyOutcome::Found(doc) => Ok(Some(doc)),
            PolicyOutcome::Missing => Ok(None),
            PolicyOutcome::Invalid {
                policy_path,
                reason,
            } => Err(match reason {
                InvalidPolicyReason::TooLarge(m) => PodError::PayloadTooLarge(m),
                InvalidPolicyReason::TooDeep(m) => PodError::BadRequest(m),
                other => PodError::AclParse(format!("{policy_path}: {other}")),
            }),
            PolicyOutcome::Unavailable {
                policy_path,
                detail,
            } => Err(PodError::Backend(format!(
                "ACL read failed at {policy_path}: {detail}"
            ))),
        }
    }

    /// Adapt a legacy `Result<Option<AclDocument>, PodError>` into a typed
    /// outcome.
    ///
    /// Used as the default [`AclResolver::resolve_policy`] body so an existing
    /// out-of-repo implementor that only supplies `find_effective_acl` keeps
    /// compiling and still reports fail-closed outcomes. The mapping is the
    /// inverse of [`Self::into_result`]; it cannot recover *which* ancestor a
    /// legacy resolver skipped, so such an implementor should override
    /// `resolve_policy` to get true per-level fidelity.
    pub fn from_legacy(result: Result<Option<AclDocument>, PodError>, resource_path: &str) -> Self {
        match result {
            Ok(Some(doc)) => PolicyOutcome::Found(doc),
            Ok(None) => PolicyOutcome::Missing,
            Err(PodError::PayloadTooLarge(m)) => PolicyOutcome::Invalid {
                policy_path: resource_path.to_string(),
                reason: InvalidPolicyReason::TooLarge(m),
            },
            Err(PodError::BadRequest(m)) => PolicyOutcome::Invalid {
                policy_path: resource_path.to_string(),
                reason: InvalidPolicyReason::TooDeep(m),
            },
            Err(PodError::AclParse(m)) => PolicyOutcome::Invalid {
                policy_path: resource_path.to_string(),
                reason: InvalidPolicyReason::Malformed(m),
            },
            Err(e) => PolicyOutcome::Unavailable {
                policy_path: resource_path.to_string(),
                detail: e.to_string(),
            },
        }
    }
}

/// The result of a single-level policy read, as observed by whichever backend
/// the tier uses.
///
/// Constructed by the caller from its own storage API and handed to
/// [`classify_policy_read`]. Deliberately carries no runtime types so the edge
/// tier can build it from a KV/R2 response.
#[derive(Debug)]
pub enum PolicyRead<'a> {
    /// The backend confirmed no `.acl` exists at this level. This is the ONLY
    /// input that permits the walk to continue upward.
    Absent,
    /// A `.acl` body was read.
    Present {
        /// Raw body bytes.
        body: &'a [u8],
        /// The stored `Content-Type`, used to decide whether to try Turtle.
        content_type: &'a str,
    },
    /// The read itself failed (I/O error, timeout, permission denied, a KV
    /// error that is not "key absent"). Never treat this as [`PolicyRead::Absent`].
    Failed(String),
}

/// What the walk should do after classifying one level.
#[derive(Debug)]
pub enum PolicyStep {
    /// Nothing governs this level; continue to the ancestor. Emitted only for
    /// [`PolicyRead::Absent`].
    Ascend,
    /// A terminal outcome was reached; stop the walk and return it.
    Settled(PolicyOutcome),
}

/// Classify one level of the WAC walk-up. Pure and runtime-free.
///
/// `policy_path` is the storage key that was read (used only for diagnostics).
/// `inherited` records whether this level is an ancestor container rather than
/// the resource's own sidecar; it is stamped onto a successfully parsed
/// document so the evaluator honours only `acl:default` rules (WAC §4.2).
///
/// A present body is tried as JSON-LD first, then — only when the stored
/// content type or the body itself looks like Turtle — as Turtle. A body that
/// satisfies neither is [`InvalidPolicyReason::Malformed`], **not** a miss:
/// this is precisely the case that used to inherit a broader ancestor grant.
pub fn classify_policy_read(
    policy_path: &str,
    read: PolicyRead<'_>,
    inherited: bool,
) -> PolicyStep {
    let (body, content_type) = match read {
        // Absence is a fact, and the only input that may inherit.
        PolicyRead::Absent => return PolicyStep::Ascend,
        // A failed read is an unknown, never a miss.
        PolicyRead::Failed(detail) => {
            return PolicyStep::Settled(PolicyOutcome::Unavailable {
                policy_path: policy_path.to_string(),
                detail,
            })
        }
        PolicyRead::Present { body, content_type } => (body, content_type),
    };

    let invalid = |reason: InvalidPolicyReason| {
        PolicyStep::Settled(PolicyOutcome::Invalid {
            policy_path: policy_path.to_string(),
            reason,
        })
    };

    // JSON-LD first, through the bounded parser. Bound violations are
    // terminal in their own right — an oversized or depth-bombed ACL must
    // never fall through to the ancestor.
    match parse_jsonld_acl_at(body, policy_path) {
        Ok(mut doc) => {
            doc.inherited = inherited;
            return PolicyStep::Settled(PolicyOutcome::Found(doc));
        }
        Err(PodError::PayloadTooLarge(m)) => return invalid(InvalidPolicyReason::TooLarge(m)),
        Err(PodError::BadRequest(m)) => return invalid(InvalidPolicyReason::TooDeep(m)),
        // Not JSON-LD — fall through to the Turtle attempt below.
        Err(_) => {}
    }

    let Ok(text) = std::str::from_utf8(body) else {
        return invalid(InvalidPolicyReason::NotUtf8);
    };

    let ct = content_type.to_ascii_lowercase();
    let looks_turtle = ct.starts_with("text/turtle")
        || ct.starts_with("application/turtle")
        || ct.starts_with("application/x-turtle");
    if !looks_turtle && !text.contains("@prefix") && !text.contains("acl:Authorization") {
        return invalid(InvalidPolicyReason::Malformed(
            "body is neither JSON-LD nor Turtle".into(),
        ));
    }

    match parse_turtle_acl(text) {
        Ok(mut doc) => {
            doc.inherited = inherited;
            PolicyStep::Settled(PolicyOutcome::Found(doc))
        }
        Err(PodError::PayloadTooLarge(m)) => invalid(InvalidPolicyReason::TooLarge(m)),
        Err(e) => invalid(InvalidPolicyReason::Malformed(e.to_string())),
    }
}

/// The storage key of the `.acl` sidecar governing `path`.
///
/// `/` maps to `/.acl`; any other path drops a trailing slash and appends
/// `.acl`, so `/a/b` → `/a/b.acl` and `/a/b/` → `/a/b.acl`.
#[must_use]
pub fn acl_sidecar_key(path: &str) -> String {
    if path == "/" {
        "/.acl".to_string()
    } else {
        format!("{}.acl", path.trim_end_matches('/'))
    }
}

/// Where a container's ACL document lives (SP-PAR-290).
///
/// A resource's ACL is always `<resource>.acl`. A container's is, by default,
/// the sibling `<container>.acl` (this crate's layout). The reference
/// JavaScript server keeps it inside the container as `<container>/.acl`. The
/// pod root is `/.acl` in every layout.
///
/// The default is [`AclLayout::Sidecar`], which is exactly the behaviour
/// before the setting existed, so nothing changes on upgrade.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum AclLayout {
    /// Read only `<container>.acl`; an inner `<container>/.acl` is ignored.
    #[default]
    Sidecar,
    /// Read only `<container>/.acl`; a sibling `<container>.acl` is ignored.
    /// For data roots laid out like the reference JavaScript server. Switching
    /// an existing sidecar data root to this layout drops every container ACL
    /// and widens access to the parent's grant.
    Inner,
    /// Read `<container>.acl` first and fall back to `<container>/.acl` only
    /// when the sidecar is absent. Both existing never denies by itself. The
    /// upgrade path for a data root that holds either form.
    Both,
}

impl AclLayout {
    /// The command-line / environment spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sidecar => "sidecar",
            Self::Inner => "inner",
            Self::Both => "both",
        }
    }
}

impl std::str::FromStr for AclLayout {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "sidecar" => Ok(Self::Sidecar),
            "inner" => Ok(Self::Inner),
            "both" => Ok(Self::Both),
            other => Err(format!(
                "unknown ACL layout {other:?}: expected sidecar, inner or both"
            )),
        }
    }
}

/// The storage keys that can hold the ACL of `path` at one level of the walk,
/// in reading order. `container` says whether this level is a container (the
/// request path ended in `/`, or it is an ancestor reached by walking up).
#[must_use]
pub fn acl_probe_keys(path: &str, container: bool, layout: AclLayout) -> Vec<String> {
    if path == "/" || path.is_empty() {
        return vec!["/.acl".to_string()];
    }
    let base = path.trim_end_matches('/');
    if !container {
        return vec![format!("{base}.acl")];
    }
    match layout {
        AclLayout::Sidecar => vec![format!("{base}.acl")],
        AclLayout::Inner => vec![format!("{base}/.acl")],
        AclLayout::Both => vec![format!("{base}.acl"), format!("{base}/.acl")],
    }
}

/// The ACL key the server writes and advertises (`Link: rel="acl"`) for
/// `path`: the inner form for a non-root container under
/// [`AclLayout::Inner`], the sidecar form otherwise.
#[must_use]
pub fn acl_advertised_key(path: &str, layout: AclLayout) -> String {
    let container = path == "/" || path.ends_with('/');
    if layout == AclLayout::Inner && container && path != "/" {
        return format!("{}/.acl", path.trim_end_matches('/'));
    }
    acl_sidecar_key(path)
}

/// True when `path` lies beneath an ACL or meta document: some directory
/// component (every component of a container key, all but the last of a
/// resource key) is itself an ACL or meta name (`.acl`, `.meta`, `x.acl`,
/// `x.meta`, any case). Nothing may be created there: a directory at an ACL
/// key makes the resolver's read of that key fail and locks the subtree out.
#[must_use]
pub fn path_beneath_sidecar(path: &str) -> bool {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let dirs = if path.ends_with('/') {
        &segs[..]
    } else {
        &segs[..segs.len().saturating_sub(1)]
    };
    dirs.iter().any(|s| {
        let l = s.to_ascii_lowercase();
        l.ends_with(".acl") || l.ends_with(".meta")
    })
}

/// The next ancestor to probe after `path`, or `None` once the root has been
/// probed.
#[must_use]
pub fn parent_container(path: &str) -> Option<String> {
    if path == "/" || path.is_empty() {
        return None;
    }
    let trimmed = path.trim_end_matches('/');
    Some(match trimmed.rfind('/') {
        Some(0) => "/".to_string(),
        Some(pos) => trimmed[..pos].to_string(),
        None => "/".to_string(),
    })
}

/// Resolve the effective policy for `resource_path` against a [`Storage`]
/// backend, honouring the typed outcomes.
///
/// Object-safe in its storage argument (`&dyn Storage`), so both the generic
/// [`StorageAclResolver`] and a server holding an `Arc<dyn Storage>` share this
/// one implementation rather than maintaining two copies of the walk that can
/// drift apart.
///
/// The walk ascends **only** while each level reports [`PolicyRead::Absent`]
/// ([`PodError::NotFound`] from the backend). Any other backend error, or any
/// `.acl` that fails to parse, terminates the walk with a failure outcome.
#[cfg(feature = "tokio-runtime")]
pub async fn resolve_policy_from_storage(
    storage: &dyn Storage,
    resource_path: &str,
) -> PolicyOutcome {
    resolve_policy_from_storage_with_base(storage, resource_path, None).await
}

/// As [`resolve_policy_from_storage`], resolving the IRIs inside the found
/// ACL against the configured pod origin (SP-PAR-288, SP-PAR-289), with the
/// default [`AclLayout::Sidecar`].
#[cfg(feature = "tokio-runtime")]
pub async fn resolve_policy_from_storage_with_base(
    storage: &dyn Storage,
    resource_path: &str,
    base: Option<&crate::wac::iri::AclBase>,
) -> PolicyOutcome {
    resolve_policy_with_layout(storage, resource_path, base, AclLayout::Sidecar).await
}

/// Read one ACL key. A directory at the key reads as absent, never as an
/// error (SP-PAR-290 (d)); any other failure, including a permission error,
/// stays a failure and denies.
#[cfg(feature = "tokio-runtime")]
async fn read_acl_key(
    storage: &dyn Storage,
    key: &str,
) -> Result<Option<(bytes::Bytes, String)>, String> {
    match storage.get(key).await {
        Ok((body, meta)) => Ok(Some((body, meta.content_type))),
        Err(PodError::NotFound(_)) => Ok(None),
        Err(e) => {
            if storage.is_directory(key).await {
                Ok(None)
            } else {
                Err(e.to_string())
            }
        }
    }
}

/// As [`resolve_policy_from_storage_with_base`] under an explicit
/// [`AclLayout`]. With [`AclLayout::Both`] the sidecar is read first and the
/// inner key only when the sidecar is absent: an unreadable or malformed
/// sidecar denies, and two present documents never deny merely because both
/// exist.
#[cfg(feature = "tokio-runtime")]
pub async fn resolve_policy_with_layout(
    storage: &dyn Storage,
    resource_path: &str,
    base: Option<&crate::wac::iri::AclBase>,
    layout: AclLayout,
) -> PolicyOutcome {
    let mut path = resource_path.to_string();
    // The first iteration probes the resource's OWN ACL (a direct ACL); every
    // later iteration walks up to an ANCESTOR container, whose ACL is
    // INHERITED and honours only `acl:default` (WAC section 4.2).
    let mut inherited = false;
    let mut container = resource_path.ends_with('/');
    loop {
        for acl_key in acl_probe_keys(&path, container, layout) {
            let got = read_acl_key(storage, &acl_key).await;
            let read = match &got {
                Ok(Some((body, ct))) => PolicyRead::Present {
                    body,
                    content_type: ct,
                },
                Ok(None) => PolicyRead::Absent,
                Err(e) => PolicyRead::Failed(e.clone()),
            };
            match classify_policy_read(&acl_key, read, inherited) {
                PolicyStep::Settled(PolicyOutcome::Found(doc)) => {
                    return PolicyOutcome::Found(match base {
                        Some(b) => b.resolve_document(&doc, &acl_key),
                        None => doc,
                    });
                }
                PolicyStep::Settled(outcome) => return outcome,
                PolicyStep::Ascend => {}
            }
        }
        match parent_container(&path) {
            Some(parent) => {
                inherited = true;
                container = true;
                path = parent;
            }
            None => return PolicyOutcome::Missing,
        }
    }
}

/// Resolves the effective ACL document for a resource using the WAC walk-up-the-tree algorithm.
///
/// Starting at the resource path, the resolver looks for an `.acl` sidecar at each ancestor
/// container up to the root. The first parseable ACL document found (JSON-LD or Turtle) is
/// returned. If no ACL is found at any level, returns `Ok(None)` -- callers must deny access
/// when no ACL exists (deny-by-default).
///
/// Prefer [`resolve_policy`](AclResolver::resolve_policy) in new code: it
/// distinguishes a genuine miss from an unparseable or unreadable policy, which
/// `find_effective_acl` cannot express (see the [module docs](self)).
#[async_trait]
pub trait AclResolver: Send + Sync {
    /// Locate the nearest ACL document that governs `resource_path`.
    async fn find_effective_acl(
        &self,
        resource_path: &str,
    ) -> Result<Option<AclDocument>, PodError>;

    /// Resolve the effective policy with typed outcomes (ADR-2005).
    ///
    /// The default implementation adapts [`Self::find_effective_acl`] via
    /// [`PolicyOutcome::from_legacy`], so an existing implementor keeps
    /// compiling and stays fail-closed. Implementors whose backend can tell a
    /// missing key from a failed read should override this to report the
    /// distinction faithfully.
    async fn resolve_policy(&self, resource_path: &str) -> PolicyOutcome {
        PolicyOutcome::from_legacy(self.find_effective_acl(resource_path).await, resource_path)
    }
}

/// `AclResolver` backed by a [`Storage`] implementation.
#[cfg(feature = "tokio-runtime")]
pub struct StorageAclResolver<S: Storage> {
    storage: std::sync::Arc<S>,
    base: Option<crate::wac::iri::AclBase>,
    layout: AclLayout,
}

#[cfg(feature = "tokio-runtime")]
impl<S: Storage> StorageAclResolver<S> {
    /// Wrap a shared storage handle in a resolver.
    pub fn new(storage: std::sync::Arc<S>) -> Self {
        Self {
            storage,
            base: None,
            layout: AclLayout::Sidecar,
        }
    }

    /// Read container ACLs under `layout` (default [`AclLayout::Sidecar`]).
    #[must_use]
    pub fn with_layout(mut self, layout: AclLayout) -> Self {
        self.layout = layout;
        self
    }

    /// Resolve ACL IRIs against the configured pod origin (see
    /// [`AclBase`](crate::wac::iri::AclBase)). Without it absolute targets
    /// fail closed.
    #[must_use]
    pub fn with_base(mut self, base: Option<crate::wac::iri::AclBase>) -> Self {
        self.base = base;
        self
    }
}

#[cfg(feature = "tokio-runtime")]
#[async_trait]
impl<S: Storage> AclResolver for StorageAclResolver<S> {
    /// Walk from `resource_path` toward `/`, returning the first valid `.acl` sidecar found.
    ///
    /// A malformed or unreadable `.acl` now yields `Err` rather than silently
    /// inheriting the next ancestor's grant — see [`PolicyOutcome::into_result`].
    async fn find_effective_acl(
        &self,
        resource_path: &str,
    ) -> Result<Option<AclDocument>, PodError> {
        self.resolve_policy(resource_path).await.into_result()
    }

    async fn resolve_policy(&self, resource_path: &str) -> PolicyOutcome {
        resolve_policy_with_layout(
            &*self.storage,
            resource_path,
            self.base.as_ref(),
            self.layout,
        )
        .await
    }
}

#[cfg(test)]
mod layout_tests {
    use super::*;

    #[test]
    fn probe_keys_per_layout() {
        use AclLayout::{Both, Inner, Sidecar};
        // The root is `/.acl` everywhere; a resource is `<r>.acl` everywhere.
        for l in [Sidecar, Inner, Both] {
            assert_eq!(acl_probe_keys("/", true, l), ["/.acl"]);
            assert_eq!(acl_probe_keys("/a/b.txt", false, l), ["/a/b.txt.acl"]);
        }
        assert_eq!(acl_probe_keys("/docs/", true, Sidecar), ["/docs.acl"]);
        assert_eq!(acl_probe_keys("/docs", true, Inner), ["/docs/.acl"]);
        assert_eq!(
            acl_probe_keys("/docs/", true, Both),
            ["/docs.acl", "/docs/.acl"]
        );
    }

    #[test]
    fn advertised_key_follows_the_layout() {
        use AclLayout::{Both, Inner, Sidecar};
        assert_eq!(acl_advertised_key("/docs/", Sidecar), "/docs.acl");
        assert_eq!(acl_advertised_key("/docs/", Both), "/docs.acl");
        assert_eq!(acl_advertised_key("/docs/", Inner), "/docs/.acl");
        assert_eq!(acl_advertised_key("/", Inner), "/.acl");
        assert_eq!(acl_advertised_key("/docs/a.txt", Inner), "/docs/a.txt.acl");
    }

    #[test]
    fn layout_parses_and_defaults_to_sidecar() {
        assert_eq!(AclLayout::default(), AclLayout::Sidecar);
        assert_eq!("Inner".parse::<AclLayout>(), Ok(AclLayout::Inner));
        assert_eq!(" both ".parse::<AclLayout>(), Ok(AclLayout::Both));
        assert!("nested".parse::<AclLayout>().is_err());
    }

    #[test]
    fn beneath_an_acl_or_meta_document() {
        for p in [
            "/docs.acl/x",
            "/docs/.acl/x",
            "/docs/a.txt.acl/x",
            "/a.meta/x",
            "/.meta/x",
            "/docs.ACL/x",
            "/docs.acl/",
            "/x/.acl/y/z",
        ] {
            assert!(path_beneath_sidecar(p), "{p}");
        }
        for p in [
            "/docs.acl",
            "/docs/.acl",
            "/docs/a.txt.acl",
            "/docs/a.txt",
            "/docs/",
            "/",
            "/acl/x",
            "/docs.aclx/x",
        ] {
            assert!(!path_beneath_sidecar(p), "{p}");
        }
    }
}
