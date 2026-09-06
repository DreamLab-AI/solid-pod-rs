//! Web Access Control evaluator.
//!
//! Parses JSON-LD / Turtle ACL documents and evaluates whether a given
//! agent URI is granted a specific access mode on a resource path.
//! WAC 2.0 conditions (client / issuer gates) are supported via the
//! `conditions` submodule.
//!
//! Reference: <https://solid.github.io/web-access-control-spec/> +
//! <https://webacl.org/secure-access-conditions/>

use serde::{Deserialize, Serialize};

use crate::error::PodError;

// ---------------------------------------------------------------------------
// Parser DoS bounds.
//
// The ACL parsers run on untrusted bodies uploaded by external clients.
// Without bounds, a pathological document can either exhaust memory
// (oversize Turtle) or blow the parser stack (deeply nested JSON-LD).
// JSS's `n3`-based parser is similarly bounded; we match for parity and
// defence-in-depth.
// ---------------------------------------------------------------------------

/// Maximum byte length of an ACL document body. WAC 2.0 ACLs are flat
/// declarative documents; 1 MiB is generous and prevents O(n²) parser
/// blowup. Configurable at parse time via `JSS_MAX_ACL_BYTES`.
pub const MAX_ACL_BYTES: usize = 1_048_576;

/// Maximum JSON-LD nesting depth. Solid ACLs are ≤4 levels deep in
/// practice; 32 is a generous fail-closed cap against depth bombs.
/// Configurable via `JSS_MAX_ACL_JSON_DEPTH`.
pub const MAX_ACL_JSON_DEPTH: usize = 32;

/// Count the structural nesting depth of a JSON byte slice without
/// parsing it. Ignores braces/brackets inside string literals. Fails
/// fast as soon as `max` is exceeded so pathological documents never
/// reach `serde_json`, which allocates stack proportional to depth.
fn check_json_depth(body: &[u8], max: usize) -> Result<(), PodError> {
    let mut depth: usize = 0;
    let mut in_str = false;
    let mut esc = false;
    for &b in body {
        if in_str {
            if esc {
                esc = false;
            } else if b == b'\\' {
                esc = true;
            } else if b == b'"' {
                in_str = false;
            }
            continue;
        }
        match b {
            b'"' => in_str = true,
            b'{' | b'[' => {
                depth = depth.saturating_add(1);
                if depth > max {
                    return Err(PodError::BadRequest(format!(
                        "ACL JSON depth exceeds {max}"
                    )));
                }
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    Ok(())
}

/// Parse a JSON-LD ACL body with byte and depth bounds enforced.
///
/// The resolver in [`StorageAclResolver`] routes through this helper so
/// fuzzed or malicious ACLs are rejected before `serde_json` is invoked.
/// To supply explicit limits, use [`parse_jsonld_acl_with_limits`].
pub fn parse_jsonld_acl(body: &[u8]) -> Result<AclDocument, PodError> {
    let limit = std::env::var("JSS_MAX_ACL_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(MAX_ACL_BYTES);
    let depth_limit = std::env::var("JSS_MAX_ACL_JSON_DEPTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(MAX_ACL_JSON_DEPTH);
    parse_jsonld_acl_with_limits(body, limit, depth_limit)
}

/// Parse a JSON-LD ACL body with caller-supplied byte and depth limits.
///
/// Equivalent to [`parse_jsonld_acl`] but accepts limits as parameters
/// instead of reading from environment variables. Returns
/// `PodError::PayloadTooLarge` (HTTP 413 equivalent) when
/// `body.len() > max_bytes`.
pub fn parse_jsonld_acl_with_limits(
    body: &[u8],
    max_bytes: usize,
    max_depth: usize,
) -> Result<AclDocument, PodError> {
    if body.len() > max_bytes {
        return Err(PodError::PayloadTooLarge(format!(
            "ACL body exceeds {max_bytes} bytes"
        )));
    }
    check_json_depth(body, max_depth)?;
    serde_json::from_slice::<AclDocument>(body)
        .map_err(|e| PodError::AclParse(format!("JSON-LD ACL parse: {e}")))
}

// Sub-modules — each kept under 500 LOC.
pub mod anchor;
pub mod client;
pub mod conditions;
pub mod document;
pub mod evaluator;
pub mod issuer;
pub mod origin;
pub mod parser;
pub mod payment;
pub mod resolver;
pub mod serializer;

// ---------------------------------------------------------------------------
// Re-exports (preserve the pre-split public surface verbatim so no
// consumer import breaks).
// ---------------------------------------------------------------------------

pub use anchor::{anchor_mode_of, AnchorMode, ProvenanceAnchorBody, ProvenanceAnchorEvaluator};
pub use client::{ClientConditionBody, ClientConditionEvaluator};
pub use conditions::{
    validate_acl_document, validate_for_write, Condition, ConditionDispatcher, ConditionOutcome,
    ConditionRegistry, EmptyDispatcher, RequestContext, UnsupportedCondition,
};
pub use document::{AclAuthorization, AclDocument, IdOrIds, IdRef};
pub use evaluator::{
    evaluate_access, evaluate_access_ctx, evaluate_access_ctx_with_registry,
    evaluate_access_with_groups, granted_payment_cost, GroupMembership, StaticGroupMembership,
};
pub use issuer::{IssuerConditionBody, IssuerConditionEvaluator};
pub use origin::{check_origin, extract_origin_patterns, Origin, OriginDecision, OriginPattern};
pub use parser::{parse_turtle_acl, parse_turtle_acl_with_limit};
pub use payment::{total_payment_cost, PaymentConditionBody, PaymentConditionEvaluator};
pub use resolver::{
    acl_sidecar_key, classify_policy_read, parent_container, AclResolver, InvalidPolicyReason,
    PolicyOutcome, PolicyRead, PolicyStep,
};
#[cfg(feature = "tokio-runtime")]
pub use resolver::{resolve_policy_from_storage, StorageAclResolver};
pub use serializer::serialize_turtle_acl;

/// Access modes defined by WAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccessMode {
    Read,
    Write,
    Append,
    Control,
}

pub const ALL_MODES: &[AccessMode] = &[
    AccessMode::Read,
    AccessMode::Write,
    AccessMode::Append,
    AccessMode::Control,
];

pub(crate) fn map_mode(mode_ref: &str) -> &'static [AccessMode] {
    match mode_ref {
        "acl:Read" | "http://www.w3.org/ns/auth/acl#Read" => &[AccessMode::Read],
        "acl:Write" | "http://www.w3.org/ns/auth/acl#Write" => {
            &[AccessMode::Write, AccessMode::Append]
        }
        "acl:Append" | "http://www.w3.org/ns/auth/acl#Append" => &[AccessMode::Append],
        "acl:Control" | "http://www.w3.org/ns/auth/acl#Control" => &[AccessMode::Control],
        _ => &[],
    }
}

pub fn method_to_mode(method: &str) -> AccessMode {
    match method.to_uppercase().as_str() {
        "GET" | "HEAD" => AccessMode::Read,
        "PUT" | "DELETE" | "PATCH" => AccessMode::Write,
        "POST" => AccessMode::Append,
        _ => AccessMode::Read,
    }
}

pub fn mode_name(mode: AccessMode) -> &'static str {
    match mode {
        AccessMode::Read => "read",
        AccessMode::Write => "write",
        AccessMode::Append => "append",
        AccessMode::Control => "control",
    }
}

// ---------------------------------------------------------------------------
// Sidecar-enforcement policy — SINGLE SOURCE OF TRUTH.
//
// An `.acl` / `.meta` sidecar governs *another* resource's permissions, so
// WAC §4.3.5 requires `acl:Control` on the PROTECTED resource for ANY
// access to the sidecar — read AND write. Encoding that rule once, in
// wasm-safe core, keeps every runtime (native `solid-pod-rs-server`,
// CF-Workers pods, downstream forums) on the same decision so the READ
// and WRITE elevation cannot drift apart per-consumer.
// ---------------------------------------------------------------------------

/// Strip a `.acl` / `.meta` suffix from `path`, returning the protected
/// resource the sidecar governs. `/victim/.acl` → `/victim/`,
/// `/a/b.acl` → `/a/b`, `/.acl` → `/`, `.acl` → `/`. Returns `None` when
/// `path` is not an ACL/meta sidecar.
///
/// Pure and I/O-free (wasm-safe). This is THE canonical
/// "is-this-a-sidecar / what-does-it-govern" predicate; do not re-derive
/// it per runtime.
pub fn protected_resource_for_acl(path: &str) -> Option<String> {
    for suffix in [".acl", ".meta"] {
        if let Some(stripped) = path.strip_suffix(suffix) {
            // `/.acl` and `/dir/.acl` strip to `/` and `/dir/`
            // respectively (container ACLs); `/a/b.acl` strips to the
            // resource `/a/b`. A bare `.acl` (no leading slash) strips to
            // the empty string and maps to the pod root `/`.
            if stripped.is_empty() {
                return Some("/".to_string());
            }
            return Some(stripped.to_string());
        }
    }
    None
}

/// Canonical sidecar-elevation decision for BOTH reads and writes.
///
/// Maps a `(path, base_mode)` access request to the `(resource, mode)` the
/// WAC check must actually run against:
///
/// * When `path` is an `.acl`/`.meta` sidecar
///   ([`protected_resource_for_acl`] is `Some(p)`), the check elevates to
///   `(p, AccessMode::Control)` — because reading or writing the sidecar
///   discloses or rewrites the full authorization graph of `p`, which WAC
///   §4.3.5 gates on `acl:Control` of `p`, never the base mode on the
///   sidecar path.
/// * Otherwise the request passes through unchanged as `(path, base_mode)`.
///
/// Callers pass `base_mode = AccessMode::Read` for a read and the request's
/// write mode (`Write`/`Append`/`Control`) for a write; the elevation
/// collapses either to `Control` on the governed resource. This is the ONE
/// function the native server's read/write enforcement and any wasm runtime
/// share, so the sidecar rule has a single source of truth. Pure and
/// I/O-free (wasm-safe).
pub fn effective_acl_target(path: &str, base_mode: AccessMode) -> (String, AccessMode) {
    match protected_resource_for_acl(path) {
        Some(protected) => (protected, AccessMode::Control),
        None => (path.to_string(), base_mode),
    }
}

/// Build a `WAC-Allow` header value (WAC 1.x — no condition dispatcher).
///
/// Advertises static capabilities for the authenticated agent and for
/// anonymous (public) access. The origin gate is a per-request concern,
/// so we evaluate without an origin and leave any origin-gated rules to
/// reject at request time.
pub fn wac_allow_header(
    acl_doc: Option<&AclDocument>,
    agent_uri: Option<&str>,
    resource_path: &str,
) -> String {
    let mut user_modes = Vec::new();
    let mut public_modes = Vec::new();
    for mode in ALL_MODES {
        if evaluate_access(acl_doc, agent_uri, resource_path, *mode, None) {
            user_modes.push(mode_name(*mode));
        }
        if evaluate_access(acl_doc, None, resource_path, *mode, None) {
            public_modes.push(mode_name(*mode));
        }
    }
    format!(
        "user=\"{}\", public=\"{}\"",
        user_modes.join(" "),
        public_modes.join(" ")
    )
}

/// WAC 2.0 — build a `WAC-Allow` header omitting modes whose conditions
/// are unsatisfied in the current request context.
pub fn wac_allow_header_with_dispatcher(
    acl_doc: Option<&AclDocument>,
    ctx: &RequestContext<'_>,
    resource_path: &str,
    groups: &dyn GroupMembership,
    dispatcher: &dyn ConditionDispatcher,
) -> String {
    let mut user_modes = Vec::new();
    let mut public_modes = Vec::new();
    let public_ctx = RequestContext {
        web_id: None,
        client_id: ctx.client_id,
        issuer: ctx.issuer,
        payment_balance_sats: ctx.payment_balance_sats,
    };
    for mode in ALL_MODES {
        if evaluate_access_ctx(acl_doc, ctx, resource_path, *mode, None, groups, dispatcher) {
            user_modes.push(mode_name(*mode));
        }
        if evaluate_access_ctx(
            acl_doc,
            &public_ctx,
            resource_path,
            *mode,
            None,
            groups,
            dispatcher,
        ) {
            public_modes.push(mode_name(*mode));
        }
    }
    format!(
        "user=\"{}\", public=\"{}\"",
        user_modes.join(" "),
        public_modes.join(" ")
    )
}

// ---------------------------------------------------------------------------
// Lightweight metric counter for the acl-origin gate. When a proper
// metrics facade lands (F1/F2) this module will be swapped for its
// `Counter` type; for now we expose a minimal atomic compatible with
// whichever facade arrives.
// ---------------------------------------------------------------------------
#[cfg(feature = "acl-origin")]
pub mod metrics {
    use std::sync::atomic::AtomicU64;

    /// Total number of WAC evaluations denied by the `acl:origin` gate.
    pub static ACL_ORIGIN_REJECTED_TOTAL: AtomicU64 = AtomicU64::new(0);
}

// ---------------------------------------------------------------------------
// Tests — retained from pre-split wac.rs. Exercise JSON-LD round-trip,
// Turtle parse/serialise, and the WAC-Allow header shape.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_doc(graph: Vec<AclAuthorization>) -> AclDocument {
        AclDocument {
            context: None,
            graph: Some(graph),
            inherited: false,
        }
    }

    fn public_read(path: &str) -> AclAuthorization {
        AclAuthorization {
            id: None,
            r#type: None,
            agent: None,
            agent_class: Some(IdOrIds::Single(IdRef {
                id: "foaf:Agent".into(),
            })),
            agent_group: None,
            origin: None,
            access_to: Some(IdOrIds::Single(IdRef { id: path.into() })),
            default: None,
            mode: Some(IdOrIds::Single(IdRef {
                id: "acl:Read".into(),
            })),
            condition: None,
        }
    }

    #[test]
    fn no_acl_denies_all() {
        assert!(!evaluate_access(None, None, "/foo", AccessMode::Read, None));
    }

    #[test]
    fn public_read_grants_anonymous() {
        let doc = make_doc(vec![public_read("/")]);
        assert!(evaluate_access(
            Some(&doc),
            None,
            "/",
            AccessMode::Read,
            None
        ));
    }

    #[test]
    fn write_implies_append() {
        let auth = AclAuthorization {
            id: None,
            r#type: None,
            agent: Some(IdOrIds::Single(IdRef {
                id: "did:nostr:owner".into(),
            })),
            agent_class: None,
            agent_group: None,
            origin: None,
            access_to: Some(IdOrIds::Single(IdRef { id: "/".into() })),
            default: None,
            mode: Some(IdOrIds::Single(IdRef {
                id: "acl:Write".into(),
            })),
            condition: None,
        };
        let doc = make_doc(vec![auth]);
        assert!(evaluate_access(
            Some(&doc),
            Some("did:nostr:owner"),
            "/",
            AccessMode::Append,
            None,
        ));
    }

    #[test]
    fn method_mapping() {
        assert_eq!(method_to_mode("GET"), AccessMode::Read);
        assert_eq!(method_to_mode("PUT"), AccessMode::Write);
        assert_eq!(method_to_mode("POST"), AccessMode::Append);
    }

    #[test]
    fn wac_allow_shape() {
        let doc = make_doc(vec![public_read("/")]);
        let hdr = wac_allow_header(Some(&doc), None, "/");
        assert_eq!(hdr, "user=\"read\", public=\"read\"");
    }

    #[test]
    fn turtle_acl_round_trip_parses_basic_rules() {
        let ttl = r#"
            @prefix acl: <http://www.w3.org/ns/auth/acl#> .
            @prefix foaf: <http://xmlns.com/foaf/0.1/> .

            <#public> a acl:Authorization ;
                acl:agentClass foaf:Agent ;
                acl:accessTo </> ;
                acl:mode acl:Read .
        "#;
        let doc = parse_turtle_acl(ttl).unwrap();
        assert!(evaluate_access(
            Some(&doc),
            None,
            "/",
            AccessMode::Read,
            None
        ));
        assert!(!evaluate_access(
            Some(&doc),
            None,
            "/",
            AccessMode::Write,
            None
        ));
    }

    #[test]
    fn turtle_acl_with_owner_grants_write() {
        let ttl = r#"
            @prefix acl: <http://www.w3.org/ns/auth/acl#> .

            <#owner> a acl:Authorization ;
                acl:agent <did:nostr:owner> ;
                acl:accessTo </> ;
                acl:default </> ;
                acl:mode acl:Write, acl:Control .
        "#;
        let doc = parse_turtle_acl(ttl).unwrap();
        assert!(evaluate_access(
            Some(&doc),
            Some("did:nostr:owner"),
            "/foo",
            AccessMode::Write,
            None,
        ));
    }

    #[test]
    fn serialize_turtle_acl_emits_prefixes_and_rules() {
        let doc = make_doc(vec![public_read("/")]);
        let out = serialize_turtle_acl(&doc);
        assert!(out.contains("@prefix acl:"));
        assert!(out.contains("acl:Authorization"));
        assert!(out.contains("acl:mode"));
    }

    // ----- Sprint 12: parameterised JSON-LD size cap ----------------------

    #[test]
    fn jsonld_acl_with_limits_rejects_oversized() {
        let body = b"{\"@context\": \"https://www.w3.org/ns/auth/acl\"}";
        let err = parse_jsonld_acl_with_limits(body, 10, 32).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("payload too large") || msg.contains("exceeds"),
            "oversized JSON-LD should be rejected: {msg}"
        );
    }

    #[test]
    fn jsonld_acl_with_limits_accepts_within_bounds() {
        // Minimal valid JSON-LD ACL (empty graph).
        let body = b"{}";
        let doc = parse_jsonld_acl_with_limits(body, 1024, 32).unwrap();
        assert!(doc.graph.is_none());
    }

    // ----- Sidecar-enforcement policy (single source of truth) ------------

    #[test]
    fn protected_resource_for_acl_strips_suffixes() {
        assert_eq!(
            protected_resource_for_acl("/victim/.acl").as_deref(),
            Some("/victim/")
        );
        assert_eq!(
            protected_resource_for_acl("/a/b.acl").as_deref(),
            Some("/a/b")
        );
        assert_eq!(protected_resource_for_acl("/.acl").as_deref(), Some("/"));
        assert_eq!(
            protected_resource_for_acl("/a/b.meta").as_deref(),
            Some("/a/b")
        );
        assert_eq!(
            protected_resource_for_acl("/dir/.meta").as_deref(),
            Some("/dir/")
        );
        assert_eq!(protected_resource_for_acl("/.meta").as_deref(), Some("/"));
        assert_eq!(protected_resource_for_acl(".acl").as_deref(), Some("/"));
        // Not a sidecar.
        assert_eq!(protected_resource_for_acl("/a/b").as_deref(), None);
        assert_eq!(protected_resource_for_acl("/foo.aclx").as_deref(), None);
    }

    /// GOLDEN CONFORMANCE VECTORS for [`effective_acl_target`].
    ///
    /// Every runtime that enforces WAC (native server, CF-Workers pod,
    /// downstream forum) MUST reproduce this table exactly: `(path,
    /// base_mode)` → `(resource, mode)`. The sidecar rows cover both READ
    /// and WRITE elevating to `Control` on the governed resource — the
    /// invariant a downstream consumer previously got wrong on the READ
    /// side.
    #[test]
    fn effective_acl_target_golden_conformance_vectors() {
        use AccessMode::{Append, Control, Read, Write};
        // (input path, base_mode) -> (expected resource, expected mode)
        let vectors: &[(&str, AccessMode, &str, AccessMode)] = &[
            // Ordinary resource: read / write / append pass through unchanged.
            ("/foo", Read, "/foo", Read),
            ("/foo", Write, "/foo", Write),
            ("/foo", Append, "/foo", Append),
            ("/dir/", Read, "/dir/", Read),
            ("/dir/", Write, "/dir/", Write),
            // `.acl` sidecar: READ *and* WRITE both elevate to Control on /foo.
            ("/foo.acl", Read, "/foo", Control),
            ("/foo.acl", Write, "/foo", Control),
            ("/foo.acl", Append, "/foo", Control),
            // Container `.acl`: /dir/.acl -> (/dir/, Control).
            ("/dir/.acl", Read, "/dir/", Control),
            ("/dir/.acl", Write, "/dir/", Control),
            // Root `.acl`: /.acl -> (/, Control).
            ("/.acl", Read, "/", Control),
            ("/.acl", Write, "/", Control),
            // `.meta` behaves identically to `.acl`.
            ("/foo.meta", Read, "/foo", Control),
            ("/foo.meta", Write, "/foo", Control),
            ("/dir/.meta", Read, "/dir/", Control),
            ("/.meta", Write, "/", Control),
        ];
        for (path, base, exp_res, exp_mode) in vectors {
            let (res, mode) = effective_acl_target(path, *base);
            assert_eq!(&res, exp_res, "resource for ({path:?}, {base:?})");
            assert_eq!(mode, *exp_mode, "mode for ({path:?}, {base:?})");
        }
    }

    #[test]
    fn effective_acl_target_non_sidecar_is_identity() {
        for mode in ALL_MODES {
            let (res, out) = effective_acl_target("/data/note.ttl", *mode);
            assert_eq!(res, "/data/note.ttl");
            assert_eq!(out, *mode);
        }
    }
}
