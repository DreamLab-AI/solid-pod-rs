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
pub fn parse_jsonld_acl(body: &[u8]) -> Result<AclDocument, PodError> {
    let limit = std::env::var("JSS_MAX_ACL_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(MAX_ACL_BYTES);
    if body.len() > limit {
        return Err(PodError::BadRequest(format!(
            "ACL body exceeds {limit} bytes"
        )));
    }
    let depth_limit = std::env::var("JSS_MAX_ACL_JSON_DEPTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(MAX_ACL_JSON_DEPTH);
    check_json_depth(body, depth_limit)?;
    serde_json::from_slice::<AclDocument>(body)
        .map_err(|e| PodError::AclParse(format!("JSON-LD ACL parse: {e}")))
}

// Sub-modules — each kept under 500 LOC.
pub mod client;
pub mod conditions;
pub mod document;
pub mod evaluator;
pub mod issuer;
pub mod origin;
pub mod parser;
pub mod resolver;
pub mod serializer;

// ---------------------------------------------------------------------------
// Re-exports (preserve the pre-split public surface verbatim so no
// consumer import breaks).
// ---------------------------------------------------------------------------

pub use client::{ClientConditionBody, ClientConditionEvaluator};
pub use conditions::{
    validate_for_write, Condition, ConditionDispatcher, ConditionOutcome, ConditionRegistry,
    EmptyDispatcher, RequestContext, UnsupportedCondition,
};
pub use document::{AclAuthorization, AclDocument, IdOrIds, IdRef};
pub use evaluator::{
    evaluate_access, evaluate_access_ctx, evaluate_access_ctx_with_registry,
    evaluate_access_with_groups, GroupMembership, StaticGroupMembership,
};
pub use issuer::{IssuerConditionBody, IssuerConditionEvaluator};
pub use origin::{check_origin, extract_origin_patterns, Origin, OriginDecision, OriginPattern};
pub use parser::parse_turtle_acl;
pub use resolver::{AclResolver, StorageAclResolver};
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
            mode: Some(IdOrIds::Single(IdRef { id: "acl:Read".into() })),
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
        assert!(evaluate_access(Some(&doc), None, "/", AccessMode::Read, None));
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
        assert!(evaluate_access(Some(&doc), None, "/", AccessMode::Read, None));
        assert!(!evaluate_access(Some(&doc), None, "/", AccessMode::Write, None));
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
}
