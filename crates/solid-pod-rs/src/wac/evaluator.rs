//! Core WAC evaluation engine.
//!
//! Shared between WAC 1.x (`evaluate_access`) and WAC 2.0
//! (`evaluate_access_ctx`). The 1.x entry point is a thin shim that
//! constructs an empty request context and an empty dispatcher so any
//! rule bearing conditions fails closed.

use crate::wac::conditions::{
    ConditionDispatcher, ConditionOutcome, ConditionRegistry, EmptyDispatcher, RequestContext,
};
use crate::wac::document::{get_ids, AclAuthorization, AclDocument};
use crate::wac::origin;
use crate::wac::{map_mode, AccessMode};

/// Synchronous group membership lookup used by
/// `evaluate_access_with_groups` and by condition evaluators
/// (`acl:clientGroup`, `acl:issuerGroup`).
///
/// Implementors resolve a group IRI (typically a `vcard:Group`
/// document) against a subject URI and return whether the subject is
/// a member. The default no-op implementation returns `false` for
/// every call.
pub trait GroupMembership {
    fn is_member(&self, group_iri: &str, agent_uri: &str) -> bool;
}

pub(crate) struct NoGroupMembership;
impl GroupMembership for NoGroupMembership {
    fn is_member(&self, _group_iri: &str, _agent_uri: &str) -> bool {
        false
    }
}

/// Static group-membership resolver used in tests and by pods that
/// resolve group documents eagerly into an in-memory map.
#[derive(Debug, Default, Clone)]
pub struct StaticGroupMembership {
    pub groups: std::collections::HashMap<String, Vec<String>>,
}

impl StaticGroupMembership {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, group_iri: impl Into<String>, members: Vec<String>) {
        self.groups.insert(group_iri.into(), members);
    }
}

impl GroupMembership for StaticGroupMembership {
    fn is_member(&self, group_iri: &str, agent_uri: &str) -> bool {
        self.groups
            .get(group_iri)
            .map(|m| m.iter().any(|x| x == agent_uri))
            .unwrap_or(false)
    }
}

pub(crate) fn normalize_path(path: &str) -> String {
    let stripped = path.strip_prefix("./").or_else(|| path.strip_prefix('.'));
    let base = match stripped {
        Some("") => "/".to_string(),
        Some(s) if !s.starts_with('/') => format!("/{s}"),
        Some(s) => s.to_string(),
        None => path.to_string(),
    };
    let trimmed = base.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

pub(crate) fn path_matches(rule_path: &str, resource_path: &str, is_default: bool) -> bool {
    let rule = normalize_path(rule_path);
    let resource = normalize_path(resource_path);
    if resource == rule {
        return true;
    }
    // `acl:accessTo` covers exact match plus direct children of a
    // container target — NOT deep descendants (WAC §4.2; cf. tests
    // `access_to_does_not_inherit_by_itself` and
    // `access_to_on_container_covers_direct_children`).
    // `acl:default`, by contrast, applies recursively.
    if !is_default {
        let prefix = if rule == "/" {
            String::from("/")
        } else {
            format!("{rule}/")
        };
        if let Some(rest) = resource.strip_prefix(&prefix) {
            return !rest.is_empty() && !rest.contains('/');
        }
        return false;
    }
    if rule == "/" {
        resource.starts_with('/')
    } else {
        resource.starts_with(&format!("{rule}/"))
    }
}

pub(crate) fn get_modes(auth: &AclAuthorization) -> Vec<AccessMode> {
    let mut modes = Vec::new();
    for mode_ref in get_ids(&auth.mode) {
        modes.extend_from_slice(map_mode(mode_ref));
    }
    modes
}

fn agent_matches_with_groups(
    auth: &AclAuthorization,
    agent_uri: Option<&str>,
    groups: &dyn GroupMembership,
) -> bool {
    let agents = get_ids(&auth.agent);
    if let Some(uri) = agent_uri {
        if agents.contains(&uri) {
            return true;
        }
    }
    for cls in get_ids(&auth.agent_class) {
        if cls == "foaf:Agent" || cls == "http://xmlns.com/foaf/0.1/Agent" {
            return true;
        }
        if agent_uri.is_some()
            && (cls == "acl:AuthenticatedAgent"
                || cls == "http://www.w3.org/ns/auth/acl#AuthenticatedAgent")
        {
            return true;
        }
    }
    if let Some(uri) = agent_uri {
        for group_iri in get_ids(&auth.agent_group) {
            if groups.is_member(group_iri, uri) {
                return true;
            }
        }
    }
    false
}

/// Evaluate whether access should be granted (WAC 1.x entry point).
///
/// The `request_origin` parameter carries the RFC 6454 origin from the
/// HTTP `Origin:` header; pass `None` for request paths that have no
/// origin context (e.g. server-to-server calls or tests). When the
/// `acl-origin` feature is enabled, any ACL that declares `acl:origin`
/// triples gates access on the request origin per WAC §4.3.
///
/// Note: WAC 2.0 documents with `acl:condition` triples will fail
/// closed under this entry point because it wires an `EmptyDispatcher`.
/// Use `evaluate_access_ctx` for WAC 2.0 evaluation.
pub fn evaluate_access(
    acl_doc: Option<&AclDocument>,
    agent_uri: Option<&str>,
    resource_path: &str,
    required_mode: AccessMode,
    request_origin: Option<&origin::Origin>,
) -> bool {
    evaluate_access_with_groups(
        acl_doc,
        agent_uri,
        resource_path,
        required_mode,
        request_origin,
        &NoGroupMembership,
    )
}

/// WAC 1.x evaluation with a caller-supplied group resolver. Rules
/// bearing `acl:condition` triples fail closed (empty dispatcher).
pub fn evaluate_access_with_groups(
    acl_doc: Option<&AclDocument>,
    agent_uri: Option<&str>,
    resource_path: &str,
    required_mode: AccessMode,
    request_origin: Option<&origin::Origin>,
    groups: &dyn GroupMembership,
) -> bool {
    let ctx = RequestContext {
        web_id: agent_uri,
        client_id: None,
        issuer: None,
    };
    evaluate_access_ctx_inner(
        acl_doc,
        &ctx,
        resource_path,
        required_mode,
        request_origin,
        groups,
        &EmptyDispatcher,
    )
}

/// WAC 2.0 evaluation entry point. Accepts a `RequestContext` carrying
/// WebID / client / issuer, plus a `ConditionDispatcher` (typically a
/// `ConditionRegistry`).
///
/// Conjunctive semantics: for every authorisation whose agent+mode+path
/// predicates match, each attached `acl:condition` must dispatch to
/// `Satisfied` for the rule to grant. Any `NotApplicable` or `Denied`
/// outcome causes the rule to be skipped.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_access_ctx(
    acl_doc: Option<&AclDocument>,
    ctx: &RequestContext<'_>,
    resource_path: &str,
    required_mode: AccessMode,
    request_origin: Option<&origin::Origin>,
    groups: &dyn GroupMembership,
    dispatcher: &dyn ConditionDispatcher,
) -> bool {
    evaluate_access_ctx_inner(
        acl_doc,
        ctx,
        resource_path,
        required_mode,
        request_origin,
        groups,
        dispatcher,
    )
}

/// Convenience wrapper that takes a `ConditionRegistry` directly.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_access_ctx_with_registry(
    acl_doc: Option<&AclDocument>,
    ctx: &RequestContext<'_>,
    resource_path: &str,
    required_mode: AccessMode,
    request_origin: Option<&origin::Origin>,
    groups: &dyn GroupMembership,
    registry: &ConditionRegistry,
) -> bool {
    evaluate_access_ctx_inner(
        acl_doc,
        ctx,
        resource_path,
        required_mode,
        request_origin,
        groups,
        registry,
    )
}

#[allow(clippy::too_many_arguments)]
fn evaluate_access_ctx_inner(
    acl_doc: Option<&AclDocument>,
    ctx: &RequestContext<'_>,
    resource_path: &str,
    required_mode: AccessMode,
    request_origin: Option<&origin::Origin>,
    groups: &dyn GroupMembership,
    dispatcher: &dyn ConditionDispatcher,
) -> bool {
    let Some(doc) = acl_doc else {
        return false;
    };
    let Some(graph) = doc.graph.as_ref() else {
        return false;
    };
    let mut base_grant = false;
    for auth in graph {
        let granted = get_modes(auth);
        if !granted.contains(&required_mode) {
            continue;
        }
        if !agent_matches_with_groups(auth, ctx.web_id, groups) {
            continue;
        }
        let mut path_ok = false;
        for target in get_ids(&auth.access_to) {
            if path_matches(target, resource_path, false) {
                path_ok = true;
                break;
            }
        }
        if !path_ok {
            for target in get_ids(&auth.default) {
                if path_matches(target, resource_path, true) {
                    path_ok = true;
                    break;
                }
            }
        }
        if !path_ok {
            continue;
        }

        // WAC 2.0 conjunctive condition gate. All conditions must
        // return `Satisfied`. Any `NotApplicable` or `Denied` skips
        // this authorisation (fail-closed).
        let mut conditions_ok = true;
        if let Some(conds) = &auth.condition {
            for cond in conds {
                match dispatcher.dispatch(cond, ctx, groups) {
                    ConditionOutcome::Satisfied => continue,
                    ConditionOutcome::NotApplicable | ConditionOutcome::Denied => {
                        conditions_ok = false;
                        break;
                    }
                }
            }
        }
        if !conditions_ok {
            continue;
        }

        base_grant = true;
        break;
    }
    if !base_grant {
        return false;
    }

    // WAC §4.3 invariant 4: Control mode bypasses the origin gate so
    // that an owner can always fix a mis-configured ACL from any
    // origin.
    if matches!(required_mode, AccessMode::Control) {
        return true;
    }

    // F4 — origin gate. Only active behind the `acl-origin` feature;
    // otherwise behave exactly as pre-F4 to preserve backward compat.
    #[cfg(feature = "acl-origin")]
    {
        match origin::check_origin(doc, request_origin) {
            origin::OriginDecision::NoPolicySet | origin::OriginDecision::Permitted => true,
            origin::OriginDecision::RejectedMismatch
            | origin::OriginDecision::RejectedNoOrigin => {
                crate::wac::metrics::ACL_ORIGIN_REJECTED_TOTAL
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                false
            }
        }
    }
    #[cfg(not(feature = "acl-origin"))]
    {
        let _ = request_origin;
        true
    }
}
