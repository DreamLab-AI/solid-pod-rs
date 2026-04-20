//! `acl:ClientCondition` — gate authorisation on the requesting client.
//!
//! A `ClientCondition` is satisfied when the request context's
//! `client_id` matches one of the listed `acl:client` IRIs, when the
//! client is a member of a listed `acl:clientGroup`, or when the
//! condition names a public class (`foaf:Agent`).

use serde::{Deserialize, Serialize};

use crate::wac::conditions::{ConditionOutcome, RequestContext};
use crate::wac::document::{get_ids, IdOrIds};
use crate::wac::evaluator::GroupMembership;

/// Body of an `acl:ClientCondition`.
///
/// Fields mirror the WAC 2.0 predicates: `acl:client`, `acl:clientGroup`,
/// `acl:clientClass`. Any subset may be populated; evaluation is OR
/// across the populated predicates (i.e. a client matching any of them
/// satisfies the condition).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ClientConditionBody {
    #[serde(rename = "acl:client", default, skip_serializing_if = "Option::is_none")]
    pub client: Option<IdOrIds>,

    #[serde(
        rename = "acl:clientGroup",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub client_group: Option<IdOrIds>,

    #[serde(
        rename = "acl:clientClass",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub client_class: Option<IdOrIds>,
}

/// Default evaluator for `acl:ClientCondition`.
///
/// The evaluator is stateless; it closes over the request context and
/// (optionally) a group resolver supplied by `evaluate_access_ctx`.
/// For the first-cut implementation, groups are resolved via the same
/// `GroupMembership` trait used by `acl:agentGroup`.
#[derive(Debug, Default, Clone, Copy)]
pub struct ClientConditionEvaluator;

impl ClientConditionEvaluator {
    pub fn evaluate(
        &self,
        body: &ClientConditionBody,
        ctx: &RequestContext<'_>,
        groups: &dyn GroupMembership,
    ) -> ConditionOutcome {
        // Public class shortcut.
        for cls in get_ids(&body.client_class) {
            if cls == "foaf:Agent" || cls == "http://xmlns.com/foaf/0.1/Agent" {
                return ConditionOutcome::Satisfied;
            }
        }

        // Direct client-id match.
        if let Some(cid) = ctx.client_id {
            for c in get_ids(&body.client) {
                if c == cid {
                    return ConditionOutcome::Satisfied;
                }
            }
            // Group membership — reuses the same resolver as agentGroup
            // because WAC 2.0 treats group documents uniformly.
            for g in get_ids(&body.client_group) {
                if groups.is_member(g, cid) {
                    return ConditionOutcome::Satisfied;
                }
            }
        }

        // No predicate matched. This is `Denied` (definite no-match),
        // not `NotApplicable` — which is reserved for unknown condition
        // types that the registry cannot dispatch at all.
        ConditionOutcome::Denied
    }
}
