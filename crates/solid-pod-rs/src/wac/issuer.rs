//! `acl:IssuerCondition` — gate authorisation on the token issuer.
//!
//! An `IssuerCondition` is satisfied when the request context's
//! `issuer` (typically the `iss` claim from an OIDC/DPoP access token)
//! matches a listed `acl:issuer` IRI, belongs to a listed
//! `acl:issuerGroup`, or the class predicate names a catch-all.

use serde::{Deserialize, Serialize};

use crate::wac::conditions::{ConditionOutcome, RequestContext};
use crate::wac::document::{get_ids, IdOrIds};
use crate::wac::evaluator::GroupMembership;

/// Body of an `acl:IssuerCondition`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct IssuerConditionBody {
    #[serde(rename = "acl:issuer", default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<IdOrIds>,

    #[serde(
        rename = "acl:issuerGroup",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub issuer_group: Option<IdOrIds>,

    #[serde(
        rename = "acl:issuerClass",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub issuer_class: Option<IdOrIds>,
}

/// Default evaluator for `acl:IssuerCondition`.
#[derive(Debug, Default, Clone, Copy)]
pub struct IssuerConditionEvaluator;

impl IssuerConditionEvaluator {
    pub fn evaluate(
        &self,
        body: &IssuerConditionBody,
        ctx: &RequestContext<'_>,
        groups: &dyn GroupMembership,
    ) -> ConditionOutcome {
        // Catch-all class (rarely useful but specified for completeness).
        for cls in get_ids(&body.issuer_class) {
            if cls == "foaf:Agent" || cls == "http://xmlns.com/foaf/0.1/Agent" {
                return ConditionOutcome::Satisfied;
            }
        }

        let Some(iss) = ctx.issuer else {
            // No issuer in context — with no class allowlist, condition
            // is definitively denied.
            return ConditionOutcome::Denied;
        };

        for i in get_ids(&body.issuer) {
            if i == iss {
                return ConditionOutcome::Satisfied;
            }
        }
        for g in get_ids(&body.issuer_group) {
            if groups.is_member(g, iss) {
                return ConditionOutcome::Satisfied;
            }
        }

        ConditionOutcome::Denied
    }
}
