//! WAC 2.0 conditions framework.
//!
//! Reference: <https://webacl.org/secure-access-conditions/>
//!
//! The framework models authorisation predicates beyond the classic
//! `acl:agent`/`acl:agentGroup`/`acl:agentClass` triad. Each condition
//! evaluates to one of three outcomes:
//!
//! * `Satisfied` — the predicate holds; continue evaluating other rules.
//! * `Denied` — the predicate explicitly does not hold.
//! * `NotApplicable` — the server does not recognise the condition type,
//!   so it cannot make a ruling. Per the WAC 2.0 fail-closed rule, a
//!   `NotApplicable` outcome causes the host authorisation to be
//!   skipped (i.e. it must not grant).
//!
//! Conjunctive semantics: for a rule bearing `N` conditions, every
//! condition must return `Satisfied` for the rule to grant.

use serde::{Deserialize, Serialize};

use crate::wac::client::{ClientConditionBody, ClientConditionEvaluator};
use crate::wac::document::AclDocument;
use crate::wac::evaluator::GroupMembership;
use crate::wac::issuer::{IssuerConditionBody, IssuerConditionEvaluator};

/// Outcome of evaluating a single `acl:condition` predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConditionOutcome {
    /// Predicate holds for the current request.
    Satisfied,
    /// Server cannot dispatch (unknown condition type / no evaluator).
    /// Fail-closed: the host authorisation does NOT grant.
    NotApplicable,
    /// Predicate explicitly does not hold.
    Denied,
}

/// Discriminated union of recognised condition types.
///
/// Parsed from the `@type` discriminator in JSON-LD. Unknown types
/// land in the `Unknown` arm via `#[serde(other)]` so the document
/// still parses but dispatch returns `NotApplicable`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "@type")]
pub enum Condition {
    #[serde(
        rename = "acl:ClientCondition",
        alias = "http://www.w3.org/ns/auth/acl#ClientCondition",
        alias = "https://www.w3.org/ns/auth/acl#ClientCondition"
    )]
    Client(ClientConditionBody),

    #[serde(
        rename = "acl:IssuerCondition",
        alias = "http://www.w3.org/ns/auth/acl#IssuerCondition",
        alias = "https://www.w3.org/ns/auth/acl#IssuerCondition"
    )]
    Issuer(IssuerConditionBody),

    /// Unknown type — `serde(other)` captures any tag we did not list.
    /// `ConditionRegistry::dispatch` returns `NotApplicable` for this
    /// arm, which propagates to a denied host authorisation.
    #[serde(other)]
    Unknown,
}

/// Minimal request context passed to every condition evaluator.
///
/// Borrowed so the caller does not have to allocate on the hot path.
#[derive(Debug, Clone, Copy)]
pub struct RequestContext<'a> {
    /// Authenticated WebID, if any (`Some` for logged-in requests,
    /// `None` for anonymous).
    pub web_id: Option<&'a str>,
    /// OAuth/OIDC client identifier from the access token's `azp` /
    /// `client_id` claim (or DPoP key thumbprint bound WebID).
    pub client_id: Option<&'a str>,
    /// Token issuer — the `iss` claim.
    pub issuer: Option<&'a str>,
}

/// Registry-facing dispatcher trait. Separate from the concrete
/// registry so tests can substitute a mock dispatcher without the full
/// evaluator wiring.
pub trait ConditionDispatcher: Send + Sync {
    fn dispatch(
        &self,
        cond: &Condition,
        ctx: &RequestContext<'_>,
        groups: &dyn GroupMembership,
    ) -> ConditionOutcome;
}

/// Registry mapping condition types to their evaluators.
///
/// Construct via `ConditionRegistry::new()` and chain
/// `with_client()`/`with_issuer()` to register the built-in evaluators.
/// A registry with no evaluators registered returns `NotApplicable`
/// for every condition — which means any rule bearing conditions
/// fails closed. That is intentional: it is the safe default for
/// servers that have not yet opted into WAC 2.0.
#[derive(Default)]
pub struct ConditionRegistry {
    client_eval: Option<ClientConditionEvaluator>,
    issuer_eval: Option<IssuerConditionEvaluator>,
}

impl ConditionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register the default built-in client-condition evaluator.
    pub fn with_client(mut self, e: ClientConditionEvaluator) -> Self {
        self.client_eval = Some(e);
        self
    }

    /// Register the default built-in issuer-condition evaluator.
    pub fn with_issuer(mut self, e: IssuerConditionEvaluator) -> Self {
        self.issuer_eval = Some(e);
        self
    }

    /// Convenience constructor enabling both built-ins. Used by most
    /// call sites and tests.
    pub fn default_with_client_and_issuer() -> Self {
        Self::new()
            .with_client(ClientConditionEvaluator)
            .with_issuer(IssuerConditionEvaluator)
    }

    /// List of condition-type IRIs the registry can dispatch. Used by
    /// `validate_for_write` to tell callers which types a 422 response
    /// is rejecting.
    pub fn supported_iris(&self) -> Vec<&'static str> {
        let mut s: Vec<&'static str> = Vec::new();
        if self.client_eval.is_some() {
            s.push("acl:ClientCondition");
        }
        if self.issuer_eval.is_some() {
            s.push("acl:IssuerCondition");
        }
        s
    }
}

impl ConditionDispatcher for ConditionRegistry {
    fn dispatch(
        &self,
        cond: &Condition,
        ctx: &RequestContext<'_>,
        groups: &dyn GroupMembership,
    ) -> ConditionOutcome {
        match cond {
            Condition::Client(body) => match &self.client_eval {
                Some(e) => e.evaluate(body, ctx, groups),
                None => ConditionOutcome::NotApplicable,
            },
            Condition::Issuer(body) => match &self.issuer_eval {
                Some(e) => e.evaluate(body, ctx, groups),
                None => ConditionOutcome::NotApplicable,
            },
            Condition::Unknown => ConditionOutcome::NotApplicable,
        }
    }
}

/// Empty dispatcher — returns `NotApplicable` for every call. Used by
/// the legacy `evaluate_access` entry point so that pre-WAC-2.0 callers
/// keep behaving identically (no conditions registered → any rule with
/// conditions fails closed, which for WAC 1.x documents is a no-op).
pub struct EmptyDispatcher;
impl ConditionDispatcher for EmptyDispatcher {
    fn dispatch(
        &self,
        _cond: &Condition,
        _ctx: &RequestContext<'_>,
        _groups: &dyn GroupMembership,
    ) -> ConditionOutcome {
        ConditionOutcome::NotApplicable
    }
}

/// Raised by `validate_for_write` when a document carries a condition
/// type the registry cannot dispatch. Handlers surface this as 422
/// Unprocessable Entity with the offending IRI in the body.
#[derive(Debug, thiserror::Error)]
#[error("unsupported acl:condition type: {iri}")]
pub struct UnsupportedCondition {
    pub iri: String,
}

/// Write-time gatekeeper. Walks every authorisation in the document and
/// ensures every attached condition parses to a known variant.
///
/// Returns the first `Condition::Unknown` encountered, reported as
/// `UnsupportedCondition { iri: "acl:UnknownCondition" }`. Because
/// `serde(other)` has already collapsed the tag to `Unknown`, the
/// specific rejected IRI is not preserved in the parsed AST — so the
/// best we can report is the synthetic tag. Operators can surface the
/// raw request body in the 422 response to fill in the detail.
pub fn validate_for_write(
    doc: &AclDocument,
    _registry: &ConditionRegistry,
) -> Result<(), UnsupportedCondition> {
    let Some(graph) = &doc.graph else {
        return Ok(());
    };
    for auth in graph {
        if let Some(conds) = &auth.condition {
            for c in conds {
                if matches!(c, Condition::Unknown) {
                    return Err(UnsupportedCondition {
                        iri: "acl:UnknownCondition".into(),
                    });
                }
            }
        }
    }
    Ok(())
}
