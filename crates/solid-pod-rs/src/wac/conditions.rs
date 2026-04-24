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
/// land in the [`Condition::Unknown`] arm with the offending IRI
/// preserved so the document still parses, dispatch returns
/// `NotApplicable`, and the write-time validator can echo the
/// rejected type verbatim in a 422 response.
#[derive(Debug, Clone)]
pub enum Condition {
    /// `acl:ClientCondition` — gate on the requesting client identity.
    Client(ClientConditionBody),

    /// `acl:IssuerCondition` — gate on the token issuer.
    Issuer(IssuerConditionBody),

    /// Any condition type the server does not recognise. The `type_iri`
    /// is preserved verbatim from the `@type` (or Turtle `rdf:type`)
    /// discriminator.
    Unknown {
        /// IRI of the rejected condition type (`@type` value).
        type_iri: String,
    },
}

impl Condition {
    /// Canonical IRI of the `@type` discriminator for this condition.
    /// Used by the serialiser and by `validate_acl_document` when
    /// reporting 422 rejections.
    pub fn type_iri(&self) -> &str {
        match self {
            Condition::Client(_) => "acl:ClientCondition",
            Condition::Issuer(_) => "acl:IssuerCondition",
            Condition::Unknown { type_iri } => type_iri.as_str(),
        }
    }
}

// ---------------------------------------------------------------------------
// Manual (de)serialisation.
//
// Rationale: the previous derive-based `#[serde(other)] Unknown` variant
// cannot carry the rejected IRI because `serde(other)` is restricted to
// unit variants. Sprint-9 row 56 requires a 422 response that echoes
// the exact unsupported IRI, so we route JSON through an intermediate
// `serde_json::Value` and inspect the discriminator ourselves.
// ---------------------------------------------------------------------------

impl Serialize for Condition {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        match self {
            Condition::Client(body) => {
                let mut m = ser.serialize_map(None)?;
                m.serialize_entry("@type", "acl:ClientCondition")?;
                if let Some(v) = &body.client {
                    m.serialize_entry("acl:client", v)?;
                }
                if let Some(v) = &body.client_group {
                    m.serialize_entry("acl:clientGroup", v)?;
                }
                if let Some(v) = &body.client_class {
                    m.serialize_entry("acl:clientClass", v)?;
                }
                m.end()
            }
            Condition::Issuer(body) => {
                let mut m = ser.serialize_map(None)?;
                m.serialize_entry("@type", "acl:IssuerCondition")?;
                if let Some(v) = &body.issuer {
                    m.serialize_entry("acl:issuer", v)?;
                }
                if let Some(v) = &body.issuer_group {
                    m.serialize_entry("acl:issuerGroup", v)?;
                }
                if let Some(v) = &body.issuer_class {
                    m.serialize_entry("acl:issuerClass", v)?;
                }
                m.end()
            }
            Condition::Unknown { type_iri } => {
                let mut m = ser.serialize_map(Some(1))?;
                m.serialize_entry("@type", type_iri)?;
                m.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Condition {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let raw: serde_json::Value = Deserialize::deserialize(de)?;
        let obj = raw.as_object().ok_or_else(|| {
            serde::de::Error::custom("acl:condition entry must be a JSON object")
        })?;
        let type_iri_value = obj
            .get("@type")
            .ok_or_else(|| serde::de::Error::custom("acl:condition missing @type"))?;
        let type_iri_str = type_iri_value.as_str().ok_or_else(|| {
            serde::de::Error::custom("acl:condition @type must be a string")
        })?;
        let matches_client = matches!(
            type_iri_str,
            "acl:ClientCondition"
                | "http://www.w3.org/ns/auth/acl#ClientCondition"
                | "https://www.w3.org/ns/auth/acl#ClientCondition"
        );
        let matches_issuer = matches!(
            type_iri_str,
            "acl:IssuerCondition"
                | "http://www.w3.org/ns/auth/acl#IssuerCondition"
                | "https://www.w3.org/ns/auth/acl#IssuerCondition"
        );
        if matches_client {
            let body =
                ClientConditionBody::deserialize(raw).map_err(serde::de::Error::custom)?;
            Ok(Condition::Client(body))
        } else if matches_issuer {
            let body =
                IssuerConditionBody::deserialize(raw).map_err(serde::de::Error::custom)?;
            Ok(Condition::Issuer(body))
        } else {
            Ok(Condition::Unknown {
                type_iri: type_iri_str.to_string(),
            })
        }
    }
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
            Condition::Unknown { .. } => ConditionOutcome::NotApplicable,
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

/// Write-time gatekeeper. Walks every authorisation in the document
/// and ensures every attached condition parses to a known variant.
///
/// Returns the first [`Condition::Unknown`] encountered, with the
/// exact rejected `@type` IRI preserved, so handlers can echo it in a
/// 422 Unprocessable Entity response.
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
                if let Condition::Unknown { type_iri } = c {
                    return Err(UnsupportedCondition {
                        iri: type_iri.clone(),
                    });
                }
            }
        }
    }
    Ok(())
}

/// Validate an ACL document in the shape a handler receives on PUT
/// `.acl`. Returns [`UnsupportedCondition`] for the first unknown
/// `acl:condition` type; handlers map this to 422 Unprocessable Entity
/// with the offending IRI in the response body.
///
/// Uses the default registry (client + issuer condition evaluators
/// enabled). Consumers with a customised registry should call
/// [`validate_for_write`] directly.
pub fn validate_acl_document(doc: &AclDocument) -> Result<(), UnsupportedCondition> {
    validate_for_write(doc, &ConditionRegistry::default_with_client_and_issuer())
}
