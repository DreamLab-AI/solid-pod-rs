//! ACL document AST — JSON-LD deserialisation shape.
//!
//! The same struct shape is produced by the Turtle parser in
//! `wac::parser` so downstream consumers work with a single canonical
//! representation regardless of wire format.

use serde::{Deserialize, Serialize};

use crate::wac::conditions::Condition;

/// Parsed ACL document containing zero or more authorization rules.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AclDocument {
    /// JSON-LD `@context` value, if the document was parsed from JSON-LD.
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,

    /// The list of authorization rules in this document.
    #[serde(rename = "@graph", skip_serializing_if = "Option::is_none")]
    pub graph: Option<Vec<AclAuthorization>>,
}

/// A single WAC authorization rule describing who may access what, and how.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AclAuthorization {
    /// Node identifier for this authorization (e.g. `#owner`).
    #[serde(rename = "@id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// RDF type, typically `acl:Authorization`.
    #[serde(rename = "@type", skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,

    /// WebID(s) of the agent(s) this rule grants access to.
    #[serde(rename = "acl:agent", skip_serializing_if = "Option::is_none")]
    pub agent: Option<IdOrIds>,

    /// Agent class (`foaf:Agent` for public, `acl:AuthenticatedAgent` for logged-in).
    #[serde(rename = "acl:agentClass", skip_serializing_if = "Option::is_none")]
    pub agent_class: Option<IdOrIds>,

    /// IRI(s) of `vcard:Group` documents whose members are granted access.
    #[serde(rename = "acl:agentGroup", skip_serializing_if = "Option::is_none")]
    pub agent_group: Option<IdOrIds>,

    /// Permitted request origin(s) per WAC section 4.3.
    #[serde(rename = "acl:origin", skip_serializing_if = "Option::is_none")]
    pub origin: Option<IdOrIds>,

    /// Resource path(s) this rule applies to (exact match + direct children).
    #[serde(rename = "acl:accessTo", skip_serializing_if = "Option::is_none")]
    pub access_to: Option<IdOrIds>,

    /// Container path(s) whose descendants inherit this rule recursively.
    #[serde(rename = "acl:default", skip_serializing_if = "Option::is_none")]
    pub default: Option<IdOrIds>,

    /// Access mode(s) granted: `acl:Read`, `acl:Write`, `acl:Append`, `acl:Control`.
    #[serde(rename = "acl:mode", skip_serializing_if = "Option::is_none")]
    pub mode: Option<IdOrIds>,

    /// WAC 2.0 conjunctive conditions. Every listed condition must be
    /// `Satisfied` for this authorisation to grant access. An unknown
    /// condition type parses as `Condition::Unknown` and evaluates to
    /// `NotApplicable`, which fails closed — see
    /// [`crate::wac::conditions`].
    #[serde(
        rename = "acl:condition",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub condition: Option<Vec<Condition>>,
}

/// One or more JSON-LD `@id` references, modelling both singular and array ACL values.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum IdOrIds {
    /// A single `@id` reference.
    Single(IdRef),
    /// An array of `@id` references.
    Multiple(Vec<IdRef>),
}

/// A JSON-LD node reference carrying a single `@id` IRI.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IdRef {
    /// The IRI value.
    #[serde(rename = "@id")]
    pub id: String,
}

pub(crate) fn get_ids(val: &Option<IdOrIds>) -> Vec<&str> {
    match val {
        None => Vec::new(),
        Some(IdOrIds::Single(r)) => vec![r.id.as_str()],
        Some(IdOrIds::Multiple(refs)) => refs.iter().map(|r| r.id.as_str()).collect(),
    }
}

pub(crate) fn ids_of(items: Vec<String>) -> IdOrIds {
    let mut iter = items.into_iter();
    let first = iter.next();
    let second = iter.next();
    match (first, second) {
        // Single-element path: the len==1 guard previously ensured this.
        (Some(id), None) => IdOrIds::Single(IdRef { id }),
        // Multi-element: reconstruct the full iterator.
        (Some(first), Some(second)) => IdOrIds::Multiple(
            std::iter::once(first)
                .chain(std::iter::once(second))
                .chain(iter)
                .map(|id| IdRef { id })
                .collect(),
        ),
        // Empty: shouldn't happen per call-site invariants but handle
        // defensively — return an empty Multiple rather than panicking.
        _ => IdOrIds::Multiple(Vec::new()),
    }
}
