//! ACL document AST — JSON-LD deserialisation shape.
//!
//! The same struct shape is produced by the Turtle parser in
//! `wac::parser` so downstream consumers work with a single canonical
//! representation regardless of wire format.

use serde::{Deserialize, Serialize};

use crate::wac::conditions::Condition;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AclDocument {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,

    #[serde(rename = "@graph", skip_serializing_if = "Option::is_none")]
    pub graph: Option<Vec<AclAuthorization>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AclAuthorization {
    #[serde(rename = "@id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(rename = "@type", skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,

    #[serde(rename = "acl:agent", skip_serializing_if = "Option::is_none")]
    pub agent: Option<IdOrIds>,

    #[serde(rename = "acl:agentClass", skip_serializing_if = "Option::is_none")]
    pub agent_class: Option<IdOrIds>,

    #[serde(rename = "acl:agentGroup", skip_serializing_if = "Option::is_none")]
    pub agent_group: Option<IdOrIds>,

    #[serde(rename = "acl:origin", skip_serializing_if = "Option::is_none")]
    pub origin: Option<IdOrIds>,

    #[serde(rename = "acl:accessTo", skip_serializing_if = "Option::is_none")]
    pub access_to: Option<IdOrIds>,

    #[serde(rename = "acl:default", skip_serializing_if = "Option::is_none")]
    pub default: Option<IdOrIds>,

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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum IdOrIds {
    Single(IdRef),
    Multiple(Vec<IdRef>),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IdRef {
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
    if items.len() == 1 {
        IdOrIds::Single(IdRef {
            id: items.into_iter().next().unwrap(),
        })
    } else {
        IdOrIds::Multiple(items.into_iter().map(|id| IdRef { id }).collect())
    }
}
