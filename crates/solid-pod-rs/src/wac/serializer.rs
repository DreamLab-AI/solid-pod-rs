//! Turtle serialiser for `AclDocument`.

use crate::wac::conditions::Condition;
use crate::wac::document::{AclDocument, IdOrIds};

/// Serialise an [`AclDocument`] as Turtle.
pub fn serialize_turtle_acl(doc: &AclDocument) -> String {
    let mut out = String::new();
    out.push_str("@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n");
    out.push_str("@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\n");
    let graph = match &doc.graph {
        Some(g) => g,
        None => return out,
    };
    for (i, auth) in graph.iter().enumerate() {
        let subject = format!("<#rule-{i}>");
        out.push_str(&subject);
        out.push_str(" a acl:Authorization");
        emit_pairs(&mut out, "acl:agent", &auth.agent);
        emit_pairs(&mut out, "acl:agentClass", &auth.agent_class);
        emit_pairs(&mut out, "acl:agentGroup", &auth.agent_group);
        emit_pairs(&mut out, "acl:origin", &auth.origin);
        emit_pairs(&mut out, "acl:accessTo", &auth.access_to);
        emit_pairs(&mut out, "acl:default", &auth.default);
        emit_pairs(&mut out, "acl:mode", &auth.mode);
        emit_conditions(&mut out, auth.condition.as_deref());
        out.push_str(" .\n\n");
    }
    out
}

fn emit_pairs(out: &mut String, pred: &str, vals: &Option<IdOrIds>) {
    if let Some(ids) = vals {
        let refs: Vec<&str> = match ids {
            IdOrIds::Single(r) => vec![r.id.as_str()],
            IdOrIds::Multiple(v) => v.iter().map(|r| r.id.as_str()).collect(),
        };
        if refs.is_empty() {
            return;
        }
        out.push_str(" ;\n    ");
        out.push_str(pred);
        out.push(' ');
        let rendered: Vec<String> = refs
            .iter()
            .map(|r| {
                if r.starts_with("http") {
                    format!("<{r}>")
                } else {
                    r.to_string()
                }
            })
            .collect();
        out.push_str(&rendered.join(", "));
    }
}

fn emit_conditions(out: &mut String, conds: Option<&[Condition]>) {
    let conds = match conds {
        Some(c) if !c.is_empty() => c,
        _ => return,
    };
    for cond in conds {
        out.push_str(" ;\n    acl:condition [\n        a ");
        out.push_str(cond.type_iri());
        match cond {
            Condition::Client(body) => {
                emit_body_pair(out, "acl:client", &body.client);
                emit_body_pair(out, "acl:clientGroup", &body.client_group);
                emit_body_pair(out, "acl:clientClass", &body.client_class);
            }
            Condition::Issuer(body) => {
                emit_body_pair(out, "acl:issuer", &body.issuer);
                emit_body_pair(out, "acl:issuerGroup", &body.issuer_group);
                emit_body_pair(out, "acl:issuerClass", &body.issuer_class);
            }
            Condition::Unknown { .. } => {}
        }
        out.push_str("\n    ]");
    }
}

fn emit_body_pair(out: &mut String, pred: &str, vals: &Option<IdOrIds>) {
    if let Some(ids) = vals {
        let refs: Vec<&str> = match ids {
            IdOrIds::Single(r) => vec![r.id.as_str()],
            IdOrIds::Multiple(v) => v.iter().map(|r| r.id.as_str()).collect(),
        };
        if refs.is_empty() {
            return;
        }
        out.push_str(" ;\n        ");
        out.push_str(pred);
        out.push(' ');
        let rendered: Vec<String> = refs
            .iter()
            .map(|r| {
                if r.starts_with("http") {
                    format!("<{r}>")
                } else {
                    r.to_string()
                }
            })
            .collect();
        out.push_str(&rendered.join(", "));
    }
}
