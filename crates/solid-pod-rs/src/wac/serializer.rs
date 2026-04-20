//! Turtle serialiser for `AclDocument`.

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
