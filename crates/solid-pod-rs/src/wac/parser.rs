//! Turtle ACL parser (subset sufficient for WAC documents).
//!
//! Accepts the subset used by real-world Solid ACL files: `@prefix`
//! directives, `a` shorthand, and `;`-separated predicate-object pairs
//! terminated with `.`.
//!
//! Non-recognised tokens are skipped — the parser is deliberately
//! forgiving so that odd whitespace or extra comments do not break it.

use std::collections::HashMap;

use crate::error::PodError;
use crate::wac::document::{ids_of, AclAuthorization, AclDocument};
use crate::wac::MAX_ACL_BYTES;

/// Parse a Turtle ACL document into the same `AclDocument` shape that
/// the JSON-LD deserialiser produces.
///
/// Enforces a byte cap (`JSS_MAX_ACL_BYTES`, default 1 MiB) so an
/// attacker cannot feed a multi-gigabyte document and DoS the process.
pub fn parse_turtle_acl(input: &str) -> Result<AclDocument, PodError> {
    let limit = std::env::var("JSS_MAX_ACL_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(MAX_ACL_BYTES);
    if input.len() > limit {
        return Err(PodError::BadRequest(format!(
            "ACL body exceeds {limit} bytes"
        )));
    }

    let mut prefixes: HashMap<String, String> = HashMap::new();
    prefixes.insert("acl".into(), "http://www.w3.org/ns/auth/acl#".into());
    prefixes.insert("foaf".into(), "http://xmlns.com/foaf/0.1/".into());
    prefixes.insert("vcard".into(), "http://www.w3.org/2006/vcard/ns#".into());

    // Strip comments (lines beginning with # outside IRIs).
    let cleaned = strip_turtle_comments(input);

    // Pull out @prefix directives.
    let mut body = String::new();
    for line in cleaned.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("@prefix") {
            let rest = rest.trim();
            if let Some((name, iri_part)) = rest.split_once(':') {
                let name = name.trim().to_string();
                let iri_part = iri_part.trim().trim_end_matches('.').trim();
                let iri = iri_part.trim_start_matches('<').trim_end_matches('>').trim();
                prefixes.insert(name, iri.to_string());
            }
        } else {
            body.push_str(line);
            body.push('\n');
        }
    }

    let statements = split_turtle_statements(&body);
    let mut graph: Vec<AclAuthorization> = Vec::new();
    for stmt in statements {
        if stmt.trim().is_empty() {
            continue;
        }
        if let Some(auth) = parse_turtle_authorization(&stmt, &prefixes) {
            graph.push(auth);
        }
    }
    Ok(AclDocument {
        context: None,
        graph: if graph.is_empty() { None } else { Some(graph) },
    })
}

fn strip_turtle_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for line in input.lines() {
        let mut in_iri = false;
        let mut filtered = String::with_capacity(line.len());
        for c in line.chars() {
            match c {
                '<' => {
                    in_iri = true;
                    filtered.push(c);
                }
                '>' => {
                    in_iri = false;
                    filtered.push(c);
                }
                '#' if !in_iri => break,
                _ => filtered.push(c),
            }
        }
        out.push_str(&filtered);
        out.push('\n');
    }
    out
}

fn split_turtle_statements(input: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut depth_iri = 0i32;
    let mut in_str = false;
    for c in input.chars() {
        match c {
            '<' if !in_str => {
                depth_iri += 1;
                cur.push(c);
            }
            '>' if !in_str => {
                depth_iri = (depth_iri - 1).max(0);
                cur.push(c);
            }
            '"' => {
                in_str = !in_str;
                cur.push(c);
            }
            '.' if depth_iri == 0 && !in_str => {
                out.push(cur.clone());
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

fn parse_turtle_authorization(
    stmt: &str,
    prefixes: &HashMap<String, String>,
) -> Option<AclAuthorization> {
    let trimmed = stmt.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (_subject, body) = turtle_pop_term(trimmed)?;
    let mut auth = AclAuthorization {
        id: None,
        r#type: None,
        agent: None,
        agent_class: None,
        agent_group: None,
        origin: None,
        access_to: None,
        default: None,
        mode: None,
        condition: None,
    };
    let mut any_authz = false;
    for pair in body.split(';') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (pred, rest) = turtle_pop_term(pair)?;
        let pred_expanded = expand_curie_or_iri(&pred, prefixes);
        let objects = parse_object_list(rest.trim(), prefixes);

        match pred_expanded.as_str() {
            "a" | "http://www.w3.org/1999/02/22-rdf-syntax-ns#type" | "rdf:type" => {
                if objects.iter().any(|o| {
                    o == "http://www.w3.org/ns/auth/acl#Authorization" || o == "acl:Authorization"
                }) {
                    any_authz = true;
                }
            }
            "http://www.w3.org/ns/auth/acl#agent" | "acl:agent" => {
                auth.agent = Some(ids_of(objects));
            }
            "http://www.w3.org/ns/auth/acl#agentClass" | "acl:agentClass" => {
                auth.agent_class = Some(ids_of(objects));
            }
            "http://www.w3.org/ns/auth/acl#agentGroup" | "acl:agentGroup" => {
                auth.agent_group = Some(ids_of(objects));
            }
            "http://www.w3.org/ns/auth/acl#origin" | "acl:origin" => {
                auth.origin = Some(ids_of(objects));
            }
            "http://www.w3.org/ns/auth/acl#accessTo" | "acl:accessTo" => {
                auth.access_to = Some(ids_of(objects));
            }
            "http://www.w3.org/ns/auth/acl#default" | "acl:default" => {
                auth.default = Some(ids_of(objects));
            }
            "http://www.w3.org/ns/auth/acl#mode" | "acl:mode" => {
                auth.mode = Some(ids_of(objects));
            }
            _ => {}
        }
    }
    if any_authz {
        Some(auth)
    } else {
        None
    }
}

fn turtle_pop_term(input: &str) -> Option<(String, String)> {
    let input = input.trim_start();
    if let Some(rest) = input.strip_prefix('<') {
        let end = rest.find('>')?;
        Some((rest[..end].to_string(), rest[end + 1..].to_string()))
    } else if input.starts_with('"') {
        None
    } else {
        // Identifier token terminated by whitespace *or* by Turtle
        // punctuation (comma, semicolon, closing bracket, statement
        // terminator). Without this, `acl:Write, acl:Control` would be
        // parsed as a single token `acl:Write,` with the trailing comma
        // welded to the IRI, defeating comma-separated object-list
        // handling in `parse_object_list`.
        let end = input
            .find(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | ']' | ')'))
            .unwrap_or(input.len());
        Some((input[..end].to_string(), input[end..].to_string()))
    }
}

fn parse_object_list(input: &str, prefixes: &HashMap<String, String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut remaining = input.trim().to_string();
    loop {
        let r = remaining.trim_start();
        if r.is_empty() {
            break;
        }
        let (tok, rest) = match turtle_pop_term(r) {
            Some(v) => v,
            None => break,
        };
        out.push(expand_curie_or_iri(&tok, prefixes));
        let r = rest.trim_start();
        if let Some(after_comma) = r.strip_prefix(',') {
            remaining = after_comma.to_string();
        } else {
            break;
        }
    }
    out
}

fn expand_curie_or_iri(tok: &str, prefixes: &HashMap<String, String>) -> String {
    let tok = tok.trim();
    if tok == "a" {
        return "a".to_string();
    }
    if let Some((p, local)) = tok.split_once(':') {
        if !p.starts_with('<') {
            if let Some(base) = prefixes.get(p) {
                return format!("{base}{local}");
            }
        }
    }
    tok.to_string()
}
