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
use crate::wac::client::ClientConditionBody;
use crate::wac::conditions::Condition;
use crate::wac::document::{ids_of, AclAuthorization, AclDocument, IdOrIds, IdRef};
use crate::wac::issuer::IssuerConditionBody;
use crate::wac::payment::PaymentConditionBody;
use crate::wac::MAX_ACL_BYTES;

/// Parse a Turtle ACL document into the same `AclDocument` shape that
/// the JSON-LD deserialiser produces.
///
/// Enforces a byte cap (`JSS_MAX_ACL_BYTES`, default 1 MiB) so an
/// attacker cannot feed a multi-gigabyte document and DoS the process.
/// To supply an explicit limit, use [`parse_turtle_acl_with_limit`].
pub fn parse_turtle_acl(input: &str) -> Result<AclDocument, PodError> {
    let limit = std::env::var("JSS_MAX_ACL_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(MAX_ACL_BYTES);
    parse_turtle_acl_with_limit(input, limit)
}

/// Parse a Turtle ACL document with a caller-supplied byte limit.
///
/// Equivalent to [`parse_turtle_acl`] but accepts the size cap as a
/// parameter instead of reading from the `JSS_MAX_ACL_BYTES` environment
/// variable. Returns `PodError::PayloadTooLarge` (HTTP 413 equivalent)
/// when `input.len() > max_bytes`.
pub fn parse_turtle_acl_with_limit(input: &str, max_bytes: usize) -> Result<AclDocument, PodError> {
    if input.len() > max_bytes {
        return Err(PodError::PayloadTooLarge(format!(
            "ACL body exceeds {max_bytes} bytes"
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
                let iri = iri_part
                    .trim_start_matches('<')
                    .trim_end_matches('>')
                    .trim();
                prefixes.insert(name, iri.to_string());
            }
        } else {
            body.push_str(line);
            body.push('\n');
        }
    }

    let statements = split_turtle_statements(&body);
    // Turtle permits one subject's predicates to span several statements.
    // Combine them before deciding whether the subject is an authorization;
    // otherwise a later restriction would be silently discarded.
    let mut subjects: Vec<(String, String)> = Vec::new();
    let mut subject_indices = HashMap::new();
    for stmt in statements {
        if stmt.trim().is_empty() {
            continue;
        }
        let (subject, predicates) = turtle_pop_term(stmt.trim())
            .ok_or_else(|| PodError::AclParse("malformed ACL statement".into()))?;
        let key = expand_curie_or_iri(&subject, &prefixes);
        if let Some(index) = subject_indices.get(&key).copied() {
            let (_, body): &mut (String, String) = &mut subjects[index];
            body.push_str(" ; ");
            body.push_str(&predicates);
        } else {
            subject_indices.insert(key.clone(), subjects.len());
            subjects.push((key, predicates));
        }
    }
    let mut graph: Vec<AclAuthorization> = Vec::new();
    for (subject, predicates) in subjects {
        let stmt = format!("<{subject}> {predicates}");
        if let Some(auth) = parse_turtle_authorization(&stmt, &prefixes)? {
            graph.push(auth);
        }
    }
    Ok(AclDocument {
        context: None,
        graph: if graph.is_empty() { None } else { Some(graph) },
        inherited: false,
    })
}

fn strip_turtle_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for line in input.lines() {
        let mut in_iri = false;
        let mut in_str = false;
        let mut escaped = false;
        let mut filtered = String::with_capacity(line.len());
        for c in line.chars() {
            if in_str {
                filtered.push(c);
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    in_str = false;
                }
                continue;
            }
            match c {
                '"' if !in_iri => {
                    in_str = true;
                    filtered.push(c);
                }
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
    let mut escaped = false;
    for c in input.chars() {
        if in_str {
            cur.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
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
) -> Result<Option<AclAuthorization>, PodError> {
    let trimmed = stmt.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let Some((_subject, body)) = turtle_pop_term(trimmed) else {
        return Ok(None);
    };
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
    // Split the predicate list honouring `[...]` balance so a blank
    // node body (e.g. `acl:condition [ a acl:ClientCondition; ... ]`)
    // is not torn apart by its inner `;` separators.
    for pair in split_predicate_list(&body) {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (pred, rest) = turtle_pop_term(pair)
            .ok_or_else(|| PodError::AclParse("malformed ACL predicate".into()))?;
        let pred_expanded = expand_curie_or_iri(&pred, prefixes).replace(
            "https://www.w3.org/ns/auth/acl#",
            "http://www.w3.org/ns/auth/acl#",
        );
        let objects = parse_object_list(rest.trim(), prefixes);

        match pred_expanded.as_str() {
            "a" | "http://www.w3.org/1999/02/22-rdf-syntax-ns#type" | "rdf:type"
                if objects.iter().any(|o| {
                    o == "http://www.w3.org/ns/auth/acl#Authorization"
                        || o == "https://www.w3.org/ns/auth/acl#Authorization"
                        || o == "acl:Authorization"
                }) =>
            {
                any_authz = true;
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
            "http://www.w3.org/ns/auth/acl#condition" | "acl:condition" => {
                // Conditions are usually authored as a blank-node
                // body `[ a acl:ClientCondition; acl:client <...> ]`.
                // The object side of the predicate contains one or
                // more such bodies. A malformed object invalidates the
                // document; it must never disappear from a restrictive rule.
                let parsed = parse_turtle_condition_objects(rest.trim(), prefixes)?;
                let bucket = auth.condition.get_or_insert_with(Vec::new);
                bucket.extend(parsed);
            }
            _ => {}
        }
    }
    if any_authz {
        Ok(Some(auth))
    } else {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Predicate-list splitter that respects `[...]` blank-node bodies.
//
// Turtle's top-level predicate-object pairs are terminated by `;`, but
// a blank-node body embedded as an object value also uses `;` to
// separate its internal pairs. Simple `body.split(';')` would tear the
// blank node apart; we track bracket depth instead.
// ---------------------------------------------------------------------------
fn split_predicate_list(input: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut depth: i32 = 0;
    let mut in_str = false;
    let mut in_iri = false;
    let mut escaped = false;
    for c in input.chars() {
        if in_str {
            cur.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        if in_iri {
            cur.push(c);
            if c == '>' {
                in_iri = false;
            }
            continue;
        }
        match c {
            '<' => {
                in_iri = true;
                cur.push(c);
            }
            '"' => {
                in_str = !in_str;
                cur.push(c);
            }
            '[' if !in_str => {
                depth += 1;
                cur.push(c);
            }
            ']' if !in_str => {
                depth = (depth - 1).max(0);
                cur.push(c);
            }
            ';' if !in_str && depth == 0 => {
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

// ---------------------------------------------------------------------------
// Condition-object parser.
//
// Accepts a comma-separated list of condition objects. Each object is
// either:
//
//   * a blank-node body `[ a <cond-type>; <pred> <obj> ; ... ]`, or
//   * an IRI reference (rare — usually the condition type is named
//     inline as a blank node).
//
// Unknown `@type` values are preserved verbatim so
// `validate_acl_document` can report the offending IRI in a 422.
// ---------------------------------------------------------------------------
fn parse_turtle_condition_objects(
    input: &str,
    prefixes: &HashMap<String, String>,
) -> Result<Vec<Condition>, PodError> {
    let mut out = Vec::new();
    let mut remaining = input.trim().to_string();
    loop {
        let r = remaining.trim_start();
        if r.is_empty() {
            break;
        }
        if let Some(after_open) = r.strip_prefix('[') {
            // Find the matching ']' honouring nesting + string content.
            let mut depth: i32 = 1;
            let mut idx = 0usize;
            let mut in_str = false;
            let mut escaped = false;
            for (i, c) in after_open.char_indices() {
                if in_str {
                    if escaped {
                        escaped = false;
                    } else if c == '\\' {
                        escaped = true;
                    } else if c == '"' {
                        in_str = false;
                    }
                    continue;
                }
                match c {
                    '"' => in_str = !in_str,
                    '[' if !in_str => depth += 1,
                    ']' if !in_str => {
                        depth -= 1;
                        if depth == 0 {
                            idx = i;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if depth != 0 {
                return Err(PodError::AclParse("unbalanced ACL condition".into()));
            }
            let body = &after_open[..idx];
            let rest = &after_open[idx + 1..];
            let cond = parse_turtle_condition_body(body, prefixes).ok_or_else(|| {
                PodError::AclParse("ACL condition requires valid type and parameters".into())
            })?;
            out.push(cond);
            remaining = rest.trim_start().to_string();
        } else {
            // IRI reference form — try to pop a term and treat it as an
            // Unknown condition (we cannot resolve arbitrary IRIs to
            // condition types without a registry lookup, so preserve).
            let (tok, rest) = match turtle_pop_term(r) {
                Some(v) => v,
                None => return Err(PodError::AclParse("malformed ACL condition".into())),
            };
            let iri = expand_curie_or_iri(&tok, prefixes);
            out.push(Condition::Unknown { type_iri: iri });
            remaining = rest.to_string();
        }
        let r = remaining.trim_start();
        if let Some(after_comma) = r.strip_prefix(',') {
            if after_comma.trim().is_empty() {
                return Err(PodError::AclParse("empty ACL condition".into()));
            }
            remaining = after_comma.to_string();
        } else {
            if !r.is_empty() {
                return Err(PodError::AclParse("unexpected ACL condition suffix".into()));
            }
            break;
        }
    }
    if out.is_empty() || remaining.trim_end().ends_with(',') {
        return Err(PodError::AclParse("empty ACL condition".into()));
    }
    Ok(out)
}

fn parse_turtle_condition_body(
    body: &str,
    prefixes: &HashMap<String, String>,
) -> Option<Condition> {
    let mut type_iri: Option<String> = None;
    let mut clients: Vec<String> = Vec::new();
    let mut client_groups: Vec<String> = Vec::new();
    let mut client_classes: Vec<String> = Vec::new();
    let mut issuers: Vec<String> = Vec::new();
    let mut issuer_groups: Vec<String> = Vec::new();
    let mut issuer_classes: Vec<String> = Vec::new();
    let mut cost_sats: Option<u64> = None;
    let mut anchor_mode: Option<String> = None;
    let mut anchor_ticker: Option<String> = None;

    for pair in split_predicate_list(body) {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (pred, rest) = match turtle_pop_term(pair) {
            Some(v) => v,
            None => continue,
        };
        let pred_expanded = expand_curie_or_iri(&pred, prefixes).replace(
            "https://www.w3.org/ns/auth/acl#",
            "http://www.w3.org/ns/auth/acl#",
        );
        let objects = parse_object_list(rest.trim(), prefixes);
        match pred_expanded.as_str() {
            "a" | "http://www.w3.org/1999/02/22-rdf-syntax-ns#type" | "rdf:type" => {
                if let Some(first) = objects.first() {
                    type_iri = Some(normalise_condition_type(first));
                }
            }
            "http://www.w3.org/ns/auth/acl#client" | "acl:client" => {
                clients.extend(objects);
            }
            "http://www.w3.org/ns/auth/acl#clientGroup" | "acl:clientGroup" => {
                client_groups.extend(objects);
            }
            "http://www.w3.org/ns/auth/acl#clientClass" | "acl:clientClass" => {
                client_classes.extend(objects);
            }
            "http://www.w3.org/ns/auth/acl#issuer" | "acl:issuer" => {
                issuers.extend(objects);
            }
            "http://www.w3.org/ns/auth/acl#issuerGroup" | "acl:issuerGroup" => {
                issuer_groups.extend(objects);
            }
            "http://www.w3.org/ns/auth/acl#issuerClass" | "acl:issuerClass" => {
                issuer_classes.extend(objects);
            }
            "http://www.w3.org/ns/auth/acl#costSats" | "acl:costSats" => {
                if let Some(first) = objects.first() {
                    cost_sats = first.parse::<u64>().ok();
                }
            }
            "http://www.w3.org/ns/auth/acl#anchorMode" | "acl:anchorMode" => {
                if let Some(first) = objects.first() {
                    anchor_mode = Some(first.clone());
                }
            }
            "http://www.w3.org/ns/auth/acl#anchorTicker" | "acl:anchorTicker" => {
                if let Some(first) = objects.first() {
                    anchor_ticker = Some(first.clone());
                }
            }
            _ => {}
        }
    }

    let t = type_iri?;
    match t.as_str() {
        "acl:ClientCondition" => Some(Condition::Client(ClientConditionBody {
            client: strs_to_ids(clients),
            client_group: strs_to_ids(client_groups),
            client_class: strs_to_ids(client_classes),
        })),
        "acl:IssuerCondition" => Some(Condition::Issuer(IssuerConditionBody {
            issuer: strs_to_ids(issuers),
            issuer_group: strs_to_ids(issuer_groups),
            issuer_class: strs_to_ids(issuer_classes),
        })),
        "acl:PaymentCondition" => Some(Condition::Payment(PaymentConditionBody {
            cost_sats: cost_sats?,
        })),
        "acl:ProvenanceAnchor" => Some(Condition::ProvenanceAnchor(
            crate::wac::anchor::ProvenanceAnchorBody {
                anchor_mode,
                ticker: anchor_ticker,
            },
        )),
        other => Some(Condition::Unknown {
            type_iri: other.to_string(),
        }),
    }
}

fn strs_to_ids(items: Vec<String>) -> Option<IdOrIds> {
    let mut iter = items.into_iter();
    let first = iter.next()?; // empty → None
    match iter.next() {
        None => Some(IdOrIds::Single(IdRef { id: first })),
        Some(second) => Some(IdOrIds::Multiple(
            std::iter::once(first)
                .chain(std::iter::once(second))
                .chain(iter)
                .map(|id| IdRef { id })
                .collect(),
        )),
    }
}

fn normalise_condition_type(raw: &str) -> String {
    // Fold full IRI forms to the short curie so match arms in
    // `parse_turtle_condition_body` can branch on a single string.
    match raw {
        "http://www.w3.org/ns/auth/acl#ClientCondition"
        | "https://www.w3.org/ns/auth/acl#ClientCondition" => "acl:ClientCondition".into(),
        "http://www.w3.org/ns/auth/acl#IssuerCondition"
        | "https://www.w3.org/ns/auth/acl#IssuerCondition" => "acl:IssuerCondition".into(),
        "http://www.w3.org/ns/auth/acl#PaymentCondition"
        | "https://www.w3.org/ns/auth/acl#PaymentCondition" => "acl:PaymentCondition".into(),
        "http://www.w3.org/ns/auth/acl#ProvenanceAnchor"
        | "https://www.w3.org/ns/auth/acl#ProvenanceAnchor" => "acl:ProvenanceAnchor".into(),
        other => other.to_string(),
    }
}

fn turtle_pop_term(input: &str) -> Option<(String, String)> {
    let input = input.trim_start();
    if let Some(rest) = input.strip_prefix('<') {
        let end = rest.find('>')?;
        Some((rest[..end].to_string(), rest[end + 1..].to_string()))
    } else if let Some(rest) = input.strip_prefix('"') {
        // Quoted string literal (e.g. `acl:anchorMode "always"`). Return the
        // unquoted content; honour `\"` escapes. The closing quote terminates
        // the term; any `^^<datatype>` / `@lang` suffix is left in the
        // remainder (object-list parsing ignores it for the predicates that
        // accept literals). Subjects/predicates are never quoted, so adding
        // this branch only widens object parsing — it never mis-pops elsewhere.
        let bytes = rest.as_bytes();
        let mut i = 0;
        let mut value = String::new();
        while i < bytes.len() {
            let c = bytes[i];
            if c == b'\\' && i + 1 < bytes.len() {
                // Preserve the escaped character verbatim (sufficient for the
                // short keyword literals conditions use).
                value.push(bytes[i + 1] as char);
                i += 2;
                continue;
            }
            if c == b'"' {
                return Some((value, rest[i + 1..].to_string()));
            }
            value.push(c as char);
            i += 1;
        }
        // Unterminated literal — bail (matches the prior conservative None).
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

// ---------------------------------------------------------------------------
// Unit tests — size-capped parsing (Sprint 12 security hardening).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_subject_and_https_restrictions_are_preserved() {
        for condition_predicate in [
            "acl:condition",
            "<https://www.w3.org/ns/auth/acl#condition>",
        ] {
            let acl = format!("<#r> a acl:Authorization; acl:agentClass foaf:Agent; acl:accessTo </x>; acl:mode acl:Read . <#r> {condition_predicate} [ a acl:PaymentCondition; acl:costSats 100 ] .");
            let doc = parse_turtle_acl(&acl).unwrap();
            let graph = doc.graph.unwrap();
            assert_eq!(graph.len(), 1);
            assert!(
                matches!(&graph[0].condition.as_ref().unwrap()[0], Condition::Payment(body) if body.cost_sats == 100)
            );
        }
    }

    #[test]
    fn quoted_hash_and_iri_semicolon_are_not_delimiters() {
        let acl = r##"<#r> a acl:Authorization; acl:accessTo <https://example/r?a=1;b=2>; acl:mode acl:Read; acl:condition [ a acl:ProvenanceAnchor; acl:anchorTicker "a#b" ] ."##;
        let graph = parse_turtle_acl(acl).unwrap().graph.unwrap();
        assert!(
            matches!(&graph[0].access_to, Some(IdOrIds::Single(id)) if id.id == "https://example/r?a=1;b=2")
        );
        assert!(
            matches!(&graph[0].condition.as_ref().unwrap()[0], Condition::ProvenanceAnchor(body) if body.ticker.as_deref() == Some("a#b"))
        );
        assert_eq!(
            strip_turtle_comments(r##""a\"#b" # real comment"##).trim(),
            r##""a\"#b""##
        );
    }

    /// Valid minimal Turtle ACL for round-trip sanity.
    const TINY_ACL: &str = r#"
        @prefix acl: <http://www.w3.org/ns/auth/acl#> .
        @prefix foaf: <http://xmlns.com/foaf/0.1/> .

        <#public> a acl:Authorization ;
            acl:agentClass foaf:Agent ;
            acl:accessTo </> ;
            acl:mode acl:Read .
    "#;

    /// One authorisation spread over several statements (N-Triples, or
    /// Turtle that repeats the subject) is one authorisation. The server
    /// writes ACLs back as N-Triples after a PATCH; reading each statement
    /// as its own authorisation kept only the `rdf:type` line and dropped
    /// every agent, mode and target.
    #[test]
    fn statements_about_one_subject_merge_into_one_authorization() {
        let nt = "<http://h/a.acl#o> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://www.w3.org/ns/auth/acl#Authorization> .\n\
                  <http://h/a.acl#o> <http://www.w3.org/ns/auth/acl#agent> <http://h/me#i> .\n\
                  <http://h/a.acl#o> <http://www.w3.org/ns/auth/acl#accessTo> </a/> .\n\
                  <http://h/a.acl#o> <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read> .\n\
                  <http://h/a.acl#o> <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> .\n\
                  <http://h/a.acl#x> <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Write> .\n";
        let doc = parse_turtle_acl(nt).unwrap();
        let graph = doc.graph.expect("one authorization");
        assert_eq!(graph.len(), 1, "an untyped subject is not an authorization");
        let auth = &graph[0];
        let ids = |f: &Option<IdOrIds>| -> Vec<String> {
            match f {
                None => vec![],
                Some(IdOrIds::Single(r)) => vec![r.id.clone()],
                Some(IdOrIds::Multiple(v)) => v.iter().map(|r| r.id.clone()).collect(),
            }
        };
        assert_eq!(ids(&auth.agent), vec!["http://h/me#i"]);
        assert_eq!(ids(&auth.access_to), vec!["/a/"]);
        assert_eq!(
            ids(&auth.mode),
            vec![
                "http://www.w3.org/ns/auth/acl#Read",
                "http://www.w3.org/ns/auth/acl#Control"
            ]
        );
    }

    #[test]
    fn parse_turtle_acl_with_limit_accepts_small_doc() {
        // A generous limit should succeed.
        let doc = parse_turtle_acl_with_limit(TINY_ACL, 1_048_576).unwrap();
        assert!(doc.graph.is_some());
    }

    #[test]
    fn parse_turtle_acl_with_limit_rejects_oversized_doc() {
        // Set limit to 10 bytes — well under the document size.
        let err = parse_turtle_acl_with_limit(TINY_ACL, 10).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("payload too large") || msg.contains("exceeds"),
            "error should mention size: {msg}"
        );
    }

    #[test]
    fn parse_turtle_acl_with_limit_boundary() {
        // Exactly at the boundary: len == limit should succeed.
        let doc_str = "a".repeat(100);
        // This won't be valid Turtle, but the size check passes and the
        // parser returns an empty-graph document (it is forgiving).
        let result = parse_turtle_acl_with_limit(&doc_str, 100);
        assert!(result.is_ok(), "exactly at limit should not reject");

        // One byte over the boundary should be rejected.
        let doc_str_over = "a".repeat(101);
        assert!(parse_turtle_acl_with_limit(&doc_str_over, 100).is_err());
    }

    #[test]
    fn default_limit_is_one_mib() {
        assert_eq!(MAX_ACL_BYTES, 1_048_576);
    }

    #[test]
    fn restrictive_condition_cannot_disappear() {
        for condition in [
            "[ acl:client <urn:client> ]",
            "[ a acl:ClientCondition",
            "[ a acl:PaymentCondition; acl:costSats \"not-a-number\" ]",
            "[ a acl:PaymentCondition ]",
        ] {
            let acl = format!("<#r> a acl:Authorization; acl:agentClass foaf:Agent; acl:accessTo <urn:private>; acl:mode acl:Read; acl:condition {condition} .");
            assert!(
                parse_turtle_acl(&acl).is_err(),
                "malformed condition accepted: {condition}"
            );
            use crate::wac::resolver::{
                classify_policy_read, PolicyOutcome, PolicyRead, PolicyStep,
            };
            assert!(
                matches!(
                    classify_policy_read(
                        "/private.acl",
                        PolicyRead::Present {
                            body: acl.as_bytes(),
                            content_type: "text/turtle"
                        },
                        false
                    ),
                    PolicyStep::Settled(PolicyOutcome::Invalid { .. })
                ),
                "malformed restriction must settle Invalid, never inherit"
            );
        }
        assert!(parse_turtle_acl("<#r> a acl:Authorization; acl:mode acl:Read; acl:condition [ a acl:ClientCondition; acl:client <urn:client> ] .").is_ok());
    }
}
