//! JSON-LD ACL reading by expanded IRI (SP-PAR-265).
//!
//! A JSON-LD ACL is read through a real JSON-LD processor ([`oxjsonld`]), so a
//! rule is recognised by the IRIs its keys and values *expand to*, not by how
//! they were abbreviated: any prefix for the ACL vocabulary (`wac:`, `auth:`),
//! `@vocab`, the fully expanded form, a top-level array of expanded nodes, a
//! single node with no `@graph`, and `@type` given as an array all read the
//! same as the canonical `acl:`-keyed `@graph` document.
//!
//! # Policy
//!
//! * **Remote contexts are never fetched.** The processor has no document
//!   loader, so a remote `@context` (a string URL, or one inside an array) is
//!   an error. The ACL is then unreadable and the resolver denies, exactly as
//!   for any other malformed policy.
//! * **Implicit prefixes, underneath.** `acl:` and `foaf:` are bound to their
//!   vocabularies *before* the document's own `@context`, which can override
//!   them. A document with no `@context` at all (the shape this crate has
//!   always read) therefore still reads, and a document that rebinds `acl` to
//!   another vocabulary is read as it says.
//! * **Relative IRIs resolve against the ACL's own path** using a placeholder
//!   authority, so `/a/`, `./b`, `../c` and `#me` mean what they say. Targets
//!   and agents that came from a relative reference are rewritten to path
//!   form (`/a/b`, `/alice/card#me`); [`AclBase`](crate::wac::AclBase) turns a
//!   relative agent into an absolute WebID when the pod origin is configured.
//!   An IRI that really names the placeholder host is indistinguishable from a
//!   relative one and is read the same way; it can name only this pod.
//!   This happens with or without a configured pod origin: expansion cannot
//!   tell `/a/` from `./a/`, and a relative reference can only name this pod.
//!   A Turtle ACL with no configured origin still leaves `./a/` unresolved
//!   (it denies), so the two syntaxes differ on relative targets until an
//!   origin is configured; absolute IRIs deny in both.
//! * Only the default graph is read. Quads in a named graph are ignored, so
//!   they can add no rule.
//! * Everything a rule is built from is read from the expansion: the rule
//!   fields (`agent`, `agentClass`, `agentGroup`, `origin`, `accessTo`,
//!   `default`, `mode`) and `acl:condition` nodes. An `acl:condition` that
//!   cannot be read as a typed node makes the whole document unreadable
//!   rather than silently dropping a restriction.

use std::collections::HashMap;

use serde_json::{json, Map, Value};

use crate::error::PodError;
use crate::wac::document::AclDocument;

const ACL_NS: &str = "http://www.w3.org/ns/auth/acl#";
const FOAF_NS: &str = "http://xmlns.com/foaf/0.1/";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
/// Placeholder authority that relative references resolve against.
const SENTINEL: &str = "https://acl-base.invalid";
/// Its host, which no document may spell out.
const SENTINEL_HOST: &str = "acl-base.invalid";
/// Cap on the quads one ACL document may expand to.
const MAX_QUADS: usize = 10_000;

const RULE_PREDICATES: [&str; 8] = [
    "agent",
    "agentClass",
    "agentGroup",
    "origin",
    "accessTo",
    "default",
    "mode",
    "condition",
];
const CONDITION_PREDICATES: [&str; 9] = [
    "client",
    "clientGroup",
    "clientClass",
    "issuer",
    "issuerGroup",
    "issuerClass",
    "costSats",
    "anchorMode",
    "anchorTicker",
];

#[derive(Debug, Clone)]
enum Obj {
    Iri(String),
    Blank(String),
    Literal { value: String, datatype: String },
}

/// Read a JSON-LD ACL body by expanded IRI. `doc_path` is the storage path of
/// the ACL document and anchors relative IRIs.
///
/// # Errors
///
/// [`PodError::AclParse`] when the body is not JSON, is not a JSON-LD
/// document, needs a remote context, or holds an unreadable `acl:condition`.
pub(crate) fn parse_expanded(body: &[u8], doc_path: &str) -> Result<AclDocument, PodError> {
    let err = |m: String| PodError::AclParse(format!("JSON-LD ACL: {m}"));
    // The placeholder authority must be unnameable: a document that spells it
    // out is refused, so nothing but a relative reference can resolve to it.
    if std::str::from_utf8(body).is_ok_and(|t| t.contains(SENTINEL_HOST)) {
        return Err(err("the reserved placeholder host may not appear".into()));
    }
    let mut value: Value =
        serde_json::from_slice(body).map_err(|e| err(format!("not JSON: {e}")))?;
    let defaults = json!({ "acl": ACL_NS, "foaf": FOAF_NS });
    value = match value {
        Value::Object(mut m) => {
            // A top-level object that carries `@graph` is a container for the
            // rules in it. Any other key beside it (a stray `label`) would
            // make a streaming processor treat the whole `@graph` as a named
            // graph, which is not read; this crate has always ignored such
            // keys, so drop them. An `@id` is kept: that is a named graph by
            // design and adds no rule.
            if m.contains_key("@graph") {
                m.retain(|k, _| matches!(k.as_str(), "@context" | "@graph" | "@id"));
            }
            let mut ctx = vec![defaults];
            match m.remove("@context") {
                None => {}
                Some(Value::Array(items)) => ctx.extend(items),
                Some(other) => ctx.push(other),
            }
            m.insert("@context".into(), Value::Array(ctx));
            Value::Object(m)
        }
        // An empty top-level array holds no node at all: not an ACL document.
        Value::Array(items) if items.is_empty() => {
            return Err(err("an empty array is not an ACL document".into()))
        }
        Value::Array(items) => json!({ "@context": [defaults], "@graph": items }),
        _ => return Err(err("the top level is neither an object nor an array".into())),
    };
    let patched = serde_json::to_vec(&value).map_err(|e| err(e.to_string()))?;

    let base = format!(
        "{SENTINEL}{}",
        if doc_path.starts_with('/') {
            doc_path
        } else {
            "/"
        }
    );
    let parser = oxjsonld::JsonLdParser::new()
        .with_base_iri(base)
        .map_err(|e| err(format!("bad base: {e}")))?;

    // Subjects in first-seen order, each with its (predicate, object) pairs.
    let mut order: Vec<String> = Vec::new();
    let mut nodes: HashMap<String, Vec<(String, Obj)>> = HashMap::new();
    let mut quads = 0usize;
    for item in parser.for_slice(&patched) {
        let q = item.map_err(|e| err(e.to_string()))?;
        if !matches!(q.graph_name, oxrdf::GraphName::DefaultGraph) {
            continue;
        }
        quads += 1;
        if quads > MAX_QUADS {
            return Err(PodError::PayloadTooLarge(format!(
                "JSON-LD ACL expands to more than {MAX_QUADS} quads"
            )));
        }
        let subject = match &q.subject {
            oxrdf::Subject::NamedNode(n) => format!("<{}>", n.as_str()),
            oxrdf::Subject::BlankNode(b) => format!("_:{}", b.as_str()),
            #[allow(unreachable_patterns)]
            _ => return Err(err("quoted triples are not supported".into())),
        };
        let object = match &q.object {
            oxrdf::Term::NamedNode(n) => Obj::Iri(n.as_str().to_string()),
            oxrdf::Term::BlankNode(b) => Obj::Blank(format!("_:{}", b.as_str())),
            oxrdf::Term::Literal(l) => Obj::Literal {
                value: l.value().to_string(),
                datatype: l.datatype().as_str().to_string(),
            },
            // `Term::Triple` exists when any crate in the build enables
            // `oxrdf/rdf-star` (oxigraph does); quoted triples are not ACL terms.
            #[allow(unreachable_patterns)]
            _ => return Err(err("quoted triples are not supported".into())),
        };
        if !nodes.contains_key(&subject) {
            order.push(subject.clone());
        }
        nodes
            .entry(subject)
            .or_default()
            .push((q.predicate.as_str().to_string(), object));
    }

    let is_acl = |p: &str, names: &[&str]| {
        p.strip_prefix(ACL_NS)
            .is_some_and(|local| names.contains(&local))
    };
    let mut graph = Vec::new();
    for subject in &order {
        let props = &nodes[subject];
        let is_rule = props.iter().any(|(p, o)| {
            is_acl(p, &RULE_PREDICATES)
                || (p == RDF_TYPE
                    && matches!(o, Obj::Iri(t) if t == &format!("{ACL_NS}Authorization")))
        });
        if !is_rule {
            continue;
        }
        graph.push(rule_json(subject, props, &nodes)?);
    }
    // No rule at all is the empty document, as it always was for `{}`.
    let doc = if graph.is_empty() {
        json!({})
    } else {
        json!({ "@graph": graph })
    };
    serde_json::from_value::<AclDocument>(doc).map_err(|e| err(format!("not an ACL document: {e}")))
}

/// Compact an expanded IRI to the form the evaluator compares: the ACL and
/// FOAF vocabularies to `acl:` / `foaf:`, a relative reference (placeholder
/// authority) to its path, anything else verbatim.
fn compact(iri: &str) -> String {
    // Strip the placeholder only when the URL's host is exactly it, with no
    // port or userinfo and a path that is empty or starts with `/`; a string
    // prefix would also match `https://acl-base.invalid.evil.example/x`.
    if let Some(rest) = iri.strip_prefix(SENTINEL) {
        if rest.is_empty() || rest.starts_with(['/', '?', '#']) {
            if let Ok(u) = url::Url::parse(iri) {
                if u.scheme() == "https"
                    && u.host_str() == Some(SENTINEL_HOST)
                    && u.port().is_none()
                    && u.username().is_empty()
                    && u.password().is_none()
                {
                    return if rest.starts_with('/') {
                        rest.to_string()
                    } else {
                        format!("/{rest}")
                    };
                }
            }
        }
    }
    if let Some(local) = iri.strip_prefix(ACL_NS) {
        return format!("acl:{local}");
    }
    if let Some(local) = iri.strip_prefix(FOAF_NS) {
        return format!("foaf:{local}");
    }
    iri.to_string()
}

fn id_ref(o: &Obj) -> Option<Value> {
    match o {
        Obj::Iri(i) => Some(json!({ "@id": compact(i) })),
        _ => None,
    }
}

/// `{"@id": ..}` for one value, an array for several, absent for none.
fn one_or_many(mut values: Vec<Value>) -> Option<Value> {
    match values.len() {
        0 => None,
        1 => values.pop(),
        _ => Some(Value::Array(values)),
    }
}

fn rule_json(
    subject: &str,
    props: &[(String, Obj)],
    nodes: &HashMap<String, Vec<(String, Obj)>>,
) -> Result<Value, PodError> {
    let mut out = Map::new();
    if let Some(iri) = subject.strip_prefix('<').and_then(|s| s.strip_suffix('>')) {
        out.insert("@id".into(), Value::String(compact(iri)));
    }
    for name in &RULE_PREDICATES[..7] {
        let iri = format!("{ACL_NS}{name}");
        let mut values: Vec<Value> = Vec::new();
        for (_, o) in props.iter().filter(|(p, _)| *p == iri) {
            // A rule predicate takes IRIs. Dropping a literal here would, for
            // `acl:origin`, turn a restricted rule into an unrestricted grant,
            // so any non-IRI object makes the whole document unreadable.
            let Some(v) = id_ref(o) else {
                return Err(PodError::AclParse(format!(
                    "JSON-LD ACL: acl:{name} must take IRIs, not a literal or blank node"
                )));
            };
            values.push(v);
        }
        if let Some(v) = one_or_many(values) {
            out.insert(format!("acl:{name}"), v);
        }
    }
    let cond_iri = format!("{ACL_NS}condition");
    let mut conditions = Vec::new();
    for (_, o) in props.iter().filter(|(p, _)| *p == cond_iri) {
        conditions.push(condition_json(o, nodes)?);
    }
    if !conditions.is_empty() {
        out.insert("acl:condition".into(), Value::Array(conditions));
    }
    Ok(Value::Object(out))
}

/// One `acl:condition` value as the typed JSON the condition deserialiser
/// reads. A value that is not a node with a type is an error, never a dropped
/// restriction.
fn condition_json(o: &Obj, nodes: &HashMap<String, Vec<(String, Obj)>>) -> Result<Value, PodError> {
    let key = match o {
        Obj::Blank(b) => b.clone(),
        Obj::Iri(i) => format!("<{i}>"),
        Obj::Literal { .. } => {
            return Err(PodError::AclParse(
                "JSON-LD ACL: acl:condition must be a node".into(),
            ))
        }
    };
    let props = nodes.get(&key).map(Vec::as_slice).unwrap_or(&[]);
    let mut out = Map::new();
    let ty = props.iter().find_map(|(p, o)| match o {
        Obj::Iri(t) if p == RDF_TYPE => Some(compact(t)),
        _ => None,
    });
    let Some(ty) = ty else {
        return Err(PodError::AclParse(
            "JSON-LD ACL: acl:condition node has no type".into(),
        ));
    };
    out.insert("@type".into(), Value::String(ty));
    for name in CONDITION_PREDICATES {
        let iri = format!("{ACL_NS}{name}");
        let values: Vec<Value> = props
            .iter()
            .filter(|(p, _)| *p == iri)
            .filter_map(|(_, o)| match o {
                Obj::Iri(_) => id_ref(o),
                Obj::Literal { value, datatype } => Some(literal_json(name, value, datatype)),
                Obj::Blank(_) => None,
            })
            .collect();
        if let Some(v) = one_or_many(values) {
            out.insert(format!("acl:{name}"), v);
        }
    }
    Ok(Value::Object(out))
}

fn literal_json(name: &str, value: &str, datatype: &str) -> Value {
    if name == "costSats" && datatype.starts_with("http://www.w3.org/2001/XMLSchema#") {
        if let Ok(n) = value.parse::<u64>() {
            return json!(n);
        }
    }
    Value::String(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wac::{evaluate_access, AccessMode};

    const WEBID: &str = "https://alice.example/card#me";

    fn read(doc: &Value, path: &str, who: Option<&str>, mode: AccessMode) -> bool {
        let d = parse_expanded(doc.to_string().as_bytes(), "/r.acl").expect("readable");
        evaluate_access(Some(&d), who, path, mode, None)
    }

    #[test]
    fn every_expressible_shape_reads_the_same() {
        let shapes = [
            // Canonical acl:-keyed @graph (control).
            json!({"@context": {"acl": ACL_NS}, "@graph": [{
                "@id": "#owner", "@type": "acl:Authorization",
                "acl:agent": {"@id": WEBID}, "acl:accessTo": {"@id": "/r"},
                "acl:mode": [{"@id":"acl:Read"},{"@id":"acl:Write"}]}]}),
            // Alternative prefix.
            json!({"@context": {"wac": ACL_NS}, "@graph": [{
                "@id": "#owner", "@type": "wac:Authorization",
                "wac:agent": {"@id": WEBID}, "wac:accessTo": {"@id": "/r"},
                "wac:mode": [{"@id":"wac:Read"},{"@id":"wac:Write"}]}]}),
            // Context as an array of objects.
            json!({"@context": [{"auth": ACL_NS}, {"x": "http://x.example/"}], "@graph": [{
                "@id": "#owner", "@type": "auth:Authorization",
                "auth:agent": {"@id": WEBID}, "auth:accessTo": {"@id": "/r"},
                "auth:mode": [{"@id":"auth:Read"},{"@id":"auth:Write"}]}]}),
            // @vocab with typed terms and no @graph.
            json!({"@context": {"@vocab": ACL_NS,
                "agent": {"@id": format!("{ACL_NS}agent"), "@type": "@id"},
                "accessTo": {"@id": format!("{ACL_NS}accessTo"), "@type": "@id"},
                "mode": {"@id": format!("{ACL_NS}mode"), "@type": "@vocab"}},
                "@id": "#owner", "@type": "Authorization", "agent": WEBID,
                "accessTo": "/r", "mode": ["Read", "Write"]}),
            // Fully expanded, as a top-level array.
            json!([{ "@id": "#owner", "@type": [format!("{ACL_NS}Authorization")],
                format!("{ACL_NS}agent"): [{"@id": WEBID}],
                format!("{ACL_NS}accessTo"): [{"@id": "/r"}],
                format!("{ACL_NS}mode"): [{"@id": format!("{ACL_NS}Read")},
                                          {"@id": format!("{ACL_NS}Write")}]}]),
            // Single node, @type as an array, no @graph.
            json!({"@context": {"acl": ACL_NS}, "@id": "#owner",
                "@type": ["acl:Authorization"],
                "acl:agent": {"@id": WEBID}, "acl:accessTo": {"@id": "/r"},
                "acl:mode": [{"@id":"acl:Read"},{"@id":"acl:Write"}]}),
            // No @context at all: the shape this crate has always read.
            json!({"@graph": [{
                "@id": "#owner", "@type": "acl:Authorization",
                "acl:agent": {"@id": WEBID}, "acl:accessTo": {"@id": "/r"},
                "acl:mode": [{"@id":"acl:Read"},{"@id":"acl:Write"}]}]}),
        ];
        for (i, doc) in shapes.iter().enumerate() {
            assert!(
                read(doc, "/r", Some(WEBID), AccessMode::Read),
                "shape {i} read"
            );
            assert!(
                read(doc, "/r", Some(WEBID), AccessMode::Write),
                "shape {i} write"
            );
            assert!(
                !read(doc, "/r", Some(WEBID), AccessMode::Control),
                "shape {i} control"
            );
            assert!(
                !read(doc, "/r", Some("https://eve.example/#me"), AccessMode::Read),
                "shape {i} other"
            );
            assert!(!read(doc, "/r", None, AccessMode::Read), "shape {i} anon");
        }
    }

    #[test]
    fn an_agent_class_is_read_through_any_foaf_prefix() {
        let doc = json!({"@context": {"wac": ACL_NS, "people": FOAF_NS}, "@graph": [{
            "@id": "#public", "@type": "wac:Authorization",
            "wac:agentClass": {"@id": "people:Agent"},
            "wac:accessTo": {"@id": "/r"}, "wac:mode": {"@id": "wac:Read"}}]});
        assert!(read(&doc, "/r", None, AccessMode::Read));
        assert!(!read(&doc, "/r", None, AccessMode::Write));
    }

    #[test]
    fn a_remote_context_makes_the_acl_unreadable() {
        for ctx in [
            json!("https://www.w3.org/ns/solid/context"),
            json!(["https://www.w3.org/ns/solid/context", {"auth": ACL_NS}]),
            json!({"@import": "https://remote.example/ctx.jsonld"}),
        ] {
            let doc = json!({"@context": ctx, "@graph": [{
                "@id": "#o", "@type": "auth:Authorization",
                "auth:agent": {"@id": WEBID}, "auth:accessTo": {"@id": "/r"},
                "auth:mode": {"@id": "auth:Read"}}]});
            assert!(
                parse_expanded(doc.to_string().as_bytes(), "/r.acl").is_err(),
                "{ctx}: must be unreadable so the resolver denies"
            );
        }
    }

    #[test]
    fn a_context_that_rebinds_acl_is_read_as_it_says() {
        // `acl` here is NOT the WAC vocabulary, so this grants nothing.
        let doc = json!({"@context": {"acl": "http://evil.example/ns#"}, "@graph": [{
            "@id": "#o", "@type": "acl:Authorization",
            "acl:agentClass": {"@id": "foaf:Agent"}, "acl:accessTo": {"@id": "/r"},
            "acl:mode": {"@id": "acl:Read"}}]});
        assert!(!read(&doc, "/r", Some(WEBID), AccessMode::Read));
        assert!(!read(&doc, "/r", None, AccessMode::Read));
    }

    #[test]
    fn relative_iris_resolve_against_the_acl_path() {
        let doc = |target: &str| {
            json!({"@context": {"acl": ACL_NS}, "@graph": [{
                "@id": "#o", "@type": "acl:Authorization",
                "acl:agentClass": {"@id": "foaf:Agent"},
                "acl:accessTo": {"@id": target}, "acl:mode": {"@id": "acl:Read"}}]})
        };
        let at = |target: &str, path: &str| {
            let d = parse_expanded(doc(target).to_string().as_bytes(), "/a/b.acl").unwrap();
            evaluate_access(Some(&d), None, path, AccessMode::Read, None)
        };
        assert!(at("/a/b", "/a/b"));
        assert!(at("./b", "/a/b"));
        assert!(at("b", "/a/b"));
        assert!(!at("./b", "/b"), "./b is relative to the ACL, not the root");
        assert!(at("../x", "/x"));
        // An absolute IRI on another origin stays absolute and matches no path.
        assert!(!at("https://other.example/a/b", "/a/b"));
    }

    #[test]
    fn quads_in_a_named_graph_add_no_rule() {
        let doc = json!({"@context": {"acl": ACL_NS}, "@id": "http://x.example/g", "@graph": [{
            "@id": "#o", "@type": "acl:Authorization",
            "acl:agentClass": {"@id": "foaf:Agent"}, "acl:accessTo": {"@id": "/r"},
            "acl:mode": {"@id": "acl:Read"}}]});
        assert!(!read(&doc, "/r", None, AccessMode::Read));
    }

    #[test]
    fn conditions_are_read_and_an_unreadable_one_voids_the_document() {
        let ok = json!({"@context": {"acl": ACL_NS}, "@graph": [{
            "@id": "#p", "@type": "acl:Authorization",
            "acl:agentClass": {"@id": "foaf:Agent"}, "acl:accessTo": {"@id": "/r"},
            "acl:mode": {"@id": "acl:Read"},
            "acl:condition": {"@type": "acl:PaymentCondition", "acl:costSats": 5}}]});
        let d = parse_expanded(ok.to_string().as_bytes(), "/r.acl").unwrap();
        let rule = &d.graph.as_ref().unwrap()[0];
        assert_eq!(rule.condition.as_ref().map(Vec::len), Some(1));
        // The restriction is not dropped: the payment gate is still there.
        assert_eq!(
            crate::wac::total_payment_cost(rule.condition.as_ref().unwrap()),
            5
        );
        // An untyped condition node, and a literal condition, are errors.
        for bad in [json!({"acl:costSats": 5}), json!("free")] {
            let doc = json!({"@context": {"acl": ACL_NS}, "@graph": [{
                "@id": "#p", "@type": "acl:Authorization",
                "acl:agentClass": {"@id": "foaf:Agent"}, "acl:accessTo": {"@id": "/r"},
                "acl:mode": {"@id": "acl:Read"}, "acl:condition": bad}]});
            assert!(
                parse_expanded(doc.to_string().as_bytes(), "/r.acl").is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn stray_top_level_keys_beside_graph_do_not_hide_the_rules() {
        // A PATCH that adds `label` to a stored ACL must not turn its @graph
        // into an unread named graph and lock the owner out.
        let doc = json!({"@context": {"acl": ACL_NS}, "label": "updated", "@graph": [{
            "@id": "#o", "@type": "acl:Authorization",
            "acl:agentClass": {"@id": "foaf:Agent"}, "acl:accessTo": {"@id": "/r"},
            "acl:mode": {"@id": "acl:Read"}}]});
        assert!(read(&doc, "/r", None, AccessMode::Read));
    }

    #[test]
    fn a_foreign_iri_that_merely_starts_like_the_placeholder_never_becomes_a_local_path() {
        // The placeholder host stands for "relative reference". These are
        // other hosts (or carry a port or userinfo) and must never be read
        // as this pod's paths: the document is refused outright.
        for iri in [
            "https://acl-base.invalid.evil.example/x",
            "https://acl-base.invalid:8443/x",
            "https://user@acl-base.invalid/x",
            "https://acl-base.invalid@evil.example/x",
            "https://acl-base.invalid/x",
            "http://acl-base.invalid/x",
        ] {
            let doc = json!({"@context": {"acl": ACL_NS}, "@graph": [{
                "@id": "#o", "@type": "acl:Authorization",
                "acl:agentClass": {"@id": "foaf:Agent"},
                "acl:accessTo": {"@id": iri}, "acl:mode": {"@id": "acl:Read"}}]});
            assert!(
                parse_expanded(doc.to_string().as_bytes(), "/r.acl").is_err(),
                "{iri} must make the ACL unreadable"
            );
        }
        // And `compact` itself, whatever reaches it, is URL-exact.
        assert_eq!(compact("https://acl-base.invalid/x/y#f"), "/x/y#f");
        assert_eq!(compact("https://acl-base.invalid"), "/");
        for foreign in [
            "https://acl-base.invalid.evil.example/x",
            "https://acl-base.invalid:8443/x",
            "https://u@acl-base.invalid/x",
            "https://acl-base.invalid@evil.example/x",
        ] {
            assert_eq!(compact(foreign), foreign, "{foreign}");
        }
    }

    #[test]
    fn a_non_iri_object_on_a_rule_predicate_makes_the_acl_unreadable() {
        for pred in [
            "agent",
            "agentClass",
            "agentGroup",
            "origin",
            "accessTo",
            "default",
            "mode",
        ] {
            for obj in [
                json!("https://app.example"),
                json!({"@value": 7}),
                json!({"x": "blank"}),
            ] {
                let mut node = json!({
                    "@id": "#o", "@type": "acl:Authorization",
                    "acl:agentClass": {"@id": "foaf:Agent"},
                    "acl:accessTo": {"@id": "/r"}, "acl:mode": {"@id": "acl:Read"}});
                node[format!("acl:{pred}")] =
                    json!([node[format!("acl:{pred}")].clone(), obj.clone()]);
                if node[format!("acl:{pred}")][0].is_null() {
                    node[format!("acl:{pred}")] = json!([obj.clone()]);
                }
                let doc = json!({"@context": {"acl": ACL_NS, "x": "http://x.example/"}, "@graph": [node]});
                assert!(
                    parse_expanded(doc.to_string().as_bytes(), "/r.acl").is_err(),
                    "acl:{pred} with {obj} must be unreadable"
                );
            }
        }
    }

    #[test]
    fn malformed_input_is_an_error() {
        for body in ["{not json", "42", "\"s\"", "null", "[]"] {
            assert!(parse_expanded(body.as_bytes(), "/r.acl").is_err(), "{body}");
        }
    }
}
