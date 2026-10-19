//! Turtle and Notation3 request-body parsing into the in-crate
//! [`ldp::Graph`](crate::ldp::Graph) triple model.
//!
//! JSS accepts `text/turtle` and `text/n3` as input representations when
//! content negotiation is on: `src/rdf/conneg.js` lists both in
//! `SUPPORTED_INPUT` (lines 16, 25) and `toJsonLd` routes either media type
//! through the n3.js based `turtleToJsonLd` in `src/rdf/turtle.js`
//! (conneg.js 144-145). This module is the Rust counterpart. It parses with
//! [`oxttl`], the Turtle/N3 sibling of the `oxrdf`/`spargebra` crates the
//! crate already depends on, and converts the result into the existing
//! triple model, so no second RDF stack is introduced.
//!
//! # Policy
//!
//! * Input is bounded: [`MAX_RDF_INPUT_BYTES`] and [`MAX_RDF_TRIPLES`].
//! * The base IRI is taken from the request URL so relative references
//!   (`<>`, `<#me>`, `<../x>`) resolve exactly as a client expects.
//! * `text/n3` is parsed with the N3 grammar but only the RDF-compatible
//!   subset is accepted. Quoted graphs (formulas) and variables are
//!   rejected with [`PodError::Unsupported`] (HTTP 415), as are the
//!   `log:implies` / `log:impliedBy` rules that need them. Literal
//!   subjects and any non-IRI predicate are rejected with
//!   [`PodError::BadRequest`] (HTTP 400) because they are not RDF triples.
//! * A syntax error is a [`PodError::BadRequest`] (HTTP 400).
//!
//! # Example
//!
//! ```
//! use solid_pod_rs::rdf_input::{parse_rdf_body, RdfInputSyntax};
//!
//! let g = parse_rdf_body(
//!     RdfInputSyntax::Turtle,
//!     br#"<#me> a <http://xmlns.com/foaf/0.1/Person> ."#,
//!     "https://pod.example/profile/card",
//! )
//! .unwrap();
//! assert_eq!(g.len(), 1);
//! ```

use oxttl::n3::{N3Parser, N3Term};
use oxttl::TurtleParser;

use crate::error::PodError;
use crate::ldp::{Graph, Term, Triple};

/// Largest accepted Turtle / N3 document, in bytes.
pub const MAX_RDF_INPUT_BYTES: usize = 4 * 1024 * 1024;

/// Largest number of triples a single document may expand to. Guards
/// against small inputs that fan out (deeply nested collections).
pub const MAX_RDF_TRIPLES: usize = 250_000;

const LOG_IMPLIES: &str = "http://www.w3.org/2000/10/swap/log#implies";
const LOG_IMPLIED_BY: &str = "http://www.w3.org/2000/10/swap/log#impliedBy";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const RDF_LANG_STRING: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString";

/// Concrete input syntax of a request body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdfInputSyntax {
    /// `text/turtle` (Turtle 1.1).
    Turtle,
    /// `text/n3` (Notation3, restricted to its RDF-compatible subset).
    N3,
}

impl RdfInputSyntax {
    /// Map a `Content-Type` header value (parameters ignored, case
    /// insensitive) to an input syntax. `application/turtle` and
    /// `application/x-turtle` are accepted as Turtle aliases.
    ///
    /// ```
    /// use solid_pod_rs::rdf_input::RdfInputSyntax;
    /// assert_eq!(RdfInputSyntax::from_content_type("text/n3; charset=utf-8"), Some(RdfInputSyntax::N3));
    /// assert_eq!(RdfInputSyntax::from_content_type("application/json"), None);
    /// ```
    pub fn from_content_type(content_type: &str) -> Option<Self> {
        let mime = content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        match mime.as_str() {
            "text/turtle" | "application/turtle" | "application/x-turtle" => Some(Self::Turtle),
            "text/n3" => Some(Self::N3),
            _ => None,
        }
    }
}

fn bad(msg: impl Into<String>) -> PodError {
    PodError::BadRequest(msg.into())
}

fn push_checked(g: &mut Graph, t: Triple) -> Result<(), PodError> {
    g.insert(t);
    if g.len() > MAX_RDF_TRIPLES {
        return Err(PodError::PayloadTooLarge(format!(
            "RDF document expands to more than {MAX_RDF_TRIPLES} triples"
        )));
    }
    Ok(())
}

fn literal_to_term(l: &oxrdf::Literal) -> Term {
    let value = l.value().to_string();
    if let Some(lang) = l.language() {
        return Term::Literal {
            value,
            datatype: None,
            language: Some(lang.to_string()),
        };
    }
    let dt = l.datatype().as_str();
    if dt == XSD_STRING || dt == RDF_LANG_STRING {
        Term::Literal {
            value,
            datatype: None,
            language: None,
        }
    } else {
        Term::Literal {
            value,
            datatype: Some(dt.to_string()),
            language: None,
        }
    }
}

fn subject_to_term(s: &oxrdf::Subject) -> Result<Term, PodError> {
    match s {
        oxrdf::Subject::NamedNode(n) => Ok(Term::Iri(n.as_str().to_string())),
        oxrdf::Subject::BlankNode(b) => Ok(Term::BlankNode(b.as_str().to_string())),
        #[allow(unreachable_patterns)]
        _ => Err(PodError::Unsupported(
            "quoted triples are not supported".into(),
        )),
    }
}

fn term_to_term(t: &oxrdf::Term) -> Result<Term, PodError> {
    match t {
        oxrdf::Term::NamedNode(n) => Ok(Term::Iri(n.as_str().to_string())),
        oxrdf::Term::BlankNode(b) => Ok(Term::BlankNode(b.as_str().to_string())),
        oxrdf::Term::Literal(l) => Ok(literal_to_term(l)),
        #[allow(unreachable_patterns)]
        _ => Err(PodError::Unsupported(
            "quoted triples are not supported".into(),
        )),
    }
}

fn n3_term(t: &N3Term, role: &str) -> Result<Term, PodError> {
    match t {
        N3Term::NamedNode(n) => Ok(Term::Iri(n.as_str().to_string())),
        N3Term::BlankNode(b) => Ok(Term::BlankNode(b.as_str().to_string())),
        N3Term::Literal(l) => Ok(literal_to_term(l)),
        N3Term::Variable(v) => Err(PodError::Unsupported(format!(
            "N3 variable ?{} in {role} position is not supported",
            v.as_str()
        ))),
        #[allow(unreachable_patterns)]
        _ => Err(PodError::Unsupported(format!(
            "unsupported N3 term in {role} position"
        ))),
    }
}

/// Parse a Turtle or N3 body into a [`Graph`].
///
/// `base_iri` is the absolute request URL (scheme, authority and path) and
/// is used to resolve relative IRIs. Returns:
///
/// * [`PodError::PayloadTooLarge`] over [`MAX_RDF_INPUT_BYTES`] bytes or
///   [`MAX_RDF_TRIPLES`] triples;
/// * [`PodError::BadRequest`] for a bad base IRI, a syntax error, a literal
///   subject or a non-IRI predicate;
/// * [`PodError::Unsupported`] for N3 formulas, variables and rules.
pub fn parse_rdf_body(
    syntax: RdfInputSyntax,
    body: &[u8],
    base_iri: &str,
) -> Result<Graph, PodError> {
    if body.len() > MAX_RDF_INPUT_BYTES {
        return Err(PodError::PayloadTooLarge(format!(
            "RDF body of {} bytes exceeds the {MAX_RDF_INPUT_BYTES} byte limit",
            body.len()
        )));
    }
    if std::str::from_utf8(body).is_err() {
        return Err(bad("RDF body is not valid UTF-8"));
    }
    match syntax {
        RdfInputSyntax::Turtle => parse_turtle_inner(body, base_iri),
        RdfInputSyntax::N3 => parse_n3_inner(body, base_iri),
    }
}

/// Parse a Turtle 1.1 document. Convenience wrapper over [`parse_rdf_body`].
pub fn parse_turtle(body: &[u8], base_iri: &str) -> Result<Graph, PodError> {
    parse_rdf_body(RdfInputSyntax::Turtle, body, base_iri)
}

/// Parse a Notation3 document (RDF-compatible subset). Convenience wrapper
/// over [`parse_rdf_body`].
pub fn parse_n3(body: &[u8], base_iri: &str) -> Result<Graph, PodError> {
    parse_rdf_body(RdfInputSyntax::N3, body, base_iri)
}

fn parse_turtle_inner(body: &[u8], base_iri: &str) -> Result<Graph, PodError> {
    let parser = TurtleParser::new()
        .with_base_iri(base_iri)
        .map_err(|e| bad(format!("invalid base IRI: {e}")))?;
    let mut g = Graph::new();
    for item in parser.for_slice(body) {
        let t = item.map_err(|e| bad(format!("Turtle syntax error: {e}")))?;
        let triple = Triple::new(
            subject_to_term(&t.subject)?,
            Term::Iri(t.predicate.as_str().to_string()),
            term_to_term(&t.object)?,
        );
        push_checked(&mut g, triple)?;
    }
    Ok(g)
}

fn parse_n3_inner(body: &[u8], base_iri: &str) -> Result<Graph, PodError> {
    let parser = N3Parser::new()
        .with_base_iri(base_iri)
        .map_err(|e| bad(format!("invalid base IRI: {e}")))?;
    let mut g = Graph::new();
    for item in parser.for_slice(body) {
        let q = item.map_err(|e| bad(format!("N3 syntax error: {e}")))?;
        if !matches!(q.graph_name, oxrdf::GraphName::DefaultGraph) {
            return Err(PodError::Unsupported(
                "N3 formulas (quoted graphs) are not supported".into(),
            ));
        }
        let subject = n3_term(&q.subject, "subject")?;
        let predicate = n3_term(&q.predicate, "predicate")?;
        let object = n3_term(&q.object, "object")?;
        if matches!(subject, Term::Literal { .. }) {
            return Err(bad("literal subjects are not valid RDF"));
        }
        match &predicate {
            Term::Iri(p) if p == LOG_IMPLIES || p == LOG_IMPLIED_BY => {
                return Err(PodError::Unsupported(
                    "N3 rules (log:implies) are not supported".into(),
                ));
            }
            Term::Iri(_) => {}
            _ => return Err(bad("predicate must be an IRI")),
        }
        push_checked(&mut g, Triple::new(subject, predicate, object))?;
    }
    Ok(g)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "https://pod.example/data/doc";

    fn nt(g: &Graph) -> String {
        g.to_ntriples()
    }

    #[test]
    fn turtle_resolves_relative_against_request_url() {
        let g = parse_turtle(b"<> <#p> <../o> .", BASE).unwrap();
        let t = g.triples().next().unwrap();
        assert_eq!(t.subject, Term::iri(BASE));
        assert_eq!(t.predicate, Term::iri("https://pod.example/data/doc#p"));
        assert_eq!(t.object, Term::iri("https://pod.example/o"));
    }

    #[test]
    fn turtle_prefixes_literals_and_lists() {
        let g = parse_turtle(
            b"@prefix ex: <http://e/> . ex:s ex:n 1 ; ex:l \"hi\"@en ; ex:t \"x\" ; ex:d \"1\"^^ex:T .",
            BASE,
        )
        .unwrap();
        let s = nt(&g);
        assert!(s.contains("<http://e/n> \"1\"^^<http://www.w3.org/2001/XMLSchema#integer>"));
        assert!(s.contains("\"hi\"@en"));
        assert!(s.contains("<http://e/t> \"x\" ."));
        assert!(s.contains("\"1\"^^<http://e/T>"));
    }

    #[test]
    fn syntax_error_is_bad_request() {
        assert!(matches!(
            parse_turtle(b"<a> <b> .", BASE),
            Err(PodError::BadRequest(_))
        ));
    }

    #[test]
    fn invalid_utf8_is_bad_request() {
        assert!(matches!(
            parse_turtle(&[0xff, 0xfe, 0x20], BASE),
            Err(PodError::BadRequest(_))
        ));
    }

    #[test]
    fn oversize_body_is_rejected_before_parsing() {
        let big = vec![b' '; MAX_RDF_INPUT_BYTES + 1];
        assert!(matches!(
            parse_turtle(&big, BASE),
            Err(PodError::PayloadTooLarge(_))
        ));
    }

    #[test]
    fn bad_base_is_bad_request() {
        assert!(matches!(
            parse_turtle(b"<a:b> <a:c> <a:d> .", "not an iri"),
            Err(PodError::BadRequest(_))
        ));
    }

    #[test]
    fn n3_plain_triples_parse() {
        let g = parse_n3(b"@prefix : <http://e/> . :a :b :c , :d .", BASE).unwrap();
        assert_eq!(g.len(), 2);
    }

    #[test]
    fn n3_formula_is_unsupported() {
        let r = parse_n3(b"@prefix : <http://e/> . { :a :b :c } :says :x .", BASE);
        assert!(matches!(r, Err(PodError::Unsupported(_))), "{r:?}");
    }

    #[test]
    fn n3_variable_is_unsupported() {
        let r = parse_n3(b"@prefix : <http://e/> . ?x :b :c .", BASE);
        assert!(matches!(r, Err(PodError::Unsupported(_))), "{r:?}");
    }

    #[test]
    fn n3_rule_is_unsupported() {
        let r = parse_n3(
            b"@prefix : <http://e/> . { ?x :a :b } => { ?x :c :d } .",
            BASE,
        );
        assert!(matches!(r, Err(PodError::Unsupported(_))), "{r:?}");
        let r = parse_n3(b"@prefix : <http://e/> . {} => {} .", BASE);
        assert!(r.is_err(), "empty-formula rule must be refused: {r:?}");
    }

    #[test]
    fn n3_literal_subject_is_bad_request() {
        let r = parse_n3(b"\"x\" <http://e/p> <http://e/o> .", BASE);
        assert!(matches!(r, Err(PodError::BadRequest(_))), "{r:?}");
    }

    #[test]
    fn content_type_mapping() {
        assert_eq!(
            RdfInputSyntax::from_content_type("Text/Turtle;charset=utf-8"),
            Some(RdfInputSyntax::Turtle)
        );
        assert_eq!(
            RdfInputSyntax::from_content_type("text/n3"),
            Some(RdfInputSyntax::N3)
        );
        assert_eq!(RdfInputSyntax::from_content_type("text/plain"), None);
    }
}
