//! Solid N3 Patch, parsed with the full N3 grammar and applied as triples.
//!
//! Port of JSS `src/patch/quads.js` (PR #633, JSS `0.0.224`). The patch body is
//! parsed with [`oxttl`]'s N3 parser against the resource URL, so prefixed
//! names, `a`, `;`/`,` lists, typed and language-tagged literals, long strings
//! and relative IRIs all survive. Semantics follow the Solid Protocol and
//! JSS: a `solid:where` clause must match the document exactly once, every
//! triple in `solid:deletes` must be present, variables are bound by the
//! `where` clause, and blank nodes from the patch are minted fresh so they
//! never merge with the document's own.
//!
//! The public surface is re-exported from [`crate::ldp`].

use std::sync::atomic::{AtomicU64, Ordering};

use oxttl::n3::{N3Parser, N3Term};

use crate::error::PodError;
use crate::ldp::{Graph, PatchOutcome, Term, Triple};
use crate::rdf_input::{literal_to_term, MAX_RDF_INPUT_BYTES};

const SOLID: &str = "http://www.w3.org/ns/solid/terms#";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

/// Most triple patterns a `solid:where` formula may hold. Solid clients send
/// a handful; the bound keeps evaluation, a join over the document, small.
const MAX_WHERE_PATTERNS: usize = 32;

/// Most partial bindings `where` evaluation keeps between patterns.
/// Patterns are joined most-bound-first, so a selective clause stays far
/// below it; a clause whose evaluation exceeds it is refused (409) as too
/// broad, even where its final answer might have been unique.
const MAX_PARTIAL_BINDINGS: usize = 10_000;

/// Most pattern-against-triple comparisons one `where` evaluation makes.
/// Each comparison is constant-time (bindings borrow from the document and
/// are copied only on a match), so this bounds the work.
const MAX_MATCH_STEPS: usize = 10_000_000;

/// A position in a patch triple: a concrete RDF term or a `?variable`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchTerm {
    /// A concrete IRI, blank node or literal.
    Term(Term),
    /// A variable, named without its leading `?`.
    Variable(String),
}

/// One triple pattern from a `solid:inserts`, `solid:deletes` or
/// `solid:where` formula.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchTriple {
    /// Subject position.
    pub subject: PatchTerm,
    /// Predicate position.
    pub predicate: PatchTerm,
    /// Object position.
    pub object: PatchTerm,
}

/// A parsed Solid N3 Patch (`solid:InsertDeletePatch`).
///
/// Parsing and applying are separate so a server can authorise from the
/// parsed patch (an insert-only patch needs only `acl:Append`) and then apply
/// it inside its write lock.
///
/// ```
/// use solid_pod_rs::ldp::{Graph, N3Patch};
///
/// let patch = N3Patch::parse(
///     "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n\
///      @prefix sioc: <http://rdfs.org/sioc/ns#>.\n\
///      _:p a solid:InsertDeletePatch; solid:inserts { <#m1> sioc:content \"hello\" }.",
///     Some("https://pod.example/chat.ttl"),
/// )
/// .unwrap();
/// assert!(patch.is_insert_only());
/// let out = patch.apply(Graph::new()).unwrap();
/// assert_eq!(out.inserted, 1);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct N3Patch {
    /// Triples to add, after variable substitution.
    pub inserts: Vec<PatchTriple>,
    /// Triples to remove, after variable substitution; each must be present.
    pub deletes: Vec<PatchTriple>,
    /// Patterns that must match the document exactly once.
    pub where_clause: Vec<PatchTriple>,
}

impl N3Patch {
    /// Parse an N3 Patch body.
    ///
    /// `base_iri` is the absolute URL of the resource being patched; relative
    /// IRIs resolve against it. With `None`, a relative IRI is a syntax error.
    ///
    /// The patch resource is any subject typed `solid:InsertDeletePatch` or
    /// carrying `solid:inserts`, `solid:deletes` or `solid:where`; the triples
    /// of each formula it names are collected. An empty formula `{ }` is a
    /// no-op.
    ///
    /// # Errors
    ///
    /// [`PodError::BadRequest`] for a syntax error, a bad base IRI, a body
    /// with no patch resource, or a literal in subject or predicate position;
    /// [`PodError::PayloadTooLarge`] above
    /// [`MAX_RDF_INPUT_BYTES`](crate::rdf_input::MAX_RDF_INPUT_BYTES).
    pub fn parse(body: &str, base_iri: Option<&str>) -> Result<Self, PodError> {
        if body.len() > MAX_RDF_INPUT_BYTES {
            return Err(PodError::PayloadTooLarge(format!(
                "N3 Patch of {} bytes exceeds the {MAX_RDF_INPUT_BYTES} byte limit",
                body.len()
            )));
        }
        let mut parser = N3Parser::new();
        if let Some(base) = base_iri {
            parser = parser
                .with_base_iri(base)
                .map_err(|e| bad(format!("invalid base IRI: {e}")))?;
        }
        let mut quads = Vec::new();
        for item in parser.for_slice(body.as_bytes()) {
            quads.push(item.map_err(|e| bad(format!("Invalid N3 Patch: {e}")))?);
        }

        let is_patch_prop = |p: &N3Term| {
            matches!(p, N3Term::NamedNode(n) if [
                format!("{SOLID}inserts"),
                format!("{SOLID}deletes"),
                format!("{SOLID}where"),
            ].iter().any(|x| x == n.as_str()))
        };
        let is_patch_type = |p: &N3Term, o: &N3Term| {
            matches!(p, N3Term::NamedNode(n) if n.as_str() == RDF_TYPE)
                && matches!(o, N3Term::NamedNode(n) if n.as_str() == format!("{SOLID}InsertDeletePatch"))
        };
        let top: Vec<_> = quads
            .iter()
            .filter(|q| matches!(q.graph_name, oxrdf::GraphName::DefaultGraph))
            .collect();
        let patch_subjects: Vec<&N3Term> = top
            .iter()
            .filter(|q| is_patch_type(&q.predicate, &q.object) || is_patch_prop(&q.predicate))
            .map(|q| &q.subject)
            .collect();
        if patch_subjects.is_empty() {
            return Err(bad("Invalid N3 Patch: no solid:InsertDeletePatch found"));
        }

        let formula = |prop: &str| -> Result<Vec<PatchTriple>, PodError> {
            let predicate = format!("{SOLID}{prop}");
            let graphs: Vec<&str> = top
                .iter()
                .filter(|q| patch_subjects.contains(&&q.subject))
                .filter(|q| matches!(&q.predicate, N3Term::NamedNode(n) if n.as_str() == predicate))
                .filter_map(|q| match &q.object {
                    N3Term::BlankNode(b) => Some(b.as_str()),
                    _ => None,
                })
                .collect();
            quads
                .iter()
                .filter(|q| {
                    matches!(&q.graph_name, oxrdf::GraphName::BlankNode(g) if graphs.contains(&g.as_str()))
                })
                .map(|q| {
                    Ok(PatchTriple {
                        subject: pattern_term(&q.subject, "subject")?,
                        predicate: pattern_term(&q.predicate, "predicate")?,
                        object: pattern_term(&q.object, "object")?,
                    })
                })
                .collect()
        };

        let where_clause = formula("where")?;
        if where_clause.len() > MAX_WHERE_PATTERNS {
            return Err(bad(format!(
                "Invalid N3 Patch: the where clause has {} patterns, more than {MAX_WHERE_PATTERNS}",
                where_clause.len()
            )));
        }
        Ok(Self {
            inserts: formula("inserts")?,
            deletes: formula("deletes")?,
            where_clause,
        })
    }

    /// True when the patch only adds triples (no deletes, no `where`), which
    /// the Solid Protocol authorises with `acl:Append` alone.
    #[must_use]
    pub fn is_insert_only(&self) -> bool {
        self.deletes.is_empty() && self.where_clause.is_empty()
    }

    /// Apply the patch to `target`.
    ///
    /// # Errors
    ///
    /// [`PodError::Conflict`] (HTTP 409) when the `where` clause matches the
    /// document zero times or more than once (including when it is too
    /// broad to evaluate within a fixed budget), when a triple to delete is
    /// absent, or when a variable is used without being bound by `where`.
    pub fn apply(&self, target: Graph) -> Result<PatchOutcome, PodError> {
        let bindings = if self.where_clause.is_empty() {
            Vec::new()
        } else {
            let found = solutions(&self.where_clause, &target)?;
            match found.as_slice() {
                [only] => only
                    .iter()
                    .map(|(name, term)| ((*name).to_string(), (*term).clone()))
                    .collect(),
                [] => {
                    return Err(PodError::Conflict(
                        "the patch where clause does not match the resource".into(),
                    ))
                }
                _ => {
                    return Err(PodError::Conflict(
                        "the patch where clause matches more than once".into(),
                    ))
                }
            }
        };

        let mut fresh = FreshBlanks::default();
        let deletes = self
            .deletes
            .iter()
            .map(|t| substitute(t, &bindings, &mut fresh))
            .collect::<Result<Vec<_>, _>>()?;
        let inserts = self
            .inserts
            .iter()
            .map(|t| substitute(t, &bindings, &mut fresh))
            .collect::<Result<Vec<_>, _>>()?;

        let mut graph = target;
        let mut removal = Graph::new();
        for d in &deletes {
            if !graph.contains(d) {
                return Err(PodError::Conflict(format!(
                    "triple to delete not found: {d:?}"
                )));
            }
            removal.insert(d.clone());
        }
        graph.subtract(&removal);
        let mut addition = Graph::new();
        for i in inserts {
            addition.insert(i);
        }
        let inserted = addition.len();
        graph.extend(&addition);

        Ok(PatchOutcome {
            graph,
            inserted,
            deleted: removal.len(),
        })
    }
}

fn bad(msg: impl Into<String>) -> PodError {
    PodError::BadRequest(msg.into())
}

fn pattern_term(t: &N3Term, role: &str) -> Result<PatchTerm, PodError> {
    let term = match t {
        N3Term::Variable(v) => return Ok(PatchTerm::Variable(v.as_str().to_string())),
        N3Term::NamedNode(n) => Term::Iri(n.as_str().to_string()),
        N3Term::BlankNode(b) => Term::BlankNode(b.as_str().to_string()),
        N3Term::Literal(l) => {
            if role != "object" {
                return Err(bad(format!("a literal is not allowed in {role} position")));
            }
            literal_to_term(l)
        }
        #[allow(unreachable_patterns)]
        _ => return Err(bad(format!("unsupported N3 term in {role} position"))),
    };
    if role == "predicate" && !matches!(term, Term::Iri(_)) {
        return Err(bad("a patch predicate must be an IRI or a variable"));
    }
    Ok(PatchTerm::Term(term))
}

/// Variable bindings owned by the applied patch.
type Bindings = Vec<(String, Term)>;

fn bound<'a>(b: &'a Bindings, name: &str) -> Option<&'a Term> {
    b.iter().find(|(k, _)| k == name).map(|(_, v)| v)
}

/// Variable bindings during `where` evaluation, borrowing the variable names
/// from the patch and the values from the document, so extending one copies
/// pointers, never a literal's text.
type BorrowedBindings<'a> = Vec<(&'a str, &'a Term)>;

/// Extend `b` so `pattern` matches `triple`, or `None` when it cannot.
/// Allocates only on a match.
fn extend<'a>(
    pattern: &'a PatchTriple,
    triple: &'a Triple,
    b: &BorrowedBindings<'a>,
) -> Option<BorrowedBindings<'a>> {
    let mut added: [Option<(&'a str, &'a Term)>; 3] = [None; 3];
    let positions = [
        (&pattern.subject, &triple.subject),
        (&pattern.predicate, &triple.predicate),
        (&pattern.object, &triple.object),
    ];
    for (i, (p, t)) in positions.into_iter().enumerate() {
        match p {
            PatchTerm::Term(term) => {
                if term != t {
                    return None;
                }
            }
            PatchTerm::Variable(name) => {
                let earlier = b
                    .iter()
                    .copied()
                    .chain(added[..i].iter().flatten().copied())
                    .find(|(k, _)| *k == name.as_str());
                match earlier {
                    Some((_, v)) if v != t => return None,
                    Some(_) => {}
                    None => added[i] = Some((name.as_str(), t)),
                }
            }
        }
    }
    let mut next = b.clone();
    next.extend(added.into_iter().flatten());
    Some(next)
}

/// How many of `p`'s positions are fixed once the variables in `bound` are
/// known: constants, and variables already bound.
fn fixed_positions(p: &PatchTriple, bound: &[&str]) -> usize {
    [&p.subject, &p.predicate, &p.object]
        .into_iter()
        .filter(|t| match t {
            PatchTerm::Term(_) => true,
            PatchTerm::Variable(v) => bound.contains(&v.as_str()),
        })
        .count()
}

/// The bindings of the `where` patterns against the document, stopping at
/// two: the caller accepts exactly one, so a second already decides.
///
/// Patterns are joined most-bound-first: greedily, the pattern with the
/// most constants and already-bound variables next, ties going to the one
/// whose constants match the fewest triples. The answer and the cost do not
/// depend on the order the client wrote the patterns in. The graph is a
/// set, so a binding extended by a pattern it fully binds matches at most
/// one triple; distinct triples therefore give distinct bindings and no
/// deduplication is needed.
///
/// # Errors
///
/// [`PodError::Conflict`] when evaluation would exceed
/// [`MAX_PARTIAL_BINDINGS`] or [`MAX_MATCH_STEPS`].
fn solutions<'a>(
    patterns: &'a [PatchTriple],
    g: &'a Graph,
) -> Result<Vec<BorrowedBindings<'a>>, PodError> {
    let too_broad = || PodError::Conflict("the patch where clause is too broad to evaluate".into());
    let mut steps = 0usize;
    // How many triples each pattern's constants alone match: one scan per
    // pattern, charged to the step budget.
    let mut remaining: Vec<(&PatchTriple, usize)> = Vec::with_capacity(patterns.len());
    for p in patterns {
        let mut matches = 0usize;
        for t in g.triples() {
            steps += 1;
            if steps > MAX_MATCH_STEPS {
                return Err(too_broad());
            }
            if extend(p, t, &Vec::new()).is_some() {
                matches += 1;
            }
        }
        remaining.push((p, matches));
    }
    let mut bound_vars: Vec<&str> = Vec::new();
    let mut partial: Vec<BorrowedBindings<'a>> = vec![Vec::new()];
    while !remaining.is_empty() {
        let pick = (0..remaining.len())
            .max_by_key(|&i| {
                let (p, matches) = remaining[i];
                (
                    fixed_positions(p, &bound_vars),
                    usize::MAX - matches,
                    usize::MAX - i,
                )
            })
            .unwrap_or(0);
        let (p, _) = remaining.remove(pick);
        for t in [&p.subject, &p.predicate, &p.object] {
            if let PatchTerm::Variable(v) = t {
                if !bound_vars.contains(&v.as_str()) {
                    bound_vars.push(v.as_str());
                }
            }
        }
        let last = remaining.is_empty();
        let mut next = Vec::new();
        'extend: for b in &partial {
            for t in g.triples() {
                steps += 1;
                if steps > MAX_MATCH_STEPS {
                    return Err(too_broad());
                }
                if let Some(nb) = extend(p, t, b) {
                    next.push(nb);
                    if last && next.len() > 1 {
                        break 'extend;
                    }
                    if next.len() > MAX_PARTIAL_BINDINGS {
                        return Err(too_broad());
                    }
                }
            }
        }
        partial = next;
        if partial.is_empty() {
            break;
        }
    }
    Ok(partial)
}

/// Renames the patch's blank nodes to labels no document can already hold.
#[derive(Default)]
struct FreshBlanks {
    map: Vec<(String, String)>,
}

impl FreshBlanks {
    fn get(&mut self, label: &str) -> Term {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        if let Some((_, fresh)) = self.map.iter().find(|(l, _)| l == label) {
            return Term::BlankNode(fresh.clone());
        }
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let fresh = format!("p{}_{nonce:x}", COUNTER.fetch_add(1, Ordering::Relaxed));
        self.map.push((label.to_string(), fresh.clone()));
        Term::BlankNode(fresh)
    }
}

fn substitute(t: &PatchTriple, b: &Bindings, fresh: &mut FreshBlanks) -> Result<Triple, PodError> {
    let mut term = |p: &PatchTerm| -> Result<Term, PodError> {
        match p {
            PatchTerm::Variable(name) => bound(b, name)
                .cloned()
                .ok_or_else(|| PodError::Conflict(format!("unbound variable ?{name} in patch"))),
            PatchTerm::Term(Term::BlankNode(label)) => Ok(fresh.get(label)),
            PatchTerm::Term(t) => Ok(t.clone()),
        }
    };
    let subject = term(&t.subject)?;
    let predicate = term(&t.predicate)?;
    let object = term(&t.object)?;
    if matches!(subject, Term::Literal { .. }) || !matches!(predicate, Term::Iri(_)) {
        return Err(PodError::Conflict(
            "a variable bound to a literal cannot be a subject or predicate".into(),
        ));
    }
    Ok(Triple::new(subject, predicate, object))
}
