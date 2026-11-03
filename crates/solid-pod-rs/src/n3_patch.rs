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
/// Patterns are joined most-selective-first, so a selective clause stays far
/// below it; a clause whose evaluation exceeds it is refused (409) as too
/// broad, even where its final answer might have been unique.
const MAX_PARTIAL_BINDINGS: usize = 10_000;

/// Most pattern-against-triple comparisons one `where` evaluation's join
/// makes. Terms are interned to integer ids first, so each comparison is
/// constant-time whatever the length of the IRIs and literals involved.
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

/// A `where` solution: each variable name with the document term bound to it.
type BorrowedBindings<'a> = Vec<(&'a str, &'a Term)>;

/// Marks an unbound variable slot in an interned binding.
const UNBOUND: u32 = u32::MAX;

/// One position of a `where` pattern, interned against the document.
#[derive(Clone, Copy)]
enum Slot {
    /// A constant, by term id; `None` when the document never holds it, so
    /// the pattern cannot match.
    Const(Option<u32>),
    /// A variable, by index into the binding.
    Var(usize),
}

/// Extend interned binding `b` so pattern `p` matches triple `t`, or `None`.
/// Constant-time; allocates only on a match.
fn extend(p: &[Slot; 3], t: &[u32; 3], b: &[u32]) -> Option<Vec<u32>> {
    let mut tentative: [(usize, u32); 3] = [(usize::MAX, UNBOUND); 3];
    for i in 0..3 {
        match p[i] {
            Slot::Const(Some(id)) if id == t[i] => {}
            Slot::Const(_) => return None,
            Slot::Var(v) => {
                let earlier = if b[v] != UNBOUND {
                    Some(b[v])
                } else {
                    tentative[..i]
                        .iter()
                        .find(|(k, _)| *k == v)
                        .map(|(_, id)| *id)
                };
                match earlier {
                    Some(id) if id != t[i] => return None,
                    Some(_) => {}
                    None => tentative[i] = (v, t[i]),
                }
            }
        }
    }
    let mut next = b.to_vec();
    for (v, id) in tentative {
        if v != usize::MAX {
            next[v] = id;
        }
    }
    Some(next)
}

/// The bindings of the `where` patterns against the document, stopping at
/// two: the caller accepts exactly one, so a second already decides.
///
/// Every document term is interned to an integer id once (hashing, linear in
/// the document's size), so the join compares ids in constant time. Each
/// pattern's matches are counted once, then patterns are joined greedily:
/// next, a pattern sharing a variable already bound (avoiding cartesian
/// products), fewest counted matches first. The answer and the cost do not
/// depend on the order the client wrote the patterns in. The graph is a set,
/// so a binding extended by a pattern it fully binds matches at most one
/// triple; distinct triples therefore give distinct bindings.
///
/// # Errors
///
/// [`PodError::Conflict`] when the join would exceed
/// [`MAX_PARTIAL_BINDINGS`] or [`MAX_MATCH_STEPS`].
fn solutions<'a>(
    patterns: &'a [PatchTriple],
    g: &'a Graph,
) -> Result<Vec<BorrowedBindings<'a>>, PodError> {
    let too_broad = || PodError::Conflict("the patch where clause is too broad to evaluate".into());

    let mut ids: std::collections::HashMap<&'a Term, u32> = std::collections::HashMap::new();
    let mut terms: Vec<&'a Term> = Vec::new();
    let mut intern = |t: &'a Term| -> u32 {
        *ids.entry(t).or_insert_with(|| {
            terms.push(t);
            u32::try_from(terms.len() - 1).unwrap_or(UNBOUND)
        })
    };
    let triples: Vec<[u32; 3]> = g
        .triples()
        .map(|t| [intern(&t.subject), intern(&t.predicate), intern(&t.object)])
        .collect();

    let mut var_names: Vec<&'a str> = Vec::new();
    let compiled: Vec<[Slot; 3]> = patterns
        .iter()
        .map(|p| {
            [&p.subject, &p.predicate, &p.object].map(|term| match term {
                PatchTerm::Term(t) => Slot::Const(ids.get(t).copied()),
                PatchTerm::Variable(name) => {
                    Slot::Var(match var_names.iter().position(|n| *n == name.as_str()) {
                        Some(i) => i,
                        None => {
                            var_names.push(name.as_str());
                            var_names.len() - 1
                        }
                    })
                }
            })
        })
        .collect();
    let empty = vec![UNBOUND; var_names.len()];
    // Matches per pattern on its own: one linear scan each, at most
    // MAX_WHERE_PATTERNS of them, outside the join budget.
    let counts: Vec<usize> = compiled
        .iter()
        .map(|p| {
            triples
                .iter()
                .filter(|t| extend(p, t, &empty).is_some())
                .count()
        })
        .collect();

    let mut remaining: Vec<usize> = (0..compiled.len()).collect();
    let mut bound = vec![false; var_names.len()];
    let mut steps = 0usize;
    let mut partial: Vec<Vec<u32>> = vec![empty.clone()];
    while !remaining.is_empty() {
        let pick = (0..remaining.len())
            .min_by_key(|&i| {
                let p = &compiled[remaining[i]];
                let joined = p.iter().any(|s| matches!(s, Slot::Var(v) if bound[*v]));
                (!joined, counts[remaining[i]], i)
            })
            .unwrap_or(0);
        let p = compiled[remaining.remove(pick)];
        for s in p {
            if let Slot::Var(v) = s {
                bound[v] = true;
            }
        }
        let last = remaining.is_empty();
        let mut next = Vec::new();
        'extend: for b in &partial {
            for t in &triples {
                steps += 1;
                if steps > MAX_MATCH_STEPS {
                    return Err(too_broad());
                }
                if let Some(nb) = extend(&p, t, b) {
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
    Ok(partial
        .into_iter()
        .map(|b| {
            b.into_iter()
                .enumerate()
                .filter(|(_, id)| *id != UNBOUND)
                .map(|(v, id)| (var_names[v], terms[id as usize]))
                .collect()
        })
        .collect())
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
