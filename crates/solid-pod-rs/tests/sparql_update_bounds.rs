//! Bounds on a SPARQL Update (row 41 follow-up): the WHERE pattern cap, the
//! operation cap and one step budget per request apply on the SPARQL path as
//! they do on the N3 path. Each refusal comes before any evaluation, so the
//! caller writes nothing.

use solid_pod_rs::ldp::{apply_sparql_patch, Graph, Term, Triple};
use solid_pod_rs::PodError;

fn doc() -> Graph {
    Graph::parse_ntriples("<http://e/a> <http://e/name> \"x\" .\n").unwrap()
}

/// `n` patterns that match nothing, so an evaluator that ran them would
/// answer quickly with a no-op; only the cap refuses them.
fn patterns(n: usize) -> String {
    (0..n)
        .map(|i| format!("?s{i} <http://e/none> ?o{i} ."))
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn thousands_of_where_patterns_are_refused_with_400() {
    let update = format!(
        "DELETE {{ ?s0 <http://e/none> ?o0 }} WHERE {{ {} }}",
        patterns(5000)
    );
    let err = apply_sparql_patch(doc(), &update).unwrap_err();
    assert!(matches!(err, PodError::BadRequest(_)), "{err:?}");
}

#[test]
fn the_pattern_cap_is_the_n3_cap() {
    let ok = format!("DELETE WHERE {{ {} }}", patterns(32));
    assert!(apply_sparql_patch(doc(), &ok).is_ok());
    let over = format!("DELETE WHERE {{ {} }}", patterns(33));
    assert!(matches!(
        apply_sparql_patch(doc(), &over),
        Err(PodError::BadRequest(_))
    ));
}

fn operations(n: usize) -> String {
    (0..n)
        .map(|i| format!("INSERT DATA {{ <http://e/s{i}> <http://e/p> \"v\" }}"))
        .collect::<Vec<_>>()
        .join(" ;\n")
}

#[test]
fn many_operations_in_one_update_are_refused_with_400() {
    let ok = apply_sparql_patch(doc(), &operations(16)).unwrap();
    assert_eq!(ok.inserted, 16);
    let err = apply_sparql_patch(doc(), &operations(17)).unwrap_err();
    assert!(matches!(err, PodError::BadRequest(_)), "{err:?}");
}

/// A big document makes each operation cost more than the budget divided by
/// the operation cap, so only a budget shared by the whole request refuses.
fn big_document(n: usize) -> Graph {
    let mut g = Graph::new();
    for i in 0..n {
        g.insert(Triple::new(
            Term::iri(format!("http://e/s{i}")),
            Term::iri("http://e/q"),
            Term::iri(format!("http://e/o{i}")),
        ));
    }
    g
}

fn rewrite() -> &'static str {
    "DELETE { ?s <http://e/none> ?o } WHERE { ?s <http://e/none> ?o . ?s <http://e/q> ?o2 . ?s <http://e/q> ?o3 }"
}

#[test]
fn the_step_budget_is_shared_across_operations_and_counts_scans() {
    let n = 150_000;
    // One operation fits.
    assert!(apply_sparql_patch(big_document(n), rewrite()).is_ok());
    // Sixteen of them together do not: each re-indexes and scans the graph.
    let many = vec![rewrite(); 16].join(" ;\n");
    let err = apply_sparql_patch(big_document(n), &many).unwrap_err();
    assert!(matches!(err, PodError::Conflict(_)), "{err:?}");
}
