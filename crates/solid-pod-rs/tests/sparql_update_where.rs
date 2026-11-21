//! SPARQL Update with a `WHERE` clause (checklist row 41): the forms JSS
//! lists (`DELETE/INSERT ... WHERE`, `DELETE WHERE`, standalone `INSERT ...
//! WHERE`) are evaluated, not silently ignored, and anything this evaluator
//! cannot honour is refused with an error rather than answered as a no-op.

use solid_pod_rs::ldp::{apply_sparql_patch, Graph};
use solid_pod_rs::PodError;

fn graph(nt: &str) -> Graph {
    Graph::parse_ntriples(nt).unwrap()
}

const DOC: &str = "<http://e/a> <http://e/name> \"old\" .\n\
                   <http://e/a> <http://e/age> \"3\" .\n\
                   <http://e/b> <http://e/name> \"bee\" .\n";

fn has(g: &Graph, nt: &str) -> bool {
    let want = Graph::parse_ntriples(nt).unwrap();
    let all = want.triples().all(|t| g.contains(t));
    all
}

#[test]
fn delete_insert_where_rewrites_the_bound_triple() {
    let out = apply_sparql_patch(
        graph(DOC),
        "DELETE { <http://e/a> <http://e/name> ?o } \
         INSERT { <http://e/a> <http://e/name> \"new\" } \
         WHERE  { <http://e/a> <http://e/name> ?o }",
    )
    .unwrap();
    assert!(has(&out.graph, "<http://e/a> <http://e/name> \"new\" ."));
    assert!(!has(&out.graph, "<http://e/a> <http://e/name> \"old\" ."));
    assert!(has(&out.graph, "<http://e/b> <http://e/name> \"bee\" ."));
    assert_eq!((out.inserted, out.deleted), (1, 1));
}

#[test]
fn delete_where_with_variables_deletes_every_match() {
    let out = apply_sparql_patch(graph(DOC), "DELETE WHERE { ?s <http://e/name> ?o }").unwrap();
    assert_eq!(out.deleted, 2);
    assert!(!has(&out.graph, "<http://e/b> <http://e/name> \"bee\" ."));
    assert!(has(&out.graph, "<http://e/a> <http://e/age> \"3\" ."));
}

#[test]
fn insert_where_copies_a_bound_value() {
    let out = apply_sparql_patch(
        graph(DOC),
        "INSERT { ?s <http://e/label> ?o } WHERE { ?s <http://e/name> ?o }",
    )
    .unwrap();
    assert_eq!(out.inserted, 2);
    assert!(has(&out.graph, "<http://e/b> <http://e/label> \"bee\" ."));
}

#[test]
fn a_join_binds_across_patterns() {
    let out = apply_sparql_patch(
        graph(DOC),
        "DELETE { ?s <http://e/age> ?a } INSERT { ?s <http://e/seen> ?a } \
         WHERE { ?s <http://e/name> \"old\" . ?s <http://e/age> ?a }",
    )
    .unwrap();
    assert!(has(&out.graph, "<http://e/a> <http://e/seen> \"3\" ."));
    assert!(!has(&out.graph, "<http://e/a> <http://e/age> \"3\" ."));
}

#[test]
fn a_where_that_matches_nothing_changes_nothing() {
    let out = apply_sparql_patch(
        graph(DOC),
        "DELETE { ?s <http://e/name> ?o } WHERE { ?s <http://e/nothing> ?o }",
    )
    .unwrap();
    assert_eq!((out.inserted, out.deleted), (0, 0));
    assert_eq!(out.graph.len(), 3);
}

#[test]
fn an_empty_where_applies_a_ground_template_once() {
    let out = apply_sparql_patch(
        graph(DOC),
        "INSERT { <http://e/c> <http://e/p> \"x\" } WHERE { }",
    )
    .unwrap();
    assert_eq!(out.inserted, 1);
}

#[test]
fn a_template_variable_the_where_does_not_bind_adds_nothing() {
    let out = apply_sparql_patch(
        graph(DOC),
        "INSERT { ?s <http://e/p> ?unbound } WHERE { ?s <http://e/age> ?a }",
    )
    .unwrap();
    assert_eq!(out.inserted, 0);
}

#[test]
fn blank_nodes_in_an_insert_template_are_fresh_per_solution() {
    let out = apply_sparql_patch(
        graph(DOC),
        "INSERT { ?s <http://e/note> _:n . _:n <http://e/about> ?o } \
         WHERE { ?s <http://e/name> ?o }",
    )
    .unwrap();
    assert_eq!(out.inserted, 4);
    let nodes: std::collections::HashSet<String> = out
        .graph
        .triples()
        .filter(|t| format!("{:?}", t.predicate).contains("note"))
        .map(|t| format!("{:?}", t.object))
        .collect();
    assert_eq!(nodes.len(), 2, "one fresh blank node per solution");
}

#[test]
fn constructs_the_evaluator_cannot_honour_are_refused_not_ignored() {
    for update in [
        "DELETE { ?s <http://e/p> ?o } WHERE { ?s <http://e/p> ?o FILTER(?o = \"x\") }",
        "INSERT { ?s <http://e/p> \"1\" } WHERE { OPTIONAL { ?s <http://e/q> ?o } }",
        "INSERT { ?s <http://e/p> \"1\" } WHERE { { ?s <http://e/a> ?x } UNION { ?s <http://e/b> ?x } }",
        "INSERT { ?s <http://e/p> \"1\" } WHERE { GRAPH <http://g> { ?s <http://e/a> ?x } }",
        "INSERT DATA { GRAPH <http://g> { <http://e/s> <http://e/p> \"1\" } }",
        "DELETE DATA { GRAPH <http://g> { <http://e/s> <http://e/p> \"1\" } }",
        "WITH <http://g> DELETE { ?s <http://e/p> ?o } WHERE { ?s <http://e/p> ?o }",
        "INSERT { ?s <http://e/p> \"1\" } USING <http://g> WHERE { ?s <http://e/a> ?x }",
        "INSERT { ?s <http://e/p> ?o } WHERE { ?s ?p ?o BIND(1 AS ?z) }",
    ] {
        let r = apply_sparql_patch(graph(DOC), update);
        assert!(
            matches!(r, Err(PodError::Unsupported(_)) | Err(PodError::BadRequest(_))),
            "{update}: {r:?}"
        );
    }
}

#[test]
fn an_all_variable_where_over_a_large_document_is_bounded() {
    let mut nt = String::new();
    for i in 0..400 {
        nt.push_str(&format!("<http://e/s{i}> <http://e/p> \"{i}\" .\n"));
    }
    // Three independent all-variable patterns: 400^3 solutions.
    let r = apply_sparql_patch(
        graph(&nt),
        "INSERT { ?a <http://e/q> ?z } WHERE { ?a ?b ?c . ?d ?e ?f . ?g ?h ?z }",
    );
    assert!(r.is_err(), "an unbounded join must be refused");
}

#[test]
fn the_insert_only_classifier_and_the_inspects_classifier_agree() {
    use solid_pod_rs::ldp::{sparql_update_inspects, sparql_update_is_insert_only};
    let insert = "INSERT DATA { <http://e/s> <http://e/p> \"1\" }";
    assert!(sparql_update_is_insert_only(insert));
    assert!(!sparql_update_inspects(insert));
    let delete_data = "DELETE DATA { <http://e/s> <http://e/p> \"1\" }";
    // A DELETE DATA that names triples answers 409 when one is absent, so it
    // reads the resource (it pinned `false` while an absent delete was a 204).
    assert!(sparql_update_inspects(delete_data));
    assert!(!sparql_update_is_insert_only(delete_data));
    for u in [
        "DELETE WHERE { ?s ?p ?o }",
        "INSERT { ?s <http://e/p> ?o } WHERE { ?s <http://e/q> ?o }",
        "DELETE { <http://e/s> <http://e/p> ?o } WHERE { <http://e/s> <http://e/p> ?o }",
    ] {
        assert!(sparql_update_inspects(u), "{u}");
        assert!(!sparql_update_is_insert_only(u), "{u}");
    }
}
