//! A SPARQL delete that removes fewer triples than it names is a 409 and
//! writes nothing, as an N3 Patch does and as the reference server does for
//! both dialects. The hazard it removes: a revocation (`DELETE DATA` of an
//! `acl:agent`) that matches nothing answering success while the grant stays.

use solid_pod_rs::ldp::{
    apply_patch_to_absent, apply_sparql_patch, sparql_update_inspects,
    sparql_update_is_insert_only, Graph, PatchDialect,
};
use solid_pod_rs::PodError;

const DOC: &str = "<http://e/a> <http://e/name> \"old\" .\n<http://e/a> <http://e/age> \"3\" .\n";

fn graph() -> Graph {
    Graph::parse_ntriples(DOC).unwrap()
}

fn conflict(update: &str) {
    let err = apply_sparql_patch(graph(), update).unwrap_err();
    assert!(matches!(err, PodError::Conflict(_)), "{update}: {err:?}");
}

#[test]
fn delete_data_of_an_absent_triple_is_a_conflict() {
    conflict("DELETE DATA { <http://e/a> <http://e/name> \"other\" }");
}

#[test]
fn delete_data_naming_one_present_and_one_absent_triple_is_a_conflict() {
    conflict("DELETE DATA { <http://e/a> <http://e/name> \"old\" . <http://e/a> <http://e/nope> \"x\" }");
}

#[test]
fn a_delete_template_instance_that_is_absent_is_a_conflict() {
    // The WHERE binds ?o, the template names a triple the document lacks.
    conflict(
        "DELETE { <http://e/a> <http://e/missing> ?o } WHERE { <http://e/a> <http://e/name> ?o }",
    );
}

#[test]
fn a_second_operation_is_judged_against_the_graph_the_first_left() {
    conflict(
        "DELETE DATA { <http://e/a> <http://e/name> \"old\" } ; \
         DELETE DATA { <http://e/a> <http://e/name> \"old\" }",
    );
}

#[test]
fn present_deletes_still_apply_and_a_repeated_name_counts_once() {
    let out = apply_sparql_patch(
        graph(),
        "DELETE DATA { <http://e/a> <http://e/name> \"old\" . <http://e/a> <http://e/name> \"old\" }",
    )
    .unwrap();
    assert_eq!((out.inserted, out.deleted), (0, 1));
    // Two solutions producing the same template instance are one deletion.
    let out = apply_sparql_patch(
        graph(),
        "DELETE { <http://e/a> <http://e/name> ?o } WHERE { <http://e/a> ?p ?o }",
    );
    // ?o is "old" or "3": only "old" is present, so the "3" instance is absent.
    assert!(matches!(out, Err(PodError::Conflict(_))));
    let out = apply_sparql_patch(
        graph(),
        "DELETE { <http://e/a> <http://e/name> \"old\" } WHERE { <http://e/a> ?p ?o }",
    )
    .unwrap();
    assert_eq!(out.deleted, 1);
}

#[test]
fn an_empty_delete_data_is_still_insert_only_and_still_applies() {
    assert!(sparql_update_is_insert_only("DELETE DATA { }"));
    assert!(!sparql_update_inspects("DELETE DATA { }"));
    let out = apply_sparql_patch(graph(), "DELETE DATA { }").unwrap();
    assert_eq!((out.inserted, out.deleted), (0, 0));
}

#[test]
fn a_delete_data_with_triples_inspects_the_resource() {
    // Its 409-or-204 answer reveals whether a triple exists, so it needs
    // Read as well as Write, like an N3 delete.
    assert!(sparql_update_inspects(
        "DELETE DATA { <http://e/a> <http://e/name> \"old\" }"
    ));
    assert!(!sparql_update_is_insert_only(
        "DELETE DATA { <http://e/a> <http://e/name> \"old\" }"
    ));
    assert!(!sparql_update_inspects(
        "INSERT DATA { <http://e/a> <http://e/b> \"c\" }"
    ));
}

#[test]
fn creating_by_patch_with_a_delete_is_a_conflict() {
    let err = apply_patch_to_absent(
        PatchDialect::SparqlUpdate,
        "DELETE DATA { <http://e/a> <http://e/name> \"old\" }",
    );
    assert!(matches!(err, Err(PodError::Conflict(_))));
}
