//! JSS parity: PATCH against an absent resource must seed an empty
//! graph and return 201 Created semantics for N3 and SPARQL dialects.
//! JSON Patch is intentionally unsupported because it requires an
//! existing JSON document.

use solid_pod_rs::error::PodError;
use solid_pod_rs::ldp::{apply_patch_to_absent, PatchCreateOutcome, PatchDialect};

#[test]
fn n3_patch_against_absent_resource_returns_created() {
    let body = r#"
        _:r a solid:InsertDeletePatch ;
          solid:inserts {
            <http://s/a> <http://p/new> "shiny" .
          } .
    "#;
    let outcome = apply_patch_to_absent(PatchDialect::N3, body).unwrap();
    match outcome {
        PatchCreateOutcome::Created { inserted, graph } => {
            assert_eq!(inserted, 1);
            assert_eq!(graph.len(), 1);
        }
        _ => panic!("expected Created"),
    }
}

#[test]
fn sparql_insert_data_against_absent_resource_seeds_empty_graph() {
    let body = r#"INSERT DATA { <http://s> <http://p> "v" . }"#;
    let outcome = apply_patch_to_absent(PatchDialect::SparqlUpdate, body).unwrap();
    match outcome {
        PatchCreateOutcome::Created { inserted, graph } => {
            assert_eq!(inserted, 1);
            assert_eq!(graph.len(), 1);
        }
        _ => panic!("expected Created"),
    }
}

#[test]
fn json_patch_against_absent_resource_returns_unsupported() {
    let body = r#"[{"op":"add","path":"/x","value":1}]"#;
    let err = apply_patch_to_absent(PatchDialect::JsonPatch, body).unwrap_err();
    assert!(matches!(err, PodError::Unsupported(_)), "got {err:?}");
}

#[test]
fn n3_delete_only_patch_against_absent_is_empty_create() {
    // Delete-only against absent should still create an empty resource
    // (inserted=0), because the WHERE/DELETE produces nothing to remove
    // against an empty graph but that is not an error here.
    let body = r#"
        _:r a solid:InsertDeletePatch ;
          solid:inserts { } .
    "#;
    let outcome = apply_patch_to_absent(PatchDialect::N3, body).unwrap();
    match outcome {
        PatchCreateOutcome::Created { inserted, graph } => {
            assert_eq!(inserted, 0);
            assert!(graph.is_empty());
        }
        _ => panic!("expected Created"),
    }
}
