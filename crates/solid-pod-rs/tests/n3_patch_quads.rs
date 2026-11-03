//! N3 Patch applied as quads, ported from JSS PR #633 (`src/patch/quads.js`,
//! `test/patch.test.js`, JSS `0.0.224`), plus the round-trip regressions for
//! non-ASCII literals. Parity checklist rows 269-272 and the §27 defects.

use solid_pod_rs::error::PodError;
use solid_pod_rs::ldp::{apply_n3_patch, Graph, N3Patch, Term, Triple};

const BASE: &str = "https://pod.example/patchtest/public/chat.ttl";
const SIOC_CONTENT: &str = "http://rdfs.org/sioc/ns#content";
const PREFIXES: &str = "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n\
                        @prefix sioc: <http://rdfs.org/sioc/ns#>.\n";

fn iri(s: &str) -> Term {
    Term::iri(s)
}

fn lit(s: &str) -> Term {
    Term::literal(s)
}

fn doc(id: &str) -> String {
    format!("{BASE}#{id}")
}

fn patch(body: &str) -> N3Patch {
    N3Patch::parse(&format!("{PREFIXES}{body}"), Some(BASE)).expect("patch parses")
}

fn content_of(g: &Graph, id: &str) -> Vec<Term> {
    g.triples()
        .filter(|t| t.subject == iri(&doc(id)) && t.predicate == iri(SIOC_CONTENT))
        .map(|t| t.object.clone())
        .collect()
}

#[test]
fn prefixed_names_typed_literals_multiline_strings_and_relative_iris_survive() {
    let p = N3Patch::parse(
        r#"
        @prefix solid: <http://www.w3.org/ns/solid/terms#>.
        @prefix dct: <http://purl.org/dc/terms/>.
        @prefix sioc: <http://rdfs.org/sioc/ns#>.
        @prefix wf: <http://www.w3.org/2005/01/wf/flow#>.
        @prefix xsd: <http://www.w3.org/2001/XMLSchema#>.
        _:p a solid:InsertDeletePatch; solid:inserts {
          <index.ttl#this> wf:message <#m1>.
          <#m1> dct:created "2026-10-22T10:00:00Z"^^xsd:dateTime;
            sioc:content """two lines; with a dot.
and a "quote" end""".
        }."#,
        Some(BASE),
    )
    .unwrap();
    assert!(p.is_insert_only());
    let out = p.apply(Graph::new()).unwrap();
    assert_eq!(out.inserted, 3);
    let g = out.graph;
    assert!(g.contains(&Triple::new(
        iri("https://pod.example/patchtest/public/index.ttl#this"),
        iri("http://www.w3.org/2005/01/wf/flow#message"),
        iri(&doc("m1")),
    )));
    assert!(g.contains(&Triple::new(
        iri(&doc("m1")),
        iri("http://purl.org/dc/terms/created"),
        Term::typed_literal(
            "2026-10-22T10:00:00Z",
            "http://www.w3.org/2001/XMLSchema#dateTime"
        ),
    )));
    assert_eq!(
        content_of(&g, "m1"),
        vec![lit("two lines; with a dot.\nand a \"quote\" end")]
    );
}

#[test]
fn insert_keeps_existing_triples() {
    let first =
        patch(r#"_:p a solid:InsertDeletePatch; solid:inserts { <#m1> sioc:content "first" }."#)
            .apply(Graph::new())
            .unwrap()
            .graph;
    let g =
        patch(r#"_:p a solid:InsertDeletePatch; solid:inserts { <#m2> sioc:content "second" }."#)
            .apply(first)
            .unwrap()
            .graph;
    assert_eq!(content_of(&g, "m1"), vec![lit("first")]);
    assert_eq!(content_of(&g, "m2"), vec![lit("second")]);
}

#[test]
fn where_clause_binds_variables_once() {
    let seed =
        patch(r#"_:p a solid:InsertDeletePatch; solid:inserts { <#m2> sioc:content "second" }."#)
            .apply(Graph::new())
            .unwrap()
            .graph;
    let edit = patch(
        r#"_:p a solid:InsertDeletePatch;
             solid:where { <#m2> sioc:content ?old };
             solid:deletes { <#m2> sioc:content ?old };
             solid:inserts { <#m2> sioc:content "second, edited" }."#,
    );
    assert!(!edit.is_insert_only());
    let out = edit.apply(seed).unwrap();
    assert_eq!(out.deleted, 1);
    assert_eq!(content_of(&out.graph, "m2"), vec![lit("second, edited")]);
}

#[test]
fn where_clause_that_does_not_match_is_a_conflict() {
    let miss = patch(
        r#"_:p a solid:InsertDeletePatch;
             solid:where { <#nope> sioc:content ?old };
             solid:deletes { <#nope> sioc:content ?old }."#,
    );
    assert!(matches!(
        miss.apply(Graph::new()),
        Err(PodError::Conflict(_))
    ));
}

#[test]
fn where_clause_that_matches_more_than_once_is_a_conflict() {
    let seed = patch(
        r#"_:p a solid:InsertDeletePatch; solid:inserts { <#a> sioc:content "1". <#b> sioc:content "2" }."#,
    )
    .apply(Graph::new())
    .unwrap()
    .graph;
    let ambiguous = patch(
        r#"_:p a solid:InsertDeletePatch;
             solid:where { ?m sioc:content ?c };
             solid:deletes { ?m sioc:content ?c }."#,
    );
    assert!(matches!(ambiguous.apply(seed), Err(PodError::Conflict(_))));
}

#[test]
fn deleting_an_absent_triple_is_a_conflict() {
    let seed =
        patch(r#"_:p a solid:InsertDeletePatch; solid:inserts { <#m2> sioc:content "second" }."#)
            .apply(Graph::new())
            .unwrap()
            .graph;
    let p =
        patch(r#"_:p a solid:InsertDeletePatch; solid:deletes { <#m2> sioc:content "never" }."#);
    assert!(matches!(p.apply(seed), Err(PodError::Conflict(_))));
}

#[test]
fn an_unbound_variable_is_a_conflict() {
    let p =
        patch(r#"_:p a solid:InsertDeletePatch; solid:inserts { <#m> sioc:content ?nowhere }."#);
    assert!(matches!(p.apply(Graph::new()), Err(PodError::Conflict(_))));
}

#[test]
fn patch_blank_nodes_never_merge_with_the_documents_own() {
    let mut seed = Graph::new();
    seed.insert(Triple::new(
        Term::blank("b"),
        iri(SIOC_CONTENT),
        lit("document's own"),
    ));
    let g = patch(
        r#"_:p a solid:InsertDeletePatch; solid:inserts { _:b sioc:content "from the patch" }."#,
    )
    .apply(seed)
    .unwrap()
    .graph;
    let subjects: Vec<&Term> = g.triples().map(|t| &t.subject).collect();
    assert_eq!(subjects.len(), 2);
    assert_ne!(subjects[0], subjects[1], "the patch's _:b was not renamed");
}

#[test]
fn empty_formulas_are_no_ops() {
    let p = patch(
        r#"_:p a solid:InsertDeletePatch; solid:deletes { } ; solid:inserts { <#e1> <http://example.org/p> "x" }."#,
    );
    assert!(p.is_insert_only());
    let g = p.apply(Graph::new()).unwrap().graph;
    assert_eq!(g.len(), 1);
    let none = patch("_:p a solid:InsertDeletePatch; solid:deletes {\n}.");
    assert_eq!(none.apply(g.clone()).unwrap().graph, g);
}

#[test]
fn a_document_without_a_patch_resource_is_rejected() {
    let err = N3Patch::parse("<#a> <#b> <#c> .", Some(BASE)).unwrap_err();
    assert!(matches!(err, PodError::BadRequest(_)), "{err:?}");
    let err = N3Patch::parse("this is not n3 {", Some(BASE)).unwrap_err();
    assert!(matches!(err, PodError::BadRequest(_)), "{err:?}");
}

#[test]
fn non_ascii_literals_round_trip_through_patch_and_storage() {
    let p = patch(
        "_:p a solid:InsertDeletePatch; solid:inserts { <#u> sioc:content \"café é 😀\", \"\\u00e9\\U0001F600\" }.",
    );
    let g = p.apply(Graph::new()).unwrap().graph;
    let mut got = content_of(&g, "u");
    got.sort_by_key(|t| format!("{t:?}"));
    assert_eq!(got, vec![lit("café é 😀"), lit("é😀")]);

    // Stored as N-Triples and read back unchanged, as many times as it is patched.
    let mut stored = g.to_ntriples();
    for i in 0..3 {
        let reread = Graph::parse_ntriples(&stored).unwrap();
        assert_eq!(reread, g, "round {i}: {stored}");
        stored = reread.to_ntriples();
    }
}

#[test]
fn ntriples_reader_decodes_utf8_and_unicode_escapes() {
    let g = Graph::parse_ntriples(
        "<http://e/s> <http://e/p> \"é\\u00e9\\U0001F600\\\"\" .\n<http://e/s> <http://e/q> \"x\"@fr .\n",
    )
    .unwrap();
    let objects: Vec<Term> = g.triples().map(|t| t.object.clone()).collect();
    assert!(objects.contains(&lit("éé😀\"")));
    assert!(objects.contains(&Term::lang_literal("x", "fr")));
}

#[test]
fn legacy_wrapper_still_applies_ground_patches() {
    let out = apply_n3_patch(
        Graph::new(),
        "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n\
         _:p a solid:InsertDeletePatch; solid:inserts { <http://e/s> <http://e/p> \"ü\" }.",
    )
    .unwrap();
    assert_eq!(out.inserted, 1);
}

#[test]
fn ntriples_reader_refuses_turtle_lists_instead_of_dropping_triples() {
    for body in [
        "<http://e/a> <http://e/p> \"one\" ; <http://e/q> \"two\" .\n",
        "<http://e/a> <http://e/p> \"one\" . <http://e/b> <http://e/p> \"two\" .\n",
    ] {
        assert!(Graph::parse_ntriples(body).is_err(), "accepted {body:?}");
    }
}

/// `where` evaluation is bounded: an all-variable clause over a large
/// document is refused as too broad instead of enumerating n^k bindings,
/// and a clause with too many patterns is refused at parse time.
#[test]
fn where_evaluation_is_bounded() {
    use solid_pod_rs::ldp::{Graph, N3Patch, Term, Triple};
    use solid_pod_rs::PodError;

    let mut g = Graph::new();
    for i in 0..1000 {
        g.insert(Triple::new(
            Term::iri(format!("http://e/s{i}")),
            Term::iri("http://e/p"),
            Term::literal(i.to_string()),
        ));
    }
    let patch = N3Patch::parse(
        "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n\
         _:p a solid:InsertDeletePatch; solid:where { ?a ?b ?c . ?d ?e ?f . ?g ?h ?i }.",
        None,
    )
    .unwrap();
    let started = std::time::Instant::now();
    assert!(matches!(patch.apply(g), Err(PodError::Conflict(_))));
    assert!(started.elapsed() < std::time::Duration::from_secs(2));

    let many: String = (0..33)
        .map(|i| format!("?s <http://e/p{i}> ?o{i} . "))
        .collect();
    let body = format!(
        "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n\
         _:p a solid:InsertDeletePatch; solid:where {{ {many} }}."
    );
    assert!(matches!(
        N3Patch::parse(&body, None),
        Err(PodError::BadRequest(_))
    ));
}

fn person_graph(n: usize) -> solid_pod_rs::ldp::Graph {
    use solid_pod_rs::ldp::{Graph, Term, Triple};
    let mut g = Graph::new();
    for i in 0..n {
        let s = Term::iri(format!("http://e/p{i}"));
        g.insert(Triple::new(
            s.clone(),
            Term::iri("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"),
            Term::iri("http://e/Person"),
        ));
        g.insert(Triple::new(
            s,
            Term::iri("http://e/id"),
            Term::literal(i.to_string()),
        ));
    }
    g
}

/// A selective `where` succeeds over a large document whichever order the
/// client writes its patterns in: patterns are joined most-bound-first.
#[test]
fn a_selective_where_succeeds_in_either_pattern_order() {
    use solid_pod_rs::ldp::N3Patch;
    for clause in [
        "?s a <http://e/Person> . ?s <http://e/id> \"4242\"",
        "?s <http://e/id> \"4242\" . ?s a <http://e/Person>",
    ] {
        let patch = N3Patch::parse(
            &format!(
                "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n\
                 _:p a solid:InsertDeletePatch; solid:where {{ {clause} }};\n\
                 solid:inserts {{ ?s <http://e/found> true }}."
            ),
            None,
        )
        .unwrap();
        let out = patch.apply(person_graph(20_000)).expect(clause);
        assert_eq!(out.inserted, 1, "{clause}");
    }
}

/// The step budget bounds a clause whose partial bindings stay under the
/// cap but whose join scans the document once per binding.
#[test]
fn the_match_step_budget_is_enforced() {
    use solid_pod_rs::ldp::N3Patch;
    use solid_pod_rs::PodError;
    // 5,000 Person bindings (under the partial cap), then a pattern sharing
    // no variable and matching nothing: 5,000 x 10,000 comparisons.
    let patch = N3Patch::parse(
        "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n\
         _:p a solid:InsertDeletePatch; solid:where { ?s a <http://e/Person> . ?x <http://e/none> ?y }.",
        None,
    )
    .unwrap();
    let started = std::time::Instant::now();
    assert!(matches!(
        patch.apply(person_graph(5_000)),
        Err(PodError::Conflict(_))
    ));
    assert!(started.elapsed() < std::time::Duration::from_secs(20));
}

/// Bindings borrow from the document: a `where` binding a multi-megabyte
/// literal across many patterns never copies it per comparison.
#[test]
fn a_large_bound_literal_is_not_copied_per_step() {
    use solid_pod_rs::ldp::{Graph, N3Patch, Term, Triple};
    let mut g = person_graph(2_000);
    let big = "x".repeat(4 * 1024 * 1024);
    g.insert(Triple::new(
        Term::iri("http://e/s0"),
        Term::iri("http://e/big"),
        Term::literal(big),
    ));
    let mut clause = String::from("<http://e/s0> <http://e/big> ?big . ");
    for i in 0..30 {
        clause.push_str(&format!("<http://e/p{i}> <http://e/id> ?v{i} . "));
    }
    let patch = N3Patch::parse(
        &format!(
            "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n\
             _:p a solid:InsertDeletePatch; solid:where {{ {clause} }}."
        ),
        None,
    )
    .unwrap();
    let started = std::time::Instant::now();
    patch.apply(g).unwrap();
    let _ = Graph::new();
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "took {:?}",
        started.elapsed()
    );
}
