//! Differential test: Turtle / N3 request bodies parse to the same triple set
//! as the JSS parser.
//!
//! Oracle: JSS 0.0.221 `src/rdf/turtle.js` `turtleToJsonLd()` which builds
//! `new Parser({ baseIRI })` from n3.js 1.26 (reached for both `text/turtle`
//! and `text/n3` via `src/rdf/conneg.js` `toJsonLd`). The expected triple
//! sets in `tests/fixtures/rdf_input/expected.json` were produced by running
//! that parser over `corpus.json` with `gen.mjs`; nothing here is derived by
//! hand. Blank-node labels are not stable across parsers, so graphs are
//! compared up to blank-node renaming.

use std::collections::BTreeSet;

use serde_json::Value;
use solid_pod_rs::error::PodError;
use solid_pod_rs::ldp::{Graph, Term, Triple};
use solid_pod_rs::rdf_input::{parse_rdf_body, RdfInputSyntax};

const CORPUS: &str = include_str!("fixtures/rdf_input/corpus.json");
const EXPECTED: &str = include_str!("fixtures/rdf_input/expected.json");

fn json_term(v: &Value) -> Term {
    let val = v["v"].as_str().unwrap().to_string();
    match v["t"].as_str().unwrap() {
        "iri" => Term::Iri(val),
        "bnode" => Term::BlankNode(val),
        "lit" => Term::Literal {
            value: val,
            datatype: v.get("dt").and_then(|d| d.as_str()).map(String::from),
            language: v.get("lang").and_then(|d| d.as_str()).map(String::from),
        },
        other => panic!("unexpected term kind {other}"),
    }
}

fn expected_triples(entry: &Value) -> Vec<Triple> {
    entry["triples"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| Triple::new(json_term(&t[0]), json_term(&t[1]), json_term(&t[2])))
        .collect()
}

/// Backtracking blank-node isomorphism over small graphs.
fn isomorphic(a: &BTreeSet<Triple>, b: &BTreeSet<Triple>) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let ground = |t: &Triple| {
        ![&t.subject, &t.predicate, &t.object]
            .iter()
            .any(|x| matches!(x, Term::BlankNode(_)))
    };
    let (ag, ab): (Vec<_>, Vec<_>) = a.iter().partition(|t| ground(t));
    let (bg, bb): (Vec<_>, Vec<_>) = b.iter().partition(|t| ground(t));
    if ag != bg || ab.len() != bb.len() {
        return false;
    }
    fn go(
        i: usize,
        ab: &[&Triple],
        bb: &[&Triple],
        used: &mut Vec<bool>,
        map: &mut Vec<(String, String)>,
    ) -> bool {
        if i == ab.len() {
            return true;
        }
        for (j, cand) in bb.iter().enumerate() {
            if used[j] {
                continue;
            }
            let mark = map.len();
            let mut ok = true;
            for (x, y) in [
                (&ab[i].subject, &cand.subject),
                (&ab[i].predicate, &cand.predicate),
                (&ab[i].object, &cand.object),
            ] {
                match (x, y) {
                    (Term::BlankNode(p), Term::BlankNode(q)) => {
                        let fwd = map.iter().find(|(l, _)| l == p).map(|(_, r)| r.clone());
                        let rev = map.iter().find(|(_, r)| r == q).map(|(l, _)| l.clone());
                        match (fwd, rev) {
                            (Some(r), _) if &r != q => ok = false,
                            (None, Some(_)) => ok = false,
                            (None, None) => map.push((p.clone(), q.clone())),
                            _ => {}
                        }
                    }
                    (p, q) if p == q => {}
                    _ => ok = false,
                }
                if !ok {
                    break;
                }
            }
            if ok {
                used[j] = true;
                if go(i + 1, ab, bb, used, map) {
                    return true;
                }
                used[j] = false;
            }
            map.truncate(mark);
        }
        false
    }
    let mut used = vec![false; bb.len()];
    go(0, &ab, &bb, &mut used, &mut Vec::new())
}

#[test]
fn corpus_matches_jss_parser() {
    let corpus: Vec<Value> = serde_json::from_str(CORPUS).unwrap();
    let expected: Value = serde_json::from_str(EXPECTED).unwrap();
    assert!(corpus.len() >= 20, "corpus unexpectedly small");
    for doc in &corpus {
        let name = doc["name"].as_str().unwrap();
        let syntax = match doc["syntax"].as_str().unwrap() {
            "turtle" => RdfInputSyntax::Turtle,
            "n3" => RdfInputSyntax::N3,
            s => panic!("{name}: syntax {s}"),
        };
        let base = doc["base"].as_str().unwrap();
        let text = doc["text"].as_str().unwrap();
        let want = &expected[name];
        let got = parse_rdf_body(syntax, text.as_bytes(), base);
        if want.get("error").is_some() {
            assert!(
                matches!(
                    got,
                    Err(PodError::BadRequest(_)) | Err(PodError::Unsupported(_))
                ),
                "{name}: JSS rejects ({}) but Rust returned {got:?}",
                want["error"]
            );
            continue;
        }
        let got: Graph = got.unwrap_or_else(|e| panic!("{name}: JSS parses, Rust failed: {e}"));
        let want_set: BTreeSet<Triple> = expected_triples(want).into_iter().collect();
        let got_set: BTreeSet<Triple> = got.triples().cloned().collect();
        assert!(
            isomorphic(&got_set, &want_set),
            "{name}: triple sets differ\n rust: {got_set:#?}\n jss : {want_set:#?}"
        );
    }
}

#[test]
fn comparator_distinguishes_graphs() {
    let t = |s: &str, o: &str| Triple::new(Term::blank(s), Term::iri("http://e/p"), Term::literal(o));
    let a: BTreeSet<Triple> = [t("x", "1"), t("y", "2")].into_iter().collect();
    let renamed: BTreeSet<Triple> = [t("m", "1"), t("n", "2")].into_iter().collect();
    let merged: BTreeSet<Triple> = [t("m", "1"), t("m", "2")].into_iter().collect();
    let other: BTreeSet<Triple> = [t("m", "1"), t("n", "3")].into_iter().collect();
    assert!(isomorphic(&a, &renamed));
    assert!(!isomorphic(&a, &merged));
    assert!(!isomorphic(&a, &other));
}

#[test]
fn n3_restricted_constructs_are_never_stored() {
    // Constructs outside the RDF-compatible subset are refused with 400/415
    // regardless of what a particular JSS parser mode would do with them.
    for src in [
        "@prefix : <http://e/> . { :a :b :c } :says :x .",
        "@prefix : <http://e/> . ?x :b :c .",
        "@prefix : <http://e/> . { ?x :a :b } => { ?x :c :d } .",
        "@prefix : <http://e/> . {} => {} .",
    ] {
        let r = parse_rdf_body(RdfInputSyntax::N3, src.as_bytes(), "https://p.example/x");
        assert!(
            matches!(r, Err(PodError::Unsupported(_)) | Err(PodError::BadRequest(_))),
            "{src}: {r:?}"
        );
    }
}
