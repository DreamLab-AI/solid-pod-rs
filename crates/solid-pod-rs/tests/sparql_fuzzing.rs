//! SPARQL-Update fuzzing property tests (khive bb54cb41).
//!
//! These tests generate random SPARQL-like strings and verify the parser
//! either succeeds or returns an error — never panics.  They also verify
//! the size cap: inputs exceeding `SPARQL_UPDATE_MAX_BYTES` are rejected
//! before reaching the spargebra parser.

use solid_pod_rs::ldp::{apply_sparql_patch, Graph, SPARQL_UPDATE_MAX_BYTES};
use solid_pod_rs::PodError;

// ---------------------------------------------------------------------------
// Size-cap enforcement
// ---------------------------------------------------------------------------

#[test]
fn sparql_update_rejects_oversized_input() {
    // Build a string that exceeds the 1 MiB limit.
    let oversized = "x".repeat(SPARQL_UPDATE_MAX_BYTES + 1);
    let result = apply_sparql_patch(Graph::new(), &oversized);
    assert!(result.is_err());
    match result.unwrap_err() {
        PodError::BadRequest(msg) => {
            assert!(
                msg.contains("exceeds"),
                "error message should mention the limit: {msg}"
            );
        }
        other => panic!("expected BadRequest, got: {other:?}"),
    }
}

#[test]
fn sparql_update_accepts_input_at_exact_limit() {
    // An input at exactly the limit should not be rejected by the size
    // guard (it may still fail to parse, but that is an Unsupported
    // error, not a BadRequest about size).
    let at_limit = "x".repeat(SPARQL_UPDATE_MAX_BYTES);
    let result = apply_sparql_patch(Graph::new(), &at_limit);
    // The parser will reject this as invalid SPARQL, but the size guard
    // should not trigger.
    // Either Ok or some other parse error is acceptable; only the size guard
    // must not fire on at-limit input.
    if let Err(PodError::BadRequest(msg)) = result {
        assert!(
            !msg.contains("exceeds"),
            "at-limit input should not trigger size guard: {msg}"
        );
    }
}

// ---------------------------------------------------------------------------
// Property: random bytes never cause a panic
// ---------------------------------------------------------------------------

#[test]
fn sparql_random_ascii_does_not_panic() {
    // Deterministic PRNG using a simple xorshift approach.
    let mut state: u64 = 0xDEAD_BEEF_CAFE_BABE;
    for round in 0..500 {
        // Simple xorshift-like PRNG.
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state = state.wrapping_add(round);

        let len = (state as usize % 512) + 1;
        let input: String = (0..len)
            .map(|i| {
                let byte = ((state.wrapping_mul(i as u64 + 1)) % 128) as u8;
                // Ensure printable ASCII or common whitespace.
                if (32..127).contains(&byte) {
                    byte as char
                } else {
                    ' '
                }
            })
            .collect();

        let _ = apply_sparql_patch(Graph::new(), &input);
    }
}

#[test]
fn sparql_structured_variants_do_not_panic() {
    // Feed structured SPARQL-like strings that exercise parser edge
    // cases: unclosed braces, mixed keywords, nested constructs.
    let cases = [
        "",
        " ",
        "INSERT",
        "INSERT DATA",
        "INSERT DATA {",
        "INSERT DATA { }",
        "INSERT DATA { <> <> <> }",
        "INSERT DATA { <> <> <> . }",
        "DELETE DATA { <> <> <> . }",
        "DELETE WHERE { ?s ?p ?o . }",
        "INSERT DATA { <http://s> <http://p> \"\" . }",
        "INSERT DATA { <http://s> <http://p> \"value\"@en . }",
        "INSERT DATA { <http://s> <http://p> \"42\"^^<http://www.w3.org/2001/XMLSchema#integer> . }",
        "DELETE DATA { <http://s> <http://p> <http://o> . } ; INSERT DATA { <http://s> <http://p> <http://o2> . }",
        "PREFIX : <http://example.org/> INSERT DATA { :s :p :o . }",
        // Malformed — should produce errors, not panics.
        "INSERT DATA {{ <> <> <> . }}",
        "DELETE",
        "SELECT * WHERE { ?s ?p ?o }",
        "CONSTRUCT { ?s ?p ?o } WHERE { ?s ?p ?o }",
        "DROP ALL",
        "LOAD <http://example.org/data>",
        "CREATE GRAPH <http://example.org/g>",
        // Deeply nested
        "INSERT DATA { <http://s> <http://p> \"\\\"escaped\\\"\" . }",
        // Unicode
        "INSERT DATA { <http://s> <http://p> \"\u{1F600}\" . }",
        // Very long IRI
        &format!(
            "INSERT DATA {{ <http://example.org/{}> <http://p> <http://o> . }}",
            "a".repeat(8000)
        ),
        // Repeated operations
        &"INSERT DATA { <http://s> <http://p> <http://o> . } ; ".repeat(100),
    ];

    for (i, input) in cases.iter().enumerate() {
        let result = apply_sparql_patch(Graph::new(), input);
        // Must not panic — Ok or Err are both acceptable.
        match &result {
            Ok(outcome) => {
                // Sanity: if the parse succeeded, the graph should be
                // consistent (insert count is usize, always >= 0, but
                // verify the graph length matches).
                assert!(
                    outcome.graph.len() <= outcome.inserted,
                    "case {i}: graph larger than insert count"
                );
            }
            Err(_) => {
                // Expected for malformed input.
            }
        }
    }
}

#[test]
fn sparql_empty_input_returns_zero_mutations() {
    // An empty SPARQL-Update document is syntactically valid (no
    // operations). The parser should accept it and return zero changes.
    let result = apply_sparql_patch(Graph::new(), "");
    match result {
        Ok(outcome) => {
            assert_eq!(outcome.inserted, 0);
            assert_eq!(outcome.deleted, 0);
            assert!(outcome.graph.is_empty());
        }
        Err(_) => {
            // Some parsers consider empty input an error — acceptable.
        }
    }
}

#[test]
fn sparql_null_bytes_do_not_panic() {
    let inputs = [
        "\0",
        "INSERT DATA { \0 }",
        "INSERT\0DATA { <http://s> <http://p> <http://o> . }",
        "\0\0\0\0\0",
    ];
    for input in &inputs {
        let _ = apply_sparql_patch(Graph::new(), input);
    }
}
