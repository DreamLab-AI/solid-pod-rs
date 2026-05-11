// crates/solid-pod-rs-didkey/tests/upstream_vectors/all_fixtures.rs
//! L1 reference-vector tests — solid-pod-rs-didkey substrate.
//!
//! Per ADR-082 D5, the DID-key crate consumes fixtures relevant to identity
//! resolution: did-doc, multibase, bip340 (Schnorr is the underlying signature
//! algo for did:nostr per ADR-074 D1).

use std::fs;
use std::path::PathBuf;

fn fixture_root() -> PathBuf {
    if let Ok(env_root) = std::env::var("VISIONCLAW_FIXTURE_ROOT") {
        return PathBuf::from(env_root);
    }
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p
}

fn try_load_fixture(name: &str) -> Option<serde_json::Value> {
    let mut path = fixture_root();
    path.push(name);
    let bytes = fs::read(&path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn assert_meta_block(fixture: &serde_json::Value, expected_spec_substring: &str) {
    let meta = fixture.get("_meta").expect("fixture must have _meta block");
    let spec = meta
        .get("spec")
        .and_then(|v| v.as_str())
        .expect("_meta.spec required");
    assert!(
        spec.contains(expected_spec_substring),
        "_meta.spec '{}' did not contain '{}'",
        spec,
        expected_spec_substring
    );
}

macro_rules! fixture_test {
    ($name:ident, $file:literal, $spec:literal, $min_vectors:expr) => {
        #[test]
        fn $name() {
            let Some(f) = try_load_fixture($file) else {
                eprintln!(
                    "fixture {} not found; skipping (run substrate-side scripts/sync-fixtures.sh first)",
                    $file
                );
                return;
            };
            assert_meta_block(&f, $spec);
            if let Some(vectors) = f["vectors"].as_array() {
                assert!(
                    vectors.len() >= $min_vectors,
                    "fixture {} must have >= {} vectors",
                    $file,
                    $min_vectors
                );
            }
        }
    };
}

fixture_test!(
    did_doc_load_and_validate,
    "did-doc-conformance.json",
    "ADR-074",
    7
);
fixture_test!(
    bip340_load_and_validate,
    "bip340-schnorr.json",
    "BIP-340",
    19
);
fixture_test!(
    multibase_load_and_validate,
    "multibase.json",
    "Multibase",
    27
);

#[test]
#[ignore = "wires into solid-pod-rs-didkey's DID Document emitter; ADR-074 D2 conformance check — Phase 2"]
fn did_doc_emitter_matches_canonical_shape() {
    let _ = try_load_fixture("did-doc-conformance.json");
}
