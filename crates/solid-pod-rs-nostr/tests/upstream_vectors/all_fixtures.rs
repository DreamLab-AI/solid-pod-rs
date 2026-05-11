// crates/solid-pod-rs-nostr/tests/upstream_vectors/all_fixtures.rs
//! L1 reference-vector tests — solid-pod-rs-nostr substrate.
//!
//! Per ADR-082 D5, solid-pod-rs consumes fixtures synced from VisionClaw's
//! docs/specs/fixtures/. Fixtures relevant to the nostr/auth crate per the
//! coverage matrix: nip01, nip19, nip98, bip340, rfc8785, did-doc, is-envelope,
//! multibase.

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
    nip01_events_load_and_validate,
    "nip01-events.json",
    "NIP-01",
    11
);
fixture_test!(
    nip19_bech32_load_and_validate,
    "nip19-bech32.json",
    "NIP-19",
    12
);
fixture_test!(
    nip98_tokens_load_and_validate,
    "nip98-tokens.json",
    "NIP-98",
    6
);
fixture_test!(
    bip340_load_and_validate,
    "bip340-schnorr.json",
    "BIP-340",
    19
);
fixture_test!(rfc8785_load_and_validate, "rfc8785-jcs.json", "RFC 8785", 6);
fixture_test!(
    multibase_load_and_validate,
    "multibase.json",
    "Multibase",
    27
);
fixture_test!(
    did_doc_load_and_validate,
    "did-doc-conformance.json",
    "ADR-074",
    7
);
fixture_test!(
    is_envelope_load_and_validate,
    "is-envelope-v1.json",
    "ADR-075",
    11
);
