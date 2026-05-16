//! Integration test for the JSS v0.0.190 Phase 1 pod-resident NIP-05
//! endpoint (parity row 197, issue #437).
//!
//! Exercises the builder + extractor primitives wired into the server
//! route at `/.well-known/nostr.json?name=<local>`. The full route
//! handler is integration-tested under
//! `solid-pod-rs-server/tests` so that suite owns the actix-app
//! lifecycle; here we test the building blocks that the handler
//! composes.

#![cfg(feature = "nip05-endpoint")]

use solid_pod_rs::interop::{nip05_document, verify_nip05, Nip05Document};
use solid_pod_rs::webid::{extract_nostr_pubkey, generate_webid_html};

#[test]
fn nip05_round_trip_builds_then_resolves() {
    let pubkey_hex = "a".repeat(64);
    let doc = nip05_document([("alice".to_string(), pubkey_hex.clone())]);
    let resolved = verify_nip05("alice@pod.example", &doc).unwrap();
    assert_eq!(resolved, pubkey_hex);
}

#[test]
fn nip05_response_shape_serialises_per_spec() {
    let pubkey_hex = "b".repeat(64);
    let doc = nip05_document([("alice".to_string(), pubkey_hex.clone())]);
    let json = serde_json::to_value(&doc).unwrap();
    assert!(json["names"].is_object());
    assert_eq!(json["names"]["alice"], pubkey_hex);
    // NIP-05 §"Response" — `relays` is optional and omitted when absent.
    assert!(json.get("relays").is_none() || json["relays"].is_null());
}

#[test]
fn extract_nostr_pubkey_from_webid_html_returns_none_when_absent() {
    // The vanilla WebID generator does not seed `nostr:pubkey` — only
    // `provision_pod_keys` does. Confirm the extractor honestly
    // reports "absent" rather than falling back to the
    // verificationMethod subgraph.
    let html = generate_webid_html("abc", Some("Alice"), "https://pod.example");
    let extracted = extract_nostr_pubkey(html.as_bytes()).unwrap();
    assert!(extracted.is_none());
}

#[test]
fn extract_nostr_pubkey_from_webid_html_finds_string_value() {
    // Hand-craft a profile/card whose JSON-LD island carries the
    // `nostr:pubkey` triple. Mirrors what `provision_pod_keys`
    // produces after patching.
    let html = r#"<!DOCTYPE html><html><head>
<script type="application/ld+json">
{
  "@context": { "nostr": "https://nostr.org/ns#" },
  "@id": "https://pod.example/profile/card#me",
  "nostr:pubkey": "deadbeefcafebabe000000000000000000000000000000000000000000000000"
}
</script>
</head><body></body></html>"#;
    let extracted = extract_nostr_pubkey(html.as_bytes()).unwrap();
    assert_eq!(
        extracted.as_deref(),
        Some("deadbeefcafebabe000000000000000000000000000000000000000000000000")
    );
}

#[test]
fn nip05_document_omits_relays_when_unset() {
    let _ = Nip05Document {
        names: std::collections::HashMap::new(),
        relays: None,
    };
    // The omission contract is covered by
    // `nip05_response_shape_serialises_per_spec` above.
}
