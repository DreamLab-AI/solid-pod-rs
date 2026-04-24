//! NIP-11 integration test: the relay info document serialises to the
//! shape advertised to `GET /` with `Accept: application/nostr+json`.
//!
//! The wire handler in this crate surfaces the document as a JSON
//! object; consumers are expected to serve it with content-type
//! `application/nostr+json`. This test asserts the expected fields are
//! populated and that `supported_nips` contains 1, 11, and 16 (the
//! JSS-parity minimum).

use solid_pod_rs_nostr::{Relay, RelayInfo};

#[test]
fn relay_serves_nip11_info_compatible_with_jss() {
    let relay = Relay::in_memory();
    let info: &RelayInfo = relay.info();

    // Required NIP-11 top-level fields.
    assert!(!info.name.is_empty(), "name must not be empty");
    assert!(!info.description.is_empty(), "description must not be empty");
    assert!(!info.software.is_empty(), "software must not be empty");
    assert!(!info.version.is_empty(), "version must not be empty");

    // JSS parity claims NIP 1, 11, 16.
    for nip in [1u64, 11, 16] {
        assert!(
            info.supported_nips.contains(&nip),
            "expected NIP-{nip} in supported_nips (got {:?})",
            info.supported_nips
        );
    }

    // Serialisation round-trip: the doc must JSON-encode cleanly since
    // consumers serve it verbatim with `Content-Type: application/nostr+json`.
    let json = serde_json::to_value(info).expect("serialises");
    assert_eq!(json["name"], info.name);
    assert_eq!(json["supported_nips"][0], 1);
}

#[test]
fn custom_relay_info_round_trips() {
    use std::sync::Arc;
    use solid_pod_rs_nostr::InMemoryEventStore;

    let info = RelayInfo {
        name: "custom-relay".into(),
        description: "test".into(),
        pubkey: "aa".repeat(32),
        contact: "mailto:ops@example".into(),
        supported_nips: vec![1, 11, 16],
        software: "https://example.com".into(),
        version: "0.0.1".into(),
    };
    let relay = Relay::new(Arc::new(InMemoryEventStore::default()), info.clone(), 16);
    assert_eq!(relay.info().name, info.name);
    assert_eq!(relay.info().pubkey, info.pubkey);
    assert_eq!(relay.info().contact, info.contact);
}
