//! `did:nostr` DID Document rendering and well-known path layout.
//!
//! Upstream parity:
//! - `JavaScriptSolidServer/src/auth/did-nostr.js:79` — DID Doc URL
//!   (`<resolver>/<pubkey>.json`). We pin the resolver base to
//!   `/.well-known/did/nostr/` per PARITY-CHECKLIST row 132.
//! - `JavaScriptSolidServer/src/auth/did-nostr.js:94-107` — `alsoKnownAs`
//!   array is the canonical carrier for the WebID link.
//!
//! The canonical implementations live in `solid_pod_rs::did_nostr_types`
//! (feature `did-nostr-types`). This module re-exports them for backward
//! compatibility.

// Re-export canonical types from the core crate.
pub use solid_pod_rs::did_nostr_types::{
    did_nostr_uri, format_multibase_schnorr, is_valid_hex_pubkey, render_did_document_tier1,
    render_did_document_tier3, verify_webid_tag, well_known_path, NostrPubkey, ServiceEntry,
};

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const PK_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn pubkey_roundtrip_hex() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        assert_eq!(pk.to_hex(), PK_HEX);
    }

    #[test]
    fn pubkey_rejects_short_hex() {
        assert!(NostrPubkey::from_hex("abcd").is_err());
    }

    #[test]
    fn pubkey_rejects_non_hex() {
        assert!(NostrPubkey::from_hex(&"z".repeat(64)).is_err());
    }

    #[test]
    fn did_uri_format() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        assert_eq!(did_nostr_uri(&pk), format!("did:nostr:{PK_HEX}"));
    }

    #[test]
    fn well_known_path_matches_spec() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let path = well_known_path(&pk);
        assert_eq!(path, format!("/.well-known/did/nostr/{PK_HEX}.json"));
        assert!(path.starts_with("/.well-known/did/nostr/"));
        assert!(path.ends_with(".json"));
    }

    #[test]
    fn tier1_document_has_required_fields() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let doc = render_did_document_tier1(&pk);
        assert_eq!(doc["id"], format!("did:nostr:{PK_HEX}"));
        assert_eq!(doc["@context"][0], "https://www.w3.org/ns/did/v1");
        assert_eq!(
            doc["@context"][1], "https://w3id.org/security/suites/secp256k1-2019/v1",
            "Tier-1 must include the secp256k1-2019 suite context so \
             SchnorrSecp256k1VerificationKey2019 resolves under JSON-LD"
        );
        assert!(doc["alsoKnownAs"].is_array());
        assert_eq!(doc["alsoKnownAs"].as_array().unwrap().len(), 0);

        let vm = &doc["verificationMethod"][0];
        assert_eq!(vm["type"], "SchnorrSecp256k1VerificationKey2019");
        assert_eq!(vm["publicKeyHex"], PK_HEX);
        assert!(vm["publicKeyMultibase"].as_str().unwrap().starts_with('z'));
    }

    #[test]
    fn tier3_document_carries_webid_and_services() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let webid = "https://alice.example/profile/card#me";
        let service = ServiceEntry {
            id: format!("did:nostr:{PK_HEX}#solid"),
            service_type: "SolidWebID".to_string(),
            service_endpoint: webid.to_string(),
            extra: None,
        };
        let doc = render_did_document_tier3(&pk, Some(webid), &[service]);
        assert_eq!(doc["alsoKnownAs"][0], webid);
        assert_eq!(
            doc["verificationMethod"][0]["type"],
            "SchnorrSecp256k1VerificationKey2019"
        );
        assert_eq!(doc["service"][0]["type"], "SolidWebID");
        assert_eq!(doc["service"][0]["serviceEndpoint"], webid);
        assert_eq!(
            doc["authentication"][0],
            format!("did:nostr:{PK_HEX}#nostr-schnorr")
        );
    }

    #[test]
    fn tier3_extras_do_not_override_core_fields() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let extra = json!({"id": "malicious", "type": "evil", "custom": "ok"});
        let service = ServiceEntry {
            id: "real-id".to_string(),
            service_type: "NostrRelay".to_string(),
            service_endpoint: "wss://relay.example".to_string(),
            extra: Some(extra),
        };
        let doc = render_did_document_tier3(&pk, None, &[service]);
        assert_eq!(doc["service"][0]["id"], "real-id");
        assert_eq!(doc["service"][0]["type"], "NostrRelay");
        assert_eq!(doc["service"][0]["custom"], "ok");
    }

    #[test]
    fn tier3_without_webid_has_empty_also_known_as() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let doc = render_did_document_tier3(&pk, None, &[]);
        assert!(doc["alsoKnownAs"].as_array().unwrap().is_empty());
    }

    #[test]
    fn multibase_schnorr_is_deterministic() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let a = format_multibase_schnorr(&pk.0);
        let b = format_multibase_schnorr(&pk.0);
        assert_eq!(a, b);
        assert!(a.starts_with('z'));
        assert!(a.len() > 10);
    }
}
