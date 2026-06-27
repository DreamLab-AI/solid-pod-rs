//! `did:nostr` DID Document rendering and well-known path layout.
//!
//! Upstream parity:
//! - `JavaScriptSolidServer/src/auth/did-nostr.js:79` — DID Doc URL
//!   (`<resolver>/<pubkey>.json`). We pin the resolver base to
//!   `/.well-known/did/nostr/` per PARITY-CHECKLIST row 132.
//! - `JavaScriptSolidServer/src/auth/did-nostr.js:94-107` — `alsoKnownAs`
//!   array is the canonical carrier for the WebID link.
//!
//! The DID Document shape is the canonical `DIDNostr` / `Multikey` form
//! (ADR-125 — `did:nostr` CG / melvincarvalho create-agent), superseding the
//! 2019-suite / `publicKeyHex` shape (ADR-074 §D2/§D3/§D4/§D13).
//!
//! The canonical implementations live in `solid_pod_rs::did_nostr_types`
//! (feature `did-nostr-types`). This module re-exports them for backward
//! compatibility.

// Re-export canonical types from the core crate.
pub use solid_pod_rs::did_nostr_types::{
    did_nostr_uri, format_multibase_schnorr, is_valid_hex_pubkey, parse_multibase_schnorr,
    render_did_document, render_did_document_tier1, render_did_document_tier3, verify_webid_tag,
    well_known_path, NostrPubkey, ServiceEntry,
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
    fn canonical_document_has_required_fields() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let did = format!("did:nostr:{PK_HEX}");
        let doc = render_did_document(&pk);
        assert_eq!(doc["id"], did);
        assert_eq!(doc["@context"][0], "https://www.w3.org/ns/cid/v1");
        assert_eq!(doc["@context"][1], "https://w3id.org/nostr/context");
        assert_eq!(doc["type"], "DIDNostr");
        // service:[] is the canonical create-agent form; no top-level alsoKnownAs.
        assert!(doc["service"].as_array().unwrap().is_empty());
        assert!(doc.get("alsoKnownAs").is_none());

        let vm = &doc["verificationMethod"][0];
        assert_eq!(vm["type"], "Multikey");
        assert!(vm.get("publicKeyHex").is_none());
        assert_eq!(vm["publicKeyMultibase"], format!("fe70102{PK_HEX}"));
        assert_eq!(doc["authentication"][0], "#key1");
        assert_eq!(doc["assertionMethod"][0], "#key1");
    }

    #[test]
    fn tier1_alias_emits_canonical_document() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        assert_eq!(render_did_document_tier1(&pk), render_did_document(&pk));
    }

    #[test]
    fn tier3_document_carries_webid_and_services_as_extensions() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let webid = "https://alice.example/profile/card#me";
        let service = ServiceEntry {
            id: format!("did:nostr:{PK_HEX}#solid"),
            service_type: "SolidWebID".to_string(),
            service_endpoint: webid.to_string(),
            extra: None,
        };
        let doc = render_did_document_tier3(&pk, Some(webid), &[service]);
        assert_eq!(doc["type"], "DIDNostr");
        assert_eq!(doc["verificationMethod"][0]["type"], "Multikey");
        assert_eq!(doc["authentication"][0], "#key1");
        // agentbox extensions.
        assert_eq!(doc["alsoKnownAs"][0], webid);
        assert_eq!(doc["service"][0]["type"], "SolidWebID");
        assert_eq!(doc["service"][0]["serviceEndpoint"], webid);
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
    fn tier3_without_webid_or_services_is_canonical() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let doc = render_did_document_tier3(&pk, None, &[]);
        assert_eq!(doc, render_did_document(&pk));
        assert!(doc.get("alsoKnownAs").is_none());
        assert!(doc["service"].as_array().unwrap().is_empty());
    }

    #[test]
    fn multibase_schnorr_round_trips_canonical() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let a = format_multibase_schnorr(&pk.0);
        assert_eq!(a, format_multibase_schnorr(&pk.0), "deterministic");
        assert_eq!(a, format!("fe70102{PK_HEX}"));
        assert_eq!(a.len(), 71);
        assert_eq!(a, a.to_lowercase());
        // ACCEPT path: round-trips to the identical key (I2).
        assert_eq!(parse_multibase_schnorr(&a).unwrap(), pk);
        // Reject the pre-pivot z-base58 form.
        assert!(parse_multibase_schnorr("zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme").is_err());
    }
}
