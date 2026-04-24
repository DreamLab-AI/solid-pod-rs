//! `did:nostr` DID Document rendering and well-known path layout.
//!
//! Upstream parity:
//! - `JavaScriptSolidServer/src/auth/did-nostr.js:79` — DID Doc URL
//!   (`<resolver>/<pubkey>.json`). We pin the resolver base to
//!   `/.well-known/did/nostr/` per PARITY-CHECKLIST row 132.
//! - `JavaScriptSolidServer/src/auth/did-nostr.js:94-107` — `alsoKnownAs`
//!   array is the canonical carrier for the WebID link.
//!
//! This module publishes:
//!
//! - [`NostrPubkey`]           — 32-byte x-only Schnorr pubkey (hex ↔ bytes).
//! - [`did_nostr_uri`]         — `did:nostr:<hex>` formatter.
//! - [`well_known_path`]       — path at which to serve the DID document.
//! - [`render_did_document_tier1`] — minimum-viable doc (pubkey only).
//! - [`render_did_document_tier3`] — owner-signed doc with `alsoKnownAs`
//!   and service entries (for CID/LWS parity).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::DidError;

/// A 32-byte x-only Schnorr (secp256k1) public key, as used by NIP-01.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NostrPubkey(pub [u8; 32]);

impl NostrPubkey {
    /// Parse a lowercase hex string of exactly 64 characters.
    pub fn from_hex(s: &str) -> Result<Self, DidError> {
        if s.len() != 64 {
            return Err(DidError::InvalidPubkey(format!(
                "expected 64 hex chars, got {}",
                s.len()
            )));
        }
        let bytes = hex::decode(s).map_err(|e| DidError::InvalidPubkey(e.to_string()))?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Lower-case hex encoding (64 chars).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Format a `did:nostr:<hex>` URI for the given pubkey.
pub fn did_nostr_uri(pk: &NostrPubkey) -> String {
    format!("did:nostr:{}", pk.to_hex())
}

/// Path component at which the DID document should be served.
/// Mirrors JSS resolver convention (`<base>/<pubkey>.json`).
pub fn well_known_path(pk: &NostrPubkey) -> String {
    format!("/.well-known/did/nostr/{}.json", pk.to_hex())
}

/// A service entry published in a Tier-3 DID document.
///
/// The minimal JSS contract only requires `id`, `type`, and
/// `serviceEndpoint`; callers may attach implementation-specific fields
/// via `extra`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEntry {
    /// Service id — typically `<did>#<name>`.
    pub id: String,
    /// Service type, e.g. `SolidWebID`, `NostrRelay`.
    #[serde(rename = "type")]
    pub service_type: String,
    /// Endpoint URL or URN.
    pub service_endpoint: String,
    /// Optional vendor-specific properties; merged into the rendered
    /// service entry at publication time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

/// Render a minimum-viable (Tier 1) DID document.
///
/// Contains:
/// - `@context`: W3C DID Core v1.
/// - `id`: `did:nostr:<hex>`.
/// - `alsoKnownAs`: empty array (WebID binding is Tier 3).
/// - `verificationMethod`: single `NostrSchnorrKey2024` entry keyed by
///   the x-only pubkey (`publicKeyMultibase` uses multibase `z` +
///   multicodec `0xe7` for secp256k1 schnorr per emerging convention,
///   retaining `publicKeyHex` for JSS parity).
pub fn render_did_document_tier1(pk: &NostrPubkey) -> Value {
    let did = did_nostr_uri(pk);
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "alsoKnownAs": [],
        "verificationMethod": [{
            "id": format!("{did}#nostr-schnorr"),
            "type": "NostrSchnorrKey2024",
            "controller": did,
            "publicKeyHex": pk.to_hex(),
            "publicKeyMultibase": format_multibase_schnorr(&pk.0),
        }]
    })
}

/// Render a Tier-3 DID document with a bidirectional WebID link and
/// operator service entries.
///
/// `webid` populates `alsoKnownAs` (and becomes the canonical WebID of
/// the controller). `services` surface federation endpoints (Solid
/// `SolidWebID`, `NostrRelay`, ActivityPub `ActivityPubActor`,
/// `ContentIdentifierService` for CID/LWS parity, etc.).
pub fn render_did_document_tier3(
    pk: &NostrPubkey,
    webid: Option<&str>,
    services: &[ServiceEntry],
) -> Value {
    let did = did_nostr_uri(pk);
    let also_known_as: Vec<Value> = webid
        .into_iter()
        .map(|w| Value::String(w.to_string()))
        .collect();

    let service_values: Vec<Value> = services
        .iter()
        .map(|s| {
            // Start from the required triple, merge extras (extras never
            // override the declared id / type / serviceEndpoint).
            let mut obj = serde_json::Map::new();
            if let Some(Value::Object(extra)) = s.extra.clone() {
                for (k, v) in extra {
                    obj.insert(k, v);
                }
            }
            obj.insert("id".to_string(), Value::String(s.id.clone()));
            obj.insert("type".to_string(), Value::String(s.service_type.clone()));
            obj.insert(
                "serviceEndpoint".to_string(),
                Value::String(s.service_endpoint.clone()),
            );
            Value::Object(obj)
        })
        .collect();

    json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/secp256k1-2019/v1"
        ],
        "id": did,
        "alsoKnownAs": also_known_as,
        "verificationMethod": [{
            "id": format!("{did}#nostr-schnorr"),
            "type": "NostrSchnorrKey2024",
            "controller": did,
            "publicKeyHex": pk.to_hex(),
            "publicKeyMultibase": format_multibase_schnorr(&pk.0),
        }],
        "authentication": [format!("{did}#nostr-schnorr")],
        "assertionMethod": [format!("{did}#nostr-schnorr")],
        "service": service_values,
    })
}

/// Build a `publicKeyMultibase` string for a secp256k1 x-only pubkey.
///
/// Layout: `'z' || base58btc( 0xe7 0x01 || pubkey )`.
/// (Multicodec `0xe7` = secp256k1-pub; leading `0x01` is the varint
/// marker.) Callers that need the raw hex can use `NostrPubkey::to_hex`.
fn format_multibase_schnorr(pk: &[u8; 32]) -> String {
    let mut prefixed = Vec::with_capacity(34);
    prefixed.push(0xe7);
    prefixed.push(0x01);
    prefixed.extend_from_slice(pk);
    format!("z{}", base58_encode(&prefixed))
}

/// Minimal base58btc encoder — avoids pulling an extra dependency for
/// what is a single multicodec rendering site.
fn base58_encode(input: &[u8]) -> String {
    // Bitcoin base58 alphabet.
    const ALPHABET: &[u8; 58] =
        b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if input.is_empty() {
        return String::new();
    }

    // Count leading zeros (preserved as '1' per spec).
    let zeros = input.iter().take_while(|&&b| b == 0).count();

    // Convert to base-58 via repeated division (big-endian).
    let mut digits: Vec<u8> = Vec::with_capacity(input.len() * 2);
    for &byte in input {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut out = String::with_capacity(zeros + digits.len());
    out.extend(std::iter::repeat('1').take(zeros));
    for &d in digits.iter().rev() {
        out.push(ALPHABET[d as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PK_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn pubkey_roundtrip_hex() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        assert_eq!(pk.to_hex(), PK_HEX);
    }

    #[test]
    fn pubkey_rejects_short_hex() {
        let err = NostrPubkey::from_hex("abcd").unwrap_err();
        assert!(matches!(err, DidError::InvalidPubkey(_)));
    }

    #[test]
    fn pubkey_rejects_non_hex() {
        let err = NostrPubkey::from_hex(&"z".repeat(64)).unwrap_err();
        assert!(matches!(err, DidError::InvalidPubkey(_)));
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
        assert!(doc["alsoKnownAs"].is_array());
        assert_eq!(doc["alsoKnownAs"].as_array().unwrap().len(), 0);

        let vm = &doc["verificationMethod"][0];
        assert_eq!(vm["type"], "NostrSchnorrKey2024");
        assert_eq!(vm["publicKeyHex"], PK_HEX);
        assert!(vm["publicKeyMultibase"]
            .as_str()
            .unwrap()
            .starts_with('z'));
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
            "NostrSchnorrKey2024"
        );
        assert_eq!(doc["service"][0]["type"], "SolidWebID");
        assert_eq!(doc["service"][0]["serviceEndpoint"], webid);
        assert_eq!(doc["authentication"][0], format!("did:nostr:{PK_HEX}#nostr-schnorr"));
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
