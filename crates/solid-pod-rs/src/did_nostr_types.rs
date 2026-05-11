//! Canonical `did:nostr` types and DID-Document renderers.
//!
//! This module lives in the core crate behind the lightweight
//! `did-nostr-types` feature flag so that wasm32 consumers (Cloudflare
//! Workers) can use it without pulling tokio or reqwest. The heavier
//! resolver surface stays in `solid-pod-rs-nostr` and in
//! `interop::did_nostr` (feature `did-nostr`).
//!
//! Re-exported by `solid-pod-rs-nostr::did` — that crate's DID module
//! delegates here for the canonical implementations.
//!
//! ## Published items
//!
//! - [`NostrPubkey`]           — 32-byte x-only Schnorr pubkey (hex round-trip).
//! - [`did_nostr_uri`]         — `did:nostr:<hex>` formatter.
//! - [`well_known_path`]       — `/.well-known/did/nostr/<hex>.json`.
//! - [`ServiceEntry`]          — service block for Tier-3 documents.
//! - [`render_did_document_tier1`] — minimum-viable DID document.
//! - [`render_did_document_tier3`] — owner-signed doc with services.
//! - [`format_multibase_schnorr`]  — `publicKeyMultibase` encoding.
//! - [`is_valid_hex_pubkey`]   — 64-char lowercase hex validation.
//! - [`verify_webid_tag`]      — checks a tag value against a pubkey.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::PodError;

// ── NostrPubkey ──────────────────────────────────────────────────────

/// A 32-byte x-only Schnorr (secp256k1) public key, as used by NIP-01.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NostrPubkey(pub [u8; 32]);

impl NostrPubkey {
    /// Parse a lowercase hex string of exactly 64 characters.
    pub fn from_hex(s: &str) -> Result<Self, PodError> {
        if s.len() != 64 {
            return Err(PodError::BadRequest(format!(
                "expected 64 hex chars, got {}",
                s.len()
            )));
        }
        let bytes = hex::decode(s).map_err(|e| PodError::BadRequest(e.to_string()))?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Lower-case hex encoding (64 chars).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

// ── URI helpers ──────────────────────────────────────────────────────

/// Format a `did:nostr:<hex>` URI for the given pubkey.
pub fn did_nostr_uri(pk: &NostrPubkey) -> String {
    format!("did:nostr:{}", pk.to_hex())
}

/// Path component at which the DID document should be served.
/// Mirrors JSS resolver convention (`<base>/<pubkey>.json`).
pub fn well_known_path(pk: &NostrPubkey) -> String {
    format!("/.well-known/did/nostr/{}.json", pk.to_hex())
}

// ── ServiceEntry ─────────────────────────────────────────────────────

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

// ── Document renderers ───────────────────────────────────────────────

/// Render a minimum-viable (Tier 1) DID document.
///
/// Contains:
/// - `@context`: W3C DID Core v1 + `secp256k1-2019` suite (required so the
///   `SchnorrSecp256k1VerificationKey2019` term resolves under JSON-LD
///   processing).
/// - `id`: `did:nostr:<hex>`.
/// - `alsoKnownAs`: empty array (WebID binding is Tier 3).
/// - `verificationMethod`: single `SchnorrSecp256k1VerificationKey2019` entry
///   keyed by the x-only pubkey (`publicKeyMultibase` uses multibase `z` +
///   multicodec `0xe7` for secp256k1 schnorr per emerging convention,
///   retaining `publicKeyHex` for JSS parity).
///
/// Per ADR-074 D1: cross-system DID canonicalisation mandates the suite
/// identifier `SchnorrSecp256k1VerificationKey2019` — the only published W3C
/// secp256k1 Schnorr suite.
pub fn render_did_document_tier1(pk: &NostrPubkey) -> Value {
    let did = did_nostr_uri(pk);
    json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/secp256k1-2019/v1"
        ],
        "id": did,
        "alsoKnownAs": [],
        "verificationMethod": [{
            "id": format!("{did}#nostr-schnorr"),
            "type": "SchnorrSecp256k1VerificationKey2019",
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
            "type": "SchnorrSecp256k1VerificationKey2019",
            "controller": did,
            "publicKeyHex": pk.to_hex(),
            "publicKeyMultibase": format_multibase_schnorr(&pk.0),
        }],
        "authentication": [format!("{did}#nostr-schnorr")],
        "assertionMethod": [format!("{did}#nostr-schnorr")],
        "service": service_values,
    })
}

// ── Multibase encoding ───────────────────────────────────────────────

/// Build a `publicKeyMultibase` string for a secp256k1 x-only pubkey.
///
/// Layout: `'z' || base58btc( 0xe7 0x01 || pubkey )`.
/// (Multicodec `0xe7` = secp256k1-pub; leading `0x01` is the varint
/// marker.) Callers that need the raw hex can use `NostrPubkey::to_hex`.
pub fn format_multibase_schnorr(pk: &[u8; 32]) -> String {
    let mut prefixed = Vec::with_capacity(34);
    prefixed.push(0xe7);
    prefixed.push(0x01);
    prefixed.extend_from_slice(pk);
    format!("z{}", base58_encode(&prefixed))
}

/// Minimal base58btc encoder — avoids pulling an extra dependency for
/// what is a single multicodec rendering site.
fn base58_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if input.is_empty() {
        return String::new();
    }

    let zeros = input.iter().take_while(|&&b| b == 0).count();

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

// ── Validation helpers ───────────────────────────────────────────────

/// Validate that `s` is a 64-character lowercase hex string (a valid
/// NIP-01 pubkey in hex form).
pub fn is_valid_hex_pubkey(s: &str) -> bool {
    s.len() == 64
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// Check whether `tag_value` matches the expected `did:nostr` URI for
/// `pubkey`, or is a pod URL that embeds the pubkey hex.
///
/// This supports two patterns:
/// 1. Exact `did:nostr:<pubkey>` match.
/// 2. A URL containing the pubkey hex (e.g.
///    `https://pod.example/.well-known/did/nostr/<pubkey>.json`).
pub fn verify_webid_tag(tag_value: &str, pubkey: &str) -> bool {
    if !is_valid_hex_pubkey(pubkey) {
        return false;
    }
    let expected_did = format!("did:nostr:{pubkey}");
    if tag_value == expected_did {
        return true;
    }
    tag_value.contains(pubkey)
}

// ── Tests ────────────────────────────────────────────────────────────

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
            doc["@context"][1],
            "https://w3id.org/security/suites/secp256k1-2019/v1",
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

    #[test]
    fn is_valid_hex_pubkey_accepts_valid() {
        assert!(is_valid_hex_pubkey(PK_HEX));
        assert!(is_valid_hex_pubkey(&"ab".repeat(32)));
    }

    #[test]
    fn is_valid_hex_pubkey_rejects_invalid() {
        assert!(!is_valid_hex_pubkey("short"));
        assert!(!is_valid_hex_pubkey(&"Z".repeat(64)));
        assert!(!is_valid_hex_pubkey(&"g".repeat(64)));
    }

    #[test]
    fn verify_webid_tag_did_uri() {
        assert!(verify_webid_tag(&format!("did:nostr:{PK_HEX}"), PK_HEX));
    }

    #[test]
    fn verify_webid_tag_url_containing_pubkey() {
        let url = format!("https://pod.example/.well-known/did/nostr/{PK_HEX}.json");
        assert!(verify_webid_tag(&url, PK_HEX));
    }

    #[test]
    fn verify_webid_tag_rejects_mismatch() {
        assert!(!verify_webid_tag("https://other.example/foo", PK_HEX));
    }

    #[test]
    fn verify_webid_tag_rejects_invalid_pubkey() {
        assert!(!verify_webid_tag("did:nostr:abc", "abc"));
    }
}
