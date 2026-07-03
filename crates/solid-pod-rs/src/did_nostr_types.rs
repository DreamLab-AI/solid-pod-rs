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
//! - [`ServiceEntry`]          — service block (agentbox extension; the
//!   canonical create-agent form emits `service: []`).
//! - [`render_did_document`]   — canonical `DIDNostr` / `Multikey` document
//!   (ADR-125; supersedes the 2019-suite renderers).
//! - [`render_did_document_tier1`] — back-compat alias → [`render_did_document`].
//! - [`render_did_document_tier3`] — back-compat: canonical doc + extensions.
//! - [`format_multibase_schnorr`]  — `publicKeyMultibase` encoding
//!   (`fe70102` + x-only hex, multicodec `secp256k1-pub` over the 33-byte
//!   SEC1-compressed even-y point).
//! - [`parse_multibase_schnorr`]   — round-trip decoder (ACCEPT path).
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

/// A service entry published in a DID document.
///
/// **agentbox extension** — the canonical create-agent / did-nostr-CG form
/// emits `service: []`. Populating `service[]` is permitted (the spec marks
/// `service` optional) and yields a conformant *superset*, but the minimal
/// reference output is the empty array. `SolidWebID`, `SolidStorage`,
/// `NostrRelay`, `DIDNostrMesh` are agentbox extension types, never the
/// create-agent form.
///
/// The minimal contract only requires `id`, `type`, and `serviceEndpoint`;
/// callers may attach implementation-specific fields via `extra`.
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

/// Fragment of the canonical verification method (`#key1`).
const KEY_FRAGMENT: &str = "#key1";

/// Render the canonical minimal `did:nostr` DID document (ADR-125, fully
/// aligned to the did:nostr CG spec, <https://nostrcg.github.io/did-nostr/>).
///
/// This is the minimal / offline (Tier-2) form: the six REQUIRED fields only.
/// Per the spec's field model, the optional members (`alsoKnownAs`, `service`,
/// `profile`, `follows`, `modified`) are OMITTED entirely when there is no
/// data for them — an empty `service: []` is not emitted (that was the
/// pre-alignment shape). Use [`render_did_document_tier3`] to attach
/// `alsoKnownAs` identity links and `service` entries, or
/// [`render_did_document_complete`] for the full profile/social-graph form.
///
/// ```json
/// {
///   "@context": ["https://www.w3.org/ns/cid/v1", "https://w3id.org/nostr/context"],
///   "id": "did:nostr:<hex>",
///   "type": "DIDNostr",
///   "verificationMethod": [{
///     "id": "did:nostr:<hex>#key1",
///     "type": "Multikey",
///     "controller": "did:nostr:<hex>",
///     "publicKeyMultibase": "fe70102<hex>"
///   }],
///   "authentication": ["#key1"],
///   "assertionMethod": ["#key1"]
/// }
/// ```
///
/// `publicKeyMultibase` is `f` (base16-lower multibase) ‖ `e701`
/// (`varint(0xe7)` = `secp256k1-pub`) ‖ `02 ‖ X` (the 33-byte SEC1-compressed
/// even-y point — `0x02` is load-bearing multicodec payload, invariant for
/// BIP-340 `lift_x`). It round-trips byte-for-byte to the same x-only key as
/// the `did:nostr:<hex>` body. Per ADR-074 D1 (I4) the `did:nostr:<hex>`
/// string is unchanged.
pub fn render_did_document(pk: &NostrPubkey) -> Value {
    let did = did_nostr_uri(pk);
    json!({
        "@context": [
            "https://www.w3.org/ns/cid/v1",
            "https://w3id.org/nostr/context"
        ],
        "id": did,
        "type": "DIDNostr",
        "verificationMethod": [{
            "id": format!("{did}{KEY_FRAGMENT}"),
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": format_multibase_schnorr(&pk.0),
        }],
        "authentication": [KEY_FRAGMENT],
        "assertionMethod": [KEY_FRAGMENT]
    })
}

/// Back-compat alias for [`render_did_document`].
///
/// The Tier-1/Tier-3 split is superseded by the single canonical form
/// (ADR-125). Retained so existing call sites keep compiling; emits the
/// canonical `DIDNostr`/`Multikey` document with `service: []`.
pub fn render_did_document_tier1(pk: &NostrPubkey) -> Value {
    render_did_document(pk)
}

/// Render the enhanced DID document with a top-level `alsoKnownAs` identity
/// link and `service[]` entries.
///
/// Fully aligned to the did:nostr CG spec (<https://nostrcg.github.io/did-nostr/>):
/// the WebID (and any other identity URIs) are surfaced as **top-level
/// `alsoKnownAs`** — the spec's canonical location for cross-platform identity
/// links (WebID, ActivityPub, AT-proto) — and `service[]` carries actual
/// service endpoints (relays etc.; relay entries SHOULD use `type: "Relay"`
/// and a `wss://…/` endpoint with a trailing slash). Both members are omitted
/// when empty. This supersedes the ADR-125 §2.3 interim decision that routed
/// the WebID through a `service[] SolidWebID` entry.
pub fn render_did_document_tier3(
    pk: &NostrPubkey,
    webid: Option<&str>,
    services: &[ServiceEntry],
) -> Value {
    let mut doc = render_did_document(pk);

    if let Some(w) = webid {
        doc["alsoKnownAs"] = json!([w]);
    }
    if !services.is_empty() {
        doc["service"] = render_service_entries(services);
    }

    doc
}

/// Render the complete DID document with the optional social/profile members
/// from the spec's "complete" example: multi-URI top-level `alsoKnownAs`,
/// `service[]`, `profile` (kind-0 metadata object), `follows` (an array of
/// bare `did:nostr:<hex>` strings — SHOULD be bounded to a recent subset for
/// large follow lists), and `modified` (`dcterms:modified`, ISO-8601 UTC).
/// Every optional member is omitted when empty/absent, matching the spec's
/// omit-when-empty field model.
pub fn render_did_document_complete(
    pk: &NostrPubkey,
    also_known_as: &[String],
    services: &[ServiceEntry],
    profile: Option<&Value>,
    follows: &[String],
    modified: Option<&str>,
) -> Value {
    let mut doc = render_did_document(pk);

    if !also_known_as.is_empty() {
        doc["alsoKnownAs"] = json!(also_known_as);
    }
    if !services.is_empty() {
        doc["service"] = render_service_entries(services);
    }
    if let Some(p) = profile {
        doc["profile"] = p.clone();
    }
    if !follows.is_empty() {
        doc["follows"] = json!(follows);
    }
    if let Some(m) = modified {
        doc["modified"] = json!(m);
    }

    doc
}

/// Serialise `service[]` entries to their JSON-LD form, merging any
/// vendor-specific `extra` fields under the canonical `id`/`type`/
/// `serviceEndpoint` (the canonical trio always wins over `extra`).
fn render_service_entries(services: &[ServiceEntry]) -> Value {
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
    Value::Array(service_values)
}

// ── Multibase encoding ───────────────────────────────────────────────

/// The fixed `publicKeyMultibase` prefix: `f` (base16-lower multibase) ‖
/// `e701` (`varint(0xe7)` = `secp256k1-pub`) ‖ `02` (SEC1 even-y compressed
/// prefix). The 64-char x-only hex body follows. ADR-125 §2.1 / I2.
pub const MULTIKEY_PREFIX: &str = "fe70102";

/// Alternate prefix with odd-y parity byte (`0x03`). The spec says
/// "Implementations SHOULD handle both cases" — we accept `fe70103` on
/// decode but always produce the canonical even-y `fe70102` on encode.
pub const MULTIKEY_PREFIX_ODD: &str = "fe70103";

/// Fixed total length of a canonical `publicKeyMultibase` string:
/// `fe70102`(7) + 64 hex chars = 71. ADR-125 §2.1.
pub const MULTIKEY_LEN: usize = 71;

/// Build a `publicKeyMultibase` string for a BIP-340 x-only pubkey (I2).
///
/// Layout: `"f"` (base16-lower multibase) ‖ `hex(e701 ‖ 02 ‖ X)`, i.e. the
/// literal `"fe70102"` followed by the 64-char lowercase x-only hex.
///
/// - `e701` = unsigned-varint of multicodec `0xe7` (`secp256k1-pub`).
/// - `02 ‖ X` = the **33-byte SEC1-compressed even-y point**. The `0x02`
///   parity byte is load-bearing multicodec payload (the `secp256k1-pub`
///   codec is defined over the compressed key), invariant because BIP-340
///   `lift_x` always selects even-y.
///
/// Fixed [`MULTIKEY_LEN`] (71) chars, lowercase. Round-trips to the identical
/// key via [`parse_multibase_schnorr`]. No key bytes change (I2). Callers that
/// need the raw hex can use `NostrPubkey::to_hex`.
pub fn format_multibase_schnorr(pk: &[u8; 32]) -> String {
    // f + e701 + 02 + <x-only-hex-lower>. hex::encode is lowercase.
    format!("{MULTIKEY_PREFIX}{}", hex::encode(pk))
}

/// Decode a canonical `publicKeyMultibase` string back to the x-only key
/// (the ACCEPT path — strict round-trip with [`format_multibase_schnorr`]).
///
/// Validates, in order: the `fe70102` or `fe70103` prefix (base16-lower ‖
/// `varint(secp256k1-pub)` ‖ even-y or odd-y compressed prefix), the fixed
/// [`MULTIKEY_LEN`], lowercase hex, and that the 33-byte multicodec payload
/// frames as `02 ‖ X` or `03 ‖ X`. Returns the 32-byte x-only `X`.
///
/// The spec says "Implementations SHOULD handle both cases" (even-y `0x02`
/// and odd-y `0x03`). Both decode to the same x-only key.
///
/// Rejects (each an I2 violation): base58btc (`z…`); the missing-parity
/// `fe701<x>` 67-char form; uppercase hex under `f`;
/// any non-71 length; retained `publicKeyHex`-style raw hex.
pub fn parse_multibase_schnorr(s: &str) -> Result<NostrPubkey, PodError> {
    if s.len() != MULTIKEY_LEN {
        return Err(PodError::BadRequest(format!(
            "publicKeyMultibase: expected {MULTIKEY_LEN} chars, got {}",
            s.len()
        )));
    }
    // Lowercase + exact prefix in one pass (uppercase under `f` is malformed).
    // Accept both even-y (02) and odd-y (03) parity — the spec says
    // "Implementations SHOULD handle both cases".
    let body = s.strip_prefix(MULTIKEY_PREFIX)
        .or_else(|| s.strip_prefix(MULTIKEY_PREFIX_ODD))
        .ok_or_else(|| PodError::BadRequest(format!(
            "publicKeyMultibase: expected `{MULTIKEY_PREFIX}` or `{MULTIKEY_PREFIX_ODD}` prefix (got `{}`)",
            &s[..s.len().min(7)]
        )))?;
    if body.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(PodError::BadRequest(
            "publicKeyMultibase: uppercase hex under `f` indicator is malformed".into(),
        ));
    }
    NostrPubkey::from_hex(body)
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
    fn canonical_document_has_required_fields() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let did = format!("did:nostr:{PK_HEX}");
        let doc = render_did_document(&pk);
        assert_eq!(doc["id"], did);
        // Canonical did:nostr CG / Controlled Identifiers v1.0 context (ADR-125 §2).
        assert_eq!(doc["@context"][0], "https://www.w3.org/ns/cid/v1");
        assert_eq!(doc["@context"][1], "https://w3id.org/nostr/context");
        // Top-level type + canonical Multikey VM.
        assert_eq!(doc["type"], "DIDNostr");
        // Minimal form omits optional members entirely (spec omit-when-empty):
        // no empty `service: []`, no `alsoKnownAs`.
        assert!(doc.get("service").is_none(), "minimal form omits service");
        // The 2019 suite + publicKeyHex are GONE (ADR-074 D2 superseded).
        assert!(doc.get("alsoKnownAs").is_none());

        let vm = &doc["verificationMethod"][0];
        assert_eq!(vm["id"], format!("{did}#key1"));
        assert_eq!(vm["type"], "Multikey");
        assert_eq!(vm["controller"], did);
        assert!(vm.get("publicKeyHex").is_none(), "publicKeyHex must be dropped (I2)");
        assert_eq!(
            vm["publicKeyMultibase"],
            format!("fe70102{PK_HEX}"),
            "publicKeyMultibase == fe70102 + same x-only hex (I2)"
        );
        // Fragment-only auth/assertion references (ADR-125 §2).
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
        // Canonical core unchanged.
        assert_eq!(doc["type"], "DIDNostr");
        assert_eq!(doc["verificationMethod"][0]["type"], "Multikey");
        assert_eq!(doc["authentication"][0], "#key1");
        // agentbox extensions present.
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
    fn tier3_without_webid_or_services_is_canonical_empty_service() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let doc = render_did_document_tier3(&pk, None, &[]);
        // No extensions ⇒ byte-identical to the minimal form: no service,
        // no alsoKnownAs (both omitted, per the spec's omit-when-empty model).
        assert_eq!(doc, render_did_document(&pk));
        assert!(doc.get("alsoKnownAs").is_none());
        assert!(doc.get("service").is_none());
    }

    #[test]
    fn complete_document_carries_spec_profile_social_members() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let also = vec![
            "https://alice.example.com/#me".to_string(),
            "at://alice.bsky.social".to_string(),
        ];
        let relay = ServiceEntry {
            id: format!("did:nostr:{PK_HEX}#relay1"),
            service_type: "Relay".to_string(),
            service_endpoint: "wss://relay.damus.io/".to_string(),
            extra: None,
        };
        let profile = json!({
            "name": "Alice",
            "about": "Building the decentralized web",
            "picture": "https://example.com/alice.jpg",
            "created_at": 1737906600
        });
        let follows = vec![
            format!("did:nostr:{}", "ab".repeat(32)),
        ];
        let doc = render_did_document_complete(
            &pk, &also, &[relay], Some(&profile), &follows, Some("2025-01-26T15:50:00Z"),
        );
        // Canonical core unchanged (spec-aligned).
        assert_eq!(doc["type"], "DIDNostr");
        assert_eq!(doc["@context"][0], "https://www.w3.org/ns/cid/v1");
        assert_eq!(doc["verificationMethod"][0]["type"], "Multikey");
        assert_eq!(doc["authentication"][0], "#key1");
        // Top-level alsoKnownAs (spec canonical, multi-URI).
        assert_eq!(doc["alsoKnownAs"][1], "at://alice.bsky.social");
        // Relay service with trailing-slash endpoint.
        assert_eq!(doc["service"][0]["type"], "Relay");
        assert_eq!(doc["service"][0]["serviceEndpoint"], "wss://relay.damus.io/");
        // Complete-form members.
        assert_eq!(doc["profile"]["name"], "Alice");
        assert_eq!(doc["profile"]["created_at"], 1737906600);
        assert!(doc["follows"][0].as_str().unwrap().starts_with("did:nostr:"));
        assert_eq!(doc["modified"], "2025-01-26T15:50:00Z");
    }

    #[test]
    fn multibase_schnorr_is_canonical_form() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let a = format_multibase_schnorr(&pk.0);
        let b = format_multibase_schnorr(&pk.0);
        assert_eq!(a, b, "deterministic");
        // C2: `f` + base16, NOT `z` + base58.
        assert!(a.starts_with("fe70102"), "must be fe70102 prefix, not z-base58");
        // C1: fixed 71-char length (fe70102 + 64 hex).
        assert_eq!(a.len(), MULTIKEY_LEN);
        // C3: explicit lowercase-hex assertion + exact literal.
        assert_eq!(a, format!("fe70102{PK_HEX}"));
        assert_eq!(a, a.to_lowercase(), "lowercase hex throughout");
        assert!(a.chars().all(|c| !c.is_ascii_uppercase()));
        // I2: multibase body == DID body (x-only hex).
        assert_eq!(&a[7..], PK_HEX);
    }

    #[test]
    fn multibase_schnorr_round_trips_identical_key() {
        // I2: encode → decode → identical key, no bytes change.
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let mb = format_multibase_schnorr(&pk.0);
        let decoded = parse_multibase_schnorr(&mb).unwrap();
        assert_eq!(decoded, pk);
        assert_eq!(decoded.to_hex(), PK_HEX);
    }

    #[test]
    fn parse_multibase_accepts_odd_parity() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let odd = format!("fe70103{PK_HEX}");
        let decoded = parse_multibase_schnorr(&odd).unwrap();
        assert_eq!(decoded, pk, "odd parity decodes to same x-only key");
    }

    #[test]
    fn parse_multibase_rejects_missing_parity_form() {
        // C1/C2 negative vector: the `fe701<x>` 67-char missing-parity form.
        let bad = format!("fe701{PK_HEX}"); // 5 + 64 = 69 chars (no 02)
        assert!(parse_multibase_schnorr(&bad).is_err());
    }

    #[test]
    fn parse_multibase_rejects_base58btc() {
        // The pre-ADR-125 `z`+base58 form must be rejected.
        assert!(parse_multibase_schnorr("zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme").is_err());
    }

    #[test]
    fn parse_multibase_rejects_uppercase_hex() {
        // C2 negative vector: uppercase hex under the `f` indicator.
        // The key MUST contain hex letters so `to_uppercase()` is non-trivial.
        // An all-digit key (PK_HEX = 000…001) makes `to_uppercase()` a no-op,
        // leaving the body lowercase, which the decoder accepts — the vector
        // would then assert `is_err()` on an `Ok(..)` and FAIL the build. Use a
        // lettered key and guard the fixture so this can never silently regress.
        let lettered = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        assert_eq!(lettered.len(), 64, "fixture guard: 64-char x-only hex");
        assert!(
            lettered.chars().any(|c| c.is_ascii_alphabetic()),
            "fixture guard: the negative vector must contain hex letters",
        );
        let upper = format!("fe70102{}", lettered.to_uppercase());
        assert!(parse_multibase_schnorr(&upper).is_err());
    }

    #[test]
    fn parse_multibase_rejects_wrong_length() {
        assert!(parse_multibase_schnorr("fe70102").is_err());
        assert!(parse_multibase_schnorr(&format!("fe70102{PK_HEX}ab")).is_err());
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
