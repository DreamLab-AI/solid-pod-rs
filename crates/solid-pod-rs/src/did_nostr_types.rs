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
//! - [`render_did_document_published`] — the document a controller publishes
//!   from its full key; the parity byte follows the key's actual y.
//! - [`format_multibase_schnorr`]  — `publicKeyMultibase` from the identifier
//!   alone (`fe70102` + x-only hex: the `0x02` even-y lift).
//! - [`format_multibase_public_key`] / [`format_multibase_sec1`] —
//!   `publicKeyMultibase` from a full SEC1 point (`fe70102` or `fe70103`).
//! - [`parse_multibase_schnorr`]   — decoder to the x-only identifier;
//!   accepts both parity prefixes.
//! - [`parse_multibase_sec1`]      — decoder to the full point the document
//!   carries (for key arithmetic on a published document).
//! - [`is_valid_hex_pubkey`]   — 64-char lowercase hex validation.
//! - [`verify_webid_tag`]      — checks a tag value against a pubkey.
//!
//! ## Parity model
//!
//! Follows the did:nostr parity model as reconciled in
//! [nostrcg/did-nostr#145](https://github.com/nostrcg/did-nostr/pull/145)
//! (closing [#144](https://github.com/nostrcg/did-nostr/issues/144)):
//!
//! 1. **Identifier** — `did:nostr:<64-hex>` is the x-only BIP-340 key and
//!    carries no parity.
//! 2. **Multikey** — a resolver holding only the identifier (minimal /
//!    offline resolution) emits `0x02`, the BIP-340 even-y lift
//!    ([`render_did_document`]). A document the controller publishes (HTTP or
//!    relay resolution) MAY carry `0x03` when the controller holds the full
//!    key and its y is odd ([`render_did_document_published`]).
//! 3. **Verifiers** — accept both prefixes; the x-coordinate is the
//!    identifier either way ([`parse_multibase_schnorr`]).
//!
//! **Key arithmetic.** Code that tweaks a key works on the full point: with a
//! published document, the point the document carries
//! ([`parse_multibase_sec1`]); with only the identifier, the `0x02` point
//! ([`NostrPubkey::to_even_public_key`]), and a holder whose secret `d` gives
//! an odd-y point uses `n − d` once so that the `0x02` point is exactly theirs.

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

    /// The x-only identifier of a full secp256k1 public key.
    ///
    /// Drops the parity: an odd-y key and its even-y negation share the same
    /// `did:nostr` identifier.
    ///
    /// ```
    /// use k256::SecretKey;
    /// use solid_pod_rs::did_nostr_types::NostrPubkey;
    ///
    /// let sk = SecretKey::from_slice(&[0x11; 32]).unwrap();
    /// let id = NostrPubkey::from_public_key(&sk.public_key());
    /// assert_eq!(id.to_hex().len(), 64);
    /// ```
    pub fn from_public_key(pk: &k256::PublicKey) -> Self {
        let sec1 = compressed_sec1(pk);
        let mut x = [0u8; 32];
        x.copy_from_slice(&sec1[1..]);
        Self(x)
    }

    /// The `0x02` (even-y) point for this identifier — BIP-340 `lift_x`.
    ///
    /// This is the point to tweak when only the identifier is known. A holder
    /// whose secret `d` yields the odd-y point must use `n − d` once so that
    /// this point is exactly theirs (did:nostr parity model, nostrcg/did-nostr
    /// #145).
    ///
    /// # Errors
    ///
    /// [`PodError::BadRequest`] if `x` is not the x-coordinate of a point on
    /// secp256k1 (including `x ≥ p`).
    ///
    /// ```
    /// use solid_pod_rs::did_nostr_types::NostrPubkey;
    ///
    /// let id = NostrPubkey::from_hex(
    ///     "124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2",
    /// ).unwrap();
    /// let point = id.to_even_public_key().unwrap();
    /// assert_eq!(NostrPubkey::from_public_key(&point), id);
    /// assert!(NostrPubkey([0u8; 32]).to_even_public_key().is_err());
    /// ```
    pub fn to_even_public_key(&self) -> Result<k256::PublicKey, PodError> {
        let mut sec1 = [0u8; 33];
        sec1[0] = 0x02;
        sec1[1..].copy_from_slice(&self.0);
        k256::PublicKey::from_sec1_bytes(&sec1).map_err(|_| {
            PodError::BadRequest("did:nostr key: x is not on the secp256k1 curve".into())
        })
    }
}

/// 33-byte SEC1-compressed encoding (`0x02`/`0x03` ‖ X) of a public key.
fn compressed_sec1(pk: &k256::PublicKey) -> [u8; 33] {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let ep = pk.to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(ep.as_bytes());
    out
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
///   "@context": ["https://www.w3.org/ns/did/v1", "https://www.w3.org/ns/cid/v1", "https://w3id.org/nostr/context"],
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
/// even-y point). `0x02` is what a resolver holding only the identifier
/// emits — the BIP-340 `lift_x` default. A controller that holds its full key
/// may publish `0x03` instead when its y is odd: see
/// [`render_did_document_published`] (nostrcg/did-nostr#144/#145). The
/// multibase body round-trips to the same x-only key as the `did:nostr:<hex>`
/// body. Per ADR-074 D1 (I4) the `did:nostr:<hex>` string is unchanged.
pub fn render_did_document(pk: &NostrPubkey) -> Value {
    render_with_multibase(pk, format_multibase_schnorr(&pk.0))
}

/// Render the minimal `did:nostr` document a **controller publishes** from
/// its full public key (HTTP or relay resolution).
///
/// Identical to [`render_did_document`] except that `publicKeyMultibase`
/// carries the key's actual parity: `fe70102…` for even y, `fe70103…` for
/// odd y — for example a key derived by additive tweaking, whose parity is
/// not predictable in advance. The `did:nostr:<hex>` identifier is the x-only
/// key either way. Use [`render_did_document`] when only the identifier is
/// known (minimal / offline resolution always emits `0x02`).
///
/// Per the did:nostr parity model (nostrcg/did-nostr#145, closing #144) a
/// controller-published document MAY carry `0x03`, and every verifier MUST
/// accept both prefixes.
///
/// ```
/// use k256::SecretKey;
/// use solid_pod_rs::did_nostr_types::{
///     parse_multibase_schnorr, render_did_document_published, NostrPubkey,
/// };
///
/// let pk = SecretKey::from_slice(&[0x11; 32]).unwrap().public_key();
/// let doc = render_did_document_published(&pk);
/// let mb = doc["verificationMethod"][0]["publicKeyMultibase"].as_str().unwrap();
/// assert!(mb.starts_with("fe70102") || mb.starts_with("fe70103"));
/// // The identifier is the x-only key whichever prefix was emitted.
/// assert_eq!(parse_multibase_schnorr(mb).unwrap(), NostrPubkey::from_public_key(&pk));
/// ```
pub fn render_did_document_published(pk: &k256::PublicKey) -> Value {
    render_with_multibase(
        &NostrPubkey::from_public_key(pk),
        format_multibase_public_key(pk),
    )
}

/// Shared body of the minimal document; `multibase` is the already-encoded
/// `publicKeyMultibase` for `pk`.
fn render_with_multibase(pk: &NostrPubkey, multibase: String) -> Value {
    let did = did_nostr_uri(pk);
    json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://www.w3.org/ns/cid/v1",
            "https://w3id.org/nostr/context"
        ],
        "id": did,
        "type": "DIDNostr",
        "verificationMethod": [{
            "id": format!("{did}{KEY_FRAGMENT}"),
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": multibase,
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

/// The `publicKeyMultibase` prefix for an even-y key: `f` (base16-lower
/// multibase) ‖ `e701` (`varint(0xe7)` = `secp256k1-pub`) ‖ `02` (SEC1 even-y
/// compressed prefix). The 64-char x-only hex body follows. ADR-125 §2.1 / I2.
///
/// This is the only prefix a resolver holding just the identifier can emit.
pub const MULTIKEY_PREFIX: &str = "fe70102";

/// The `publicKeyMultibase` prefix for an odd-y key (`0x03` parity byte).
///
/// Emitted only by [`format_multibase_public_key`] /
/// [`format_multibase_sec1`] when a controller publishes its own document
/// from a full key whose y is odd; always accepted on decode
/// (nostrcg/did-nostr#145).
pub const MULTIKEY_PREFIX_ODD: &str = "fe70103";

/// Fixed total length of a `publicKeyMultibase` string: the 7-char prefix
/// (`fe70102` or `fe70103`) + 64 hex chars = 71. ADR-125 §2.1.
pub const MULTIKEY_LEN: usize = 71;

/// Build the `publicKeyMultibase` for a did:nostr **identifier** (minimal /
/// offline resolution).
///
/// Layout: `"f"` (base16-lower multibase) ‖ `hex(e701 ‖ 02 ‖ X)`, i.e. the
/// literal `"fe70102"` followed by the 64-char lowercase x-only hex.
///
/// - `e701` = unsigned-varint of multicodec `0xe7` (`secp256k1-pub`).
/// - `02 ‖ X` = the 33-byte SEC1-compressed **even-y** point. With only the
///   32-byte identifier, the even-y lift (BIP-340 `lift_x`) is the point every
///   resolver computes, so this function always emits `0x02`.
///
/// A controller holding its full key uses [`format_multibase_public_key`]
/// instead, which emits `0x03` for an odd-y key.
///
/// Fixed [`MULTIKEY_LEN`] (71) chars, lowercase. Round-trips to the identical
/// key via [`parse_multibase_schnorr`]. No key bytes change (I2).
///
/// ```
/// use solid_pod_rs::did_nostr_types::format_multibase_schnorr;
///
/// let x = hex::decode("124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2")
///     .unwrap();
/// assert_eq!(
///     format_multibase_schnorr(&x.try_into().unwrap()),
///     "fe70102124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2",
/// );
/// ```
pub fn format_multibase_schnorr(pk: &[u8; 32]) -> String {
    // f + e701 + 02 + <x-only-hex-lower>. hex::encode is lowercase.
    format!("{MULTIKEY_PREFIX}{}", hex::encode(pk))
}

/// Build the `publicKeyMultibase` for a controller's **full** public key.
///
/// Emits `fe70102 ‖ X` when y is even and `fe70103 ‖ X` when y is odd — the
/// SEC1-compressed point under the `secp256k1-pub` multicodec. This is the
/// form a document published by the controller (HTTP or relay resolution) MAY
/// carry (nostrcg/did-nostr#145); the identifier is X in both cases.
///
/// ```
/// use k256::SecretKey;
/// use solid_pod_rs::did_nostr_types::{format_multibase_public_key, MULTIKEY_LEN};
///
/// let pk = SecretKey::from_slice(&[0x11; 32]).unwrap().public_key();
/// let mb = format_multibase_public_key(&pk);
/// assert_eq!(mb.len(), MULTIKEY_LEN);
/// let negated = -*pk.as_affine();
/// let other = k256::PublicKey::from_affine(negated).unwrap();
/// // Negation flips the parity byte and keeps X.
/// assert_ne!(mb[..7], format_multibase_public_key(&other)[..7]);
/// assert_eq!(mb[7..], format_multibase_public_key(&other)[7..]);
/// ```
pub fn format_multibase_public_key(pk: &k256::PublicKey) -> String {
    format!("fe701{}", hex::encode(compressed_sec1(pk)))
}

/// Build the `publicKeyMultibase` for a controller's full key given as a
/// 33-byte SEC1-compressed point (`0x02`/`0x03` ‖ X).
///
/// The point is validated with `k256` before encoding; the parity byte is
/// preserved. See [`format_multibase_public_key`].
///
/// # Errors
///
/// [`PodError::BadRequest`] if `compressed` is not exactly 33 bytes, does not
/// start with `0x02`/`0x03`, or is not a point on secp256k1.
///
/// ```
/// use solid_pod_rs::did_nostr_types::format_multibase_sec1;
///
/// let mut sec1 = [0u8; 33];
/// sec1[0] = 0x03;
/// sec1[1..].copy_from_slice(
///     &hex::decode("124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2").unwrap(),
/// );
/// assert_eq!(
///     format_multibase_sec1(&sec1).unwrap(),
///     "fe70103124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2",
/// );
/// assert!(format_multibase_sec1(&sec1[..32]).is_err());
/// ```
pub fn format_multibase_sec1(compressed: &[u8]) -> Result<String, PodError> {
    if compressed.len() != 33 || !matches!(compressed[0], 0x02 | 0x03) {
        return Err(PodError::BadRequest(
            "publicKeyMultibase: expected a 33-byte SEC1-compressed point (02/03 ‖ X)".into(),
        ));
    }
    let pk = k256::PublicKey::from_sec1_bytes(compressed).map_err(|_| {
        PodError::BadRequest("publicKeyMultibase: point is not on the secp256k1 curve".into())
    })?;
    Ok(format_multibase_public_key(&pk))
}

/// Split a `publicKeyMultibase` into its parity byte and x-only key,
/// validating prefix, length and lowercase hex.
fn split_multikey(s: &str) -> Result<(u8, NostrPubkey), PodError> {
    if s.len() != MULTIKEY_LEN {
        return Err(PodError::BadRequest(format!(
            "publicKeyMultibase: expected {MULTIKEY_LEN} chars, got {}",
            s.len()
        )));
    }
    let (parity, body) = if let Some(body) = s.strip_prefix(MULTIKEY_PREFIX) {
        (0x02, body)
    } else if let Some(body) = s.strip_prefix(MULTIKEY_PREFIX_ODD) {
        (0x03, body)
    } else {
        return Err(PodError::BadRequest(format!(
            "publicKeyMultibase: expected `{MULTIKEY_PREFIX}` or `{MULTIKEY_PREFIX_ODD}` prefix (got `{}`)",
            s.get(..7).unwrap_or(s)
        )));
    };
    // Uppercase under the lowercase `f` indicator is malformed.
    if body.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(PodError::BadRequest(
            "publicKeyMultibase: uppercase hex under `f` indicator is malformed".into(),
        ));
    }
    Ok((parity, NostrPubkey::from_hex(body)?))
}

/// Decode a `publicKeyMultibase` string to the x-only did:nostr key.
///
/// Validates, in order: the fixed [`MULTIKEY_LEN`], the `fe70102` or
/// `fe70103` prefix (base16-lower ‖ `varint(secp256k1-pub)` ‖ even-y or odd-y
/// compressed prefix), and lowercase hex. Returns the 32-byte x-only `X`.
///
/// Both prefixes are accepted and decode to the same key: the x-coordinate is
/// the identifier either way, and a BIP-340 signature verifies against the
/// same X whichever prefix the document carries (did:nostr test vectors
/// `decode_even_parity` / `decode_odd_parity`; nostrcg/did-nostr#145).
///
/// Rejects (each an I2 violation): base58btc (`z…`); the missing-parity
/// `fe701<x>` form; uppercase hex under `f`; any non-71 length; retained
/// `publicKeyHex`-style raw hex.
///
/// ```
/// use solid_pod_rs::did_nostr_types::parse_multibase_schnorr;
///
/// let x = "124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2";
/// let even = parse_multibase_schnorr(&format!("fe70102{x}")).unwrap();
/// let odd = parse_multibase_schnorr(&format!("fe70103{x}")).unwrap();
/// assert_eq!(even, odd);
/// assert_eq!(even.to_hex(), x);
/// ```
pub fn parse_multibase_schnorr(s: &str) -> Result<NostrPubkey, PodError> {
    split_multikey(s).map(|(_, pk)| pk)
}

/// Decode a `publicKeyMultibase` string to the **full point** it carries.
///
/// Use this when doing key arithmetic on a published document: the parity
/// model says to tweak the point the document carries, not the even-y lift.
/// For the identifier alone use [`parse_multibase_schnorr`] (and
/// [`NostrPubkey::to_even_public_key`] if a point is needed).
///
/// # Errors
///
/// Every error of [`parse_multibase_schnorr`], plus [`PodError::BadRequest`]
/// if X is not on secp256k1.
///
/// ```
/// use solid_pod_rs::did_nostr_types::{format_multibase_public_key, parse_multibase_sec1};
///
/// let mb = "fe70103124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2";
/// let point = parse_multibase_sec1(mb).unwrap();
/// assert_eq!(format_multibase_public_key(&point), mb);
/// ```
pub fn parse_multibase_sec1(s: &str) -> Result<k256::PublicKey, PodError> {
    let (parity, pk) = split_multikey(s)?;
    let mut sec1 = [0u8; 33];
    sec1[0] = parity;
    sec1[1..].copy_from_slice(&pk.0);
    k256::PublicKey::from_sec1_bytes(&sec1).map_err(|_| {
        PodError::BadRequest("publicKeyMultibase: point is not on the secp256k1 curve".into())
    })
}

// ── Validation helpers ───────────────────────────────────────────────

/// Validate that `s` is a 64-character lowercase hex string (a valid
/// NIP-01 pubkey in hex form).
pub fn is_valid_hex_pubkey(s: &str) -> bool {
    s.len() == 64
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// Check whether `tag_value` binds back to `pubkey` — the bidirectional
/// `did:nostr` ↔ WebID backlink test.
///
/// Accepts exactly two forms and NOTHING ELSE (no bare-substring match):
/// 1. An exact `did:nostr:<pubkey>` URI.
/// 2. A URL whose PATH carries the pubkey as a full segment, optionally
///    with a file extension — e.g.
///    `https://pod.example/.well-known/did/nostr/<pubkey>.json`.
///
/// A value that merely *contains* the hex elsewhere — in a query string
/// (`https://evil.example/?ref=<pubkey>`), a fragment, or a host label
/// (`https://<pubkey>.evil.example/`) — is REJECTED. The previous
/// `tag_value.contains(pubkey)` substring check accepted all of those,
/// letting an attacker forge a backlink by parking the victim's key in a
/// query parameter.
pub fn verify_webid_tag(tag_value: &str, pubkey: &str) -> bool {
    if !is_valid_hex_pubkey(pubkey) {
        return false;
    }
    // 1. Exact `did:nostr:<pubkey>` match.
    if tag_value == format!("did:nostr:{pubkey}") {
        return true;
    }
    // 2. Validated pod-URL-path match (full path segment, not a substring).
    url_path_declares_pubkey(tag_value, pubkey)
}

/// Whether `pubkey` appears as a full PATH SEGMENT of `tag_value`
/// (optionally with a file extension, e.g. `<pubkey>.json`) — never as a
/// bare substring, query-string value, fragment, or host label.
///
/// Isolates the URL path by dropping `scheme://authority` and any
/// `?query` / `#fragment`, then requires an exact segment (or
/// `<pubkey>.<ext>`) match. Pure and I/O-free (wasm-safe).
fn url_path_declares_pubkey(tag_value: &str, pubkey: &str) -> bool {
    let is_delim = |c: char| c == '/' || c == '?' || c == '#';
    // Drop `scheme://authority` so a host-embedded key does not match.
    let after_authority = match tag_value.find("://") {
        Some(i) => {
            let rest = &tag_value[i + 3..];
            match rest.find(is_delim) {
                // The authority ends at the first '/', which begins the path.
                Some(j) if rest.as_bytes()[j] == b'/' => &rest[j..],
                // A '?'/'#' before any '/', or no delimiter, => no path.
                _ => return false,
            }
        }
        // No scheme: treat the whole value as a (relative) path.
        None => tag_value,
    };
    // Drop the query / fragment.
    let path = match after_authority.find(['?', '#']) {
        Some(k) => &after_authority[..k],
        None => after_authority,
    };
    path.split('/').any(|seg| {
        seg == pubkey
            || seg
                .strip_prefix(pubkey)
                .is_some_and(|ext| ext.starts_with('.'))
    })
}

/// Bidirectional-binding verifier: does the fetched WebID profile document
/// declare `pubkey_hex` back?
///
/// A `did:nostr` DID-Document may point at a WebID (`alsoKnownAs`); a
/// trustworthy binding requires the WebID profile to point back at the same
/// Nostr key. This function is the PURE half of that check: the runtime
/// fetches the WebID over the network (I/O stays per-runtime), then hands
/// the raw `profile` bytes here. It extracts the profile's advertised
/// `nostr:pubkey` (via [`crate::webid::extract_nostr_pubkey`]) and confirms
/// it binds to `pubkey_hex` under the tightened [`verify_webid_tag`] rule
/// (exact `did:nostr:` / bare hex / validated pod-URL-path — never a
/// substring). Returns `false` when `pubkey_hex` is not a valid key, the
/// profile is unparseable, advertises no key, or advertises a different
/// key. Pure and I/O-free (wasm-safe).
pub fn webid_declares_pubkey(profile: &[u8], pubkey_hex: &str) -> bool {
    if !is_valid_hex_pubkey(pubkey_hex) {
        return false;
    }
    match crate::webid::extract_nostr_pubkey(profile) {
        Ok(Some(declared)) => verify_webid_tag(&declared, pubkey_hex),
        _ => false,
    }
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
        // Canonical did:nostr CG 0.1.1 three-context form (ADR-125 §2):
        // DID Core first (required by DID Core), then CID v1.0, then nostr.
        assert_eq!(doc["@context"][0], "https://www.w3.org/ns/did/v1");
        assert_eq!(doc["@context"][1], "https://www.w3.org/ns/cid/v1");
        assert_eq!(doc["@context"][2], "https://w3id.org/nostr/context");
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
        assert!(
            vm.get("publicKeyHex").is_none(),
            "publicKeyHex must be dropped (I2)"
        );
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
        let follows = vec![format!("did:nostr:{}", "ab".repeat(32))];
        let doc = render_did_document_complete(
            &pk,
            &also,
            &[relay],
            Some(&profile),
            &follows,
            Some("2025-01-26T15:50:00Z"),
        );
        // Canonical core unchanged (spec-aligned).
        assert_eq!(doc["type"], "DIDNostr");
        assert_eq!(doc["@context"][0], "https://www.w3.org/ns/did/v1");
        assert_eq!(doc["@context"][1], "https://www.w3.org/ns/cid/v1");
        assert_eq!(doc["verificationMethod"][0]["type"], "Multikey");
        assert_eq!(doc["authentication"][0], "#key1");
        // Top-level alsoKnownAs (spec canonical, multi-URI).
        assert_eq!(doc["alsoKnownAs"][1], "at://alice.bsky.social");
        // Relay service with trailing-slash endpoint.
        assert_eq!(doc["service"][0]["type"], "Relay");
        assert_eq!(
            doc["service"][0]["serviceEndpoint"],
            "wss://relay.damus.io/"
        );
        // Complete-form members.
        assert_eq!(doc["profile"]["name"], "Alice");
        assert_eq!(doc["profile"]["created_at"], 1737906600);
        assert!(doc["follows"][0]
            .as_str()
            .unwrap()
            .starts_with("did:nostr:"));
        assert_eq!(doc["modified"], "2025-01-26T15:50:00Z");
    }

    #[test]
    fn multibase_schnorr_is_canonical_form() {
        let pk = NostrPubkey::from_hex(PK_HEX).unwrap();
        let a = format_multibase_schnorr(&pk.0);
        let b = format_multibase_schnorr(&pk.0);
        assert_eq!(a, b, "deterministic");
        // C2: `f` + base16, NOT `z` + base58.
        assert!(
            a.starts_with("fe70102"),
            "must be fe70102 prefix, not z-base58"
        );
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
        assert!(
            parse_multibase_schnorr("zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme").is_err()
        );
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

    #[test]
    fn verify_webid_tag_rejects_pubkey_in_query_string() {
        // The pubkey parked in a query parameter must NOT be accepted as a
        // backlink — the exact forgery the old substring `contains` allowed.
        let evil = format!("https://evil.example/?ref={PK_HEX}");
        assert!(!verify_webid_tag(&evil, PK_HEX));
    }

    #[test]
    fn verify_webid_tag_rejects_pubkey_in_host_or_fragment() {
        assert!(!verify_webid_tag(
            &format!("https://{PK_HEX}.evil.example/"),
            PK_HEX
        ));
        assert!(!verify_webid_tag(
            &format!("https://evil.example/x#{PK_HEX}"),
            PK_HEX
        ));
        // A longer segment that merely starts with the key (no '.' boundary).
        assert!(!verify_webid_tag(
            &format!("https://pod.example/{PK_HEX}deadbeef"),
            PK_HEX
        ));
    }

    #[test]
    fn verify_webid_tag_accepts_bare_hex_segment() {
        // A bare-hex path segment (no extension) still binds.
        assert!(verify_webid_tag(
            &format!("https://pod.example/keys/{PK_HEX}"),
            PK_HEX
        ));
    }

    #[test]
    fn webid_declares_pubkey_matches_profile_triple() {
        let profile = format!(
            r#"<html><head><script type="application/ld+json">
            {{ "nostr:pubkey": "{PK_HEX}" }}
            </script></head></html>"#
        );
        assert!(webid_declares_pubkey(profile.as_bytes(), PK_HEX));
    }

    #[test]
    fn webid_declares_pubkey_matches_did_uri_triple() {
        let profile = format!(
            r#"<html><head><script type="application/ld+json">
            {{ "nostr:pubkey": "did:nostr:{PK_HEX}" }}
            </script></head></html>"#
        );
        assert!(webid_declares_pubkey(profile.as_bytes(), PK_HEX));
    }

    #[test]
    fn webid_declares_pubkey_rejects_absent_or_mismatched() {
        // No nostr:pubkey triple.
        let none = br#"<html><head><script type="application/ld+json">
            { "name": "Alice" }
            </script></head></html>"#;
        assert!(!webid_declares_pubkey(none, PK_HEX));
        // A different key declared.
        let other = "1111111111111111111111111111111111111111111111111111111111111111";
        let profile = format!(
            r#"<html><head><script type="application/ld+json">
            {{ "nostr:pubkey": "{other}" }}
            </script></head></html>"#
        );
        assert!(!webid_declares_pubkey(profile.as_bytes(), PK_HEX));
        // Invalid expected key.
        assert!(!webid_declares_pubkey(profile.as_bytes(), "abc"));
    }
}
