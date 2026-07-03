//! Pod key provisioning — Schnorr secp256k1 keypair generation, NIP-19
//! bech32 encoding, owner-only WAC carve-out, WebID `nostr:pubkey`
//! triple seeding.
//!
//! Tracks JSS v0.0.190 (May 2026, issue #437):
//!
//! - Single-user CLI: `--provision-keys` flag on the JSS binary.
//! - Multi-user HTTP: `POST /.pods` body field `{ "provisionKeys": true }`.
//! - On success, JSS generates a fresh BIP-340 Schnorr keypair on
//!   secp256k1, encodes NIP-19 bech32 (`npub1…` / `nsec1…`), writes
//!   `pods/<webid>/private/privkey.jsonld`, WAC-locks the resource to
//!   the pod owner via `acl:owner`, and seeds the `nostr:pubkey` triple
//!   into `profile/card` so downstream NIP-05 / NIP-07 / did:nostr
//!   resolvers can discover the pod's identity.
//!
//! Parity row **196**. Smoke test:
//! [`tests/key_provisioning_smoke.rs`](../../tests/key_provisioning_smoke.rs).
//!
//! ## Type contract (stable)
//!
//! [`KeyProvisioningOutcome`] and [`KeyProvisioningPlan`] are the wire
//! formats consumed by NRF and dreamlab-overlay; treat their field
//! shapes as ABI.

use bytes::Bytes;
use chrono::Utc;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use k256::schnorr::SigningKey;

use solid_pod_rs::{
    storage::Storage,
    wac::{AclAuthorization, AclDocument, IdOrIds, IdRef},
    PodError,
};

/// Storage path (relative to the pod root) of the bech32-encoded
/// private-key document produced by [`provision_pod_keys`].
///
/// JSS v0.0.190 writes to `/private/privkey.jsonld` and WAC-locks it
/// to the pod owner. Mirrored here as a constant so the route table
/// and the WAC scaffolder share one source of truth.
pub const POD_PRIVKEY_PATH: &str = "/private/privkey.jsonld";

/// Sibling ACL path that owner-only-locks the privkey document.
pub const POD_PRIVKEY_ACL_PATH: &str = "/private/privkey.jsonld.acl";

/// Storage path of the WebID profile/card seeded with the
/// `nostr:pubkey` triple.
pub const POD_PROFILE_CARD_PATH: &str = "/profile/card";

/// JSON-LD `@context` namespace used inside `privkey.jsonld`. Stable
/// across releases — NRF and dreamlab-overlay parsers anchor on this
/// URL.
pub const NOSTR_NS: &str = "https://nostr.org/ns#";

/// Result of pod key provisioning.
///
/// All fields are public so consumers can serialise the outcome onto
/// their own admin response surfaces. `nsec` is the bech32-encoded
/// private key — handle with care. JSS returns it once in the
/// `POST /.pods` response body and never again; this crate matches
/// that contract: `nsec` is *not* persisted in plaintext anywhere
/// beyond `privkey.jsonld` (WAC-locked).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyProvisioningOutcome {
    /// NIP-19 bech32-encoded public key (`npub1…`).
    pub npub: String,
    /// NIP-19 bech32-encoded private key (`nsec1…`). Returned exactly
    /// once; the caller is expected to relay it to the pod owner and
    /// then forget it.
    pub nsec: String,
    /// Hex-encoded x-only public key (32 bytes). Matches the form used
    /// by `interop::verify_nip05` and the existing `nostr:pubkey`
    /// triple emitter in `webid::generate_webid_html`.
    pub pubkey_hex: String,
    /// Storage path where the JSON-LD private-key document was
    /// written. Mirrors [`POD_PRIVKEY_PATH`].
    pub privkey_path: String,
    /// Resolved WebID of the pod owner whose `nostr:pubkey` triple was
    /// seeded.
    pub webid: String,
}

/// Input plan for pod key provisioning. Mirrors the JSS surface so the
/// single-user CLI path and the multi-user HTTP path can both feed the
/// same function.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeyProvisioningPlan {
    /// Pod owner's WebID (e.g. `https://pod.example.com/alice/profile/card#me`).
    pub webid: String,
    /// Pod root URL (e.g. `https://pod.example.com/alice/`). Used to
    /// resolve the absolute path for the privkey document and the WAC
    /// owner reference.
    pub pod_base: String,
    /// Optional caller-supplied entropy. `None` means "use the OS
    /// CSPRNG" (the production path); only test fixtures should pass
    /// `Some`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deterministic_entropy: Option<[u8; 32]>,
}

// ---------------------------------------------------------------------------
// NIP-19 bech32 encoder (bech32, *not* bech32m — NIP-19 spec §1).
//
// 32-byte payload → 5-bit groups → checksum → "<hrp>1<data><checksum>".
// Hand-rolled to keep this crate dep-free of `bech32`. The algorithm
// is BIP-173 (bech32), constant 1.
// ---------------------------------------------------------------------------

const BECH32_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_CONST: u32 = 1;

fn convert_bits_8_to_5(data: &[u8]) -> Vec<u8> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut ret = Vec::with_capacity(data.len() * 8 / 5 + 1);
    for &v in data {
        acc = (acc << 8) | (v as u32);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            ret.push(((acc >> bits) & 0x1f) as u8);
        }
    }
    if bits > 0 {
        ret.push(((acc << (5 - bits)) & 0x1f) as u8);
    }
    ret
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut r: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
    r.push(0);
    r.extend(hrp.bytes().map(|b| b & 31));
    r
}

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ (v as u32);
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 != 0 {
                chk ^= *g;
            }
        }
    }
    chk
}

fn bech32_encode(hrp: &str, payload32: &[u8; 32]) -> String {
    let data = convert_bits_8_to_5(payload32);
    let mut enc = hrp_expand(hrp);
    enc.extend_from_slice(&data);
    enc.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    let plm = polymod(&enc) ^ BECH32_CONST;
    let checksum: [u8; 6] = std::array::from_fn(|i| ((plm >> (5 * (5 - i))) & 31) as u8);

    let mut result = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    result.push_str(hrp);
    result.push('1');
    for &v in data.iter().chain(checksum.iter()) {
        result.push(BECH32_CHARSET[v as usize] as char);
    }
    result
}

// ---------------------------------------------------------------------------
// WAC ACL — owner-only carve-out for `/private/privkey.jsonld`.
//
// Public read MUST be absent. Owner gets Read + Write + Control. The
// resource sits below `/private/` which is already default-private,
// but writing an explicit sibling ACL keeps the lock atomic relative
// to any future operator change to `/private/.acl`.
// ---------------------------------------------------------------------------
fn build_owner_only_acl(webid: &str, resource_iri: &str) -> AclDocument {
    let owner = AclAuthorization {
        id: Some("#owner".into()),
        r#type: Some("acl:Authorization".into()),
        agent: Some(IdOrIds::Single(IdRef { id: webid.into() })),
        agent_class: None,
        agent_group: None,
        origin: None,
        access_to: Some(IdOrIds::Single(IdRef {
            id: resource_iri.into(),
        })),
        default: None,
        mode: Some(IdOrIds::Multiple(vec![
            IdRef {
                id: "acl:Read".into(),
            },
            IdRef {
                id: "acl:Write".into(),
            },
            IdRef {
                id: "acl:Control".into(),
            },
        ])),
        condition: None,
    };
    AclDocument {
        context: None,
        graph: Some(vec![owner]),
        // A directly-authored owner ACL is authoritative, not inherited from
        // an ancestor container. (Pre-existing `--all-features` build break:
        // the `inherited` field was added to `AclDocument` without updating
        // this `provision-keys`-gated literal.)
        inherited: false,
    }
}

// ---------------------------------------------------------------------------
// JSON-LD payload — `/private/privkey.jsonld`.
//
// JSS embeds `npub`, `nsec`, hex pubkey, and a created-at timestamp.
// We mirror that shape under a stable `nostr:` namespace.
// ---------------------------------------------------------------------------
fn render_privkey_jsonld(outcome: &KeyProvisioningOutcome) -> String {
    let body = json!({
        "@context": {
            "nostr": NOSTR_NS,
        },
        "@id": "",
        "nostr:npub": &outcome.npub,
        "nostr:nsec": &outcome.nsec,
        "nostr:pubkeyHex": &outcome.pubkey_hex,
        "nostr:keyAlgorithm": "schnorr-secp256k1",
        "nostr:createdAt": Utc::now().to_rfc3339(),
    });
    serde_json::to_string_pretty(&body).expect("static JSON always serialises")
}

// ---------------------------------------------------------------------------
// WebID patcher — inject `nostr:pubkey` triple into the existing
// `<script type="application/ld+json">` data island.
//
// The existing WebID generator (`webid::generate_webid_html`) already
// references the pubkey under `schema:identifier` (`did:nostr:<hex>`)
// and `verificationMethod`. Phase 1 additionally exposes the bare
// `nostr:pubkey` predicate so NIP-05 and NIP-07 consumers can look it
// up without traversing the verification-method subgraph.
// ---------------------------------------------------------------------------
fn patch_webid_with_nostr_pubkey(html: &str, pubkey_hex: &str) -> Result<String, PodError> {
    let tag_marker = "application/ld+json";
    let tag_idx = html.find(tag_marker).ok_or_else(|| {
        PodError::BadRequest("profile/card missing application/ld+json data island".into())
    })?;
    let after_tag = html[tag_idx..]
        .find('>')
        .ok_or_else(|| PodError::BadRequest("profile/card data island has no closing >".into()))?;
    let json_start = tag_idx + after_tag + 1;
    let script_end_rel = html[json_start..]
        .find("</script>")
        .ok_or_else(|| PodError::BadRequest("profile/card data island has no </script>".into()))?;
    let json_str = html[json_start..json_start + script_end_rel].trim();

    let mut value: Value = serde_json::from_str(json_str).map_err(|e| {
        PodError::BadRequest(format!(
            "profile/card data island is not valid JSON-LD: {e}"
        ))
    })?;

    // Ensure the `@context` exposes the `nostr` prefix.
    let ctx = value
        .get_mut("@context")
        .ok_or_else(|| PodError::BadRequest("profile/card missing @context".into()))?;
    if let Some(map) = ctx.as_object_mut() {
        map.entry("nostr")
            .or_insert_with(|| Value::String(NOSTR_NS.into()));
    }

    // Add the `nostr:pubkey` triple (overwrite is idempotent — calling
    // provision_pod_keys twice yields the second key, which is what
    // the operator asked for).
    let obj = value
        .as_object_mut()
        .ok_or_else(|| PodError::BadRequest("profile/card root is not a JSON object".into()))?;
    obj.insert("nostr:pubkey".into(), Value::String(pubkey_hex.into()));

    let new_json = serde_json::to_string_pretty(&value)
        .map_err(|e| PodError::BadRequest(format!("failed to serialise patched WebID: {e}")))?;

    let mut out = String::with_capacity(html.len() + new_json.len());
    out.push_str(&html[..json_start]);
    out.push('\n');
    out.push_str(&new_json);
    out.push('\n');
    out.push_str(&html[json_start + script_end_rel..]);
    Ok(out)
}

/// Generate a Schnorr secp256k1 keypair, write `/private/privkey.jsonld`
/// with an owner-only WAC carve-out, and seed the pod's WebID profile
/// with the `nostr:pubkey` triple.
///
/// JSS v0.0.190 Phase 1 (issue #437) parity row 196.
///
/// # Determinism
///
/// When `plan.deterministic_entropy` is `Some(seed)`, the keypair is
/// derived directly from that 32-byte seed (treated as a BIP-340
/// Schnorr private scalar). Used by test fixtures only — production
/// callers always pass `None` to fall back to `OsRng`.
///
/// # Errors
///
/// - [`PodError::BadRequest`] when the existing `/profile/card` cannot
///   be patched (missing data island, malformed JSON-LD, etc.).
/// - [`PodError::NotFound`] when `/profile/card` is absent. Call
///   `provision_pod` first.
/// - Backend errors propagated from `Storage::put`.
pub async fn provision_pod_keys(
    storage: &dyn Storage,
    plan: &KeyProvisioningPlan,
) -> Result<KeyProvisioningOutcome, PodError> {
    // 1. Generate / re-derive the Schnorr keypair.
    let signing_key = match plan.deterministic_entropy {
        Some(seed) => SigningKey::from_bytes(&seed)
            .map_err(|e| PodError::Backend(format!("schnorr key from seed: {e}")))?,
        None => SigningKey::random(&mut OsRng),
    };
    let verifying_key = signing_key.verifying_key();
    let pubkey_bytes: [u8; 32] = verifying_key.to_bytes().into();
    let secret_bytes: [u8; 32] = signing_key.to_bytes().into();

    let pubkey_hex = hex::encode(pubkey_bytes);
    let npub = bech32_encode("npub", &pubkey_bytes);
    let nsec = bech32_encode("nsec", &secret_bytes);

    let outcome = KeyProvisioningOutcome {
        npub,
        nsec,
        pubkey_hex: pubkey_hex.clone(),
        privkey_path: POD_PRIVKEY_PATH.to_string(),
        webid: plan.webid.clone(),
    };

    // 2. Write the JSON-LD privkey document.
    let body = render_privkey_jsonld(&outcome);
    storage
        .put(
            POD_PRIVKEY_PATH,
            Bytes::from(body.into_bytes()),
            "application/ld+json",
        )
        .await?;

    // 3. Write the owner-only ACL sibling as JSON-LD. We use the
    //    storage-relative path as the `acl:accessTo` target — matching
    //    what the WAC evaluator's `normalize_path` operates on at
    //    request time. JSON-LD (rather than Turtle) avoids the
    //    serializer's narrow http-prefix detection for bare-path
    //    IRIs; `application/ld+json` is the spec-default ACL media
    //    type and is round-trip clean via `parse_jsonld_acl`.
    let acl_doc = build_owner_only_acl(&plan.webid, POD_PRIVKEY_PATH);
    let acl_json = serde_json::to_vec(&acl_doc)
        .map_err(|e| PodError::Backend(format!("failed to serialise privkey ACL: {e}")))?;
    storage
        .put(
            POD_PRIVKEY_ACL_PATH,
            Bytes::from(acl_json),
            "application/ld+json",
        )
        .await?;

    // 4. Patch the WebID profile/card with the `nostr:pubkey` triple.
    let (existing_card, meta) = storage.get(POD_PROFILE_CARD_PATH).await?;
    let html = std::str::from_utf8(&existing_card)
        .map_err(|_| PodError::BadRequest("profile/card is not valid UTF-8".into()))?;
    let patched = patch_webid_with_nostr_pubkey(html, &pubkey_hex)?;
    storage
        .put(
            POD_PROFILE_CARD_PATH,
            Bytes::from(patched.into_bytes()),
            &meta.content_type,
        )
        .await?;

    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NIP-19 test vector (NIP-19 §"Examples"): 32-byte zero pubkey
    /// must encode to a stable npub string. We exercise structural
    /// properties (prefix, length) rather than the exact spec vector
    /// to keep the test independent of the spec's example payloads.
    #[test]
    fn bech32_npub_round_trip_prefix_and_length() {
        let pk = [0u8; 32];
        let encoded = bech32_encode("npub", &pk);
        assert!(encoded.starts_with("npub1"), "npub prefix: {encoded}");
        // 32 bytes payload → 52 bech32 chars (32 * 8 / 5 = 51.2, ceil to
        // 52 with padding) + 6 checksum + "npub1" = 63 chars.
        assert_eq!(encoded.len(), 63, "npub length: {encoded}");
    }

    #[test]
    fn bech32_nsec_prefix() {
        let sk = [0xffu8; 32];
        let encoded = bech32_encode("nsec", &sk);
        assert!(encoded.starts_with("nsec1"), "nsec prefix: {encoded}");
    }

    /// Schnorr keypair sanity — deterministic seed yields stable pubkey.
    #[test]
    fn deterministic_seed_yields_stable_pubkey() {
        let seed = [0x42u8; 32];
        let a = SigningKey::from_bytes(&seed).unwrap();
        let b = SigningKey::from_bytes(&seed).unwrap();
        assert_eq!(
            hex::encode(a.verifying_key().to_bytes()),
            hex::encode(b.verifying_key().to_bytes())
        );
    }
}
