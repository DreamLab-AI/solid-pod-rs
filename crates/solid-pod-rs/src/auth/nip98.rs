//! NIP-98 HTTP authentication: structural + cryptographic verification.
//!
//! Reference: <https://github.com/nostr-protocol/nips/blob/master/98.md>
//!
//! Wire format: `Authorization: Nostr <base64(json(event))>` where
//! the event is a kind-27235 Nostr event with tags `u` (URL),
//! `method`, and optional `payload` (SHA-256 of request body).
//!
//! Every `verify_*` entry point performs the structural checks (kind,
//! pubkey shape, timestamp tolerance, URL/method/payload binding) **and**
//! BIP-340 Schnorr signature verification. Signature verification is not
//! optional: with the `nip98-schnorr` feature it runs for real; **without
//! it the verifier fails CLOSED** (returns [`PodError::Unsupported`]) so a
//! mis-configured build denies authentication rather than accepting any
//! forged pubkey. See [`assert_schnorr_verification_enabled`] for the
//! compile-time guard binaries use to refuse a fail-open build outright.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::PodError;

const HTTP_AUTH_KIND: u64 = 27235;
const TIMESTAMP_TOLERANCE: u64 = 60;
const MAX_EVENT_SIZE: usize = 64 * 1024;
const NOSTR_PREFIX: &str = "Nostr ";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Nip98Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

#[derive(Debug, Clone)]
pub struct Nip98Verified {
    pub pubkey: String,
    pub url: String,
    pub method: String,
    pub payload_hash: Option<String>,
    pub created_at: u64,
    /// Canonical NIP-01 event id (lowercase hex sha256 over the
    /// `[0, pubkey, created_at, kind, tags, content]` serialisation).
    ///
    /// Uniquely identifies this signed request and is the single-use
    /// dedup key a replay guard keys on — two distinct requests (differing
    /// URL, method, body, or `created_at`) always hash to different ids,
    /// while a re-presented token hashes identically. See
    /// [`crate::auth::replay::Nip98ReplayCache`].
    pub event_id: String,
}

/// Verify a NIP-98 `Authorization` header against expected URL,
/// method, and optional body.
///
/// Returns the signer pubkey on success.
pub async fn verify(
    header: &str,
    url: &str,
    method: &str,
    body_hash: Option<&[u8]>,
) -> Result<String, PodError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    verify_at(header, url, method, body_hash, now).map(|v| v.pubkey)
}

/// URL/method matching leniency for NIP-98 verification.
///
/// `Strict` (the default for every HTTP endpoint) demands an exact URL
/// and method match. `GitLenient` mirrors JSS git: a single static
/// `http.extraHeader` token has to cover the multi-request git smart
/// protocol (`GET …/info/refs` then `POST …/git-receive-pack`), so the
/// client signs method `*` and the repo base URL — the verifier accepts
/// a `*` method against any request and treats the token URL as a prefix
/// of the request URL. The signing pubkey is still cryptographically
/// verified; only the request-binding is relaxed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchPolicy {
    /// Exact URL + method binding. Default for all REST/MCP endpoints.
    Strict,
    /// `*`-method wildcard + URL-prefix binding for the git push path.
    GitLenient,
}

/// `verify` with an explicit timestamp (for deterministic testing).
pub fn verify_at(
    header: &str,
    expected_url: &str,
    expected_method: &str,
    body: Option<&[u8]>,
    now: u64,
) -> Result<Nip98Verified, PodError> {
    verify_at_with_policy(
        header,
        expected_url,
        expected_method,
        body,
        now,
        MatchPolicy::Strict,
    )
}

/// `verify_at` with an explicit [`MatchPolicy`]. The git push bridge
/// passes [`MatchPolicy::GitLenient`]; everything else uses `verify_at`.
pub fn verify_at_with_policy(
    header: &str,
    expected_url: &str,
    expected_method: &str,
    body: Option<&[u8]>,
    now: u64,
    policy: MatchPolicy,
) -> Result<Nip98Verified, PodError> {
    let token = header
        .strip_prefix(NOSTR_PREFIX)
        .ok_or_else(|| PodError::Nip98("missing 'Nostr ' prefix".into()))?
        .trim();

    if token.len() > MAX_EVENT_SIZE {
        return Err(PodError::Nip98("token too large".into()));
    }
    let json_bytes = BASE64.decode(token)?;
    if json_bytes.len() > MAX_EVENT_SIZE {
        return Err(PodError::Nip98("decoded token too large".into()));
    }
    let event: Nip98Event = serde_json::from_slice(&json_bytes)?;

    if event.kind != HTTP_AUTH_KIND {
        return Err(PodError::Nip98(format!(
            "wrong kind: expected {HTTP_AUTH_KIND}, got {}",
            event.kind
        )));
    }
    if event.pubkey.len() != 64 || hex::decode(&event.pubkey).is_err() {
        return Err(PodError::Nip98("invalid pubkey".into()));
    }
    if now.abs_diff(event.created_at) > TIMESTAMP_TOLERANCE {
        return Err(PodError::Nip98(format!(
            "timestamp outside tolerance: event={}, now={now}",
            event.created_at
        )));
    }

    let token_url =
        get_tag(&event, "u").ok_or_else(|| PodError::Nip98("missing 'u' tag".into()))?;
    let url_ok = {
        let t = normalize_url(&token_url);
        let e = normalize_url(expected_url);
        match policy {
            MatchPolicy::Strict => t == e,
            // Token URL is the repo base; accept it as a prefix of the
            // request URL so one token covers every git smart-protocol
            // sub-path under that repo.
            MatchPolicy::GitLenient => t == e || e.starts_with(t),
        }
    };
    if !url_ok {
        return Err(PodError::Nip98(format!(
            "URL mismatch: token={token_url}, expected={expected_url}"
        )));
    }

    let token_method =
        get_tag(&event, "method").ok_or_else(|| PodError::Nip98("missing 'method' tag".into()))?;
    let method_ok = match policy {
        MatchPolicy::GitLenient if token_method == "*" => true,
        _ => token_method.to_uppercase() == expected_method.to_uppercase(),
    };
    if !method_ok {
        return Err(PodError::Nip98(format!(
            "method mismatch: token={token_method}, expected={expected_method}"
        )));
    }

    let payload_tag = get_tag(&event, "payload");
    let verified_payload_hash = match body {
        Some(b) if !b.is_empty() => {
            let expected = payload_tag
                .as_ref()
                .ok_or_else(|| PodError::Nip98("body provided but no payload tag".into()))?;
            let actual = hex::encode(Sha256::digest(b));
            if expected.to_lowercase() != actual.to_lowercase() {
                return Err(PodError::Nip98("payload hash mismatch".into()));
            }
            Some(expected.clone())
        }
        _ => payload_tag,
    };

    // SECURITY (F3): BIP-340 Schnorr signature verification is
    // UNCONDITIONAL. With the `nip98-schnorr` feature this checks the
    // signature for real; without it `verify_schnorr_signature` is the
    // fail-CLOSED stub that returns `PodError::Unsupported`, so a build
    // that dropped the feature denies authentication instead of accepting
    // a forged pubkey after structural checks alone. `verify_schnorr_...`
    // also recomputes and binds the canonical event id, so on success the
    // id below is signature-bound.
    verify_schnorr_signature(&event)?;

    // Canonical NIP-01 id — the single-use replay dedup key. Recomputed
    // from the event content (not trusted from `event.id`), though under
    // `nip98-schnorr` `verify_schnorr_signature` already proved they match.
    let event_id = compute_event_id(&event);

    Ok(Nip98Verified {
        pubkey: event.pubkey,
        url: token_url,
        method: token_method,
        payload_hash: verified_payload_hash,
        created_at: event.created_at,
        event_id,
    })
}

/// Compile-time proof that BIP-340 Schnorr signature verification is
/// compiled into this build of the NIP-98 verifier.
///
/// This item exists **only** under the `nip98-schnorr` feature. A binary
/// that authenticates real NIP-98 requests references it in a
/// `const _: () = solid_pod_rs::auth::nip98::assert_schnorr_verification_enabled();`
/// context so that a resolver change, a dropped dependency, or an
/// accidental feature-unification regression which removed signature
/// verification becomes a **compile error** rather than a silently
/// fail-open (structural-only) auth path. See F3 in the closeout design.
#[cfg(feature = "nip98-schnorr")]
pub const fn assert_schnorr_verification_enabled() {}

/// Canonical serialisation of a Nostr event per NIP-01 §"Serialization".
/// Returns `sha256(json([0, pubkey, created_at, kind, tags, content]))`
/// as lowercase hex.
pub fn compute_event_id(event: &Nip98Event) -> String {
    let canonical = serde_json::json!([
        0,
        event.pubkey,
        event.created_at,
        event.kind,
        event.tags,
        event.content,
    ]);
    let serialized = serde_json::to_string(&canonical).unwrap_or_default();
    hex::encode(Sha256::digest(serialized.as_bytes()))
}

/// Mint a NIP-98 `Authorization` header value for a request.
///
/// Constructs a kind-27235 event with `u` (url) and `method` tags,
/// computes the canonical NIP-01 id, signs the 32 id bytes with a
/// deterministic BIP-340 Schnorr signature (zero aux-rand, matching the
/// `verify_raw` path), and returns `base64(json(event))` — ready to wrap
/// with [`authorization_header`]. Mirrors JSS `nip98Token`.
///
/// `privkey_hex` is the 32-byte secret key as 64 hex chars.
#[cfg(feature = "nip98-schnorr")]
pub fn mint(
    url: &str,
    method: &str,
    privkey_hex: &str,
    now: u64,
) -> Result<String, PodError> {
    mint_with_payload(url, method, None, privkey_hex, now)
}

/// [`mint`] with an optional request body whose SHA-256 is recorded in a
/// `payload` tag (NIP-98 body binding).
#[cfg(feature = "nip98-schnorr")]
pub fn mint_with_payload(
    url: &str,
    method: &str,
    body: Option<&[u8]>,
    privkey_hex: &str,
    now: u64,
) -> Result<String, PodError> {
    use k256::schnorr::SigningKey;

    let sk_bytes = hex::decode(privkey_hex)
        .map_err(|e| PodError::Nip98(format!("privkey hex decode: {e}")))?;
    if sk_bytes.len() != 32 {
        return Err(PodError::Nip98(format!(
            "privkey wrong length: {} (want 32 bytes / 64 hex)",
            sk_bytes.len()
        )));
    }
    let sk = SigningKey::from_bytes(&sk_bytes)
        .map_err(|e| PodError::Nip98(format!("privkey parse: {e}")))?;
    let pubkey_hex = hex::encode(sk.verifying_key().to_bytes());

    let mut tags = vec![
        vec!["u".to_string(), url.to_string()],
        vec!["method".to_string(), method.to_uppercase()],
    ];
    if let Some(b) = body {
        if !b.is_empty() {
            tags.push(vec!["payload".to_string(), hex::encode(Sha256::digest(b))]);
        }
    }

    let mut event = Nip98Event {
        id: String::new(),
        pubkey: pubkey_hex,
        created_at: now,
        kind: HTTP_AUTH_KIND,
        tags,
        content: String::new(),
        sig: String::new(),
    };
    event.id = compute_event_id(&event);

    let id_bytes =
        hex::decode(&event.id).map_err(|e| PodError::Nip98(format!("id hex decode: {e}")))?;
    // Deterministic signature (zero aux-rand) over the 32 id bytes —
    // exactly the message `verify_raw` checks.
    let sig: k256::schnorr::Signature = sk
        .sign_raw(&id_bytes, &[0u8; 32])
        .map_err(|e| PodError::Nip98(format!("schnorr sign: {e}")))?;
    event.sig = hex::encode(sig.to_bytes());

    let json = serde_json::to_string(&event)
        .map_err(|e| PodError::Nip98(format!("event serialize: {e}")))?;
    Ok(BASE64.encode(json.as_bytes()))
}

/// No-op stub when `nip98-schnorr` is disabled — minting needs the signer.
#[cfg(not(feature = "nip98-schnorr"))]
pub fn mint(
    _url: &str,
    _method: &str,
    _privkey_hex: &str,
    _now: u64,
) -> Result<String, PodError> {
    Err(PodError::Unsupported(
        "nip98-schnorr feature not enabled (required to mint tokens)".into(),
    ))
}

/// Schnorr signature verification (feature-gated).
///
/// This validates:
/// 1. `event.id` matches the canonical NIP-01 hash.
/// 2. `event.sig` is a valid BIP-340 Schnorr signature by `event.pubkey`
///    over the event id bytes.
#[cfg(feature = "nip98-schnorr")]
pub fn verify_schnorr_signature(event: &Nip98Event) -> Result<(), PodError> {
    use k256::schnorr::{Signature, VerifyingKey};

    let computed_id = compute_event_id(event);
    if computed_id.to_lowercase() != event.id.to_lowercase() {
        return Err(PodError::Nip98(format!(
            "event id mismatch: computed={computed_id}, claimed={}",
            event.id
        )));
    }
    let pub_bytes = hex::decode(&event.pubkey)
        .map_err(|e| PodError::Nip98(format!("pubkey hex decode: {e}")))?;
    let sig_bytes =
        hex::decode(&event.sig).map_err(|e| PodError::Nip98(format!("sig hex decode: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(PodError::Nip98(format!(
            "sig wrong length: {}",
            sig_bytes.len()
        )));
    }
    let id_bytes =
        hex::decode(&computed_id).map_err(|e| PodError::Nip98(format!("id hex decode: {e}")))?;

    let vk = VerifyingKey::from_bytes(&pub_bytes)
        .map_err(|e| PodError::Nip98(format!("pubkey parse: {e}")))?;
    let sig = Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| PodError::Nip98(format!("sig parse: {e}")))?;
    vk.verify_raw(&id_bytes, &sig)
        .map_err(|e| PodError::Nip98(format!("schnorr verify: {e}")))?;
    Ok(())
}

/// No-op stub when the `nip98-schnorr` feature is not enabled.
#[cfg(not(feature = "nip98-schnorr"))]
pub fn verify_schnorr_signature(_event: &Nip98Event) -> Result<(), PodError> {
    Err(PodError::Unsupported(
        "nip98-schnorr feature not enabled".into(),
    ))
}

fn get_tag(event: &Nip98Event, name: &str) -> Option<String> {
    event
        .tags
        .iter()
        .find(|t| t.first().map(|s| s.as_str()) == Some(name))
        .and_then(|t| t.get(1).cloned())
}

fn normalize_url(u: &str) -> &str {
    u.trim_end_matches('/')
}

pub fn authorization_header(token_b64: &str) -> String {
    format!("{NOSTR_PREFIX}{token_b64}")
}

// ---------------------------------------------------------------------------
// Sprint 11 row 152: SelfSignedVerifier adapter.
//
// Wraps `verify_at` in the CID verifier contract so NIP-98 is one of
// the proof formats a `CidVerifier` can dispatch. The wire format is
// the `Nostr <base64>` header exactly as produced by clients today —
// the adapter strips the `Nostr ` prefix if the caller supplied the
// raw header, or accepts the bare token otherwise.
// ---------------------------------------------------------------------------

use crate::auth::self_signed::{
    ProofEnvelope, SelfSignedError, SelfSignedVerifier, VerifiedSubject,
};

/// [`SelfSignedVerifier`] adapter for NIP-98.
///
/// When the `lws-cid` feature is enabled, attempts WebID elevation:
/// if the Nostr signing pubkey appears in a WebID profile's
/// `verificationMethod` + `authentication`, authenticates as the WebID
/// instead of `urn:nip98:<pubkey>`. JSS PR#400 parity.
///
/// Without `lws-cid`, returns `urn:nip98:<pubkey>` unconditionally.
#[cfg(not(feature = "lws-cid"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct Nip98Verifier;

#[cfg(feature = "lws-cid")]
pub struct Nip98Verifier {
    fetcher: std::sync::Arc<dyn crate::auth::lws_cid::ProfileFetcher>,
}

#[cfg(feature = "lws-cid")]
impl Nip98Verifier {
    pub fn new(fetcher: std::sync::Arc<dyn crate::auth::lws_cid::ProfileFetcher>) -> Self {
        Self { fetcher }
    }
}

fn verify_nip98_proof(
    proof: &str,
    uri: &str,
    method: &str,
    now: u64,
) -> Result<Nip98Verified, SelfSignedError> {
    let looks_like_header = proof.starts_with(NOSTR_PREFIX);
    let header = if looks_like_header {
        proof.to_string()
    } else {
        format!("{NOSTR_PREFIX}{}", proof)
    };

    match verify_at(&header, uri, method, None, now) {
        Ok(v) => Ok(v),
        Err(crate::error::PodError::Nip98(msg)) if looks_like_header => {
            if msg.contains("timestamp") {
                Err(SelfSignedError::OutOfTimeWindow(msg))
            } else if msg.contains("URL mismatch") || msg.contains("method mismatch") {
                Err(SelfSignedError::ScopeMismatch(msg))
            } else if msg.contains("schnorr") || msg.contains("id mismatch") {
                Err(SelfSignedError::InvalidSignature(msg))
            } else {
                Err(SelfSignedError::Malformed(msg))
            }
        }
        Err(_) if !looks_like_header => Err(SelfSignedError::UnrecognisedFormat),
        Err(e) => Err(SelfSignedError::Malformed(e.to_string())),
    }
}

#[cfg(not(feature = "lws-cid"))]
#[async_trait::async_trait]
impl SelfSignedVerifier for Nip98Verifier {
    async fn verify(
        &self,
        envelope: &ProofEnvelope<'_>,
    ) -> Result<Option<VerifiedSubject>, SelfSignedError> {
        match verify_nip98_proof(
            envelope.proof,
            envelope.uri,
            envelope.method,
            envelope.now_unix,
        ) {
            Ok(v) => Ok(Some(VerifiedSubject {
                did: format!("urn:nip98:{}", v.pubkey),
                verification_method: format!("urn:nip98:{}#key-0", v.pubkey),
            })),
            Err(SelfSignedError::UnrecognisedFormat) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn name(&self) -> &'static str {
        "nip98"
    }
}

#[cfg(feature = "lws-cid")]
#[async_trait::async_trait]
impl SelfSignedVerifier for Nip98Verifier {
    async fn verify(
        &self,
        envelope: &ProofEnvelope<'_>,
    ) -> Result<Option<VerifiedSubject>, SelfSignedError> {
        let verified = match verify_nip98_proof(
            envelope.proof,
            envelope.uri,
            envelope.method,
            envelope.now_unix,
        ) {
            Ok(v) => v,
            Err(SelfSignedError::UnrecognisedFormat) => return Ok(None),
            Err(e) => return Err(e),
        };

        // Attempt WebID elevation via profile VM lookup.
        if let Some(hint) = envelope.expected_subject_hint {
            if hint.starts_with("http") {
                let profile_url = hint.split('#').next().unwrap_or(hint);
                if let Ok(Some(webid)) =
                    try_elevate(&self.fetcher, profile_url, hint, &verified.pubkey).await
                {
                    return Ok(Some(VerifiedSubject {
                        did: webid,
                        verification_method: format!("{profile_url}#nostr-key"),
                    }));
                }
            }
        }

        Ok(Some(VerifiedSubject {
            did: format!("urn:nip98:{}", verified.pubkey),
            verification_method: format!("urn:nip98:{}#key-0", verified.pubkey),
        }))
    }

    fn name(&self) -> &'static str {
        "nip98"
    }
}

// ---------------------------------------------------------------------------
// WebID elevation helpers (lws-cid only)
// ---------------------------------------------------------------------------
//
// I3 BOUNDARY (ADR-124 §7): `try_elevate` is the ONLY VM-parsing site in the
// crate. It runs strictly AFTER NIP-98 Schnorr verification has already
// succeeded against the RAW event pubkey (see `verify_at` / the
// `VerifiedSubject` construction above); a mismatch here merely declines the
// optional WebID upgrade and falls back to `urn:nip98:<pubkey>`. It can NEVER
// authenticate, and re-encoding any verification method cannot touch the auth
// decision. The `feb<hex>` needle below is the WebID-side `bip340-pub`
// multibase (D-3) — kept in exact lockstep with `webid.rs` (D-2). Legacy
// `publicKeyHex` is still matched for back-compat with pre-pivot profiles.

#[cfg(feature = "lws-cid")]
async fn try_elevate(
    fetcher: &std::sync::Arc<dyn crate::auth::lws_cid::ProfileFetcher>,
    profile_url: &str,
    webid: &str,
    pubkey_hex: &str,
) -> Result<Option<String>, String> {
    let data = fetcher.fetch(profile_url).await?;
    let text = std::str::from_utf8(&data).map_err(|e| e.to_string())?;

    let json_value: serde_json::Value = if text.trim_start().starts_with('{') {
        serde_json::from_str(text).map_err(|e| e.to_string())?
    } else {
        extract_json_ld_from_html(text)?
    };

    let vms = json_value
        .get("verificationMethod")
        .and_then(|v| v.as_array())
        .map(|arr| arr.as_slice())
        .unwrap_or(&[]);

    let matching_vm_ids: Vec<&str> = vms
        .iter()
        .filter_map(|vm| {
            let id = vm.get("id").or_else(|| vm.get("@id"))?.as_str()?;
            if let Some(mb) = vm.get("publicKeyMultibase").and_then(|v| v.as_str()) {
                let needle = format!("feb{pubkey_hex}");
                if mb.eq_ignore_ascii_case(&needle) {
                    return Some(id);
                }
            }
            if let Some(hex) = vm.get("publicKeyHex").and_then(|v| v.as_str()) {
                if hex.eq_ignore_ascii_case(pubkey_hex) {
                    return Some(id);
                }
            }
            None
        })
        .collect();

    if matching_vm_ids.is_empty() {
        return Ok(None);
    }

    let auth = json_value
        .get("authentication")
        .and_then(|v| v.as_array())
        .map(|arr| arr.as_slice())
        .unwrap_or(&[]);

    let auth_ids: Vec<&str> = auth
        .iter()
        .filter_map(|v| match v {
            serde_json::Value::String(s) => Some(s.as_str()),
            serde_json::Value::Object(m) => m.get("@id").or_else(|| m.get("id"))?.as_str(),
            _ => None,
        })
        .collect();

    let elevated = matching_vm_ids
        .iter()
        .any(|vm_id| auth_ids.iter().any(|a| a == vm_id));

    if elevated {
        Ok(Some(webid.to_string()))
    } else {
        Ok(None)
    }
}

#[cfg(feature = "lws-cid")]
fn extract_json_ld_from_html(html: &str) -> Result<serde_json::Value, String> {
    let start = html
        .find("application/ld+json")
        .ok_or("no JSON-LD data island")?;
    let tag_end = html[start..].find('>').ok_or("malformed script tag")?;
    let json_start = start + tag_end + 1;
    let script_end = html[json_start..]
        .find("</script>")
        .ok_or("unclosed script")?;
    let json_str = html[json_start..json_start + script_end].trim();
    serde_json::from_str(json_str).map_err(|e| format!("JSON-LD parse: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_event(event: &serde_json::Value) -> String {
        BASE64.encode(serde_json::to_string(event).unwrap().as_bytes())
    }

    /// Deterministic test keypair. Under `nip98-schnorr` this returns a
    /// real BIP-340 signing key whose x-only pubkey is returned as hex.
    /// Without the feature, returns the legacy `"a".repeat(64)` placeholder.
    #[cfg(feature = "nip98-schnorr")]
    fn test_signing_key() -> (k256::schnorr::SigningKey, String) {
        // Deterministic 32-byte seed — not all seeds produce a valid
        // Schnorr key, but this one does (secp256k1 is ~99.9% acceptance).
        let seed = [0x42u8; 32];
        let sk = k256::schnorr::SigningKey::from_bytes(&seed)
            .expect("seed produces valid Schnorr signing key");
        let pubkey_hex = hex::encode(sk.verifying_key().to_bytes());
        (sk, pubkey_hex)
    }

    #[cfg(not(feature = "nip98-schnorr"))]
    fn test_pubkey() -> String {
        "a".repeat(64)
    }

    #[cfg(feature = "nip98-schnorr")]
    fn test_pubkey() -> String {
        test_signing_key().1
    }

    /// Build a canonically-hashed, properly-signed (when feature on) event.
    ///
    /// - `id` is always computed from the NIP-01 canonical serialisation.
    /// - `sig` is a real BIP-340 Schnorr signature when `nip98-schnorr` is
    ///   enabled, otherwise a 128-hex-zero placeholder (not verified).
    fn valid_event(url: &str, method: &str, ts: u64, body: Option<&[u8]>) -> serde_json::Value {
        let mut tags = vec![
            vec!["u".to_string(), url.to_string()],
            vec!["method".to_string(), method.to_string()],
        ];
        if let Some(b) = body {
            tags.push(vec!["payload".to_string(), hex::encode(Sha256::digest(b))]);
        }

        let pubkey = test_pubkey();
        let kind = 27235u64;
        let content = String::new();

        // Build a Nip98Event purely to reuse `compute_event_id` —
        // that's the canonical NIP-01 hash and the single source of truth.
        let skeleton = Nip98Event {
            id: String::new(),
            pubkey: pubkey.clone(),
            created_at: ts,
            kind,
            tags: tags.clone(),
            content: content.clone(),
            sig: String::new(),
        };
        let id = compute_event_id(&skeleton);

        let sig = {
            #[cfg(feature = "nip98-schnorr")]
            {
                let (sk, _) = test_signing_key();
                let id_bytes: Vec<u8> = hex::decode(&id).expect("id is valid hex");
                let signature: k256::schnorr::Signature =
                    sk.sign_raw(&id_bytes, &[0u8; 32]).expect("sign_raw");
                hex::encode(signature.to_bytes())
            }
            #[cfg(not(feature = "nip98-schnorr"))]
            {
                "0".repeat(128)
            }
        };

        serde_json::json!({
            "id": id,
            "pubkey": pubkey,
            "created_at": ts,
            "kind": kind,
            "tags": tags,
            "content": content,
            "sig": sig,
        })
    }

    #[test]
    fn rejects_missing_prefix() {
        let err = verify_at("Bearer xyz", "https://a/b", "GET", None, 0).unwrap_err();
        assert!(matches!(err, PodError::Nip98(_)));
    }

    // Acceptance requires a valid BIP-340 signature (verification is
    // unconditional; the no-feature path fails closed), so these positive
    // cases only run when a real signer is available.
    #[cfg(feature = "nip98-schnorr")]
    #[test]
    fn accepts_well_formed_event_no_body() {
        let ts = 1_700_000_000u64;
        let ev = valid_event("https://api.example.com/x", "GET", ts, None);
        let hdr = authorization_header(&encode_event(&ev));
        let r = verify_at(&hdr, "https://api.example.com/x", "GET", None, ts).unwrap();
        assert_eq!(r.pubkey, test_pubkey());
        assert_eq!(r.url, "https://api.example.com/x");
        assert_eq!(r.event_id.len(), 64);
    }

    #[cfg(feature = "nip98-schnorr")]
    #[test]
    fn accepts_trailing_slash_variation() {
        let ts = 1_700_000_000u64;
        let ev = valid_event("https://api.example.com/x/", "GET", ts, None);
        let hdr = authorization_header(&encode_event(&ev));
        verify_at(&hdr, "https://api.example.com/x", "GET", None, ts).unwrap();
    }

    /// F3 fail-closed: without the signer feature the verifier must reject
    /// even a structurally perfect event (no signature can be checked, so
    /// authentication is denied rather than granted to a forged pubkey).
    #[cfg(not(feature = "nip98-schnorr"))]
    #[test]
    fn fails_closed_without_schnorr_feature() {
        let ts = 1_700_000_000u64;
        let ev = valid_event("https://api.example.com/x", "GET", ts, None);
        let hdr = authorization_header(&encode_event(&ev));
        let err = verify_at(&hdr, "https://api.example.com/x", "GET", None, ts).unwrap_err();
        assert!(matches!(err, PodError::Unsupported(_)));
    }

    #[test]
    fn rejects_url_mismatch() {
        let ts = 1_700_000_000u64;
        let ev = valid_event("https://good/x", "GET", ts, None);
        let hdr = authorization_header(&encode_event(&ev));
        let err = verify_at(&hdr, "https://evil/x", "GET", None, ts).unwrap_err();
        assert!(matches!(err, PodError::Nip98(_)));
    }

    #[test]
    fn rejects_payload_mismatch() {
        let ts = 1_700_000_000u64;
        let ev = valid_event("https://a/b", "POST", ts, Some(b"original"));
        let hdr = authorization_header(&encode_event(&ev));
        let err = verify_at(&hdr, "https://a/b", "POST", Some(b"tampered"), ts).unwrap_err();
        assert!(matches!(err, PodError::Nip98(_)));
    }

    #[test]
    fn rejects_body_without_payload_tag() {
        let ts = 1_700_000_000u64;
        let ev = valid_event("https://a/b", "POST", ts, None);
        let hdr = authorization_header(&encode_event(&ev));
        let err = verify_at(&hdr, "https://a/b", "POST", Some(b"sneaky"), ts).unwrap_err();
        assert!(matches!(err, PodError::Nip98(_)));
    }

    #[test]
    fn rejects_expired_timestamp() {
        let ts = 1_700_000_000u64;
        let ev = valid_event("https://a/b", "GET", ts, None);
        let hdr = authorization_header(&encode_event(&ev));
        let err = verify_at(&hdr, "https://a/b", "GET", None, ts + 120).unwrap_err();
        assert!(matches!(err, PodError::Nip98(_)));
    }

    #[test]
    fn rejects_wrong_kind() {
        let ts = 1_700_000_000u64;
        let mut ev = valid_event("https://a/b", "GET", ts, None);
        ev["kind"] = serde_json::json!(1);
        let hdr = authorization_header(&encode_event(&ev));
        let err = verify_at(&hdr, "https://a/b", "GET", None, ts).unwrap_err();
        assert!(matches!(err, PodError::Nip98(_)));
    }

    #[cfg(feature = "nip98-schnorr")]
    #[test]
    fn mint_roundtrips_through_verify() {
        let ts = 1_700_000_000u64;
        let privkey_hex = hex::encode([0x42u8; 32]);
        let (_, expected_pub) = test_signing_key();

        let token = mint("https://pod.example/x", "PUT", &privkey_hex, ts).unwrap();
        let hdr = authorization_header(&token);
        let v = verify_at(&hdr, "https://pod.example/x", "PUT", None, ts).unwrap();
        assert_eq!(v.pubkey, expected_pub);
        assert_eq!(v.method, "PUT");
    }

    #[cfg(feature = "nip98-schnorr")]
    #[test]
    fn mint_with_payload_binds_body() {
        let ts = 1_700_000_000u64;
        let privkey_hex = hex::encode([0x42u8; 32]);
        let body = b"hello world";

        let token =
            mint_with_payload("https://pod.example/x", "POST", Some(body), &privkey_hex, ts)
                .unwrap();
        let hdr = authorization_header(&token);
        verify_at(&hdr, "https://pod.example/x", "POST", Some(body), ts).unwrap();
        // Tampered body must fail.
        let err =
            verify_at(&hdr, "https://pod.example/x", "POST", Some(b"tampered"), ts).unwrap_err();
        assert!(matches!(err, PodError::Nip98(_)));
    }

    #[cfg(feature = "nip98-schnorr")]
    #[test]
    fn git_lenient_accepts_wildcard_method_and_prefix_url() {
        let ts = 1_700_000_000u64;
        let privkey_hex = hex::encode([0x42u8; 32]);
        // Client signs the repo base URL with method `*`.
        let token = mint("https://pod.example/alice/repo", "*", &privkey_hex, ts).unwrap();
        let hdr = authorization_header(&token);

        // GET …/info/refs and POST …/git-receive-pack both pass under
        // GitLenient against the one token.
        for (url, method) in [
            ("https://pod.example/alice/repo/info/refs", "GET"),
            ("https://pod.example/alice/repo/git-receive-pack", "POST"),
        ] {
            verify_at_with_policy(&hdr, url, method, None, ts, MatchPolicy::GitLenient)
                .unwrap_or_else(|e| panic!("lenient verify {url} {method}: {e:?}"));
        }

        // Strict policy rejects the same token (method `*` ≠ GET).
        let err = verify_at_with_policy(
            &hdr,
            "https://pod.example/alice/repo/info/refs",
            "GET",
            None,
            ts,
            MatchPolicy::Strict,
        )
        .unwrap_err();
        assert!(matches!(err, PodError::Nip98(_)));
    }

    #[cfg(feature = "nip98-schnorr")]
    #[test]
    fn git_lenient_rejects_foreign_repo_prefix() {
        let ts = 1_700_000_000u64;
        let privkey_hex = hex::encode([0x42u8; 32]);
        let token = mint("https://pod.example/alice/repo", "*", &privkey_hex, ts).unwrap();
        let hdr = authorization_header(&token);
        // A sibling repo is not a prefix extension of the signed base.
        let err = verify_at_with_policy(
            &hdr,
            "https://pod.example/bob/repo/info/refs",
            "GET",
            None,
            ts,
            MatchPolicy::GitLenient,
        )
        .unwrap_err();
        assert!(matches!(err, PodError::Nip98(_)));
    }

    #[test]
    fn compute_event_id_matches_canonical_hash() {
        let event = Nip98Event {
            id: String::new(),
            pubkey: "a".repeat(64),
            created_at: 1_700_000_000,
            kind: 27235,
            tags: vec![
                vec!["u".into(), "https://api.example.com/x".into()],
                vec!["method".into(), "GET".into()],
            ],
            content: String::new(),
            sig: "0".repeat(128),
        };
        // Stable canonical hash — recomputing produces the same value.
        let id1 = compute_event_id(&event);
        let id2 = compute_event_id(&event);
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64);
    }
}
