//! LWS 1.0 Controlled Identifier (CID) self-signed JWT verifier.
//!
//! Implements self-signed Bearer JWT authentication per W3C Controlled
//! Identifier Document v1.0. The JWT `kid` header field resolves to a
//! `verificationMethod` in the signer's WebID profile; the signature is
//! verified against that key.
//!
//! Reference: <https://www.w3.org/TR/cid/>
//! JSS implementation: PR #398, #388, #418.
//!
//! Gated behind the `lws-cid` feature flag.
//!
//! # Profile fetching
//!
//! The verifier does not embed an HTTP client. Consumers inject a
//! [`ProfileFetcher`] trait object so wasm32 / CF Workers callers can
//! supply their own fetch implementation.

use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use serde::Deserialize;

use crate::auth::self_signed::{
    ProofEnvelope, SelfSignedError, SelfSignedVerifier, VerifiedSubject,
};

const MAX_JWT_LIFETIME_SECS: u64 = 3600;
const DEFAULT_SKEW_SECS: u64 = 60;
const MAX_PROFILE_SIZE: usize = 256 * 1024;

// ---------------------------------------------------------------------------
// Profile fetcher trait
// ---------------------------------------------------------------------------

/// Async profile document fetcher.
///
/// Implementations MUST guard against SSRF (reject private IPs,
/// loopback, link-local), enforce a size cap, and set a reasonable
/// timeout.
#[async_trait]
pub trait ProfileFetcher: Send + Sync {
    async fn fetch(&self, url: &str) -> Result<Vec<u8>, String>;
}

// ---------------------------------------------------------------------------
// JWT wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    typ: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwtClaims {
    sub: String,
    iss: String,
    htm: String,
    htu: String,
    iat: u64,
    #[serde(default)]
    exp: Option<u64>,
    #[serde(default)]
    client_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Profile / VerificationMethod types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
struct JwkKey {
    kty: String,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VmEntry {
    id: String,
    #[serde(default)]
    controller: Option<String>,
    #[serde(default)]
    public_key_jwk: Option<JwkKey>,
    #[serde(default)]
    public_key_multibase: Option<String>,
    #[serde(default, alias = "@type")]
    r#type: Option<serde_json::Value>,
}

#[derive(Debug)]
struct ProfileData {
    id: Option<String>,
    controller: Option<String>,
    verification_methods: Vec<VmEntry>,
    authentication: Vec<String>,
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// LWS 1.0 CID JWT verifier implementing [`SelfSignedVerifier`].
///
/// Plugs into [`crate::auth::self_signed::CidVerifier`] alongside
/// `Nip98Verifier` and `DidKeyVerifier`.
pub struct LwsCidVerifier {
    fetcher: Arc<dyn ProfileFetcher>,
    skew: u64,
}

impl LwsCidVerifier {
    pub fn new(fetcher: Arc<dyn ProfileFetcher>) -> Self {
        Self {
            fetcher,
            skew: DEFAULT_SKEW_SECS,
        }
    }

    #[must_use]
    pub fn with_skew(mut self, skew: u64) -> Self {
        self.skew = skew;
        self
    }
}

#[async_trait]
impl SelfSignedVerifier for LwsCidVerifier {
    async fn verify(
        &self,
        envelope: &ProofEnvelope<'_>,
    ) -> Result<Option<VerifiedSubject>, SelfSignedError> {
        // Quick reject: must look like a compact JWS.
        if !looks_like_compact_jws(envelope.proof) {
            return Ok(None);
        }

        // Parse header to check if this is an LWS-CID token (kid is a URL#fragment).
        let (hdr_b64, payload_b64, sig_b64) =
            split_jws(envelope.proof).map_err(|e| SelfSignedError::Malformed(e))?;

        let header: JwtHeader = decode_segment(&hdr_b64)
            .map_err(|e| SelfSignedError::Malformed(format!("header: {e}")))?;

        let kid = match &header.kid {
            Some(k) if is_url_with_fragment(k) => k.clone(),
            // Not an LWS-CID token — let the next verifier try.
            _ => return Ok(None),
        };

        // Parse claims.
        let claims: JwtClaims = decode_segment(&payload_b64)
            .map_err(|e| SelfSignedError::Malformed(format!("claims: {e}")))?;

        // Identity triple: sub === iss, and client_id (if present) === sub.
        if claims.sub != claims.iss {
            return Err(SelfSignedError::Malformed(
                "sub must equal iss for self-signed CID JWT".into(),
            ));
        }
        if let Some(ref cid) = claims.client_id {
            if cid != &claims.sub {
                return Err(SelfSignedError::Malformed(
                    "client_id must equal sub for self-signed CID JWT".into(),
                ));
            }
        }

        // Scope: htm + htu must match the request.
        if !claims.htm.eq_ignore_ascii_case(envelope.method) {
            return Err(SelfSignedError::ScopeMismatch(format!(
                "htm mismatch: got {}, expected {}",
                claims.htm, envelope.method
            )));
        }
        if !htu_eq(&claims.htu, envelope.uri) {
            return Err(SelfSignedError::ScopeMismatch(format!(
                "htu mismatch: got {}, expected {}",
                claims.htu, envelope.uri
            )));
        }

        // Time bounds.
        validate_time_bounds(&claims, envelope.now_unix, self.skew)?;

        // Resolve kid → profile URL + fragment.
        let (profile_url, kid_fragment) = split_kid_url(&kid)
            .ok_or_else(|| SelfSignedError::Malformed("kid URL has no fragment".into()))?;

        // The kid's base URL should relate to the sub (WebID).
        // The sub's document URL is the WebID minus the fragment.
        let sub_doc = claims.sub.split('#').next().unwrap_or(&claims.sub);
        if profile_url != sub_doc {
            return Err(SelfSignedError::Malformed(format!(
                "kid base URL ({profile_url}) does not match sub document ({sub_doc})"
            )));
        }

        // Fetch the profile document.
        let profile_bytes = self
            .fetcher
            .fetch(&profile_url)
            .await
            .map_err(|e| SelfSignedError::Other(format!("profile fetch: {e}")))?;

        if profile_bytes.len() > MAX_PROFILE_SIZE {
            return Err(SelfSignedError::Other("profile exceeds size limit".into()));
        }

        // Parse profile to extract verificationMethods + authentication.
        let profile = parse_profile(&profile_bytes)
            .map_err(|e| SelfSignedError::Other(format!("profile parse: {e}")))?;

        // Look up the verificationMethod by kid fragment.
        let vm = profile
            .verification_methods
            .iter()
            .find(|vm| vm.id == kid || vm.id.ends_with(&format!("#{kid_fragment}")))
            .ok_or_else(|| {
                SelfSignedError::Other(format!("verificationMethod {kid} not found in profile"))
            })?;

        // Confirm the VM is listed in `authentication`.
        let vm_in_auth = profile
            .authentication
            .iter()
            .any(|a| a == &vm.id || a == &kid || a.ends_with(&format!("#{kid_fragment}")));
        if !vm_in_auth {
            return Err(SelfSignedError::Other(format!(
                "verificationMethod {kid} is not in authentication relationship"
            )));
        }

        // Controller check: VM controller must match profile controller or WebID.
        if let Some(ref vm_controller) = vm.controller {
            let profile_controller = profile
                .controller
                .as_deref()
                .or(profile.id.as_deref())
                .unwrap_or(&claims.sub);
            if vm_controller != profile_controller && vm_controller != &claims.sub {
                return Err(SelfSignedError::Other(format!(
                    "VM controller ({vm_controller}) does not match profile controller ({profile_controller})"
                )));
            }
        }

        // Extract public key from the VM's publicKeyJwk.
        let jwk = vm.public_key_jwk.as_ref().ok_or_else(|| {
            SelfSignedError::Other("verificationMethod has no publicKeyJwk".into())
        })?;

        // Alg-confusion gate: header alg must match JWK curve.
        validate_alg_jwk_match(&header.alg, jwk)?;

        // Build signing input: ASCII bytes of "header.payload".
        let signing_input = format!("{hdr_b64}.{payload_b64}");
        let sig_bytes = B64URL
            .decode(&sig_b64)
            .map_err(|e| SelfSignedError::Malformed(format!("signature base64: {e}")))?;

        // Verify signature.
        verify_signature_jwk(&header.alg, jwk, signing_input.as_bytes(), &sig_bytes)?;

        Ok(Some(VerifiedSubject {
            did: claims.sub,
            verification_method: kid,
        }))
    }

    fn name(&self) -> &'static str {
        "lws-cid"
    }
}

// ---------------------------------------------------------------------------
// JWT helpers
// ---------------------------------------------------------------------------

fn looks_like_compact_jws(s: &str) -> bool {
    let dots = s.bytes().filter(|b| *b == b'.').count();
    dots == 2
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'=' | b'+' | b'/')
        })
}

fn split_jws(jwt: &str) -> Result<(String, String, String), String> {
    let mut parts = jwt.splitn(4, '.');
    let h = parts.next().ok_or("missing header")?;
    let p = parts.next().ok_or("missing payload")?;
    let s = parts.next().ok_or("missing signature")?;
    if parts.next().is_some() {
        return Err("JWS has more than 3 segments".into());
    }
    Ok((h.to_string(), p.to_string(), s.to_string()))
}

fn decode_segment<T: for<'de> Deserialize<'de>>(b64: &str) -> Result<T, String> {
    let bytes = B64URL.decode(b64).map_err(|e| format!("base64: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("json: {e}"))
}

fn htu_eq(a: &str, b: &str) -> bool {
    let na = a.trim_end_matches('/').to_ascii_lowercase();
    let nb = b.trim_end_matches('/').to_ascii_lowercase();
    na == nb
}

fn is_url_with_fragment(kid: &str) -> bool {
    (kid.starts_with("https://") || kid.starts_with("http://")) && kid.contains('#')
}

fn split_kid_url(kid: &str) -> Option<(String, String)> {
    let hash_pos = kid.rfind('#')?;
    let base = &kid[..hash_pos];
    let fragment = &kid[hash_pos + 1..];
    if base.is_empty() || fragment.is_empty() {
        return None;
    }
    Some((base.to_string(), fragment.to_string()))
}

fn validate_time_bounds(claims: &JwtClaims, now: u64, skew: u64) -> Result<(), SelfSignedError> {
    // iat must be within skew window.
    if now.saturating_sub(claims.iat) > skew && claims.iat.saturating_sub(now) > skew {
        return Err(SelfSignedError::OutOfTimeWindow(format!(
            "iat={} outside skew={}s from now={}",
            claims.iat, skew, now
        )));
    }
    // exp must not be past.
    if let Some(exp) = claims.exp {
        if exp + skew < now {
            return Err(SelfSignedError::OutOfTimeWindow(format!(
                "exp={exp} before now={now} (skew={skew}s)"
            )));
        }
        // Lifetime cap: exp - iat must be ≤ 1 hour.
        if exp.saturating_sub(claims.iat) > MAX_JWT_LIFETIME_SECS {
            return Err(SelfSignedError::OutOfTimeWindow(format!(
                "JWT lifetime {}s exceeds max {}s",
                exp.saturating_sub(claims.iat),
                MAX_JWT_LIFETIME_SECS
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Profile parsing
// ---------------------------------------------------------------------------

fn parse_profile(data: &[u8]) -> Result<ProfileData, String> {
    // Try JSON-LD directly first, then fall back to HTML data island.
    let text = std::str::from_utf8(data).map_err(|_| "profile not valid UTF-8")?;
    let json_value: serde_json::Value = if text.trim_start().starts_with('{') {
        serde_json::from_str(text).map_err(|e| format!("JSON parse: {e}"))?
    } else {
        extract_json_ld_from_html(text)?
    };

    let id = json_value
        .get("@id")
        .or_else(|| json_value.get("id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let controller = json_value
        .get("controller")
        .or_else(|| json_value.get("cid:controller"))
        .and_then(|v| match v {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Object(m) => {
                m.get("@id").and_then(|v| v.as_str()).map(|s| s.to_string())
            }
            _ => None,
        });

    let verification_methods = parse_verification_methods(&json_value);
    let authentication = parse_authentication(&json_value);

    Ok(ProfileData {
        id,
        controller,
        verification_methods,
        authentication,
    })
}

fn extract_json_ld_from_html(html: &str) -> Result<serde_json::Value, String> {
    let start = html
        .find("application/ld+json")
        .ok_or("no JSON-LD data island in HTML profile")?;
    let tag_end = html[start..].find('>').ok_or("malformed script tag")?;
    let json_start = start + tag_end + 1;
    let script_end = html[json_start..]
        .find("</script>")
        .ok_or("unclosed script tag")?;
    let json_str = html[json_start..json_start + script_end].trim();
    serde_json::from_str(json_str).map_err(|e| format!("JSON-LD parse: {e}"))
}

fn parse_verification_methods(doc: &serde_json::Value) -> Vec<VmEntry> {
    let vm_value = doc
        .get("verificationMethod")
        .or_else(|| doc.get("cid:verificationMethod"));
    match vm_value {
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| serde_json::from_value(v.clone()).ok())
            .collect(),
        Some(v) => serde_json::from_value::<VmEntry>(v.clone())
            .ok()
            .into_iter()
            .collect(),
        None => Vec::new(),
    }
}

fn parse_authentication(doc: &serde_json::Value) -> Vec<String> {
    let auth_value = doc
        .get("authentication")
        .or_else(|| doc.get("cid:authentication"));
    match auth_value {
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| match v {
                serde_json::Value::String(s) => Some(s.clone()),
                serde_json::Value::Object(m) => {
                    m.get("@id").and_then(|v| v.as_str()).map(|s| s.to_string())
                }
                _ => None,
            })
            .collect(),
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Alg ↔ JWK match gate
// ---------------------------------------------------------------------------

fn validate_alg_jwk_match(alg: &str, jwk: &JwkKey) -> Result<(), SelfSignedError> {
    let expected_alg = match (jwk.kty.as_str(), jwk.crv.as_deref()) {
        ("EC", Some("secp256k1")) => "ES256K",
        ("EC", Some("P-256")) => "ES256",
        ("OKP", Some("Ed25519")) => "EdDSA",
        (kty, crv) => {
            return Err(SelfSignedError::Other(format!(
                "unsupported JWK kty={kty} crv={crv:?}"
            )));
        }
    };
    if alg != expected_alg {
        return Err(SelfSignedError::InvalidSignature(format!(
            "alg `{alg}` does not match JWK curve (expected `{expected_alg}`)"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Signature verification against a JWK
// ---------------------------------------------------------------------------

fn verify_signature_jwk(
    alg: &str,
    jwk: &JwkKey,
    msg: &[u8],
    sig: &[u8],
) -> Result<(), SelfSignedError> {
    match alg {
        "ES256K" => verify_es256k(jwk, msg, sig),
        #[cfg(feature = "lws-cid-p256")]
        "ES256" => verify_es256(jwk, msg, sig),
        #[cfg(feature = "lws-cid-eddsa")]
        "EdDSA" => verify_eddsa(jwk, msg, sig),
        other => Err(SelfSignedError::Other(format!("unsupported alg: {other}"))),
    }
}

/// ES256K (secp256k1 ECDSA) signature verification via k256.
fn verify_es256k(jwk: &JwkKey, msg: &[u8], sig: &[u8]) -> Result<(), SelfSignedError> {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let sec1 = jwk_ec_to_sec1(jwk)?;
    let vk = VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|e| SelfSignedError::InvalidSignature(format!("secp256k1 key parse: {e}")))?;
    if sig.len() != 64 {
        return Err(SelfSignedError::InvalidSignature(format!(
            "ES256K sig len {} (expected 64)",
            sig.len()
        )));
    }
    let signature = Signature::from_slice(sig)
        .map_err(|e| SelfSignedError::InvalidSignature(format!("ES256K sig parse: {e}")))?;
    vk.verify(msg, &signature)
        .map_err(|e| SelfSignedError::InvalidSignature(format!("ES256K: {e}")))
}

/// ES256 (P-256 ECDSA) signature verification via p256.
#[cfg(feature = "lws-cid-p256")]
fn verify_es256(jwk: &JwkKey, msg: &[u8], sig: &[u8]) -> Result<(), SelfSignedError> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let sec1 = jwk_ec_to_sec1(jwk)?;
    let vk = VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|e| SelfSignedError::InvalidSignature(format!("P-256 key parse: {e}")))?;
    if sig.len() != 64 {
        return Err(SelfSignedError::InvalidSignature(format!(
            "ES256 sig len {} (expected 64)",
            sig.len()
        )));
    }
    let signature = Signature::from_slice(sig)
        .map_err(|e| SelfSignedError::InvalidSignature(format!("ES256 sig parse: {e}")))?;
    vk.verify(msg, &signature)
        .map_err(|e| SelfSignedError::InvalidSignature(format!("ES256: {e}")))
}

/// EdDSA (Ed25519) signature verification via ed25519-dalek.
#[cfg(feature = "lws-cid-eddsa")]
fn verify_eddsa(jwk: &JwkKey, msg: &[u8], sig: &[u8]) -> Result<(), SelfSignedError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let x = jwk
        .x
        .as_deref()
        .ok_or_else(|| SelfSignedError::InvalidSignature("OKP JWK missing x".into()))?;
    let bytes = B64URL
        .decode(x)
        .map_err(|e| SelfSignedError::InvalidSignature(format!("OKP x base64: {e}")))?;
    if bytes.len() != 32 {
        return Err(SelfSignedError::InvalidSignature(format!(
            "Ed25519 key len {} (expected 32)",
            bytes.len()
        )));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);
    let vk = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| SelfSignedError::InvalidSignature(format!("Ed25519 key parse: {e}")))?;
    if sig.len() != 64 {
        return Err(SelfSignedError::InvalidSignature(format!(
            "EdDSA sig len {} (expected 64)",
            sig.len()
        )));
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(sig);
    let signature = Signature::from_bytes(&sig_bytes);
    vk.verify(msg, &signature)
        .map_err(|e| SelfSignedError::InvalidSignature(format!("EdDSA: {e}")))
}

/// Extract SEC1 compressed point from EC JWK (x, y coordinates).
fn jwk_ec_to_sec1(jwk: &JwkKey) -> Result<Vec<u8>, SelfSignedError> {
    let x = jwk
        .x
        .as_deref()
        .ok_or_else(|| SelfSignedError::InvalidSignature("EC JWK missing x".into()))?;
    let y = jwk
        .y
        .as_deref()
        .ok_or_else(|| SelfSignedError::InvalidSignature("EC JWK missing y".into()))?;
    let x_bytes = B64URL
        .decode(x)
        .map_err(|e| SelfSignedError::InvalidSignature(format!("EC x base64: {e}")))?;
    let y_bytes = B64URL
        .decode(y)
        .map_err(|e| SelfSignedError::InvalidSignature(format!("EC y base64: {e}")))?;
    if x_bytes.len() != 32 || y_bytes.len() != 32 {
        return Err(SelfSignedError::InvalidSignature(format!(
            "EC x/y must be 32 bytes each, got {}/{}",
            x_bytes.len(),
            y_bytes.len()
        )));
    }
    let prefix = if y_bytes[31] & 1 == 0 { 0x02 } else { 0x03 };
    let mut sec1 = Vec::with_capacity(33);
    sec1.push(prefix);
    sec1.extend_from_slice(&x_bytes);
    Ok(sec1)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MockFetcher {
        responses: Mutex<std::collections::HashMap<String, Vec<u8>>>,
    }

    impl MockFetcher {
        fn new() -> Self {
            Self {
                responses: Mutex::new(std::collections::HashMap::new()),
            }
        }

        fn add_response(&self, url: &str, body: &[u8]) {
            self.responses
                .lock()
                .unwrap()
                .insert(url.to_string(), body.to_vec());
        }
    }

    #[async_trait]
    impl ProfileFetcher for MockFetcher {
        async fn fetch(&self, url: &str) -> Result<Vec<u8>, String> {
            self.responses
                .lock()
                .unwrap()
                .get(url)
                .cloned()
                .ok_or_else(|| format!("mock: no response for {url}"))
        }
    }

    fn make_test_keypair() -> (k256::ecdsa::SigningKey, k256::ecdsa::VerifyingKey) {
        let sk = k256::ecdsa::SigningKey::from_bytes(&[0x42u8; 32].into()).unwrap();
        let vk = *sk.verifying_key();
        (sk, vk)
    }

    fn vk_to_jwk(vk: &k256::ecdsa::VerifyingKey) -> serde_json::Value {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let point = vk.to_encoded_point(false);
        let x = B64URL.encode(point.x().unwrap());
        let y = B64URL.encode(point.y().unwrap());
        serde_json::json!({
            "kty": "EC",
            "crv": "secp256k1",
            "x": x,
            "y": y
        })
    }

    fn sign_jwt(
        sk: &k256::ecdsa::SigningKey,
        header: &serde_json::Value,
        claims: &serde_json::Value,
    ) -> String {
        use k256::ecdsa::{signature::Signer, Signature};
        let h = B64URL.encode(serde_json::to_vec(header).unwrap());
        let p = B64URL.encode(serde_json::to_vec(claims).unwrap());
        let input = format!("{h}.{p}");
        let sig: Signature = sk.sign(input.as_bytes());
        let s = B64URL.encode(sig.to_bytes());
        format!("{h}.{p}.{s}")
    }

    fn test_profile(webid: &str, kid: &str, jwk: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "@context": ["https://www.w3.org/ns/cid/v1"],
            "@id": webid,
            "controller": webid,
            "verificationMethod": [{
                "id": kid,
                "type": "JsonWebKey",
                "controller": webid,
                "publicKeyJwk": jwk
            }],
            "authentication": [kid]
        })
    }

    #[tokio::test]
    async fn rejects_non_jwt() {
        let fetcher = Arc::new(MockFetcher::new());
        let v = LwsCidVerifier::new(fetcher);
        let env = ProofEnvelope {
            proof: "not-a-jwt",
            method: "GET",
            uri: "https://pod.example/r",
            now_unix: 1_700_000_000,
            expected_subject_hint: None,
        };
        let result = v.verify(&env).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn passes_through_didkey_jwt() {
        let fetcher = Arc::new(MockFetcher::new());
        let v = LwsCidVerifier::new(fetcher);
        // kid is did:key:z... — not our format.
        let header = serde_json::json!({"alg": "EdDSA", "kid": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"});
        let claims =
            serde_json::json!({"sub": "x", "iss": "x", "htm": "GET", "htu": "https://x", "iat": 0});
        let h = B64URL.encode(serde_json::to_vec(&header).unwrap());
        let p = B64URL.encode(serde_json::to_vec(&claims).unwrap());
        let s = B64URL.encode(b"fakesig_________________________________");
        let jwt = format!("{h}.{p}.{s}");
        let env = ProofEnvelope {
            proof: &jwt,
            method: "GET",
            uri: "https://x",
            now_unix: 0,
            expected_subject_hint: None,
        };
        let result = v.verify(&env).await.unwrap();
        assert!(result.is_none(), "should pass through did:key JWTs");
    }

    #[tokio::test]
    async fn rejects_sub_iss_mismatch() {
        let (sk, vk) = make_test_keypair();
        let jwk = vk_to_jwk(&vk);
        let webid = "https://pod.example/profile/card#me";
        let kid = "https://pod.example/profile/card#key-1";

        let header = serde_json::json!({"alg": "ES256K", "kid": kid});
        let claims = serde_json::json!({
            "sub": webid,
            "iss": "https://other.example/profile#me",
            "htm": "GET",
            "htu": "https://pod.example/resource",
            "iat": 1_700_000_000u64
        });

        let jwt = sign_jwt(&sk, &header, &claims);
        let fetcher = Arc::new(MockFetcher::new());
        let profile = test_profile(webid, kid, &jwk);
        fetcher.add_response(
            "https://pod.example/profile/card",
            serde_json::to_vec(&profile).unwrap().as_slice(),
        );

        let v = LwsCidVerifier::new(fetcher);
        let env = ProofEnvelope {
            proof: &jwt,
            method: "GET",
            uri: "https://pod.example/resource",
            now_unix: 1_700_000_000,
            expected_subject_hint: None,
        };
        let err = v.verify(&env).await.unwrap_err();
        assert!(matches!(err, SelfSignedError::Malformed(_)));
    }

    #[tokio::test]
    async fn verifies_valid_es256k_jwt() {
        let (sk, vk) = make_test_keypair();
        let jwk = vk_to_jwk(&vk);
        let webid = "https://pod.example/profile/card#me";
        let kid = "https://pod.example/profile/card#key-1";
        let now = 1_700_000_000u64;

        let header = serde_json::json!({"alg": "ES256K", "kid": kid});
        let claims = serde_json::json!({
            "sub": webid,
            "iss": webid,
            "htm": "GET",
            "htu": "https://pod.example/resource",
            "iat": now,
            "exp": now + 300
        });

        let jwt = sign_jwt(&sk, &header, &claims);

        let fetcher = Arc::new(MockFetcher::new());
        let profile = test_profile(webid, kid, &jwk);
        fetcher.add_response(
            "https://pod.example/profile/card",
            serde_json::to_vec(&profile).unwrap().as_slice(),
        );

        let v = LwsCidVerifier::new(fetcher);
        let env = ProofEnvelope {
            proof: &jwt,
            method: "GET",
            uri: "https://pod.example/resource",
            now_unix: now,
            expected_subject_hint: None,
        };
        let result = v.verify(&env).await.unwrap().unwrap();
        assert_eq!(result.did, webid);
        assert_eq!(result.verification_method, kid);
    }

    #[tokio::test]
    async fn rejects_expired_jwt() {
        let (sk, vk) = make_test_keypair();
        let jwk = vk_to_jwk(&vk);
        let webid = "https://pod.example/profile/card#me";
        let kid = "https://pod.example/profile/card#key-1";

        let header = serde_json::json!({"alg": "ES256K", "kid": kid});
        let claims = serde_json::json!({
            "sub": webid,
            "iss": webid,
            "htm": "GET",
            "htu": "https://pod.example/r",
            "iat": 1_700_000_000u64,
            "exp": 1_700_000_100u64
        });

        let jwt = sign_jwt(&sk, &header, &claims);
        let fetcher = Arc::new(MockFetcher::new());
        let profile = test_profile(webid, kid, &jwk);
        fetcher.add_response(
            "https://pod.example/profile/card",
            serde_json::to_vec(&profile).unwrap().as_slice(),
        );

        let v = LwsCidVerifier::new(fetcher);
        let env = ProofEnvelope {
            proof: &jwt,
            method: "GET",
            uri: "https://pod.example/r",
            now_unix: 1_700_001_000,
            expected_subject_hint: None,
        };
        let err = v.verify(&env).await.unwrap_err();
        assert!(matches!(err, SelfSignedError::OutOfTimeWindow(_)));
    }

    #[tokio::test]
    async fn rejects_vm_not_in_authentication() {
        let (sk, vk) = make_test_keypair();
        let jwk = vk_to_jwk(&vk);
        let webid = "https://pod.example/profile/card#me";
        let kid = "https://pod.example/profile/card#key-1";
        let now = 1_700_000_000u64;

        let header = serde_json::json!({"alg": "ES256K", "kid": kid});
        let claims = serde_json::json!({
            "sub": webid,
            "iss": webid,
            "htm": "GET",
            "htu": "https://pod.example/r",
            "iat": now
        });

        let jwt = sign_jwt(&sk, &header, &claims);
        let fetcher = Arc::new(MockFetcher::new());
        // Profile has VM but authentication is empty.
        let profile = serde_json::json!({
            "@id": webid,
            "controller": webid,
            "verificationMethod": [{
                "id": kid,
                "type": "JsonWebKey",
                "controller": webid,
                "publicKeyJwk": jwk
            }],
            "authentication": []
        });
        fetcher.add_response(
            "https://pod.example/profile/card",
            serde_json::to_vec(&profile).unwrap().as_slice(),
        );

        let v = LwsCidVerifier::new(fetcher);
        let env = ProofEnvelope {
            proof: &jwt,
            method: "GET",
            uri: "https://pod.example/r",
            now_unix: now,
            expected_subject_hint: None,
        };
        let err = v.verify(&env).await.unwrap_err();
        assert!(
            matches!(err, SelfSignedError::Other(ref m) if m.contains("not in authentication")),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_alg_confusion() {
        let (sk, vk) = make_test_keypair();
        let jwk = vk_to_jwk(&vk);
        let webid = "https://pod.example/profile/card#me";
        let kid = "https://pod.example/profile/card#key-1";
        let now = 1_700_000_000u64;

        // Claim EdDSA but key is secp256k1.
        let header = serde_json::json!({"alg": "EdDSA", "kid": kid});
        let claims = serde_json::json!({
            "sub": webid,
            "iss": webid,
            "htm": "GET",
            "htu": "https://pod.example/r",
            "iat": now
        });

        let jwt = sign_jwt(&sk, &header, &claims);
        let fetcher = Arc::new(MockFetcher::new());
        let profile = test_profile(webid, kid, &jwk);
        fetcher.add_response(
            "https://pod.example/profile/card",
            serde_json::to_vec(&profile).unwrap().as_slice(),
        );

        let v = LwsCidVerifier::new(fetcher);
        let env = ProofEnvelope {
            proof: &jwt,
            method: "GET",
            uri: "https://pod.example/r",
            now_unix: now,
            expected_subject_hint: None,
        };
        let err = v.verify(&env).await.unwrap_err();
        assert!(matches!(err, SelfSignedError::InvalidSignature(_)));
    }

    #[test]
    fn htu_eq_trailing_slash() {
        assert!(htu_eq("https://a.example/path/", "https://a.example/path"));
        assert!(htu_eq("https://A.example/path", "https://a.example/path"));
        assert!(!htu_eq("https://a.example/a", "https://a.example/b"));
    }

    #[test]
    fn is_url_with_fragment_detection() {
        assert!(is_url_with_fragment("https://pod.example/card#key-1"));
        assert!(!is_url_with_fragment(
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        ));
        assert!(!is_url_with_fragment("https://pod.example/card"));
    }

    #[test]
    fn split_kid_url_works() {
        let (base, frag) = split_kid_url("https://pod.example/card#key-1").unwrap();
        assert_eq!(base, "https://pod.example/card");
        assert_eq!(frag, "key-1");
    }

    #[test]
    fn time_bounds_accept_valid() {
        let claims = JwtClaims {
            sub: "x".into(),
            iss: "x".into(),
            htm: "GET".into(),
            htu: "https://x".into(),
            iat: 1000,
            exp: Some(1300),
            client_id: None,
        };
        assert!(validate_time_bounds(&claims, 1000, 60).is_ok());
    }

    #[test]
    fn time_bounds_reject_excessive_lifetime() {
        let claims = JwtClaims {
            sub: "x".into(),
            iss: "x".into(),
            htm: "GET".into(),
            htu: "https://x".into(),
            iat: 1000,
            exp: Some(1000 + 7200),
            client_id: None,
        };
        let err = validate_time_bounds(&claims, 1000, 60).unwrap_err();
        assert!(matches!(err, SelfSignedError::OutOfTimeWindow(_)));
    }
}
