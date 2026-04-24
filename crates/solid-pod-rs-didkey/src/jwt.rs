//! Self-signed JWT verification against an embedded `did:key`.
//!
//! Wire format: compact JWS — three base64url-no-pad segments separated
//! by `.`. The header MUST carry:
//!
//! - `alg`: `EdDSA` (Ed25519), `ES256` (P-256), or `ES256K` (secp256k1).
//!   The value MUST match the `did:key` codec. This is the alg-confusion
//!   mitigation — an attacker who substitutes e.g. `HS256` or who pairs
//!   `ES256` with an Ed25519 key is rejected before any crypto runs.
//! - Either `kid` (a `did:key:z…` identifier, possibly with a method
//!   fragment) OR an embedded `jwk` member that encodes the same key.
//!
//! Payload MUST carry `htm` + `htu` + `iat`, matching the DPoP-shaped
//! claims familiar from Solid-OIDC. `iat` is bounded by the caller's
//! `skew` window. Optional `exp` is honoured if present.
//!
//! This verifier is hand-rolled rather than delegating to the
//! `jsonwebtoken` crate because `jsonwebtoken` v9's Ed25519 path
//! requires a PKCS8-wrapped key, which `did:key` does not carry — we
//! have the raw 32-byte public point and must verify against it
//! directly via `ed25519-dalek::Verifier`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use serde::Deserialize;

use crate::did;
use crate::error::DidKeyError;
use crate::pubkey::DidKeyPubkey;

/// Decoded + verified JWT.
#[derive(Debug, Clone)]
pub struct VerifiedJwt {
    /// Canonical `did:key:z…` identifier the JWT was signed by.
    pub did: String,
    /// `kid` the client advertised (often `did:key:z…#z…`).
    pub verification_method: String,
    /// `htm` claim (request method).
    pub htm: String,
    /// `htu` claim (request URI).
    pub htu: String,
    /// `iat` claim (issued-at, seconds since Unix epoch).
    pub iat: u64,
    /// Optional `exp` claim.
    pub exp: Option<u64>,
    /// Optional `sub` claim — mirrored into [`VerifiedJwt::did`] when
    /// absent, exposed here for callers that embed a WebID.
    pub sub: Option<String>,
}

/// Verify a self-signed compact JWT.
///
/// # Parameters
///
/// - `jwt`: compact JWS string.
/// - `expected_htu`: the absolute request URI the caller saw; compared
///   case-insensitively with a trailing-slash-tolerant match.
/// - `expected_htm`: HTTP method, upper-cased before comparison.
/// - `now`: caller's current time in Unix seconds.
/// - `skew`: acceptable drift in seconds for the `iat` check. Also
///   used when validating `exp` (proof is accepted up to `now + skew`).
///
/// # Errors
///
/// Returns [`DidKeyError`]. The variant distinguishes malformed envelopes
/// (`MalformedJwt`), alg-confusion rejections (`InvalidHeader`), scope
/// mismatches (`InvalidClaims`), and signature failures (`BadSignature`).
pub fn verify_self_signed_jwt(
    jwt: &str,
    expected_htu: &str,
    expected_htm: &str,
    now: u64,
    skew: u64,
) -> Result<VerifiedJwt, DidKeyError> {
    // Split into header.payload.signature.
    let mut parts = jwt.splitn(4, '.');
    let hdr_b64 = parts
        .next()
        .ok_or_else(|| DidKeyError::MalformedJwt("missing header".into()))?;
    let payload_b64 = parts
        .next()
        .ok_or_else(|| DidKeyError::MalformedJwt("missing payload".into()))?;
    let sig_b64 = parts
        .next()
        .ok_or_else(|| DidKeyError::MalformedJwt("missing signature".into()))?;
    if parts.next().is_some() {
        return Err(DidKeyError::MalformedJwt(
            "compact JWS has exactly three segments".into(),
        ));
    }

    let header_bytes = B64URL
        .decode(hdr_b64)
        .map_err(|e| DidKeyError::MalformedJwt(format!("header base64: {e}")))?;
    let payload_bytes = B64URL
        .decode(payload_b64)
        .map_err(|e| DidKeyError::MalformedJwt(format!("payload base64: {e}")))?;
    let sig_bytes = B64URL
        .decode(sig_b64)
        .map_err(|e| DidKeyError::MalformedJwt(format!("signature base64: {e}")))?;

    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| DidKeyError::InvalidHeader(format!("header json: {e}")))?;
    let claims: JwtClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| DidKeyError::InvalidClaims(format!("claims json: {e}")))?;

    // Resolve the key from header (kid first; fall back to embedded jwk).
    let (pubkey, verification_method) = resolve_key(&header)?;

    // Alg-confusion gate: the header alg MUST match the key variant.
    let expected_alg = pubkey.jws_alg();
    if header.alg != expected_alg {
        return Err(DidKeyError::InvalidHeader(format!(
            "alg `{}` does not match {} did:key (expected `{expected_alg}`)",
            header.alg,
            pubkey.codec_name()
        )));
    }

    // Signing input is the ASCII bytes of `header.payload`.
    let signing_input = {
        let mut buf = Vec::with_capacity(hdr_b64.len() + 1 + payload_b64.len());
        buf.extend_from_slice(hdr_b64.as_bytes());
        buf.push(b'.');
        buf.extend_from_slice(payload_b64.as_bytes());
        buf
    };

    verify_signature(&pubkey, &signing_input, &sig_bytes)?;

    // Claim checks: method, URI, time window.
    if !claims.htm.eq_ignore_ascii_case(expected_htm) {
        return Err(DidKeyError::InvalidClaims(format!(
            "htm mismatch: got {}, expected {expected_htm}",
            claims.htm
        )));
    }
    if !htu_eq(&claims.htu, expected_htu) {
        return Err(DidKeyError::InvalidClaims(format!(
            "htu mismatch: got {}, expected {expected_htu}",
            claims.htu
        )));
    }
    if now.saturating_sub(claims.iat) > skew || claims.iat.saturating_sub(now) > skew {
        return Err(DidKeyError::InvalidClaims(format!(
            "iat={} outside skew={skew}s from now={now}",
            claims.iat
        )));
    }
    if let Some(exp) = claims.exp {
        if exp + skew < now {
            return Err(DidKeyError::InvalidClaims(format!(
                "exp={exp} before now={now} (skew={skew}s)"
            )));
        }
    }

    let did_str = did::encode(&pubkey);
    Ok(VerifiedJwt {
        did: did_str,
        verification_method,
        htm: claims.htm,
        htu: claims.htu,
        iat: claims.iat,
        exp: claims.exp,
        sub: claims.sub,
    })
}

fn htu_eq(a: &str, b: &str) -> bool {
    let na = a.trim_end_matches('/').to_ascii_lowercase();
    let nb = b.trim_end_matches('/').to_ascii_lowercase();
    na == nb
}

fn resolve_key(header: &JwtHeader) -> Result<(DidKeyPubkey, String), DidKeyError> {
    if let Some(kid) = &header.kid {
        let pk = did::decode(kid)?;
        return Ok((pk, kid.clone()));
    }
    if let Some(jwk) = &header.jwk {
        let pk = jwk_to_pubkey(jwk)?;
        let vm = did::encode(&pk);
        return Ok((pk, vm));
    }
    Err(DidKeyError::InvalidHeader(
        "neither kid nor jwk present".into(),
    ))
}

fn jwk_to_pubkey(jwk: &JwkLite) -> Result<DidKeyPubkey, DidKeyError> {
    match jwk.kty.as_str() {
        "OKP" => {
            if jwk.crv.as_deref() != Some("Ed25519") {
                return Err(DidKeyError::InvalidHeader(format!(
                    "OKP jwk crv unsupported: {:?}",
                    jwk.crv
                )));
            }
            let x = jwk
                .x
                .as_deref()
                .ok_or_else(|| DidKeyError::InvalidHeader("OKP jwk missing x".into()))?;
            let bytes = B64URL
                .decode(x)
                .map_err(|e| DidKeyError::InvalidHeader(format!("OKP x base64: {e}")))?;
            if bytes.len() != 32 {
                return Err(DidKeyError::InvalidKeyLength {
                    codec: "ed25519",
                    expected: 32,
                    actual: bytes.len(),
                });
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(DidKeyPubkey::Ed25519(arr))
        }
        "EC" => {
            let crv = jwk
                .crv
                .as_deref()
                .ok_or_else(|| DidKeyError::InvalidHeader("EC jwk missing crv".into()))?;
            let x = jwk
                .x
                .as_deref()
                .ok_or_else(|| DidKeyError::InvalidHeader("EC jwk missing x".into()))?;
            let y = jwk
                .y
                .as_deref()
                .ok_or_else(|| DidKeyError::InvalidHeader("EC jwk missing y".into()))?;
            let x_bytes = B64URL
                .decode(x)
                .map_err(|e| DidKeyError::InvalidHeader(format!("EC x base64: {e}")))?;
            let y_bytes = B64URL
                .decode(y)
                .map_err(|e| DidKeyError::InvalidHeader(format!("EC y base64: {e}")))?;
            if x_bytes.len() != 32 || y_bytes.len() != 32 {
                return Err(DidKeyError::InvalidHeader(format!(
                    "EC x/y must be 32 bytes each, got {}/{}",
                    x_bytes.len(),
                    y_bytes.len()
                )));
            }
            // SEC1 compressed: 0x02 or 0x03 | X depending on y parity.
            let prefix = if y_bytes[31] & 1 == 0 { 0x02 } else { 0x03 };
            let mut sec1 = Vec::with_capacity(33);
            sec1.push(prefix);
            sec1.extend_from_slice(&x_bytes);
            match crv {
                "P-256" => Ok(DidKeyPubkey::P256(sec1)),
                "secp256k1" => Ok(DidKeyPubkey::Secp256k1(sec1)),
                other => Err(DidKeyError::InvalidHeader(format!(
                    "EC jwk crv unsupported: {other}"
                ))),
            }
        }
        other => Err(DidKeyError::InvalidHeader(format!(
            "jwk kty unsupported: {other}"
        ))),
    }
}

fn verify_signature(
    pubkey: &DidKeyPubkey,
    msg: &[u8],
    sig: &[u8],
) -> Result<(), DidKeyError> {
    match pubkey {
        DidKeyPubkey::Ed25519(bytes) => {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            if sig.len() != 64 {
                return Err(DidKeyError::BadSignature(format!(
                    "ed25519 sig len {} (expected 64)",
                    sig.len()
                )));
            }
            let vk = VerifyingKey::from_bytes(bytes)
                .map_err(|e| DidKeyError::KeyParse(format!("ed25519 pubkey: {e}")))?;
            let mut sig_arr = [0u8; 64];
            sig_arr.copy_from_slice(sig);
            let sig = Signature::from_bytes(&sig_arr);
            vk.verify(msg, &sig)
                .map_err(|e| DidKeyError::BadSignature(format!("ed25519: {e}")))
        }
        DidKeyPubkey::P256(sec1) => {
            use p256::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
            let vk = VerifyingKey::from_sec1_bytes(sec1)
                .map_err(|e| DidKeyError::KeyParse(format!("p256 pubkey: {e}")))?;
            // JWS ES256: IEEE P1363 (r || s), 64 bytes.
            if sig.len() != 64 {
                return Err(DidKeyError::BadSignature(format!(
                    "ES256 sig len {} (expected 64)",
                    sig.len()
                )));
            }
            let sig = Signature::from_slice(sig)
                .map_err(|e| DidKeyError::BadSignature(format!("ES256 sig parse: {e}")))?;
            vk.verify(msg, &sig)
                .map_err(|e| DidKeyError::BadSignature(format!("ES256: {e}")))
        }
        DidKeyPubkey::Secp256k1(sec1) => {
            use k256::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
            let vk = VerifyingKey::from_sec1_bytes(sec1)
                .map_err(|e| DidKeyError::KeyParse(format!("secp256k1 pubkey: {e}")))?;
            if sig.len() != 64 {
                return Err(DidKeyError::BadSignature(format!(
                    "ES256K sig len {} (expected 64)",
                    sig.len()
                )));
            }
            let sig = Signature::from_slice(sig)
                .map_err(|e| DidKeyError::BadSignature(format!("ES256K sig parse: {e}")))?;
            vk.verify(msg, &sig)
                .map_err(|e| DidKeyError::BadSignature(format!("ES256K: {e}")))
        }
    }
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    jwk: Option<JwkLite>,
    #[serde(default)]
    #[allow(dead_code)]
    typ: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwkLite {
    kty: String,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwtClaims {
    htm: String,
    htu: String,
    iat: u64,
    #[serde(default)]
    exp: Option<u64>,
    #[serde(default)]
    sub: Option<String>,
}
