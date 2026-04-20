//! RFC 9421 HTTP Message Signatures for outgoing webhook deliveries.
//!
//! Profile
//! -------
//! * Algorithm: **Ed25519** (RFC 8032) — compact 64-byte signatures.
//! * Single-key per channel — one [`SignerConfig`] per
//!   [`WebhookChannelManager`](super::WebhookChannelManager).
//! * Signature label: `sig1`.
//! * Covered components: `@method`, `@target-uri`, `content-type`,
//!   `content-digest`, `date`, `x-solid-notification-id`.
//! * `Signature-Input` parameters: `alg="ed25519"`, `created=<unix>`,
//!   `keyid="<channel id>"`.
//!
//! This module is compiled only with the `webhook-signing` Cargo
//! feature. Both [`sign_request`] and [`verify_signed_request`] are
//! exported so that receivers using this crate can authenticate
//! incoming pod deliveries symmetrically.
//!
//! Reference: <https://www.rfc-editor.org/rfc/rfc9421.html>

use std::time::{Duration, SystemTime};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Ordered list of components covered by the signature. The order here
/// is significant — it is reproduced verbatim in both the signing
/// input and the `Signature-Input` header so that recomputation on the
/// receiver side yields byte-identical bytes.
pub const COVERED_COMPONENTS: &[&str] = &[
    "@method",
    "@target-uri",
    "content-type",
    "content-digest",
    "date",
    "x-solid-notification-id",
];

/// Per-channel signer configuration.
#[derive(Clone)]
pub struct SignerConfig {
    /// Stable identifier published to receivers via the `keyid`
    /// parameter. Typically the subscription/channel ID.
    pub keyid: String,
    /// Ed25519 secret key used to sign outgoing requests.
    pub key: SigningKey,
}

impl std::fmt::Debug for SignerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerConfig")
            .field("keyid", &self.keyid)
            // SigningKey intentionally omitted — never log private key
            // material.
            .finish_non_exhaustive()
    }
}

/// A request body paired with the full set of headers required to
/// authenticate it per RFC 9421.
#[derive(Debug, Clone)]
pub struct SignedRequest {
    /// Ordered list of `(header-name, header-value)` pairs. Names are
    /// lowercased; `Signature-Input` and `Signature` are always
    /// included.
    pub headers: Vec<(String, String)>,
    /// Request body — unchanged from the caller's input.
    pub body: Vec<u8>,
}

/// Errors raised by [`verify_signed_request`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SignatureError {
    #[error("missing required header: {0}")]
    MissingHeader(&'static str),
    #[error("malformed Signature-Input header")]
    MalformedInput,
    #[error("malformed Signature header")]
    MalformedSignature,
    #[error("keyid mismatch: expected {expected}, got {got}")]
    KeyIdMismatch { expected: String, got: String },
    #[error("content-digest mismatch")]
    DigestMismatch,
    #[error("signature verification failed")]
    BadSignature,
    #[error("base64 decode error: {0}")]
    Base64(String),
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// Build the signing input string per RFC 9421 §2.5. The same helper
/// is reused by [`verify_signed_request`] so that both paths agree on
/// the exact bytes to hash.
fn build_signature_base(
    method: &str,
    target_uri: &str,
    content_type: &str,
    content_digest: &str,
    date: &str,
    notification_id: &str,
    created: u64,
    keyid: &str,
) -> String {
    // RFC 9421 §2.5: one covered-component line per entry, then the
    // `@signature-params` line carrying the parameters.
    let mut s = String::with_capacity(512);
    s.push_str(&format!("\"@method\": {}\n", method.to_uppercase()));
    s.push_str(&format!("\"@target-uri\": {}\n", target_uri));
    s.push_str(&format!("\"content-type\": {}\n", content_type));
    s.push_str(&format!("\"content-digest\": {}\n", content_digest));
    s.push_str(&format!("\"date\": {}\n", date));
    s.push_str(&format!(
        "\"x-solid-notification-id\": {}\n",
        notification_id
    ));
    s.push_str(&format!(
        "\"@signature-params\": {}",
        signature_params_value(created, keyid)
    ));
    s
}

/// Render the structured-field value that appears both inside the
/// `Signature-Input` header and as the `@signature-params` line of the
/// signing base.
fn signature_params_value(created: u64, keyid: &str) -> String {
    // Covered-component list is an inner list of strings.
    let mut list = String::from("(");
    for (i, c) in COVERED_COMPONENTS.iter().enumerate() {
        if i > 0 {
            list.push(' ');
        }
        list.push('"');
        list.push_str(c);
        list.push('"');
    }
    list.push(')');
    format!(
        "{list};created={created};keyid=\"{keyid}\";alg=\"ed25519\"",
        list = list,
        created = created,
        keyid = keyid,
    )
}

/// Sign an outgoing request. The returned [`SignedRequest`] carries
/// all headers — including `Content-Digest`, `Date`,
/// `X-Solid-Notification-Id`, `Signature-Input`, and `Signature` — that
/// the caller must attach to the HTTP request, plus the unchanged body.
pub fn sign_request(
    cfg: &SignerConfig,
    method: &str,
    target_uri: &str,
    content_type: &str,
    body: &[u8],
    notification_id: &str,
    now_unix: u64,
) -> SignedRequest {
    // 1. Content-Digest (RFC 9530): "sha-256=:<base64>:".
    let content_digest = content_digest_header(body);

    // 2. HTTP Date (RFC 7231 §7.1.1.1).
    let date = httpdate::fmt_http_date(SystemTime::UNIX_EPOCH + Duration::from_secs(now_unix));

    // 3. Build the signing base and produce the Ed25519 signature.
    let base = build_signature_base(
        method,
        target_uri,
        content_type,
        &content_digest,
        &date,
        notification_id,
        now_unix,
        &cfg.keyid,
    );
    let sig: Signature = cfg.key.sign(base.as_bytes());
    let sig_b64 = B64.encode(sig.to_bytes());

    // 4. Assemble the RFC 9421 headers.
    let signature_input = format!(
        "sig1={}",
        signature_params_value(now_unix, &cfg.keyid)
    );
    let signature = format!("sig1=:{}:", sig_b64);

    let headers = vec![
        ("content-type".to_string(), content_type.to_string()),
        ("content-digest".to_string(), content_digest),
        ("date".to_string(), date),
        (
            "x-solid-notification-id".to_string(),
            notification_id.to_string(),
        ),
        ("signature-input".to_string(), signature_input),
        ("signature".to_string(), signature),
    ];

    SignedRequest {
        headers,
        body: body.to_vec(),
    }
}

/// Compute the `Content-Digest` header value for `body` using SHA-256,
/// formatted per RFC 9530 §2.
pub fn content_digest_header(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    format!("sha-256=:{}:", B64.encode(digest))
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Look up a header by case-insensitive name in a slice of
/// `(name, value)` pairs.
fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Parse the `Signature-Input` header and extract `(created, keyid)`
/// for the `sig1` label. This is deliberately permissive about
/// whitespace but strict about the covered-component list — if a
/// receiver sees a different component set, it should reject the
/// request outright (returned here as [`SignatureError::MalformedInput`]).
fn parse_signature_input(
    raw: &str,
) -> Result<(u64, String), SignatureError> {
    // Strip the "sig1=" prefix.
    let after = raw
        .strip_prefix("sig1=")
        .ok_or(SignatureError::MalformedInput)?;
    // Expect inner list "(\"@method\" ... )" followed by ";created=...;keyid=\"...\";alg=\"ed25519\"".
    let list_end = after.find(')').ok_or(SignatureError::MalformedInput)?;
    let list = &after[..=list_end];
    let expected_list = {
        let mut s = String::from("(");
        for (i, c) in COVERED_COMPONENTS.iter().enumerate() {
            if i > 0 {
                s.push(' ');
            }
            s.push('"');
            s.push_str(c);
            s.push('"');
        }
        s.push(')');
        s
    };
    if list != expected_list {
        return Err(SignatureError::MalformedInput);
    }
    let params = &after[list_end + 1..];
    // params looks like ";created=...;keyid=\"...\";alg=\"ed25519\"" —
    // walk through semicolon-separated kv pairs.
    let mut created: Option<u64> = None;
    let mut keyid: Option<String> = None;
    for part in params.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (k, v) = part
            .split_once('=')
            .ok_or(SignatureError::MalformedInput)?;
        match k {
            "created" => {
                created = Some(v.parse().map_err(|_| SignatureError::MalformedInput)?);
            }
            "keyid" => {
                let v = v
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .ok_or(SignatureError::MalformedInput)?;
                keyid = Some(v.to_string());
            }
            "alg" => {
                let v = v
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .ok_or(SignatureError::MalformedInput)?;
                if v != "ed25519" {
                    return Err(SignatureError::MalformedInput);
                }
            }
            _ => {}
        }
    }
    Ok((
        created.ok_or(SignatureError::MalformedInput)?,
        keyid.ok_or(SignatureError::MalformedInput)?,
    ))
}

/// Parse the `Signature` header's `sig1=:<base64>:` form and return
/// the decoded bytes.
fn parse_signature_header(raw: &str) -> Result<Vec<u8>, SignatureError> {
    let after = raw
        .strip_prefix("sig1=:")
        .and_then(|s| s.strip_suffix(':'))
        .ok_or(SignatureError::MalformedSignature)?;
    B64.decode(after)
        .map_err(|e| SignatureError::Base64(e.to_string()))
}

/// Verify a previously-signed request. This checks:
///
/// 1. `Content-Digest` matches the actual body bytes.
/// 2. `Signature-Input` uses the expected component set and `ed25519`
///    algorithm.
/// 3. `keyid` matches the expected channel identifier.
/// 4. The Ed25519 signature over the reconstructed signing base is
///    valid under `pubkey`.
pub fn verify_signed_request(
    pubkey: &VerifyingKey,
    expected_keyid: &str,
    headers: &[(String, String)],
    method: &str,
    target_uri: &str,
    body: &[u8],
) -> Result<(), SignatureError> {
    let sig_input = find_header(headers, "signature-input")
        .ok_or(SignatureError::MissingHeader("signature-input"))?;
    let sig_value =
        find_header(headers, "signature").ok_or(SignatureError::MissingHeader("signature"))?;
    let content_type = find_header(headers, "content-type")
        .ok_or(SignatureError::MissingHeader("content-type"))?;
    let received_digest = find_header(headers, "content-digest")
        .ok_or(SignatureError::MissingHeader("content-digest"))?;
    let date =
        find_header(headers, "date").ok_or(SignatureError::MissingHeader("date"))?;
    let notification_id = find_header(headers, "x-solid-notification-id")
        .ok_or(SignatureError::MissingHeader("x-solid-notification-id"))?;

    // 1. Digest check — prevents body tampering.
    let computed = content_digest_header(body);
    if computed != received_digest {
        return Err(SignatureError::DigestMismatch);
    }

    // 2/3. Parse input and check keyid.
    let (created, keyid) = parse_signature_input(sig_input)?;
    if keyid != expected_keyid {
        return Err(SignatureError::KeyIdMismatch {
            expected: expected_keyid.to_string(),
            got: keyid,
        });
    }

    // 4. Rebuild the signing base and verify.
    let base = build_signature_base(
        method,
        target_uri,
        content_type,
        received_digest,
        date,
        notification_id,
        created,
        &keyid,
    );
    let sig_bytes = parse_signature_header(sig_value)?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| SignatureError::MalformedSignature)?;
    let signature = Signature::from_bytes(&sig_arr);
    pubkey
        .verify(base.as_bytes(), &signature)
        .map_err(|_| SignatureError::BadSignature)
}

// ---------------------------------------------------------------------------
// Unit tests — happy path only; cross-cutting coverage lives in
// tests/webhook_signing.rs.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn fresh_key(seed: u8) -> SigningKey {
        let bytes = [seed; 32];
        SigningKey::from_bytes(&bytes)
    }

    #[test]
    fn content_digest_is_rfc9530_shaped() {
        let d = content_digest_header(b"hello");
        assert!(d.starts_with("sha-256=:"));
        assert!(d.ends_with(':'));
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let sk = fresh_key(7);
        let vk = sk.verifying_key();
        let cfg = SignerConfig {
            keyid: "chan-test".into(),
            key: sk,
        };
        let body = br#"{"hello":"world"}"#;
        let signed = sign_request(
            &cfg,
            "POST",
            "https://example.com/hook",
            "application/ld+json",
            body,
            "urn:uuid:00000000-0000-0000-0000-000000000001",
            1_700_000_000,
        );
        verify_signed_request(
            &vk,
            "chan-test",
            &signed.headers,
            "POST",
            "https://example.com/hook",
            body,
        )
        .expect("signature must verify");
    }
}
