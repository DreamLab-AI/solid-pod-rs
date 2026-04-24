//! Authentication bridge — converts a `Basic nostr:<token>` request
//! header into a NIP-98 verification call, mirroring the JSS behaviour
//! where a `Basic` auth line whose username is `nostr` and whose
//! password is a base64-encoded NIP-98 event is accepted by the git
//! handler (PARITY row 69).
//!
//! The JSS server layers this bridge on top of the normal NIP-98
//! `Authorization: Nostr <b64>` scheme so that off-the-shelf
//! HTTP-Basic Git clients (e.g. the stock `git` CLI with a credential
//! helper) can still push/pull against a Nostr-authenticated pod.

use std::sync::Arc;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use thiserror::Error;

use crate::service::GitRequest;

/// Auth failures exposed to the HTTP surface.
#[derive(Debug, Error)]
pub enum AuthError {
    /// No `Authorization` header on a write request.
    #[error("missing Authorization header")]
    Missing,

    /// The `Authorization` header was present but malformed.
    #[error("malformed Authorization header: {0}")]
    Malformed(String),

    /// The credential decoded cleanly but the NIP-98 verifier
    /// rejected it (bad sig, URL mismatch, stale, …). The inner
    /// string is the verifier's error text.
    #[error("NIP-98 verification failed: {0}")]
    Verification(String),
}

/// Pluggable authoriser invoked by the service on write operations.
///
/// The default implementation ([`BasicNostrExtractor`]) fits the JSS
/// behaviour. Consumers embedding the service in a server that has
/// its own richer auth stack can supply their own implementation.
#[async_trait]
pub trait GitAuth: Send + Sync {
    /// Inspect `req` and either return `Ok(webid_or_pubkey)` — the
    /// identity string the CGI layer will expose in `REMOTE_USER` —
    /// or `Err(AuthError)`.
    async fn authorise(&self, req: &GitRequest) -> Result<String, AuthError>;
}

/// The canonical JSS-parity authoriser.
///
/// Parses `Authorization: Basic <b64(nostr:<token>)>` headers,
/// base64-decodes, splits on the first `:`, verifies the username is
/// literally `nostr`, then treats the remainder as a NIP-98 event
/// token and delegates to `solid_pod_rs::auth::nip98::verify_at`.
///
/// The URL verified against is reconstructed from the request's
/// scheme/host/path; see [`GitRequest::auth_url`].
#[derive(Clone, Debug, Default)]
pub struct BasicNostrExtractor {
    /// Allow-list of pubkeys. Empty means accept any valid NIP-98
    /// signature (the JSS default).
    allowed_pubkeys: Option<Arc<Vec<String>>>,
}

impl BasicNostrExtractor {
    /// Construct a default extractor (no pubkey allow-list).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restrict to the given hex pubkeys (lowercase).
    #[must_use]
    pub fn with_allowed(mut self, pubkeys: Vec<String>) -> Self {
        self.allowed_pubkeys = Some(Arc::new(
            pubkeys.into_iter().map(|p| p.to_lowercase()).collect(),
        ));
        self
    }

    /// Strip the `Basic ` prefix, base64-decode, split on the first
    /// colon, and validate the username is `nostr`. Returns the raw
    /// NIP-98 token (the password half).
    pub fn extract_nostr_token(header_value: &str) -> Result<String, AuthError> {
        let b64 = header_value
            .strip_prefix("Basic ")
            .ok_or_else(|| AuthError::Malformed("not a Basic scheme".into()))?
            .trim();

        let decoded = BASE64
            .decode(b64)
            .map_err(|e| AuthError::Malformed(format!("base64 decode: {e}")))?;
        let creds = String::from_utf8(decoded)
            .map_err(|e| AuthError::Malformed(format!("utf-8 decode: {e}")))?;

        let (user, pass) = creds
            .split_once(':')
            .ok_or_else(|| AuthError::Malformed("no colon in credentials".into()))?;
        if user != "nostr" {
            return Err(AuthError::Malformed(format!(
                "expected username 'nostr', got '{user}'"
            )));
        }
        if pass.is_empty() {
            return Err(AuthError::Malformed("empty token".into()));
        }
        Ok(pass.to_string())
    }
}

#[async_trait]
impl GitAuth for BasicNostrExtractor {
    async fn authorise(&self, req: &GitRequest) -> Result<String, AuthError> {
        // Pull the Authorization header (case-insensitive match).
        let auth_header = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v.as_str())
            .ok_or(AuthError::Missing)?;

        let token = if let Some(stripped) = auth_header.strip_prefix("Basic ") {
            // Re-use the Basic-scheme extractor.
            Self::extract_nostr_token(&format!("Basic {stripped}"))?
        } else if let Some(stripped) = auth_header.strip_prefix("Nostr ") {
            // Also accept a raw Nostr scheme — JSS git.js hands the
            // request through to the normal NIP-98 middleware which
            // handles this.
            stripped.trim().to_string()
        } else {
            return Err(AuthError::Malformed(
                "unknown Authorization scheme".into(),
            ));
        };

        // Wrap the raw token back into the `Nostr ` header shape that
        // the core verifier expects.
        let nostr_header = format!("Nostr {token}");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let verified = solid_pod_rs::auth::nip98::verify_at(
            &nostr_header,
            &req.auth_url(),
            &req.method,
            // body hashing: git push bodies are large & binary; the
            // JSS bridge verifies structure + URL + method only for
            // compatibility with stock git clients that cannot sign
            // the body (they have no Nostr keypair during push).
            None,
            now,
        )
        .map_err(|e| AuthError::Verification(format!("{e:?}")))?;

        if let Some(allowed) = &self.allowed_pubkeys {
            let pk = verified.pubkey.to_lowercase();
            if !allowed.contains(&pk) {
                return Err(AuthError::Verification(format!(
                    "pubkey not in allow-list: {pk}"
                )));
            }
        }

        Ok(verified.pubkey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_rejects_non_basic_scheme() {
        let err = BasicNostrExtractor::extract_nostr_token("Bearer abc").unwrap_err();
        assert!(matches!(err, AuthError::Malformed(_)));
    }

    #[test]
    fn extract_rejects_bad_base64() {
        let err = BasicNostrExtractor::extract_nostr_token("Basic !!!not-base64!!!").unwrap_err();
        assert!(matches!(err, AuthError::Malformed(_)));
    }

    #[test]
    fn extract_rejects_missing_colon() {
        // base64("nostronlynocolon")
        let b64 = BASE64.encode(b"nostronlynocolon");
        let err = BasicNostrExtractor::extract_nostr_token(&format!("Basic {b64}")).unwrap_err();
        assert!(matches!(err, AuthError::Malformed(_)));
    }

    #[test]
    fn extract_rejects_wrong_user() {
        let b64 = BASE64.encode(b"alice:sometoken");
        let err = BasicNostrExtractor::extract_nostr_token(&format!("Basic {b64}")).unwrap_err();
        assert!(matches!(err, AuthError::Malformed(_)));
    }

    #[test]
    fn extract_rejects_empty_token() {
        let b64 = BASE64.encode(b"nostr:");
        let err = BasicNostrExtractor::extract_nostr_token(&format!("Basic {b64}")).unwrap_err();
        assert!(matches!(err, AuthError::Malformed(_)));
    }

    #[test]
    fn extract_accepts_valid_shape() {
        let b64 = BASE64.encode(b"nostr:someopaquetoken");
        let tok = BasicNostrExtractor::extract_nostr_token(&format!("Basic {b64}")).unwrap();
        assert_eq!(tok, "someopaquetoken");
    }
}
