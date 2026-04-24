//! Access token issuance.
//!
//! Produces a DPoP-bound JWT access token that can be verified by
//! downstream resource servers via
//! `solid_pod_rs::oidc::verify_access_token` plus the JWKS published
//! at `/.well-known/jwks.json`. Matches the JSS payload shape in
//! `src/idp/credentials.js:112-137`.

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::jwks::SigningKey;

/// Errors from access-token issuance.
#[derive(Debug, Error)]
pub enum TokenError {
    /// JWT encoding failure.
    #[error("JWT encode: {0}")]
    Encode(String),
}

/// Solid-OIDC access-token payload. Named explicitly rather than
/// reusing `solid_pod_rs::oidc::SolidOidcClaims` because we own
/// *issuance* here (we control every field) whereas the core crate
/// owns *verification* (it must accept whatever upstream IdPs emit).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenPayload {
    /// Issuer URL (always trailing-slashed).
    pub iss: String,
    /// Subject — JSS matches this to `account.id`.
    pub sub: String,
    /// Audience. Solid-OIDC uses `"solid"` (JSS line 116).
    pub aud: String,
    /// WebID — the whole point of Solid-OIDC.
    pub webid: String,
    /// Issued at (seconds since Unix epoch).
    pub iat: u64,
    /// Expiry (seconds since Unix epoch).
    pub exp: u64,
    /// JWT id (random).
    pub jti: String,
    /// Requesting client id.
    pub client_id: String,
    /// OAuth2 scope string.
    pub scope: String,
    /// DPoP binding. `None` on Bearer-token issuance (no DPoP proof
    /// supplied at /token); `Some(jkt)` on DPoP-bound issuance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<CnfClaim>,
}

/// DPoP binding — SHA-256 thumbprint of the proof's embedded JWK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnfClaim {
    /// RFC 9449 §6.1 `jkt` — JWK thumbprint.
    pub jkt: String,
}

/// Wrapped access token — the signed JWT plus the payload used to
/// mint it (callers who want to emit `token_type`, `expires_in`, etc.
/// can derive them).
#[derive(Debug, Clone)]
pub struct AccessToken {
    /// Signed JWT string (header.payload.signature, base64url).
    pub jwt: String,
    /// Payload that was signed.
    pub payload: AccessTokenPayload,
}

/// Issue a DPoP-bound (or Bearer) access token.
///
/// - `signing_key` — the currently-active JWKS key. Provides the
///   `kid` header and the private key material.
/// - `issuer` — the IdP's `iss` claim. Must match the discovery
///   document's `issuer`.
/// - `webid` — subject's WebID URL. Populates both `webid` and the
///   `sub` claim (JSS populates `sub` with the account id and
///   `webid` separately; we mirror that).
/// - `account_id` — stable internal subject id.
/// - `client_id` — the OAuth2 client requesting the token.
/// - `scope` — space-separated scope string (`openid webid` is the
///   baseline).
/// - `dpop_jkt` — DPoP thumbprint, `None` for a Bearer token.
/// - `now` / `ttl_secs` — issuance + expiry.
#[allow(clippy::too_many_arguments)]
pub fn issue_access_token(
    signing_key: &SigningKey,
    issuer: &str,
    webid: &str,
    account_id: &str,
    client_id: &str,
    scope: &str,
    dpop_jkt: Option<&str>,
    now: u64,
    ttl_secs: u64,
) -> Result<AccessToken, TokenError> {
    let payload = AccessTokenPayload {
        iss: issuer.to_string(),
        sub: account_id.to_string(),
        aud: "solid".into(),
        webid: webid.to_string(),
        iat: now,
        exp: now + ttl_secs,
        jti: uuid::Uuid::new_v4().to_string(),
        client_id: client_id.to_string(),
        scope: scope.to_string(),
        cnf: dpop_jkt.map(|jkt| CnfClaim {
            jkt: jkt.to_string(),
        }),
    };

    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(signing_key.kid.clone());

    let key = EncodingKey::from_ec_der(&signing_key.private_der);

    let jwt = encode(&header, &payload, &key)
        .map_err(|e| TokenError::Encode(e.to_string()))?;
    Ok(AccessToken { jwt, payload })
}

/// Hash an access token into the base64url-encoded SHA-256 value
/// that RFC 9449 §4.3 calls `ath`. Callers who want to emit tokens
/// alongside a DPoP `ath` challenge can use this helper.
pub fn ath_hash(token: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine;
    let digest = Sha256::digest(token.as_bytes());
    B64.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwks::Jwks;

    #[test]
    fn issue_access_token_produces_signed_jwt() {
        let jwks = Jwks::generate_es256().unwrap();
        let key = jwks.active_key();
        let t = issue_access_token(
            &key,
            "https://pod.example/",
            "https://alice.example/profile#me",
            "acct-1",
            "client-xyz",
            "openid webid",
            Some("DPOP-JKT"),
            1_700_000_000,
            3600,
        )
        .unwrap();
        // Three segments, base64url.
        assert_eq!(t.jwt.matches('.').count(), 2);
        assert_eq!(t.payload.iss, "https://pod.example/");
        assert_eq!(t.payload.webid, "https://alice.example/profile#me");
        assert_eq!(t.payload.cnf.as_ref().unwrap().jkt, "DPOP-JKT");
        assert_eq!(t.payload.exp - t.payload.iat, 3600);
    }

    #[test]
    fn issue_token_without_dpop_has_no_cnf() {
        let jwks = Jwks::generate_es256().unwrap();
        let key = jwks.active_key();
        let t = issue_access_token(
            &key,
            "https://pod.example/",
            "https://a/me",
            "a",
            "c",
            "openid",
            None,
            0,
            60,
        )
        .unwrap();
        assert!(t.payload.cnf.is_none());
    }

    #[test]
    fn ath_hash_matches_known_value() {
        // Cross-check against `echo -n 'foo' | sha256sum` (base64url, no pad)
        // → LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564
        assert_eq!(ath_hash("foo"), "LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564");
    }
}
