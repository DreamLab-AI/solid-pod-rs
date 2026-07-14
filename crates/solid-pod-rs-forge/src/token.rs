//! Forge push token — a macaroon-lite HMAC bearer.
//!
//! Wire format: `f1.<b64url(json claims)>.<b64url(HMAC-SHA256)>`. The MAC
//! covers the `f1.<claims>` prefix so neither the version tag nor the
//! claims can be swapped without invalidating it. Verification is
//! constant-time (via [`hmac::Mac::verify_slice`]) and checks version +
//! expiry. Cites JSS `forge` `token.js` behaviour by name only; the
//! implementation is original.
//!
//! A token is minted from an already-authenticated caller (NIP-98 or a
//! pod session) so subsequent forge requests present the cheap bearer
//! instead of re-signing every call.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::ownership::ForgeAgent;

type HmacSha256 = Hmac<Sha256>;

/// Current token format version.
pub const TOKEN_VERSION: u8 = 1;
const PREFIX: &str = "f1.";

/// Decoded token claims.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Claims {
    /// Format version (must be [`TOKEN_VERSION`]).
    v: u8,
    /// Subject — the author id (WebID or `did:nostr:<hex>`).
    sub: String,
    /// Owner namespace (pod username or 64-hex pubkey).
    own: String,
    /// Issued-at, Unix seconds.
    iat: u64,
    /// Expiry, Unix seconds.
    exp: u64,
}

/// Token verify/mint failure modes.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenError {
    /// Not a `f1.*` token or the wrong number of segments.
    #[error("malformed token")]
    Malformed,
    /// The HMAC did not verify.
    #[error("bad signature")]
    BadMac,
    /// `exp` is in the past.
    #[error("token expired")]
    Expired,
    /// Unsupported version tag.
    #[error("unsupported token version")]
    UnsupportedVersion,
    /// The HMAC key was empty/invalid.
    #[error("invalid key")]
    Key,
}

/// Mint a token for `agent`, valid for `ttl` seconds from `iat`. Returns
/// `None` for an anonymous caller (nothing to authorise).
#[must_use]
pub fn mint(key: &[u8], agent: &ForgeAgent, iat: u64, ttl: u64) -> Option<String> {
    let (sub, own) = match agent {
        ForgeAgent::Pod { webid, username } => (webid.clone(), username.clone()),
        ForgeAgent::Nostr { pubkey_hex } => {
            (format!("did:nostr:{pubkey_hex}"), pubkey_hex.clone())
        }
        ForgeAgent::Anonymous => return None,
    };
    let claims = Claims {
        v: TOKEN_VERSION,
        sub,
        own,
        iat,
        exp: iat.saturating_add(ttl),
    };
    let claims_json = serde_json::to_vec(&claims).ok()?;
    let claims_b64 = B64.encode(claims_json);
    let signing_input = format!("{PREFIX}{claims_b64}");
    let mac = mac_tag(key, signing_input.as_bytes())?;
    Some(format!("{signing_input}.{}", B64.encode(mac)))
}

/// Verify a token at `now`, returning the reconstructed caller identity.
pub fn verify(key: &[u8], token: &str, now: u64) -> Result<ForgeAgent, TokenError> {
    let rest = token.strip_prefix(PREFIX).ok_or(TokenError::Malformed)?;
    let (claims_b64, mac_b64) = rest.split_once('.').ok_or(TokenError::Malformed)?;
    if claims_b64.is_empty() || mac_b64.is_empty() {
        return Err(TokenError::Malformed);
    }

    // Recompute + constant-time compare over the exact signing input.
    let signing_input = format!("{PREFIX}{claims_b64}");
    let provided = B64.decode(mac_b64).map_err(|_| TokenError::Malformed)?;
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| TokenError::Key)?;
    mac.update(signing_input.as_bytes());
    mac.verify_slice(&provided).map_err(|_| TokenError::BadMac)?;

    // MAC is valid → decode and check the claims.
    let claims_json = B64.decode(claims_b64).map_err(|_| TokenError::Malformed)?;
    let claims: Claims = serde_json::from_slice(&claims_json).map_err(|_| TokenError::Malformed)?;
    if claims.v != TOKEN_VERSION {
        return Err(TokenError::UnsupportedVersion);
    }
    if claims.exp <= now {
        return Err(TokenError::Expired);
    }

    Ok(if crate::ownership::classify_owner(&claims.own)
        == crate::ownership::OwnerKind::NostrHex
    {
        ForgeAgent::Nostr {
            pubkey_hex: claims.own,
        }
    } else {
        ForgeAgent::Pod {
            webid: claims.sub,
            username: claims.own,
        }
    })
}

fn mac_tag(key: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).ok()?;
    mac.update(msg);
    Some(mac.finalize().into_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"test-hmac-key-32-bytes-exactly!!";

    fn nostr() -> ForgeAgent {
        ForgeAgent::Nostr {
            pubkey_hex: "a".repeat(64),
        }
    }
    fn pod() -> ForgeAgent {
        ForgeAgent::Pod {
            webid: "https://pod/alice/card#me".into(),
            username: "alice".into(),
        }
    }

    #[test]
    fn mint_verify_roundtrip_nostr() {
        let t = mint(KEY, &nostr(), 1000, 3600).unwrap();
        assert!(t.starts_with("f1."));
        let agent = verify(KEY, &t, 1500).unwrap();
        assert_eq!(agent, nostr());
    }

    #[test]
    fn mint_verify_roundtrip_pod() {
        let t = mint(KEY, &pod(), 1000, 3600).unwrap();
        let agent = verify(KEY, &t, 1500).unwrap();
        assert_eq!(agent, pod());
    }

    #[test]
    fn anonymous_mints_nothing() {
        assert!(mint(KEY, &ForgeAgent::Anonymous, 0, 1).is_none());
    }

    #[test]
    fn expired_token_rejected() {
        let t = mint(KEY, &nostr(), 1000, 100).unwrap();
        assert_eq!(verify(KEY, &t, 2000), Err(TokenError::Expired));
    }

    #[test]
    fn tampered_claims_fail_mac() {
        let t = mint(KEY, &nostr(), 1000, 3600).unwrap();
        // Flip a char in the claims section.
        let (head, tail) = t.split_once('.').unwrap();
        let (claims, mac) = tail.split_once('.').unwrap();
        let mut cb = claims.as_bytes().to_vec();
        cb[0] ^= 0x01;
        let tampered = format!(
            "{head}.{}.{mac}",
            String::from_utf8_lossy(&cb)
        );
        assert!(matches!(
            verify(KEY, &tampered, 1500),
            Err(TokenError::BadMac) | Err(TokenError::Malformed)
        ));
    }

    #[test]
    fn wrong_key_fails_mac() {
        let t = mint(KEY, &nostr(), 1000, 3600).unwrap();
        assert_eq!(verify(b"another-key-entirely-different!!", &t, 1500), Err(TokenError::BadMac));
    }

    #[test]
    fn malformed_tokens_rejected() {
        assert_eq!(verify(KEY, "nope", 0), Err(TokenError::Malformed));
        assert_eq!(verify(KEY, "f1.only-one", 0), Err(TokenError::Malformed));
        assert_eq!(verify(KEY, "f1..", 0), Err(TokenError::Malformed));
    }
}
