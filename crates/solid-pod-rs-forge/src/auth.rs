//! Caller-identity resolution for forge requests.
//!
//! Three schemes, tried in order (cites JSS `forge` auth by name only):
//!
//! 1. **Forge push token** — `Authorization: Bearer f1.…` verified by
//!    [`crate::token::verify`] (cheap HMAC, no signature per call).
//! 2. **Pod session** — the embedding server's own `getAgent`/WAC layer
//!    resolves a pod account and passes a [`ForgeAgent::Pod`] directly to
//!    [`crate::ForgeService::handle`]; this module does not re-resolve it.
//! 3. **NIP-98** — `Authorization: Nostr <base64>` verified by the core
//!    [`solid_pod_rs::auth::nip98`] verifier (real Schnorr when the
//!    `nip98-schnorr` feature is unified in, fail-closed otherwise).
//!
//! Any failure resolves to [`ForgeAgent::Anonymous`]; the service's
//! guards then decide, fail-closed.

use solid_pod_rs::auth::nip98;
use solid_pod_rs::did_nostr_types::is_valid_hex_pubkey;

use crate::ownership::ForgeAgent;
use crate::request::ForgeRequest;

/// Resolve a [`ForgeAgent`] from the request's `Authorization` header.
/// `token_key` is the forge instance HMAC key; `now` is the current Unix
/// time (injected for deterministic testing).
#[must_use]
pub fn resolve_agent(req: &ForgeRequest, token_key: &[u8], now: u64) -> ForgeAgent {
    let Some(authz) = req.header("authorization") else {
        return ForgeAgent::Anonymous;
    };

    // Scheme 1: forge push token.
    if let Some(bearer) = authz.strip_prefix("Bearer ") {
        let bearer = bearer.trim();
        if bearer.starts_with("f1.") {
            if let Ok(agent) = crate::token::verify(token_key, bearer, now) {
                return agent;
            }
            return ForgeAgent::Anonymous;
        }
    }

    // Scheme 3: NIP-98 (scheme 2, pod session, is injected by the server).
    if authz.starts_with(nip98_prefix()) {
        let url = req.absolute_url();
        let body = if req.raw_body.is_empty() {
            None
        } else {
            Some(req.raw_body.as_ref())
        };
        if let Ok(v) = nip98::verify_at(authz, &url, &req.method.to_uppercase(), body, now) {
            if is_valid_hex_pubkey(&v.pubkey) {
                return ForgeAgent::Nostr {
                    pubkey_hex: v.pubkey,
                };
            }
        }
    }

    ForgeAgent::Anonymous
}

fn nip98_prefix() -> &'static str {
    "Nostr "
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    const KEY: &[u8] = b"forge-instance-hmac-key-0123456789";

    fn req_with_auth(authz: Option<&str>) -> ForgeRequest {
        ForgeRequest {
            method: "GET".into(),
            path: "/forge/x".into(),
            query: String::new(),
            headers: authz
                .map(|a| vec![("authorization".to_string(), a.to_string())])
                .unwrap_or_default(),
            raw_body: Bytes::new(),
            host_url: Some("https://pod.example".into()),
        }
    }

    #[test]
    fn no_header_is_anonymous() {
        assert_eq!(
            resolve_agent(&req_with_auth(None), KEY, 0),
            ForgeAgent::Anonymous
        );
    }

    #[test]
    fn valid_forge_token_resolves() {
        let agent = ForgeAgent::Nostr {
            pubkey_hex: "c".repeat(64),
        };
        let tok = crate::token::mint(KEY, &agent, 1000, 3600).unwrap();
        let req = req_with_auth(Some(&format!("Bearer {tok}")));
        assert_eq!(resolve_agent(&req, KEY, 1500), agent);
    }

    #[test]
    fn expired_or_tampered_token_is_anonymous() {
        let agent = ForgeAgent::Nostr {
            pubkey_hex: "c".repeat(64),
        };
        let tok = crate::token::mint(KEY, &agent, 1000, 10).unwrap();
        let req = req_with_auth(Some(&format!("Bearer {tok}")));
        // Expired.
        assert_eq!(resolve_agent(&req, KEY, 9999), ForgeAgent::Anonymous);
        // Wrong key.
        assert_eq!(
            resolve_agent(&req, b"different-key-abcdefghijklmn", 1500),
            ForgeAgent::Anonymous
        );
    }

    #[test]
    fn non_forge_bearer_is_anonymous() {
        let req = req_with_auth(Some("Bearer some-oauth-jwt"));
        assert_eq!(resolve_agent(&req, KEY, 0), ForgeAgent::Anonymous);
    }

    #[test]
    fn malformed_nip98_is_anonymous() {
        // Without the nip98-schnorr feature unified in, verification fails
        // closed; with a garbage token it is Anonymous regardless.
        let req = req_with_auth(Some("Nostr bm90LWEtdmFsaWQ="));
        assert_eq!(resolve_agent(&req, KEY, 0), ForgeAgent::Anonymous);
    }
}
