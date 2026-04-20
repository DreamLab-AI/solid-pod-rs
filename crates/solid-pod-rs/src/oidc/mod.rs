//! Solid-OIDC 0.1 — server-side.
//!
//! This module is feature-gated (`oidc`) because it pulls in
//! `jsonwebtoken` for DPoP verification and `openidconnect` for
//! types/primitives that consumer crates may want to reuse.
//!
//! Responsibilities:
//!
//! - **Dynamic Client Registration** (RFC 7591).
//! - **OIDC Discovery** document (`/.well-known/openid-configuration`).
//! - **DPoP-bound access token verification** per Solid-OIDC 0.1.
//!   The bearer token is a JWT; the `cnf.jkt` claim is compared
//!   against the SHA-256 thumbprint of the DPoP proof's `jwk` header.
//! - **WebID extraction** from either the `webid` claim or the URL
//!   form of `sub`.
//! - **Token introspection** (RFC 7662) response builder.
//!
//! Reference: <https://solid.github.io/solid-oidc/>
//! Reference: <https://datatracker.ietf.org/doc/html/rfc9449> (DPoP)

#![cfg(feature = "oidc")]

use std::collections::{BTreeMap, HashMap};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL;
use base64::Engine;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::debug;

use crate::error::PodError;

// F5 (Sprint 4): DPoP jti replay cache, gated behind
// `dpop-replay-cache`. The module compiles to nothing without the
// feature so pre-F5 consumers see zero surface change.
#[cfg(feature = "dpop-replay-cache")]
pub mod replay;

#[cfg(feature = "dpop-replay-cache")]
pub use replay::{
    DpopReplayCache, ReplayError, ReplayRejectedCounter, DPOP_REPLAY_REJECTED_TOTAL,
};

// Sprint 5 P0-2: SSRF-guarded JWKS + OIDC discovery fetcher.
pub mod jwks;

// ---------------------------------------------------------------------------
// Dynamic Client Registration (RFC 7591)
// ---------------------------------------------------------------------------

/// Client registration request body (RFC 7591 §2).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientRegistrationRequest {
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub client_uri: Option<String>,
    #[serde(default)]
    pub grant_types: Vec<String>,
    #[serde(default)]
    pub response_types: Vec<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    /// Solid-OIDC §5.1: presence of this implies the client is a
    /// public app identified by a public client id document.
    #[serde(default)]
    pub application_type: Option<String>,
}

/// Client registration response body (RFC 7591 §3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRegistrationResponse {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub client_id_issued_at: u64,
    pub client_secret_expires_at: u64,
    #[serde(flatten)]
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Register a client. Real servers persist this; callers should wrap
/// with their own storage.
pub fn register_client(
    req: &ClientRegistrationRequest,
    now: u64,
) -> ClientRegistrationResponse {
    let client_id = format!("client-{}", uuid::Uuid::new_v4());
    let client_secret = match req.token_endpoint_auth_method.as_deref() {
        Some("none") => None,
        _ => Some(format!("secret-{}", uuid::Uuid::new_v4())),
    };
    let mut metadata = HashMap::new();
    metadata.insert(
        "redirect_uris".into(),
        serde_json::to_value(&req.redirect_uris).unwrap_or_default(),
    );
    if let Some(name) = &req.client_name {
        metadata.insert("client_name".into(), serde_json::Value::String(name.clone()));
    }
    if let Some(scope) = &req.scope {
        metadata.insert("scope".into(), serde_json::Value::String(scope.clone()));
    }
    if !req.grant_types.is_empty() {
        metadata.insert(
            "grant_types".into(),
            serde_json::to_value(&req.grant_types).unwrap_or_default(),
        );
    }
    if !req.response_types.is_empty() {
        metadata.insert(
            "response_types".into(),
            serde_json::to_value(&req.response_types).unwrap_or_default(),
        );
    }
    ClientRegistrationResponse {
        client_id,
        client_secret,
        client_id_issued_at: now,
        client_secret_expires_at: 0,
        metadata,
    }
}

// ---------------------------------------------------------------------------
// Discovery document
// ---------------------------------------------------------------------------

/// OIDC discovery document subset used by Solid-OIDC clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub registration_endpoint: String,
    pub introspection_endpoint: String,
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub dpop_signing_alg_values_supported: Vec<String>,
    pub solid_oidc_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
}

/// Build the Solid-OIDC discovery document for an issuer.
pub fn discovery_for(issuer: &str) -> DiscoveryDocument {
    let b = issuer.trim_end_matches('/');
    DiscoveryDocument {
        issuer: b.to_string(),
        authorization_endpoint: format!("{b}/authorize"),
        token_endpoint: format!("{b}/token"),
        userinfo_endpoint: format!("{b}/userinfo"),
        jwks_uri: format!("{b}/jwks"),
        registration_endpoint: format!("{b}/register"),
        introspection_endpoint: format!("{b}/introspect"),
        scopes_supported: vec![
            "openid".into(),
            "profile".into(),
            "webid".into(),
            "offline_access".into(),
        ],
        response_types_supported: vec!["code".into(), "id_token".into()],
        grant_types_supported: vec![
            "authorization_code".into(),
            "refresh_token".into(),
            "client_credentials".into(),
        ],
        token_endpoint_auth_methods_supported: vec![
            "client_secret_basic".into(),
            "client_secret_post".into(),
            "private_key_jwt".into(),
            "none".into(),
        ],
        dpop_signing_alg_values_supported: vec!["ES256".into(), "RS256".into()],
        solid_oidc_supported: vec!["https://solidproject.org/TR/solid-oidc".into()],
        id_token_signing_alg_values_supported: vec!["RS256".into(), "ES256".into()],
    }
}

// ---------------------------------------------------------------------------
// JWK thumbprint (RFC 7638)
// ---------------------------------------------------------------------------

/// Minimal JWK representation (Solid-OIDC only cares about the
/// canonical member set for thumbprint computation).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    #[serde(rename = "use")]
    pub use_: Option<String>,

    // EC keys
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,

    // RSA keys
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,

    // Symmetric (for testing)
    #[serde(default)]
    pub k: Option<String>,
}

impl Jwk {
    /// RFC 7638 JWK thumbprint — SHA-256 over the canonical JSON of
    /// the key-type-specific required members.
    ///
    /// # Canonicalisation
    ///
    /// Per RFC 7638 §3.2, the thumbprint input is the JSON encoding
    /// of an object whose members are EXACTLY the required members
    /// for the key type (any optional member — `alg`, `kid`, `use`,
    /// etc. — is excluded) sorted lexicographically with no
    /// whitespace. We build the object with `BTreeMap<&str, &str>`
    /// + `serde_json::to_vec` to guarantee:
    ///
    /// - lexicographic ordering of member names,
    /// - minimal whitespace (the `serde_json` default for `to_vec`),
    /// - no stray members leaking in if the struct layout changes.
    ///
    /// # Key types
    ///
    /// - **EC** (RFC 7638 §3.2 example 2):
    ///   `{"crv":...,"kty":"EC","x":...,"y":...}`
    /// - **RSA** (RFC 7638 §3.1 worked example):
    ///   `{"e":...,"kty":"RSA","n":...}`
    /// - **OKP** (Ed25519 / Ed448):
    ///   `{"crv":...,"kty":"OKP","x":...}`
    /// - **oct** (symmetric — for test-only HS256 flows):
    ///   `{"k":...,"kty":"oct"}`
    ///
    /// Unknown key types are rejected with [`PodError::Unsupported`].
    pub fn thumbprint(&self) -> Result<String, PodError> {
        let mut map: BTreeMap<&str, &str> = BTreeMap::new();
        match self.kty.as_str() {
            "EC" => {
                let crv = self
                    .crv
                    .as_deref()
                    .ok_or_else(|| PodError::Unsupported("EC JWK missing crv".into()))?;
                let x = self
                    .x
                    .as_deref()
                    .ok_or_else(|| PodError::Unsupported("EC JWK missing x".into()))?;
                let y = self
                    .y
                    .as_deref()
                    .ok_or_else(|| PodError::Unsupported("EC JWK missing y".into()))?;
                map.insert("crv", crv);
                map.insert("kty", "EC");
                map.insert("x", x);
                map.insert("y", y);
            }
            "RSA" => {
                let e = self
                    .e
                    .as_deref()
                    .ok_or_else(|| PodError::Unsupported("RSA JWK missing e".into()))?;
                let n = self
                    .n
                    .as_deref()
                    .ok_or_else(|| PodError::Unsupported("RSA JWK missing n".into()))?;
                map.insert("e", e);
                map.insert("kty", "RSA");
                map.insert("n", n);
            }
            "OKP" => {
                let crv = self
                    .crv
                    .as_deref()
                    .ok_or_else(|| PodError::Unsupported("OKP JWK missing crv".into()))?;
                let x = self
                    .x
                    .as_deref()
                    .ok_or_else(|| PodError::Unsupported("OKP JWK missing x".into()))?;
                map.insert("crv", crv);
                map.insert("kty", "OKP");
                map.insert("x", x);
            }
            "oct" => {
                let k = self
                    .k
                    .as_deref()
                    .ok_or_else(|| PodError::Unsupported("oct JWK missing k".into()))?;
                map.insert("k", k);
                map.insert("kty", "oct");
            }
            other => {
                return Err(PodError::Unsupported(format!(
                    "unsupported JWK kty: {other}"
                )));
            }
        };
        let bytes = serde_json::to_vec(&map)
            .map_err(|e| PodError::Nip98(format!("JWK thumbprint canonical JSON: {e}")))?;
        let hash = Sha256::digest(&bytes);
        Ok(BASE64_URL.encode(hash))
    }
}

// ---------------------------------------------------------------------------
// DPoP proof verification
// ---------------------------------------------------------------------------

/// DPoP proof header claims that matter for the server.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DpopHeader {
    pub typ: String,
    pub alg: String,
    pub jwk: Jwk,
}

/// DPoP proof body claims that matter for the server.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DpopClaims {
    pub htu: String,
    pub htm: String,
    pub iat: u64,
    pub jti: String,
    /// Access token hash — required when the DPoP proof is sent with
    /// an access token (RFC 9449 §4.3).
    #[serde(default)]
    pub ath: Option<String>,
}

/// Verified DPoP proof.
#[derive(Debug, Clone)]
pub struct DpopVerified {
    pub jkt: String,
    pub htm: String,
    pub htu: String,
    pub iat: u64,
    pub jti: String,
}

/// Verify a DPoP proof against an expected URL + method. The proof
/// itself is HS256-signed by the caller's key for tests; real flows
/// use ES256 or RS256 — the implementation dispatches on the `alg`
/// header.
///
/// `replay_cache` is an optional jti-replay tracker (Solid-OIDC §5.2,
/// added in Sprint 4 / F5). Pass `None` to preserve pre-F5 behaviour
/// (no replay detection); pass `Some(&cache)` to reject a DPoP proof
/// whose `jti` was already seen inside the cache's TTL window.
///
/// When the `dpop-replay-cache` feature is disabled, the cache type
/// is unavailable and this function reduces to its historical
/// 5-argument form.
#[cfg(feature = "dpop-replay-cache")]
pub async fn verify_dpop_proof(
    proof: &str,
    expected_htu: &str,
    expected_htm: &str,
    now: u64,
    skew: u64,
    replay_cache: Option<&DpopReplayCache>,
) -> Result<DpopVerified, PodError> {
    let verified = verify_dpop_proof_core(proof, expected_htu, expected_htm, now, skew)?;

    // F5: replay check after signature/claim validation so we never
    // admit a tampered proof into the cache.
    if let Some(cache) = replay_cache {
        if let Err(e) = cache.check_and_record(&verified.jti).await {
            match e {
                ReplayError::Replayed { .. } => {
                    DPOP_REPLAY_REJECTED_TOTAL.increment();
                    return Err(PodError::Nip98(format!(
                        "DPoP jti replay detected: {e}"
                    )));
                }
            }
        }
    }

    Ok(verified)
}

/// Pre-F5 synchronous signature, retained when the replay-cache
/// feature is disabled. Callers who were already on this path keep
/// compiling without changes.
#[cfg(not(feature = "dpop-replay-cache"))]
pub fn verify_dpop_proof(
    proof: &str,
    expected_htu: &str,
    expected_htm: &str,
    now: u64,
    skew: u64,
) -> Result<DpopVerified, PodError> {
    verify_dpop_proof_core(proof, expected_htu, expected_htm, now, skew)
}

/// Core DPoP proof verification — shared between the feature-gated
/// async wrapper and the feature-off sync form above.
///
/// # Security invariants
///
/// 1. **Signature verified** against `header.jwk`. A proof whose
///    signature does not match the embedded public key is rejected
///    before any claim is trusted. This is the difference between a
///    DPoP proof (authenticated) and arbitrary JSON.
///
/// 2. **Algorithm whitelist.** The `alg` header MUST be one of
///    ES256, RS256, EdDSA. `alg=none` is unconditionally rejected.
///    HS256 is only accepted when the `jwk.kty` is `oct` (test/dev
///    path); asymmetric JWKs signed with HS256 are rejected to block
///    the classic alg-confusion attack (public key fed as an HMAC
///    secret).
///
/// 3. **Thumbprint derived from the JWK**, not the alg — [`DpopVerified::jkt`]
///    is RFC 7638 over the canonical member set of `header.jwk`, so
///    the pod binds the access token's `cnf.jkt` to the same key
///    that actually signed this proof.
fn verify_dpop_proof_core(
    proof: &str,
    expected_htu: &str,
    expected_htm: &str,
    now: u64,
    skew: u64,
) -> Result<DpopVerified, PodError> {
    let header = decode_header(proof)
        .map_err(|e| PodError::Nip98(format!("DPoP header decode failed: {e}")))?;
    if header.typ.as_deref() != Some("dpop+jwt") {
        return Err(PodError::Nip98("DPoP typ must be dpop+jwt".into()));
    }
    let jwk_json = header
        .jwk
        .as_ref()
        .ok_or_else(|| PodError::Nip98("DPoP header missing jwk".into()))?;

    // Two views of the same jwk: one in our local `Jwk` shape for
    // thumbprint computation, one in jsonwebtoken's shape for signing
    // key construction. The local parse is also what catches
    // structurally broken jwks (missing x/y for EC, etc.) before we
    // try to build a DecodingKey from them.
    let jwk_val = serde_json::to_value(jwk_json)
        .map_err(|e| PodError::Nip98(format!("DPoP jwk serialisation failed: {e}")))?;
    let jwk: Jwk = serde_json::from_value(jwk_val.clone())
        .map_err(|e| PodError::Nip98(format!("DPoP jwk parse failed: {e}")))?;
    let jkt = jwk.thumbprint()?;

    // Algorithm dispatch — reject anything we do not explicitly
    // whitelist. `decode_header` above already rejects `alg=none`
    // (jsonwebtoken's `Algorithm` enum has no `None` variant), but we
    // assert it here too for defence in depth.
    let alg = header.alg;
    match alg {
        Algorithm::ES256 | Algorithm::RS256 | Algorithm::EdDSA => {}
        Algorithm::HS256 if jwk.kty == "oct" => {
            // Test/dev path only. A `kty=oct` jwk is a symmetric key
            // and therefore not useful for authenticated DPoP in
            // production — but the Sprint-4 replay-cache tests rely
            // on HS256 + oct, so we keep the path alive while still
            // verifying the signature below.
            debug!(
                "DPoP proof using HS256+oct (test/dev path); \
                not suitable for production"
            );
        }
        other => {
            return Err(PodError::Nip98(format!(
                "DPoP alg {other:?} is not permitted (ES256/RS256/EdDSA only; \
                HS256 test-path requires kty=oct)"
            )));
        }
    }

    // Build the signing key from the embedded jwk, then have
    // `jsonwebtoken::decode` verify the signature AND return the
    // claim set in a single shot. Anything that doesn't match is
    // surfaced as a signature failure.
    let jwt_jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwk_val)
        .map_err(|e| PodError::Nip98(format!("DPoP jwk → jsonwebtoken parse failed: {e}")))?;
    let key = DecodingKey::from_jwk(&jwt_jwk)
        .map_err(|e| PodError::Nip98(format!("DPoP jwk → DecodingKey failed: {e}")))?;

    let mut validation = Validation::new(alg);
    validation.required_spec_claims.clear();
    validation.validate_exp = false; // DPoP proofs have no `exp`
    validation.validate_aud = false;

    let data = decode::<DpopClaims>(proof, &key, &validation).map_err(|e| {
        PodError::Nip98(format!("DPoP proof signature verification failed: {e}"))
    })?;
    let claims = data.claims;

    if claims.htm.to_uppercase() != expected_htm.to_uppercase() {
        return Err(PodError::Nip98(format!(
            "DPoP htm mismatch: {} vs {}",
            claims.htm, expected_htm
        )));
    }
    if normalise_htu(&claims.htu) != normalise_htu(expected_htu) {
        return Err(PodError::Nip98(format!(
            "DPoP htu mismatch: {} vs {}",
            claims.htu, expected_htu
        )));
    }
    // The two saturating_sub branches are mutually exclusive (one
    // returns 0 unless the other is 0), so an `&&` here was always
    // false and the gate never fired. Use `||` so iat outside
    // tolerance in either direction trips the rejection.
    if now.saturating_sub(claims.iat) > skew || claims.iat.saturating_sub(now) > skew {
        return Err(PodError::Nip98("DPoP iat outside tolerance".into()));
    }

    Ok(DpopVerified {
        jkt,
        htm: claims.htm,
        htu: claims.htu,
        iat: claims.iat,
        jti: claims.jti,
    })
}

fn normalise_htu(u: &str) -> String {
    u.trim_end_matches('/').to_ascii_lowercase()
}

// ---------------------------------------------------------------------------
// Access token verification
// ---------------------------------------------------------------------------

/// Solid-OIDC access-token claims (partial — only what the pod uses).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SolidOidcClaims {
    pub iss: String,
    pub sub: String,
    pub aud: serde_json::Value,
    pub exp: u64,
    pub iat: u64,
    #[serde(default)]
    pub webid: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub cnf: Option<CnfClaim>,
    #[serde(default)]
    pub scope: Option<String>,
}

/// `cnf` binding — contains the SHA-256 thumbprint of the DPoP key.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CnfClaim {
    pub jkt: String,
}

/// Verified Solid-OIDC access token.
#[derive(Debug, Clone)]
pub struct AccessTokenVerified {
    pub webid: String,
    pub client_id: Option<String>,
    pub iss: String,
    pub jkt: String,
    pub scope: Option<String>,
    pub exp: u64,
}

/// Key material supplied to [`verify_access_token`].
///
/// Production deployments MUST use `Asymmetric(JwkSet)` populated
/// from the IdP's `jwks_uri`. The symmetric variant exists only for
/// tests and local dev fixtures — if an external OIDC issuer ever
/// returns a token with `alg=HS256`, [`verify_access_token`] refuses
/// to verify it against an asymmetric keyset.
#[derive(Debug, Clone)]
pub enum TokenVerifyKey {
    /// Shared secret path. HMAC-SHA256 only. Intended for integration
    /// tests that issue their own tokens.
    Symmetric(Vec<u8>),
    /// Public-key path. The JWK set is usually fetched from the IdP's
    /// `jwks_uri` and rotated on cache expiry.
    Asymmetric(jsonwebtoken::jwk::JwkSet),
}

/// Verify a Solid-OIDC access token.
///
/// # Security invariants
///
/// 1. **Header-alg dispatch.** The token's `alg` header drives which
///    verification path runs. `alg=none` is unconditionally rejected
///    (jsonwebtoken's `Algorithm` enum has no `None` variant — decode
///    fails early). `HS256` is accepted only under
///    [`TokenVerifyKey::Symmetric`]; any attempt to verify an HS256
///    token against an asymmetric keyset is refused with an explicit
///    "HS256 not permitted for external OIDC" error. This blocks the
///    alg-confusion attack where an RSA public key is re-used as an
///    HMAC secret.
///
/// 2. **Asymmetric keys are selected by `kid`** from the configured
///    [`jsonwebtoken::jwk::JwkSet`], falling back to a match on
///    algorithm family when the token omits `kid`.
///
/// 3. **`cnf.jkt` MUST match the DPoP thumbprint** passed by the
///    caller. This is the Solid-OIDC bearer-bound-to-DPoP invariant.
///
/// 4. **`exp` is checked manually** so the error is a
///    [`PodError::Nip98`] — callers surface this as a `401` with an
///    RFC 6750 `error="invalid_token"` challenge.
pub fn verify_access_token(
    token: &str,
    keyset: &TokenVerifyKey,
    expected_issuer: &str,
    dpop_jkt: &str,
    now: u64,
) -> Result<AccessTokenVerified, PodError> {
    let header = decode_header(token)
        .map_err(|e| PodError::Nip98(format!("access token header decode failed: {e}")))?;
    let alg = header.alg;

    // Resolve a DecodingKey based on (alg, keyset).
    let key = match (alg, keyset) {
        // Symmetric test path.
        (Algorithm::HS256, TokenVerifyKey::Symmetric(secret)) => {
            DecodingKey::from_secret(secret)
        }
        (Algorithm::HS256, TokenVerifyKey::Asymmetric(_)) => {
            return Err(PodError::Nip98(
                "HS256 not permitted for external OIDC — asymmetric keyset required".into(),
            ));
        }

        // Asymmetric production path.
        (Algorithm::RS256, TokenVerifyKey::Asymmetric(set))
        | (Algorithm::ES256, TokenVerifyKey::Asymmetric(set))
        | (Algorithm::EdDSA, TokenVerifyKey::Asymmetric(set)) => {
            // Prefer exact `kid` match; fall back to the first JWK
            // that advertises the same algorithm family.
            let jwk = if let Some(kid) = header.kid.as_deref() {
                set.find(kid).ok_or_else(|| {
                    PodError::Nip98(format!(
                        "access token kid '{kid}' not present in configured JwkSet"
                    ))
                })?
            } else {
                set.keys
                    .iter()
                    .find(|j| {
                        j.common
                            .key_algorithm
                            .and_then(|k| k.to_string().parse::<Algorithm>().ok())
                            == Some(alg)
                    })
                    .ok_or_else(|| {
                        PodError::Nip98(format!(
                            "access token alg {alg:?} has no matching JWK in keyset"
                        ))
                    })?
            };
            DecodingKey::from_jwk(jwk)
                .map_err(|e| PodError::Nip98(format!("JwkSet → DecodingKey failed: {e}")))?
        }
        (Algorithm::RS256, TokenVerifyKey::Symmetric(_))
        | (Algorithm::ES256, TokenVerifyKey::Symmetric(_))
        | (Algorithm::EdDSA, TokenVerifyKey::Symmetric(_)) => {
            return Err(PodError::Nip98(format!(
                "access token uses asymmetric alg {alg:?} but only a symmetric \
                keyset is configured"
            )));
        }

        (other, _) => {
            return Err(PodError::Nip98(format!(
                "access token alg {other:?} not permitted (ES256/RS256/EdDSA \
                for production, HS256 for test-only)"
            )));
        }
    };

    let mut validation = Validation::new(alg);
    validation.set_issuer(&[expected_issuer]);
    validation.validate_exp = false; // we check manually to return `Nip98`
    validation.validate_aud = false; // Solid-OIDC allows arbitrary aud

    let data = decode::<SolidOidcClaims>(token, &key, &validation)
        .map_err(|e| PodError::Nip98(format!("access token decode failed: {e}")))?;
    let claims = data.claims;

    if claims.exp < now {
        return Err(PodError::Nip98("access token expired".into()));
    }

    let cnf = claims
        .cnf
        .as_ref()
        .ok_or_else(|| PodError::Nip98("access token missing cnf".into()))?;
    if cnf.jkt != dpop_jkt {
        return Err(PodError::Nip98(
            "cnf.jkt does not match DPoP thumbprint".into(),
        ));
    }

    let webid = extract_webid(&claims)?;
    Ok(AccessTokenVerified {
        webid,
        client_id: claims.client_id,
        iss: claims.iss,
        jkt: cnf.jkt.clone(),
        scope: claims.scope,
        exp: claims.exp,
    })
}

/// Backwards-compat shim — delegates to [`verify_access_token`] with
/// a [`TokenVerifyKey::Symmetric`] keyset. New code should call the
/// dispatching form directly; this exists so pre-Sprint-5 integration
/// tests keep compiling.
#[deprecated(
    since = "0.4.0-alpha.2",
    note = "use verify_access_token with TokenVerifyKey::Symmetric"
)]
pub fn verify_access_token_hs256(
    token: &str,
    secret: &[u8],
    expected_issuer: &str,
    dpop_jkt: &str,
    now: u64,
) -> Result<AccessTokenVerified, PodError> {
    let ks = TokenVerifyKey::Symmetric(secret.to_vec());
    verify_access_token(token, &ks, expected_issuer, dpop_jkt, now)
}

/// Extract a WebID from an access-token claim set. Prefers the
/// explicit `webid` claim; falls back to a URL-shaped `sub`.
pub fn extract_webid(claims: &SolidOidcClaims) -> Result<String, PodError> {
    if let Some(w) = &claims.webid {
        if w.starts_with("http://") || w.starts_with("https://") {
            return Ok(w.clone());
        }
    }
    if claims.sub.starts_with("http://") || claims.sub.starts_with("https://") {
        return Ok(claims.sub.clone());
    }
    Err(PodError::Nip98(
        "no WebID present in access token (neither webid claim nor url-shaped sub)".into(),
    ))
}

// ---------------------------------------------------------------------------
// Introspection (RFC 7662)
// ---------------------------------------------------------------------------

/// Response body for a successful introspection call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrospectionResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<CnfClaim>,
}

impl IntrospectionResponse {
    /// Build a response body from a verified access token.
    pub fn from_verified(v: &AccessTokenVerified) -> Self {
        Self {
            active: true,
            webid: Some(v.webid.clone()),
            client_id: v.client_id.clone(),
            exp: Some(v.exp),
            iss: Some(v.iss.clone()),
            scope: v.scope.clone(),
            cnf: Some(CnfClaim { jkt: v.jkt.clone() }),
        }
    }

    /// Inactive response.
    pub fn inactive() -> Self {
        Self {
            active: false,
            webid: None,
            client_id: None,
            exp: None,
            iss: None,
            scope: None,
            cnf: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    #[test]
    fn discovery_contains_standard_endpoints() {
        let d = discovery_for("https://op.example/");
        assert_eq!(d.issuer, "https://op.example");
        assert!(d.authorization_endpoint.ends_with("/authorize"));
        assert!(d.registration_endpoint.ends_with("/register"));
        assert!(d.solid_oidc_supported[0].contains("solid-oidc"));
    }

    #[test]
    fn dynamic_registration_returns_client_id() {
        let req = ClientRegistrationRequest {
            redirect_uris: vec!["https://app.example/cb".into()],
            client_name: Some("App".into()),
            client_uri: None,
            grant_types: vec!["authorization_code".into()],
            response_types: vec!["code".into()],
            scope: Some("openid webid".into()),
            token_endpoint_auth_method: Some("none".into()),
            application_type: Some("web".into()),
        };
        let resp = register_client(&req, 1_700_000_000);
        assert!(resp.client_id.starts_with("client-"));
        assert!(resp.client_secret.is_none()); // "none" auth
    }

    #[test]
    fn jwk_ec_thumbprint_is_stable() {
        let jwk = Jwk {
            kty: "EC".into(),
            alg: None,
            kid: None,
            use_: None,
            crv: Some("P-256".into()),
            x: Some("fooX".into()),
            y: Some("fooY".into()),
            n: None,
            e: None,
            k: None,
        };
        let t1 = jwk.thumbprint().unwrap();
        let t2 = jwk.thumbprint().unwrap();
        assert_eq!(t1, t2);
        assert!(!t1.is_empty());
    }

    #[test]
    fn extract_webid_from_explicit_claim() {
        let c = SolidOidcClaims {
            iss: "https://op".into(),
            sub: "0xabc".into(),
            aud: serde_json::json!("solid"),
            exp: 0,
            iat: 0,
            webid: Some("https://me.example/profile#me".into()),
            client_id: None,
            cnf: None,
            scope: None,
        };
        assert_eq!(extract_webid(&c).unwrap(), "https://me.example/profile#me");
    }

    #[test]
    fn extract_webid_falls_back_to_sub_when_url() {
        let c = SolidOidcClaims {
            iss: "https://op".into(),
            sub: "https://me.example/profile#me".into(),
            aud: serde_json::json!("solid"),
            exp: 0,
            iat: 0,
            webid: None,
            client_id: None,
            cnf: None,
            scope: None,
        };
        assert_eq!(extract_webid(&c).unwrap(), "https://me.example/profile#me");
    }

    #[test]
    fn extract_webid_fails_when_no_webid() {
        let c = SolidOidcClaims {
            iss: "https://op".into(),
            sub: "0xabc".into(),
            aud: serde_json::json!("solid"),
            exp: 0,
            iat: 0,
            webid: None,
            client_id: None,
            cnf: None,
            scope: None,
        };
        assert!(extract_webid(&c).is_err());
    }

    fn issue_hs256_access_token(
        secret: &[u8],
        issuer: &str,
        jkt: &str,
        exp: u64,
    ) -> String {
        // `saturating_sub` avoids overflow when tests set `exp=100`
        // to force the expired path without caring about `iat`.
        let claims = SolidOidcClaims {
            iss: issuer.to_string(),
            sub: "https://me.example/profile#me".into(),
            aud: serde_json::json!("solid"),
            exp,
            iat: exp.saturating_sub(3600),
            webid: Some("https://me.example/profile#me".into()),
            client_id: Some("client-123".into()),
            cnf: Some(CnfClaim {
                jkt: jkt.to_string(),
            }),
            scope: Some("openid webid".into()),
        };
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    #[test]
    fn access_token_binds_to_dpop_jkt() {
        let secret = b"test-secret";
        let jkt = "THUMB-OK";
        let token = issue_hs256_access_token(secret, "https://op", jkt, 9_999_999_999);
        let ks = TokenVerifyKey::Symmetric(secret.to_vec());
        let verified =
            verify_access_token(&token, &ks, "https://op", jkt, 1_700_000_000).unwrap();
        assert_eq!(verified.webid, "https://me.example/profile#me");
        assert_eq!(verified.client_id.as_deref(), Some("client-123"));
    }

    #[test]
    fn access_token_rejects_wrong_jkt() {
        let secret = b"test-secret";
        let token = issue_hs256_access_token(secret, "https://op", "THUMB-OK", 9_999_999_999);
        let ks = TokenVerifyKey::Symmetric(secret.to_vec());
        let err = verify_access_token(&token, &ks, "https://op", "WRONG", 1_700_000_000)
            .err()
            .unwrap();
        assert!(matches!(err, PodError::Nip98(_)));
    }

    #[test]
    fn access_token_rejects_expired() {
        let secret = b"test-secret";
        let token = issue_hs256_access_token(secret, "https://op", "T", 100);
        let ks = TokenVerifyKey::Symmetric(secret.to_vec());
        let err = verify_access_token(&token, &ks, "https://op", "T", 1_700_000_000)
            .err()
            .unwrap();
        assert!(matches!(err, PodError::Nip98(_)));
    }

    #[test]
    fn introspection_active_contains_webid() {
        let v = AccessTokenVerified {
            webid: "https://me".into(),
            client_id: Some("c".into()),
            iss: "https://op".into(),
            jkt: "t".into(),
            scope: Some("openid".into()),
            exp: 0,
        };
        let r = IntrospectionResponse::from_verified(&v);
        assert!(r.active);
        assert_eq!(r.webid.as_deref(), Some("https://me"));
    }

    #[test]
    fn introspection_inactive_is_minimal() {
        let r = IntrospectionResponse::inactive();
        assert!(!r.active);
        assert!(r.webid.is_none());
    }
}
