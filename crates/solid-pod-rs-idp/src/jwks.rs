//! JWKS publication + key rotation (row 77, 130).
//!
//! JSS parity: `src/idp/keys.js`. JSS persists keys to disk on first
//! boot; this crate generates in-process keys with in-memory
//! rotation. Consumers who need disk persistence can serialise the
//! PKCS8-PEM `SigningKey::private_pem` field to their own store.
//!
//! ## Algorithm choice
//!
//! Sprint 10 ships **ES256** (P-256 ECDSA) as the single supported
//! signing algorithm. JSS publishes both RS256 and ES256; we picked
//! ES256 because:
//!
//! 1. It is the *mandatory* alg for Solid-OIDC DPoP proofs
//!    (`dpop_signing_alg_values_supported` MUST include ES256).
//! 2. Every Solid client library we checked (SolidOS, CSS,
//!    `@inrupt/solid-client-authn-node`) accepts ES256 id-tokens.
//! 3. Skipping RS256 keeps the crate's dep graph small — no `rsa`
//!    crate, no PKCS#1 handling.
//!
//! The JSON Web Key Set surface is still plural: callers can add
//! more keys via [`Jwks::insert_signing_key`] if their IdP policy
//! requires it, and `rotate` retains the old key for a configurable
//! verification window.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use p256::ecdsa::SigningKey as EcdsaSigningKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from key generation / encoding.
#[derive(Debug, Error)]
pub enum JwksError {
    /// Key-generation or PEM-encoding failure.
    #[error("key generation: {0}")]
    KeyGen(String),
}

/// A single signing key. Only ES256 is issued by this crate.
#[derive(Debug, Clone)]
pub struct SigningKey {
    /// RFC 7517 `kid`.
    pub kid: String,
    /// RFC 7518 algorithm identifier. Always `"ES256"` today.
    pub alg: String,
    /// PKCS#8 PEM-encoded private key material. Callers who need
    /// disk persistence should serialise this and reload via
    /// [`SigningKey::from_pem`].
    pub private_pem: String,
    /// PKCS#8 encoded private key, cached for [`jsonwebtoken::EncodingKey`]
    /// hand-off.
    pub private_der: Vec<u8>,
    /// RFC 7517 public JWK (`kty`, `crv`, `x`, `y`, `kid`, `alg`,
    /// `use`).
    pub public_jwk: PublicJwk,
    /// Creation timestamp, seconds since Unix epoch.
    pub created_at: u64,
}

/// Public JWK shape as published at `/.well-known/jwks.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicJwk {
    /// Key type, always `"EC"` for ES256.
    pub kty: String,
    /// EC curve, always `"P-256"` for ES256.
    pub crv: String,
    /// Base64url EC X coordinate.
    pub x: String,
    /// Base64url EC Y coordinate.
    pub y: String,
    /// Key id.
    pub kid: String,
    /// Algorithm.
    pub alg: String,
    /// `"sig"` — Solid-OIDC always publishes signing keys.
    #[serde(rename = "use")]
    pub use_: String,
}

impl SigningKey {
    /// Generate a fresh ES256 signing key.
    pub fn generate_es256() -> Result<Self, JwksError> {
        use rand::rngs::OsRng;

        let sk = EcdsaSigningKey::random(&mut OsRng);
        let pk = p256::PublicKey::from(sk.verifying_key());
        let point = pk.to_encoded_point(false); // uncompressed
        let x = point
            .x()
            .ok_or_else(|| JwksError::KeyGen("EC point missing x coordinate".into()))?;
        let y = point
            .y()
            .ok_or_else(|| JwksError::KeyGen("EC point missing y coordinate".into()))?;

        let kid = format!("es256-{}", uuid::Uuid::new_v4());
        let public_jwk = PublicJwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: B64.encode(x.as_ref() as &[u8]),
            y: B64.encode(y.as_ref() as &[u8]),
            kid: kid.clone(),
            alg: "ES256".into(),
            use_: "sig".into(),
        };

        let private_pem = sk
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| JwksError::KeyGen(format!("PKCS8 PEM encode: {e}")))?
            .to_string();
        let private_der = sk
            .to_pkcs8_der()
            .map_err(|e| JwksError::KeyGen(format!("PKCS8 DER encode: {e}")))?
            .as_bytes()
            .to_vec();
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(Self {
            kid,
            alg: "ES256".into(),
            private_pem,
            private_der,
            public_jwk,
            created_at,
        })
    }

    /// Re-hydrate a signing key from previously-serialised PKCS8 PEM.
    /// The public JWK is re-derived; `kid` is caller-supplied.
    pub fn from_pem(kid: impl Into<String>, pem: &str) -> Result<Self, JwksError> {
        use p256::pkcs8::DecodePrivateKey;

        let sk = EcdsaSigningKey::from_pkcs8_pem(pem)
            .map_err(|e| JwksError::KeyGen(format!("PKCS8 PEM decode: {e}")))?;
        let pk = p256::PublicKey::from(sk.verifying_key());
        let point = pk.to_encoded_point(false);
        let x = point
            .x()
            .ok_or_else(|| JwksError::KeyGen("EC point missing x coordinate".into()))?;
        let y = point
            .y()
            .ok_or_else(|| JwksError::KeyGen("EC point missing y coordinate".into()))?;

        let kid_s: String = kid.into();
        let public_jwk = PublicJwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: B64.encode(x.as_ref() as &[u8]),
            y: B64.encode(y.as_ref() as &[u8]),
            kid: kid_s.clone(),
            alg: "ES256".into(),
            use_: "sig".into(),
        };
        let private_der = sk
            .to_pkcs8_der()
            .map_err(|e| JwksError::KeyGen(format!("PKCS8 DER encode: {e}")))?
            .as_bytes()
            .to_vec();
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(Self {
            kid: kid_s,
            alg: "ES256".into(),
            private_pem: pem.to_string(),
            private_der,
            public_jwk,
            created_at,
        })
    }
}

/// Published JWK set body (`{"keys": [...]}`), matching RFC 7517.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksDocument {
    /// Public keys advertised at `/.well-known/jwks.json`.
    pub keys: Vec<PublicJwk>,
}

/// Active-key container. Holds the current signing key plus zero or
/// more "previous" keys retained for verifier-rollover windows.
#[derive(Clone)]
pub struct Jwks {
    inner: Arc<RwLock<JwksInner>>,
    /// Max time a rotated-out key is retained for JWKS publication.
    /// After this, [`Jwks::prune_expired`] removes it.
    retention: Duration,
}

struct JwksInner {
    active: SigningKey,
    retired: Vec<(SigningKey, SystemTime)>,
}

impl Jwks {
    /// Create a fresh JWKS with a newly-generated ES256 active key.
    pub fn generate_es256() -> Result<Self, JwksError> {
        let active = SigningKey::generate_es256()?;
        Ok(Self::from_active(active))
    }

    /// Build a JWKS around a pre-existing signing key.
    pub fn from_active(active: SigningKey) -> Self {
        Self {
            inner: Arc::new(RwLock::new(JwksInner {
                active,
                retired: Vec::new(),
            })),
            retention: Duration::from_secs(7 * 24 * 3600), // 1 week default
        }
    }

    /// Override the retention window for retired keys. Defaults to
    /// 1 week; tests that exercise rotation drop this to seconds.
    pub fn with_retention(mut self, retention: Duration) -> Self {
        self.retention = retention;
        self
    }

    /// Clone the currently-active signing key.
    pub fn active_key(&self) -> SigningKey {
        self.inner.read().active.clone()
    }

    /// Generate a fresh ES256 signing key, make it the active key,
    /// and retain the old one for the retention window.
    pub fn rotate(&self) -> Result<SigningKey, JwksError> {
        let new = SigningKey::generate_es256()?;
        let mut inner = self.inner.write();
        let old = std::mem::replace(&mut inner.active, new.clone());
        inner.retired.push((old, SystemTime::now()));
        Ok(new)
    }

    /// Insert an additional signing key. Useful for testing rollover
    /// without going through [`Jwks::rotate`].
    pub fn insert_signing_key(&self, key: SigningKey) {
        let mut inner = self.inner.write();
        let old = std::mem::replace(&mut inner.active, key);
        inner.retired.push((old, SystemTime::now()));
    }

    /// Remove retired keys that have exceeded the retention window.
    pub fn prune_expired(&self) {
        let mut inner = self.inner.write();
        let retention = self.retention;
        inner.retired.retain(|(_, ts)| {
            ts.elapsed().unwrap_or(Duration::ZERO) < retention
        });
    }

    /// Render the public JWKS document (active + all retained
    /// retired keys). Solid-OIDC RPs consult this via the
    /// `jwks_uri` from the discovery document.
    pub fn public_document(&self) -> JwksDocument {
        let inner = self.inner.read();
        let mut keys = Vec::with_capacity(1 + inner.retired.len());
        keys.push(inner.active.public_jwk.clone());
        for (k, _) in &inner.retired {
            keys.push(k.public_jwk.clone());
        }
        JwksDocument { keys }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_jwks_publishes_signing_key() {
        let jwks = Jwks::generate_es256().unwrap();
        let doc = jwks.public_document();
        assert_eq!(doc.keys.len(), 1);
        let k = &doc.keys[0];
        assert_eq!(k.kty, "EC");
        assert_eq!(k.crv, "P-256");
        assert_eq!(k.alg, "ES256");
        assert_eq!(k.use_, "sig");
        assert!(!k.x.is_empty() && !k.y.is_empty());
        assert!(k.kid.starts_with("es256-"));
    }

    #[test]
    fn rotate_retains_old_key_for_verification_window() {
        let jwks = Jwks::generate_es256().unwrap();
        let original_kid = jwks.active_key().kid.clone();
        jwks.rotate().unwrap();
        let doc = jwks.public_document();
        // Rotated set MUST include the new active key AND the retired one.
        assert_eq!(doc.keys.len(), 2);
        // New active key's kid != original.
        assert_ne!(jwks.active_key().kid, original_kid);
        // Original key still present for verifier rollover.
        assert!(doc.keys.iter().any(|k| k.kid == original_kid));
    }

    #[test]
    fn prune_expired_drops_retired_keys_past_retention() {
        let jwks = Jwks::generate_es256().unwrap().with_retention(Duration::from_millis(1));
        jwks.rotate().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        jwks.prune_expired();
        let doc = jwks.public_document();
        // After prune only the active key should remain.
        assert_eq!(doc.keys.len(), 1);
    }

    #[test]
    fn key_round_trips_through_pem() {
        let k = SigningKey::generate_es256().unwrap();
        let k2 = SigningKey::from_pem(&k.kid, &k.private_pem).unwrap();
        // The PEM preserves the private key, so the derived public
        // JWK X/Y coordinates must match.
        assert_eq!(k.public_jwk.x, k2.public_jwk.x);
        assert_eq!(k.public_jwk.y, k2.public_jwk.y);
    }
}
