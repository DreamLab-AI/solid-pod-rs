//! [`solid_pod_rs::SelfSignedVerifier`] implementation for `did:key`.
//!
//! Plugs into a [`solid_pod_rs::CidVerifier`] so an
//! `acl:IssuerCondition` with `cid:Verifier` accepts did:key-signed
//! proofs alongside NIP-98 and did:nostr.

use async_trait::async_trait;
use solid_pod_rs::auth::self_signed::{
    ProofEnvelope, SelfSignedError, SelfSignedVerifier, VerifiedSubject,
};

use crate::jwt::verify_self_signed_jwt;

/// Default acceptance window for `iat` drift (seconds).
pub const DEFAULT_SKEW_SECONDS: u64 = 60;

/// Verifier for did:key self-signed compact JWTs.
#[derive(Debug, Clone)]
pub struct DidKeyVerifier {
    skew: u64,
}

impl DidKeyVerifier {
    /// Use [`DEFAULT_SKEW_SECONDS`] as the acceptance window.
    pub fn new() -> Self {
        Self {
            skew: DEFAULT_SKEW_SECONDS,
        }
    }

    /// Override the `iat` skew tolerance.
    #[must_use]
    pub fn with_skew(mut self, skew_seconds: u64) -> Self {
        self.skew = skew_seconds;
        self
    }
}

impl Default for DidKeyVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Heuristic: does this proof look like a compact JWS?
///
/// Used so the fan-out dispatcher can return `Ok(None)` for
/// non-JWT inputs (letting the next verifier try) while still
/// surfacing a real error for malformed JWTs.
fn looks_like_compact_jws(s: &str) -> bool {
    let dots = s.bytes().filter(|b| *b == b'.').count();
    dots == 2
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'=')
        })
}

#[async_trait]
impl SelfSignedVerifier for DidKeyVerifier {
    async fn verify(
        &self,
        envelope: &ProofEnvelope<'_>,
    ) -> Result<Option<VerifiedSubject>, SelfSignedError> {
        if !looks_like_compact_jws(envelope.proof) {
            return Ok(None);
        }
        match verify_self_signed_jwt(
            envelope.proof,
            envelope.uri,
            envelope.method,
            envelope.now_unix,
            self.skew,
        ) {
            Ok(verified) => Ok(Some(VerifiedSubject {
                did: verified.did,
                verification_method: verified.verification_method,
            })),
            Err(crate::error::DidKeyError::MalformedJwt(m)) => {
                Err(SelfSignedError::Malformed(m))
            }
            Err(crate::error::DidKeyError::InvalidHeader(m))
            | Err(crate::error::DidKeyError::NotDidKey(m)) => {
                // Header parseable but not bound to a did:key →
                // not our format, let the next verifier try.
                // If the envelope _was_ structurally JWT-shaped but
                // pointed at another DID method we still want to
                // give siblings a chance.
                let _ = m;
                Ok(None)
            }
            Err(crate::error::DidKeyError::InvalidClaims(m)) => {
                Err(SelfSignedError::ScopeMismatch(m))
            }
            Err(crate::error::DidKeyError::BadSignature(m)) => {
                Err(SelfSignedError::InvalidSignature(m))
            }
            Err(e) => Err(SelfSignedError::Other(e.to_string())),
        }
    }

    fn name(&self) -> &'static str {
        "did:key"
    }
}
