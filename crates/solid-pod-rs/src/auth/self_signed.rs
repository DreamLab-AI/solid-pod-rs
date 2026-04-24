//! Self-signed proof verifier abstraction (Sprint 11 row 152).
//!
//! Controlled Identifier (CID) authentication admits multiple proof
//! formats: did:key self-signed JWTs (Sprint 11 row 153), NIP-98
//! Nostr events (Sprint 3 `auth::nip98`), did:nostr bridged profiles
//! (Sprint 6 `interop::did_nostr`), and any future DID method that
//! publishes a verification-relationship-bearing controller document.
//!
//! This module defines the transport-independent contract every
//! verifier implements, plus a fan-out [`CidVerifier`] that consults
//! each registered inner verifier in order and returns the first
//! success. Wiring is at the [`crate::wac::issuer`] layer: an
//! `acl:IssuerCondition` with `acl:issuer <cid:Verifier>` dispatches
//! through a dispatcher the consumer builds from a `CidVerifier`.
//!
//! Reference: W3C Controlled Identifier Document 1.0
//! (<https://www.w3.org/TR/cid/>). WAC 2.0 profile:
//! <https://webacl.org/secure-access-conditions/>.

use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;

/// Proof envelope passed to every [`SelfSignedVerifier`] implementation.
///
/// The fields are borrowed so callers do not allocate on the hot path.
/// Concrete verifiers interpret `proof` according to their own wire
/// format (JWT compact serialisation, base64 Nostr event, etc.).
#[derive(Debug, Clone, Copy)]
pub struct ProofEnvelope<'a> {
    /// Wire-format proof string (JWT / NIP-98 event / …).
    pub proof: &'a str,

    /// Canonical HTTP method in upper-case (`GET`, `POST`, …). Matches
    /// the DPoP `htm` / NIP-98 `method` tag.
    pub method: &'a str,

    /// Absolute request URI. Matches the DPoP `htu` / NIP-98 `u` tag.
    pub uri: &'a str,

    /// Caller's current wall-clock time in seconds since the Unix epoch.
    /// Passed explicitly for deterministic tests; production callers use
    /// `SystemTime::now()`.
    pub now_unix: u64,

    /// Optional subject hint — for example, the WebID supplied in a
    /// request's `Authorization` metadata. A verifier MAY use it to
    /// short-circuit matching but MUST NOT accept a proof whose actual
    /// verification output disagrees with the hint.
    pub expected_subject_hint: Option<&'a str>,
}

/// Output of a successful [`SelfSignedVerifier::verify`] call.
///
/// `did` is the canonical subject IRI — `did:key:z…`,
/// `did:nostr:<hex>`, `urn:nip98:<pubkey>`, or any other resolvable
/// controller identifier. `verification_method` is the specific key /
/// relationship that actually produced the signature; under the CID
/// model this is what the policy layer pins.
#[derive(Debug, Clone)]
pub struct VerifiedSubject {
    /// Canonical subject DID.
    pub did: String,

    /// Verification method identifier (often `did#keys-0` or a JWK `kid`).
    pub verification_method: String,
}

/// Errors returned by any [`SelfSignedVerifier`].
#[derive(Debug, Error)]
pub enum SelfSignedError {
    /// Proof envelope is syntactically malformed (invalid base64,
    /// unparseable JSON, wrong segment count for JWT, …).
    #[error("malformed proof: {0}")]
    Malformed(String),

    /// Proof's embedded method/URI does not match the request.
    #[error("proof scope mismatch: {0}")]
    ScopeMismatch(String),

    /// Proof signature did not verify against the advertised key.
    #[error("signature invalid: {0}")]
    InvalidSignature(String),

    /// Proof's timestamp is outside the acceptance window.
    #[error("proof timestamp out of range: {0}")]
    OutOfTimeWindow(String),

    /// No registered verifier recognised this proof format.
    #[error("no verifier matched the proof format")]
    UnrecognisedFormat,

    /// Bubbled-up implementation-specific failure.
    #[error("verifier: {0}")]
    Other(String),
}

/// Verifier for a single self-signed proof format.
///
/// Implementations MUST be inexpensive to clone behind an `Arc` and MUST
/// be `Send + Sync` so they can live inside a request-scoped dispatcher.
#[async_trait]
pub trait SelfSignedVerifier: Send + Sync {
    /// Attempt to verify the proof. Returns `Ok(Some(subject))` on a
    /// successful verification, `Ok(None)` if the proof does not match
    /// this verifier's format (allows the fan-out dispatcher to try the
    /// next one), or `Err(…)` when the format matches but verification
    /// fails — in which case the fan-out stops.
    async fn verify(
        &self,
        envelope: &ProofEnvelope<'_>,
    ) -> Result<Option<VerifiedSubject>, SelfSignedError>;

    /// Short name for diagnostics / metrics (`"did:key"`, `"nip98"`, …).
    fn name(&self) -> &'static str;
}

/// Fan-out dispatcher — tries each inner verifier in order. The first
/// one returning `Ok(Some(_))` wins. Any `Err(_)` short-circuits with
/// that error so a broken-but-matching proof surfaces a precise
/// diagnostic rather than being masked as `UnrecognisedFormat`.
pub struct CidVerifier {
    inner: Vec<Arc<dyn SelfSignedVerifier>>,
}

impl CidVerifier {
    /// Build an empty dispatcher; use [`CidVerifier::with`] to register
    /// verifiers.
    pub fn new() -> Self {
        Self { inner: Vec::new() }
    }

    /// Register another inner verifier. Verifiers are tried in the
    /// order they are added.
    #[must_use]
    pub fn with(mut self, verifier: Arc<dyn SelfSignedVerifier>) -> Self {
        self.inner.push(verifier);
        self
    }

    /// Number of registered inner verifiers.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Names of the registered inner verifiers — used by the WAC issuer
    /// condition layer to echo supported CID methods in 422 responses.
    pub fn registered(&self) -> Vec<&'static str> {
        self.inner.iter().map(|v| v.name()).collect()
    }
}

impl Default for CidVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SelfSignedVerifier for CidVerifier {
    async fn verify(
        &self,
        envelope: &ProofEnvelope<'_>,
    ) -> Result<Option<VerifiedSubject>, SelfSignedError> {
        if self.inner.is_empty() {
            return Err(SelfSignedError::UnrecognisedFormat);
        }
        for v in &self.inner {
            match v.verify(envelope).await {
                Ok(Some(subj)) => return Ok(Some(subj)),
                Ok(None) => continue,
                Err(SelfSignedError::UnrecognisedFormat) => continue,
                Err(e) => {
                    // A matching-but-broken proof short-circuits.
                    return Err(e);
                }
            }
        }
        Err(SelfSignedError::UnrecognisedFormat)
    }

    fn name(&self) -> &'static str {
        "cid:Verifier"
    }
}

// ---------------------------------------------------------------------------
// Tests — verifier-trait level only. Format-specific tests live in the
// integration crate (`tests/cid_verifier_sprint11.rs`) so they can
// exercise real did:key / NIP-98 fixtures.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct EchoVerifier {
        name: &'static str,
        want_prefix: &'static str,
        did: &'static str,
    }

    #[async_trait]
    impl SelfSignedVerifier for EchoVerifier {
        async fn verify(
            &self,
            envelope: &ProofEnvelope<'_>,
        ) -> Result<Option<VerifiedSubject>, SelfSignedError> {
            if envelope.proof.starts_with(self.want_prefix) {
                Ok(Some(VerifiedSubject {
                    did: self.did.to_string(),
                    verification_method: format!("{}#keys-0", self.did),
                }))
            } else {
                Ok(None)
            }
        }
        fn name(&self) -> &'static str {
            self.name
        }
    }

    struct BrokenVerifier;

    #[async_trait]
    impl SelfSignedVerifier for BrokenVerifier {
        async fn verify(
            &self,
            envelope: &ProofEnvelope<'_>,
        ) -> Result<Option<VerifiedSubject>, SelfSignedError> {
            if envelope.proof.starts_with("broken:") {
                Err(SelfSignedError::InvalidSignature("stub".into()))
            } else {
                Ok(None)
            }
        }
        fn name(&self) -> &'static str {
            "broken"
        }
    }

    fn envelope(proof: &str) -> ProofEnvelope<'_> {
        ProofEnvelope {
            proof,
            method: "GET",
            uri: "https://pod.example/r",
            now_unix: 1_700_000_000,
            expected_subject_hint: None,
        }
    }

    #[tokio::test]
    async fn empty_dispatcher_returns_unrecognised() {
        let c = CidVerifier::new();
        let env = envelope("anything");
        let err = c.verify(&env).await.unwrap_err();
        assert!(matches!(err, SelfSignedError::UnrecognisedFormat));
    }

    #[tokio::test]
    async fn first_matching_wins() {
        let c = CidVerifier::new()
            .with(Arc::new(EchoVerifier {
                name: "a",
                want_prefix: "a:",
                did: "did:a:1",
            }))
            .with(Arc::new(EchoVerifier {
                name: "b",
                want_prefix: "b:",
                did: "did:b:1",
            }));
        let env = envelope("b:hello");
        let subj = c.verify(&env).await.unwrap().unwrap();
        assert_eq!(subj.did, "did:b:1");
    }

    #[tokio::test]
    async fn broken_matching_verifier_short_circuits() {
        let c = CidVerifier::new()
            .with(Arc::new(BrokenVerifier))
            .with(Arc::new(EchoVerifier {
                name: "a",
                want_prefix: "a:",
                did: "did:a:1",
            }));
        let env = envelope("broken:sigbad");
        let err = c.verify(&env).await.unwrap_err();
        assert!(matches!(err, SelfSignedError::InvalidSignature(_)));
    }

    #[tokio::test]
    async fn no_matching_verifier_returns_unrecognised() {
        let c = CidVerifier::new().with(Arc::new(EchoVerifier {
            name: "a",
            want_prefix: "a:",
            did: "did:a:1",
        }));
        let env = envelope("z:none");
        let err = c.verify(&env).await.unwrap_err();
        assert!(matches!(err, SelfSignedError::UnrecognisedFormat));
    }

    #[test]
    fn registered_lists_names() {
        let c = CidVerifier::new()
            .with(Arc::new(EchoVerifier {
                name: "first",
                want_prefix: "f:",
                did: "did:a",
            }))
            .with(Arc::new(BrokenVerifier));
        assert_eq!(c.registered(), vec!["first", "broken"]);
        assert_eq!(c.len(), 2);
    }
}
