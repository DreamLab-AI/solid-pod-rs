//! Sprint 11 row 152 — shared `SelfSignedVerifier` + `CidVerifier`
//! fan-out across NIP-98 and did:key proof formats.
//!
//! did:key-specific fixtures live in `solid-pod-rs-didkey`; this test
//! crate exercises the cross-format dispatch surface that
//! `solid-pod-rs` exposes.

use std::sync::Arc;

use async_trait::async_trait;
use solid_pod_rs::auth::self_signed::{
    CidVerifier, ProofEnvelope, SelfSignedError, SelfSignedVerifier, VerifiedSubject,
};
use solid_pod_rs::wac::{
    evaluate_access_ctx, AccessMode, AclAuthorization, AclDocument, Condition, ConditionDispatcher,
    ConditionOutcome, ConditionRegistry, IdOrIds, IdRef, IssuerConditionBody, RequestContext,
    StaticGroupMembership,
};

// ---------------------------------------------------------------------------
// Stand-in verifier that accepts a hard-coded prefix → did mapping. Lets
// us exercise the fan-out semantics without dragging the real
// solid-pod-rs-didkey crate into solid-pod-rs's test cycle.
// ---------------------------------------------------------------------------
struct StubVerifier {
    name_: &'static str,
    prefix: &'static str,
    did: &'static str,
}

#[async_trait]
impl SelfSignedVerifier for StubVerifier {
    async fn verify(
        &self,
        envelope: &ProofEnvelope<'_>,
    ) -> Result<Option<VerifiedSubject>, SelfSignedError> {
        if envelope.proof.starts_with(self.prefix) {
            Ok(Some(VerifiedSubject {
                did: self.did.to_string(),
                verification_method: format!("{}#keys-0", self.did),
            }))
        } else {
            Ok(None)
        }
    }
    fn name(&self) -> &'static str {
        self.name_
    }
}

// ---------------------------------------------------------------------------
// 1. CID verifier accepts a did:key-shaped proof.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn cid_verifier_accepts_did_key_proof() {
    let cid = CidVerifier::new()
        .with(Arc::new(StubVerifier {
            name_: "did:key",
            prefix: "eyJ", // compact JWTs start with "eyJ"
            did: "did:key:z6MkSample",
        }))
        .with(Arc::new(solid_pod_rs::Nip98Verifier));
    let env = ProofEnvelope {
        proof: "eyJhbGciOiJFZERTQSJ9.payload.sig",
        method: "GET",
        uri: "https://pod.example/r",
        now_unix: 1_700_000_000,
        expected_subject_hint: None,
    };
    let subj = cid.verify(&env).await.unwrap().unwrap();
    assert_eq!(subj.did, "did:key:z6MkSample");
}

// ---------------------------------------------------------------------------
// 2. CID verifier accepts a NIP-98 event.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn cid_verifier_accepts_nip98_proof() {
    // Build a properly-signed NIP-98 event so the test passes both
    // with and without the `nip98-schnorr` feature (the workspace's
    // default cascade enables it).
    use base64::engine::general_purpose::STANDARD as B64STD;
    use base64::Engine;
    use k256::schnorr::signature::Signer;
    use sha2::{Digest, Sha256};

    let seed = [0x42u8; 32];
    let sk = k256::schnorr::SigningKey::from_bytes(&seed).expect("valid schnorr seed");
    let pubkey = hex::encode(sk.verifying_key().to_bytes());

    let ts = 1_700_000_000u64;
    let tags = vec![
        vec!["u".into(), "https://pod.example/r".to_string()],
        vec!["method".into(), "GET".into()],
    ];
    let kind = 27235u64;
    let canonical = serde_json::json!([0, pubkey, ts, kind, tags, ""]);
    let id = hex::encode(Sha256::digest(
        serde_json::to_string(&canonical).unwrap().as_bytes(),
    ));
    let id_bytes: Vec<u8> = hex::decode(&id).unwrap();
    let signature: k256::schnorr::Signature = sk.sign(&id_bytes);
    let sig_hex = hex::encode(signature.to_bytes());

    let event = serde_json::json!({
        "id": id,
        "pubkey": pubkey,
        "created_at": ts,
        "kind": kind,
        "tags": tags,
        "content": "",
        "sig": sig_hex,
    });
    let token = B64STD.encode(serde_json::to_string(&event).unwrap());
    let header = format!("Nostr {token}");

    let cid = CidVerifier::new().with(Arc::new(solid_pod_rs::Nip98Verifier));
    let env = ProofEnvelope {
        proof: &header,
        method: "GET",
        uri: "https://pod.example/r",
        now_unix: ts,
        expected_subject_hint: None,
    };
    let subj = cid.verify(&env).await.unwrap().unwrap();
    assert!(subj.did.starts_with("urn:nip98:"));
    assert_eq!(subj.did, format!("urn:nip98:{pubkey}"));
}

// ---------------------------------------------------------------------------
// 3. CID verifier returns UnrecognisedFormat for garbage.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn cid_verifier_rejects_unknown_proof() {
    let cid = CidVerifier::new()
        .with(Arc::new(StubVerifier {
            name_: "a",
            prefix: "a:",
            did: "did:a:1",
        }))
        .with(Arc::new(solid_pod_rs::Nip98Verifier));
    let env = ProofEnvelope {
        proof: "this-is-garbage",
        method: "GET",
        uri: "https://pod.example/r",
        now_unix: 1_700_000_000,
        expected_subject_hint: None,
    };
    let err = cid.verify(&env).await.unwrap_err();
    assert!(matches!(err, SelfSignedError::UnrecognisedFormat));
}

// ---------------------------------------------------------------------------
// 4. Integration — `acl:IssuerCondition` with issuer `cid:Verifier`
//    dispatches through a CidVerifier-aware adapter and grants when
//    the proof is accepted.
// ---------------------------------------------------------------------------

/// Adapter: a [`ConditionDispatcher`] that resolves the special
/// `cid:Verifier` issuer IRI by consulting a background
/// [`CidVerifier`] via a pre-seeded cache of verified subjects for the
/// current request. Real deployments wire the CidVerifier into the
/// HTTP request pipeline; this test stubs the outcome.
struct CidAwareDispatcher {
    /// Simulates a pre-request CID verifier run — if the request
    /// context's issuer is `cid:Verifier`, the authorisation only
    /// grants when this flag is true.
    cid_verified: bool,
    inner: ConditionRegistry,
}

impl ConditionDispatcher for CidAwareDispatcher {
    fn dispatch(
        &self,
        cond: &Condition,
        ctx: &RequestContext<'_>,
        groups: &dyn solid_pod_rs::wac::GroupMembership,
    ) -> ConditionOutcome {
        if let Condition::Issuer(body) = cond {
            // Inspect the first listed issuer IRI to see whether the
            // policy delegates to the CID verifier.
            let issuers: Vec<String> = match body.issuer.as_ref() {
                Some(IdOrIds::Single(r)) => vec![r.id.clone()],
                Some(IdOrIds::Multiple(v)) => v.iter().map(|r| r.id.clone()).collect(),
                None => Vec::new(),
            };
            if issuers.iter().any(|i| i == "cid:Verifier") {
                return if self.cid_verified {
                    ConditionOutcome::Satisfied
                } else {
                    ConditionOutcome::Denied
                };
            }
        }
        self.inner.dispatch(cond, ctx, groups)
    }
}

#[tokio::test]
async fn wac_issuer_condition_dispatches_to_cid_verifier() {
    // Build an ACL whose IssuerCondition points at cid:Verifier.
    let doc = AclDocument {
        context: None,
        graph: Some(vec![AclAuthorization {
            id: None,
            r#type: None,
            agent: Some(IdOrIds::Single(IdRef {
                id: "did:key:z6MkSample".into(),
            })),
            agent_class: None,
            agent_group: None,
            origin: None,
            access_to: Some(IdOrIds::Single(IdRef { id: "/r".into() })),
            default: None,
            mode: Some(IdOrIds::Single(IdRef { id: "acl:Read".into() })),
            condition: Some(vec![Condition::Issuer(IssuerConditionBody {
                issuer: Some(IdOrIds::Single(IdRef {
                    id: "cid:Verifier".into(),
                })),
                issuer_group: None,
                issuer_class: None,
            })]),
        }]),
    };

    let ctx = RequestContext {
        web_id: Some("did:key:z6MkSample"),
        client_id: None,
        // In real life the server would set issuer to the concrete
        // did resolved from the CID proof. For the dispatcher-level
        // test we only need it to be non-None so the base predicate
        // matches.
        issuer: Some("cid:Verifier"),
    };

    // Success path — CID verifier accepted the proof.
    let ok = CidAwareDispatcher {
        cid_verified: true,
        inner: ConditionRegistry::default_with_client_and_issuer(),
    };
    assert!(evaluate_access_ctx(
        Some(&doc),
        &ctx,
        "/r",
        AccessMode::Read,
        None,
        &StaticGroupMembership::new(),
        &ok,
    ));

    // Failure path — CID verifier rejected (or wasn't present).
    let deny = CidAwareDispatcher {
        cid_verified: false,
        inner: ConditionRegistry::default_with_client_and_issuer(),
    };
    assert!(!evaluate_access_ctx(
        Some(&doc),
        &ctx,
        "/r",
        AccessMode::Read,
        None,
        &StaticGroupMembership::new(),
        &deny,
    ));
}
