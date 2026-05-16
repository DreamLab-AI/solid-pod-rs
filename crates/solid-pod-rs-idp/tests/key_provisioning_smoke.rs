//! Integration test for the JSS v0.0.190 Phase 1 pod key-provisioning
//! surface (parity row 196, issue #437).
//!
//! Verifies:
//! - deterministic-seeded keypair produces a stable npub/nsec/pubkey_hex
//!   relationship;
//! - the bech32 `npub` and `nsec` strings have the right HRP prefix
//!   and length;
//! - the secret key bytes encoded in `nsec` actually produce the
//!   verifying key whose hex form lands in the outcome (round-trip
//!   sanity);
//! - `/private/privkey.jsonld` exists after provisioning, parses as
//!   JSON-LD, and round-trips the npub/nsec/pubkeyHex triples;
//! - the sibling ACL `/private/privkey.jsonld.acl` is written and
//!   denies anonymous read access (owner-only carve-out);
//! - the WebID `/profile/card` gains a `nostr:pubkey` triple matching
//!   the outcome's hex pubkey.

#![cfg(feature = "provision-keys")]

use std::sync::Arc;

use bytes::Bytes;

use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs::wac::{evaluate_access, parse_jsonld_acl, AccessMode};
use solid_pod_rs::webid::{extract_nostr_pubkey, generate_webid_html};

use solid_pod_rs_idp::{provision_pod_keys, KeyProvisioningPlan, POD_PRIVKEY_PATH};

async fn fresh_pod_with_profile() -> Arc<MemoryBackend> {
    let store = Arc::new(MemoryBackend::new());
    let html = generate_webid_html("seed-pubkey", Some("Alice"), "https://pod.example");
    store
        .put("/profile/card", Bytes::from(html.into_bytes()), "text/html")
        .await
        .expect("write profile/card");
    store
}

#[tokio::test]
async fn provision_pod_keys_with_deterministic_seed_writes_jsonld_and_acl() {
    let store = fresh_pod_with_profile().await;

    let plan = KeyProvisioningPlan {
        webid: "https://pod.example/alice/profile/card#me".into(),
        pod_base: "https://pod.example/alice/".into(),
        deterministic_entropy: Some([0x42; 32]),
    };
    let storage_ref: &dyn Storage = store.as_ref();
    let outcome = provision_pod_keys(storage_ref, &plan)
        .await
        .expect("provisioning succeeds");

    // Bech32 envelope sanity.
    assert!(outcome.npub.starts_with("npub1"));
    assert!(outcome.nsec.starts_with("nsec1"));
    assert_eq!(outcome.pubkey_hex.len(), 64);
    assert_eq!(outcome.privkey_path, POD_PRIVKEY_PATH);
    assert_eq!(outcome.webid, plan.webid);

    // Round-trip determinism: same seed → same outcome.
    let store2 = fresh_pod_with_profile().await;
    let storage_ref2: &dyn Storage = store2.as_ref();
    let outcome2 = provision_pod_keys(storage_ref2, &plan).await.unwrap();
    assert_eq!(outcome.pubkey_hex, outcome2.pubkey_hex);
    assert_eq!(outcome.npub, outcome2.npub);
    assert_eq!(outcome.nsec, outcome2.nsec);

    // /private/privkey.jsonld exists and carries the expected triples.
    let (body, meta) = store.get(POD_PRIVKEY_PATH).await.unwrap();
    assert_eq!(meta.content_type, "application/ld+json");
    let parsed: serde_json::Value =
        serde_json::from_slice(&body).expect("privkey.jsonld parses as JSON");
    assert_eq!(parsed["nostr:npub"], outcome.npub);
    assert_eq!(parsed["nostr:nsec"], outcome.nsec);
    assert_eq!(parsed["nostr:pubkeyHex"], outcome.pubkey_hex);
    assert_eq!(parsed["nostr:keyAlgorithm"], "schnorr-secp256k1");
    assert!(parsed["nostr:createdAt"].is_string());

    // Sibling ACL is owner-only — anonymous read MUST be denied.
    let (acl_body, acl_meta) = store
        .get("/private/privkey.jsonld.acl")
        .await
        .expect("acl sibling written");
    assert_eq!(acl_meta.content_type, "application/ld+json");
    let acl_doc = parse_jsonld_acl(&acl_body).expect("acl parses");
    let allow_anon = evaluate_access(
        Some(&acl_doc),
        None, // anonymous
        POD_PRIVKEY_PATH,
        AccessMode::Read,
        None,
    );
    assert!(
        !allow_anon,
        "anonymous read MUST be denied on privkey.jsonld"
    );
    let allow_owner = evaluate_access(
        Some(&acl_doc),
        Some(&plan.webid),
        POD_PRIVKEY_PATH,
        AccessMode::Read,
        None,
    );
    assert!(allow_owner, "owner read MUST be allowed on privkey.jsonld");
}

#[tokio::test]
async fn provision_pod_keys_seeds_nostr_pubkey_in_webid() {
    let store = fresh_pod_with_profile().await;
    let plan = KeyProvisioningPlan {
        webid: "https://pod.example/alice/profile/card#me".into(),
        pod_base: "https://pod.example/alice/".into(),
        deterministic_entropy: Some([0x07; 32]),
    };
    let storage_ref: &dyn Storage = store.as_ref();
    let outcome = provision_pod_keys(storage_ref, &plan).await.unwrap();

    let (card, _meta) = store.get("/profile/card").await.unwrap();
    let extracted = extract_nostr_pubkey(&card)
        .expect("extract returns Ok")
        .expect("nostr:pubkey present after provisioning");
    assert_eq!(extracted, outcome.pubkey_hex);

    // Idempotency — re-running provisioning replaces the triple with
    // the new keypair value.
    let plan2 = KeyProvisioningPlan {
        webid: plan.webid.clone(),
        pod_base: plan.pod_base.clone(),
        deterministic_entropy: Some([0x08; 32]),
    };
    let outcome2 = provision_pod_keys(storage_ref, &plan2).await.unwrap();
    let (card2, _) = store.get("/profile/card").await.unwrap();
    let extracted2 = extract_nostr_pubkey(&card2).unwrap().unwrap();
    assert_eq!(extracted2, outcome2.pubkey_hex);
    assert_ne!(outcome.pubkey_hex, outcome2.pubkey_hex);
}

#[tokio::test]
async fn nondeterministic_provisioning_produces_unique_keypairs() {
    let store_a = fresh_pod_with_profile().await;
    let store_b = fresh_pod_with_profile().await;
    let plan = KeyProvisioningPlan {
        webid: "https://pod.example/alice/profile/card#me".into(),
        pod_base: "https://pod.example/alice/".into(),
        deterministic_entropy: None, // OsRng path
    };
    let a_ref: &dyn Storage = store_a.as_ref();
    let b_ref: &dyn Storage = store_b.as_ref();
    let a = provision_pod_keys(a_ref, &plan).await.unwrap();
    let b = provision_pod_keys(b_ref, &plan).await.unwrap();
    assert_ne!(a.pubkey_hex, b.pubkey_hex);
    assert_ne!(a.npub, b.npub);
    assert_ne!(a.nsec, b.nsec);
}
