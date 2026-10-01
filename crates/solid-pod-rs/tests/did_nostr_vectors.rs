//! Upstream did:nostr conformance vectors and the parity model.
//!
//! `tests/fixtures/did-nostr/test-vectors-generated.json` is vendored verbatim
//! from nostrcg/did-nostr at `4ea80d84d2afe3572b737ed8324a44617cbf2835`
//! (PR #145, closing #144 — "a resolver with only the identifier emits 0x02,
//! a controller-published document may carry 0x03, verifiers accept both").
//! See `tests/fixtures/did-nostr/README.md` for provenance and checksum.

#![cfg(feature = "did-nostr-types")]

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use serde_json::Value;
use solid_pod_rs::did_nostr_types::{
    format_multibase_public_key, format_multibase_schnorr, format_multibase_sec1,
    parse_multibase_schnorr, parse_multibase_sec1, render_did_document,
    render_did_document_published, NostrPubkey, MULTIKEY_LEN,
};

const VECTORS: &str = include_str!("fixtures/did-nostr/test-vectors-generated.json");

fn vectors(group: &str) -> Vec<Value> {
    let root: Value = serde_json::from_str(VECTORS).expect("vector file is JSON");
    root["vectors"][group]
        .as_array()
        .unwrap_or_else(|| panic!("vector group `{group}` missing"))
        .clone()
}

fn vector(group: &str, name: &str) -> Value {
    vectors(group)
        .into_iter()
        .find(|v| v["name"] == name)
        .unwrap_or_else(|| panic!("vector `{group}/{name}` missing"))
}

/// Find a secret whose public key has the requested y parity (0x02 / 0x03).
fn secret_with_parity(tag: u8) -> SecretKey {
    (1u8..=255)
        .map(|b| SecretKey::from_slice(&[b; 32]).expect("valid scalar"))
        .find(|sk| sk.public_key().to_encoded_point(true).as_bytes()[0] == tag)
        .expect("both parities occur within 255 keys")
}

// ── Upstream vectors ────────────────────────────────────────────────────

#[test]
fn decode_even_and_odd_parity_vectors() {
    let even = vector("key_decoding", "decode_even_parity");
    let odd = vector("key_decoding", "decode_odd_parity");
    for v in [&even, &odd] {
        let input = v["input"].as_str().unwrap();
        let expected_x = v["output"].as_str().unwrap();
        let parity = v["parity"].as_u64().unwrap() as u8;

        // General decoder: same x-only identifier for both prefixes.
        let id = parse_multibase_schnorr(input).unwrap();
        assert_eq!(id.to_hex(), expected_x, "{}", v["name"]);

        // Full-point decoder keeps the carried parity.
        let point = parse_multibase_sec1(input).unwrap();
        assert_eq!(
            point.to_encoded_point(true).as_bytes()[0],
            parity,
            "{}",
            v["name"]
        );
        assert_eq!(NostrPubkey::from_public_key(&point), id);
        // Full-point re-encode is byte-identical.
        assert_eq!(format_multibase_public_key(&point), input);
    }
}

#[test]
fn every_key_decoding_vector_passes() {
    let all = vectors("key_decoding");
    assert!(all.len() >= 2);
    for v in all {
        let id = parse_multibase_schnorr(v["input"].as_str().unwrap()).unwrap();
        assert_eq!(id.to_hex(), v["output"].as_str().unwrap(), "{}", v["name"]);
    }
}

#[test]
fn key_transformation_vectors_emit_0x02() {
    // Identifier-only encoding: always the 0x02 lift, lowercase output.
    for v in vectors("key_transformation") {
        let id = NostrPubkey::from_hex(v["input"].as_str().unwrap()).unwrap();
        let mb = format_multibase_schnorr(&id.0);
        assert_eq!(mb, v["output"].as_str().unwrap(), "{}", v["name"]);
        if v["roundtrip"] == true {
            assert_eq!(parse_multibase_schnorr(&mb).unwrap(), id, "{}", v["name"]);
        }
    }
}

#[test]
fn minimal_document_vector_matches_offline_renderer() {
    let v = vector("did_document_generation", "minimal_document_2_3_1");
    let did = v["input"].as_str().unwrap();
    let id = NostrPubkey::from_hex(did.strip_prefix("did:nostr:").unwrap()).unwrap();
    assert_eq!(render_did_document(&id), v["output"]);
}

#[test]
fn multikey_error_vectors_are_rejected() {
    for name in [
        "error_wrong_multicodec",
        "error_invalid_multibase_prefix",
        "error_uppercase_multibase_prefix",
        "error_invalid_key_length",
    ] {
        let v = vector("error_cases", name);
        let input = v["input"].as_str().unwrap();
        assert!(parse_multibase_schnorr(input).is_err(), "{name}");
        assert!(parse_multibase_sec1(input).is_err(), "{name}");
    }
}

#[test]
fn hex_error_vectors_are_rejected() {
    for name in [
        "error_hex_too_short",
        "error_hex_too_long",
        "error_hex_empty",
        "error_invalid_hex_character",
    ] {
        let v = vector("error_cases", name);
        assert!(
            NostrPubkey::from_hex(v["input"].as_str().unwrap()).is_err(),
            "{name}"
        );
    }
}

#[test]
fn crypto_validation_error_vectors_are_rejected() {
    // x ≥ p and x not on the curve: lifting to the 0x02 point fails.
    for name in ["error_x_not_field_element", "error_x_not_on_curve"] {
        let v = vector("error_cases", name);
        let id = NostrPubkey::from_hex(v["input"].as_str().unwrap()).unwrap();
        assert!(id.to_even_public_key().is_err(), "{name}");
        let mut sec1 = [0x02u8; 33];
        sec1[1..].copy_from_slice(&id.0);
        assert!(format_multibase_sec1(&sec1).is_err(), "{name}");
    }
}

#[test]
fn general_decoder_accepts_what_a_strict_bip340_decoder_rejects() {
    // `error_odd_parity_in_bip340_decoder` pins a *strict BIP-340* decoder.
    // Ours is a general Multikey decoder, which the parity model requires to
    // accept 0x03 and yield the same x.
    let v = vector("error_cases", "error_odd_parity_in_bip340_decoder");
    let input = v["input"].as_str().unwrap();
    let even = format!("fe70102{}", &input[7..]);
    assert_eq!(
        parse_multibase_schnorr(input).unwrap(),
        parse_multibase_schnorr(&even).unwrap()
    );
}

// ── Controller-published encoding (full key) ────────────────────────────

#[test]
fn published_document_carries_0x03_for_odd_y_key() {
    let sk = secret_with_parity(0x03);
    let pk = sk.public_key();
    let id = NostrPubkey::from_public_key(&pk);

    let mb = format_multibase_public_key(&pk);
    assert_eq!(mb, format!("fe70103{}", id.to_hex()));
    assert_eq!(mb.len(), MULTIKEY_LEN);

    let sec1 = pk.to_encoded_point(true);
    assert_eq!(format_multibase_sec1(sec1.as_bytes()).unwrap(), mb);

    let doc = render_did_document_published(&pk);
    assert_eq!(doc["id"], format!("did:nostr:{}", id.to_hex()));
    assert_eq!(doc["verificationMethod"][0]["publicKeyMultibase"], mb);
    // Everything except the parity byte matches the offline document.
    let mut offline = render_did_document(&id);
    offline["verificationMethod"][0]["publicKeyMultibase"] = Value::String(mb.clone());
    assert_eq!(doc, offline);

    // The verifier reads the same identifier from either form.
    assert_eq!(parse_multibase_schnorr(&mb).unwrap(), id);
    // The full point survives the round trip.
    assert_eq!(parse_multibase_sec1(&mb).unwrap(), pk);
}

#[test]
fn published_document_carries_0x02_for_even_y_key() {
    let pk = secret_with_parity(0x02).public_key();
    let id = NostrPubkey::from_public_key(&pk);
    let doc = render_did_document_published(&pk);
    assert_eq!(doc, render_did_document(&id));
}

#[test]
fn offline_resolution_of_odd_key_still_emits_0x02() {
    // A resolver holding only the identifier cannot know the parity.
    let pk = secret_with_parity(0x03).public_key();
    let id = NostrPubkey::from_public_key(&pk);
    let mb = render_did_document(&id)["verificationMethod"][0]["publicKeyMultibase"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(mb.starts_with("fe70102"));
    // The 0x02 point is the negation of the holder's odd-y point.
    let even = id.to_even_public_key().unwrap();
    assert_eq!(*even.as_affine(), -*pk.as_affine());
}

#[test]
fn odd_y_holder_negates_secret_to_own_the_0x02_point() {
    // Key arithmetic with only the identifier: tweak the 0x02 point; a holder
    // whose secret gives odd y uses n − d once, after which tweaks agree.
    use k256::{NonZeroScalar, ProjectivePoint, Scalar};

    let sk = secret_with_parity(0x03);
    let id = NostrPubkey::from_public_key(&sk.public_key());
    let even = id.to_even_public_key().unwrap();

    let d_neg = -*sk.to_nonzero_scalar().as_ref();
    let t = Scalar::from(42u64);
    let tweaked_secret = NonZeroScalar::new(d_neg + t).unwrap();
    let tweaked_point = ProjectivePoint::from(*even.as_affine()) + ProjectivePoint::GENERATOR * t;

    assert_eq!(
        (ProjectivePoint::GENERATOR * *tweaked_secret).to_affine(),
        tweaked_point.to_affine()
    );
}

#[test]
fn sec1_encoder_rejects_malformed_points() {
    let pk = secret_with_parity(0x02).public_key();
    let uncompressed = pk.to_encoded_point(false);
    assert!(format_multibase_sec1(uncompressed.as_bytes()).is_err());
    let mut bad_tag = [0u8; 33];
    bad_tag[0] = 0x04;
    bad_tag[1..].copy_from_slice(&pk.to_encoded_point(true).as_bytes()[1..]);
    assert!(format_multibase_sec1(&bad_tag).is_err());
}
