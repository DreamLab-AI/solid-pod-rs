//! did:key encoding round-trip tests — Ed25519, P-256, secp256k1.

use solid_pod_rs_didkey::{decode_did_key, encode_did_key, DidKeyError, DidKeyPubkey};

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use p256::SecretKey as P256SecretKey;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

fn ed25519_from_seed(seed: u64) -> Ed25519SigningKey {
    let mut rng = StdRng::seed_from_u64(seed);
    let secret: [u8; 32] = rng.gen();
    Ed25519SigningKey::from_bytes(&secret)
}

#[test]
fn did_key_ed25519_encoding_roundtrip() {
    let sk = ed25519_from_seed(42);
    let raw: [u8; 32] = sk.verifying_key().to_bytes();
    let pk = DidKeyPubkey::Ed25519(raw);
    let did = encode_did_key(&pk);
    assert!(did.starts_with("did:key:z"));
    let decoded = decode_did_key(&did).unwrap();
    assert_eq!(decoded, pk);
}

#[test]
fn did_key_p256_encoding_roundtrip() {
    // Derive a SEC1-compressed public key from a fresh P-256 secret.
    let mut rng = StdRng::seed_from_u64(7);
    let sk = P256SecretKey::random(&mut rng);
    let sec1 = sk
        .public_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    assert_eq!(sec1.len(), 33, "SEC1 compressed = 33 bytes");
    let pk = DidKeyPubkey::P256(sec1);
    let did = encode_did_key(&pk);
    let decoded = decode_did_key(&did).unwrap();
    assert_eq!(decoded, pk);
}

#[test]
fn did_key_secp256k1_encoding_roundtrip() {
    let mut rng = StdRng::seed_from_u64(13);
    let sk = k256::SecretKey::random(&mut rng);
    let sec1 = sk
        .public_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    assert_eq!(sec1.len(), 33);
    let pk = DidKeyPubkey::Secp256k1(sec1);
    let did = encode_did_key(&pk);
    let decoded = decode_did_key(&did).unwrap();
    assert_eq!(decoded, pk);
}

#[test]
fn decode_rejects_malformed_multibase() {
    // Non-base58 chars in body after the 'z' prefix.
    let err = decode_did_key("did:key:z0OIl").unwrap_err();
    assert!(matches!(err, DidKeyError::InvalidMultibase(_)));
}

#[test]
fn decode_rejects_unknown_codec() {
    // Craft a payload with a valid varint (0xffff = 3-byte varint) but
    // no codec table entry.
    let mut varint_buf = [0u8; 10];
    let vi = unsigned_varint::encode::u64(0xffff_u64, &mut varint_buf);
    let mut payload = vi.to_vec();
    payload.extend_from_slice(&[0u8; 32]);
    let mb = multibase::encode(multibase::Base::Base58Btc, payload);
    let err = decode_did_key(&format!("did:key:{mb}")).unwrap_err();
    assert!(matches!(err, DidKeyError::UnknownCodec(_)));
}

#[test]
fn decode_rejects_not_did_key() {
    let err = decode_did_key("did:example:abc").unwrap_err();
    assert!(matches!(err, DidKeyError::NotDidKey(_)));
}

#[test]
fn encoded_did_is_deterministic() {
    // Same bytes → same identifier, across independent encode calls.
    let key = [0x42u8; 32];
    let pk = DidKeyPubkey::Ed25519(key);
    let a = encode_did_key(&pk);
    let b = encode_did_key(&pk);
    assert_eq!(a, b);
    // And decodes identically.
    assert_eq!(decode_did_key(&a).unwrap(), pk);
}

#[test]
fn random_keys_produce_distinct_identifiers() {
    // Different random keys → different identifiers.
    let mut rng = StdRng::seed_from_u64(11);
    let a_raw: [u8; 32] = rng.gen();
    let b_raw: [u8; 32] = rng.gen();
    let a = encode_did_key(&DidKeyPubkey::Ed25519(a_raw));
    let b = encode_did_key(&DidKeyPubkey::Ed25519(b_raw));
    assert_ne!(a, b);
}
