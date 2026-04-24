//! `did:key` identifier encoding / decoding.
//!
//! Format: `did:key:z<base58btc(varint(codec) || pubkey)>`
//!
//! The 'z' prefix is the multibase tag for base58btc (Bitcoin
//! alphabet). W3C `did-method-key` pins this encoding — other
//! multibases are rejected.

use multibase::Base;

use crate::error::DidKeyError;
use crate::pubkey::DidKeyPubkey;

/// Prefix of every W3C `did:key` identifier.
pub const DID_KEY_PREFIX: &str = "did:key:";

/// Encode a [`DidKeyPubkey`] to its canonical `did:key:z…` string.
pub fn encode(pubkey: &DidKeyPubkey) -> String {
    let payload = pubkey.to_multicodec_bytes();
    let mb = multibase::encode(Base::Base58Btc, payload);
    format!("{DID_KEY_PREFIX}{mb}")
}

/// Decode a `did:key:z…` string back into a [`DidKeyPubkey`].
///
/// The method fragment (e.g. `did:key:z…#z…`) is stripped before
/// decoding so callers that pass a verification-method URL don't need
/// to preprocess.
pub fn decode(did: &str) -> Result<DidKeyPubkey, DidKeyError> {
    let stripped = did
        .strip_prefix(DID_KEY_PREFIX)
        .ok_or_else(|| DidKeyError::NotDidKey(did.to_string()))?;
    let body = stripped.split('#').next().unwrap_or(stripped);
    if !body.starts_with('z') {
        return Err(DidKeyError::InvalidMultibase(format!(
            "did:key requires base58btc 'z' prefix, got '{}'",
            body.chars().next().unwrap_or(' ')
        )));
    }
    let (base, bytes) = multibase::decode(body)
        .map_err(|e| DidKeyError::InvalidMultibase(format!("decode: {e}")))?;
    if base != Base::Base58Btc {
        return Err(DidKeyError::InvalidMultibase(format!(
            "did:key multibase must be base58btc, got {base:?}"
        )));
    }
    DidKeyPubkey::from_multicodec_bytes(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pubkey::{ED25519_LEN, SEC1_COMPRESSED_LEN};

    #[test]
    fn encode_rejects_method_fragment() {
        // The decoder strips `#…` so an encoder-decoder mismatch does
        // not occur. Sanity test.
        let k = DidKeyPubkey::Ed25519([9u8; ED25519_LEN]);
        let did = encode(&k);
        let with_frag = format!("{did}#keys-0");
        let decoded = decode(&with_frag).unwrap();
        assert_eq!(decoded, k);
    }

    #[test]
    fn ed25519_roundtrip() {
        let k = DidKeyPubkey::Ed25519([42u8; ED25519_LEN]);
        let did = encode(&k);
        assert!(did.starts_with("did:key:z"));
        let back = decode(&did).unwrap();
        assert_eq!(back, k);
    }

    #[test]
    fn p256_roundtrip() {
        let mut sec1 = vec![0u8; SEC1_COMPRESSED_LEN];
        sec1[0] = 0x02;
        for (i, byte) in sec1.iter_mut().enumerate().skip(1) {
            *byte = i as u8;
        }
        let k = DidKeyPubkey::P256(sec1);
        let did = encode(&k);
        let back = decode(&did).unwrap();
        assert_eq!(back, k);
    }

    #[test]
    fn secp256k1_roundtrip() {
        let mut sec1 = vec![0u8; SEC1_COMPRESSED_LEN];
        sec1[0] = 0x03;
        for (i, byte) in sec1.iter_mut().enumerate().skip(1) {
            *byte = (i as u8).wrapping_mul(3);
        }
        let k = DidKeyPubkey::Secp256k1(sec1);
        let did = encode(&k);
        let back = decode(&did).unwrap();
        assert_eq!(back, k);
    }

    #[test]
    fn rejects_wrong_prefix() {
        let err = decode("did:example:123").unwrap_err();
        assert!(matches!(err, DidKeyError::NotDidKey(_)));
    }

    #[test]
    fn rejects_non_base58btc_multibase() {
        // `u` = base64url. We only accept base58btc.
        let err = decode("did:key:uAQIDBAUGBw").unwrap_err();
        assert!(matches!(err, DidKeyError::InvalidMultibase(_)));
    }

    #[test]
    fn rejects_malformed_multibase_body() {
        // Valid 'z' prefix but non-base58 characters ('0', 'O', 'I', 'l'
        // are forbidden in Bitcoin alphabet).
        let err = decode("did:key:z0OIl").unwrap_err();
        assert!(matches!(err, DidKeyError::InvalidMultibase(_)));
    }
}
