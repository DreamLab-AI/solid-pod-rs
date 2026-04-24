//! Public-key representation for `did:key`.
//!
//! Each variant is tagged with the W3C multicodec code used in the
//! `did:key:z…` form (after varint encoding):
//!
//! | Variant    | Codec   | Serialised pubkey size |
//! |------------|---------|------------------------|
//! | Ed25519    | `0xed`  | 32 bytes (raw)         |
//! | P-256      | `0x1200`| 33 bytes (SEC1 compressed) |
//! | Secp256k1  | `0xe7`  | 33 bytes (SEC1 compressed) |
//!
//! Reference:
//! <https://github.com/multiformats/multicodec/blob/master/table.csv>

use crate::error::DidKeyError;

/// Multicodec code for Ed25519 public keys.
pub const CODEC_ED25519: u64 = 0xed;

/// Multicodec code for secp256k1 public keys (SEC1 compressed).
pub const CODEC_SECP256K1: u64 = 0xe7;

/// Multicodec code for NIST P-256 public keys (SEC1 compressed).
pub const CODEC_P256: u64 = 0x1200;

/// Length of an Ed25519 raw public key.
pub const ED25519_LEN: usize = 32;

/// Length of a SEC1-compressed P-256 / secp256k1 public key.
pub const SEC1_COMPRESSED_LEN: usize = 33;

/// W3C `did:key` public-key payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DidKeyPubkey {
    /// 32-byte raw Ed25519 public key (RFC 8032).
    Ed25519([u8; ED25519_LEN]),

    /// 33-byte SEC1-compressed NIST P-256 public key.
    P256(Vec<u8>),

    /// 33-byte SEC1-compressed secp256k1 public key.
    Secp256k1(Vec<u8>),
}

impl DidKeyPubkey {
    /// Human-readable name for diagnostics.
    pub fn codec_name(&self) -> &'static str {
        match self {
            DidKeyPubkey::Ed25519(_) => "ed25519",
            DidKeyPubkey::P256(_) => "p-256",
            DidKeyPubkey::Secp256k1(_) => "secp256k1",
        }
    }

    /// Multicodec integer code corresponding to this variant.
    pub fn codec_code(&self) -> u64 {
        match self {
            DidKeyPubkey::Ed25519(_) => CODEC_ED25519,
            DidKeyPubkey::P256(_) => CODEC_P256,
            DidKeyPubkey::Secp256k1(_) => CODEC_SECP256K1,
        }
    }

    /// JWS `alg` value required for a signature produced by the paired
    /// private key, per RFC 8037 (EdDSA) / RFC 7518 §3.4 (ES256 /
    /// ES256K).
    pub fn jws_alg(&self) -> &'static str {
        match self {
            DidKeyPubkey::Ed25519(_) => "EdDSA",
            DidKeyPubkey::P256(_) => "ES256",
            DidKeyPubkey::Secp256k1(_) => "ES256K",
        }
    }

    /// Raw key bytes (no multicodec prefix).
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            DidKeyPubkey::Ed25519(b) => b.as_slice(),
            DidKeyPubkey::P256(v) => v.as_slice(),
            DidKeyPubkey::Secp256k1(v) => v.as_slice(),
        }
    }

    /// Multicodec payload: `varint(codec) || key_bytes`. Used by the
    /// `did:key` encoder and by callers that want a raw identifier
    /// (e.g. CBOR identity tokens).
    pub fn to_multicodec_bytes(&self) -> Vec<u8> {
        let mut buf = [0u8; 10]; // unsigned-varint max for u64 is 10.
        let varint = unsigned_varint::encode::u64(self.codec_code(), &mut buf);
        let mut out = Vec::with_capacity(varint.len() + self.as_bytes().len());
        out.extend_from_slice(varint);
        out.extend_from_slice(self.as_bytes());
        out
    }

    /// Parse a multicodec payload into a [`DidKeyPubkey`]. Returns an
    /// error for unknown codecs or length mismatches.
    pub fn from_multicodec_bytes(bytes: &[u8]) -> Result<Self, DidKeyError> {
        let (code, rest) = unsigned_varint::decode::u64(bytes)
            .map_err(|e| DidKeyError::InvalidMultibase(format!("varint: {e}")))?;
        match code {
            CODEC_ED25519 => {
                if rest.len() != ED25519_LEN {
                    return Err(DidKeyError::InvalidKeyLength {
                        codec: "ed25519",
                        expected: ED25519_LEN,
                        actual: rest.len(),
                    });
                }
                let mut arr = [0u8; ED25519_LEN];
                arr.copy_from_slice(rest);
                Ok(DidKeyPubkey::Ed25519(arr))
            }
            CODEC_P256 => {
                if rest.len() != SEC1_COMPRESSED_LEN {
                    return Err(DidKeyError::InvalidKeyLength {
                        codec: "p-256",
                        expected: SEC1_COMPRESSED_LEN,
                        actual: rest.len(),
                    });
                }
                Ok(DidKeyPubkey::P256(rest.to_vec()))
            }
            CODEC_SECP256K1 => {
                if rest.len() != SEC1_COMPRESSED_LEN {
                    return Err(DidKeyError::InvalidKeyLength {
                        codec: "secp256k1",
                        expected: SEC1_COMPRESSED_LEN,
                        actual: rest.len(),
                    });
                }
                Ok(DidKeyPubkey::Secp256k1(rest.to_vec()))
            }
            other => Err(DidKeyError::UnknownCodec(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_roundtrip_multicodec() {
        let k = DidKeyPubkey::Ed25519([7u8; ED25519_LEN]);
        let bytes = k.to_multicodec_bytes();
        let out = DidKeyPubkey::from_multicodec_bytes(&bytes).unwrap();
        assert_eq!(k, out);
        assert_eq!(k.jws_alg(), "EdDSA");
    }

    #[test]
    fn p256_roundtrip_multicodec() {
        let mut sec1 = vec![0x02; SEC1_COMPRESSED_LEN];
        sec1[0] = 0x02; // compressed prefix
        let k = DidKeyPubkey::P256(sec1);
        let bytes = k.to_multicodec_bytes();
        let out = DidKeyPubkey::from_multicodec_bytes(&bytes).unwrap();
        assert_eq!(k, out);
        assert_eq!(k.jws_alg(), "ES256");
    }

    #[test]
    fn secp256k1_roundtrip_multicodec() {
        let mut sec1 = vec![0x02; SEC1_COMPRESSED_LEN];
        sec1[0] = 0x03;
        let k = DidKeyPubkey::Secp256k1(sec1);
        let bytes = k.to_multicodec_bytes();
        let out = DidKeyPubkey::from_multicodec_bytes(&bytes).unwrap();
        assert_eq!(k, out);
        assert_eq!(k.jws_alg(), "ES256K");
    }

    #[test]
    fn rejects_unknown_codec() {
        // 0xFFFF unused in the multicodec table as of 2026-04.
        let payload = vec![0xff, 0xff, 0x03, 1, 2, 3];
        let err = DidKeyPubkey::from_multicodec_bytes(&payload).unwrap_err();
        assert!(matches!(err, DidKeyError::UnknownCodec(_)));
    }

    #[test]
    fn rejects_wrong_ed25519_length() {
        let mut buf = [0u8; 10];
        let varint = unsigned_varint::encode::u64(CODEC_ED25519, &mut buf);
        let mut payload = varint.to_vec();
        payload.extend_from_slice(&[0u8; 16]); // wrong length
        let err = DidKeyPubkey::from_multicodec_bytes(&payload).unwrap_err();
        assert!(matches!(err, DidKeyError::InvalidKeyLength { .. }));
    }
}
