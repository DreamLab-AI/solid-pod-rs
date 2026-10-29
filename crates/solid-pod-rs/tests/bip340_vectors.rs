//! BIP-340 published test vectors against the `k256` Schnorr implementation.
//!
//! The fixture `tests/fixtures/bip340-test-vectors.csv` is the unmodified
//! upstream file from
//! <https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv>
//! (19 vectors). It guards the RustCrypto 0.14 migration: rows with a secret
//! key must reproduce the published signature byte for byte, and every row
//! must verify (or be rejected) exactly as the `verification result` column
//! states.

#![cfg(feature = "nip98-schnorr")]

use k256::schnorr::{Signature, SigningKey, VerifyingKey};

const VECTORS: &str = include_str!("fixtures/bip340-test-vectors.csv");

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("bad hex {s:?}: {e}"))
}

#[test]
fn bip340_published_vectors() {
    let mut rows = 0;
    let mut signed = 0;
    for line in VECTORS.lines().skip(1).filter(|l| !l.trim().is_empty()) {
        let f: Vec<&str> = line.trim_end().split(',').collect();
        assert_eq!(f.len(), 8, "malformed row: {line}");
        let (index, secret, public, aux, msg, sig, result) =
            (f[0], f[1], f[2], f[3], unhex(f[4]), unhex(f[5]), f[6]);
        let expect_ok = match result {
            "TRUE" => true,
            "FALSE" => false,
            other => panic!("vector {index}: bad result column {other:?}"),
        };

        // Signing rows: secret key present, so sign and compare bytes.
        if !secret.is_empty() {
            let sk = SigningKey::from_slice(&unhex(secret)).expect("valid secret key");
            assert_eq!(
                hex::encode_upper(sk.verifying_key().to_bytes()),
                public,
                "vector {index}: derived public key"
            );
            let aux: [u8; 32] = unhex(aux).try_into().expect("32-byte aux_rand");
            let got = sk.sign_raw(&msg, &aux).expect("sign_raw");
            assert_eq!(
                hex::encode_upper(got.to_bytes()),
                f[5],
                "vector {index}: signature bytes"
            );
            signed += 1;
        }

        // Every row: verify, treating unparseable keys/signatures as rejection.
        let verified = (|| {
            let vk = VerifyingKey::from_slice(&unhex(public)).ok()?;
            let sig = Signature::try_from(sig.as_slice()).ok()?;
            vk.verify_raw(&msg, &sig).ok()
        })()
        .is_some();
        assert_eq!(verified, expect_ok, "vector {index}: verification result");
        rows += 1;
    }
    assert_eq!(rows, 19, "expected all 19 BIP-340 vectors");
    assert_eq!(signed, 8, "vectors 0-3 and 15-18 carry secret keys");
}
