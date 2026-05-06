# solid-pod-rs-didkey

W3C `did:key` (Ed25519 / P-256 / secp256k1) resolver and self-signed JWT
verifier for [solid-pod-rs](https://crates.io/crates/solid-pod-rs).

## What it does

- Parses and encodes `did:key:z...` multibase identifiers.
- Resolves a `did:key` to a W3C DID Document with verification methods.
- Verifies compact JWS tokens self-signed by an embedded `did:key`.
- Implements `solid_pod_rs::SelfSignedVerifier` so it plugs into the
  core `CidVerifier` dispatcher.

## Supported key types

| Multicodec | Algorithm   | JWS `alg` |
|------------|-------------|-----------|
| 0xed       | Ed25519     | EdDSA     |
| 0x1200     | P-256       | ES256     |
| 0xe7       | secp256k1   | ES256K    |

## Quick start

```rust,no_run
use solid_pod_rs_didkey::{decode_did_key, encode_did_key, DidKeyPubkey};

let did = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";
let pubkey = decode_did_key(did).unwrap();
let roundtrip = encode_did_key(&pubkey);
assert_eq!(roundtrip, did);
```

## Licence

AGPL-3.0-only
