//! Authentication modules.
//!
//! Phase 1 ships NIP-98 structural verification (tag layout,
//! URL/method/payload match, timestamp tolerance). Schnorr signature
//! verification is the `nip98-schnorr` feature on [`nip98`]. Sprint 11
//! adds [`self_signed`] — the Controlled Identifier verifier abstraction
//! (row 152) used to fan out across did:key, NIP-98, did:nostr, etc.

pub mod nip98;
pub mod self_signed;
