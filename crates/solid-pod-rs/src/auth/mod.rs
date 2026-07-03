//! Authentication modules.
//!
//! Phase 1 ships NIP-98 structural verification (tag layout,
//! URL/method/payload match, timestamp tolerance). Schnorr signature
//! verification is the `nip98-schnorr` feature on [`nip98`]. Sprint 11
//! adds [`self_signed`] — the Controlled Identifier verifier abstraction
//! (row 152) used to fan out across did:key, NIP-98, did:nostr, etc.

pub mod nip98;
pub mod self_signed;

/// NIP-98 single-use replay guard (F3). Gated behind `nip98-replay`; the
/// native single-process pod tier wires it into every request so a
/// captured token cannot be replayed within the ~120s tolerance window.
#[cfg(feature = "nip98-replay")]
pub mod replay;

#[cfg(feature = "lws-cid")]
pub mod lws_cid;
