# solid-pod-rs-nostr

**Status: Reserved stub for v0.5.0. Not yet implemented.**

This crate is a namespace placeholder in the `solid-pod-rs` workspace.
`src/lib.rs` contains a doc comment and nothing else. Do not depend on
it from integrator code — the module graph is empty until v0.5.0.

Note: the did:nostr bidirectional resolver already shipped in Sprint 6
and lives inside the core library at `interop::did_nostr` (feature
`did-nostr`). This sibling crate will add the **embedded relay** and
the Tier 3 DID surface on top of that core resolver.

## Target scope

- did:nostr DID Document publication at
  `/.well-known/did/nostr/:pubkey.json` (Tier 1 / Tier 3) — Tier 1
  already in `interop::did_nostr`, this crate adds Tier 3.
- Embedded Nostr relay implementing NIP-01, NIP-11, NIP-16.
- Integration hook with `solid-pod-rs-activitypub` for the SAND
  stack (AP Actor + did:nostr via `alsoKnownAs`).
- NIP-98 Schnorr already ships in the library core
  (`auth::nip98::verify_schnorr_signature` under `nip98-schnorr`);
  this crate does not re-implement it.

Target LOC: 800–1,200 at first landing.

## Parity rows

Rows that will close when this crate lands (see
[`../solid-pod-rs/PARITY-CHECKLIST.md`](../solid-pod-rs/PARITY-CHECKLIST.md)):

- **89** — Embedded Nostr relay (NIP-01).
- **90** — Relay NIP-11 + NIP-16 support.
- **101** — did:nostr Tier 3 DID Document surface.
- **132** — SAND composition (AP Actor + did:nostr `alsoKnownAs`).

## JSS references

- `src/did/resolver.js`
- `src/nostr/relay.js`
- `src/auth/did-nostr.js`

## Licence

AGPL-3.0-only.
