# solid-pod-rs-nostr

**Status: 0.5.0-alpha.12 — functional did:nostr + embedded relay.**
2,177 LOC, 45 tests. Integrators may depend on this crate today.

Note: the did:nostr bidirectional resolver also ships inside the core
library at `interop::did_nostr` (feature `did-nostr`). This sibling
crate adds the **embedded relay** and the Tier 3 DID surface on top
of that core resolver.

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

Rows this crate serves (see
[`../solid-pod-rs/PARITY-CHECKLIST.md`](../solid-pod-rs/PARITY-CHECKLIST.md)):

- **89** and **132** — did:nostr DID Document publication (Tier 1 / Tier 3).
- **90** — did:nostr ↔ WebID resolver via `alsoKnownAs`.
- **101** — Nostr relay, NIP-01 / NIP-11 / NIP-16. `partial-parity`: the relay
  is a library for embedders; `solid-pod-rs-server` does not mount it, so the
  NIP-11 document is not served over HTTP (rows 278, 280).
- **108** — SAND composition (AP Actor + did:nostr `alsoKnownAs`), with
  `solid-pod-rs-activitypub`.

## JSS references

- `src/did/resolver.js`
- `src/nostr/relay.js`
- `src/auth/did-nostr.js`

## Licence

AGPL-3.0-only.
