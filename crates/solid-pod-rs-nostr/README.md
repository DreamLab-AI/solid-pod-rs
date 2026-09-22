# solid-pod-rs-nostr

**Status: 0.5.0-alpha.9 — functional did:nostr + embedded relay.**
2,666 LOC (`src/`), 63 unit tests plus the `did_nostr_resolver` and
`relay_nip11` integration suites (counts at 2026-09-22). Integrators may
depend on this crate today.

Note: the did:nostr bidirectional resolver also ships inside the core
library at `interop::did_nostr` (feature `did-nostr`). This sibling
crate adds the **embedded relay** and the Tier 3 DID surface on top
of that core resolver.

## Scope

- did:nostr DID Document publication at
  `/.well-known/did/nostr/:pubkey.json` (Tier 1 / Tier 3) — Tier 1
  already in `interop::did_nostr`, this crate adds Tier 3.
- Embedded Nostr relay implementing NIP-01, NIP-11, NIP-16.
- Integration hook with `solid-pod-rs-activitypub` for the SAND
  stack (AP Actor + did:nostr via `alsoKnownAs`).
- NIP-98 Schnorr already ships in the library core
  (`auth::nip98::verify_schnorr_signature` under `nip98-schnorr`);
  this crate does not re-implement it.

## Parity rows

Rows closed by this crate (see
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
