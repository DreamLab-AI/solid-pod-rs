# solid-pod-rs-git

**Status: 0.4.0-alpha.15 — functional Git HTTP backend.** 1,685 LOC,
25 tests. Integrators may depend on this crate today.

## Target scope

- Git HTTP smart-protocol backend (`info/refs`, `upload-pack`,
  `receive-pack`) mounted as a pod sub-scope.
- Path-traversal hardening matching JSS `src/handlers/git.js`.
- `receive.denyCurrentBranch=updateInstead` semantics for live,
  single-checkout pods.
- `Basic nostr:<token>` client support bridging NIP-98 to git
  clients that speak HTTP Basic only.
- WAC integration so repo `.git/` trees honour the enclosing pod's
  ACL.

Target LOC: ~450 + 12 integration tests at first landing.

## Parity rows

Rows that will close when this crate lands (see
[`../solid-pod-rs/PARITY-CHECKLIST.md`](../solid-pod-rs/PARITY-CHECKLIST.md)):

- **69** — `Basic nostr:<token>` HTTP Basic bridge to NIP-98.
- **100** — Git HTTP smart-protocol backend.

## JSS references

- `src/handlers/git.js`

## Licence

AGPL-3.0-only.
