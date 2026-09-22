# solid-pod-rs-git

**Status: 0.5.0-alpha.9 — functional Git HTTP backend.** Integrators may
depend on this crate today; see the workspace audit for current quality gates.

## Scope

- Git HTTP smart-protocol backend (`info/refs`, `upload-pack`,
  `receive-pack`) mounted as a pod sub-scope.
- Path-traversal hardening matching JSS `src/handlers/git.js`.
- `receive.denyCurrentBranch=updateInstead` semantics for live,
  single-checkout pods.
- `Basic nostr:<token>` client support bridging NIP-98 to git
  clients that speak HTTP Basic only.
- WAC integration so repo `.git/` trees honour the enclosing pod's
  ACL.

Shipped: 3,240 LOC (`src/`, 2026-09-22), 60 unit tests plus the
`git_service_sprint10` integration suite.

## Parity rows

Rows closed by this crate (see
[`../solid-pod-rs/PARITY-CHECKLIST.md`](../solid-pod-rs/PARITY-CHECKLIST.md)):

- **69** — `Basic nostr:<token>` HTTP Basic bridge to NIP-98.
- **100** — Git HTTP smart-protocol backend.

## JSS references

- `src/handlers/git.js`

## Licence

AGPL-3.0-only.
