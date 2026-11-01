# solid-pod-rs-git

**Workspace version: 0.5.0-alpha.18.** See the workspace changelog for unreleased
repairs and the estate review for validation and remaining export boundaries.

## Target scope

- Git HTTP smart-protocol backend (`info/refs`, `upload-pack`,
  `receive-pack`) mounted as a pod sub-scope.
- Path-traversal hardening matching JSS `src/handlers/git.js`.
- `receive.denyCurrentBranch=updateInstead` semantics for live,
  single-checkout pods.
- `Basic nostr:<token>` client support bridging NIP-98 to git
  clients that speak HTTP Basic only.
- Framework-independent transport; callers own repository read authority.

## Export authority

The caller must authorise access to the whole repository before handing a read
to `GitHttpService`. The CGI does not evaluate per-resource WAC or historical
permissions. The pod server's root-only gate does not fulfil that contract for
private children; see the workspace estate review before exposing that route.

The service refuses direct requests for unadvertised object hashes, overriding
repository-local `uploadpack.allowTipSHA1InWant`,
`uploadpack.allowReachableSHA1InWant` and `uploadpack.allowAnySHA1InWant` settings.
Ordinary advertised-tip fetches remain supported. Hidden refs still do not
provide general object isolation: content that must be withheld belongs in a
separate object store until approved for publication.

## Parity rows

Implemented transport rows (see
[`../solid-pod-rs/PARITY-CHECKLIST.md`](../solid-pod-rs/PARITY-CHECKLIST.md)):

- **69** — `Basic nostr:<token>` HTTP Basic bridge to NIP-98.
- **100** — Git HTTP smart-protocol backend.

## JSS references

- `src/handlers/git.js`

## Licence

AGPL-3.0-only.
