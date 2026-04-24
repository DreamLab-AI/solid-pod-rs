# solid-pod-rs-activitypub

**Status: Reserved stub for v0.5.0. Not yet implemented.**

This crate is a namespace placeholder in the `solid-pod-rs` workspace.
`src/lib.rs` contains a doc comment and nothing else. Do not depend on
it from integrator code — the module graph is empty until v0.5.0.

## Target scope

- Actor discovery (ActivityPub §3 + NodeInfo 2.0).
- `POST /inbox` handling with HTTP Signature verification.
- Outbox + federated delivery (Accept / Follow / Undo / Create).
- Follower / Following stores backed by `solid-pod-rs` storage.
- NodeInfo 2.0 emission at `/.well-known/nodeinfo` (nb: the NodeInfo
  2.1 discovery document already ships in the core library's
  `interop::nodeinfo_2_1`).
- Integration with `solid-pod-rs`'s WAC evaluator for per-actor
  authorisation.
- SAND stack composition: AP Actor on `/profile/card` composed with
  did:nostr via `alsoKnownAs` (bundles with `solid-pod-rs-nostr`).

Target LOC: ~1,200 + 40 unit + 15 integration tests at first landing.

## Parity rows

Rows that will close when this crate lands (see
[`../solid-pod-rs/PARITY-CHECKLIST.md`](../solid-pod-rs/PARITY-CHECKLIST.md)):

- **102** — ActivityPub Actor discovery.
- **103** — inbox with HTTP Signature verification.
- **104** — outbox emission.
- **105** — Follow / Accept / Undo handling.
- **106** — Create activity delivery.
- **107** — Follower + Following collections.
- **108** — ActivityPub conformance subset.
- **131** — NodeInfo 2.0 (AP-specific fields).

## JSS references

- `src/ap/index.js`
- `src/ap/routes/inbox.js`
- `src/ap/routes/outbox.js`
- `src/ap/store.js`

## Licence

AGPL-3.0-only.
