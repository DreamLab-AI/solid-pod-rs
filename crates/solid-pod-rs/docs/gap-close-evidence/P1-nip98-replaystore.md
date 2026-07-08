# P1 evidence — NIP-98 `ReplayStore` trait extraction (WP-2 / ADR-060 Decision 2)

**Item:** Extract `trait ReplayStore` from the process-local `Nip98ReplayCache`
into the core crate, with the existing cache as the reference implementor;
every in-repo tier consumes the trait; the out-of-repo forum/CF tier is the
documented edge-local exception.
**Base commit verified against:** `48c826a` (`gap-close/2026-07`)
**Maturity:** cross-tier seam `scaffolded` → `standalone` (trait published, one
reference implementor; `integrated` withheld until a second tier consumes it).

## What changed

| File | Change |
|---|---|
| `crates/solid-pod-rs/src/auth/replay_store.rs` (new) | `trait ReplayStore: Send + Sync` + `enum ReplayError`, compiled on every build (no `lru`/tokio gate) so a pure-`core` wasm/CF consumer can depend on the nonce contract. |
| `crates/solid-pod-rs/src/auth/mod.rs` | `pub mod replay_store;` (ungated). |
| `crates/solid-pod-rs/src/auth/replay.rs` | `Nip98ReplayCache` now implements `ReplayStore` (moved `check_and_record` out of the inherent impl into `#[async_trait] impl ReplayStore`); re-exports `ReplayError`/`ReplayStore` for the historical path; new `trait_object_dispatch_rejects_replay` test. |
| `crates/solid-pod-rs-server/src/lib.rs` | Imports `auth::replay::ReplayStore`; the native single-process tier now drives `NIP98_REPLAY.check_and_record` **through the trait**, not an inherent method. |

The seam is genuine, not a same-crate rename: `check_and_record` exists **only**
on the trait now, so every caller must bring `ReplayStore` into scope. In this
repo the one caller is the server; the forum/CF tier is out of repo and supplies
its own datastore-backed implementor (edge-local exception, documented in the
trait module and ADR-060 Decision 2).

## Receipts

### R1 — core replay tests exercise the trait (5 pass)

```
$ date -u '+%Y-%m-%dT%H:%M:%SZ'   # 2026-07-08T12:51:49Z
$ cargo test -p solid-pod-rs --features nip98-replay --lib auth::replay
running 5 tests
test auth::replay::tests::expired_entry_treated_as_fresh ... ok
test auth::replay::tests::clones_share_storage ... ok
test auth::replay::tests::trait_object_dispatch_rejects_replay ... ok
test auth::replay::tests::first_sighting_accepts_replay_rejects ... ok
test auth::replay::tests::capacity_eviction_is_bounded ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 427 filtered out; finished in 0.00s
```

`first_sighting_accepts_replay_rejects` proves a re-presented id inside the TTL
returns `ReplayError::Replayed`; `trait_object_dispatch_rejects_replay` proves
the same through an `Arc<dyn ReplayStore>` (object-safe seam an out-of-repo tier
can hold over its own store).

### R1b — no NIP-98 verifier re-implementation outside core (single-source)

```
$ grep -rn "verify_schnorr_signature\|fn verify_at\b" crates/*/src --include="*.rs" \
    | grep -v "crates/solid-pod-rs/src/auth/nip98.rs"
（no output — zero re-implementations; git/idp/server all delegate to auth::nip98）
```

### R1c — the server tier compiles consuming the trait

```
$ cargo check -p solid-pod-rs-server
    Checking solid-pod-rs-server v0.5.0-alpha.4
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 7.03s
```

### R1d — no auth-module regression (23 pass)

```
$ cargo test -p solid-pod-rs --features nip98-replay --lib auth::
running 23 tests
test result: ok. 23 passed; 0 failed; 0 ignored; 0 measured; 409 filtered out; finished in 0.01s
```

## Falsification (WP-2) — how this survives it

- *"any crate reintroduces a NIP-98 verifier that does not delegate to
  `auth::nip98`"* → R1b greps zero re-implementations.
- *"a replayed token is accepted inside the tolerance window"* → R1 rejects a
  re-presented id (`ReplayError::Replayed`), incl. via the trait object.
- *"the seam is claimed `integrated` while no second tier consumes it"* → the
  seam is claimed **`standalone`**, not integrated; the edge-local exception is
  documented (trait module doc + ADR-060 Decision 2), and `integrated` is
  explicitly withheld until a second tier consumes the trait.
- *"the shipped server binds only a slice the library implements without that
  being documented"* → the server consumes the full `ReplayStore` contract
  (R1c), documented in the import comment and this file.
