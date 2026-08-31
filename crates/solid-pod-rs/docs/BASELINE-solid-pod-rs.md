---
title: solid-pod-rs Architecture Baseline
doc_id: SPR-BASELINE
version: 0.1.0
status: active-normative
verified_commit: 0ccad60
sources:
  - crates/solid-pod-rs/src/lib.rs
  - crates/solid-pod-rs/src/oidc/mod.rs
  - crates/solid-pod-rs/src/auth/nip98.rs
  - crates/solid-pod-rs/src/auth/replay.rs
  - crates/solid-pod-rs/src/auth/replay_store.rs
  - crates/solid-pod-rs/src/security/dotfile.rs
  - crates/solid-pod-rs/src/multitenant.rs
  - crates/solid-pod-rs/src/wac/parser.rs
  - crates/solid-pod-rs/src/mrc20.rs
  - crates/solid-pod-rs/src/provenance.rs
  - crates/solid-pod-rs-server/src/lib.rs
  - crates/solid-pod-rs-git/src/auth.rs
  - crates/solid-pod-rs-server/Cargo.toml
  - Cargo.toml
date: 2026-08-31
---

# solid-pod-rs Architecture Baseline

## Purpose

Single source of truth for the solid-pod-rs crate family: what the code does
*now* — its authentication, access-control, OIDC, provenance and multitenancy
surfaces — and where the shipped code diverges from the legacy ADR corpus
(ADR-057 … ADR-061, now archived). Ground-truth order: **live code > legacy ADR
prose**. Every load-bearing claim carries a `file:line` citation into the tree
at `verified_commit`. Legacy ADRs are cited as evidence ("legacy ADR-059"),
never as authority.

## Current State

### Workspace shape

The workspace ships eight crates (`Cargo.toml`), library-first: `solid-pod-rs`
(the core library), the embedded HTTP server `solid-pod-rs-server`, and the
siblings `-git`, `-idp`, `-activitypub`, `-nostr`, `-didkey`, `-forge`.
Workspace version is `0.5.0-alpha.8` (`Cargo.toml:15`) — four alphas past the
`0.5.0-alpha.4` at which legacy ADR-060 was written, and eight past the
`0.5.0-alpha.0` legacy ADR-059 set as its acceptance tag.

### NIP-98 authentication (single-sourced)

The NIP-98 HTTP-signature verifier is single-sourced in the core library:
`crates/solid-pod-rs/src/auth/nip98.rs` exposes `verify` (`nip98.rs:65`),
`verify_at` (`nip98.rs:97`) and `verify_at_with_policy` (`nip98.rs:116`). The
siblings delegate rather than re-implement: `solid-pod-rs-git` calls
`solid_pod_rs::auth::nip98::verify_at_with_policy` with a `GitLenient` match
policy (`solid-pod-rs-git/src/auth.rs:144,157`), and `solid-pod-rs-idp` reuses
`verify_schnorr_signature` (`solid-pod-rs-idp/src/schnorr.rs:11`).

Replay protection is a single-use nonce cache, `Nip98ReplayCache`
(`auth/replay.rs:70`), now formalised behind a `trait ReplayStore`
(`auth/replay_store.rs:68`) with `Nip98ReplayCache` as the reference implementor
(`auth/replay.rs:178`). The cache is **process-local**: replay protection does
not span replicas, and the out-of-repo forum/CF edge tier keeps its own
datastore — the documented edge-local exception (`auth/replay.rs:20,174`).

### OIDC / DPoP surface

`crates/solid-pod-rs/src/oidc/mod.rs` implements the **Solid-OIDC 0.1** profile:
dynamic client registration, a discovery document (`discovery_for`,
`oidc/mod.rs:156`), DPoP proof verification with the RFC 9449 §4.3 `ath` binding,
and access-token verification accepting `ES256`/`RS256`/`EdDSA`
(`oidc/mod.rs:549,765`). The crypto path already dispatches `EdDSA`; the
**discovery metadata does not advertise it** (`oidc/mod.rs:184`). This is the
Solid-OIDC 0.1 wire, *not* the LWS10 profile — the LWS10 delta legacy ADR-057
enumerated is unshipped (see divergences).

### Access control, dotfiles and multitenancy

- Dotfile allowlist `DEFAULT_ALLOWED = [".acl", ".meta", ".account"]`
  (`security/dotfile.rs:24`) — `.account` is present.
- Pod-label sanitisation scrubs `..` with an **iterative double-pass**
  `scrub_dotdot` loop that runs until the string stops changing, defeating the
  `....//` bypass (`multitenant.rs:181-198`), guarded further by an explicit
  `!safe.contains("..")` check (`multitenant.rs:118`).
- WAC ACL parsing enforces a byte cap `MAX_ACL_BYTES` (`JSS_MAX_ACL_BYTES`,
  default 1 MiB) at the parse boundary, rejecting oversized bodies before serde
  (`wac/parser.rs:23-39`).

### Provenance (git-marks + block-trails)

The provenance composition shipped (legacy ADR-059 Phase 5, commit `182ed31`):
`ProvenanceLog::record` in `crates/solid-pod-rs/src/provenance.rs` is the single
canonical write path, invoked from the server's `git_mark_write`
(`solid-pod-rs-server/src/lib.rs:3317`) on every LDP `PUT`/`POST`/`PATCH`
(`lib.rs:1374,1486,1582`). The "SINGLE canonical path" comment sits at
`lib.rs:3400`. It composes a cheap git-mark (always) with an opt-in Bitcoin
block-trail anchor (per resolved `AnchorPolicy`).

**But it is off in a default build.** The server's default feature set is empty
(`solid-pod-rs-server/Cargo.toml:123`), so `git_mark_write` compiles to the
no-op shim `#[cfg(not(feature = "git"))]` (`lib.rs:3490`) and a default build
records **zero** provenance marks. Marks require `--features git`.

The MRC20 block-trail crypto (RFC-8785 JCS, SHA-256 state-chaining, BIP-341
taproot) lives in `mrc20.rs`; the mempool REST client defaults to the **public**
`mempool.space/testnet4` explorer (`mrc20.rs` mempool client + legacy ADR-061).

### Non-destructive PATCH

`handle_patch` (`solid-pod-rs-server/src/lib.rs:1498`) seeds the working graph
from the stored resource via `seed_graph_from_patch_target` (`lib.rs:1769`)
before applying the patch, failing closed on an unparseable existing body. This
is the REC-1 fix (commit `791977a`).

## Known divergences & open items

1. **LWS10 OIDC delta unshipped (legacy ADR-057).** The "negligible-cost P1"
   items never landed: discovery still advertises
   `dpop_signing_alg_values_supported: ["ES256","RS256"]` (`oidc/mod.rs:184`) —
   no `EdDSA` (B.3); there is no `lws_supported` field, only `solid_oidc_supported`
   (`oidc/mod.rs:151,185`) (B.5); `extract_webid` reads only the top-level
   `webid` claim and a URL-shaped `sub`, with **no `cnf.webid` branch**
   (`oidc/mod.rs:864-876`) (C.1); no `authorization_response_iss_parameter_supported`
   (B.1) or `client_registration_types_supported` (B.4). The pod is Solid-OIDC
   0.1, not LWS10.
2. **Legacy ADR-058's security "gaps" are all closed.** ADR-058 lists
   `.account` allowlist (P1), iterative `..` sanitisation (P0) and size-capped
   ACL parse (`safeJsonParse`, P0) as gaps; all three shipped
   (`security/dotfile.rs:24`, `multitenant.rs:181-198`, `wac/parser.rs:23-39`).
   ADR-058 was never updated post-Sprint 12.
3. **Provenance is off by default (legacy ADR-059 D1).** The "always-on
   git-mark" wording is contradicted by the empty default feature set
   (`solid-pod-rs-server/Cargo.toml:123`, no-op shim `lib.rs:3490`). Every
   provenance claim must carry the `--features git` caveat.
4. **No pod-wide `_prov` enumeration (REC-11).** The provenance query surface is
   point-lookup only — `GET /{pod}/_prov/{commit_sha}` plus per-resource
   `.prov.ttl` sidecars — so "one queryable trace over a whole pod" is not
   delivered. The contract, not the endpoint, is this crate's REC-11 share
   (legacy ADR-060 Decision 3).
5. **Cross-tier NIP-98 replay store open across a repo boundary.** The
   `ReplayStore` seam exists (`auth/replay_store.rs:68`) but reaches
   `integrated` only when a second tier (forum/CF) consumes it; that tier is a
   sibling repository (legacy ADR-060 Decision 2).
6. **LAN Bitcoin node cutover unverified (legacy ADR-061).** `192.168.2.27` was
   unreachable at design time (2026-08-25); the shipped default stays public
   `mempool.space/testnet4`. The LAN URL is deployment config, gated on the
   acceptance checklist, not a crate default.
7. **Legacy ADR line citations rotted.** `solid-pod-rs-server/src/lib.rs` grew
   to ~5,059 lines; ADR-060's cited offsets (`git_mark_write` @2838,
   `handle_patch` @1210, `seed_graph_from_patch_target` @1467, "SINGLE canonical
   path" @2917) no longer match the code (actual: 3317, 1498, 1769, 3400). This
   baseline supersedes those numbers.

## Invariants (must not silently change)

1. **NIP-98 is single-sourced.** One verifier in `auth/nip98.rs`; siblings
   delegate. Re-implementing it in a sibling crate is a regression.
2. **NIP-98 replay protection keeps both layers** — freshness window *and*
   single-use `ReplayStore` claim — and is process-local by design; any
   multi-replica deployment must add shared state before relying on it.
3. **Pod-label `..` scrubbing stays iterative.** Reverting `scrub_dotdot` to a
   single pass reopens the `....//` traversal bypass.
4. **ACL parsing stays size-capped** at the parse boundary — removing the cap
   reopens the parse-bomb DoS.
5. **Provenance never changes a write's HTTP status.** `git_mark_write` is
   additive and best-effort; every mark/anchor/sidecar failure is logged and
   swallowed after the LDP write has already succeeded.
6. **Discovery metadata must match the crypto path.** If `EdDSA` (or any alg) is
   advertised, the verifier must accept it, and vice versa — today the verifier
   accepts `EdDSA` but discovery omits it; closing that gap must keep the two in
   lockstep.

## Change process

Any change to the surfaces above updates this baseline **in the same commit**:
revise the affected section with the new `file:line`, confirm the relevant
invariant still holds, bump `version`, and re-record `verified_commit` from
`git rev-parse --short HEAD`. New decisions are recorded as thin ADRs in
`docs/adr/` (copy `docs/adr/TEMPLATE.md`, next free number, honest three-axis
status) and must cite this baseline. Legacy ADRs in `docs/archive/adr/` are
frozen evidence — cite them, never defer to them.
