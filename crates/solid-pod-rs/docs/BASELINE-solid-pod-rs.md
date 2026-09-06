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
- **Effective-policy resolution is typed and fail-closed** (ADR-2005,
  2026-09-05). `wac/resolver.rs` returns a `PolicyOutcome`, not a
  `Result<Option<AclDocument>, _>`: `Missing` (no `.acl` — the only outcome
  that may inherit from an ancestor, per WAC §4.2), `Found`, `Invalid`
  (present but unparseable or over-bounds — deny, never inherit) and
  `Unavailable` (backend read failed — deny, never inherit). Only a backend
  `NotFound` counts as absence; every other non-success is an unknown and can
  no longer be laundered into the ancestor's grant.
- `classify_policy_read` is the pure, runtime-free single-level decision
  function and compiles on the `core` (wasm/edge) surface;
  `resolve_policy_from_storage` is the native walk over `&dyn Storage`. The
  server's previously duplicated walk (`find_effective_acl_dyn`) now delegates
  to it, so the two paths cannot drift. `enforce_read_ctx` /
  `enforce_write_ctx` deny on a failure outcome — `Invalid` → 403,
  `Unavailable` → 503.

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

**Outcomes are typed and reported** (ADR-2004, 2026-09-05).
`ProvenanceLog::record_receipt` returns a `ProvenanceReceipt` carrying a
`ProvenanceStage` — `Skipped`, `ResourceStored` (the mark was attempted and
failed), `LocalMarkCommitted`, `AnchorSubmitted` (anchoring tx exists but is
unconfirmed) or `AnchorConfirmed` — plus per-tier `mark_error` /
`anchor_error` and a `ProvenanceSkip` reason. The server emits it on every
write as `X-Provenance` and `X-Provenance-Commit`. A failed anchor never
suppresses a successful git-mark.

The MRC20 block-trail crypto (RFC-8785 JCS, SHA-256 state-chaining, BIP-341
taproot) lives in `mrc20.rs`; the mempool REST client defaults to the **public**
`mempool.space/testnet4` explorer (`mrc20.rs` mempool client + legacy ADR-061).
That selection is now recorded once at startup — base URL, inferred Bitcoin
network and whether it was explicit or defaulted — by
`solid-pod-rs-server/src/mempool.rs` (`select_mempool_endpoint`,
`log_mempool_selection_once`), with a warning when the network is unknown or
the endpoint defaulted (ADR-2007).

### Response cache policy

Cache-Control is decided by the response's **audience**, not its media type
(ADR-2002, 2026-09-05). `ldp::cache_control_for_response(content_type,
ResponseAudience)` returns `CACHE_CONTROL_PRIVATE` (`private, no-store`) for
any response an anonymous client would not have received, and the media-type
policy (`CACHE_CONTROL_RDF`, or nothing for public binaries) otherwise.
`enforce_read_ctx` classifies the audience by re-evaluating the
already-resolved ACL with no principal — pure, no extra I/O — and forces
`Private` for sidecar (Control-elevated) reads. Private responses also carry
`Vary: Authorization`. Previously a private non-RDF body went out with **no**
`Cache-Control` at all, which under RFC 9111 §4.2.2 leaves a shared cache free
to store and re-serve it.

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
   `ReplayStore` seam exists (`auth/replay_store.rs`) but reaches `integrated`
   only when a second tier (forum/CF) consumes it; that tier is a sibling
   repository (legacy ADR-060 Decision 2). The contract it must satisfy is now
   explicit (atomicity, no eviction of unexpired entries, no refresh on
   rejection, documented restart semantics — ADR-2006).
5b. **The edge/WASM ACL resolver is not in this repository.** It lives in
   `nostr-rust-forum` (`crates/nostr-bbs-pod-worker/src/acl.rs`), which pins
   `solid-pod-rs =0.5.0-alpha.7, default-features = false, features = ["core"]`.
   The typed `PolicyOutcome` and `classify_policy_read` are `core`-compilable
   precisely so that tier can adopt them, but that needs a published version to
   pin. Until then the edge tier still treats failed or invalid reads as misses,
   and the same caveat applies to the private-cache policy (ADR-2002/2005).
5c. **Access-token `aud` is not validated.** `verify_access_token` sets
   `validate_aud = false`; only the claim's *presence* is enforced (no
   `#[serde(default)]` on `SolidOidcClaims::aud`). A token minted for another
   audience verifies. Pinned by `tests/oidc_compat_matrix.rs::c1`/`c2` and
   documented in the compatibility matrix. A deployment needing audience
   restriction must enforce it above this API (ADR-2003).
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
   **A bounded store never evicts an unexpired entry to make room** (ADR-2006):
   at capacity it reclaims expired entries and, failing that, refuses the new
   credential with `ReplayError::CapacityExhausted`. Reverting to LRU eviction
   reopens the replay window for whichever id is evicted. Size with
   `auth::replay::sizing_floor(peak_rps, ttl)`.
3. **Pod-label `..` scrubbing stays iterative.** Reverting `scrub_dotdot` to a
   single pass reopens the `....//` traversal bypass.
4. **ACL parsing stays size-capped** at the parse boundary — removing the cap
   reopens the parse-bomb DoS.
4b. **Only an absent policy inherits.** An `.acl` that exists but cannot be
   parsed or read must deny, never fall through to an ancestor
   (`PolicyOutcome::Invalid` / `Unavailable`). Collapsing these back into
   `Ok(None)` re-opens the ADR-2005 escalation: a malformed restrictive policy
   silently replaced by a permissive inherited one.
5. **Provenance never changes a write's HTTP status.** `git_mark_write` is
   additive and best-effort; a mark/anchor/sidecar failure never alters the
   response status after the LDP write has already succeeded. **But it is no
   longer swallowed** (ADR-2004): the failure is returned as a typed
   `ProvenanceReceipt` and surfaced on the response as `X-Provenance`. Silently
   discarding a failed mark again would make "stored" and "stored and provably
   marked" indistinguishable to the caller.
6. **Discovery metadata must match the crypto path.** If `EdDSA` (or any alg) is
   advertised, the verifier must accept it, and vice versa — today the verifier
   accepts `EdDSA` but discovery omits it; closing that gap must keep the two in
   lockstep. The full contract is
   [`reference/solid-oidc-compatibility-matrix.md`](reference/solid-oidc-compatibility-matrix.md),
   pinned by `tests/oidc_compat_matrix.rs`; a change to either half updates both.
7. **A private response is never advertised as publicly cacheable** (ADR-2002).
   Any response an anonymous client would not have received carries
   `private, no-store`, whatever its media type. Reverting to a media-type-only
   policy leaves private binaries heuristically cacheable by shared caches.

## Change process

Any change to the surfaces above updates this baseline **in the same commit**:
revise the affected section with the new `file:line`, confirm the relevant
invariant still holds, bump `version`, and re-record `verified_commit` from
`git rev-parse --short HEAD`. New decisions are recorded as thin ADRs in
`docs/adr/` (copy `docs/adr/TEMPLATE.md`, next free number, honest three-axis
status) and must cite this baseline. Legacy ADRs in `docs/archive/adr/` are
frozen evidence — cite them, never defer to them.

## Estate closeout qualification — 2026-09-04

[ADR-2005](adr/ADR-2005-fail-closed-untrusted-parsing.md) now separates completed
parser bounds from the unresolved effective-policy failure contract. The
[CP-04 closeout roadmap](../../../../VisionFlow/docs/estate-review/closeout/README.md)
requires invalid/unavailable ACL resolution, inheritance and revocation checks
across native and edge consumers. Existing parser completion must not be used
as evidence that those composed paths fail closed. The resolver probe records
a current gap; no repair or deployment is claimed by this documentation update.

## Complete-system acceptance qualification — 2026-09-04

All seven operative ADRs now distinguish scoped implementation from consumer acceptance. WAC selection and bounded parsing do not establish resolver denial or private-cache policy. ReplayStore is an interface; the reference bounded LRU does not retain all events through its nominal window under eviction. Default-off provenance remains intentional; opting in does not make resource mutation, git marking and external anchoring atomic.

OIDC discovery and WebID extraction are source observations, not a refreshed standards or deployed interoperability certification. The single configured mempool URL has a public default for absent/blank configuration; no runtime fallback chain is implied. Release acceptance needs exact consumer versions/features, fail/restart receipts and separately observable content, mark and anchor outcomes. See the [estate storage review](../../../../VisionFlow/docs/estate-review/storage-and-authority.md).

## Estate closeout progress — 2026-09-05

The 2026-09-04 qualifications above are partly discharged **in this
repository**; none of them is discharged at the deployed or cross-repo tier,
and no ADR's `activation_status` or `verified_commit` changed.

| ADR | In-repo status after this change |
|---|---|
| [ADR-2002](adr/ADR-2002-wac-access-model.md) | Private-cache policy implemented at the server layer and tested; the **forum edge** finding stays open (sibling repo). |
| [ADR-2003](adr/ADR-2003-solid-oidc-01-defer-lws10.md) | Versioned compatibility matrix + 28 executable checks replace source observations. Three divergences (audience not validated, malformed `webid` silently ignored, issuer normalisation asymmetry) are now documented and pinned — **not fixed**. |
| [ADR-2004](adr/ADR-2004-provenance-off-by-default.md) | Content, mark and anchor outcomes are separately observable and typed; a failed mark reaches the caller. Write-then-mark **ordering is unchanged** — the three steps are still not atomic; the receipt makes the window observable, not closed. |
| [ADR-2005](adr/ADR-2005-fail-closed-untrusted-parsing.md) | Typed missing/invalid/unavailable outcomes carried through the native and object-safe resolvers, which are now one implementation. Edge resolver is out of repo. |
| [ADR-2006](adr/ADR-2006-nip98-replaystore-seam.md) | The reference bounded LRU now retains every event through its nominal window: at capacity it refuses rather than evicting an unexpired entry. The seam remains `standalone` — one implementor. |
| [ADR-2007](adr/ADR-2007-mempool-single-url-no-fallback.md) | Endpoint, inferred network and explicit-vs-defaulted source recorded once at startup; unknown-transaction and ambiguous-failure remain distinct. Still a single URL, still no fallback chain. |
| [ADR-2001](adr/ADR-2001-corpus-consolidation.md) | Not advanced by this change. |

**What this evidence does and does not establish.** It is in-process test
evidence at the working tree, produced with no network access: 1801 tests
passing across 114 binaries, `cargo clippy --all-targets --all-features
-- -D warnings` clean, and the `core` (wasm/edge) feature surface compiling.
It does **not** establish deployed activation, behaviour observed through a
real cache or across a restart, or conformance of any out-of-repo consumer.

**Consumer compatibility.** `nostr-rust-forum` pins
`solid-pod-rs =0.5.0-alpha.7, default-features = false, features = ["core"]`.
No crate version was bumped, so that consumer is unaffected by this work and
also cannot yet adopt it. Every new type intended for the edge tier —
`PolicyOutcome`, `InvalidPolicyReason`, `PolicyRead`, `PolicyStep`,
`classify_policy_read`, `ResponseAudience`, `cache_control_for_response` —
compiles under `core` so adoption is a version pin, not a port. The one
source-compatibility note is `ReplayError`, which gained a
`CapacityExhausted` variant and is now `#[non_exhaustive]`; `nip98-replay` is
not in `core`, so no in-estate consumer is affected.

Receipts: [`estate-closeout/2026-09-05/test-run.md`](estate-closeout/2026-09-05/test-run.md).
