# Changelog

All notable changes to solid-pod-rs will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.5.0-alpha.8] - 2026-08-20

A feature-parity and hardening bump. The public surface loses the unfinished
S3 backend and gains capability-sandboxed filesystem storage, an atomic quota
reservation path, and an observer-atomic payment ledger; the ActivityPub, git,
IdP and nostr siblings each pick up a targeted correctness or hardening fix.
All eight workspace crates are re-pinned to `0.5.0-alpha.8`.

### Removed

- **S3 storage backend dropped.** The `s3-backend` feature, the `aws-sdk-s3`
  dependency, the `StorageBackendConfig::S3` config variant, and the
  `JSS_S3_BUCKET` / `JSS_S3_REGION` / `JSS_S3_PREFIX` env vars are gone.
  Storage is now filesystem or memory only; downstream consumers needing an
  object store supply their own `Storage` implementation. An unsupported
  `JSS_STORAGE_TYPE` (including `s3`) is now preserved through the env layer
  so tagged-enum deserialisation fails loudly, rather than silently falling
  back to filesystem storage. The core / wasm dependency surface shrinks.

### Security

- **Filesystem backend is capability-sandboxed (`cap-std`).** `FsBackend`
  now holds a `cap_std::fs::Dir` handle rooted at the pod store, so path
  traversal is prevented at the OS-handle level rather than by string
  inspection alone. `fs-backend` pulls `cap-std`.
- **Atomic quota reservation.** `QuotaPolicy` gains a `reserve` method that
  performs check-and-commit under a per-pod async lock, so concurrent writers
  to the same pod can no longer each pass a pre-check and collectively
  overshoot the cap. The existing `check` + `record` pair is retained as the
  non-atomic cooperative discipline; `record` and `reconcile` also take the
  per-pod lock now. New `security.default_quota_bytes` config field.
- **Observer-atomic payment state.** The payment handlers now commit the Web
  Ledger, replay set, order book and exchange together as a single
  `state.json` document via one `Storage::put`; the legacy per-concern
  documents (`webledgers/ledger.json`, `replay.json`, `offers.json`,
  `pool.json`) are demoted to best-effort compatibility mirrors, consulted on
  read only as a first-run bootstrap fallback. This closes a crash window
  between the ledger and replay writes that could double-credit a deposit.
  Adds `base64` / `hex` / `hmac` / `sha2` to the server for TXO txid
  derivation and dev-bearer HMAC auth.
- **HTTP-signature covered-component validation (ActivityPub).** The verifier
  now rejects a well-formed `Signature` header that omits or duplicates a
  required covered component (`SigError::MalformedSignature`).
- **IdP: spoofable header path removed.** An `AuthenticatedUserId` extractor
  replaces the trust-the-`X-Authenticated-User`-header path, and the DPoP
  replay cache is wired into the provider.
- **Git CGI execution timeout.** A 120 s guard kills a hung
  `git-http-backend` child, surfaced as `GitError::BackendFailed` with
  `exit_code: None`.
- **Nostr relay limits.** `RelayLimits` / `dispatch_message_with_limits` bound
  per-connection relay message handling in the WebSocket path.

### Changed

- **`solid-pod-rs-forge`** enables `nip98-schnorr` + `nip98-replay` on its
  core dependency and makes agent resolution async with replay handling.
- **Server transport trimmed.** `actix-web` is taken at
  `default-features = false, features = ["macros"]`; `rustls-pemfile` is
  dropped from the `tls` feature. `lru` moves `0.16 → 0.18`.
- **CI / release hardening.** All workflow actions are pinned to commit SHAs;
  the core feature matrix is restructured (nested `features` object) and the
  now-removed `s3-backend` combination is gone; coverage (tarpaulin) is
  promoted to a required gate (`--fail-under 60`, `fail_ci_if_error: true`);
  `cargo-deny` runs against the workspace-root manifest. New security
  regression tests land for MCP/WAC, payment atomicity, quota enforcement and
  registration.

## [0.5.0-alpha.7] - 2026-07-26

did:nostr CG spec 0.1.1 alignment plus the JSS `0.0.204 → 0.0.219`
comparator sync. The upstream delta was audited commit-by-commit: most of it
is either already covered here (raw-bytes NIP-98 hashing, POST-sidecar
Control elevation, MCP `write_acl` accessTo, HEAD conneg — all structural or
closed by the alpha.4 closeout) or not applicable to a compiled server (the
entire 11-commit runtime-plugin cluster, node-oidc-provider/Fastify/n3.js
specific fixes). One genuine gap and one latent bug were found and fixed.

### Changed

- **did:nostr `@context` is now the CG spec 0.1.1 three-context form** —
  `["https://www.w3.org/ns/did/v1", "https://www.w3.org/ns/cid/v1",
  "https://w3id.org/nostr/context"]`, with the DID Core context first as
  DID Core requires (and as the DID 1.1 transition expects). Previously the
  documents carried only the two-entry `[cid/v1, nostr/context]` form.
  Applied at the single canonical renderer
  (`did_nostr_types::render_did_document`), the `interop` malformed-hex
  fallback, and across tests, conformance fixtures, and fixture schemas in
  the `nostr` and `didkey` crates. Both forms expand to the same terms under
  JSON-LD, so consumers that parse rather than byte-compare are unaffected.

### Fixed

- **Git smart-HTTP CORS on denied responses (JSS #548)** — the WAC gate's
  401/402/403 and the git service's error responses (e.g. 404
  `NotARepository`) now carry the git CORS trio, so browser-based git
  clients see the real status and `WWW-Authenticate` challenge instead of a
  generic CORS error. The trio is now a single source of truth
  (`service::GIT_CORS_HEADERS`) shared by the preflight, success, error,
  and WAC-denial paths, and `Access-Control-Allow-Headers` gains
  `Git-Protocol` (protocol-v2 clients send it). The server-wide CORS
  middleware now defers to handler-set `Access-Control-Allow-Origin`
  (git/forge surfaces are deliberately `*`-open), making git CORS identical
  in wildcard and allowlist deployments; the global preflight header list
  also gains `Git-Protocol`.
- **IdP issuer slash-normalisation (JSS #524 class)** — `ProviderConfig::new`
  now canonicalises the issuer to its trailing-slash form, so the discovery
  document's `issuer`, the RFC 9207 `iss` authorization-response parameter,
  and the access-token `iss` claim are byte-identical regardless of how the
  operator wrote the config. Previously discovery slash-normalised while
  token minting used the raw configured string — strict clients comparing
  the two byte-for-byte would reject the response.
- **IdP DPoP test helper minted HS256 proofs** — the alg-confusion gate
  (audit sprint) rightly rejects HS*/`kty=oct` DPoP proofs, which had left
  two provider unit tests failing on `main`. The helper now mints real
  ES256 proofs with an embedded P-256 JWK.

### Added

- **`JSS_BODY_LIMIT` env alias** for `JSS_MAX_REQUEST_BODY` (upstream
  #474/#543 config name), for drop-in config parity. The canonical name
  wins when both are set; the default stays 50 MiB (upstream raised theirs
  to 20 MB, still below ours).
- **Blank-node round-trip regression test (JSS #536 class)** — pins that
  blank-node subjects survive N-Triples re-parsing and stay `_:`-prefixed
  in JSON-LD `@id` (the n3.js bare-label bug is structurally absent here;
  the test keeps it that way).

### Not ported (audited, classified N/A)

- The JSS runtime plugin system (`createServer({plugins})`, `--plugin`,
  `appPaths`, `api.mountApp`/`serverInfo`/`reservePath`/`plugins`,
  0.0.213–0.0.219): architectural mismatch — this workspace extends via
  compile-time Cargo features. Revisit via ADR only if a downstream needs
  recompile-free app mounts; if ever built, copy upstream's two safety
  invariants (parameterised reserved paths are read-only by default;
  validate path shapes *after* normalisation).
- JWK Y-parity reconcile (#571), well-known profile-probe (#451),
  `lastSubmission` error transport (#514), hijack-then-throw sweeps
  (#412/#526), passkey WebView degradation (#556), tunnel credential
  passthrough (#530), port fallback (#477), Termux tmpdir (#518): fix
  JS-runtime constructs (JWK VM path, filesystem DID indexer, node
  oidc-provider, Fastify, inline browser JS, ops tunnel) that do not exist
  in this codebase.

## [0.5.0-alpha.5] - 2026-07-15

Ships the new **`solid-pod-rs-forge`** crate and clears the supply-chain audit
gate that was holding the release. All eight workspace crates are re-pinned to
`0.5.0-alpha.5`; the core / wasm surface is untouched (the forge is a default-off
sibling, absent from the core dependency tree), so this is a drop-in upgrade for
existing consumers.

### Added

- **`solid-pod-rs-forge` — a Solid-hosted git forge (Phases 0–3)**, a
  clean-room Rust reimplementation of the JSS forge plugin built entirely on
  solid-pod-rs's own primitives (git smart-HTTP, provenance, NIP-98, did:nostr,
  WAC). Wired into `solid-pod-rs-server` behind the default-off `forge` feature;
  the core and wasm surfaces gain zero new dependencies. Complete and
  test-green (95 tests): the XSS-by-content-type spine, Tier-1 git hosting +
  browse porcelain (tree/blob/raw/commits/branches/tags), Tier-2 issues over an
  atomic `FsSpineStore` with a two-phase pod-write coordinator, and the Tier-2.5
  `f1.*` HMAC push-token path for podless did:nostr identities. Phases 4–7
  (forks/PRs, polish, Bitcoin anchors, NIP-34) are feature-scaffolded and
  compiling, not yet implemented. The forge enforces its **own** namespace
  guard and own-area SSRF check rather than the pod WAC ACL evaluator — see the
  `/forge` route notes added to the `solid-pod-rs-server` crate `//!` docs.

### Fixed

- **Supply-chain: two yanked `spin` versions cleared (CI/audit gate)** — the
  transitive `spin` crate appeared twice in the lockfile (`0.9.8` via
  `flume`/`lazy_static`, `0.10.0` via `crc-fast`), and both were yanked from
  crates.io, which failed `cargo-deny` (`error[yanked]`) and `cargo-audit`
  (2 denied warnings) and blocked the release. Resolved per this repo's own
  audit policy — *in-semver fixes are applied by `cargo update`, not ignored* —
  by pinning the lockfile to the non-yanked in-semver successors `spin 0.9.9`
  and `spin 0.10.1`. No source or API change; lockfile only.

## [0.5.0-alpha.4] - 2026-07-03

The **closeout security release**. Four hardening fixes land on top of the
`0.5.0-alpha.3` interop-convergence surface; the public API is unchanged, so
this is a drop-in upgrade. All seven workspace crates are re-pinned to
`0.5.0-alpha.4` and published together.

### Security

- **NIP-98 single-use replay guard (native tier)** — the stateless NIP-98
  verifier accepts any token within its ±120s timestamp tolerance, so a
  captured `Authorization` header could be replayed inside that window. The
  new `auth::replay::Nip98ReplayCache` (feature `nip98-replay`, a bounded
  process-local LRU keyed on the canonical NIP-01 event id) closes the window:
  `Nip98Verified` now carries a signature-bound `event_id`, and
  `solid-pod-rs-server` records every accepted id in a shared
  `LazyLock<Nip98ReplayCache>` — a re-presented token is treated as
  unauthenticated and the WAC gate returns 401. TTL and size are tunable via
  `SOLID_POD_NIP98_REPLAY_TTL_SECS` / `SOLID_POD_NIP98_REPLAY_MAX_SIZE`. The
  cache is per-process; multi-replica deployments share no state.

- **Schnorr signature verification is now unconditional (fail-closed)** —
  previously BIP-340 signature verification ran only under the `nip98-schnorr`
  feature; a build that dropped the feature silently degraded to structural
  checks alone and would accept any forged pubkey. `verify_at_with_policy` now
  calls `verify_schnorr_signature` on every path: with `nip98-schnorr` it
  verifies for real, and without it the call is a fail-closed stub returning
  `PodError::Unsupported`, so a mis-configured build denies authentication
  rather than granting it. A new `const fn assert_schnorr_verification_enabled`
  (present only under `nip98-schnorr`) is referenced in const context by
  `solid-pod-rs-server`, turning any regression that removes signature
  verification — a resolver change, a dropped dependency, a feature-unification
  slip — into a compile error rather than a fail-open server.

- **WAC `acl:origin` enforcement wired into the request path (F4)** — the
  `acl-origin` evaluator support shipped previously but the server never fed it
  a request Origin, so origin-restricted ACLs were inert. The server now threads
  the HTTP `Origin` header through `enforce_read_ctx` / `enforce_write_ctx` into
  the evaluator's `RequestContext`, so an ACL bearing `acl:origin` triples gates
  cross-origin reads and writes (CSRF defence). Behaviour is conservative:
  plain ACLs with no `acl:origin` triple are unaffected, origin-less requests
  (server-to-server, git smart-HTTP, curl) are denied only where an ACL
  explicitly restricts origins, and `acl:Control` bypasses the origin gate by
  design so an owner can always repair a mis-configured ACL from any origin.
  Note: `acl:origin` is the only WAC 2.0 condition satisfiable end-to-end today
  — the `client_id` and `issuer` conditions remain unsatisfiable because the
  server does not yet surface an authenticated OIDC client_id / issuer into the
  `RequestContext`; those conditions therefore still evaluate deny.

### Added

- **`GET /api/exports/all` — JSON-LD time-chain pod export route (parity row
  198)** — `solid-pod-rs-server` now exposes the previously library-only
  `export::export_pod_jsonld` walker over HTTP under the `export-jsonld`
  feature (default-off, native-only). The route is owner-gated: the caller must
  hold `acl:Control` on the pod root, because the bundle can expose every
  resource (including `/private/*` when `?include_private=true`), bypassing
  per-resource ACLs. Emitted with the `export::EXPORT_CONTENT_TYPE` media type.

### Changed

- Documentation across the changed crates now reflects the hardened posture:
  the NIP-98 verifier module doc states verification is unconditional and
  fail-closed; the `provision.rs` / `solid-pod-rs-idp` key-provisioning docs
  drop the stale "scaffold / `todo!()`" wording (the bodies are implemented and
  tested); the core `lib.rs` export section notes the route is native-only.

## [0.5.0-alpha.3] - 2026-06-27

The **interop-convergence release**. Also the release that finishes shipping
the workspace: `0.5.0-alpha.2` was published for the `solid-pod-rs` core crate
only — the six sibling crates (`-server`, `-idp`, `-git`, `-nostr`,
`-activitypub`, `-didkey`) were version-bumped but never published and stayed
at `0.5.0-alpha.1` on crates.io. `alpha.3` publishes the whole workspace
together, so all seven crates now carry the canonical Multikey + CID work.

### Changed
- **W3C CID v1.0 context** — the did:nostr DID-document `@context[0]` migrates
  from `https://w3id.org/did` to the W3C Controlled Identifiers v1.0 IRI
  `https://www.w3.org/ns/cid/v1` (`render_did_document`, `did_nostr_document`,
  `did_nostr_types` docs). This matches the context already emitted by the
  downstream `dreamlab-ai-website` resolver, closing a live interop skew where
  the published pod crates trailed their own consumer. ADR-125 §2.

### Added
- **Odd-parity Multikey accept** — `parse_multibase_schnorr` now accepts the
  odd-y compressed prefix `fe70103` (`MULTIKEY_PREFIX_ODD`) on decode, per the
  CID guidance that implementations SHOULD handle both parities; canonical
  even-y `fe70102` is still the only form produced on encode. New
  `parse_multibase_accepts_odd_parity` round-trip test.

## [0.5.0-alpha.2] - 2026-06-15

> Partial release: only `solid-pod-rs` (core) reached crates.io at this version;
> the sibling crates ship this content under `0.5.0-alpha.3`.

### Changed
- **Canonical Multikey convergence** (`did-nostr`) — DID-document emission
  converges on the canonical `Multikey` verification-method form
  (`publicKeyMultibase: "fe70102<hex>"`, `MULTIKEY_PREFIX`/`MULTIKEY_LEN`),
  superseding the 2019-suite + `publicKeyHex` shapes. Adds
  `solid-pod-rs-git::identity` write-side DID emission.

## [0.5.0-alpha.1] - 2026-06-13

### Documentation
- Complete in-crate Diataxis docs + crate-level rustdoc for the
  `0.5.0-alpha.0` provenance/economy release (the embedded `DOCS_DIR` and the
  `//!` overviews had no coverage of it). New `explanation/` docs for
  provenance & the trust ledger and for payments & the web ledger; the new
  `/pay/*` + `_prov` routes in `reference/http-endpoints.md`; the new env vars
  in `reference/env-vars.md`; a corrected feature-flag table and JSS-parity
  rows. **No code changes** — documentation only; `0.5.0-alpha.0` consumers
  need not bump.

## [0.5.0-alpha.0] - 2026-06-13

The **provenance release** (ADR-059). Two composable, cost-tiered provenance
primitives become first-class, and the JSS-derived payment economy is fully
routed. Full workspace: 1542 tests pass; the wasm32 `core` surface stays pure.

### Added
- **git-marks** (cheap, always-on): every LDP write to a git-backed pod becomes
  a git commit, captured as a `GitMark` and persisted as a PROV-O sidecar
  (`<resource>.prov.ttl`), emitted on the Updates-via notification stream.
  `provenance::GitMarker` trait + `solid-pod-rs-git::ShellGitMarker`.
- **block-trails** (expensive, opt-in): a Bitcoin taproot-anchored, hash-chained,
  tamper-evident provenance trail. `bitcoin_tx.rs` ports the JSS `token.js`
  taproot tx-builder **byte-for-byte** (P2TR, BIP-341 TapSighash, BIP-340 schnorr
  signing), validated against official BIP-340/341 vectors and a JSS cross-impl
  golden. `MempoolLookup`/`MempoolBroadcast` over the public mempool.space
  testnet4 API; `BlockAnchorer` (verify + write). MRC20 is one instance of the
  general trail.
- **ProvenanceLog** composition: git-mark always / Bitcoin anchor opt-in via
  `AnchorPolicy` {Never, Always, HighValue, Epoch}; the anchor's `state_hash`
  commits to the git commit SHA, binding the two tiers. **Epoch** batches commit
  SHAs into one Merkle root anchored by a single tx (one tx notarises many
  commits). `acl:ProvenanceAnchor` WAC condition flags anchor-worthy resources.
- **`_prov` API**: `GET /{pod}/_prov/{commit_sha}` resolves a git-mark to its
  resource + anchor; `POST /{pod}/_prov/anchor` (NIP-98, payment-gated) upgrades
  a git-mark to a Bitcoin anchor.
- Routed the previously-orphaned web-ledger / order-book / AMM **402 economy**:
  `/pay/.balance`, `/pay/.deposit` (TXO + MRC20), `/pay/.address`, `/pay/.offers`,
  `/pay/.sell`, `/pay/.swap`, `/pay/.pool`, `/pay/.buy`, `/pay/.withdraw`,
  `/pay/.withdraw-sats`. `StoragePaymentStore` is now the sole ledger I/O path.

### Fixed
- **Security**: git smart-HTTP routes are now WAC-gated — `handle_git` enforces
  Read for clone/fetch and Write for push against the pod ACL, closing the
  anonymous clone/push hole (a private pod's history was world-clonable).
- Payment **replay protection** (`check_replay`/`record_replay`) is now wired
  into the deposit path — a duplicate TXO/MRC20-state deposit can no longer
  double-credit.
- `verify_mrc20_anchor` composes the taproot crypto with a real mempool UTXO
  lookup (was: lookup left to the caller).

### Changed
- On-demand git auto-init on first push (replaces the prior 404-on-missing-repo).
- Workspace `0.4.0-alpha.17` → `0.5.0-alpha.0`.

## [0.4.0-alpha.17] - 2026-06-10

### Fixed
- `solid-pod-rs-server` could not be published to crates.io: its MCP docs
  tools embedded the documentation tree via
  `include_dir!("$CARGO_MANIFEST_DIR/../solid-pod-rs/docs")`, a path escape
  that does not exist in a packaged tarball, so `cargo publish` verification
  failed. The embedding now lives in the owning crate as
  `solid_pod_rs::DOCS_DIR` behind the new `embedded-docs` feature
  (re-exporting `include_dir`), and the server consumes that. Registry builds
  of every crate in the workspace are now self-contained.

### Added
- `solid-pod-rs`: `embedded-docs` feature — embeds the crate's Diataxis
  `docs/` tree as `pub static DOCS_DIR` (the tree already ships in the
  published package).

## [0.4.0-alpha.16] — 2026-06-09 — version-bump to disambiguate the alpha.15 alias

Version-only release. `0.4.0-alpha.15` had come to alias two distinct code
states: the crates.io publish (checksum `a53804d0…`, consumed by
nostr-rust-forum) and git HEAD, which had advanced past the publish without a
version bump or tag (the highest real git tag was `alpha.11`). Downstream
consumers pinned to the same version string were building different auth code.
This release cuts a real version and the first tag since `alpha.11` so every
consumer can pin a single, unambiguous code state.

### Changed

- Workspace version `0.4.0-alpha.15` → `0.4.0-alpha.16`; all seven member
  crates and their internal cross-crate `path` dependency pins advance with it.

### Included (post-publish commits now under a real version/tag)

- **WAC ancestor `accessTo` over-inheritance + git HTTP read-auth bypass fix**
  (`75946cf`).
- **`payments::debit` wired into the WAC grant path** (`f7785d7`, R-04) — the
  resource-cost-accounting fix. The published `alpha.15` crate predates this, so
  it served cost-gated reads without consuming the cost; consumers pinned to the
  git state get the corrected behaviour.

## [0.4.0-alpha.15] — 2026-05-30 — JSS v0.0.204 sync (MCP server, `install` CLI, NIP-98 minting)

Integrates the upstream JSS changes from `0.0.197` (`10bd60f`) through
`0.0.204` (`9d29167`): the Model Context Protocol agent surface (#490),
the `install` app-distribution CLI, and two content-type/listing fixes
(#531, #533). The JSS comparator pin advances accordingly across
`PARITY-CHECKLIST.md`, `GAP-ANALYSIS.md`, and the feature inventory.
alpha.12–alpha.14 are documented in `crates/solid-pod-rs/CHANGELOG.md`.

### Added

- **MCP server subsystem** (`solid-pod-rs-server/src/mcp/`, JSS #490) —
  `POST /mcp` exposes the pod as a Model Context Protocol 2025-03-26 tool
  surface over the Streamable HTTP transport (JSON-RPC 2.0, single-shot
  JSON with an SSE upgrade for the streaming `subscribe` tool). Sixteen
  tools spanning resource CRUD, ACL read/write, skills, docs, pod info,
  subscribe, and `call_remote_pod`. Identity reuses the pod's NIP-98
  verifier, so every tool call gets the same WAC treatment as a REST
  request. Off by default — enabled with `--mcp` / `JSS_MCP`, overridable
  by `--no-mcp`. `call_remote_pod` is gated to `/private/federation/` for
  `did:nostr` identities with a depth-3 recursion cap.
- **`install` operator subcommand** (`solid-pod-rs-server/src/cli/install.rs`,
  JSS `src/cli/install.js`) — clones a Solid app and pushes it into a pod
  over the git smart protocol. App-spec grammar mirrors JSS (bare name →
  `github.com/solid-apps/<name>`, `org/repo`, full git URLs, with `#<ref>`
  pin and `=<dest>` rename). Dual `HEAD:main` + `HEAD:gh-pages` push.
  Authenticates with a single NIP-98 token minted over the destination
  repo URL (method `*`) via git `http.extraHeader`, or a bearer `--token`
  fallback. NIP-98 signing requires the new `install` cargo feature.
- **NIP-98 token minting** (`auth::nip98::mint` / `mint_with_payload`,
  feature `nip98-schnorr`) — constructs a kind-27235 event, computes the
  canonical NIP-01 id, and signs it with a deterministic BIP-340 Schnorr
  signature matching the `verify_raw` path. `Nip98Event` now derives
  `Serialize`.
- **`auth::nip98::MatchPolicy`** — `Strict` (every REST/MCP endpoint) and
  `GitLenient` (the git push bridge: `*`-method wildcard + repo-URL-prefix
  binding, so one static `http.extraHeader` token covers the multi-request
  smart protocol). Schnorr is fully verified under both.
- **`ldp::guess_content_type`** (JSS #533 `getContentType`) — resolves a
  MIME type for sidecar-absent resources (dotfile rule → Solid RDF /
  playlist overrides → the `mime_guess` database → `application/octet-stream`),
  so git-extracted app files render inline instead of downloading.

### Fixed

- **Symlinked-directory container listing** (JSS #531) — `FsBackend`
  container listings now reclassify symlinks from their dereferenced stat,
  so a symlinked directory lists as a container, matching a direct GET.
- **Mashlib audio rendering** (JSS #533) — `mashlib::should_serve` now
  matches the whole `audio/*` family rather than enumerating exact
  spellings.

## [0.4.0-alpha.11] — 2026-05-16 — JSS Phase 1 port

Implements the three Phase 1 features shipped by JSS v0.0.190 (May
2026, issue #437). All three feature flags are default-off so existing
consumers see no surface change unless they opt in. Type shapes
declared in the alpha.10 scaffold (`KeyProvisioningOutcome`,
`KeyProvisioningPlan`, `PodExportBundle`, `PodExportEntry`,
`ExportOptions`) are preserved as ABI — downstream crates (NRF,
dreamlab-ai-website) can import unchanged.

### Added

- **`provision-keys` feature** (`solid-pod-rs-idp`, default-off,
  parity row 196). `key_provisioning::provision_pod_keys` generates a
  BIP-340 Schnorr secp256k1 keypair, NIP-19 bech32-encodes `npub` and
  `nsec` (hand-rolled bech32 encoder — no new dependency on `bech32`),
  writes `/private/privkey.jsonld` and an owner-only JSON-LD ACL
  sibling, and patches the WebID `/profile/card` JSON-LD island to
  include the `nostr:pubkey` triple. Accepts deterministic entropy
  for test reproducibility. Depends on `solid-pod-rs/did-nostr` +
  core's `nip98-schnorr` + `dep:k256`. 3 integration tests cover
  deterministic seeding, ACL evaluator round-trip, and WebID patching
  idempotency.
- **`nip05-endpoint` feature** (`solid-pod-rs` + `solid-pod-rs-server`,
  default-off, parity row 197). Wires `GET /.well-known/nostr.json?name=<local>`.
  Validates the NIP-05 local-part regex, resolves `_` → `/profile/card`
  and `<name>` → `/<name>/profile/card`, extracts `nostr:pubkey` from
  the JSON-LD data island via the new `webid::extract_nostr_pubkey`
  helper, returns `application/json` with `Access-Control-Allow-Origin: *`.
  5 actix-test integration tests in `solid-pod-rs-server`.
- **`export-jsonld` feature** (`solid-pod-rs`, default-off, parity row
  198). `export::export_pod_jsonld` walks the pod tree, excludes
  `/private/*` by default, opt-in via `ExportOptions::include_private`,
  base64-encodes each resource body (binary-safe), sorts entries
  ascending by `created` (mirrored from `modified` on backends that
  don't track creation separately). Bundle envelope carries
  `@context = "https://solid-pod-rs.dev/ns/export/v1"`. 3 integration
  tests cover default exclusion, opt-in inclusion, and time-chain
  ordering.
- **`webid::extract_nostr_pubkey`** helper (always available) — locates
  the `nostr:pubkey` triple inside a WebID's JSON-LD data island.
  Mirrors `extract_oidc_issuer` semantics; returns `Ok(None)` when
  absent.

### Changed

- **`PARITY-CHECKLIST.md`**: rows 196–198 promoted from `scheduled` to
  `present` (Phase 1 port). Tally restored to ~98% strict parity
  (129/135). Row 128 (NIP-05) updated — builder primitives still ship
  as `net-new`; the pod-resident server route lands via row 197.
- **`solid-pod-rs-idp/Cargo.toml`**: added `bytes` to direct
  dependencies (was transitive through `solid-pod-rs`); the
  `provision-keys` feature flag inherits `solid-pod-rs/did-nostr` plus
  `dep:k256`.

### Cross-repo consumer chain

- **NRF (nostr-bbs forum primitive)**: now upgradable to alpha.11 —
  the `KeyProvisioningOutcome` shape is stable; NRF can opt into the
  `provision-keys` feature for its registration flow.
- **dreamlab-ai-website**: can call `export_pod_jsonld` via the
  `export-jsonld` feature for "download my data" surfaces.

### Upgrade path (alpha.10 → alpha.11)

No breaking changes to default-feature builds. Consumers who pinned
`solid-pod-rs = "0.4.0-alpha.10"` bump the patch component; struct
literals constructing `ProvisionPlan` will gain a new optional
`provision_keys` field gated on the `provision-keys` feature — only
visible when the consumer enables that flag.

## [BIP-340 Schnorr Fix] - 2026-05-12

### Fixed

- **NIP-98 BIP-340 Schnorr pre-hashing mismatch (BREAKING).** The
  Schnorr signature verifier in `auth::nip98::verify_schnorr_signature`
  was calling `vk.verify()` (the k256 `Verifier` trait method, which
  applies an extra SHA-256 tagged hash per the k256 Verifier trait
  semantics) instead of `vk.verify_raw()` (BIP-340 correct, raw 32-byte
  message). This caused signature verification to fail against any
  standard Nostr client that signs per BIP-340 (raw event-id bytes),
  breaking SSO interoperability with the nostr-bbs relay and forum.
  The fix switches to `verify_raw()` for verification and `sign_raw()`
  for test fixture signing. The k256 `signature::Verifier` trait import
  is no longer used.
- Test and bench fixtures updated to use `sk.sign_raw(&id_bytes,
  &[0u8; 32])` instead of `sk.sign()`, matching the BIP-340 raw
  signing convention: `tests/cid_verifier_sprint11.rs`,
  `tests/nip98_extended.rs`, `tests/oidc_integration.rs`,
  `benches/nip98_verify_bench.rs`.

## [Security Audit Sprint] - 2026-05-11

DreamLab ecosystem-wide security audit. 8 fixes applied to solid-pod-rs
covering P0 critical, P1 high, P2 medium, and Round 2 P0 findings.

### Security

- **P0-07**: HTTP signature Date header freshness check enforced at +/-5
  minutes in http_sig.rs, rejecting replayed signatures with stale
  timestamps that previously passed verification indefinitely
- **P0-08**: SSRF guard added to actor key resolver in http_sig.rs and
  new ssrf.rs module, blocking requests to RFC-1918 private addresses,
  link-local, loopback, and metadata endpoints when resolving remote
  ActivityPub actor keys
- **P0-09**: SSRF guard added to ActivityPub delivery outbound POST in
  delivery.rs, applying the same private-address blocklist to prevent
  the server from being used as an HTTP proxy to internal services
- **R2-P0-04**: IPv4-compatible IPv6 SSRF bypass fixed in ssrf.rs;
  addresses like ::ffff:10.0.0.1 and ::ffff:127.0.0.1 now correctly
  resolve to their IPv4 equivalents before the private-range check
- **R2-P0-05**: Same IPv4-in-IPv6 fix applied in the ActivityPub SSRF
  module (activitypub ssrf.rs), plus 6to4 (2002::/16) address bypass
  blocked

### Fixed

- **P1-25**: WAC PATCH operations now require Write permission instead of
  Append in server lib.rs, matching the Solid Protocol specification
  where PATCH replaces resource content
- **P1-26**: Passkey credential counter updated on successful
  authentication in passkey.rs, enabling clone detection per the
  WebAuthn specification
- **P2-09**: Notification buffer bounded to 10,000 entries in
  notifications/mod.rs, preventing unbounded memory growth from
  slow or disconnected subscribers
