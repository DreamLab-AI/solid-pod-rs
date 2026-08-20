# Security and quality audit — 2026-08-19

This is a point-in-time audit of workspace commit
`72daa20a1764651c1e079875c7368b446da6cf68` (`0.5.0-alpha.7`). It covers all
eight crates, 236 Rust source files, and 84,562 lines of Rust. It is not a
claim of formal verification or a substitute for deployment-specific threat
modelling.

## Executive result

This document preserves the original 2026-08-19 findings below. All 19 were
remediated and regression-tested on 2026-08-20. The changes close the reported
authentication, authorisation, path-confinement, atomicity, payment-recovery,
resource-bound, dependency, configuration, and CI gaps. Deployment-specific
threat modelling and external conformance testing remain operator duties.

## Remediation status — 2026-08-20

| Finding | Status | Implemented control |
|---|---|---|
| AUD-001 | fixed | IdP mutations consume authenticated typed request extensions; caller identity headers are not authoritative. |
| AUD-002 | fixed | Both registration routes share validation, policy, and rate-limit enforcement; registration defaults closed. |
| AUD-003 | fixed | Proxy responses reject oversized lengths early and stream through a counted cap. |
| AUD-004 | fixed | Git CGI output, diagnostics, execution time, and idle time are bounded. |
| AUD-005 | fixed | Patched dependency lines are locked; the two unavoidable advisories have scoped, dated exceptions and compensating controls. |
| AUD-006 | fixed | Forge loopback responses use bounded streaming. |
| AUD-007 | fixed | CI uses a real feature matrix, required coverage, workspace-wide policy gates, and commit-pinned actions. |
| AUD-008 | fixed | DPoP proof identifiers are recorded in the replay cache and duplicate proofs fail closed. |
| AUD-009 | fixed | MCP resource operations pass through the same WAC checks as HTTP and cannot mutate ACL sidecars without Control. |
| AUD-010 | fixed | NIP-98 verification binds the raw request body and canonical query-bearing URL. |
| AUD-011 | fixed | Payment debits and intents commit atomically; recovery reconciles confirmed, absent, and indeterminate broadcasts without double-spend. |
| AUD-012 | fixed | Forge authentication rejects replayed events. |
| AUD-013 | fixed | Filesystem access uses capability-confined path resolution and rejects escapes through symlinks. |
| AUD-014 | fixed | Filesystem body and metadata writes use temporary files and atomic replacement. |
| AUD-015 | fixed | The dependency-only S3 selection was removed; unsupported storage types fail validation. |
| AUD-016 | fixed | ActivityPub verification requires the signed request-target, host, date, and digest components. |
| AUD-017 | fixed | ActivityPub actor identity is bound to the verified signing key. |
| AUD-018 | fixed | Nostr frames, subscriptions, filters, and outbound queues have enforced limits. |
| AUD-019 | fixed | Quota reservations are process-wide atomic and wired into every mutating server route. |

## Reproducible verification

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `cargo check --workspace --all-targets --all-features` | pass |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | pass |
| `cargo test --workspace --all-targets --all-features` | pass |
| `cargo audit --deny warnings` | pass; scoped exceptions are documented in `.cargo/audit.toml` |
| `RUSTDOCFLAGS='-D warnings -D rustdoc::broken_intra_doc_links' cargo doc --workspace --all-features --no-deps` | pass |
| Local relative-link scan over 62 public README/crate-doc Markdown files | pass: 318 local targets checked, zero missing |
| `scripts/parity-check.sh` | pass: 206/211 (97.6%); zero rows classified as missing |
| `cargo deny --manifest-path Cargo.toml --config crates/solid-pod-rs/deny.toml check` | pass: advisories, bans, licences, and sources |
| `actionlint .github/workflows/ci.yml .github/workflows/release.yml` | pass with actionlint 1.7.12 |
| `scripts/check-diagram-staleness.sh` | pass: all nine Mermaid sources current against SVG and PNG outputs |
| External CTH Docker suite | not run locally; `scripts/test-cth.sh` supplies the discovery preflight and runner integration, but requires a deployed Solid-OIDC test server |

The tests include all workspace targets and feature combinations requested by
Cargo. An aggregate test number is intentionally not reported: Cargo does not
emit a trustworthy single total for this invocation.

## Findings

### AUD-001 — critical — forged IdP identity header permits account deletion

The optional `solid-pod-rs-idp` Axum router mounts password change and account
deletion directly. Both derive the target account solely from caller-controlled
`X-Authenticated-User`; the returned router installs no middleware that
authenticates or overwrites that header.

The audit reproduced the issue against the public router: create a victim,
send `DELETE /idp/account` with the victim id in the header and the documented
confirmation phrase, receive HTTP 200, and observe that the victim record is
gone. The temporary diagnostic test was removed after verification.

Evidence: `solid-pod-rs-idp/src/axum_binder.rs` (`router`,
`extract_user_id_header`, `account_delete_handler`).

Required fix: make authenticated identity a typed extension produced by
mandatory middleware, or remove state-changing routes from the pre-built
router. A caller-supplied header must never be the authority. Add a regression
test proving an untrusted header cannot select another account.

### AUD-002 — high — public account provisioning bypasses validation and limits

`POST /api/accounts/new` is mounted on the public server router and provisions
a pod without authentication, invitation/admin policy, per-IP rate limiting,
or `valid_pod_name`. The neighbouring `POST /.pods` path applies the local
limiter and name validation, demonstrating the missing controls. This permits
namespace squatting and storage/CPU exhaustion.

Evidence: `solid-pod-rs-server/src/lib.rs` (`handle_create_account`,
`handle_create_pod`, and `build_app`).

Required fix: consolidate both entry points behind one validated provisioning
service and one explicit registration policy. Default public registration to
off unless deliberately enabled.

### AUD-003 — high — proxy byte cap is applied after full buffering

The authenticated `/proxy` handler calls `response.bytes().await` before
checking the configured cap. A large upstream response can therefore consume
memory beyond the nominal limit. The endpoint's identity check proves only a
valid NIP-98 signer; it does not apply WAC to a pod resource.

Evidence: `solid-pod-rs-server/src/lib.rs` in the proxy response path.

Required fix: reject oversized `Content-Length` early when present, stream the
body while counting bytes, abort at the cap, and bound redirect count and total
time as one operation.

### AUD-004 — high — Git CGI output is collected without a cap

The Git smart-HTTP bridge reads child stdout and stderr into unbounded vectors
before constructing a response. Large pack output or a noisy/faulting backend
can exhaust process memory.

Evidence: `solid-pod-rs-git/src/service.rs` (`spawn_cgi`).

Required fix: stream successful stdout with backpressure, cap diagnostic
stderr, impose execution and idle timeouts, and terminate the child when a
limit is exceeded.

### AUD-005 — high — denied dependency advisories

`cargo audit --deny warnings` reports RUSTSEC-2026-0258 for `h2` 0.3.27 and
0.4.13 (unbounded processing of empty DATA frames). It also denies unsoundness
warnings for `event-listener` 5.4.1 and direct dependency `lru` 0.16.4. The
`h2` paths reach shipped HTTP stacks through Actix and Hyper/Reqwest.

Required fix: update to patched dependency lines where compatible, track the
Actix `h2` 0.3 path upstream if no compatible patch exists, and do not waive an
advisory without a scoped, dated rationale and compensating control.

### AUD-006 — medium — forge loopback applies its limit after buffering

The forge loopback client has the same collect-then-check pattern as the proxy.
Its same-origin scope lowers exploitability, but a large local resource still
causes avoidable memory pressure.

Required fix: use the same bounded streaming primitive as AUD-003.

### AUD-007 — medium — CI does not enforce its documented coverage and matrix

The core build matrix declares feature objects under `include` rather than a
feature axis, so it does not express the documented Cartesian product. The
coverage upload is non-blocking and has no minimum threshold. `cargo-deny`
targets only the core manifest, while the workspace contains eight crates.
Several actions use mutable major tags or `master` rather than immutable
commit SHAs. Comments still describe seven members and omit the forge crate.

Required fix: define a real feature axis, validate the workflow with
`actionlint`, make the chosen coverage floor explicit and required, run policy
checks for the complete workspace, pin third-party actions by SHA, and update
the comments.

### AUD-008 — low — provider-token DPoP replay cache is not wired

The provider token exchange passes no replay cache to DPoP verification. The
authorization code is single-use, which limits practical replay, but the
documented defence-in-depth hook is absent.

Required fix: wire a bounded shared replay cache and test concurrent reuse of
the same proof and authorization code.

### AUD-009 — critical — MCP bypasses WAC and ACL-sidecar Control

The opt-in MCP `get_skill` tool accepts any caller-provided pod path and reads
it directly from storage without a WAC check or restriction to conventional
skill locations. The audit reproduced anonymous disclosure of
`/private/privkey.jsonld` through public `POST /mcp`; the temporary diagnostic
test was removed afterward.

The generic `read_resource`, `head_resource`, `write_resource`,
`create_resource`, and `delete_resource` tools also use a local `wac_check`
that does not apply the shared `effective_acl_target` rule. A caller with
ordinary Read/Write/Append can therefore read or mutate `.acl`/`.meta`
sidecars where the REST surface correctly requires `acl:Control`. The
specialised `read_acl`/`write_acl` tools require Control, but generic tools
provide a bypass.

Evidence: `solid-pod-rs-server/src/mcp/skills.rs::read_skill` and
`src/mcp/tools.rs` (`get_skill`, `wac_check`, and generic CRUD tools).

Required fix: make all storage-reading tools pass through one authoritative
WAC/effective-target gate; restrict skill paths to the documented locations;
reject generic sidecar operations or elevate them to Control; and add
anonymous-read plus Write-without-Control regression tests. Keep MCP off until
these are fixed.

### AUD-010 — high — bundled NIP-98 authentication omits bodies and queries

The core verifier correctly checks a `payload` tag when given raw bytes, but
`solid-pod-rs-server::extract_pubkey` always calls `verify_at(..., None, ...)`.
Every ordinary PUT/POST/PATCH, payment, proxy, and MCP route therefore accepts
a valid method/URL token without checking the signed body. The reconstructed
URL includes only `req.uri().path()`, excluding the query string;
authenticated query parameters such as the proxy target are likewise not
signature-bound. An intercepted proof can have its body or query altered
before its first use. The replay cache prevents a second use but does not
authenticate the first request's omitted fields.

Evidence: `solid-pod-rs-server/src/lib.rs::extract_pubkey` and its call sites.
The forge resolver separately supplies `raw_body`, demonstrating the intended
core API usage.

Required fix: authenticate only after the body is available, pass the exact
raw bytes, reconstruct the canonical external URL including query, and add
end-to-end tampered-body/query tests for every state-changing transport.

### AUD-011 — critical — payment state transitions are non-atomic

Ledger, replay set, order book, pool state, and trail updates are independent
read-modify-write sequences over `Storage::get`/`put`, without a transaction,
compare-and-swap, or shared lock. Concurrent deposits can both pass the replay
check and receive credit; concurrent debits can overwrite each other; pool and
order updates can be lost.

The token-transfer path broadcasts an irreversible Bitcoin transaction before
saving the trail and debiting the ledger. A persistence error or raced debit
can therefore transfer value without charging the account. The withdraw-sats
path reserves before broadcast, but concurrent requests can still overwrite
the same ledger version and produce multiple successful withdrawals when
different funding vouchers are supplied.

Evidence: `solid-pod-rs-server/src/handlers/pay.rs::StoragePaymentStore`,
`handle_deposit`, `handle_swap`, `handle_pool_post`,
`execute_token_transfer`, and `handle_withdraw_sats`; also
`solid-pod-rs-server/src/lib.rs::debit_ledger`.

Required fix: define a transactional payment-store operation that atomically
checks replay/version, mutates all local state, and records an idempotency key.
Use storage CAS/transactions or a serialisable database transaction; design an
explicit prepare/broadcast/commit recovery protocol for external Bitcoin side
effects. Add deterministic concurrency and crash-injection tests before the
routes carry real value.

### AUD-012 — medium — forge NIP-98 requests have no replay cache

The forge resolver verifies signature, URL, method, and body but calls the
stateless core verifier directly. It does not share the server's replay cache,
so the same proof can be replayed within the timestamp window for forge writes
or token minting.

Required fix: inject the shared replay-store abstraction into `ForgeService`
and reject an already-seen canonical event id before dispatch.

### AUD-013 — critical — filesystem symlinks escape the pod root

`FsBackend::resolve` joins the caller's path to the configured root and checks
only lexical `starts_with`. Subsequent `read`, `write`, `metadata`, and delete
operations follow symlinks. The audit reproduced `FsBackend::get("/escape")`
returning a host file outside the root through an in-root symlink; the
temporary diagnostic test was removed afterward.

This is reachable across a tenant boundary when git-backed pods are enabled:
a tenant-controlled repository can contain an absolute or relative symlink,
and checkout/update-instead can materialise it inside the pod. An authorised
LDP read or write through that path then acts with the server process's host
permissions outside the pod root.

Evidence: `solid-pod-rs/src/storage/fs.rs` (`resolve`, `get`, `put`, `head`,
and `delete`) and the git checkout/update-instead integration.

Required fix: use descriptor-relative, no-follow filesystem operations on
every path component (for example `openat2` with `RESOLVE_BENEATH` and
`RESOLVE_NO_SYMLINKS` on Linux), or reject symlinks via a race-safe equivalent.
Do not rely on canonicalise-then-open, which remains TOCTOU-prone. Add
read/write/delete escape tests and a git-materialised-symlink integration test.

### AUD-014 — high — filesystem writes violate the atomic storage contract

`Storage::put` is documented to be observer-atomic, but `FsBackend::put` uses
`tokio::fs::write`, which opens and truncates the destination before writing.
A concurrent reader can observe an empty or partial body. The metadata sidecar
is then written as a second independent operation, so a crash or sidecar error
can leave new body bytes paired with old metadata. `delete` similarly removes
the body and sidecar separately. Payment and other state stores build
read-modify-write operations on this backend, magnifying its integrity risk.

The README and storage guides previously claimed `tempfile + rename(2)` even
though no such implementation exists; this audit corrects those claims.

Evidence: `solid-pod-rs/src/storage/fs.rs::put` and `delete`, compared with the
contract in `src/storage/mod.rs` and `docs/explanation/storage-abstraction.md`.

Required fix: write body and metadata to unpredictable temporary files within
the same filesystem, flush them as required by the durability contract, and
publish with atomic renames under a per-resource lock or generation/CAS
scheme. Define how body/metadata generations recover after a crash. Add
concurrent-reader and fault-injection tests.

### AUD-015 — medium — S3 configuration advertises an absent backend

The `s3-backend` Cargo feature only enables `aws-sdk-s3`; no `storage::s3`
module or `S3Backend` implementation exists. The configuration schema and
environment mapping nevertheless accept S3 settings. The bundled server's
`build_storage` always rejects `StorageBackendConfig::S3`, including an
all-features build, and incorrectly says that the binary was built without the
feature. This can turn a documented production deployment choice into a
startup outage after operators have supplied credentials and migrated data.

Evidence: `solid-pod-rs/Cargo.toml`, `src/config/schema.rs`, and
`solid-pod-rs-server/src/main.rs::build_storage`; absence of a corresponding
implementation under `src/storage`.

Required fix: either implement and conformance-test the backend before exposing
the selection, or remove S3 from accepted runtime configuration and rename the
feature to make its SDK-only purpose explicit. Until then, fail validation with
an accurate "not implemented" message. The user-facing documentation has been
updated to mark the design as non-runnable.

### AUD-016 — high — ActivityPub POST signatures need not bind the request

The ActivityPub verifier accepts Cavage signatures whose declared `headers`
list omits `(request-target)`, `host`, `date`, and `digest`. Its parser defaults
an absent list to `date`; freshness and digest checks run only when those names
were voluntarily included. A remote signer can therefore produce a valid
signature over one benign `Date` value and have it accepted for arbitrary POST
paths and bodies within the freshness window. This contradicts the module's
claim that `digest` is mandatory for POST.

This crate is transport-agnostic and is not mounted by the bundled server, so
exploitability depends on an embedder routing inbound federation through it.

Evidence: `solid-pod-rs-activitypub/src/http_sig.rs`
(`parse_signature_header` and `verify_request_signature`).

Required fix: enforce a minimum covered-component set based on method: POST
must cover `(request-target)`, `host`, `date`, and `digest`; safe methods must
at least cover target, host, and freshness. Reject duplicates/ambiguous
components and add negative tests for every omission.

### AUD-017 — high — ActivityPub activity actor is not bound to signer

After HTTP-signature verification, `handle_inbox` accepts the activity's
caller-controlled `actor` field for `Follow`, `Undo(Follow)`, and related state
changes. It falls back to `verified_actor.actor_url` only when the field is
absent; it never requires equality. A valid remote actor can therefore claim
another actor URL and add/remove follower state under that identity. The
`actorInbox` field is likewise accepted directly from the activity for a
follow response target.

As with AUD-016, this is an optional library integration rather than a route in
the bundled server.

Evidence: `solid-pod-rs-activitypub/src/inbox.rs::handle_inbox`.

Required fix: require the canonical activity actor to equal the actor document
bound to the verified `keyId`; validate nested actors/objects for Undo and
Accept; obtain inbox endpoints from the verified actor document through an
SSRF-safe resolver rather than trusting activity JSON.

### AUD-018 — medium — Nostr WebSocket resource limits are embedder-dependent

The relay WebSocket loop has no application-level cap on text-frame size,
subscription count, filters per subscription, filter array/string sizes, or
historical result fan-out. `subscriptions` grows for every distinct client id,
and a `REQ` serialises the complete matching history into a `Vec<String>`
before sending. The in-memory event store bounds event count, but does not
bound event byte size. A public embedder that uses default transport limits can
therefore incur large per-connection memory and CPU costs.

Evidence: `solid-pod-rs-nostr/src/ws.rs` (`serve_relay_ws_stream`,
`dispatch_message`, and `handle_req`) and `src/relay.rs` (`Event`, `Filter`, and
`InMemoryEventStore`).

Required fix: expose conservative `RelayLimits`, reject oversized frames and
events before JSON cloning, cap subscriptions/filters and filter values, clamp
result counts, stream history with backpressure, and configure Tungstenite's
message/frame limits in the convenience acceptor.

### AUD-019 — medium — quota checks are neither atomic nor server-wired

`FsQuotaStore` atomically replaces its sidecar file, but the enforcement
sequence is a separate `check` followed later by `record`. Concurrent writers
can both pass against the same usage and exceed the limit; concurrent `record`
read-modify-write operations can lose increments. The bundled server does not
construct or call a `QuotaPolicy`, despite feature and README language
describing per-pod enforcement.

Evidence: `solid-pod-rs/src/quota/mod.rs` (`QuotaPolicy`, `check`, `record`, and
`write_sidecar`) and absence of quota-policy wiring in
`solid-pod-rs-server/src/lib.rs`.

Required fix: replace `check`/`record` with an atomic reservation/commit API (or
transaction/CAS), wire it into every create/update/delete path, account for
replacement deltas rather than full new body size, and add concurrent quota
tests. Until then, describe the feature as a cooperative primitive rather than
enforced server quota.

## JavaScriptSolidServer progression

The comparator was refreshed from JSS `gh-pages` commit `f9f7a4d` (package
`0.0.220`, 2026-07-26). The `0.0.204` to `0.0.220` range contains 47 commits.
Twenty-three behaviours are recorded as parity rows 208–230 in
`PARITY-CHECKLIST.md`: the portable developer ergonomics, including automatic
busy-port shifting, are now implemented; thirteen rows are present by absence
or not applicable to the compiled Rust architecture. Strict portable parity is
206/211, or 97.6%, under the tracker classification (which counts
present-by-absence as shipped). No row remains classified as missing.

The material upstream additions now tracked include raw-byte NIP-98 hashing,
configurable body limits, HEAD negotiation, MCP ACL targeting, POST sidecar
Control checks, the runtime-plugin cluster, and DID Core-first context order.
No runtime-plugin ABI is proposed for Rust; Cargo features and typed route
composition remain the documented architectural choice.

## Positive controls verified

- Unsafe Rust is denied/forbidden across the workspace.
- The all-targets, all-features build, Clippy, and test suite pass.
- Proxy redirect targets are revalidated and DNS-pinned by the SSRF policy.
- Storage path normalisation and deny-by-default WAC controls are implemented
  for the ordinary LDP route family; AUD-009 records MCP exceptions.
- The current JSS DID context ordering already matches the Rust renderer.
- A current-worktree and Git-history pattern scan found no known-format private
  key or provider-token secret; the only private-key marker was a test
  assertion string, not key material.

## Audit limitations

This pass was source-led and exercised the complete existing Rust test suite
plus focused IdP, MCP, and filesystem-symlink exploit reproductions. It did not
perform internet-scale DAST, fuzz every parser, test a production reverse
proxy, or measure branch coverage. Dedicated `gitleaks`, `trufflehog`, Semgrep,
and `actionlint` binaries were unavailable, so secrets/SAST/workflow checks used
source review and pattern scans rather than those engines. Deployment secrets
and operating-system policy remain release gates for an exposed production
service.
