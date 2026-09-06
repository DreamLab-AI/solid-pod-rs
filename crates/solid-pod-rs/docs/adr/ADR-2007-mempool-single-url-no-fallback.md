---
id: ADR-2007
title: Anchor against one configured explorer URL, public default, no silent fallback
date: 2026-08-31
decision_status: accepted
implementation_status: complete
activation_status: live
supersedes: []
superseded_by: []
verified_commit: e093e88
owner: jjohare
review_trigger: the LAN Bitcoin node passes its cutover checklist, or telemetry justifies a fallback chain
repo: solid-pod-rs
domain: BASELINE-solid-pod-rs.md
lineage: Distils archived ADR-061 (LAN Bitcoin node substrate — non-goals: no ordered multi-URL fallback, LAN URL is deployment config not a crate default) and ADR-059 D3 (the mempool write side the anchor consumes).
---

# ADR-2007 — Anchor against one configured explorer URL, public default, no silent fallback

## Context

Block-trail anchoring needs a mempool.space-style REST backend for UTXO lookup
and tx broadcast. A sovereign LAN node (192.168.2.27) is intended but was
unreachable at design time. The obvious convenience — an ordered LAN→public
fallback so anchoring "just works" — would let a broken LAN node hide behind a
public explorer and silently reintroduce the third-party dependency the LAN node
exists to remove.

## Decision

`MempoolHttpClient` speaks exactly one configured REST base URL and fails loudly
on it — the struct holds a single `base: String` with no fallback list
(`mempool.rs:56-72`). The shipped crate default stays the **public**
`https://mempool.space/testnet4` (`mempool.rs:48`), so a pod without LAN access
keeps working; a sovereign/LAN explorer is selected purely by
`JSS_PAY_MEMPOOL_URL` (`mempool.rs:44`) as deployment configuration, never a new
crate default. Pod code never speaks bitcoind RPC directly — the REST seam
(`MempoolLookup`/`MempoolBroadcast`) is the only substrate boundary. A failed
lookup surfaces as an error, not a failover.

## Consequences

- Forecloses LAN→public failover: a down LAN node breaks anchoring visibly
  rather than degrading to a public explorer unnoticed; revisiting needs
  explicit telemetry.
- Keeping the public testnet4 default means the stock build's settlement path
  still touches a third party — sovereignty is a deployment act, not a default.
- The single-URL client cannot straddle mainnet and testnet4 at once; a
  deployment needing both runs two configured clients.
- Speaking only REST (never RPC) keeps the node's RPC LAN-firewalled to its own
  stack, at the cost of depending on an explorer's REST schema fidelity.

## Verification

- `mempool.rs:56-60` struct has a single `base` field, no fallback collection;
  `mempool.rs:48` `DEFAULT_MEMPOOL_URL = "https://mempool.space/testnet4"`;
  `mempool.rs:44` env override `JSS_PAY_MEMPOOL_URL`.
- `mempool.rs` error paths return `PaymentError::InvalidState` on non-success
  rather than retrying another URL, verified at `e093e88`.

## Closeout extension — 2026-09-04

Work packages: CP-04/08. Accountable owner: the existing owner above, with storage, identity and release maintainers for consumer acceptance. Historical status axes and verified commits are preserved; no deployment is re-certified.

The client retains one base URL, the public testnet4 default and a non-empty environment override. Blank or absent configuration selects the default; that is startup selection, not transport failover. Source distinguishes transaction absence from an ambiguous transport/server failure.

**Acceptance condition:** Record the selected endpoint and network in the deployment manifest. Test empty/explicit configuration, endpoint unavailability, unknown transaction and ambiguous broadcast recovery using fixtures. Distinguish submitted from confirmed anchors and retain an operator repair path. No real transaction or endpoint cutover is authorised or performed by this review.

Dependencies: CP-01 release identity and CP-04 effective authority. Reopen when the governed implementation, adapter, dependency, feature or deployment profile changes. See the [storage review](../../../../../VisionFlow/docs/estate-review/storage-and-authority.md) and [source revalidation](../../../../../VisionFlow/docs/estate-review/evidence/pod-closeout-snapshot.json). Scoped implementation status does not close these cross-service requirements.

## Acceptance progress — 2026-09-05

**Implemented.** The single-URL decision is retained — no fallback chain was
added, which would have introduced exactly the ambiguity this ADR rejects —
but the selection is no longer silent.

The finding: `MempoolHttpClient::from_env` read `JSS_PAY_MEMPOOL_URL` and fell
back to `https://mempool.space/testnet4` with no record anywhere. An operator
could not tell from the logs whether the pod was anchoring against mainnet,
testnet4, or an operator-supplied explorer — a silent default that could
anchor or verify against the wrong chain.

`crates/solid-pod-rs-server/src/mempool.rs` gained a pure selection surface:

- `MempoolConfigSource` — `Explicit` or `Default`, so a defaulted endpoint is
  distinguishable from a chosen one. Supplying a URL that happens to equal the
  default still counts as `Explicit`: it was a choice.
- `BitcoinNetwork` and `infer_network(base_url)` — classifies from the
  trailing path segment, case-insensitively; treats loopback as `Regtest`
  unless the path names a network; maps a bare `mempool.space` host to
  `Mainnet`; and returns `Unknown` for anything unrecognised rather than
  **guessing mainnet**.
- `MempoolSelection { base_url, network, source }` with `to_manifest_json()`.
- `select_mempool_endpoint(Option<&str>)` — the pure selector, treating an
  empty or whitespace-only value as absent, matching the previous behaviour.
- `log_mempool_selection` — one `info!` with structured `base_url`, `network`
  and `source` fields, plus a `warn!` naming `JSS_PAY_MEMPOOL_URL` whenever
  the network is `Unknown` **or** the source is `Default`.

`MempoolHttpClient` carries its `MempoolSelection` and exposes `selection()`;
`base_url()` is unchanged. Because `from_env()` is called per request on the
payment and provenance routes, logging there unconditionally would repeat the
record on every request — so `log_mempool_selection_once` guards it with a
`std::sync::Once`, and `solid-pod-rs-server`'s `main` calls it explicitly
after `AppState` construction. The selection is process-global (it comes from
an environment variable), so exactly one record is the right number: it
appears at boot even on a pod that never serves a payment route.

**Tests + results.** `crates/solid-pod-rs-server/tests/mempool_selection.rs`,
13 tests, all passing. No real network: HTTP cases use a local `wiremock`
`MockServer`, and the transport-failure case targets a refused loopback port.
No test reads or writes `JSS_PAY_MEMPOOL_URL` — the pure `Option<&str>`
selector is driven instead, so nothing races other tests.

- *empty config* — `absent_config_yields_defaulted_testnet4`,
  `whitespace_only_config_is_treated_as_absent`.
- *explicit config* — `explicit_config_is_marked_explicit_and_trimmed`,
  `explicit_default_url_is_still_explicit`,
  `infer_network_classifies_known_bases`,
  `infer_network_treats_loopback_as_regtest`,
  `infer_network_never_guesses_mainnet`.
- *manifest* — `manifest_json_carries_url_network_and_source`,
  `client_records_its_selection`.
- *unavailability* — `service_unavailable_is_ambiguous_not_a_definite_negative`
  (503 → `Err`, not `Ok(false)`), `unreachable_explorer_is_ambiguous`.
- *unknown transaction vs ambiguous failure* —
  `not_found_is_a_definite_negative_but_server_error_is_not` asserts the
  distinction explicitly, and `ok_response_reports_the_transaction_as_known`
  pins the positive case. This preserves the existing invariant that payment
  intent recovery may compensate a debit only for a definitive `Ok(false)`.

`wiremock = "0.6"` was added to the server crate's **dev**-dependencies only;
cargo strips dev-dependencies from published metadata. Full workspace: 1801
passed, 0 failed. Clippy clean.

**Receipts.** `../estate-closeout/2026-09-05/test-run.md`.

**Remaining.** (a) The manifest is emitted as a structured log record;
`to_manifest_json()` exists but is not yet surfaced on an HTTP manifest or
health endpoint, which would let an operator query the selection rather than
grep for it. (b) `AppState` still stores `mempool_url: Option<String>` (a
test-only override) rather than a resolved `MempoolSelection` built once at
boot; the three handler construction sites in `handlers/pay.rs` and
`handlers/prov.rs` each rebuild a client per request. That is a structural
tidy-up, not a correctness gap, and was left out of scope. (c) Deployed-tier
verification — the startup record observed in a real pod's logs, and network
selection confirmed against a live explorer — is not covered here.
(d) `activation_status` unchanged.

**Governed paths changed.** `crates/solid-pod-rs-server/src/mempool.rs`,
`crates/solid-pod-rs-server/src/main.rs`,
`crates/solid-pod-rs-server/Cargo.toml` (dev-dependencies only). New:
`crates/solid-pod-rs-server/tests/mempool_selection.rs`. `verified_commit`
unchanged.
