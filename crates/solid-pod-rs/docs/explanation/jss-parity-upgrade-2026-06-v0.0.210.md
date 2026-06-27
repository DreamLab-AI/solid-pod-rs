# JSS v0.0.204 → v0.0.210 Parity Sync — Engineering Report

**Date:** 2026-06-27
**Comparator:** JavaScriptSolidServer (JSS) — npm `javascript-solid-server`,
baseline `0.0.204` (upstream `9d29167`) → latest `0.0.210` (gitHead
`0f4287f`). The upstream repo publishes no GitHub releases and ships no
CHANGELOG; the delta was reconstructed by `npm pack`-ing both versions and
diffing the `src/` trees (16 changed files), with issue numbers read from the
code comments.
**Target:** `solid-pod-rs` on branch `claude/agentic-qe-global-install-l20lwk`.
**Method:** per-file source diff → map each change to the Rust port → port the
real functional gaps, classify the rest (satisfied-by-design / sibling-crate /
not-applicable) with rationale.

---

## 0. Executive summary

The v0.0.204→v0.0.210 delta is **15 modified files + 1 new** (`src/utils/port.js`).
Classifying every change:

| Item | Area | Verdict | Action |
|------|------|---------|--------|
| **#548 / #371** | git CORS on auth denial | **GAP** | **Ported** |
| **#561** | git CONTENT_LENGTH for chunked pushes | **GAP** | **Ported** |
| **#563 / #474** | configurable body limit (`JSS_BODY_LIMIT`) | **GAP (env name)** | **Ported** |
| **#575** | `write_acl` `acl:default` only on containers | **partial** | **Ported** |
| #552 | HEAD/GET Content-Type & Cache-Control parity | satisfied-by-design | documented |
| #565 / #573 | NIP-98 payload hash over raw bytes | library already correct | documented |
| #428 | host-portable (relative) ACL IRIs | deliberate divergence | documented |
| #557 | `findFreePort` / `formatUrl` for `jss start` | optional CLI DX | not ported (semantics) |
| #451 | root-path WebID resolution (rebuild loop) | sibling-crate, no analog | N/A |
| #524 | IdP discovery field normalization | sibling-crate | N/A |
| #526 / #514 | IdP interaction retry foundation | sibling-crate refactor | N/A |
| #556 | WebAuthn secure-context gate (WebView) | client-side HTML view | N/A |
| #530 | tunnel credential passthrough | feature not ported to Rust | N/A |

Four real functional gaps were closed; the remainder are either already correct
by construction, deliberate divergences, or JSS-internal changes with no 1:1
analog in the independently-architected Rust crates.

---

## 1. Ported — git (`solid-pod-rs-git`, `solid-pod-rs-server`)

### #548 / #371 — git CORS headers on the WAC denial path
**JSS:** `server.js` now calls the (newly exported) `setGitCorsHeaders` on the
401/402/403 returns of the WAC preHandler, and `git.js` adds `Git-Protocol` to
`Access-Control-Allow-Headers`.

**Rust before:** `handle_git`'s WAC gate returned `e.error_response()` on denial
with no CORS headers — a browser-based git client (e.g. `jss.live/git/`) hitting
an auth-gated repo saw a generic CORS/network error instead of the real status.
The git service set CORS only on its *own* responses, but the WAC gate runs
*before* the service.

**Rust now:** a single source-of-truth `GIT_CORS_HEADERS` const
(`solid-pod-rs-git/src/service.rs`) backs the OPTIONS preflight, the CGI
response, **and** the WAC-denial path in `handle_git`. `Git-Protocol` is now in
`Allow-Headers` for protocol-v2 clients. Test:
`git_wac_gating::wac_denied_git_response_carries_cors_headers`.

### #561 — CONTENT_LENGTH from the buffered body
**JSS:** `git.js` sets the CGI `CONTENT_LENGTH` from `request.body.length` when
the body is non-empty, because git sends packs larger than `http.postBuffer`
(1 MiB) with `Transfer-Encoding: chunked` and **no** `Content-Length` — the
header fallback reported "0 bytes" and `receive-pack` died on any push > 1 MiB.

**Rust before:** `spawn_cgi` set `CONTENT_LENGTH` from the `content-length`
header, only falling back to the body length when the header was absent — so the
chunked case worked via fallback, but a present-but-stale header was trusted.

**Rust now:** `resolve_content_length(body_len, headers)` prefers the buffered
length whenever the body is non-empty (extracted as a pure, unit-tested helper).
Tests: `content_length_prefers_buffered_body_over_header`,
`content_length_falls_back_to_header_for_empty_body`.

---

## 2. Ported — config & MCP

### #563 / #474 — configurable request body limit
**JSS:** the hardcoded 10 MiB body cap became a configurable `bodyLimit`
(`--body-limit` / `JSS_BODY_LIMIT` / `createServer({ bodyLimit })`), default
raised to 20 MiB, parsed through `parseSize` for size-string support.

**Rust:** the body cap was **already** configurable (`JSS_MAX_REQUEST_BODY`,
parsed via `parse_size`). The delta is the canonical env name. `body_cap_from_env`
and the config overlay now recognise **`JSS_BODY_LIMIT`** first, with
`JSS_MAX_REQUEST_BODY` / `JSS_MAX_BODY_SIZE` retained as aliases.

*Deliberate divergence:* we keep the historically more-permissive
`DEFAULT_BODY_CAP` (50 MiB) rather than JSS's 20 MiB — a larger cap is not a
security regression, and lowering a default that existing deployments rely on is
a breaking change; operators tighten it via `JSS_BODY_LIMIT`.

### #575 — `write_acl` `acl:default` only on container ACLs
**JSS:** the MCP `buildAclDoc` change has two parts: (1) `accessTo` for a
*resource* ACL must be `./<basename>`, not `./` (which resolved to the parent
container and locked the owner out), and (2) `acl:default` is emitted only for
container ACLs.

**Rust:** part (1) **does not arise** — our `build_acl_jsonld` uses the
**absolute** resource `path` for `accessTo`, which already targets the resource
correctly (the JS bug was specific to its relative `./` form). Part (2) is
ported: `acl:default` is now gated on `path.ends_with('/')`, since it is inert
on a resource ACL.

*Note (#428):* JSS moved to relative IRIs for host-portability of stored ACLs;
we retain absolute IRIs (a long-standing, tracked semantic-difference — the WAC
evaluator matches them directly).

---

## 3. Satisfied by design — no change needed

### #552 — HEAD emits the same Content-Type / Cache-Control as GET (RFC 9110 §9.3.2)
JSS split HEAD from GET historically, so a large `negotiateHeadFileContentType`
helper (with bounded 1 MiB reads) was added so HEAD mirrors GET's negotiated
type and RDF `Cache-Control`, and omits `Content-Length` for conneg-converted
bodies.

In the Rust port **HEAD is routed to `handle_get`** (one handler;
actix strips the body), so HEAD has *always* emitted the exact Content-Type,
Cache-Control, and (converted-aware) Content-Length a GET would — the parity
#552 retrofits is structural here. *Residual divergence:* `handle_get` reads the
whole file for a HEAD, where JSS's #552 added a bounded read for multi-GB files.
This is an efficiency difference, not a correctness one, and is confined to HEAD
on very large resources; splitting HEAD into a bounded-read handler is tracked as
a possible future optimisation, not a parity gap.

### #565 / #573 — NIP-98 payload hash over the exact signed bytes
JSS's bug was that its JSON parser discarded the raw wire bytes, so the payload
hash was checked against a *re-serialization* — pretty-printed or
differently-escaped bodies 401'd despite a valid signature. The fix captures
`rawBody` and hashes Buffers directly; #573 keys the check on body-present, not
truthiness.

The Rust `auth::nip98` verifier takes the body hash as `Option<&[u8]>` and the
caller computes it over the raw `web::Bytes` — there is **no re-serialization
step to get wrong**, and presence is already modelled as `Some`/`None` (not
truthiness), so the #565/#573 semantics hold in the library by construction.
*Separately:* the consumed pod-auth path (`extract_pubkey`) currently passes
`None` (no payload binding) — wiring full payload binding through every handler
is a pre-existing, larger decision unrelated to this delta and is tracked
independently.

---

## 4. Not applicable / not ported (with rationale)

- **#557 `findFreePort` / `formatUrl`** — a `jss start` DX nicety (probe for a
  free port, pretty startup banner URL). The Rust binary binds the configured
  address and fails hard on a taken port. Auto-incrementing the port would
  change operator-visible bind-failure semantics (scripts may rely on the hard
  failure), so this is left as an optional future flag rather than a silent
  behaviour change.
- **#451 root-path WebID resolution** — fixes an edge case in JSS's
  `well-known-did-nostr.js` *rebuild loop* (it scans `profile/card.jsonld` files
  to build a did:nostr→WebID index). The Rust resolver
  (`solid-pod-rs-nostr/src/resolver.rs`) resolves **directly** (fetch the WebID
  doc, extract the pubkey) — there is no scan-and-rebuild index, so the edge case
  has no analog.
- **#524 / #526 / #514 / #556 (IdP)** — `solid-pod-rs-idp` is an independently
  implemented Rust OIDC IdP, not a wrapper over Node `oidc-provider`. These are
  internal to JSS's provider/interactions/HTML-views: #524 normalizes a
  discovery field, #526/#514 are foundation/refactor for an interaction-retry
  flow, and #556 is a **client-side** `isSecureContext` gate in the HTML login
  page JSS serves. The Rust IdP delegates UI rendering to the consumer
  (`provider.rs`: "the consumer must render a login page"), so #556 has no
  server surface, and the others have no 1:1 analog.
- **#530 tunnel** — credential passthrough for JSS's built-in HTTP tunnel. The
  tunnel feature is not part of the Rust port (no `tunnel` module), so this is
  N/A — consistent with its long-standing `wontfix-in-crate` classification.

---

## 5. Result

Four commits on `claude/agentic-qe-global-install-l20lwk` close the functional
gaps (#548, #561, #563, #575) with regression tests; `solid-pod-rs`,
`solid-pod-rs-server`, and `solid-pod-rs-git` suites are green. The
spec-normative and protocol-visible surface remains at full parity; the residual
divergences (#552 HEAD efficiency, #428 absolute ACL IRIs, #563 default cap) are
deliberate and documented.
