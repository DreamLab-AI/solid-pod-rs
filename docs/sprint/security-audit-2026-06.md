# solid-pod-rs Security Audit — 2026-06

**Date:** 2026-06-27
**Subject:** Verification of the upstream security report (`upstream-security-report-2026-06.md`,
authored in the DreamLab overlay repo) **against the actual `solid-pod-rs` source tree.**
**Pin audited:** workspace `0.5.0-alpha.2` (commit `6ea0299`), branch
`claude/agentic-qe-global-install-l20lwk`.

> **Why this doc exists.** The upstream report was written from the *overlay*
> repo (`dreamlab-ai-website` / `forum-config`), which only *consumes* these
> crates and cannot fix them, so it framed every finding as "file upstream."
> **This tree is `solid-pod-rs` itself.** Every B-series finding is therefore
> directly fixable here — and the P1/P2 items already are (see
> [§5 Status](#5-status)). This audit re-read every cited line; where the
> original report was imprecise (it imported two claims from the Cloudflare
> Worker variant), the correction is recorded.

Verdict legend: **CONFIRMED** (reproduced against source) · **CORRECTED**
(finding real, report wording wrong) · **N/A** (does not apply to this tree).

---

## 1. Executive summary

| ID | Finding | Severity | Verdict | Status |
|----|---------|----------|---------|--------|
| B1 | Stored content served inline, no `nosniff` → XSS | HIGH | CONFIRMED | **Fixed** |
| B2 | CORS reflects any origin **+** `credentials: true` | HIGH | CONFIRMED | **Fixed** |
| B3 | Container listing leaks names of ACL-private children | MEDIUM | CONFIRMED | **Fixed** |
| B4 | NIP-05 endpoint has no rate limit | MEDIUM | CORRECTED | **Fixed** |
| B5 | Quota never enforced on the write path | MEDIUM | CORRECTED | **Fixed** |
| B6 | git read contract / inbox spam / WebID HTML escaping | LOW | CONFIRMED | **Fixed** |
| A1–A7 | Forum-relay findings (zones, COUNT, moderation, WoT, WebAuthn) | — | **N/A** | n/a |

All B-series findings are now fixed on `claude/agentic-qe-global-install-l20lwk`
with regression tests; see [§5 Status](#5-status) for the per-commit breakdown.

**Posture:** the cryptographic / access-control core is sound (WAC deny-by-default,
NIP-98 verified, path-traversal defence in depth, zero `unsafe`). All confirmed
issues were **response-hardening and resource-accounting** gaps. The two HIGH
findings were exploitable in the default configuration and are now closed.

---

## 2. The A-series does **not** apply to this repository

The upstream report's A1–A7 target `nostr-bbs-relay-worker` — the **forum** relay
in the separate `nostr-rust-forum` project. They concern features that **do not
exist** in this tree:

`solid-pod-rs-nostr` is a **vanilla NIP-01/11/16 relay**. Its wire dispatcher
(`crates/solid-pod-rs-nostr/src/ws.rs:129-134`) handles only `EVENT`, `REQ`, and
`CLOSE`. There is **no** `COUNT` (NIP-45), **no** `AUTH` (NIP-42), and no concept
of zones, channels, moderation/`hidden_events`, Web-of-Trust, invites, or WebAuthn
registration anywhere in the crate. Each A-finding therefore has no surface here:

| Finding | Concerns | Present in `solid-pod-rs-nostr`? |
|---------|----------|----------------------------------|
| A1 broadcast zone gate | per-zone cohort gating | No — no zones |
| A2 REQ/COUNT default-allow | channel→zone projection | No — no channels; no COUNT |
| A3 soft-hidden events | moderation `hidden_events` table | No — no moderation |
| A4 NIP-45 COUNT auth | COUNT verb | No — COUNT not implemented |
| A5 WoT/invite dead code | registration gating | No — no registration/WoT |
| A6 NIP-42 AUTH relay tag | AUTH verb | No — AUTH not implemented |
| A7 WebAuthn atomic consume | WebAuthn ceremony | No — no WebAuthn |

Additionally, the embedded relay is **not wired into the deployed pod server** —
`crates/solid-pod-rs-server/Cargo.toml` has no dependency on `solid-pod-rs-nostr`.

> **Correction to the agentic-QE run that produced the first draft:** an
> intermediate automated pass reported "all seven A-series findings relevant."
> That pass was never given the real A1–A7 text and instead *invented* seven
> generic relay findings (rate-limit, subscription caps, etc.) and matched those.
> It is wrong. The report's actual A1–A7 are **N/A** here.

**Standalone observation (not from the report):** the generic relay does have its
own robustness gaps a downstream embedder should note — unbounded subscriptions
per socket (`ws.rs:190`), no event-size cap before `store.put`, and broadcast lag
swallowed by `let _ = self.broadcast(&event)` (`typestate.rs:343-382`). These are
low priority precisely because the relay is an optional library not mounted by the
server. Tracked separately from this audit.

---

## 3. Finding-by-finding (B-series)

### B1 — Stored content served inline without `nosniff` → stored XSS · HIGH · CONFIRMED
**Evidence:** repository-wide search found **zero** occurrences of `nosniff` /
`X-Content-Type-Options`. `guess_content_type` returns `text/html` for `.html`
(`crates/solid-pod-rs/src/ldp.rs:404`). The verbatim blob GET path
(`crates/solid-pod-rs-server/src/lib.rs:901`) sets `Content-Type` from stored
metadata and emits no protective headers; the middleware stack
(`build_app`) had no security-headers layer. Any principal with `acl:Write` on a
world-readable path can store `evil.html` and have it execute in the pod origin.

**Fix (this branch):**
- New `SecurityHeaders` actix middleware emits `X-Content-Type-Options: nosniff`
  on every response and `X-Frame-Options: SAMEORIGIN` when absent (preserving the
  stricter `DENY` already set on the mashlib HTML wrapper). Registered outermost
  in `build_app` so it covers responses short-circuited by inner guards.
- The verbatim blob path now adds `Content-Disposition: attachment` for *active*
  content-types (`is_active_content_type`: html, xhtml, SVG, JS/ECMAScript) so a
  correctly-typed `text/html` upload downloads instead of rendering. RDF and
  ordinary media stay inline.
- Tests: `crates/solid-pod-rs-server/tests/security_headers_b1.rs`.

### B2 — CORS reflects any origin **with** `credentials: true` · HIGH · CONFIRMED
**Evidence:** `add_cors_headers` (`lib.rs:2252`) resolved the ACAO to
`origin.unwrap_or("*")` when no allowlist is configured (the default —
`AppState.allowed_origins` is empty, `lib.rs:232`) **and** emitted
`access-control-allow-credentials: true` unconditionally. That is *reflect-any-origin
+ credentials*: any site could make credentialed cross-origin requests to the pod.
The correct `CorsPolicy` primitive existed in `crates/solid-pod-rs/src/security/cors.rs`
but the middleware never called it, and a test
(`middleware_guards.rs`) asserted the buggy header, locking it in.

**Fix (this branch):** `add_cors_headers` now advertises credentials **only** for
an origin matched against an explicit allowlist, and adds `Vary: Origin` for that
case. Open mode (no allowlist) still reflects the origin for usability but never
sends credentials. The locked-in test was inverted, and positive
(allowlisted → credentials) and negative (off-allowlist → no CORS headers) tests
added. *Note:* Solid's bearer/DPoP tokens are explicit headers, not CORS
"credentials," so dropping `Allow-Credentials` in open mode does not break token
auth. A follow-up may wire the middleware through `CorsPolicy` to retire the
parallel implementation entirely.

### B3 — Container listing enumerates ACL-private children · MEDIUM · CONFIRMED · *fixed*
**Evidence:** `container_representation` (`crates/solid-pod-rs/src/ldp.rs:2187`) is
`list(path)` → `render_container` with no per-child WAC evaluation; the WAC gate
fires once for the container (`lib.rs:767`). A caller with Read on the container
enumerates the *names* of every child, including those a child-specific `.acl`
restricts. Content stays protected; existence/naming leaks.
**Recommended fix:** filter the membership list with `find_effective_acl_dyn` +
`evaluate_access` per child, short-circuiting children that inherit the
already-satisfied container ACL (only fetch a child `.acl` when one exists). Cap
listing size to bound worst-case ACL fetches.

### B4 — NIP-05 endpoint has no rate limit · MEDIUM · CORRECTED · *fixed*
**Evidence:** `handle_well_known_nip05` performs no throttle; `LruRateLimiter`
exists (`crates/solid-pod-rs/src/security/rate_limit.rs`) but is not wired to the
route, enabling unbounded username enumeration (`{"names":{}}` vs a populated map
is a clean oracle).
**Correction:** the report's "limiter fails open on KV error" does **not** apply —
this native server uses in-process mutex limiters, not a fallible KV backend. The
real defect is the *absence* of any limiter on the route. ("Fails open on KV" was
imported from the Cloudflare Worker variant.)
**Recommended fix:** add an `LruRateLimiter` (per-IP) to `AppState`, call it at the
top of the handler, return 429 + `Retry-After`.

### B5 — Quota never enforced on the write path · MEDIUM · CORRECTED · *fixed*
**Evidence:** the only `quota` references in the server are the `quota reconcile`
CLI subcommand (`crates/solid-pod-rs-server/src/cli/mod.rs`) — a post-hoc disk
scan. No write handler (`handle_put`/`handle_post`/`handle_patch`) calls
`FsQuotaStore::check`/`record`; `AppState` has no quota field; the `quota` feature
is defined in `Cargo.toml:114` but is **opt-in and unused at request time**. Any
writer (including unauthenticated inbox appenders) can write unbounded data.
**Correction:** the report says quota is "charged to `owner_pubkey`." The
`QuotaPolicy` API is keyed by **pod-directory name string**, not a pubkey, and has
no writer-identity parameter at all. The substantive point (no per-writer
accounting, and in fact no enforcement) holds — and is worse than described, since
nothing is charged at write time.
**Recommended fix:** wire `FsQuotaStore` into `AppState` and the write handlers
(507 on `QuotaExceeded`); add an independent per-container inbox cap for
unauthenticated/append writes.

### B6 — Minor (git read contract; inbox spam; WebID HTML) · LOW · CONFIRMED
- **B6.1 git read contract — *fixed this branch (non-breaking opt-in).***
  `crates/solid-pod-rs-git/src/service.rs` gated reads only when
  `self.auth.is_some()`, so an embedder mounting `GitHttpService` without an auth
  provider *and* without its own access gate served anonymous clones. The
  deployed server is already protected by the WAC gate in `handle_git`, and the
  anonymous-read default is a documented JSS-parity behaviour with a test
  asserting it — so rather than flip that contract, a `require_read_auth()`
  builder was added: an embedder without its own gate opts in and unauthenticated
  reads are then rejected `401`. Default behaviour and existing tests are
  unchanged. Test: `require_read_auth_rejects_anonymous_read_without_provider`.
- **B6.2 inbox append spam — *fixed this branch*.** `handle_post` enforced WAC
  `Append` but applied no per-sender rate limit. Now throttled per sender (WebID
  when authenticated, else source IP) via the always-compiled `RouteRateLimiter`,
  honouring `JSS_RATE_LIMIT_WRITES_PER_MIN`. (See B4 for the shared limiter.)
- **B6.3 WebID HTML escaping — *fixed this branch*.** `generate_webid_html_with_issuer`
  (`crates/solid-pod-rs/src/webid.rs`) interpolated `display_name`/`webid`/`pod_url`
  into the HTML title, `<h1>`, and `href` attributes unescaped, and embedded
  JSON-LD without guarding the `</script>` close. Now HTML-escapes all three values
  and replaces every `<` with its six-character JSON unicode escape inside
  the JSON-LD island (so a value cannot close the script block). Tests:
  `webid::tests::display_name_with_markup_is_escaped`,
  `html_escape_covers_significant_chars`. (Hardening `validate_webid_html` to reject
  executable markup in *uploaded* profiles remains a follow-up.)

---

## 4. The upstream patch does not apply here

`upstream-patches/0001-pod-worker-cors-nosniff-credentials-guard.patch` targets
`nostr-bbs-pod-worker` — a `wasm32` Cloudflare Worker using a JS-style `Response`
API. This tree is a native actix-web binary; **zero lines apply verbatim**. The
patch's *intent* (nosniff everywhere; no credentials under a wildcard) is correct
and is what the B1/B2 fixes on this branch implement with actix middleware. The
patch itself lives in the overlay repo against the forum kit; it is not vendored
here because nothing in it is mechanically applicable to this codebase.

---

## 5. Status

**All B-series findings fixed on `claude/agentic-qe-global-install-l20lwk`**, each
with regression tests; full `solid-pod-rs`, `solid-pod-rs-server`, and
`solid-pod-rs-git` suites green (default features, plus `nip05-endpoint`, `quota`,
and `git` feature builds verified).

| Commit | Findings | Headline change |
|--------|----------|-----------------|
| 1 | B1, B2, B6.3 | `SecurityHeaders` middleware + `Content-Disposition`; CORS credentials only for allowlisted origins; WebID HTML escaping |
| 2 | B4, B6.2 | always-compiled `RouteRateLimiter` on NIP-05 (per-IP) and container POST (per-sender) |
| 3 | B3 | per-child WAC filter + auxiliary-resource exclusion on container listing |
| 4 | B5 | per-pod quota check/record on PUT/POST (507 on exceed); `FsQuotaStore` wired under the `quota` feature |
| 5 | B6.1 | `require_read_auth()` opt-in for git embedders without their own gate |

**Follow-ups (not blocking, noted for completeness):**
- B5 — extend quota to `PATCH` (the resulting body size must be computed after
  applying the patch) and add an independent inbox child-count cap.
- B6.3 — harden `validate_webid_html` to reject executable markup in *uploaded*
  profiles (the generation path is escaped; the validation path is not).
- B2 — optionally retire the parallel `add_cors_headers` by delegating to the
  library `CorsPolicy`.
- Relay robustness (separate from the report): subscription/event-size caps and
  surfaced broadcast-lag errors in `solid-pod-rs-nostr` — low priority while the
  relay is an unmounted library.

The crypto/auth core needs no changes at this pin.
