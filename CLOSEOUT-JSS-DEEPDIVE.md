# solid-pod-rs vs JavaScriptSolidServer — Closeout Deep-Dive Register

**Date:** 2026-07-03
**Method:** Fable-queen-orchestrated ruflo mesh; 10 comparison dimensions, each analysed by an Opus agent and adversarially verified by a second Opus agent (58 CONFIRMED / 4 ADJUSTED / 1 REFUTED verdicts + ~30 verifier-surfaced misses). Fable confined to planning + decision synthesis; all code analysis performed by the Opus mesh.
**Baseline:** JSS on-disk = `gh-pages` @ `10bd60f` = package `0.0.197` (authoritative comparator). The tracked `0.0.204` forward-delta (MCP #490, install CLI, NIP-98 mint, getContentType, symlink-listing, audio-pane) was ported from upstream commit refs and is *intentionally ahead* — not counted as a gap. solid-pod-rs @ `957fb8e`, 7 crates / ~76.8k LOC. JSS ~25.2k LOC.

---

## Executive verdict

**solid-pod-rs is a high-quality library port with a thin reference server.** The crate-level modules are, in several places, *richer and more hardened than JSS* (single-use NIP-98 replay cache, argon2, SSRF classification, durable AP delivery with backoff, an ACL-lockout guard JSS lacks, correct deny-by-default + mode-implication, frame/CSP/no-store on mashlib). The problem is almost never the library — it is that the shipped `solid-pod-rs-server` (actix-web) **wires only a slice of what the libraries implement**, and `PARITY-CHECKLIST.md` measures *library presence*, not *deployed HTTP behaviour*, so it **systematically overstates real-world parity**. (The `acl:agentGroup` support is the sharpest example: the library implements it, but the server passes an empty resolver at every call-site, so at runtime it is a no-op — see P1-r.)

Three consequences dominate this closeout:

1. **The "unwired library" cluster** — 2 P0s (AP federation, OIDC issuer) and ~10 P1s are fully-built, unit-tested modules with **zero call-sites in the request path**. Closing them is mostly plumbing, not new design.
2. **Access-control breaks in the WAC path** — 2 P0s from the WAC re-run: `.acl`/`.meta` **reads** gated on `acl:Read` not `acl:Control` (info-disclosure of the whole authorization graph — the *inverse* of JSS), and POST `Slug: x.acl` **injecting** a self-granting ACL sidecar from `Append`-only rights. Plus a document-wide (not rule-scoped) `acl:origin` gate. These block deployment.
3. **A cluster of genuine correctness/security bugs in code that *is* wired** — POST-Slug data loss, a `did/nostr` endpoint that asserts a false identity binding for *any* pubkey, an unverified `alsoKnownAs` resolver, missing `Vary`/`Cache-Control` on authenticated responses, `.meta.json` content-type poisoning, and the `provision_pod` shared-root path clobber.

**Headline decision:** for each unwired surface, the choice is binary — **FINISH** (bind the existing library into the server) or **FREEZE + relabel** the checklist row honestly (`library-only, not server-wired`). What is *not* acceptable at closeout is leaving the checklist claiming "present" for surfaces a deployed pod cannot actually serve.

### Severity tally (verified, deduped)

| Severity | Count | Character |
|----------|-------|-----------|
| **P0** | 4 | Whole federation + whole OIDC-issuer surface non-functional; **+2 WAC access-control breaks** (`.acl` read-disclosure, POST `.acl` injection) |
| **P1** | 18 | User-hit functional gaps + real security/correctness bugs (+2 WAC: doc-wide origin gate, agentGroup no-op) |
| **P2** | ~28 | Robustness, spec-drift, hardening, header/status divergences |
| **P3** | ~25 | Polish, cosmetic, accepted-scope differences (many are net-positive over JSS) |

---

## P0 — whole-surface non-function (P0-1/2) and access-control breaks (P0-3/4)

### P0-1 · ActivityPub crate is orphaned — federation is non-functional
`solid-pod-rs-activitypub` is a workspace member but **not a dependency of `solid-pod-rs-server`** (nor any binary). The server mounts no actor negotiation, no `/inbox`, no outbox/collections, and never instantiates `DeliveryWorker`. The library (actor/inbox/outbox/http_sig/delivery/store) is self-consistent and unit-tested but no HTTP surface reaches it — the pod cannot receive a Follow, emit an Accept, serve its actor, or deliver a post. Checklist rows 102–108 mark these "present."
- JSS: `src/server.js:377-378, 425-440`; `src/ap/index.js:176-188`
- Rust: `crates/solid-pod-rs-server/Cargo.toml` (no `activitypub` dep); `.../src/lib.rs:3593-3604` (only webfinger+nodeinfo)
- **Decision: FINISH** (wire behind a `--federation` flag: actor negotiation + inbox/outbox/collections + `DeliveryWorker::run`) **or FREEZE** and downgrade rows 102–108 to `library-only, server wiring deferred`.

### P0-2 · Solid-OIDC issuer HTTP surface is not mounted
The idp crate implements discovery, JWKS, authorize/token/userinfo, client registration, and credential login, and exposes an **axum** router (`axum_binder.rs`) — but the shipped **actix** server never binds it. `build_app` mounts no `openid-configuration`, no `jwks.json`, none of `/idp/*`. Worse, `handle_well_known_solid` advertises a `solid_oidc_issuer` pointer whose `openid-configuration` 404s, so Solid-OIDC discovery is broken end to end.
- JSS: `src/idp/index.js:162-262, 375-536`
- Rust: `.../lib.rs:3593-3670` (no oidc routes); `crates/solid-pod-rs-idp/src/axum_binder.rs:56-67` (router never bound)
- **Decision: FINISH** (bind openid-configuration, jwks.json, `/idp/reg`, `/idp/credentials`, wire `/auth`+`/token`) **or FREEZE** + relabel rows 74/76/79 `library-only, not deployed`.

### P0-3 · `.acl`/`.meta` sidecar READS enforce `acl:Read`, not `acl:Control` — ACL info-disclosure
The port protects `.acl` **writes** (Control elevation in `enforce_write_ctx`) but **not reads**: `handle_get` routes every path, sidecars included, through `enforce_read_ctx` with `AccessMode::Read` and **no** `protected_resource_for_acl` elevation. The resolver then walks up to an ancestor's `acl:default` **Read** grant. So on any pod with a public- or authenticated-Read `acl:default` (e.g. a `/public/` container), an under-privileged agent can `GET /public/foo.acl` and read the entire authorization graph — every WebID, `acl:agentGroup` IRI, `acl:origin`, and `acl:PaymentCondition` amount. This is the **exact inverse of JSS** (which gates *all* ACL ops on Control) and contradicts the port's own `wac-modes.md:14`.
- JSS: `src/auth/middleware.js:93-95` → `authorizeAclAccess` requires `AccessMode.CONTROL` (`438-451`, with the "all ACL operations require Control… more secure" comment)
- Rust: `lib.rs:885` + `enforce_read_ctx` `lib.rs:758-805` (no elevation) vs write-path elevation `lib.rs:588-615`
- **Decision: FIX** — in `enforce_read_ctx`, mirror `enforce_write_ctx`: if `protected_resource_for_acl(path).is_some()`, evaluate `AccessMode::Control` on the protected resource.

### P0-4 · POST + `Slug: x.acl` injects a sidecar with only `Append` on the container — privilege escalation
`handle_post` enforces `AccessMode::Append` on the **container only**, then `resolve_slug` (which permits `.`) turns `Slug: victim.acl` into `/c/victim.acl`, written verbatim by `storage.put`. Unlike `handle_put`, the POST path neither elevates to Control **nor** runs the lockout guard on the resolved target. An agent holding only `Append` on a container (a public-append inbox/upload dir) can create a **direct** `.acl` for a named sibling granting itself `acl:Control`+`acl:Read`; the resolver probes the resource's own sidecar first (`honour_access_to=true`), so the injected ACL overrides the stricter inherited default. **Same bug class as the storage-dim `.meta.json` poisoning (P2)** — unreserved sidecar namespace + unguarded write path. (JSS shares this latent gap — not a port regression — but the Rust PUT path already shows how to close it.)
- JSS: `src/handlers/container.js:70-80` (same slug filter), `middleware.js:93` (Control guard keyed on container path, not `.acl`)
- Rust: `lib.rs:1115-1157` (no `protected_resource_for_acl`/lockout on `target`), `ldp.rs:170-181`; contrast `lib.rs:1089-1096`
- **Decision: FIX** — after `resolve_slug`, if `protected_resource_for_acl(&target).is_some()`, elevate to `Control` and run `proposed_acl_keeps_caller_control` before writing.

---

## P1 — user-hit functional gaps and real security/correctness bugs

### Unwired-library cluster (FINISH or FREEZE+relabel)

| # | Finding | Evidence | Decision |
|---|---------|----------|----------|
| P1-a | **Conditional requests never enforced** — `If-Match`/`If-None-Match`/304/412 advertised in CORS but no handler reads them; `evaluate_preconditions` has zero call-sites. Permits concurrent-write data loss. | Rust `ldp.rs:1520` (defined, never called); `lib.rs:1048-1113,1462-1476,2478-2479` · JSS `resource.js:814-829,917-923,1005-1013` | **FINISH** — wire into put/delete/patch (412) + get (304); emit ETag on container listings |
| P1-b | **Quota never wired into write path** — `FsQuotaStore`/`QuotaTracker` fully built, 0 call-sites; 507 never fires, disk-fill unprotected. Row 113 marks "present." | Rust `lib.rs:1098-1102,1140-1144`; `provision.rs:420`, `quota/mod.rs:245` (no server callers) · JSS `resource.js:865-878` | **FIX** — call `FsQuotaStore::check` before `put` (507), `record`/`release` after; else DELETE the code + drop the claim |
| P1-c | **NIP-98-only resource auth** — no Solid-OIDC/DPoP, Bearer, or IdP-JWT on protected resources. Full DPoP+JWKS machinery exists in core but `extract_pubkey` calls only `nip98::verify_at`. A standard DPoP-bound token is denied. | Rust `lib.rs:339-372`; DPoP verify only in `idp/provider.rs:225,314` · JSS `auth/token.js:201-263` | **FINISH** (wire `verify_dpop_proof`+`verify_access_token`+JWKS behind `auth.oidc_enabled`) **or ACCEPT** + relabel binary NIP-98-only and stop advertising DPoP/Bearer |
| P1-d | **Pod provisioning seeds no owner ACL tree** — `plan.root_acl = None`; WAC is deny-by-default so a freshly provisioned pod **locks the owner out** of everything but the public type index. | Rust `lib.rs:1797-1834`, `provision.rs:256-262`, `wac/resolver.rs:26-27` · JSS `container.js:231-255` | **FIX** — construct+pass `root_acl` (owner full control + default) and the per-container ACLs JSS writes |
| P1-e | **WebID omits `solid:oidcIssuer`** — issuer-carrying `generate_webid_html_with_issuer` exists but the provisioning path calls the 3-arg variant; WebID→issuer discovery broken. | Rust `provision.rs:247`, `lib.rs:1897` · JSS `container.js:297`, `profile.js:120,127-133` | **FIX** — thread `oidc_issuer` through `ProvisionPlan` |
| P1-f | **WebID omits `pim:storage`** (uses `solid:account`) — clients can't locate storage from the WebID. | Rust `webid.rs:123` · JSS `profile.js:119` | **FIX** — emit `pim:storage`, keep `solid:account` as additive |
| P1-g | **Registration establishes no credential** — `CreateAccountRequest` carries no password; login/reset/change are no-op stubs that `let _ = ...` and return success. A "registered" user cannot log in; password endpoints falsely report success. | Rust `lib.rs:1752-1757,2037-2067` · JSS `interactions.js:539-544`, `credentials.js:83,145` | **FIX** (hash password → persistent UserStore, wire real handlers) **or DELETE** the stub endpoints |
| P1-h | **WebFinger omits AP `self`/`application/activity+json` link** — even the one wired discovery endpoint can't be resolved by any fediverse server. | Rust `interop.rs:104-130` (wired at `lib.rs:1541`) · JSS microfed `webfinger.js:18-33` | **FIX** — add self-link `href=<base>/profile/card.jsonld#me`, gated on federation |
| P1-i | **Notifications unmounted** — `Updates-Via: wss://host/.notifications` stamped on responses but **no `/.notifications` route exists** (falls to 404); `pump_from_storage`/`LegacyWebSocketSession` are library-only. SolidOS/mashlib live updates absent. | Rust `lib.rs:857-865,3592-3798`, `main.rs` (no pump) · JSS `notifications/index.js:36-40`, `websocket.js:273` | **FIX** — mount `/.notifications` WS + `storage.watch`→fan-out; until then stop advertising `Updates-Via` or relabel rows 27/91/99 |
| P1-j | **Follower inbox never resolved** — `handle_inbox` reads a non-standard `actorInbox` field; a real Follow stores `inbox=NULL`, so the follower is never delivered anything and the Accept can't be sent back. | Rust `inbox.rs:79-91`, `store.rs:180-188` · JSS `inbox.js:195-219` | **FIX** — resolve the follower actor via `ActorKeyResolver` before `add_follower` |

### Wired-code bugs cluster (FIX)

| # | Finding | Evidence | Decision |
|---|---------|----------|----------|
| P1-k | **POST with colliding Slug overwrites** — silent data loss; LDP POST must mint a new name. JSS appends `-1`,`-2`. | Rust `ldp.rs:155-185`, `lib.rs:1131-1144` · JSS `container.js:86-90`, `filesystem.js:202-226` | **FIX** — existence-probe/`409-on-collision` in `handle_post` |
| P1-l | **`did/nostr` returns a hardcoded doc for ANY pubkey** — no ownership check, no 404, `alsoKnownAs` hardcoded to a single-user profile path; asserts a **false identity binding** for every pubkey the owner doesn't hold; flatly wrong for multi-user. | Rust `lib.rs:1569-1609` · JSS `well-known-did-nostr.js:111-262,465-483,524-561` | **FINISH** (port account-index resolution: ownership, real WebID, 404, multi-account exclusion) **or FREEZE** only if contractually single-user *and* the handler verifies the queried key is the owner's |
| P1-m | **`resolve_nostr_to_webid` trusts `alsoKnownAs` with no backlink verification** — a hostile DID doc pointing `alsoKnownAs` at a victim WebID makes the resolver return the victim's identity. Latent (library API only) hence P1 not P0, but strictly weaker than the JSS baseline. | Rust `resolver.rs:141-190` · JSS `did-nostr.js:275-304,336-512` | **FIX** — add CID-VM / `sameAs` backlink verification mirroring `verifyWebIdBacklink` |
| P1-n | **No `Vary`/`Cache-Control` on authenticated responses** — container listings, index.html, verbatim resources carry per-user `WAC-Allow` yet are cacheable without keying on `Authorization`; CORS echoes Origin with no `Vary: Origin`. Shared-cache cross-user leak. | Rust `lib.rs:945-953,1019-1032,2470-2492`; `ldp.rs:1844-1860` (helpers unused) · JSS `conneg.js:201-205`, `resource.js:30,383-385` | **FIX** — emit `Vary: Authorization, Origin` (+Accept) + `Cache-Control: private, no-cache, must-revalidate` on all RDF/WAC-varying responses |
| P1-o | **N3/SPARQL PATCH refuses Solid-native JSON-LD + real Turtle** — patch seed parses stored body as N-Triples only → 409 on the common create-then-patch flow; success rewrites resource as N-Triples relabelled `text/turtle`. Integration test asserts the 409, so it's designed behaviour — but a real regression vs JSS. | Rust `lib.rs:1386-1401,1207-1246`, `ldp.rs:791-804` · JSS `resource.js:1019-1140`, `patch/*.js` | **FIX** — Turtle/JSON-LD→Graph parser for patch seeding (or normalise to N-Triples at PUT) + preserve content-type; else FREEZE with a prominent `N-Triples-canonical` constraint doc |
| P1-p | **N3-Patch body parser is N-Triples-only** — rejects `@prefix`, `a`, `;` continuations, relative/hash IRIs; canonical solid-client/mashlib/penny patches 400. (SPARQL-Update via spargebra is fine — weakness is the N3 dialect + `solid:where` variables hard-fail 400.) | Rust `ldp.rs:1124-1156,817-838` · JSS `n3-patch.js:30-35,98-100,140-148,204-232` | **FIX** — prefix expansion + `a` + `;` + base-relative IRI resolution; classify variable `where` as 501 not 400 |
| P1-q | **`acl:origin` gate is document-wide, not rule-scoped** — `check_origin` matches the request origin against *any* pattern in the whole ACL doc, decoupled from which rule granted. So Rule A (`Alice;Write;origin alice-app`) is satisfied by an origin on unrelated Rule B → Alice writes from `bob-app`; and a public-Read rule with no origin is spuriously denied whenever another rule has origin patterns (fail-closed availability bug). The module comment claims rule-level short-circuiting "is performed by the evaluator" — **it is not**. (`acl:origin` *is* wired — refutes the old "possibly unwired" flag.) | Rust `origin.rs:264-305`, `evaluator.rs:328-351` · JSS n/a (no origin gate) | **FIX** — scope the origin check to the single granting authorization |
| P1-r | **`acl:agentGroup` is a runtime no-op** — the core evaluator supports it, but *every* enforcement call-site builds an empty `StaticGroupMembership::default()` and nothing fetches a `vcard:Group` doc, so `is_member` always returns `false` and group grants never match a live request. At runtime the server behaves **identically to JSS's TODO stub**. Fail-closed (no hole) but the advertised parity feature is unreachable — the *library-present ≠ server-wired* pattern again. | Rust `lib.rs:601,639,777` (empty resolver), `tools.rs:89` · JSS `checker.js:227` (`// TODO`) | **FINISH** (wire a group-doc resolver before evaluation) **or FREEZE** + drop the "implements agentGroup" claim |

---

## P2 — robustness, spec-drift, hardening (condensed)

**LDP:** POST can't create subcontainers (`ldp:BasicContainer` Link ignored) → FINISH · Range/206 never honoured → FINISH · bare 404s (rich discovery headers unused) → FINISH · container listing leaks non-allowlisted dotfiles JSS filters → FIX · container PUT returns 405 not 201/409 → FIX.
**Auth:** NIP-98 payload-integrity not enforced (`verify_at(..,None,..)`) → FIX · GitLenient URL match lacks path-boundary, over-grants scope → FIX · NIP-98 caller never elevated to declared WebID (always `did:nostr:<pubkey>`) → FINISH/ACCEPT · **DPoP HS256+oct symmetric carve-out compiled into production** (RFC 9449 §5 violation) → FIX (gate behind `#[cfg(test)]`).
**Nostr/DID:** `interop::DidNostrResolver` backlink is a substring scan, misses CID-VM linkage → FIX · emitted DID doc not byte-parity across ports (auth form, key order, `alsoKnownAs`) → FREEZE explicitly · well-known header policy diverges (no `Nostr-Timestamp`/`Last-Modified`/404-case) → FINISH · serves only `<pubkey>.json` not `<pubkey>`/`.jsonld` → FINISH · **stale `did.rs` tests panic** asserting a `service` array the renderer no longer emits → FIX (dead test).
**Storage:** git auto-init drops JSS empty-dir guard (can swallow a populated dir) → FIX · no restrictive file modes — owner privkey loses JSS `0o600` at-rest protection → FIX · corrupt `.quota.json` under-counts (used=0) vs disk-truth reconcile → FIX · MongoDB `/db` backend absent+undocumented → ACCEPT+document · HEAD reads whole file to hash etag → FIX (perf) · **`.meta.json` sidecar namespace unreserved** — `x.meta.json` PUT hides the resource + can poison a sibling's served Content-Type (stored-XSS vector) → FIX.
**IDP/WebID:** `/.pods` stamps a bogus Nostr VM from the username → FIX · WebID served `text/html` at `/profile/card` not JSON-LD at `card.jsonld` → FIX · `provision_pod` **path-model mismatch** — every `/api/accounts/new` clobbers shared-root `/profile/card` + type indexes (no `{username}` prefix), WebID URL unresolvable → FIX (data-corruption-grade) · missing `ldp:inbox`/`pim:preferencesFile` + prefs file → FIX · weak username validation, no invite/single-user gating/rate-limit → FIX.
**ActivityPub:** outbox Note→Create drops `to`/`cc` addressing → FIX · no OrderedCollection renderers (outbox/followers/following) → FIX · HTTP-Sig doesn't mandate Digest coverage for POST (contradicts own comment) → FIX · **inbox doesn't bind `activity.actor` to the verified signature key** → FIX · Mastodon client API + OAuth absent → ACCEPT/FINISH · NodeInfo advertises `activitypub` while serving none (dishonest discovery) → FIX.
**PATCH/RDF:** SPARQL `DELETE/INSERT…WHERE` + named-GRAPH quads silently no-op → 204 → FIX (400/501) · N-Triples `\uXXXX`/`\UXXXXXXXX` escapes corrupted → FIX · `text/turtle` output is N-Triples relabelled (no real serialiser) → FINISH/ACCEPT · `solid:deletes` not enforced as precondition → ACCEPT/FIX.
**WAC/ACL:** `acl:accessTo` matches direct container children (+ `default` honoured on direct ACLs) — over-grant vs JSS exact-match, confined by the `honour_access_to` inherited-gate → ACCEPT+document or FIX to exact-match · DID:Nostr feeds agent matching only as `did:nostr:<hex>`, no `alsoKnownAs`→WebID resolution → **ACLs non-portable** with JSS (fail-closed) → ACCEPT+document or FINISH · **PATCH on `.acl` elevates to Control but skips the lockout guard** (`handle_put` runs it, `handle_patch` doesn't) — a Control holder can strip all principals' Control → FIX (unify the guard across POST/PATCH per P0-4).

---

## P3 — polish & accepted-scope (condensed)

PUT always 201 (never 204 + Location) · container members drop `stat:size`/`dcterms:modified` · HEAD reads full body · 401 challenge advertises DPoP/Bearer it can't process · DPoP `htu` lowercases the case-sensitive path · IdP `/token` DPoP omits jti replay cache (feature built, unused) → **FINISH (low effort)** · NIP-98 `u`-with-query rejected · NIP-05 no name-lowercasing · uppercase-hex pubkey 400 vs JSS-normalise · relay hex-case strictness differs · path-normalise `..` divergence · dead `MetaSidecar.links` channel · WebID `@type` omits `schema:Person` · no HTML registration UI · Actor omits `url`/`<p>`-summary · wired NodeInfo drops `localPosts`+metadata (unused richer duplicate exists → **consolidate**) · SSRF check-then-fetch DNS-TOCTOU (residual) · `to_jsonld` expanded not compacted · `application/json` not a JSON-LD alias.

**Confirmed-closed / net-positive over JSS (ACCEPT, no action):** NIP-98 single-use replay guard (prior P0 closed) · WS forged-identity P0 closed (Schnorr verified on EVENT ingest) · durable AP delivery+backoff+SSRF classification JSS lacks · deny-by-default + mode-implication (`Write`→`{Write,Append}`, `Control` isolated) correct at/above JSS · `.acl` **write** Control-elevation correct · ACL-lockout guard on **PUT** is a genuine improvement JSS lacks (but coverage incomplete — POST/PATCH bypass it, see P0-4/P1-r/WAC-P2) · mashlib data-browser at/above parity with added frame/CSP/no-store.
> **Correction from the WAC re-run:** the earlier "`acl:agentGroup` implemented (net-positive)" claim is **withdrawn** — the library implements it but the server wires an empty resolver at every call-site, so at runtime it is a no-op identical to JSS's TODO stub (see P1-r). This is the clearest single instance of the *library-present ≠ server-wired* thesis.

---

## Deliberate omissions — correctly scoped out (FREEZE + document)

These are **client-side / operator-tooling** surfaces with no server-port obligation. The only real gap is *documentation hygiene* — several are absent from **both** parity docs, and the verifier found that `crates/solid-pod-rs/docs/reference/jss-source-breadcrumbs.md:54,55,293` **already records `terminal` and `tunnel` as wontfix/out-of-scope** (parity tracking lives across two docs, not one — the `jss-only` analyst missed this).

| JSS surface | Classification | Action |
|-------------|----------------|--------|
| `terminal/` (WS remote shell, RCE-by-design) | Intentional non-goal | Already in breadcrumbs; add a PARITY row |
| `tunnel/` (decentralised-ngrok reverse proxy) | Operator/dev convenience, needs external WS transport | Already in breadcrumbs; add a PARITY row |
| `mashlib` SolidOS UI shell (`generateSolidosUiHtml`) | Client-side; also **dead code in JSS** (defined, never imported) | ACCEPT — row 110 already `wontfix-in-crate`; fix the stale `server.js:411` pointer |
| `ui/server-root.js` `seedServerRoot` (first-run landing + public-read root ACL) | DX nicety | ACCEPT or FINISH (small); the **one scope decision absent from both docs** |

---

## Parity-doc integrity

The doc-accuracy pass (which tested **library existence**, not server-wiring) returned a result that *corroborates the strategic finding from the opposite direction* — and the two are not in tension:

- **`PARITY-CHECKLIST.md` is accurate at the library level.** Every "present"/"net-new" claim sampled verified true; there is **no code overstatement** — when a row says "present," the crate code genuinely exists (the AP crate is 3,383 LOC and functional, idp 5,925, notifications/legacy.rs 1,034). The defect is that the checklist **does not distinguish `library-present` from `server-wired`**, so rows 74/76/79 (OIDC), 102–108 (AP), 27/91/99 (notifications), 113 (quota) read as *deployed parity* when the server does not wire them. **FIX-DOC: split every such row into `lib: done` / `server-wired: no`.** (This is what reconciles the checklist with the P0/P1 "unwired" findings above — both are true.)
- **`GAP-ANALYSIS.md` narrative (§C–I) is stale in the *opposite* direction — it UNDERSTATES shipped work.** §C.3/C.4/C.6/C.7, §E.2/E.3/E.6/E.7/E.8, §F.3, §H, §I call **ActivityPub, embedded IdP, Nostr-relay, solid-0.1 notifications, config-loader, passkeys, Schnorr SSO, SSRF/dotfile primitives, and subdomain tenancy** "missing / P1 port ticket / park until 0.5.0" — all shipped Sprint 10–11 and **contradict the same document's own §I bottom line** ("all five sibling crates are functional and shipping") and the checklist. A reader of the prose would conclude the port is far less complete than it is. **FIX-DOC: regenerate §C–H directly from the checklist statuses** and close the dead E.2/E.3/E.6/E.7/E.8 port tickets. (Highest single-leverage doc fix.)
- **`parity-check.sh` gate is looser than advertised.** Line 6/168 comments say "strict ≥ 95%" but line 177 is `threshold=90` — a regression to 90–94% still prints PASS. Live run is 189/197 = 95.9% PASS, so the defect is latent. Also stale: hardcoded "Sprint 12" label (docs at Sprint 16) and "180 rows" (parses 207). **FIX-DOC: set `threshold=95`; derive sprint/row labels.**
- **Citation drift (P3):** checklist §1–3 `src/ldp.rs` line anchors are off by 20–550 lines (symbols all exist; `ldp.rs` grew and citations weren't re-synced). Three disagreeing workspace test totals across the two docs (835 / 870+ / ~1,519). Row-numbering jumps 200→202 (`62b` compensates for absent 201). **FIX-DOC: cite symbols not lines; reconcile to one test-count source of truth.**

**Net:** the checklist is trustworthy *as a library ledger*; the GAP-ANALYSIS prose is a pre-Sprint-10 fossil that understates; and neither doc encodes the *deployed-vs-library* axis that this deep-dive shows is the real parity story. The closeout doc-fix is two-sided: **stop the checklist overstating *deployed* parity (add the server-wired column), and stop the narrative understating *library* parity (regenerate from statuses).**

---

## Recommended closeout decisions

**FIX FIRST — access-control breaks (block any deployment):**
**P0-3** `.acl` read-disclosure (`enforce_read_ctx` Control-elevation) · **P0-4** POST `.acl` injection + unify the lockout guard across POST/PATCH (with WAC-P2) · **P1-q** scope `acl:origin` to the granting rule.

**FINISH (bind existing, tested libraries — mostly plumbing, highest value/effort ratio):**
P0-1 AP wiring · P0-2 OIDC surface · P1-a conditional requests · P1-c OIDC/DPoP resource auth · P1-i notifications route+pump · P1-r agentGroup resolver · (P2) Range/206, subcontainer POST, 404 headers, IdP jti replay cache.

**FIX (correctness/security bugs in wired code — do before any release):**
P1-d owner ACL seeding · P1-k POST-Slug overwrite · P1-l `did/nostr` false binding · P1-m `alsoKnownAs` backlink · P1-n Vary/Cache-Control · P1-o/p PATCH RDF parsing · P2 `.meta.json` namespace poisoning · P2 `provision_pod` path clobber · P2 DPoP symmetric carve-out · P1-e/f/g/j WebID+AP discovery.

**FREEZE + relabel (honesty at closeout, near-zero code):**
Every "present"-but-unwired checklist row → `library-only, server wiring deferred`; `terminal`/`tunnel`/`seedServerRoot` → explicit out-of-scope rows.

**ACCEPT (keep as-is; several are net-positive over JSS):**
NIP-98 replay guard, WS Schnorr verification, AP delivery hardening, `acl:agentGroup`, ACL-lockout guard, mashlib hardening, MongoDB `/db` omission (documented).

**The single strategic instruction:** treat "does the *server* do it," not "does a *crate* do it," as the parity bar. On that bar the port is a strong library ~two focused wiring sprints away from a truthful, deployable parity claim.
