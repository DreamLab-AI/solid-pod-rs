# JSS parity audit, 2026-11-01

**Comparators.** Upstream `JavaScriptSolidServer/JavaScriptSolidServer` `gh-pages` at
`7c9b0de` (package `0.0.224`, 2026-10-22), ten commits after the previous comparator
`8d68ceb`; and `JavaScriptSolidServer/plugins` at `63a16cb`, unchanged since the
2026-10-19 forge audit. Feature branches (`feature/*`) were out of scope.
**solid-pod-rs** at `e1d16ad`.

**Results** are in [`PARITY-CHECKLIST.md`](../../PARITY-CHECKLIST.md) §26 (the `0.0.224`
delta), §27 (pre-existing core gaps) and §28 (plugin system and plugins repository),
with the plugin-system decision in
[ADR-2011](../adr/ADR-2011-extensions-are-compile-time-crates-route-ownership-is-the-exemption.md).
This page records the method and the evidence behind those rows.

## Method

A ruflo mesh of Opus agents in a dedicated worktree, five analyst lanes and an
adversarial verifier per lane:

| Lane | Scope | Verifier verdict |
|---|---|---|
| 1 WAC | #631/#632: expanded JSON-LD ACL reads, refusal of ACLs that grant nothing | 4 confirmed (3 at runtime), 1 claim about JSS corrected; found the `POST /.pods` P0 and the library `provision_pod` absolute-IRI defect |
| 2 PATCH | #633: quad-based N3 Patch and SPARQL Update, Append for insert-only, serialisation, cross-process lock; the `turtle.js` `@graph` change | 8 of 9 confirmed at runtime, 1 adjusted (401, not 403), 0 refuted; 4 new defects |
| 3 Relay | #635 NIP-11 at the relay URL; commit-to-lane map of the whole delta | 5 confirmed, 4 adjusted, 0 refuted |
| 4 Plugin system | `src/plugins.js` contract (`activate(api)`) against our extension model | 5 confirmed, 1 downgraded (dotfile row: JSS also refuses, 404 vs our 403) |
| 5 Plugins inventory | all 41 directories of the plugins repository | 4 confirmed, 3 adjusted, 0 refuted |

Every row answers two questions: does the library have the behaviour, and does
`solid-pod-rs-server` serve it. The July 2026 closeout found the checklist had been
counting the first as parity; this audit counts only the second.

**Runtime evidence.** Verifiers built `solid-pod-rs-server` from `e1d16ad` and drove
it on localhost with hand-written Turtle ACLs, or drove `build_app` in-process on a
scratch copy. Reproduced at runtime:

- N3 Patch bodies using `@prefix` (JSS's own test bodies) get 400.
- 20 concurrent insert-only PATCHes all return 204; 3–4 of the 20 inserts survive
  (four rounds).
- A stale `If-Match` is ignored on PATCH (204) and PUT (201); `If-None-Match: *` overwrites.
- `é` sent in a PATCH is stored as `c3 83 c2 a9`; stored non-ASCII is re-mangled by every
  later PATCH to the resource.
- PUT `.acl` with `{not json`, `[]` or `text/plain` returns 201; the owner then gets 403
  on the resource, the `.acl`, and the repair PUT.
- An ACL with an absolute `acl:accessTo` is stored (201) and then locks the owner out.
- `POST /.pods {"name":"alice"}` returns 201; the owner then gets 403 on `GET /alice/`
  and on PUT into the pod.
- With `--features forge`: `GET /forge/<o>/<r>/raw/HEAD/.gitignore` returns 403; PUT under
  `/forge` returns 404 and writes nothing.

All other rows are code-read on both sides, with the file:line cited in the row.

**Evidence files** (in [`jss-parity-audit-2026-11-01/`](jss-parity-audit-2026-11-01/)):

| File | What it shows |
|---|---|
| `wac-probe-lane1.rs`, `wac-probe-lane1-output.txt` | The JSS #631 fixtures run through `build_app` (rows 265–268, 288) |
| `wac-probe-verify.rs`, `wac-probe-verify-output.txt` | The verifier's probe: unparseable-ACL lockout, absolute and relative `accessTo`, `POST /.pods`, library `provision_pod` (rows 266, 287, 288) |
| `patch-runtime-evidence.log` | Every curl request and status against the built server: N3 parsing, Append, `where`, concurrency, conditional writes, non-ASCII (rows 269–277, 286, 290, §27 defects) |
| `forge-dotfile-runtime.txt` | Dot segment and PUT under `/forge` with `--features forge` (rows 291, 297) |

The probes are kept as written by the audit and are not part of the test suite; they
need a scratch copy of the workspace to build. The checklist still trusts the
`present` rows the audit did not re-check: those were not re-audited for server
wiring, so the strict figure is an upper bound.

**Not established.** Behaviour of downstream consumers (VisionClaw, nostr-bbs) on the
library `provision_pod` defect; whether any storage backend maps `/x.acl` to `/x/.acl`;
the shutdown behaviour of the mirror (code-read only); whether the `/login`, `/logout`
and `api/accounts/recover` endpoints that `/.well-known/solid` advertises are routed
(they did not appear in the server's route table; not run). No JSS instance was run; JSS
behaviour comes from its source and its tests in the delta.

## Upstream observations

The audit noted two possible weaknesses in upstream JSS code, both code-read and neither
run. They are not detailed here; they are recorded for the maintainer to raise with
upstream directly. The checklist records only the invariant our own server must keep
(rows 280 and 297).

## Plugins repository: classification of all 41 directories

`PL/` is the plugins repository, `JSS/` the core repository, `LIB/` is
`crates/solid-pod-rs`, `SRV/` is `crates/solid-pod-rs-server`. Line numbers are at the
comparator commits above and at `e1d16ad`. The "proposed status" column is the inventory
lane's proposal; the adopted rows are in checklist §27 and §28.

### Summary counts (41 directories)

| Class | Count | Directories |
|---|---|---|
| (a) port or analogue of a JSS core feature | 11 | relay, webrtc, terminal, tunnel, notifications, pay, remotestorage, nip05, webfinger, activitypub, corsproxy |
| (b) net-new, exists only in the plugins repo | 28 | admin, backup, bluesky, caldav, capability, carddav, dashboard, didweb, gallery, gitscratch, globs, jmap, markets, mastodon, matrix, metrics, micropub, oembed, otp, recordweb, ripple, rss, s3, search, shortlink, sparql, turn, webdav |
| (c) forge, covered by §25 | 1 | forge |
| demo or scenario, not a plugin | 1 | federation-demo (no `plugin.js`, `PL/README.md` "a scenario, not a plugin") |

Demo-flavoured (b) entries: `globs` (a game match server), `gallery` ("demo-facing", `PL/gallery/README.md:2`), `markets` (play-money betting UI). `gitscratch` is a real plugin, not a scratch dir.

Of the 11 (a) entries, `PL/README.md` calls 7 "ports of bundled features" (relay, webrtc, terminal, tunnel, notifications, pay, remotestorage). It lists the other 4 (nip05, webfinger, activitypub, corsproxy) as "new features", but core ships each one too: `JSS/src/server.js` serves `nostr.json`, `JSS/src/ap/index.js:80` serves webfinger, `JSS/src/ap/` is ActivityPub, and `JSS/src/handlers/cors-proxy.js` is the CORS proxy. So I class them as core analogues.

### Full table

Columns: what it does (with a citation) · upstream maturity (plugin LoC excluding test.js, number of test call sites) · our equivalent · whether the server wires it · proposed status · priority.

### (a) Ports or analogues of core features

| Plugin | Core file it ports | What it does | Upstream maturity | Our equivalent (lib) | Server-wired? | Proposed status | Plugin-side improvement to note | Prio |
|---|---|---|---|---|---|---|---|---|
| relay | `JSS/src/nostr/relay.js` | NIP-01 relay: EVENT/REQ/CLOSE, replaceable, ephemeral, rate limit (`PL/relay/README.md:1-14`) | ✅ parity+, 241 LoC, 4 tests | `crates/solid-pod-rs-nostr/src/relay.rs:340`, `ws.rs:60` | **No**: not a server dep, no `/relay` route | row 101 stays present (lib); add a server-mount row, `missing` | JSONL persistence to the plugin dir, so it survives restarts (core holds events in memory) | P1 |
| webrtc | `JSS/src/webrtc/index.js` (`/.webrtc`) | WebRTC signalling: identity dialect (WebID/did:nostr) plus a content-addressed announce dialect (`PL/webrtc/README.md:1-25`) | ✅ full parity, 396 LoC, 7 tests | none | No | new row, `missing` | **Fixes core's auth race**: core attaches its message handler after `await`ing auth, so early messages are lost; the plugin buffers first and replays (`PL/webrtc/README.md:58-62`). Port the fixed shape. | P2 |
| terminal | `JSS/src/terminal/index.js` | WebSocket shell (`PL/terminal/README.md:1-5`) | ✅ parity+ hardened, 164 LoC, 5 tests | none (`SRV/src/hardened_git.rs:25` is unrelated) | No | new row, `explicitly-deferred` or `missing` | **Mandatory access control**: `activate()` throws without `allowAgents`/`token`, core's `public` escape hatch is dropped, the child env is minimal and the cwd is confined (`PL/terminal/README.md:28-40`) | P3 (remote shell; port only if the estate asks, and then with the plugin's model, never core's) |
| tunnel | `JSS/src/tunnel/index.js` (`/.tunnel`) | Reverse HTTP tunnel over WebSocket, a "decentralized ngrok" (`PL/tunnel/README.md:1-16`) | ✅ parity, 334 LoC, 10 tests | none; row 214 marks passthrough N/A | No | extend row 214, or a new row `not-applicable` (deployment layer) | One deviation: a single prefix forces the `{prefix}/connect` control path | P3 |
| notifications | `JSS/src/notifications/` | solid-0.1 `sub`/`ack`/`err`/`pub`/`unsub`, ancestor fan-out, status endpoint (`PL/notifications/README.md:1-18`) | ✅ parity, 185 LoC, 5 tests | `LIB/src/handlers/legacy_notifications.rs:99-241`, `LIB/src/notifications/legacy.rs` | **No** WebSocket route; `Updates-Via` still advertised (`SRV/src/lib.rs:1359`) | row 91 → `partial-parity` (not served); new server-mount row | The plugin's WAC goes over loopback; core and ours check WAC in-process, so this is no improvement for us | **P1** |
| pay | core pay mode (`JSS/src/handlers/pay.js`, `mrc20.js`) | Wall-report: pay changes the LDP pipeline, so it cannot be a plugin (`PL/pay/README.md:1-20`) | 📋 wall-report, 46 LoC, 1 test | `SRV/src/handlers/pay.rs`, routes `SRV/src/lib.rs:5256-5262` | Yes | covered by §18/§23; one row `present-by-absence` recording the "stays core" verdict | none | — |
| remotestorage | `JSS/src/remotestorage.js` (`/storage/:user/*`, always-on) | remoteStorage draft-22 server, documents as pod resources (`PL/remotestorage/README.md:1-10`) | ✅ parity, 420 LoC, 15 tests | none | No | new row, `missing` | Fully WAC-governed over loopback (core imports `storage/filesystem.js` + `auth/token.js`, `PL/remotestorage/README.md:156-164`) | P2 |
| nip05 | `JSS/src/server.js` (`nostr.json`, v0.0.190) | `/.well-known/nostr.json` aggregated from public-profile Nostr keys (`PL/nip05/README.md:1-25`) | 215 LoC, 7 tests | `LIB/src/interop.rs:147,165`; `SRV/src/lib.rs:2486` | Yes (`nip05-endpoint`, default-off) | `present` (rows 128, 197) | Optional `relays` block (`relayUrl`) and a single-user `rootName`; check whether row 197 emits `relays` (UNVERIFIED) | P2 (delta check only) |
| webfinger | `JSS/src/ap/index.js:80` (only with AP on) | RFC 7033 for every pod, always-on, `acct:` → actor/profile/issuer (`PL/webfinger/README.md:1-20`) | 209 LoC, 5 tests | `LIB/src/interop.rs:104` | Yes, always-on (`SRV/src/lib.rs:5210`) | `present` (row 105) | The plugin adds an issuer link and an actor `self` template; diff the JRD links against ours (UNVERIFIED) | P2 (delta check) |
| activitypub | `JSS/src/ap/` (the plugin reimplements it, imports nothing) | Pod as an AS2 actor: actor with RSA key, outbox Note, inbox Follow/Create/Like, signed delivery (`PL/activitypub/README.md:1-16`) | 675 LoC, 20 tests | `crates/solid-pod-rs-activitypub/src/{actor,inbox,outbox,delivery}.rs` | **Actor only** (`SRV/src/lib.rs:1456`); inbox/outbox unrouted | rows 103/104/174 → note "library-only"; new server-mount row `missing` | Outbox stored *in the pod over loopback LDP under WAC*, where core uses an SQLite side store | P1 |
| corsproxy | `JSS/src/handlers/cors-proxy.js` (#379) | Forward proxy with permissive CORS, fail-closed SSRF (`PL/corsproxy/README.md:1-20`) | 388 LoC, 13 tests | `SRV/src/lib.rs:3272` `handle_proxy` | Yes (`/proxy`) | `present` (existing proxy rows) | `allowHosts` allowlist, `maxRedirects`, and zero-record DNS refused fail-closed (`PL/corsproxy/README.md:20-24,79`); compare with our SSRF guard (UNVERIFIED) | P2 (delta check) |

### (b) Net-new capabilities (plugins repo only)

| Plugin | What it does (citation) | Upstream maturity | Our equivalent | Server-wired? | Proposed status | Prio + rationale |
|---|---|---|---|---|---|---|
| admin | wp-admin-style operator page: server, plugins, pods (`PL/admin/README.md:1-8`) | 611 LoC, 10 tests | `/_admin/provision` only (`SRV/src/lib.rs:5279`) | n/a | out-of-scope | P3: depends on the Node plugin registry; our ops surface is different |
| backup | Container → `.tar.gz` download of everything the caller can read (`PL/backup/README.md:1-7`) | 342 LoC, 7 tests | `LIB/src/export.rs:179` `export_pod_jsonld` (JSON-LD, `export-jsonld`) | Yes, `/api/exports/all` behind a feature | consider | P2: data portability matters, and our JSON-LD export covers most of it; tar would be additive |
| bluesky | AT-Protocol XRPC shim, personal author feed in the pod (`PL/bluesky/README.md:1-7`) | 437 LoC, 11 tests | none | — | out-of-scope | P3: not part of the estate's protocol set (Nostr/AP) |
| caldav | CalDAV over a pod (`PL/caldav/README.md:1-7`) | 793 LoC, 23 tests | none | — | out-of-scope | P3: DAV family, no estate consumer |
| capability | Macaroon-lite scoped, time-bound, revocable capability URLs, #506 (`PL/capability/README.md:1-8`) | 315 LoC, 9 tests | none for pods; the forge has a macaroon-lite push token (`crates/solid-pod-rs-forge/src/token.rs`) | — | consider | P2: real auth design, but core has no layer yet, so track #506 upstream before porting; must use an established format (biscuit/macaroon crate), never a bespoke token |
| carddav | CardDAV over a pod, #157 (`PL/carddav/README.md:1-7`) | 536 LoC, 16 tests | none | — | out-of-scope | P3: DAV family |
| dashboard | Plugin status page with loopback probes (`PL/dashboard/README.md:1-7`) | 272 LoC, 8 tests | none | — | out-of-scope | P3: a consumer of the Node registry seam (#610) |
| didweb | `did:web` resolver for host and per-user `did.json` (`PL/didweb/README.md:1-15`) | 405 LoC, 7 tests | none: we serve `did:nostr` (`SRV/src/lib.rs:5225`) and `did:key` (`crates/solid-pod-rs-didkey`) | — | consider | **P2**: cheap, identity-adjacent, and complements did:nostr in the LWS/CID verifier family |
| gallery | Media gallery; first `api.mountApp` consumer, streamed uploads (`PL/gallery/README.md:1-7`) | 520 LoC, 11 tests | none | — | out-of-scope (demo) | P3: a demo UI |
| gitscratch | Push-to-create, TTL-expiring Solid-authed git remotes, #322 (`PL/gitscratch/README.md:1-4`) | 318 LoC, 8 tests | `crates/solid-pod-rs-git` (clone/fetch only; push refused, ER-28, `SRV/src/lib.rs` git block) | — | out-of-scope | P3: conflicts with the ER-28 owner decision (no pod-lane push); the forge covers hosting |
| globs | NEONGLOBS game match server, ELO (`PL/globs/README.md:1-4`) | 686 LoC, 5 tests | none | — | out-of-scope (demo) | P3 |
| jmap | JMAP mail over pod JSON messages (`PL/jmap/README.md:1-6`) | 642 LoC, 17 tests | none | — | out-of-scope | P3 |
| markets | LMSR prediction markets, journal ledger, disputes, WebSocket prices (`PL/markets/README.md:1-6`) | 6,362 LoC (69 files), 78 tests | `LIB/src/trading.rs:1-15`: order book + constant-product AMM, which is a different mechanism (no LMSR) | `/pay/*` (trading) | consider | P2: payments-adjacent and the second largest plugin, but play money. Overlap with our Web-Ledger trading is conceptual, not parity |
| mastodon | Mastodon-API shim, Phanpy-grade, local-only (`PL/mastodon/README.md:1-7`) | 1,348 LoC, 27 tests | none | — | out-of-scope | P3: big surface, client-compat shim; AP federation comes first |
| matrix | Matrix C-S shim, room as a pod resource (`PL/matrix/README.md:1-7`) | 426 LoC, 12 tests | none | — | out-of-scope | P3 |
| metrics | `/healthz` + Prometheus text exporter (`PL/metrics/README.md:1-5`) | 180 LoC, 7 tests | `LIB/src/metrics.rs:26` `SecurityMetrics` (atomics; Prometheus export deliberately left out, `:1-7`); no `/healthz` route | No | consider | **P2**: operationally cheap and useful to estate deployments; small |
| micropub | IndieWeb Micropub, posts land in the author's pod (`PL/micropub/README.md:1-7`) | 317 LoC, 11 tests | none | — | out-of-scope | P3 |
| oembed | oEmbed provider for pod resources, WAC as caller, XSS-refusing (`PL/oembed/README.md:1-5`) | 330 LoC, 15 tests | none | — | out-of-scope | P3 |
| otp | OTP challenge/verify/session, #505 (`PL/otp/README.md:1-7`) | 337 LoC, 8 tests | none | — | consider | P2/P3: auth-adjacent, but upstream notes account recovery needs core auth; wait for core |
| recordweb | RecordWeb (RWP) node: `did:rwp`, content-addressed version DAG (RFC 8785 + SHA-256 + Ed25519), Merkle cases (`PL/README.md` table) | 723 LoC, 19 tests | none | — | out-of-scope | P3: third-party W3C CG draft, no estate consumer |
| ripple | Fugger-classic trustlines, BFS credit routing, hash-chained log (`PL/ripple/README.md:1-6`) | 958 LoC, 15 tests | none (`LIB/src/payments.rs` is Web Ledger) | — | consider | P3: payments-adjacent but speculative (webcontracts#4) |
| rss | Container → Atom/RSS feed (`PL/rss/README.md:1-4`) | 367 LoC, 8 tests | none | — | out-of-scope | P3 |
| s3 | S3 SigV4 path-style gateway over the pod (`PL/s3/README.md:1-6`) | 618 LoC, 16 tests | none (`s3` hits in LIB are storage-backend references) | — | out-of-scope | P3 |
| search | TF-IDF full-text search over a container (`PL/search/README.md:1-6`) | 591 LoC, 11 tests | none for pods (`crates/solid-pod-rs-forge/src/search.rs` is git grep of repos) | — | consider | P2/P3: agent-useful, but would compete with the estate's RuVector search |
| shortlink | Local-only pod URL shortener, not an open redirector (`PL/shortlink/README.md:1-5`) | 273 LoC, 16 tests | none | — | out-of-scope | P3 |
| sparql | SPARQL SELECT + ground UPDATE over pod JSON-LD, #509 (`PL/sparql/README.md:1-7`) | 1,059 LoC, 21 tests | SPARQL *Update PATCH* only: `LIB/src/ldp.rs:1276` `apply_sparql_patch` (spargebra); no query endpoint | PATCH yes; `/sparql` no | consider | **P2**: we already carry spargebra, so a WAC-filtered SELECT endpoint is a moderate step; it makes pods queryable for agents |
| turn | TURN REST time-limited credentials for coturn (`PL/turn/README.md:1-6`) | 73 LoC, 7 tests | none | — | consider (bundle with webrtc) | P3, rising to P2 if webrtc is ported: tiny HMAC-SHA1 per the draft; use the `hmac`/`sha1` crates |
| webdav | WebDAV ↔ LDP bridge, mount a pod in Finder (`PL/webdav/README.md:1-7`) | 341 LoC, 13 tests | none | — | out-of-scope | P3: no estate consumer; DAV family as a unit |

### (c) and demo

| Plugin | Class | Note |
|---|---|---|
| forge | (c) | Covered by §25 (rows 236-264); bounded by ADR-2009. Not redone here. |
| federation-demo | demo/scenario | Two JSS instances federating via webfinger + activitypub over loopback (`PL/federation-demo/README.md:1-6`), 486 LoC, 9 tests. It would make a good *acceptance scenario* for our AP server-mount work, not a parity row. |

