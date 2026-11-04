| Date | Deep | Finding | Issue | PR | Evaluated? | Verdict | Effect | Witness | Prior-night fates |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-08-15 | storage-backend | Given a Solid Pod resource stored in Turtle, when GET with Accept: ld+json / n-triples is issued, then re-serialisation should preserve all triples | NONE | NONE | blocked | INCONCLUSIVE | no candidate produced (single-call mode, no FS) | d7bc08a5 | first HP annexe live cycle |
| 2026-08-15 | provenance-api | ** process finding — nightly harness supplied no clock, no commit, no repo mount | NONE | NONE | yes | INCONCLUSIVE |  | 1f0c35e0 |  |
| 2026-08-15 | wac-evaluator | Given a resource R with no co-located ACL, when an intermediate ancestor contain | NONE | NONE | yes | INCONCLUSIVE |  | 7f3eecee04df |  |
| 2026-08-16 | storage-backend | Given a Solid Pod resource stored as Turtle in the storage backend, when a GET i | NONE | NONE | yes | INCONCLUSIVE |  | c2e0e8e1fd74 |  |
| 2026-08-16 | storage-backend | Given a Solid Pod resource stored as Turtle in the storage backend, when a GET i | NONE | NONE | yes | INCONCLUSIVE |  | e817f4c74074 |  |
| 2026-10-24 | performance-hardening | SubdomainResolver::resolve drops 3 per-request allocs; outputs identical | NONE | https://github.com/DreamLab-AI/solid-pod-rs/pull/7 | yes | ACCEPT |  | 13246d3c542c |  |  |  |
| 2026-10-25 | wac-evaluator | No WAC/ACL source supplied; ancestor-ACL-walk deny-termination untestable | NONE | NONE | yes | INCONCLUSIVE |  | f3b688ccbe22 |  |  |  |
| 2026-10-26 | storage-backend | Slug "." slipped resolve_slug; bare-dot POST now 400, dotted names unaffected | NONE | https://github.com/DreamLab-AI/solid-pod-rs/pull/8 | yes | ACCEPT |  | cfaac782b751 |  |  |  |
| 2026-10-28 | did-nostr-resolver | did:nostr text scan bound 64-hex prefix of 65+ runs; boundary check added | NONE | https://github.com/DreamLab-AI/solid-pod-rs/pull/9 | yes | ACCEPT |  | 3e336486be88 |  |  |  |
| 2026-10-29 | performance-hardening | rate-limit key canonical 2→1 allocs/check; byte format pinned by test | NONE | https://github.com/DreamLab-AI/solid-pod-rs/pull/10 | yes | ACCEPT |  | cd2a990fd145 |  |  |  |
| 2026-10-30 | wac-evaluator | lib.rs locates WAC evaluator at root src/wac mod; wac.rs/mod.rs not supplied | NONE | NONE | yes | INCONCLUSIVE |  | 8bcc9de5bc02 |  |  |  |
| 2026-10-31 | storage-backend | In-memory backend accepted ../ and NUL paths; normalize now rejects like FS | NONE | https://github.com/DreamLab-AI/solid-pod-rs/pull/12 | yes | ACCEPT |  | 86db8980e19d |  |  |  |
| 2026-11-01 | storage-backend | VETOED: Criterion bench added for SubdomainResolver::resolve per 2026-10-24… | NONE | NONE | yes | REJECT |  | beeb15c1a6ad |  |  |  |
| 2026-11-02 | provenance-api | no acceptance claimed (model verdict INCONCLUSIVE) | NONE | NONE | yes | INCONCLUSIVE |  | f88f742e8fa9 |  |  |  |
| 2026-11-03 | did-nostr-resolver | red bench: link_headers acl /container.acl vs /container/.acl; need ldp module | NONE | NONE | yes | INCONCLUSIVE |  | b26428b24cec |  |  |  |
| 2026-11-04 | performance-hardening | quota pod_lock drops warm-path key String alloc; Arc+map reuse pinned by test | NONE | https://github.com/DreamLab-AI/solid-pod-rs/pull/13 | yes | ACCEPT |  | 76d92c8fb7ea |  |  |  |
