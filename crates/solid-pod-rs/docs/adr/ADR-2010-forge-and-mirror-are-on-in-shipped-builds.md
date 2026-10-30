---
id: ADR-2010
title: The forge and the kind-30618 mirror are on in shipped builds; anchoring, open edit and the mainnet stay opt-in
date: 2026-10-20
decision_status: accepted
implementation_status: complete
activation_status: staged
supersedes: []
superseded_by: []
verified_commit: 76ab7aa
verified_paths: [crates/solid-pod-rs-server/Cargo.toml, crates/solid-pod-rs-server/src/lib.rs, crates/solid-pod-rs-server/src/main.rs, crates/solid-pod-rs-forge/src/mirror.rs]
owner: jjohare
review_trigger: activation event — a solid-pod-rs-server process observed holding a mirror relay session for a configured follow entry; the first release that carries these crates (fired at 0.5.0-alpha.17, 2026-10-20); a consumer build that sets `forge-full`; any change to `open_edit`, `allow_mainnet` or the mirror follow list defaults; JSS `plugins/forge` moving its contract
repo: solid-pod-rs
domain: BASELINE-solid-pod-rs.md
lineage: "Amends ADR-2009 (default-off mirror, accepted risks) and baseline invariant 8 (mirror opt-in). Implements the solid-pod-rs half of VisionFlow ADR-2019. Builds on ADR-2004 (provenance opt-in) and ADR-2008."
---

# ADR-2010 — The forge and the kind-30618 mirror are on in shipped builds; anchoring, open edit and the mainnet stay opt-in

## Context

- ADR-2009 shipped the mirror default-off and unwired, and accepted four risks on that basis: DNS rebinding, no fetch size cap, a stalling relay loop, and a push race. Baseline invariant 8 said the mirror stays opt-in.
- The owner decided on 2026-10-19 that consumers of this workspace ship with the forge and the mirror switched on, and that the Rust crates cover the JSS `plugins/forge` feature set. That is a change of default, so it is recorded here and not left to a config edit.
- Since ADR-2009 the forge crate gained the rest of the plugin: JSON API, labels, search, releases, private repositories, forks, compare, pull requests and real merges, forge-held Blocktrails trails, the NIP-34 builder, signer and publisher, web-edit and the ephemeral preview (ledger rows 245 to 264).
- An independent security review of that work (`secreview-wave1`) found one high, four medium and eight low issues. All are fixed except the CSP residual and the dependency audit, which was not run (`cargo audit` is not installed in the build container).

## Decision

- `solid-pod-rs-server` gains `forge-mirror` and `forge-full` (forge, anchoring, announce, mirror). Consumers that run the forge build with `forge-full`. The cargo defaults of the crates do not change: a library user who depends on `solid-pod-rs-forge` still gets nothing optional unless they ask.
- "On" means compiled in and started at boot (`start_forge`). It does not mean it acts on anything. The mirror follows nothing until `FORGE_MIRROR_RELAYS` and `FORGE_MIRROR_FOLLOW` name relays and `<pubkey>/<repo>` entries; the shipped default follow list is the operator's own key and nothing external.
- Staying opt-in, each with an explicit setting:
  - `open_edit` (`FORGE_OPEN_EDIT`). JSS `openEdit` skips authorisation, so any caller may edit any repository. No shipped default sets it, and the forge logs a warning at boot when it is on.
  - `allow_mainnet` (`FORGE_ALLOW_MAINNET`). The default chain is `txbt4`. The forge never broadcasts or spends: it derives addresses and records transaction outputs a funded client posts.
  - `private_repos`, `anchoring_ui` and `sparse_marks`.
  - Relays the mirror and announce talk to. A loopback or private-network relay is admitted only when the operator lists it (`OperatorRelays`); every other host goes through the workspace SSRF policy.
- The residual risks of ADR-2009 are closed, so they no longer justify default-off: DNS is pinned to the SSRF-approved address (git 2.37+), remote clone URLs are normalised and stripped of userinfo and ambiguity, a repository over 512 MiB is killed with its process group, signature checks run after the cheap filters, events go through a bounded per-repository queue so a slow fetch cannot stall a relay socket, failures back off, and a push to a mirrored repository is refused. The review's own fixes are in (key binding of the trail, reachability, replay and far-future states, hidden `refs/mirror`).
- Baseline invariant 8 is reworded: the mirror is on in shipped builds but fails closed. Its guards (validated refs and URLs, argv not shell, http and https only for remote clones, the SSRF check with address pinning, the size cap, and a branch moving only to a commit the fetch brought whose committed trail carries the followed key and lists the marked commit) are the invariant.

## Consequences

- Egress now exists in a default build: the mirror opens relay sockets and runs `git fetch` when configured, and announce publishes to configured relays. Both are inert without configuration.
- Enabling a consumer is still a deployment act: agentbox needs the server built with `forge-full` and its `FORGE_*` settings; VisionClaw does not run this server (it embeds the library behind its own `/solid` handler) and needs a `/forge` adapter before it can host the forge at all.
- Residual risks, accepted: the CSP for the vendored login widget keeps `'unsafe-inline'` and `esm.sh`, because the widget needs both (pages without the widget get a nonce policy); an anonymous compare can still ask the forge to fetch a same-named repository from an owner the base repository already has a pull request with, which needs edge rate limiting; the dependency audit is outstanding.
- Superseded by this record: the default-off clauses of ADR-2009 and baseline invariant 8's "stays opt-in" wording. ADR-2009's analysis stands.

## Verification

Status is partial and inactive: the code is merged but unreleased, and no consumer builds it. Verified at `8dd5dc1`: `cargo test --workspace` and `--all-features`, `cargo clippy --all-targets --all-features -D warnings`, `cargo doc -Dwarnings` and `scripts/parity-check.sh` (the full gate output is recorded in the release commit). The mirror hardening and review fixes each have a failing-then-passing test named in the commit messages.

## Close-out 2026-10-30

`accepted / partial / inactive` → `accepted / complete / staged`, verified at `origin/main` `76ab7aa`. The Verification section gave two reasons for `partial / inactive`: the code was unreleased and no consumer built it. Both are now resolved:

- Released: the crates.io API lists `solid-pod-rs-forge` 0.5.0-alpha.17 (2026-10-20) and 0.5.0-alpha.18 (2026-10-29). `cargo search solid-pod-rs-server` → `0.5.0-alpha.18`. The published `solid-pod-rs-server` 0.5.0-alpha.18 features include `forge-full = [forge, forge-anchoring, forge-announce, forge-mirror]` (also in `crates/solid-pod-rs-server/Cargo.toml:170-172`).
- Built by a consumer: agentbox `flake.nix:1547` adds `forge-full` unless the forge is disabled. The running `solid-pod` service (supervisor, pid 450) executes `/nix/store/3ykjqn74…-solid-pod-rs-server-0.5.0-alpha.18`. Its binary contains the mirror-gated strings `is a mirror and read-only` and `refs/mirror`, and it runs with `FORGE_OPEN_EDIT=0`, `FORGE_ALLOW_MAINNET=0` and `FORGE_CHAIN=txbt4`, which are the opt-in defaults this record requires.
- Started at boot: `start_forge` (`crates/solid-pod-rs-server/src/lib.rs:5044`, called from `main.rs:460`). `GET http://127.0.0.1:8484/forge/api/repos` → `200 {"repos":[]}`.
- Dependency audit: the RustCrypto 0.14 migration `84bf9f5` cleared RUSTSEC-2026-0386/0387/0391/0395–0403. `cargo audit` was not re-run for this note.

Activation stays `staged`. No mirror relay session from `solid-pod-rs-server` was observed: the only established `127.0.0.1:7777` connection is between `nostr-pod-bridge` and `node`. The cause is configuration, not a start defect: the running process's `FORGE_MIRROR_FOLLOW` holds no entries (0 matching `^[0-9a-f]{64}/`), and `mirror_config` (`crates/solid-pod-rs-server/src/lib.rs:4964-4985`) keeps the mirror off unless at least one relay and one valid follow entry are present. The public `https://pods-native.dreamlab-ai.com/forge` did not answer (curl status 000). `review_trigger` now names the observable event that would move this record to `live`.
