# Maintainers

solid-pod-rs is maintained by a small group with commit access, working in the open.
Decisions are recorded in issues and PRs.

## Current maintainers

| Maintainer | GitHub | Focus |
|---|---|---|
| John O'Hare | [@jjohare](https://github.com/jjohare) | Project lead; Rust implementation, DID:Nostr, native pod mesh |
| Melvin Carvalho | [@melvincarvalho](https://github.com/melvincarvalho) | Upstream IP; JSS specification, DID:Nostr, Solid protocol, Web Ledgers, identity standards |

## Upstream

solid-pod-rs is a Rust-native port of Melvin Carvalho's
[JavaScriptSolidServer (JSS)](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer) —
the AGPL-3.0 reference implementation of the Solid Protocol. JSS is the canonical source for
the feature set, protocol extensions (ActivityPub federation, git HTTP backend, HTTP 402 Web Ledgers,
DID:Nostr identity, passkey SSO), and conformance test surface. Protocol-level decisions and
spec alignment defer to the upstream JSS repository.

See [Melvin Carvalho's Practical Guide to Solid](https://melvin.me/public/solid/) for a 10-part
walkthrough of the JSS payment system and Solid architecture.

See [.github/CODEOWNERS](.github/CODEOWNERS) for path-level review routing.

## Process

Maintainers follow the same workflow as other contributors (issue → branch → PR → review → merge).

## Becoming a maintainer

By invitation of an existing maintainer, after demonstrated substantive
contribution. No formal vote; existing maintainers make the call and
update this file.

## Security

Security disclosures: use [GitHub private security advisories](https://github.com/DreamLab-AI/solid-pod-rs/security/advisories/new).
