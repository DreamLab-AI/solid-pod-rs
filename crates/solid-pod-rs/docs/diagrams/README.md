# solid-pod-rs — diagrams

The architecture and flow diagrams for this repository now live in the
estate's diagrams-as-code corpus in VisionFlow:

**<https://github.com/DreamLab-AI/VisionFlow/tree/main/docs/diagrams/solid-pod-rs>**

Each topic there (`SP-01` to `SP-15`) cites the code it was drawn from as
`path:line`, is stamped with the solid-pod-rs commit it was verified against,
and is checked and rendered by that corpus's generator. That replaces the nine
Mermaid sources, their rendered SVG/PNG outputs and the RES-c staleness guard
(`scripts/check-diagram-staleness.sh` and the `diagrams` CI job) that used to
sit here. All three were removed on 2026-11-23.

## Where each removed diagram is now shown

| Removed source | Now shown in |
|---|---|
| `src/01-architecture-overview.mmd` | `SP-01.3` core library module surface; `SP-02.11` and `SP-02.12` the server route table |
| `src/02-request-lifecycle.mmd` | `SP-03.3` PUT; `SP-04.1` the write gate, end to end; `SP-05.1` identity extraction and anonymous fallback |
| `src/03-wac-inheritance.mmd` | `SP-04.3` typed policy outcomes, only absence inherits; `SP-04.7` the decision loop; `SP-04.15` accessTo versus default |
| `src/04-ldp-containment.mmd` | `SP-03.15` what a container listing carries; `SP-03.11` Link headers; `SP-03.10` RDF content negotiation |
| `src/05-notifications-flow.mmd` | `SP-08.1` to `SP-08.3` the channels, the WebSocket pump and webhook retry with the circuit breaker; `SP-08.23` the change-notification envelope; `SP-08.19` what the reference server mounts |
| `src/06-oidc-dpop.mmd` | `SP-05.23` dynamic client registration; `SP-05.16` the IdP authorisation-code flow; `SP-05.7` and `SP-05.8` DPoP proof and access-token checks; `SP-12.2` what the server does not wire |
| `src/07-nip98-vs-oidc.mmd` | `SP-05.1` to `SP-05.3` NIP-98 and its match policies; `SP-05.8` the OIDC lane; `SP-12.2` |
| `src/08-storage-trait.mmd` | `SP-06.1` the Storage seam and its two shipped backends |
| `src/09-provenance-tiers.mmd` | `SP-07.1` the two provenance tiers; `SP-07.3` anchor policy; `SP-07.7` epoch batching; `SP-07.10` to `SP-07.12` the transaction builder, mempool and anchorer; `SP-07.6` the `_prov` queries |

The old sources had drifted from the code in places: Schnorr verification
described as optional, server-managed triples described as rendered on GET,
per-topic WebSocket filtering. The corpus topics record what the code does at
their stamped commit, so use them rather than the git history of this
directory.
