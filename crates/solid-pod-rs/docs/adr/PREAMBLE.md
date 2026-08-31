**How to work against this pack** (engineering/build-with-quality agents start here):

The ADR pack for this crate family is **its living governing document in
`docs/` plus the ledger records below that amend it**. The living doc is
normative — its *Invariants* section is the compliance surface and its *Change
process* section says how to amend it:

| Domain | Governing document |
|---|---|
| Auth (NIP-98), OIDC/DPoP, access control, provenance, multitenancy | [`../BASELINE-solid-pod-rs.md`](../BASELINE-solid-pod-rs.md) |

**Lookup order:** governing doc → its `file:line` citations into code → the
ledger records below → `docs/archive/adr/` **only for rationale and history —
never as authority** (the archive is the pre-2026-08-31 ADR-057…061 corpus,
frozen precisely because it drifted from the code; see
[`../archive/adr/README.md`](../archive/adr/README.md) for the legacy-record
redirect table).

**Making a decision:** copy [`TEMPLATE.md`](TEMPLATE.md) to `ADR-NNNN-slug.md`
(next free number), fill the three-axis status honestly, update the baseline
**in the same change**, and regenerate this index
(`node scripts/adr-index-gen.js crates/solid-pod-rs/docs/adr` — it fails CI on
invalid frontmatter).
