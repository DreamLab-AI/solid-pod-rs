# ARCHIVED — ADR (solid-pod-rs)

**Frozen:** 2026-08-31. **Do not add or edit records here.**

These ADR records (ADR-057 … ADR-061) drifted from the code and were retired in
the archive cut of 2026-08-31. They are kept read-only for history and to
resolve inbound cross-references.

The living decision surface is **`../../BASELINE-solid-pod-rs.md`** — the
architecture baseline for the crate family (auth, OIDC, access control,
provenance, multitenancy). Read it before trusting anything below: where a
record here disagrees with the baseline, the baseline (grounded in code at a
stated `verified_commit`) wins.

New decisions go in `../../adr/` using `../../adr/TEMPLATE.md`; the index and
routing prose live at `../../adr/README.md` (generated) and
`../../adr/PREAMBLE.md`. The cut itself is recorded as
`../../adr/ADR-2001-corpus-consolidation.md`.

## Archived records

| Legacy | Title | Superseding surface |
|--------|-------|---------------------|
| ADR-057 | LWS10 OIDC delta | BASELINE §OIDC/DPoP, divergence 1 (delta unshipped) |
| ADR-058 | JSS v0.0.60–v0.0.71 feature drift | BASELINE §Access control, divergence 2 (gaps closed) |
| ADR-059 | Block-trails & git-marks provenance primitives | BASELINE §Provenance, divergences 3–4 |
| ADR-060 | Gap-close sprint decisions | BASELINE §Provenance/PATCH/NIP-98, divergences 4–5, 7 |
| ADR-061 | LAN Bitcoin node substrate | BASELINE §Provenance, divergence 6 |
