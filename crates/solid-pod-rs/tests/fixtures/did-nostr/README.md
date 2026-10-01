# did:nostr conformance vectors (vendored)

`test-vectors-generated.json` is copied verbatim from
[nostrcg/did-nostr](https://github.com/nostrcg/did-nostr):

- Path: `test-vectors/test-vectors-generated.json`
- Repository commit: `4ea80d84d2afe3572b737ed8324a44617cbf2835` (merge of PR #145, 2026-10-01)
- File last changed upstream: `cfcda12d44a0ee32f3e071d9d1c976d24513b128`
- SHA-256: `b37ecdf0673ea0195f5960320f02bd6131c5ccc7a44ba4337ecb359f222ef45e`

Consumed by `tests/did_nostr_vectors.rs`. The `decode_even_parity` and
`decode_odd_parity` vectors pin the parity model reconciled in
[#145](https://github.com/nostrcg/did-nostr/pull/145) (closing
[#144](https://github.com/nostrcg/did-nostr/issues/144)): the identifier is the
x-only key, a resolver with only the identifier emits `0x02`, a document the
controller publishes may carry `0x03`, and verifiers accept both.

`error_odd_parity_in_bip340_decoder` describes a *strict BIP-340* decoder.
`parse_multibase_schnorr` is a general Multikey decoder and accepts `0x03`, as
the parity model requires; the test asserts that explicitly.

Refresh: re-copy the file from upstream, update the commit and SHA-256 above
and in the test-file header, and re-run `cargo test --features did-nostr-types`.
