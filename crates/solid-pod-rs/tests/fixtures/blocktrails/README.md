# Blocktrails chained-key vectors (generated upstream)

`keys-walk-vectors.json` is the output of `gen-keys-walk-vectors.mjs` in this
directory, run over the upstream reference code, never over this crate:

- the rule: [blocktrails/spec](https://github.com/blocktrails/spec) `ef54a08`
  ("the rule as it is"), walked as
  [blocktrails/verify](https://github.com/blocktrails/verify) `043e7af` walks
  a trail (a string state hashes as its UTF-8 text, an object as its JCS);
- the arithmetic: [sidestr/spec](https://github.com/sidestr/spec) `e8deb63`
  `siding/lib/keys.mjs` and `siding/lib/address.mjs`;
- the curve: [bitcoin-desktop/schema](https://github.com/bitcoin-desktop/schema)
  `b8cbf63` `codec/hash.js` and `codec/secp256k1.js`.

The git-mark cases use the inputs of
[blocktrails/git-mark](https://github.com/blocktrails/git-mark) `b852d7d`
`test/gitmark.test.js` (the first three marks of the live trail, and the
swapped-commit refusal); their outputs equal the ones that test pins.

Regenerate:

```sh
SIDESTR_SIDING=<sidestr/spec checkout>/siding SCHEMA=<schema checkout> \
  node gen-keys-walk-vectors.mjs > keys-walk-vectors.json
```

Consumed by `tests/blocktrails_keys_walk.rs` (feature `mrc20`); with the same
two variables set, that test also runs the generator live and requires its
output to equal this file.

# Whole-trail verification vectors (generated upstream)

`verify-trail-vectors.json` is the output of `gen-verify-trail-vectors.mjs`,
which runs the reference code as published, never this crate:

- [blocktrails/verify](https://github.com/blocktrails/verify) `043e7af`
  `index.html`: both scripts lifted from the page and run under a stub DOM and
  a stub `fetch` (the pinned CDN imports pointed at local checkouts of the same
  commits). One display-only adaptation: the page's `short()` calls `.slice`
  on a mark's state, which throws for an object state, so its argument is
  passed through `String()`; no check or label depends on it. Recorded: each
  mark's label and spend link, the summary verdict and text, and the walk's
  expected outputs or error.
- [blocktrails/git-mark](https://github.com/blocktrails/git-mark) `b852d7d`
  `index.js` (after `npm ci`): `Gitmark.verify` on the live trail and on two
  commits swapped, `parseTxoUri` / `formatTxoUri`, `trail()` and the
  addresses on the `gitmark` (`gm`), `tbtc4` and `mainnet` networks.
- sidestr/spec `e8deb63` `keys.mjs` `taggedScalar` with its tagged hash
  replaced by the hash under test: `int(h) mod n` for `h` at and above n.

`live-trail-txs.json` holds the three transactions of git-mark's pinned live
marks, as mempool.space testnet4 `GET /api/tx/{txid}` returned them on
2026-10-02, so the generator needs no network.

Regenerate:

```sh
GIT_MARK=<git-mark checkout, npm ci done> VERIFY=<verify checkout> \
SIDESTR_SIDING=<sidestr/spec checkout>/siding SCHEMA=<schema checkout> \
  node gen-verify-trail-vectors.mjs > verify-trail-vectors.json
```

Consumed by `tests/blocktrails_verify_walk.rs` and the `mrc20` unit tests
(feature `mrc20`); with the four variables set, that test also runs the
generator live and requires its output to equal this file.
