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
