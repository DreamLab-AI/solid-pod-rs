# Teller ledger oracle

`ledger-7c00cea.json` is produced by `oracle.mjs`, which imports
solidpayorg/teller at `7c00cea` (`lib/teller.mjs`, AGPL-3.0-or-later; not
vendored here, only its output) and runs teller's own `newLedger`, `credit`
(twice, same outpoint), `debit` and `checkLedger` with Node's `sha256`.

```sh
node oracle.mjs <teller checkout>/lib/teller.mjs > ledger-7c00cea.json
```

`../../teller_ledger_oracle.rs` checks that solid-pod-rs computes the same
ledger hash, `sha256(JCS(genesis))`, reads teller's cache document, and
applies the same receipts.

- teller `lib/teller.mjs` sha256: `ed6247756d3cf0084b9c04bd898a418ccba0772f0ebd43d1f03da260b27d79ec`
- expected ledger hash: `6edef538d26a824df5cad902ffd2d767639dddec256af206f4fafb2777cb78fe`
