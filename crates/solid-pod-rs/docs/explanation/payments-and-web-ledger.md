# Payments and the web ledger

Understanding-oriented. How does a pod charge sats for a read, hold a
balance, accept a deposit, and run a market — and why is the whole thing
built on HTTP 402 rather than a payment processor?

For the per-article gap analysis against Melvin Carvalho's *A Practical
Guide to Solid* see the
[Melvin practical guide reference](../reference/melvin-practical-guide.md);
for the inheritance matrix from JavaScriptSolidServer (JSS) see the
[provenance upgrade master plan](../design/provenance-upgrade-master-plan.md);
for the exact route surface see
[HTTP endpoints](../reference/http-endpoints.md).

## HTTP 402, finally used

`402 Payment Required` has sat reserved-but-undefined since HTTP/1.1. The
402 economy gives it a concrete meaning that fits Solid's grain: a
resource's access is gated by an `acl:PaymentCondition` in its WAC ACL,
and the unit of account is the **satoshi**. No card processor, no
account-with-us; the pod owner keyed by their `did:nostr`, the requester
keyed by theirs, a Bitcoin-settled balance between them. The money model
is fixed by PRD-015 v1.2: Lightning/L402/NWC + Bitcoin sats, **no EVM**.

As of `0.5.0-alpha.0` the entire economy is **routed** — the order book,
the AMM, the balance/deposit/withdraw surface, and the Bitcoin write-side
are all reachable over HTTP, where previously the logic was complete and
unit-tested in the library but orphaned (never mounted on a route).

## The Web Ledger

The ledger is `payments::WebLedger` — a JSON document persisted at
`/.well-known/webledgers/webledgers.json`, keyed by `did:nostr` URIs.
Each entry is a satoshi balance. The core operations are
`get_balance(did)`, `credit(did, amount)`, and `debit(did, amount)` (which
fails closed on an insufficient or missing balance). It is multi-chain
aware: deposits can arrive on any configured chain (`btc`, `tbtc3`,
`tbtc4`, `signet` — `payments::ChainConfig`), each carrying its mempool
URL, and the balance is denominated in sats.

### One ledger I/O path

A latent defect ADR-059 closed: the runtime used to read and write the
ledger through inline `Storage::get`/`put` calls, while a `PaymentStore`
trait sat orphaned beside it. The server now routes **all** ledger I/O
through a single implementation, `StoragePaymentStore` (an
`Arc<dyn Storage>`-backed `PaymentStore`). It is the sole reader/writer of
the ledger document and of the replay set — so there is one, auditable,
consistent ledger path for every `/pay/*` handler, the WAC charge path,
and the `_prov` anchor charge.

## Access gating — `acl:PaymentCondition`

Charging for a *read* is a WAC concern, not a payment-endpoint concern. An
`acl:PaymentCondition` (`wac::PaymentConditionBody`, a `cost_sats` field)
on an authorisation rule makes a granted access **consume** that cost. The
flow in the server's `enforce_read` / `enforce_write`:

1. Resolve the requesting principal's balance from the Web Ledger into the
   WAC `RequestContext` (`resolve_balance_sats`). An anonymous caller has
   `None` — so any non-zero `PaymentCondition` **fails closed** (402/403).
2. Evaluate the ACL. The `PaymentCondition` evaluator is satisfied only
   when `balance >= cost_sats`. A zero-cost condition is satisfied for any
   authenticated principal.
3. On a *granted* request whose authorising rule carried a non-zero cost,
   debit the caller's ledger by exactly that cost
   (`charge_granted_payment` → `debit_ledger`). The gate already proved
   `balance >= cost`; a debit failure can only mean a concurrent spend
   raced the balance below cost, so it **fails closed** — the request is
   never served unpaid.

`PaymentCondition` parsing fails closed on an unknown condition (a write
carrying an unrecognised `@type` is 422'd), and the `X-Balance` /
`X-Cost` / `X-Pay-Currency` response headers advertise the cost model.

## The routed surface

All routes are mounted unconditionally next to the always-on `/pay/.info`
discovery route (there is no payments feature flag). Every route except
`.info`, `.offers`, `.address`, and `.pool` (GET) requires NIP-98 auth and
resolves the caller to `did:nostr:<pubkey>`.

| Route | Method | What it does |
|---|---|---|
| `/pay/.info` | GET | Payment discovery (cost, chains, pay-token). |
| `/pay/.balance` | GET | The caller's Web-Ledger balance. |
| `/pay/.deposit` | POST | Credit a deposit — TXO **or** MRC20 (below). |
| `/pay/.address` | GET | Derive a (per-user tweaked) deposit address. |
| `/pay/.offers` | GET | List open sell orders (public; optional pair filter). |
| `/pay/.sell` | POST | Place a sell order (order book). |
| `/pay/.swap` | POST | Execute against an open order. |
| `/pay/.pool` | GET / POST | Read AMM pool state / run an AMM op. |
| `/pay/.buy` | POST | Primary market — buy the pod's pay-token with sats. |
| `/pay/.withdraw` | POST | Withdraw a sat balance as portable MRC20 tokens. |
| `/pay/.withdraw-sats` | POST | Withdraw sats as a fresh TXO voucher. |

### Deposits — TXO and MRC20

`POST /pay/.deposit` has two paths, discriminated by the body:

- **TXO** (a bare `"<txid>:<vout>"` string or `{"txo": …}`) — parse the
  TXO URI, replay-guard on `txid:vout`, credit, record the replay key.
- **MRC20** (`{"type":"mrc20", state, prevState, anchor}`) — verify a
  block-trail anchor. The handler derives the pod's deposit address from
  its issuer pubkey (`mrc20::bt_address`), replay-guards on the canonical
  `sha256(JCS(state))`, then runs `mrc20::verify_mrc20_anchor`, which
  composes the taproot crypto with a **live mempool UTXO lookup** via the
  native `MempoolHttpClient` (`JSS_PAY_MEMPOOL_URL`, default
  mempool.space testnet4). Only on a verified transfer is the amount
  credited. In tests an explicit `mempool_url` points at a local fixture
  server so CI never reaches mempool.space.

### Replay protection (now wired)

Replay protection (`check_replay` / `record_replay`) was *defined but
never called* before ADR-059 — a duplicate TXO or MRC20-state deposit
could double-credit. It is now wired into the deposit path through the
`StoragePaymentStore`: every credited deposit records a replay key (TXO
keyed `txid:vout`, MRC20 keyed `mrc20:<state-hash>` so the two namespaces
cannot collide), and a re-POST of the same output/state is rejected before
any credit.

### Per-user deposit addresses

`GET /pay/.address?user=<did>&chain=<id>` derives a deposit address by
tweaking the pod's issuer key with the user's DID
(`bt_address(issuer, [did], network)`), so funds sent there are
attributable to that user. It is public and returns only a derived address
plus the issuer pubkey — never a secret. (Whether to expose per-user
addresses publicly is an operator call: it creates a DID → on-chain
linkage.)

## The market — order book + constant-product AMM

Both trading surfaces are **live and routed** (not stubs, not removed).
They live in [`trading`](https://docs.rs/solid-pod-rs/latest/solid_pod_rs/trading/index.html)
and are richer than JSS's single-token model — every order and pool names
its currency pair explicitly.

- **Order book** (`trading::OrderBook`) — a peer-to-peer secondary market.
  `POST /pay/.sell` creates a currency-pair sell order (`create_order`);
  `GET /pay/.offers` lists open orders; `POST /pay/.swap` executes against
  an open order (`execute_swap`), moving balances atomically through the
  ledger. Orders persist at `/.well-known/webledgers/offers.json`.
- **AMM pool** (`trading::AmmPool`, `trading::Exchange`) — a
  constant-product (`x · y = k`) automated market maker.
  `POST /pay/.pool` runs `add-liquidity`, `remove-liquidity`, or `swap`
  (default fee `AmmPool::DEFAULT_FEE_BPS` = 30 bps); `GET /pay/.pool`
  returns a pool's reserves/shares or the whole registry. Pools persist at
  `/.well-known/webledgers/pool.json`.

Liquidity, swaps, and order fills all settle against the same Web Ledger
through the `StoragePaymentStore`, so a buy on the AMM and a paid read of a
resource debit the same balance.

## The Bitcoin write-side

`/pay/.buy`, `/pay/.withdraw`, and `/pay/.withdraw-sats` exercise the
Bitcoin write-side (`bitcoin_tx`, feature `mrc20`, non-wasm): P2TR output
construction, BIP-341 TapSighash, BIP-340 Schnorr signing — the
byte-for-byte JSS `token.js` port. `.buy` mints/transfers the pod's
pay-token to the buyer against their sat balance; `.withdraw` exports a
sat balance as portable MRC20 tokens with an independently-verifiable
proof; `.withdraw-sats` builds a fresh TXO voucher. In every case the
balance is debited **only after a successful broadcast** (fail-closed
ordering), and the new trail head is persisted via the server's
`trail_store`. The portable proof returned alongside a transfer is exactly
what a counterparty needs to verify the new taproot address against the
chain without trusting the pod — the same independent-verification
property described in
[Provenance and the trust ledger](provenance-and-trust-ledger.md).

## See also

- [Provenance and the trust ledger](provenance-and-trust-ledger.md) — the
  block-trail tier that shares this Bitcoin write-side.
- [Melvin practical guide](../reference/melvin-practical-guide.md) — the
  9-part 402 economy walkthrough mapped to modules.
- [Security model](security-model.md) — replay protection, WAC gating,
  and the auth the `/pay/*` routes sit behind.
- [HTTP endpoints](../reference/http-endpoints.md) — the route table.
- [Environment variables](../reference/env-vars.md) — `JSS_PAY_MEMPOOL_URL`
  and friends.
