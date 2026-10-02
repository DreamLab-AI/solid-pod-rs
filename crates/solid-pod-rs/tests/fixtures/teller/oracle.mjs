// Oracle for the solid-pod-rs Web Ledger cache document: runs solidpayorg/teller 7c00cea's own ledger functions and
// prints the fixture `ledger-7c00cea.json`. Usage: node oracle.mjs <teller checkout>/lib/teller.mjs > ledger-7c00cea.json
import { createHash } from 'node:crypto';
const T = await import(process.argv[2]);
const hash = { sha256: (b) => new Uint8Array(createHash('sha256').update(b).digest()) };
const deps = { hash };
const operator = 'did:nostr:' + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const alice = 'did:nostr:' + '4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa';
const L = T.newLedger(deps, { operator, name: 'Pod Credits', currency: 'satoshi', created: 1759300000, confirmations: 1 });
const r1 = T.credit(L, { account: alice, txid: 'ab'.repeat(32), vout: 0, value: 50000, height: 152100 }, 1759300001);
const r2 = T.credit(L, { account: alice, txid: 'ab'.repeat(32), vout: 0, value: 50000 }, 1759300002);
const r3 = T.debit(L, { id: 'cd'.repeat(32), account: alice, amount: 20000, to: 'tb1pexample', txid: 'cd'.repeat(32) }, 1759300003);
T.checkLedger(deps, L);
console.log(JSON.stringify({
  teller: 'solidpayorg/teller 7c00cea lib/teller.mjs',
  genesisJcs: T.jcs(L.genesis),
  ledgerHash: T.ledgerHash(deps, L),
  results: { firstCredit: r1, secondCredit: r2, debit: r3 },
  balance: T.balance(L, alice),
  total: T.total(L),
  document: L,
}, null, 2));
