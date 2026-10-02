// Generates verify-trail-vectors.json: what the upstream reference code says about whole trails, never
// what this crate says.
//
//   GIT_MARK=<blocktrails/git-mark b852d7d, npm ci done>  VERIFY=<blocktrails/verify 043e7af> \
//   SIDESTR_SIDING=<sidestr/spec e8deb63>/siding  SCHEMA=<bitcoin-desktop/schema b8cbf63> \
//     node gen-verify-trail-vectors.mjs > verify-trail-vectors.json
//
// Three oracles, each run as published:
//   - blocktrails/verify index.html: its two scripts are lifted out of the page verbatim and run under
//     a stub DOM and a stub fetch that serve the trail and the transactions below (one display-only
//     adaptation, see SHORT below); the pinned CDN imports are pointed at local checkouts of the same
//     commits. Every mark's label, the summary pill and the walk's expected outputs (or its error)
//     are recorded.
//   - blocktrails/git-mark index.js: Gitmark.verify on the live trail (and the swapped one),
//     formatTxoUri / parseTxoUri, trail() and the addresses of the gitmark (gm), tbtc4 and mainnet
//     networks.
//   - sidestr/spec keys.mjs taggedScalar: the mod-n reduction of a hash at or above the group order,
//     with the tagged hash replaced by the hash under test so the reduction itself is what is run.
// The live transactions are read from live-trail-txs.json (captured from mempool.space testnet4),
// so this script needs no network.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const { GIT_MARK, VERIFY, SIDESTR_SIDING: SIDING, SCHEMA } = process.env;
if (!GIT_MARK || !VERIFY || !SIDING || !SCHEMA) {
  console.error('set GIT_MARK, VERIFY, SIDESTR_SIDING and SCHEMA (see the header)');
  process.exit(2);
}
const here = dirname(fileURLToPath(import.meta.url));
const url = (p) => pathToFileURL(p).href;

const [hash, secp, { makeKeys }, GM] = await Promise.all([
  import(url(`${SCHEMA}/codec/hash.js`)),
  import(url(`${SCHEMA}/codec/secp256k1.js`)),
  import(url(`${SIDING}/lib/keys.mjs`)),
  import(url(`${GIT_MARK}/index.js`)),
]);
const utf8 = (t) => new TextEncoder().encode(t);
const jcs = (v) => v === null || typeof v !== 'object' ? JSON.stringify(v) : Array.isArray(v) ? '[' + v.map(jcs).join(',') + ']' : '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
const clone = (v) => JSON.parse(JSON.stringify(v));

// ---- 1. blocktrails/verify, run from its own page
const html = readFileSync(join(VERIFY, 'index.html'), 'utf8');
const moduleSrc = html.match(/<script type="module">([\s\S]*?)<\/script>/)[1]
  .replace(/const SCHEMA = '[^']*';/, `const SCHEMA = ${JSON.stringify(url(SCHEMA) + '/codec/')};`)
  .replace(/const KEYS = '[^']*';/, `const KEYS = ${JSON.stringify(url(`${SIDING}/lib/keys.mjs`))};`);
if (!moduleSrc.includes('file://')) throw new Error('the pinned imports were not found in index.html');
const classic = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
// One display-only adaptation: the page's short() calls .slice on a mark's state, which throws for an
// object state (a plain profile's), so the page renders nothing for such a trail. Its argument is
// passed through String(); no check, label or count depends on short().
const SHORT = "const short = s => s ? s.slice(0, 10) + '…' : '';";
const verifySrc = classic.find((s) => s.includes('async function verify('));
if (!verifySrc.includes(SHORT)) throw new Error('short() changed upstream: revisit the adaptation');
const verifyRun = verifySrc.replace(SHORT, "const short = s => s ? String(s).slice(0, 10) + '…' : '';");

function makeDom() {
  const byId = new Map();
  const el = () => {
    const subs = new Map();
    return { innerHTML: '', className: '', textContent: '', value: '', children: [], href: '',
      appendChild(c) { this.children.push(c); }, addEventListener() {},
      querySelector(sel) { if (!subs.has(sel)) subs.set(sel, el()); return subs.get(sel); } };
  };
  return {
    getElementById(id) { if (!byId.has(id)) byId.set(id, el()); return byId.get(id); },
    createElement: () => el(),
  };
}

const win = {};
new Function('window', moduleSrc)(win);
const keys = await win.__keys;

async function runVerify(trail, txs) {
  const document = makeDom();
  const fetch = async (u) => {
    if (u.endsWith('blocktrails.json')) return { ok: true, status: 200, json: async () => clone(trail) };
    const txid = u.split('/tx/')[1];
    if (txs[txid]) return { ok: true, status: 200, json: async () => clone(txs[txid]) };
    return { ok: false, status: 404, json: async () => { throw new SyntaxError('Unexpected token N in JSON'); } };
  };
  const history = { replaceState() {} };
  const location = { search: '' };
  const [verify, parseTxo] = new Function('document', 'history', 'location', 'fetch', 'window', 'URLSearchParams',
    `${verifyRun}\nreturn [verify, parseTxo];`)(document, history, location, fetch, win, URLSearchParams);
  await verify('https://example.org/trail/blocktrails.json');
  const marks = document.getElementById('marks').children.map((row) => ({
    label: row.querySelector('.stat').innerHTML.replace(/<[^>]+>/g, ''),
    cls: row.querySelector('.ix').className.replace('ix ', ''),
    linksToPrev: /links to prev ✓/.test(row.querySelector('.det').innerHTML) ? true : /chain link ✗/.test(row.querySelector('.det').innerHTML) ? false : null,
  }));
  const big = document.getElementById('bigstat').innerHTML;
  const pill = big.match(/<span class="pill \w+">([^<]+)<\/span>/)[1];
  let walk;
  try { const w = keys.walk(trail, (trail.txo || []).map(parseTxo)); walk = { expected: w.expected, profile: w.profile, baseNote: w.baseNote }; }
  catch (e) { walk = { error: e.message }; }
  return { marks, summary: { pill, text: big.replace(/<[^>]+>/g, '') }, walk };
}

// ---- the live trail: blocktrails/git-mark test/gitmark.test.js, its first three marks
const live = JSON.parse(readFileSync(join(here, 'live-trail-txs.json'), 'utf8'));
const liveTxs = Object.fromEntries(live.txs.map((t) => [t.txid, t]));
const GM_BASE = '0273c7f6cf0f135a63bc95a2e676bcf0a592c8b508fae8697e43f778c74e232b24';
const GM_COMMITS = ['9adc596cfd1100333393a12f2f41b2d820f16d0b', '4490c4c39e145915c59c0964b6dcd8dc720c9d2e', '699ee3a3ea9332cc9ec435acf8fd8cd07eecf940'];
const GM_TXIDS = live.txs.map((t) => t.txid);
const GM_AMOUNTS = live.txs.map((t) => t.vout[0].value);
const liveUris = GM_TXIDS.map((txid, i) => GM.formatTxoUri({ network: 'tbtc4', txid, vout: 0, amount: GM_AMOUNTS[i], commit: GM_COMMITS[i] }));
const liveTrail = { '@type': 'Blocktrail', version: '0.0.3', profile: 'gitmark', pubkeyBase: GM_BASE, chain: 'tbtc4', states: [...GM_COMMITS], txo: liveUris };

const cases = [];
async function verifyCase(name, note, trail, txs = liveTxs) {
  cases.push({ name, note, trail, txs: Object.values(txs), ...(await runVerify(trail, txs)) });
}
await verifyCase('live-trail', 'the live trail as blocktrails.json: every mark verified', liveTrail);
await verifyCase('live-trail-swapped-states', 'states 2 and 3 swapped: the head key is the same sum, mark 1 and 2 do not commit', { ...liveTrail, states: [GM_COMMITS[0], GM_COMMITS[2], GM_COMMITS[1]] });
await verifyCase('live-trail-states-from-txo', 'gitmark with no states: the commits are read from the TXO URIs', { ...liveTrail, states: [] });
await verifyCase('live-trail-bare-x-base', 'the base key as a bare x reads as the even-y point', { ...liveTrail, pubkeyBase: GM_BASE.slice(2) });
await verifyCase('live-trail-no-base', 'no base key: nothing to recompute from, so confirmed only', (({ pubkeyBase, ...t }) => t)(liveTrail));
await verifyCase('live-trail-amount-mismatch', 'mark 1 records an amount its output does not carry', { ...liveTrail, txo: liveUris.map((u, i) => (i === 1 ? u.replace('amount=999400', 'amount=999401') : u)) });
{
  const txs = clone(liveTxs); txs[GM_TXIDS[2]].status = { confirmed: false };
  await verifyCase('live-trail-head-unconfirmed', 'the head still in the mempool: pending', liveTrail, txs);
}
{
  const ghost = 'ee'.repeat(32);
  await verifyCase('live-trail-tx-missing', 'mark 2 names a transaction the chain does not have', { ...liveTrail, txo: liveUris.map((u, i) => (i === 2 ? u.replace(GM_TXIDS[2], ghost) : u)) });
}
{
  const txs = clone(liveTxs); txs[GM_TXIDS[1]].vin[0].txid = 'dd'.repeat(32);
  await verifyCase('live-trail-broken-link', 'mark 1 does not spend mark 0: the page shows "chain link ✗" but still labels the mark verified', liveTrail, txs);
}

// ---- plain profiles: object states hashed as JCS, string states as text, on a synthetic chain whose
// outputs are the ones the page's own walk expects
const genesis = { profile: 'mono.mrc20.v0.1', prev: '0'.repeat(64), seq: 0, ticker: 'TEST', name: 'Test Token', decimals: 0, supply: 1000, balances: { issuer: 1000 }, ops: [] };
const nested = { z: { b: [3, { y: 'é✓', x: null }], a: true }, a: -7, m: 'line\nbreak "quoted"' };
const plainStates = [genesis, 'plain text state', nested];
const plainBase = makeKeys({ hash, secp }).publicKey('b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef');
const plainTxids = plainStates.map((_, i) => hash.bytesToHex(hash.sha256(utf8(`synthetic mark ${i}`))));
const plainUris = plainTxids.map((txid, i) => `txo:tbtc4:${txid}:0?amount=${50000 - 300 * i}`);
const plainTrail = { '@type': 'Blocktrail', version: '0.0.3', profile: 'mono.mrc20.v0.1', pubkeyBase: plainBase, chain: 'tbtc4', states: plainStates, txo: plainUris };
const plainExpected = keys.walk(plainTrail, plainUris.map((u) => ({ txid: u.split(':')[2] }))).expected;
const plainTxs = Object.fromEntries(plainTxids.map((txid, i) => [txid, {
  txid,
  vin: [{ txid: i === 0 ? 'aa'.repeat(32) : plainTxids[i - 1], vout: 0 }],
  vout: [{ scriptpubkey: '5120' + plainExpected[i], value: 50000 - 300 * i }],
  status: { confirmed: true, block_height: 100000 + i },
}]));
await verifyCase('plain-object-and-text-states', 'an object state hashes as its JCS, a string state as its text', plainTrail, plainTxs);
await verifyCase('plain-object-given-as-its-jcs', 'the object state given as its JCS string commits to the same key', { ...plainTrail, states: [genesis, 'plain text state', jcs(nested)] }, plainTxs);
await verifyCase('plain-object-given-as-json-stringify', 'the object state given as JSON.stringify text (keys unsorted) is other text: mark 2 does not commit', { ...plainTrail, states: [genesis, 'plain text state', JSON.stringify(nested)] }, plainTxs);
await verifyCase('plain-no-profile', 'no profile reads as monochrome: states are still required', (({ profile, ...t }) => t)(plainTrail), plainTxs);

// ---- 2. blocktrails/git-mark
const gitMark = {};
{
  const r = GM.Gitmark.verify(liveUris, GM_BASE);
  gitMark.liveVerify = { uris: liveUris, base: GM_BASE, ...r };
  const swappedCommits = [GM_COMMITS[0], GM_COMMITS[2], GM_COMMITS[1]];
  const swappedUris = swappedCommits.map((c, i) => GM.formatTxoUri({ network: 'tbtc4', txid: 'ab'.repeat(32), vout: 0, amount: 1000, commit: c, pubkey: r.expected[i] }));
  gitMark.swappedVerify = { uris: swappedUris, base: GM_BASE, ...GM.Gitmark.verify(swappedUris, GM_BASE) };
  gitMark.liveGm = r.expected.map((x) => GM.encodeBech32m('gm', hash.hexToBytes(x)));
  gitMark.liveTb = r.expected.map((x) => GM.encodeBech32m('tb', hash.hexToBytes(x)));
}
{
  const TEST_PRIVKEY = 'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35';
  const TEST_TXID = '34cea31b10e809e7cef4e19ce6e681da22ba1d2ae723af110cbba191e854be0e';
  const COMMITS = ['0123456789abcdef0123456789abcdef01234567', 'cf97baba489e88c1ffbe6758c0fe8c18ff83d17d', 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2'];
  gitMark.networks = {};
  for (const network of ['gitmark', 'tbtc4', 'mainnet']) {
    const gm = new GM.Gitmark(TEST_PRIVKEY, network);
    gm.genesis(TEST_TXID, 0, 1000000, COMMITS[0]);
    gm.advance(COMMITS[1], 'a'.repeat(64), 0, 999000);
    gm.advance(COMMITS[2], 'b'.repeat(64), 1, 998000);
    gitMark.networks[network] = {
      pubkeyBase: GM.bytesToHex(gm.publicKeyBase),
      commits: COMMITS,
      addresses: COMMITS.map((_, i) => gm.addressAt(i)),
      outputs: gm.txos.map((t) => t.pubkey),
      trail: gm.trail(),
    };
  }
  gitMark.network_chain = GM.NETWORK_CHAIN;
}
gitMark.parse = [
  'txo:tbtc4:34cea31b10e809e7cef4e19ce6e681da22ba1d2ae723af110cbba191e854be0e:0?amount=1000000&pubkey=3e458cc6f434c2292b3a23c044f4b046d5726c5ddee91c85f920c16817a5c8cf&commit=cf97baba489e88c1ffbe6758c0fe8c18ff83d17d',
  'txo:tbtc4:34cea31b10e809e7cef4e19ce6e681da22ba1d2ae723af110cbba191e854be0e:2?amount=500000&commit=cf97baba489e88c1ffbe6758c0fe8c18ff83d17d',
  'txo:mainnet:51d87101b7cbb01cc5a68785bf3141ec6fd00894d71ab1168d4daa20420eeacf:1',
  'txo:gitmark:51d87101b7cbb01cc5a68785bf3141ec6fd00894d71ab1168d4daa20420eeacf:0?commit=9adc596cfd1100333393a12f2f41b2d820f16d0b&amount=999700',
].map((uri) => ({ uri, parsed: GM.parseTxoUri(uri), formatted: GM.formatTxoUri(GM.parseTxoUri(uri)) }));

// ---- 3. sidestr/spec keys.mjs: int(h) mod n, zero refused
const N = secp.N;
const hex32 = (n) => n.toString(16).padStart(64, '0');
const scalarModN = [N - 1n, N, N + 1n, N + 7n, N + (1n << 128n), (1n << 256n) - 1n, 1n, 0n].map((h) => {
  const H = hex32(h);
  const K = makeKeys({ hash: { ...hash, taggedHash: () => hash.hexToBytes(H) }, secp });
  try { return { hash: H, scalar: K.taggedScalar('TapTweak', '00') }; } catch (e) { return { hash: H, scalar: null, error: e.message }; }
});

process.stdout.write(JSON.stringify({
  source: {
    verify: 'blocktrails/verify 043e7af index.html, both scripts run as published under a stub DOM and fetch',
    gitMark: 'blocktrails/git-mark b852d7d index.js',
    keys: 'sidestr/spec e8deb63 siding/lib/keys.mjs on bitcoin-desktop/schema b8cbf63 codec/hash.js, codec/secp256k1.js',
    liveTxs: 'live-trail-txs.json: mempool.space testnet4 /api/tx for the three marks git-mark b852d7d pins',
    generator: 'gen-verify-trail-vectors.mjs (this directory)',
  },
  cases,
  gitMark,
  scalarModN,
}, null, 2) + '\n');
