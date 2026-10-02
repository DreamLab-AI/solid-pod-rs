// Generates keys-walk-vectors.json: the Blocktrails chained-key walk ("the rule as it is",
// blocktrails/spec ef54a08) computed by the upstream reference code, never by this crate.
//
//   SIDESTR_SIDING=<sidestr/spec e8deb63>/siding  SCHEMA=<bitcoin-desktop/schema b8cbf63> \
//     node gen-keys-walk-vectors.mjs > keys-walk-vectors.json
//
// The arithmetic is sidestr/spec siding/lib/keys.mjs on the schema engine's curve code
// (codec/hash.js, codec/secp256k1.js), the pair blocktrails/verify 043e7af pins; addresses are
// siding/lib/address.mjs. The walk is the one blocktrails/verify runs:
//   P = basePoint(base); for each state: P = tweakPoint(P, tapTweak(P, stateHash(state)))
// where stateHash is sha256 of a string state's UTF-8 text, or of an object state's JCS.
// Secrets: d (or normalize(d) when the base is a bare x) plus each step's tweak, mod n.
const SIDING = process.env.SIDESTR_SIDING;
const SCHEMA = process.env.SCHEMA;
if (!SIDING || !SCHEMA) {
  console.error('set SIDESTR_SIDING (sidestr/spec siding/ at e8deb63) and SCHEMA (bitcoin-desktop/schema at b8cbf63)');
  process.exit(2);
}
const [hash, secp, { makeKeys }, { scriptToAddress }] = await Promise.all([
  import(`${SCHEMA}/codec/hash.js`),
  import(`${SCHEMA}/codec/secp256k1.js`),
  import(`${SIDING}/lib/keys.mjs`),
  import(`${SIDING}/lib/address.mjs`),
]);
const K = makeKeys({ hash, secp });
const utf8 = (t) => new TextEncoder().encode(t);
// JCS as blocktrails/verify writes it: keys sorted at every level, JSON otherwise
const jcs = (v) => v === null || typeof v !== 'object' ? JSON.stringify(v) : Array.isArray(v) ? '[' + v.map(jcs).join(',') + ']' : '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
const stateString = (st) => (typeof st === 'string' ? st : jcs(st));
const stateHash = (st) => hash.sha256(utf8(stateString(st)));
const hex32 = (i) => i.toString(16).padStart(64, '0');

function walk({ name, note, base, secret, states }) {
  const P0 = K.basePoint(base);
  const bareX = !/^0[23]/.test(String(base).toLowerCase());
  // a bare x names the even-y point: its holder normalises the secret once, then never again
  const holderSecret = secret ? (bareX ? K.normalize(secret) : secret.toLowerCase()) : null;
  if (holderSecret && K.publicKey(holderSecret) !== P0) throw new Error(`${name}: the secret is not the base point's`);
  const tweaks = [];
  const points = [];
  let P = P0;
  for (const s of states) {
    const t = K.tapTweak(P, stateHash(s));
    tweaks.push(t);
    P = K.tweakPoint(P, t);
    points.push(P);
  }
  const secrets = holderSecret ? K.chainSecrets(holderSecret, tweaks).slice(1) : null;
  if (secrets) secrets.forEach((d, i) => { if (K.publicKey(d) !== points[i]) throw new Error(`${name}: d_${i} does not match P_${i}`); });
  const outputs = points.map((p) => K.xOnly(p));
  return {
    name,
    note,
    base,
    basePoint: P0,
    ...(secret ? { secret: secret.toLowerCase(), holderSecret } : {}),
    states,
    stateStrings: states.map(stateString),
    tweaks,
    points,
    outputs,
    ...(secrets ? { secrets } : {}),
    tb: outputs.map((x) => scriptToAddress('5120' + x, 'tb')),
    bc: outputs.map((x) => scriptToAddress('5120' + x, 'bc')),
  };
}

// MRC20 states as objects (the shape solid-pod-rs's Mrc20State serialises to), hashed as JCS
const genesis = { profile: 'mono.mrc20.v0.1', prev: '0'.repeat(64), seq: 0, ticker: 'TEST', name: 'Test Token', decimals: 0, supply: 1000, balances: { issuer: 1000 }, ops: [] };
const transfer = { profile: 'mono.mrc20.v0.1', prev: hash.bytesToHex(hash.sha256(utf8(jcs(genesis)))), seq: 1, ticker: 'TEST', name: 'Test Token', decimals: 0, supply: 1000, balances: { issuer: 900, recipient: 100 }, ops: [{ op: 'urn:mono:op:transfer', from: 'issuer', to: 'recipient', amt: 100 }] };
const nested = { z: { b: [3, { y: 'é✓', x: null }], a: true }, a: -7, m: 'line\nbreak "quoted"' };

const BIP340_1 = 'b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef';
const ODD = hex32(10); // 10·G is odd-y, and so is its first chained point over s1, s2, s3
const cases = [];
for (const d of [hex32(1), hex32(3), BIP340_1]) {
  const base = K.publicKey(d);
  cases.push(walk({ name: `golden-${d.slice(-4)}-s1`, note: 'solid-pod-rs CHAINED_GOLDEN inputs', base, secret: d, states: ['s1'] }));
  cases.push(walk({ name: `golden-${d.slice(-4)}-s1s2s3`, note: 'solid-pod-rs CHAINED_GOLDEN inputs', base, secret: d, states: ['s1', 's2', 's3'] }));
  cases.push(walk({ name: `golden-${d.slice(-4)}-mrc20-objects`, note: 'object states hashed as their JCS (solid-pod-rs CHAINED_GOLDEN_JCS inputs)', base, secret: d, states: [genesis, transfer] }));
}
cases.push(walk({ name: 'odd-base-full-point', note: 'an 03 base kept whole, its first chained point odd-y too: the tweak is never added to a lift', base: K.publicKey(ODD), secret: ODD, states: ['s1', 's2', 's3'] }));
cases.push(walk({ name: 'odd-base-bare-x', note: 'the same x given bare reads as the 02 point (the negation), its holder normalising the secret once: other outputs', base: K.xOnly(K.publicKey(ODD)), secret: ODD, states: ['s1', 's2', 's3'] }));
cases.push(walk({ name: 'even-base-bare-x', note: 'an even-y base given bare agrees with its full point', base: K.xOnly(K.publicKey(hex32(1))), secret: hex32(1), states: ['s1', 's2', 's3'] }));
cases.push(walk({ name: 'text-and-object-states', note: 'a string state hashes as its UTF-8 text (never quoted), an object as its JCS', base: K.publicKey(BIP340_1), secret: BIP340_1, states: ['é✓ plain text', nested, '{"a":1}'] }));
const GM_BASE = '0273c7f6cf0f135a63bc95a2e676bcf0a592c8b508fae8697e43f778c74e232b24';
const GM = ['9adc596cfd1100333393a12f2f41b2d820f16d0b', '4490c4c39e145915c59c0964b6dcd8dc720c9d2e', '699ee3a3ea9332cc9ec435acf8fd8cd07eecf940'];
cases.push(walk({ name: 'git-mark-live-trail', note: 'blocktrails/git-mark b852d7d: the first three marks of the live trail, commits as text', base: GM_BASE, states: GM }));
cases.push(walk({ name: 'git-mark-live-trail-bare-x', note: 'the same base as a bare x (it is 02, so it agrees)', base: GM_BASE.slice(2), states: GM }));
cases.push(walk({ name: 'git-mark-swapped', note: 'commits 2 and 3 swapped: the first output agrees, every one from the swap on differs (git-mark refuses at index 1)', base: GM_BASE, states: [GM[0], GM[2], GM[1]] }));

process.stdout.write(JSON.stringify({
  source: {
    rule: 'blocktrails/spec ef54a08 (the rule as it is); blocktrails/verify 043e7af walk and stateHash',
    keys: 'sidestr/spec e8deb63 siding/lib/keys.mjs, siding/lib/address.mjs',
    curve: 'bitcoin-desktop/schema b8cbf63 codec/hash.js, codec/secp256k1.js',
    generator: 'gen-keys-walk-vectors.mjs (this directory)',
  },
  cases,
}, null, 2) + '\n');
