// Differential vector generator for the NIP-34 builders.
//
// Boots the JSS forge plugin (plugins@63a16cb) from the oracle checkout,
// materialises the repositories described by nip34-spec.json with fixed git
// identities and dates, asks the live plugin for GET api/repos/<o>/<n>/nostr
// and writes nip34-vectors.json. The Rust test rebuilds the same repositories
// from the same spec, feeds the recorded created_at into its builders and
// requires byte-identical ids and tags (signatures differ: BIP-340 aux
// randomness, so they are verified, not compared).
//
// Run from the plugins checkout so node_modules resolve:
//   cd /home/devuser/workspace/.tmp/jss221/plugins
//   TOKEN_SECRET=testsecret-testsecret-testsecret-123456 node <this file>
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { startJss } from '/home/devuser/workspace/.tmp/jss221/plugins/helpers.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const spec = JSON.parse(fs.readFileSync(path.join(here, 'nip34-spec.json'), 'utf8'));
const modulePath = '/home/devuser/workspace/.tmp/jss221/plugins/forge/plugin.js';

const gitHome = fs.mkdtempSync(path.join(os.tmpdir(), 'nip34-home-'));
const GIT_BASE = {
  PATH: process.env.PATH, HOME: gitHome, GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0',
  GIT_AUTHOR_NAME: 'Casey Coder', GIT_AUTHOR_EMAIL: 'casey@example.org',
  GIT_COMMITTER_NAME: 'Casey Coder', GIT_COMMITTER_EMAIL: 'casey@example.org',
};
let tick = 0;
function git(cwd, args) {
  tick += 1;
  const date = `${1_700_000_000 + tick * 60} +0000`;
  return execFileSync('git', args, {
    cwd, encoding: 'utf8', env: { ...GIT_BASE, GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date },
  }).trim();
}

function populate(repo, reposDir, marksDir) {
  tick = 0; // commit dates depend on the repository's own steps only
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'nip34-work-'));
  const bare = path.join(reposDir, repo.owner, `${repo.name}.git`);
  fs.mkdirSync(path.dirname(bare), { recursive: true });
  if (repo.steps.length === 0) {
    git(path.dirname(bare), ['init', '--quiet', '--bare', '-b', 'main', bare]);
  } else {
    git(work, ['init', '--quiet', '-b', 'main']);
    for (const s of repo.steps) {
      if (s.branch) git(work, ['checkout', '--quiet', '-B', s.branch]);
      else if (s.switch) git(work, ['checkout', '--quiet', s.switch]);
      else {
        for (const [p, c] of Object.entries(s.files)) {
          fs.mkdirSync(path.dirname(path.join(work, p)), { recursive: true });
          fs.writeFileSync(path.join(work, p), c === '@TRAIL@' ? spec.trail : c);
        }
        git(work, ['add', '-A']);
        git(work, ['commit', '--quiet', '-m', s.message]);
      }
    }
    git(path.dirname(bare), ['clone', '--quiet', '--bare', work, bare]);
  }
  if (repo.description) fs.writeFileSync(path.join(bare, 'description'), repo.description);
  if (repo.forgeHeld) {
    const tip = git(bare, ['rev-parse', 'refs/heads/main']);
    const t = {
      v: 1, chain: repo.forgeHeld.chain, privkey: '22'.repeat(32),
      pubkeyBase: '034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa', createdAt: 1_700_000_000,
      marks: repo.forgeHeld.marks.map((m, i) => ({
        index: i, status: m.status, txid: m.txid, vout: m.vout, state: { commit: tip },
      })),
    };
    const f = path.join(marksDir, repo.owner, `${repo.name}.json`);
    fs.mkdirSync(path.dirname(f), { recursive: true });
    fs.writeFileSync(f, JSON.stringify(t), { mode: 0o600 });
  }
  fs.rmSync(work, { recursive: true, force: true });
}

const out = { announceKey: spec.announceKey, baseUrl: spec.baseUrl, relays: spec.relays, cases: [] };
for (const mode of ['relays', 'none']) {
  const config = {
    announceKey: spec.announceKey,
    baseUrl: spec.baseUrl,
    ...(mode === 'relays' ? { announceRelays: spec.relays } : {}),
  };
  const jss = await startJss({ plugins: [{ id: 'forge', module: modulePath, prefix: '/forge', config }] });
  const pluginDir = path.join(jss.root, '.plugins', 'forge');
  for (const repo of spec.repos.filter((r) => r.cases.includes(mode))) {
    populate(repo, path.join(pluginDir, 'repos'), path.join(pluginDir, 'marks'));
    const res = await fetch(`${jss.base}/forge/api/repos/${repo.owner}/${repo.name}/nostr`);
    if (res.status !== 200) throw new Error(`${repo.name}: ${res.status}`);
    const j = await res.json();
    out.cases.push({
      mode, owner: repo.owner, name: repo.name, pubkey: j.pubkey, npub: j.npub,
      relaysConfigured: j.relaysConfigured, event: j.event, state: j.state,
    });
  }
  await jss.close();
}
fs.writeFileSync(path.join(here, 'nip34-vectors.json'), `${JSON.stringify(out, null, 1)}\n`);
console.log(`wrote ${out.cases.length} cases`);
fs.rmSync(gitHome, { recursive: true, force: true });
process.exit(0);
