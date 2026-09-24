// deploy/keys.sh prints the address this publisher pays from, before the
// publisher has ever run (TOON_Network#162). An operator funds exactly that
// address, so it must be the one @toon-protocol/client derives from
// TOON_MNEMONIC — this package's own copy of the client, at the version the
// image ships, on phrases it generates itself. tests/deploy_keys.rs pins fixed
// phrases in CI; this runs the live derivation. Run with `npm test` here.

import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';

import { deriveFullIdentity, generateMnemonic } from '@toon-protocol/client';

const KEYS_PY = join(dirname(fileURLToPath(import.meta.url)), '../../deploy/keys.py');

/** What keys.sh would print for this phrase, via `keys.py derive`. */
function keysPy(mnemonic) {
  const dir = mkdtempSync(join(tmpdir(), 'keys-'));
  try {
    // derive reads the two connector key files too; any valid key will do.
    const key = 'ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n';
    spawnSync('sh', ['-c', `printf '${key}' > settlement.key; printf '${key}' > settlement-solana.key`], {
      cwd: dir,
    });
    const run = spawnSync('python3', [KEYS_PY, 'provider', 'derive'], {
      cwd: dir,
      env: { ...process.env, PUBLISHER_MNEMONIC: mnemonic },
      encoding: 'utf8',
    });
    assert.equal(run.status, 0, run.stderr);
    return JSON.parse(run.stdout).publisher_solana;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('the publisher address keys.sh prints', () => {
  it('is the one this client derives, the way ToonClient.create does', () => {
    for (let i = 0; i < 8; i++) {
      const mnemonic = generateMnemonic();
      // ToonClient.create: deriveFullIdentity(mnemonic.trim(), { accountIndex })
      // with TOON_ACCOUNT_INDEX '0' (deploy/docker-compose.yml).
      const expected = deriveFullIdentity(mnemonic.trim(), { accountIndex: 0 }).solana.publicKey;
      assert.equal(keysPy(mnemonic), expected, mnemonic);
    }
  });
});
