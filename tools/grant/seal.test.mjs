// The command (`seal.mjs`), driven the way a tenant drives it: a process, a
// command line, an exit code and one JSON report on stdout. What it derives
// is `handover.mjs`'s and is proven there; what is proven here is that the
// command reaches those decisions with the flags and the environment it was
// given, and that `--dry-run` needs nothing installed to do it.
//
// Run with `npm test` in this directory.

import { strict as assert } from 'node:assert';
import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { promisify } from 'node:util';

const run = promisify(execFile);

const SEAL = new URL('seal.mjs', import.meta.url).pathname;
const constants = JSON.parse(
  readFileSync(new URL('../../tests/fixtures/wire/constants.json', import.meta.url), 'utf8'),
);

const ROOT_SECRET = constants.tenant.root_secret;
const PROVIDER = constants.provider.public_key;
const WORKLOAD = 'aa'.repeat(32);
const ROUTE = 'g.toon.workload-gateway.handover';
/** A moment still ahead of the command's own clock: it runs on the real one. */
const EXPIRES_AT = String(Math.floor(Date.now() / 1000) + 86_400);
// A 65-byte uncompressed secp256k1 key, the shape a connector's `GET /ilp`
// reports and a Profile pins (ADR 0011). Synthetic: the generator point.
const SEAL_KEY =
  '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' +
  '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';

/** The gateway's connector, and the lease, as every command below names them. */
const FLAGS = [
  '--workload', WORKLOAD,
  '--standby', PROVIDER,
  '--gateway-route', ROUTE,
  '--gateway-seal-key', SEAL_KEY,
];

/** One run of the command: its exit code, its stdout and its stderr. */
async function seal(args, env = {}) {
  try {
    const { stdout, stderr } = await run(process.execPath, [SEAL, ...args], {
      // Deliberately bare: `--dry-run` must not need a mnemonic, a chain or a
      // connector, and must not read one that happens to be in the shell.
      env: { PATH: process.env.PATH, ...env },
    });
    return { code: 0, stdout, stderr };
  } catch (e) {
    return { code: e.code, stdout: e.stdout, stderr: e.stderr };
  }
}

describe('a dry run', () => {
  it('derives a handover and prints it, with nothing installed and nothing sent', async () => {
    const { code, stdout, stderr } = await seal(
      // The subcommand need not come first: `parseArgs` takes a positional
      // wherever it falls, and a tenant repeating a command edits the end of it.
      [
        ...FLAGS,
        'handover',
        '--http-port', '443',
        '--ports', '443',
        '--expires-at', EXPIRES_AT,
        '--name', 'blog',
        '--dry-run',
      ],
      { TOON_ROOT_SECRET: ROOT_SECRET },
    );

    assert.equal(code, 0, stderr);
    const report = JSON.parse(stdout);
    assert.equal(report.dry_run, true);
    assert.equal(report.workload_id, WORKLOAD);
    assert.deepEqual(report.gateway, { route: ROUTE, seal_key: SEAL_KEY });
    assert.deepEqual(Object.keys(report.handover), [
      'workload_id', 'standby_set', 'http_port', 'expires_at', 'name',
    ]);
    assert.deepEqual(Object.keys(report.handover.standby_set[0]), ['provider', 'grant']);
    assert.equal(report.handover.standby_set[0].provider, PROVIDER);
    assert.match(report.handover.standby_set[0].grant, /^[0-9a-f]{64}$/);
    assert.equal(stderr.includes(ROOT_SECRET), false, 'the root secret is never printed');
  });

  it('derives a withdrawal bearing the grant the handover carried', async () => {
    const args = [...FLAGS, '--expires-at', EXPIRES_AT, '--dry-run'];
    const env = { TOON_ROOT_SECRET: ROOT_SECRET };
    const handed = await seal(['handover', '--http-port', '443', ...args], env);
    const handover = JSON.parse(handed.stdout);
    const { code, stdout } = await seal(['withdrawal', ...args], env);

    assert.equal(code, 0);
    const report = JSON.parse(stdout);
    assert.deepEqual(Object.keys(report.withdrawal), ['workload_id', 'expires_at', 'standby_set']);
    assert.deepEqual(
      report.withdrawal.standby_set,
      handover.handover.standby_set,
      'the same members and the same grants, re-derived, not stored',
    );
  });

  it('takes the root secret from --root-secret as well as the environment', async () => {
    const args = ['handover', ...FLAGS, '--http-port', '443', '--expires-in', '24h', '--dry-run'];
    const { code, stdout } = await seal([...args, '--root-secret', ROOT_SECRET]);
    assert.equal(code, 0);
    const [member] = JSON.parse(stdout).handover.standby_set;
    assert.equal(member.provider, PROVIDER);
    assert.match(member.grant, /^[0-9a-f]{64}$/);
  });
});

describe('a refusal before anything is derived or sent', () => {
  it('exits 2, says why on stderr, and prints no report', async () => {
    const { code, stdout, stderr } = await seal(
      ['handover', ...FLAGS, '--http-port', '8080', '--ports', '443', '--expires-in', '24h'],
      { TOON_ROOT_SECRET: ROOT_SECRET },
    );
    assert.equal(code, 2);
    assert.equal(stdout, '');
    assert.match(stderr, /http_port 8080 is not one of the spawn's container ports \(443\)/);
  });

  it('never quotes the root secret back, whatever is wrong with it', async () => {
    const { code, stderr } = await seal(
      ['handover', ...FLAGS, '--http-port', '443', '--expires-in', '24h'],
      { TOON_ROOT_SECRET: 'nsec1notasecret' },
    );
    assert.equal(code, 2);
    assert.match(stderr, /root secret must be 64 lowercase hex/);
    assert.equal(stderr.includes('nsec1notasecret'), false);
  });

  it('refuses a subcommand it does not know, and asks for one when there is none', async () => {
    const env = { TOON_ROOT_SECRET: ROOT_SECRET };
    assert.match((await seal(['publish', ...FLAGS], env)).stderr, /handover, withdrawal or rotate/);
    assert.match((await seal([...FLAGS], env)).stderr, /handover, withdrawal or rotate/);
  });

  it('refuses to send without a mnemonic, because a packet to a gateway is paid for', async () => {
    const { code, stderr } = await seal(
      ['handover', ...FLAGS, '--http-port', '443', '--expires-in', '24h'],
      { TOON_ROOT_SECRET: ROOT_SECRET },
    );
    assert.equal(code, 2);
    assert.match(stderr, /TOON_MNEMONIC is required/);
  });
});

describe('rotate', () => {
  /** A lease file as the sandbox's spawn.mjs writes one. */
  const leaseFile = () => {
    const path = join(mkdtempSync(join(tmpdir(), 'seal-rotate-')), 'spawn.json');
    writeFileSync(path, JSON.stringify({ workload_id: WORKLOAD, root_secret: ROOT_SECRET }), { mode: 0o600 });
    return path;
  };
  const MEMBER = `${PROVIDER},g.toon.provider,0x${SEAL_KEY}`;

  it('refuses before anything is minted or sent when no mnemonic can pay, and leaves the lease file as it was', async () => {
    const path = leaseFile();
    const before = readFileSync(path, 'utf8');
    const { code, stdout, stderr } = await seal(['rotate', '--lease', path, '--member', MEMBER]);
    assert.equal(code, 2);
    assert.equal(stdout, '');
    assert.match(stderr, /TOON_MNEMONIC is required/);
    assert.equal(readFileSync(path, 'utf8'), before, 'no new root secret was minted for a rotation that never started');
  });

  it('reads the root secret from the lease file and from nowhere else', async () => {
    const path = leaseFile();
    const refused = await seal(['rotate', '--lease', path, '--member', MEMBER, '--root-secret', ROOT_SECRET]);
    assert.equal(refused.code, 2);
    assert.match(refused.stderr, /--root-secret is not rotate's/);
    assert.equal(refused.stderr.includes(ROOT_SECRET), false);
  });

  it('refuses a handover\'s flags, a dry run, a missing lease and a member it cannot reach', async () => {
    const path = leaseFile();
    const cases = [
      [['rotate', '--lease', path, '--member', MEMBER, '--gateway-route', ROUTE], /--gateway-route is not rotate's/],
      [['rotate', '--lease', path, '--member', MEMBER, '--dry-run'], /no dry run/],
      [['rotate', '--member', MEMBER], /--lease <lease.json> is required/],
      [['rotate', '--lease', path], /at least one member/],
      [['rotate', '--lease', path, '--member', PROVIDER], /<pubkey>,<ilp address>,<seal key>/],
      [['rotate', '--lease', path, '--member', `${PROVIDER},g.toon.provider,beef`], /sealing key/],
      [['rotate', '--lease', `${path}.missing`, '--member', MEMBER], /not a lease file/],
    ];
    for (const [args, why] of cases) {
      const { code, stderr } = await seal(args, { TOON_MNEMONIC: 'test test test test test test test test test test test junk' });
      assert.equal(code, 2, args.join(' '));
      assert.match(stderr, why);
    }
  });

  it('refuses, before any channel is opened, to finish a rotation naming other members than it started with', async () => {
    const path = leaseFile();
    const lease = JSON.parse(readFileSync(path, 'utf8'));
    writeFileSync(path, JSON.stringify({ ...lease, rotation: { root_secret: 'ab'.repeat(32), members: [PROVIDER, 'cd'.repeat(32)], confirmed: [PROVIDER] } }));
    const { code, stderr } = await seal(['rotate', '--lease', path, '--member', MEMBER], {
      TOON_MNEMONIC: 'test test test test test test test test test test test junk',
    });
    assert.equal(code, 2);
    assert.match(stderr, /same members/);
  });

  it('is the only subcommand that takes --lease and --member', async () => {
    const { code, stderr } = await seal(
      ['handover', ...FLAGS, '--http-port', '443', '--expires-in', '24h', '--dry-run', '--member', MEMBER],
      { TOON_ROOT_SECRET: ROOT_SECRET },
    );
    assert.equal(code, 2);
    assert.match(stderr, /--member is rotate's/);
  });
});

describe('--help', () => {
  it('prints the usage the file itself carries, and exits 0', async () => {
    const { code, stderr } = await seal(['--help']);
    assert.equal(code, 0);
    assert.match(stderr, /seal\.mjs (handover|<handover)/);
    assert.match(stderr, /--gateway-seal-key/);
  });
});
