// The rotate subcommand's decisions (`rotate.mjs`), which need no network, no
// chain and no mnemonic: the fresh root secret, one request per member, the
// lease file keeping both roots until every member has confirmed, and a lost
// answer recovered through `status`. Run with `npm test` in this directory.
//
// The members here are an in-memory stand-in that applies spec §6.8's rules
// to the one token it stores, so a test asserts what a later request
// OBSERVES. The same tool against the provider's real HTTP server is
// `../../tests/rotate_tool.rs`; the bytes of a rotate request against the
// provider's own wire fixture are the first test below.

import { strict as assert } from 'node:assert';
import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';

import { continuationFor } from './handover.mjs';
import {
  membersProblem,
  parseMember,
  readLease,
  rotateLease,
  rotateRequest,
  statusRequest,
} from './rotate.mjs';

const FIXTURES = new URL('../../tests/fixtures/wire/', import.meta.url);
const fixture = (name) => JSON.parse(readFileSync(new URL(name, FIXTURES), 'utf8'));
const constants = fixture('constants.json');
const ROTATE = fixture('lease_request.rotate.json');

const OLD_ROOT = constants.tenant.root_secret;
const WORKLOAD = 'aa'.repeat(32);
const PRIMARY = constants.primary_provider.public_key;
const STANDBY = constants.standby_provider.public_key;
// A 65-byte uncompressed secp256k1 key, the shape a Profile pins (ADR 0011).
// Synthetic: the generator point.
const SEAL_KEY =
  '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' +
  '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';

const MEMBERS = [
  { provider: PRIMARY, address: 'g.fixture.primary', sealKey: SEAL_KEY },
  { provider: STANDBY, address: 'g.fixture.standby', sealKey: SEAL_KEY },
];

/** A lease file as the sandbox's `spawn.mjs` writes one, with a key of its own to keep. */
function leaseFile(extra = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'rotate-'));
  const path = join(dir, 'spawn.json');
  writeFileSync(
    path,
    JSON.stringify({ workload_id: WORKLOAD, root_secret: OLD_ROOT, standby_set: ['provider', 'provider2'], ...extra }),
    { mode: 0o600 },
  );
  return path;
}

const lease = (path) => JSON.parse(readFileSync(path, 'utf8'));

/**
 * The members, in memory: each stores ONE token for the lease — the one
 * `OLD_ROOT` derives for it — and answers `rotate` and `status` by §6.8's
 * rules against it. `lose(provider, when)` drops an answer: `'after'` applies
 * the request and loses the answer, `'before'` loses the request itself.
 */
function members() {
  const tokens = new Map([PRIMARY, STANDBY].map((p) => [p, continuationFor(OLD_ROOT, p)]));
  const asked = [];
  const losing = new Map();
  const refusing = new Map();
  const refuse = (error, message) => ({ status: 403, body: { error, message } });

  const ask = async (destination, body, member) => {
    const { request } = body;
    asked.push({ destination, request, member: member.provider });
    const loss = losing.get(`${member.provider}:${request.op}`);
    if (loss === 'before') return { lost: 'T00 the packet timed out' };
    const answer = (() => {
      if (refusing.has(member.provider)) return refuse(refusing.get(member.provider), 'refused');
      if (request.provider !== member.provider) return { status: 400, body: { error: 'invalid_request', message: 'wrong provider' } };
      if (request.content.workload_id !== WORKLOAD) return { status: 404, body: { error: 'unknown_workload', message: '' } };
      if (request.continuation !== tokens.get(member.provider)) return refuse('not_tenant', 'not the tenant');
      if (request.op === 'status') return { status: 200, body: { workload_id: WORKLOAD, state: 'running' } };
      if (request.content.next === request.continuation) return { status: 400, body: { error: 'invalid_request', message: 'same token' } };
      tokens.set(member.provider, request.content.next);
      return { status: 200, body: { workload_id: WORKLOAD, rotated: true } };
    })();
    if (loss === 'after') return { lost: 'T00 the packet timed out' };
    return answer;
  };

  return {
    ask,
    asked,
    token: (provider) => tokens.get(provider),
    lose: (provider, when, op = 'rotate') => losing.set(`${provider}:${op}`, when),
    heal: () => losing.clear(),
    refuse: (provider, code) => refusing.set(provider, code),
  };
}

describe('a rotate request', () => {
  it('is the bytes the provider was proven against (lease_request.rotate)', () => {
    const request = rotateRequest({
      workloadId: ROTATE.request.content.workload_id,
      oldRoot: constants.tenant.root_secret,
      newRoot: constants.rotated_tenant.root_secret,
      provider: constants.provider.public_key,
      now: constants.now - 60,
    });
    assert.equal(request.op, 'rotate');
    assert.equal(request.provider, ROTATE.request.provider);
    assert.equal(request.continuation, ROTATE.request.continuation, 'it presents the CURRENT token');
    assert.deepEqual(request.content, ROTATE.request.content, 'exactly { workload_id, next }');
    assert.equal(request.expiration, ROTATE.request.expiration);
    assert.deepEqual(Object.keys(request).sort(), Object.keys(ROTATE.request).sort());
    assert.match(request.request_id, /^[0-9a-f]{64}$/);
  });

  it('confirms through a status presenting the new token', () => {
    const request = statusRequest({ workloadId: WORKLOAD, root: constants.rotated_tenant.root_secret, provider: constants.provider.public_key, now: 0 });
    assert.equal(request.op, 'status');
    assert.equal(request.continuation, constants.rotated_tenant.continuation_at_provider);
    assert.deepEqual(request.content, { workload_id: WORKLOAD });
  });
});

describe('rotating a Standby Set', () => {
  it('mints a fresh root secret and installs the token it derives at every member', async () => {
    const path = leaseFile();
    const set = members();
    const report = await rotateLease({ leaseFile: path, members: MEMBERS, ask: set.ask, now: () => 1_700_000_000 });

    const after = lease(path);
    assert.equal(report.rotated, true);
    assert.match(after.root_secret, /^[0-9a-f]{64}$/);
    assert.notEqual(after.root_secret, OLD_ROOT, 'a FRESH root secret, not the one the lease was spawned from');
    for (const provider of [PRIMARY, STANDBY]) {
      assert.equal(set.token(provider), continuationFor(after.root_secret, provider), 'each member holds what the new root derives for it');
    }
    assert.equal(after.rotation, undefined, 'the old root is dropped once every member confirmed');
    assert.equal(after.rotated_at, 1_700_000_000);
    assert.deepEqual(after.standby_set, ['provider', 'provider2'], 'the file owner\'s keys are kept');
    assert.equal(statSync(path).mode & 0o777, 0o600, 'a file holding a root secret is readable by its owner only');
  });

  it('mints a different root secret for every rotation', async () => {
    const path = leaseFile();
    const set = members();
    await rotateLease({ leaseFile: path, members: MEMBERS, ask: set.ask });
    const first = lease(path).root_secret;
    // The members hold the first rotation's tokens now; so does the file.
    await rotateLease({ leaseFile: path, members: MEMBERS, ask: set.ask });
    const second = lease(path).root_secret;
    assert.notEqual(second, first);
    assert.equal(set.token(PRIMARY), continuationFor(second, PRIMARY));
  });

  it('sends one rotate per member, each naming only that member and presenting its own token', async () => {
    const path = leaseFile();
    const set = members();
    await rotateLease({ leaseFile: path, members: MEMBERS, ask: set.ask });
    const newRoot = lease(path).root_secret;

    const rotates = set.asked.filter((a) => a.request.op === 'rotate');
    assert.deepEqual(
      rotates.map((a) => [a.destination, a.member, a.request.provider]),
      [
        ['g.fixture.primary.rotate', PRIMARY, PRIMARY],
        ['g.fixture.standby.rotate', STANDBY, STANDBY],
      ],
    );
    for (const { request, member } of rotates) {
      assert.equal(request.continuation, continuationFor(OLD_ROOT, member));
      assert.equal(request.content.next, continuationFor(newRoot, member));
    }
    assert.notEqual(rotates[0].request.content.next, rotates[1].request.content.next, 'every member ends with a different token');
    assert.equal(set.asked.length, 2, 'and nothing else is asked when every answer arrives');
  });

  it('records the new root secret before any request leaves', async () => {
    const path = leaseFile();
    const set = members();
    let seen;
    const ask = async (destination, body, member) => {
      seen ??= lease(path);
      return set.ask(destination, body, member);
    };
    await rotateLease({ leaseFile: path, members: MEMBERS, ask });

    assert.equal(seen.root_secret, OLD_ROOT, 'the old root stays until every member confirms');
    assert.match(seen.rotation.root_secret, /^[0-9a-f]{64}$/);
    assert.equal(seen.rotation.root_secret, lease(path).root_secret, 'and the new one is the one that was installed');
    assert.deepEqual(seen.rotation.members, [PRIMARY, STANDBY]);
    assert.deepEqual(seen.rotation.confirmed, []);
  });
});

describe('a lost answer', () => {
  it('is recovered by asking status with the new token, not by sending the rotate again', async () => {
    const path = leaseFile();
    const set = members();
    set.lose(PRIMARY, 'after');
    const report = await rotateLease({ leaseFile: path, members: MEMBERS, ask: set.ask });
    const newRoot = lease(path).root_secret;

    assert.equal(report.rotated, true);
    assert.deepEqual(report.members[0], { provider: PRIMARY, rotated: true, recovered: true });
    const toPrimary = set.asked.filter((a) => a.member === PRIMARY);
    assert.deepEqual(toPrimary.map((a) => [a.destination, a.request.op]), [
      ['g.fixture.primary.rotate', 'rotate'],
      ['g.fixture.primary.status', 'status'],
    ]);
    assert.equal(toPrimary[1].request.continuation, continuationFor(newRoot, PRIMARY), 'the status presents `next`');
    assert.equal(set.token(PRIMARY), continuationFor(newRoot, PRIMARY));
  });

  it('that means the rotation did not happen leaves that member on the old root, and a second run finishes it', async () => {
    const path = leaseFile();
    const set = members();
    set.lose(STANDBY, 'before');
    const first = await rotateLease({ leaseFile: path, members: MEMBERS, ask: set.ask });

    assert.equal(first.rotated, false);
    assert.equal(first.members[0].rotated, true);
    assert.equal(first.members[1].rotated, false);
    assert.match(first.members[1].failed, /not_tenant/, 'status with the new token said the old one still holds');

    // A partly rotated set: the file keeps BOTH roots, and each reads its member.
    const partly = lease(path);
    assert.equal(partly.root_secret, OLD_ROOT);
    assert.deepEqual(partly.rotation.confirmed, [PRIMARY]);
    assert.equal(set.token(PRIMARY), continuationFor(partly.rotation.root_secret, PRIMARY));
    assert.equal(set.token(STANDBY), continuationFor(OLD_ROOT, STANDBY));

    set.heal();
    const before = set.asked.length;
    const second = await rotateLease({ leaseFile: path, members: MEMBERS, ask: set.ask });
    assert.equal(second.rotated, true);
    assert.deepEqual(
      set.asked.slice(before).map((a) => [a.member, a.request.op]),
      [[STANDBY, 'rotate']],
      'the confirmed member is left alone',
    );
    const done = lease(path);
    assert.equal(done.root_secret, partly.rotation.root_secret, 'the rotation is resumed with the same new root, not restarted');
    assert.equal(set.token(STANDBY), continuationFor(done.root_secret, STANDBY));
  });

  it('from an interrupted run is recognised when the old token is refused, too', async () => {
    const path = leaseFile();
    const set = members();
    // A run that stopped after the primary accepted and before it said so to
    // the file: the file names no member confirmed, the primary holds `next`.
    set.lose(PRIMARY, 'after');
    set.lose(PRIMARY, 'before', 'status');
    set.lose(STANDBY, 'before');
    await rotateLease({ leaseFile: path, members: MEMBERS, ask: set.ask });
    assert.deepEqual(lease(path).rotation.confirmed, []);

    set.heal();
    const report = await rotateLease({ leaseFile: path, members: MEMBERS, ask: set.ask });
    assert.equal(report.rotated, true);
    assert.deepEqual(report.members[0], { provider: PRIMARY, rotated: true, recovered: true });
  });
});

describe('what the tool reports and refuses', () => {
  it('reports a refusal about the lease as it came, and asks nothing more of that member', async () => {
    const path = leaseFile();
    const set = members();
    set.refuse(STANDBY, 'expired');
    const report = await rotateLease({ leaseFile: path, members: MEMBERS, ask: set.ask });
    assert.equal(report.rotated, false);
    assert.match(report.members[1].failed, /^expired/);
    assert.equal(set.asked.filter((a) => a.member === STANDBY).length, 1);
  });

  it('puts no root secret and no token in its report or its log', async () => {
    const path = leaseFile();
    const set = members();
    set.lose(PRIMARY, 'after');
    const lines = [];
    const report = await rotateLease({ leaseFile: path, members: MEMBERS, ask: set.ask, log: (l) => lines.push(l) });
    const newRoot = lease(path).root_secret;
    const secrets = [OLD_ROOT, newRoot, ...[PRIMARY, STANDBY].flatMap((p) => [continuationFor(OLD_ROOT, p), continuationFor(newRoot, p)])];
    const said = JSON.stringify(report) + lines.join('\n');
    for (const secret of secrets) assert.ok(!said.includes(secret), 'a secret reached the report or the log');
  });

  it('refuses to resume a rotation naming other members than it started with', async () => {
    const path = leaseFile();
    const set = members();
    set.lose(STANDBY, 'before');
    await rotateLease({ leaseFile: path, members: MEMBERS, ask: set.ask });
    await assert.rejects(rotateLease({ leaseFile: path, members: MEMBERS.slice(0, 1), ask: set.ask }), /same members/);
  });

  it('refuses a lease file with no root secret, and quotes no secret back', () => {
    const path = leaseFile({ root_secret: 'AB'.repeat(32) });
    assert.throws(() => readLease(path), (e) => /root_secret/.test(e.message) && !e.message.includes('AB'.repeat(32)));
  });

  it('reads a member as <pubkey>,<ilp address>,<seal key>, and refuses one that is not', () => {
    assert.deepEqual(parseMember(`${PRIMARY},g.toon.provider,0x${SEAL_KEY}`), { provider: PRIMARY, address: 'g.toon.provider', sealKey: `0x${SEAL_KEY}` });
    assert.throws(() => parseMember(PRIMARY), /<pubkey>,<ilp address>,<seal key>/);
    assert.equal(membersProblem([{ provider: PRIMARY, address: 'g.toon.provider', sealKey: `0x${SEAL_KEY}` }]), null, 'a Profile\'s 0x-prefixed key is taken as it is written');
    assert.match(membersProblem([{ provider: PRIMARY, address: 'g toon', sealKey: SEAL_KEY }]), /not an ILP address/);
    assert.match(membersProblem([{ provider: PRIMARY, address: 'g.toon', sealKey: 'ab' }]), /sealing key/);
    assert.match(membersProblem([MEMBERS[0], MEMBERS[0]]), /twice/);
    assert.match(membersProblem([]), /at least one member/);
  });
});
