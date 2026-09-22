// Rotating a lease's Continuation Token at every member of its Standby Set
// (spec §6.8, ADR 0018; TOON_Network #75): what a rotate request says, what
// is refused before one is sent, how a lost answer is recovered, and how the
// lease file keeps both root secrets until every member has confirmed.
//
// Kept apart from `seal.mjs` for the reason `handover.mjs` is: that file reads
// the environment, opens a payment channel and exits. Everything here takes
// the one seam a rotation crosses — the `ask` it is handed — and is tested on
// its own (`node --test`) and, from the provider's side, against the
// provider's real HTTP server (`../../tests/rotate_tool.rs`).
//
// ROTATION IS REVOCATION. The provider stores `next` in place of the token it
// held and keeps no second value, so from that moment the old token is
// `not_tenant` and every Gateway Grant derived from it is `bad_grant` — a
// Workload Gateway handed one stops READING the lease, not only serving it.
// A tenant that keeps its gateway hands it grants of the new root afterwards
// (`seal.mjs handover`, which reads the lease file's root secret).

import { randomBytes } from 'node:crypto';
import { readFileSync, renameSync, writeFileSync } from 'node:fs';

import { HEX64, ILP_ADDRESS, SEAL_KEY, continuationFor, publicKeyProblem, sealKeyBytes } from './handover.mjs';

/**
 * How long a request this tool sends is good for (spec §6.1: a provider
 * refuses an `expiration` more than 300 s out). Short, because a rotate
 * request is answered at once or not at all.
 */
export const REQUEST_TTL_S = 120;

/** 32 fresh random bytes as 64 lowercase hex: a new root secret (spec §6.1.1). */
export const newRootSecret = () => randomBytes(32).toString('hex');

/**
 * A Lease Request (spec §6.1): a fresh `request_id`, the `op`, the ONE
 * provider it is for, an `expiration`, the token it presents and the op's
 * content. Nothing is signed.
 */
export const leaseRequest = ({ op, provider, continuation, content, now }) => ({
  request_id: randomBytes(32).toString('hex'),
  op,
  provider,
  expiration: now + REQUEST_TTL_S,
  continuation,
  content,
});

/**
 * The rotate request one member is sent (spec §6.8): it presents the token
 * `oldRoot` derives for that member and names as `next` the token `newRoot`
 * derives for it. Exactly `{ workload_id, next }`, and nothing else — a field
 * the spec does not name is refused.
 */
export const rotateRequest = ({ workloadId, oldRoot, newRoot, provider, now }) =>
  leaseRequest({
    op: 'rotate',
    provider,
    continuation: continuationFor(oldRoot, provider),
    content: { workload_id: workloadId, next: continuationFor(newRoot, provider) },
    now,
  });

/** The `status` that tells a tenant whether `root`'s token holds the lease at `provider`. */
export const statusRequest = ({ workloadId, root, provider, now }) =>
  leaseRequest({
    op: 'status',
    provider,
    continuation: continuationFor(root, provider),
    content: { workload_id: workloadId },
    now,
  });

// ── the members ───────────────────────────────────────────────────────────

/**
 * `--member <pubkey>,<ilp address>,<seal key>`: one member of the Standby Set
 * and the two facts that reach it — its Profile's `ilp_address`, the prefix
 * of its `.rotate` and `.status` routes, and its connector's PINNED sealing
 * key (ADR 0011), which nothing here fetches. One flag per member, because a
 * member and the way to reach it are one fact and not three lists to line up.
 */
export function parseMember(text) {
  const parts = String(text).split(',');
  if (parts.length !== 3) {
    throw new Error(
      `--member ${JSON.stringify(text)} must be <pubkey>,<ilp address>,<seal key>: ` +
        'the member, the address its Profile names, and its connector\'s pinned sealing key',
    );
  }
  const [provider, address, sealKey] = parts.map((p) => p.trim());
  return { provider, address, sealKey };
}

/** Why these members cannot be rotated, or `null`. */
export function membersProblem(members) {
  if (!Array.isArray(members) || members.length === 0) {
    return 'the Standby Set must name at least one member, primary first (--member <pubkey>,<ilp address>,<seal key>, once per member)';
  }
  for (const [i, { provider, address, sealKey }] of members.entries()) {
    const problem = publicKeyProblem(`Standby Set member ${i + 1}`, provider);
    if (problem !== null) return problem;
    if (typeof address !== 'string' || !ILP_ADDRESS.test(address)) {
      return `member ${provider}'s address ${JSON.stringify(address)} is not an ILP address: the \`ilp_address\` its Profile names`;
    }
    if (typeof sealKey !== 'string' || !SEAL_KEY.test(sealKey.replace(/^0x/, ''))) {
      return (
        `member ${provider}'s sealing key must be a secp256k1 public key as hex: the \`connector_seal_key\` ` +
        'its Profile pins, 65-byte uncompressed (04…) or 33-byte compressed (02…/03…)'
      );
    }
  }
  if (new Set(members.map((m) => m.provider)).size !== members.length) {
    return 'the Standby Set names one provider twice';
  }
  return null;
}

// ── the lease file ────────────────────────────────────────────────────────

/**
 * The lease file: a JSON object with at least
 *
 *   { "workload_id": "<64 hex>", "root_secret": "<64 hex>" }
 *
 * — what the sandbox's `scripts/spawn.mjs` writes — and, while a rotation is
 * under way, a `rotation` record:
 *
 *   "rotation": { "root_secret": "<the new one>", "members": [<pubkey>…], "confirmed": [<pubkey>…] }
 *
 * `root_secret` stays the OLD one until every member has confirmed, because
 * the members that have not are still read with it; `rotation.root_secret` is
 * the new one, written BEFORE a request leaves, so a crash straight after a
 * member accepted cannot lose the only secret that now reads it there. Every
 * other key is the file owner's and is kept exactly as it was.
 */
export function readLease(path) {
  let lease;
  try {
    lease = JSON.parse(readFileSync(path, 'utf8'));
  } catch (e) {
    throw new Error(`${path} is not a lease file this tool can read: ${e.message}`);
  }
  if (typeof lease !== 'object' || lease === null || Array.isArray(lease)) {
    throw new Error(`${path} is not a lease file: a JSON object with workload_id and root_secret`);
  }
  if (typeof lease.workload_id !== 'string' || !HEX64.test(lease.workload_id)) {
    throw new Error(`${path} names no workload_id: 64 lowercase hex characters, the id the spawn named`);
  }
  // The VALUES are never quoted back: they are what the whole lease hangs on.
  if (typeof lease.root_secret !== 'string' || !HEX64.test(lease.root_secret)) {
    throw new Error(`${path} holds no root_secret: 64 lowercase hex characters, the secret the lease was spawned from`);
  }
  const { rotation } = lease;
  if (rotation !== undefined) {
    const members = rotation?.members;
    const confirmed = rotation?.confirmed;
    if (
      typeof rotation?.root_secret !== 'string' ||
      !HEX64.test(rotation.root_secret) ||
      !Array.isArray(members) ||
      !Array.isArray(confirmed) ||
      !confirmed.every((c) => members.includes(c))
    ) {
      throw new Error(`${path}'s rotation record is damaged: { root_secret, members, confirmed } with confirmed a subset of members`);
    }
  }
  return lease;
}

/**
 * Replace the lease file, mode 0600 (it holds root secrets), by writing a
 * sibling and renaming it over the original: a reader never sees half a file,
 * and a crash mid-write leaves the previous one whole.
 */
export function writeLease(path, lease) {
  const next = `${path}.${process.pid}.tmp`;
  writeFileSync(next, `${JSON.stringify(lease, null, 2)}\n`, { mode: 0o600 });
  renameSync(next, path);
}

// ── one member ────────────────────────────────────────────────────────────

/** An answer, said in a line that carries no token: the code, or the status. */
const said = (answer) =>
  answer.lost !== undefined
    ? `no answer (${answer.lost})`
    : answer.body?.error !== undefined
      ? `${answer.body.error}: ${answer.body.message ?? ''}`.trim()
      : `HTTP ${answer.status}`;

/** `ask`, with a throw turned into the same "no answer" a refused packet is. */
async function asking(ask, destination, body, member) {
  try {
    return await ask(destination, body, member);
  } catch (e) {
    return { lost: e?.message ?? String(e) };
  }
}

/**
 * Rotate one member, and find out whether it took.
 *
 * A rotate is NOT retried to learn whether it worked (spec §6.8): the same
 * request again is `stale_request`, and a new one presenting the old token
 * after the first took effect is `not_tenant`. So when the answer is lost —
 * or is `not_tenant`, which is what an earlier run's lost answer looks like —
 * this asks `status` presenting `next`: accepted means the rotation took
 * effect, and `not_tenant` means it did not and the old token still holds.
 *
 * Resolves to `{ provider, rotated: true, recovered? }` or
 * `{ provider, rotated: false, failed }`. Neither carries a token.
 */
export async function rotateMember({ workloadId, oldRoot, newRoot, member, ask, now, log = () => {} }) {
  const { provider, address } = member;
  const request = rotateRequest({ workloadId, oldRoot, newRoot, provider, now: now() });
  const answer = await asking(ask, `${address}.rotate`, { request }, member);

  if (answer.status === 200) {
    if (answer.body?.workload_id === workloadId && answer.body?.rotated === true) {
      log(`${provider.slice(0, 12)}… rotated`);
      return { provider, rotated: true };
    }
    // Not the answer §6.8 gives; whatever it was, `status` says which token holds.
  } else if (answer.lost === undefined && answer.body?.error !== 'not_tenant') {
    // A refusal that is about the lease or the request, not the token:
    // `expired`, `unknown_workload`, `invalid_request`, `stale_request`.
    // Nothing changed there, and asking again would not change it.
    log(`${provider.slice(0, 12)}… refused: ${said(answer)}`);
    return { provider, rotated: false, failed: said(answer) };
  }

  log(`${provider.slice(0, 12)}… ${said(answer)}; asking status with the new token`);
  const probe = await asking(
    ask,
    `${address}.status`,
    { request: statusRequest({ workloadId, root: newRoot, provider, now: now() }) },
    member,
  );
  if (probe.status === 200 && probe.body?.workload_id === workloadId) {
    log(`${provider.slice(0, 12)}… holds the new token: rotated`);
    return { provider, rotated: true, recovered: true };
  }
  const failed =
    `rotate: ${said(answer)}; status with the new token: ${said(probe)}` +
    (probe.body?.error === 'not_tenant' ? ' — not rotated, the old token still holds it; run again' : '');
  log(`${provider.slice(0, 12)}… ${failed}`);
  return { provider, rotated: false, failed };
}

// ── the whole set ─────────────────────────────────────────────────────────

/**
 * Rotate every member of the Standby Set named in `members` (primary first,
 * each `{ provider, address, sealKey }`), one request per member naming only
 * that member (spec §6.8, §7), and keep the lease file true throughout.
 *
 * - A FRESH root secret is minted for the rotation (`mint`), and each
 *   member's `next` is the token it derives for that member — so the old root
 *   secret, if that is what leaked, derives nothing that works afterwards.
 * - It is written into the lease file (`rotation.root_secret`) before any
 *   request leaves, and becomes `root_secret` only once EVERY member has
 *   confirmed. Until then the old one stays, because the members that have
 *   not confirmed are still read with it.
 * - A lease file that already records a rotation is RESUMED, never restarted:
 *   the same new root secret, the members already confirmed left alone, and
 *   the rest asked again — which is how a member that was unreachable, or a
 *   run that was interrupted, is finished. A resumed rotation must name the
 *   same members it started with.
 *
 * `ask(destination, body, member)` sends one packet and resolves to
 * `{ status, body }` for an answer, or `{ lost: why }` when none came back.
 * `seal.mjs` fills it with a packet sealed to the member's pinned key.
 *
 * Resolves to `{ workload_id, rotated, members: [{ provider, rotated, recovered?, failed? }] }`,
 * where `rotated` is true only when every member confirmed. Nothing in it is
 * a secret: the new root secret is in the lease file and nowhere else.
 */
export async function rotateLease({
  leaseFile,
  members,
  ask,
  mint = newRootSecret,
  now = () => Math.floor(Date.now() / 1000),
  log = () => {},
}) {
  const problem = membersProblem(members);
  if (problem !== null) throw new Error(problem);
  const lease = readLease(leaseFile);
  const workloadId = lease.workload_id;
  const oldRoot = lease.root_secret;
  const named = members.map((m) => m.provider);

  let rotation = lease.rotation;
  if (rotation === undefined) {
    const newRoot = mint();
    if (!HEX64.test(newRoot) || newRoot === oldRoot) {
      throw new Error('the new root secret must be 64 lowercase hex and not the one the lease holds');
    }
    rotation = { root_secret: newRoot, members: named, confirmed: [] };
    writeLease(leaseFile, { ...lease, rotation });
    log(`workload ${workloadId}: a fresh root secret, recorded in ${leaseFile} before anything is sent`);
  } else {
    const same = rotation.members.length === named.length && rotation.members.every((m) => named.includes(m));
    if (!same) {
      throw new Error(
        `${leaseFile} records a rotation of ${rotation.members.length} member(s) still under way; ` +
          'finish it naming the same members, or the ones left out would be read with a root secret this file no longer holds',
      );
    }
    log(`workload ${workloadId}: resuming the rotation ${leaseFile} records (${rotation.confirmed.length} of ${named.length} confirmed)`);
  }

  const confirmed = new Set(rotation.confirmed);
  const outcomes = [];
  for (const member of members) {
    if (confirmed.has(member.provider)) {
      outcomes.push({ provider: member.provider, rotated: true });
      continue;
    }
    const outcome = await rotateMember({
      workloadId,
      oldRoot,
      newRoot: rotation.root_secret,
      member,
      ask,
      now,
      log,
    });
    outcomes.push(outcome);
    if (outcome.rotated) {
      confirmed.add(member.provider);
      // Recorded member by member, so a run that stops here resumes after it.
      rotation = { ...rotation, confirmed: named.filter((m) => confirmed.has(m)) };
      writeLease(leaseFile, { ...lease, rotation });
    }
  }

  const done = named.every((m) => confirmed.has(m));
  if (done) {
    // Every member now holds a token of the new root: the old one reads
    // nothing anywhere, so it is dropped rather than kept.
    const { rotation: _finished, ...rest } = lease;
    writeLease(leaseFile, { ...rest, root_secret: rotation.root_secret, rotated_at: now() });
    log(`every member rotated; ${leaseFile} holds the new root secret only`);
  } else {
    log(`${confirmed.size} of ${named.length} member(s) rotated; ${leaseFile} keeps both root secrets until the rest confirm — run again to finish`);
  }
  return { workload_id: workloadId, rotated: done, members: outcomes };
}

/**
 * The `ask` seam filled by a connector client: one packet to `destination`,
 * sealed to the member's PINNED key through the client's own sealing path
 * (`sealTo`, ADR 0011), exactly as `handover.mjs`'s `sealedSender` seals to a
 * gateway's. A packet that was not fulfilled is `{ lost }`: whether it reached
 * the provider is not known, which is precisely the case `status` settles.
 */
export const sealedAsker = (client) => async (destination, body, member) => {
  const answer = await client.send(destination, { body }, { sealTo: sealKeyBytes(member.sealKey.replace(/^0x/, '')) });
  if (!answer.fulfilled) {
    return { lost: `${destination} refused by ${answer.refusedBy}: ${answer.code} ${answer.message}` };
  }
  let parsed = null;
  try {
    parsed = answer.json();
  } catch {
    /* not JSON: said by its status alone */
  }
  return { status: answer.status, body: parsed };
};
