// What a Gateway Handover and a Gateway Withdrawal say, what is refused
// before one is sealed, and how the grant inside one is derived (spec §6.1.1,
// §6.5.1; TOON_Network #59).
//
// Kept apart from `seal.mjs` because that file reads the environment, opens a
// payment channel and exits: these are the decisions worth testing on their
// own (`node --test`), and they are pure.

import { hkdfSync } from 'node:crypto';

/** The HKDF `info` prefix a Continuation Token is derived under (spec §6.1.1). */
export const CONTINUATION_DOMAIN = 'toon-network-continuation:';
/** The HKDF `info` prefix a Gateway Grant is derived under (spec §6.5.1). */
export const GATEWAY_DOMAIN = 'toon-network-gateway:';

/**
 * 32 bytes of HKDF-SHA256 over `ikm` under `info`, as 64 lowercase hex
 * characters: RFC 5869 with an empty salt (its own default, which extracts
 * with 32 zero bytes) and an ASCII `info`. One function for both derivations,
 * exactly as the provider's `expand` is (src/nostr/continuation.rs), so the
 * two cannot drift on the thing they must agree about.
 */
const expand = (ikmHex, info) =>
  Buffer.from(hkdfSync('sha256', Buffer.from(ikmHex, 'hex'), Buffer.alloc(0), info, 32)).toString('hex');

/**
 * The Continuation Token a lease presents to `provider` (spec §6.1.1):
 *
 *   continuation(provider) = HKDF-SHA256(root, "toon-network-continuation:" || provider_pubkey)
 *
 * `rootSecret` and `provider` are 64 lowercase hex characters each; the
 * provider's key goes into `info` spelled exactly so.
 */
export const continuationFor = (rootSecret, provider) => expand(rootSecret, `${CONTINUATION_DOMAIN}${provider}`);

/**
 * The Gateway Grant a lease's token derives for the moment `expiresAt`
 * (spec §6.5.1):
 *
 *   gateway_sub(provider, expires_at) = HKDF-SHA256(continuation(provider),
 *                                           "toon-network-gateway:" || expires_at)
 *
 * `expiresAt` is unix seconds, spelled in `info` as unpadded decimal.
 */
export const gatewaySub = (continuation, expiresAt) => expand(continuation, `${GATEWAY_DOMAIN}${expiresAt}`);

/** 32 bytes as 64 lowercase hex: a root secret, a token, a workload id, a key. */
export const HEX64 = /^[0-9a-f]{64}$/;

/**
 * Why `key` is not a provider's public key this tool will name, or `null`.
 *
 * Lowercase hex, and nothing else: the key goes into the derivation's `info`
 * spelled exactly as the spec spells it (§6.1.1), so a key written any other
 * way would derive a token the provider does not hold.
 */
export function publicKeyProblem(what, key) {
  if (key === undefined || key === null || key === '') {
    return `${what} is required: the 64-hex Nostr public key it names`;
  }
  const shown = JSON.stringify(key);
  if (typeof key !== 'string') return `${what} ${shown} is not a public key: 64 hex characters`;
  if (/^[0-9A-Fa-f]{64}$/.test(key) && key !== key.toLowerCase()) {
    return `${what} ${shown} must be lowercase hex: the key is spelled into the derivation, and the provider spells it lowercase (spec §6.1.1)`;
  }
  if (!HEX64.test(key)) {
    return `${what} ${shown} is not a public key: 64 hex characters (an x-only Nostr public key; this tool takes no npub)`;
  }
  return null;
}

/**
 * Why `name` is not a single DNS label, or `null`.
 *
 * The gateway serves `<name>.<gateway-domain>`, so a name is exactly one
 * label: 1 to 63 characters of lowercase letters, digits and hyphens, not
 * starting or ending with a hyphen, and no dots. Each rule is named on its
 * own, because "not a DNS label" tells a tenant nothing about which
 * character to change.
 */
function dnsLabelProblem(name) {
  const shown = JSON.stringify(name);
  if (typeof name !== 'string') return `name ${shown} must be a string`;
  if (name === '') return `name ${shown} is empty; a single DNS label has 1 to 63 characters`;
  if (name.includes('.')) {
    return `name ${shown} is not a single DNS label: no dots — the gateway serves <name>.<gateway-domain>, one label`;
  }
  if (name.length > 63) return `name ${shown} is ${name.length} characters; a DNS label has at most 63`;
  if (name !== name.toLowerCase()) {
    return `name ${shown} must be lowercase: a hostname is case-insensitive, and the gateway serves it lowercase`;
  }
  if (name.startsWith('-') || name.endsWith('-')) return `name ${shown} may not start or end with a hyphen`;
  if (!/^[a-z0-9-]+$/.test(name)) return `name ${shown} may carry only letters, digits and hyphens`;
  return null;
}

/**
 * Why `rotation` is not a lease's rotation record, or `null` — also when
 * there is none to check (spec §6.8; TOON_Network #80). A lease file keeps
 * `{ root_secret: <new>, members: [<pubkey>…], confirmed: [<pubkey>…] }`
 * while a rotation is unfinished; `confirmed` names the members already
 * reading the new root, and must be a subset of `members`.
 */
export function rotationProblem(rotation) {
  if (rotation === undefined) return null;
  const { root_secret: newRoot, members, confirmed } = rotation ?? {};
  if (
    typeof newRoot !== 'string' ||
    !HEX64.test(newRoot) ||
    !Array.isArray(members) ||
    !Array.isArray(confirmed) ||
    !confirmed.every((c) => members.includes(c))
  ) {
    // Never the VALUE, for the same reason a root secret is not: it is a
    // second root secret, and just as live.
    return 'a rotation record must be { root_secret, members, confirmed }: 64-hex root_secret and confirmed a subset of members';
  }
  return null;
}

/**
 * The root secret that reads ONE member's lease right now (spec §6.8;
 * TOON_Network #80): `rotation.root_secret` — the NEW one — when `provider`
 * has confirmed it, `rootSecret` — the OLD one — for every other member, and
 * always when `rotation` is `undefined`.
 *
 * This is the one seam every tenant tool derives a member's token or grant
 * through, so a Standby Set rotated at some members and not others is read
 * correctly wherever it is addressed member by member: a handover, a
 * withdrawal, a termination, a status check.
 */
export function currentRootFor(rootSecret, rotation, provider) {
  return rotation !== undefined && rotation.confirmed.includes(provider) ? rotation.root_secret : rootSecret;
}

/**
 * Why a tenant should see this before a tool derives anything from
 * `rotation` — a rotation still under way — or `null` when there is none.
 * Names how many of how many members have confirmed and how to finish it.
 * Carries no secret: neither root secret, old or new, appears in it.
 */
export function rotationWarning(rotation) {
  if (rotation === undefined) return null;
  return (
    `a rotation is unfinished (${rotation.confirmed.length} of ${rotation.members.length} member(s) confirmed): ` +
    'each member is read with its OWN current token — the new one where confirmed, the old one otherwise. ' +
    "Finish it with `seal.mjs rotate` (or the sandbox's `node scripts/rotate.mjs <lease.json>`), naming the same members."
  );
}

/**
 * Why nothing should be derived for these inputs, or `null`: the root secret,
 * the workload id and the Standby Set, which a handover and a withdrawal both
 * take, and without which there is no grant to derive. `rotation`, when
 * given, is the lease's own unfinished-rotation record (above).
 */
function leaseProblem({ rootSecret, rotation, workloadId, standbySet }) {
  if (typeof rootSecret !== 'string' || !HEX64.test(rootSecret)) {
    // The VALUE is never in the message: a refusal must not quote a secret back.
    return 'the root secret must be 64 lowercase hex characters, the secret the lease was spawned from (spec §6.1.1)';
  }
  const rotationIssue = rotationProblem(rotation);
  if (rotationIssue !== null) return rotationIssue;
  if (typeof workloadId !== 'string' || !HEX64.test(workloadId)) {
    return `the workload id ${JSON.stringify(workloadId)} must be 64 lowercase hex characters, the id the spawn named (spec §6.2)`;
  }
  if (!Array.isArray(standbySet) || standbySet.length === 0) {
    return 'the Standby Set must name at least one provider, the primary first (--standby <pubkey>, once per member)';
  }
  for (const [i, member] of standbySet.entries()) {
    const problem = publicKeyProblem(`Standby Set member ${i + 1}`, member);
    if (problem !== null) return problem;
  }
  if (new Set(standbySet).size !== standbySet.length) {
    return 'the Standby Set names one provider twice';
  }
  return null;
}

/**
 * Why this handover must not be derived, or `null` if it may be.
 *
 * `now` is unix seconds. Everything a provider checks from the grant a
 * gateway will present (§6.5.1: the moment) and everything a gateway acts on
 * unchecked (the port, the Standby Set, the name) is checked here, in the
 * order a tenant reads the handover.
 */
export function checkHandover({ rootSecret, rotation, workloadId, standbySet, httpPort, ports, expiresAt, name }, now) {
  const lease = leaseProblem({ rootSecret, rotation, workloadId, standbySet });
  if (lease !== null) return lease;

  if (!Number.isInteger(httpPort) || httpPort < 1 || httpPort > 65535) {
    return `http_port must be an integer between 1 and 65535 (--http-port), not ${JSON.stringify(httpPort)}`;
  }
  if (ports !== undefined && !ports.includes(httpPort)) {
    return (
      `http_port ${httpPort} is not one of the spawn's container ports (${ports.join(', ')}): ` +
      'a gateway would forward to a port the workload never asked for'
    );
  }

  if (!Number.isInteger(expiresAt)) {
    return `expires_at must be unix seconds, not ${JSON.stringify(expiresAt)}`;
  }
  // The provider's rule is `now <= expires_at` (§6.5.1), so a grant expiring
  // this very second is not yet expired there — and is expired by the time a
  // gateway has been handed it. Neither is worth a packet.
  if (expiresAt < now) {
    return (
      `expires_at ${expiresAt} is already past (now ${now}): a provider refuses a grant for a past moment as bad_grant, ` +
      'and there is no renewing one except by deriving again for a later moment'
    );
  }
  if (expiresAt === now) {
    return `expires_at ${expiresAt} is now: the grant would be expired by the time a Workload Gateway held it`;
  }

  if (name !== undefined) {
    const problem = dnsLabelProblem(name);
    if (problem !== null) return problem;
  }
  return null;
}

/**
 * The Standby Set as a message carries it (spec §12.1): one entry per member,
 * in the set's own order and primary first, each carrying the Gateway Grant
 * derived for that member's OWN key.
 *
 *   [ { provider: "<pubkey hex>", grant: "<64 hex>" }, … ]
 *
 * Per MEMBER, because a grant derives from the lease's Continuation Token
 * and that token is per provider (spec §6.1.1, §7): the grant that reads the
 * lease at the primary is `bad_grant` at a standby. A gateway resolving a
 * workload asks every member (§12.4), so it needs one for each.
 *
 * One structure and not two parallel ones, because a member and the grant it
 * is asked with are one fact: there is no list to fall out of step with, and
 * a member cannot reach a gateway without the value that reads its lease.
 *
 * `rotation`, when given, is the lease's unfinished-rotation record: each
 * member's OWN current root (`currentRootFor`, spec §6.8) is what its grant
 * is derived from, so a handover sealed mid-rotation is one a member that has
 * already confirmed still admits — and so does one that has not.
 */
const standbySetFor = (rootSecret, rotation, providers, expiresAt) =>
  providers.map((provider) => ({
    provider,
    grant: gatewaySub(continuationFor(currentRootFor(rootSecret, rotation, provider), provider), expiresAt),
  }));

/**
 * The Gateway Handover for these inputs: what the removed Gateway Grant
 * event's content carried, less the tenant that signed it, plus the grant
 * itself — because the gateway needs all of it and can no longer read any of
 * it anywhere. Refused with a thrown explanation when `checkHandover` would
 * refuse it. `now` is the clock the expiry is checked against.
 *
 *   { workload_id, standby_set: [{ provider, grant }, …], http_port, expires_at, name? }
 *
 * Nothing about a run but its inputs decides the grant: the same root secret,
 * Standby Set and `expires_at` give the same handover on any machine.
 */
export function handoverFor(handover, now) {
  const problem = checkHandover(handover, now);
  if (problem !== null) throw new Error(problem);
  const { rootSecret, rotation, workloadId, standbySet, httpPort, expiresAt, name } = handover;
  return {
    workload_id: workloadId,
    standby_set: standbySetFor(rootSecret, rotation, standbySet, expiresAt),
    http_port: httpPort,
    expires_at: expiresAt,
    ...(name === undefined ? {} : { name }),
  };
}

// ── the gateway's connector ───────────────────────────────────────────────

/** An ILP address: `g.toon.workload-gateway.handover`, and nothing with a space in it. */
export const ILP_ADDRESS = /^[a-zA-Z0-9._~-]+$/;
/** A secp256k1 public key as hex: 65 bytes uncompressed (`04…`) or 33 compressed (`02…`/`03…`). */
export const SEAL_KEY = /^(04[0-9a-fA-F]{128}|0[23][0-9a-fA-F]{64})$/;

/**
 * Why `gateway` is not a connector this tool will seal to, or `null`.
 *
 * Two facts name a gateway's connector to a tenant: the route it terminates
 * — where the packet goes — and its sealing key, which the tenant is given
 * out of band and PINS, exactly as a Provider Profile pins a provider's
 * (ADR 0011). The key is what the payload is sealed to; the route only says
 * where to send it. Nothing is fetched to learn either.
 */
export function gatewayProblem({ route, sealKey } = {}) {
  if (route === undefined || route === null || route === '') {
    return 'the gateway route is required: the ILP address the gateway\'s connector terminates for handovers (--gateway-route)';
  }
  if (typeof route !== 'string' || !ILP_ADDRESS.test(route)) {
    return `the gateway route ${JSON.stringify(route)} is not an ILP address (letters, digits, dots, and no spaces)`;
  }
  if (sealKey === undefined || sealKey === null || sealKey === '') {
    return 'the gateway\'s sealing key is required: its connector\'s pinned secp256k1 key, hex (--gateway-seal-key)';
  }
  if (typeof sealKey !== 'string' || !SEAL_KEY.test(sealKey)) {
    return (
      'the gateway\'s sealing key must be a secp256k1 public key as hex: 65-byte uncompressed (04…, as a connector\'s ' +
      '`GET /ilp` reports it) or 33-byte compressed (02…/03…)'
    );
  }
  return null;
}

/** The pinned key as the bytes the connector client seals to (`sealTo`). */
export const sealKeyBytes = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));

/**
 * The `send` seam below, filled by a connector client: one packet to
 * `destination`, sealed to the gateway's pinned key. Null on success, or a
 * string saying why not.
 *
 * `sealTo` is the connector client's OWN sealing path — the one every tenant
 * request to a provider takes, and the one the sandbox's smokes take to a
 * provider's pinned edge. Nothing here seals anything itself (ADR 0011), and
 * the key is handed over as BYTES: it was pinned out of band, so there is no
 * `GET /ilp` to fetch it from and no hop that could name it on the gateway's
 * behalf.
 *
 * The two refusals are spelled exactly as the directory publisher spells
 * them (tools/publisher/publish.mjs), because they are the same two facts: a
 * packet that never reached the app, and an app that answered something else.
 */
export const sealedSender = (client, sealKey) => async (destination, body) => {
  const answer = await client.send(destination, { body }, { sealTo: sealKeyBytes(sealKey) });
  if (!answer.fulfilled) {
    return `${destination} refused by ${answer.refusedBy}: ${answer.code} ${answer.message}`;
  }
  if (answer.status !== 200) {
    return `${destination} answered HTTP ${answer.status}: ${answer.text().slice(0, 200)}`;
  }
  return null;
};

// ── the two messages ──────────────────────────────────────────────────────

/**
 * Seal `body` — a handover or a withdrawal, under the key `kind` names — to
 * the gateway
 * through `send`, and report. The one seam a handover crosses is the sender
 * it is handed:
 *
 *   send(destination, body) -> null on success, or a string saying why not
 *
 * which is the directory publisher's `writeTo` shape with a route in place of
 * a relay, and what `seal.mjs` fills with one paid packet sealed to the
 * gateway's pinned key — the connector client's own sealing path (ADR 0011),
 * the same one every tenant request to a provider takes.
 *
 * A refusal is reported, never thrown: the message is still in the report, so
 * a tenant sees what it derived and can try the delivery again.
 */
async function deliver(kind, body, gateway, send, log) {
  const message = { [kind]: body };
  const report = {
    workload_id: body.workload_id,
    gateway: { route: gateway.route, seal_key: gateway.sealKey },
    ...message,
  };
  try {
    const why = await send(gateway.route, message);
    if (why === null) {
      log(`sealed ${kind} to ${gateway.route}`);
      return { ...report, delivered: true };
    }
    log(`${gateway.route} refused: ${why}`);
    return { ...report, delivered: false, failed: why };
  } catch (e) {
    const why = e?.message ?? String(e);
    log(`${gateway.route} failed: ${why}`);
    return { ...report, delivered: false, failed: why };
  }
}

/**
 * Derive a Gateway Handover for `handover` (the inputs `checkHandover` takes)
 * and seal it to `gateway` through `send`. Resolves to
 *   { workload_id, gateway: { route, seal_key }, handover, delivered, failed? }
 * where `handover` is the message as sent.
 *
 * Nothing is derived if `checkHandover` or `gatewayProblem` refuses, and
 * nothing is sent then either.
 *
 * A GRANT ROTATES BY RE-DERIVATION AT A LATER MOMENT. Run this again with a
 * later `expiresAt` and the gateway holds a second grant that outlives the
 * first; the first keeps working until its own moment passes, because
 * re-deriving revokes nothing (spec §6.5.1). Only rotating the lease's token
 * does (`rotate.mjs`, §6.8), which ends every grant of the old one at once.
 */
export async function handOver({ handover, gateway, send, now = () => Math.floor(Date.now() / 1000), log = () => {} }) {
  const problem = gatewayProblem(gateway);
  if (problem !== null) throw new Error(problem);
  return deliver('handover', handoverFor(handover, now()), gateway, send, log);
}

/**
 * Why this withdrawal must not be derived, or `null`: the lease it names,
 * and the moment of the grant it bears. The moment is NOT checked against
 * the clock — a withdrawal is compared by the gateway against the grant it
 * was handed, not by a provider against `now`, so it names whatever moment
 * the handover named.
 */
export function checkWithdrawal({ rootSecret, rotation, workloadId, standbySet, expiresAt }) {
  const lease = leaseProblem({ rootSecret, rotation, workloadId, standbySet });
  if (lease !== null) return lease;
  if (!Number.isInteger(expiresAt) || expiresAt < 0) {
    return (
      'expires_at must be unix seconds, the moment the handover named, ' +
      `not ${JSON.stringify(expiresAt)}`
    );
  }
  return null;
}

/**
 * The Gateway Withdrawal for these inputs: the workload, and the grant
 * currently in force on the gateway — re-derived, because the tenant stores
 * nothing, from the same root secret and the moment the handover named.
 * Refused with a thrown explanation when `checkWithdrawal` would refuse it.
 *
 *   { workload_id, expires_at, standby_set: [{ provider, grant }, …] }
 *
 * The members are spelled exactly as a handover spells them, because they are
 * the same fact: a gateway reading one message has learned to read the other.
 *
 * A WITHDRAWAL ENDS SERVING, NOT READING. Bearing the grant is what makes it
 * safe without a signature — only the holder of the lease's token can derive
 * it — but the withdrawn gateway KEEPS that grant, and it reads the lease's
 * `status` until `expires_at` whether or not this was ever sent. This is not
 * a revocation; rotating the lease's token is (`rotate.mjs`, spec §6.8).
 */
export function withdrawalFor(withdrawal) {
  const problem = checkWithdrawal(withdrawal);
  if (problem !== null) throw new Error(problem);
  const { rootSecret, rotation, workloadId, standbySet, expiresAt } = withdrawal;
  return {
    workload_id: workloadId,
    expires_at: expiresAt,
    standby_set: standbySetFor(rootSecret, rotation, standbySet, expiresAt),
  };
}

/**
 * Derive a Gateway Withdrawal for `withdrawal` (the inputs `checkWithdrawal`
 * takes) and seal it to `gateway` through `send`. Resolves to
 *   { workload_id, gateway: { route, seal_key }, withdrawal, delivered, failed? }
 * exactly as `handOver` does, over exactly the same channel.
 */
export async function withdraw({ withdrawal, gateway, send, log = () => {} }) {
  const problem = gatewayProblem(gateway);
  if (problem !== null) throw new Error(problem);
  return deliver('withdrawal', withdrawalFor(withdrawal), gateway, send, log);
}

// ── the command line ──────────────────────────────────────────────────────

const DURATION = /^(\d+)([smhd]?)$/;
const UNIT_SECONDS = { '': 1, s: 1, m: 60, h: 3600, d: 86_400 };

/**
 * `expiresAt` as unix seconds, from `--expires-at <unix seconds>` or
 * `--expires-in <duration>` (seconds, or a number followed by `m`, `h` or
 * `d`), exactly one of the two.
 */
export function parseExpiry({ expiresAt, expiresIn }, now) {
  if (expiresAt !== undefined && expiresIn !== undefined) {
    throw new Error('give --expires-at or --expires-in, not both');
  }
  if (expiresAt !== undefined) {
    if (!/^\d+$/.test(expiresAt)) throw new Error(`--expires-at ${JSON.stringify(expiresAt)} must be unix seconds`);
    return Number(expiresAt);
  }
  if (expiresIn !== undefined) {
    const match = DURATION.exec(expiresIn);
    if (!match) {
      throw new Error(`--expires-in ${JSON.stringify(expiresIn)} must be a duration: seconds, or a number followed by m, h or d (90m, 24h, 7d)`);
    }
    return now + Number(match[1]) * UNIT_SECONDS[match[2]];
  }
  throw new Error('an expiry is required: --expires-at <unix seconds> or --expires-in <duration, e.g. 24h>');
}

/**
 * `--ports 80,443`: the container ports the spawn asked for, as numbers, so
 * `--http-port` can be checked against them; `undefined` when not given.
 */
export function parsePorts(text) {
  if (text === undefined) return undefined;
  return String(text)
    .split(',')
    .map((p) => p.trim())
    .map((p) => {
      if (!/^\d+$/.test(p)) throw new Error(`--ports ${JSON.stringify(text)}: ${JSON.stringify(p)} is not a port number`);
      return Number(p);
    });
}

/**
 * The tool's inputs from its subcommand, its parsed flags (`values`, as
 * `node:util`'s `parseArgs` returns them) and the environment:
 *   { handover: <checkHandover's inputs>, gateway }     for `handover`
 *   { withdrawal: <checkWithdrawal's inputs>, gateway } for `withdrawal`
 *
 * The root secret is `--root-secret` or `TOON_ROOT_SECRET`, and is checked
 * first: a command that has no secret to derive from has nothing else worth
 * reading. There is no key and no place to put one — this tool derives, it
 * never signs (spec §6.1.1, ADR 0016).
 *
 * `leaseRecord`, when given — a lease `rotate.mjs`'s `readLease` read off
 * `--lease` — supplies the workload id, the root secret and any unfinished
 * `rotation` record instead: the file is the tenant's one true record of
 * which root secret each member reads with right now (spec §6.8;
 * TOON_Network #80), and `--root-secret` / `TOON_ROOT_SECRET` / `--workload`
 * are refused alongside it by the caller before this is reached.
 */
export function optionsFrom(subcommand, values, env, now, leaseRecord) {
  if (subcommand !== 'handover' && subcommand !== 'withdrawal') {
    throw new Error(`the first argument is what to do: handover, withdrawal or rotate, not ${JSON.stringify(subcommand)}`);
  }
  let rootSecret;
  let workloadId;
  let rotation;
  if (leaseRecord !== undefined) {
    ({ root_secret: rootSecret, rotation } = leaseRecord);
    workloadId = leaseRecord.workload_id;
  } else {
    rootSecret = values['root-secret'] ?? env.TOON_ROOT_SECRET;
    if (rootSecret === undefined || rootSecret === '') {
      throw new Error('a root secret is required: --root-secret <64 hex> or TOON_ROOT_SECRET');
    }
    if (!HEX64.test(rootSecret)) {
      // Never quoted back: it is the secret the whole lease hangs on.
      throw new Error('the root secret must be 64 lowercase hex characters (32 bytes); this tool takes no key and no nsec');
    }
    workloadId = values.workload;
  }

  const lease = {
    rootSecret,
    ...(rotation === undefined ? {} : { rotation }),
    workloadId,
    standbySet: values.standby ?? [],
  };
  const gateway = { route: values['gateway-route'], sealKey: values['gateway-seal-key'] };

  if (subcommand === 'withdrawal') {
    // Named one by one, and never dropped. A withdrawal carries the workload
    // and its grant and nothing else — the gateway already holds the rest —
    // so a tenant that typed one of a handover's flags here has misunderstood
    // what it is sending, and should be told which flag rather than have it
    // silently ignored.
    for (const flag of ['http-port', 'ports', 'name']) {
      if (values[flag] !== undefined) {
        throw new Error(
          `--${flag} is a handover's: a withdrawal names the workload and bears its grant, ` +
            'and the gateway already holds everything else',
        );
      }
    }
    if (values['expires-in'] !== undefined) {
      throw new Error(
        'a withdrawal names the moment the handover named: --expires-at <unix seconds>, not --expires-in',
      );
    }
    return {
      withdrawal: { ...lease, expiresAt: parseExpiry({ expiresAt: values['expires-at'] }, now) },
      gateway,
    };
  }
  return {
    handover: {
      ...lease,
      httpPort: values['http-port'] === undefined ? undefined : Number(values['http-port']),
      ports: parsePorts(values.ports),
      expiresAt: parseExpiry({ expiresAt: values['expires-at'], expiresIn: values['expires-in'] }, now),
      name: values.name,
    },
    gateway,
  };
}
