// What a Gateway Grant says, what is refused before one is signed, and how
// one is published (spec §3.1.3, §6.5; TOON_Network #48).
//
// Kept apart from `publish.mjs` because that file reads the environment,
// opens a payment channel and exits: these are the decisions worth testing
// on their own (`node --test`), and they are pure. The one seam a publication
// crosses is the relay writer it is handed:
//
//   writeTo(relay, event) -> null on success, or a string saying why not
//
// which is the directory publisher's own shape (tools/publisher/publish.mjs,
// `writeTo`), and what `publish.mjs` fills with a paid write.
//
// A grant is signed by the TENANT and read by two parties with different
// stakes. A provider reads `workload_id`, `gateway` and `expires_at` and
// refuses anything wrong with them as `bad_grant`, after the request that
// carried the grant has already been made (§6.5). A Workload Gateway reads
// `http_port`, `standby_set` and `name` and acts on them without a provider
// ever checking them (§3.1.3). So this file refuses, BEFORE signing, every
// defect a provider would refuse and every defect a gateway would act on
// wrongly — a grant that is published broken is a relay write paid for and a
// gateway serving nothing, and neither party will say why.

import { schnorr } from '@noble/curves/secp256k1.js';
import { getEventHash, getPublicKey } from 'nostr-tools/pure';

/** Kind `30438`, addressable on `d = <workload_id>` (spec §3.1). */
export const K_GATEWAY_GRANT = 30438;
/** The label every published TOON Network event carries (spec §3.1). */
export const TOON_LABEL = 'toon.network';

/** The address a gateway or a tenant reads a grant at: `30438:<tenant>:<workload_id>`. */
export const grantAddress = (tenant, workloadId) => `${K_GATEWAY_GRANT}:${tenant}:${workloadId}`;

const HEX64 = /^[0-9a-f]{64}$/;

/**
 * Why `key` is not a public key this tool will name, or `null`.
 *
 * Hex only, and lowercase: the provider compares keys as keys, not as
 * strings, so an uppercase spelling would verify — but the `p` tag is what
 * a gateway FILTERS on, and a relay filter is a string comparison. A grant
 * whose `p` tag spells the gateway's key differently from the gateway's own
 * filter is a grant the gateway never finds.
 */
function publicKeyProblem(what, key) {
  if (key === undefined || key === null || key === '') {
    return `${what} is required: the 64-hex Nostr public key it names`;
  }
  const shown = JSON.stringify(key);
  if (typeof key !== 'string') return `${what} ${shown} is not a public key: 64 hex characters`;
  if (/^[0-9A-Fa-f]{64}$/.test(key) && key !== key.toLowerCase()) {
    return `${what} ${shown} must be lowercase hex: a relay's \`p\` filter compares strings, and a gateway filters on its own spelling`;
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
export function dnsLabelProblem(name) {
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
 * Why this grant must not be signed, or `null` if it may be.
 *
 * `now` is unix seconds. Everything a provider checks from the grant alone
 * (§6.5: the workload id, the gateway, the expiry) and everything a gateway
 * would act on unchecked (§3.1.3: the port, the Standby Set, the name) is
 * checked here, in the order a tenant reads the content.
 */
export function checkGrant({ workloadId, gateway, httpPort, ports, standbySet, expiresAt, name }, now) {
  if (typeof workloadId !== 'string' || !HEX64.test(workloadId)) {
    return `the workload id ${JSON.stringify(workloadId)} must be 64 lowercase hex characters, the id the spawn was signed with (spec §6.2)`;
  }

  const gatewayProblem = publicKeyProblem('the gateway', gateway);
  if (gatewayProblem !== null) return gatewayProblem;

  if (!Array.isArray(standbySet) || standbySet.length === 0) {
    return 'the Standby Set must name at least one provider, the primary first (--standby <pubkey>, once per member)';
  }
  for (const [i, member] of standbySet.entries()) {
    const problem = publicKeyProblem(`Standby Set member ${i + 1}`, member);
    if (problem !== null) return problem;
  }

  if (!Array.isArray(ports) || ports.length === 0) {
    return "the spawn's container ports (--ports) must name at least one port, so http_port can be checked against them";
  }
  if (!Number.isInteger(httpPort) || httpPort < 1 || httpPort > 65535) {
    return `http_port must be an integer between 1 and 65535 (--http-port), not ${JSON.stringify(httpPort)}`;
  }
  if (!ports.includes(httpPort)) {
    return (
      `http_port ${httpPort} is not one of the spawn's container ports (${ports.join(', ')}): ` +
      'a gateway would forward to a port the workload never asked for'
    );
  }

  if (!Number.isInteger(expiresAt)) {
    return `expires_at must be unix seconds, not ${JSON.stringify(expiresAt)}`;
  }
  // The provider's rule is `now <= expires_at` (§6.5), so a grant expiring
  // this very second is not yet expired there — and is expired by the time
  // a gateway has read it from a relay and carried it. Neither is worth a
  // relay write.
  if (expiresAt < now) {
    return (
      `expires_at ${expiresAt} is already past (now ${now}): a provider refuses an expired grant as bad_grant, ` +
      'and there is no renewing one except by publishing it again with a later expiry'
    );
  }
  if (expiresAt === now) {
    return `expires_at ${expiresAt} is now: the grant would be expired by the time a Workload Gateway carried it`;
  }

  if (name !== undefined) {
    const problem = dnsLabelProblem(name);
    if (problem !== null) return problem;
  }
  return null;
}

/**
 * The unsigned Gateway Grant for `grant` (spec §3.1.3), refused with a
 * thrown explanation when `checkGrant` would refuse it. `createdAt` is the
 * moment of signing, in unix seconds, and is also the clock the expiry is
 * checked against.
 *
 * The content is written in the order §3.1.3 declares its fields —
 * `workload_id, gateway, http_port, standby_set, expires_at, name?` — and
 * NOT sorted. The provider's own builder serialises it that way, the wire
 * fixture's `id` is the hash of that exact string, and the fixture checker
 * copies the signed string rather than rebuilding it. A tool that sorted
 * keys would sign a different event from the one the fixtures prove.
 */
export function grantEvent(grant, createdAt) {
  const problem = checkGrant(grant, createdAt);
  if (problem !== null) throw new Error(problem);
  const { workloadId, gateway, httpPort, standbySet, expiresAt, name } = grant;
  const content = {
    workload_id: workloadId,
    gateway,
    http_port: httpPort,
    standby_set: [...standbySet],
    expires_at: expiresAt,
    ...(name === undefined ? {} : { name }),
  };
  return {
    kind: K_GATEWAY_GRANT,
    created_at: createdAt,
    tags: [
      ['d', workloadId],
      ['p', gateway],
      ['L', TOON_LABEL],
    ],
    content: JSON.stringify(content),
  };
}

/**
 * Sign `unsigned` with the tenant's secret key (32 bytes): NIP-01's id over
 * `[0, pubkey, created_at, kind, tags, content]`, then BIP-340 Schnorr over
 * that id.
 *
 * `auxRand` is the signature's auxiliary randomness. Left out — always, in
 * use — it is drawn fresh, as BIP-340 intends. The wire fixtures were
 * generated with 32 zero bytes so their bytes are reproducible, and a test
 * passes the same to prove this tool signs the fixture's exact signature;
 * nothing else has a reason to set it.
 */
export function signGrant(unsigned, secretKey, { auxRand } = {}) {
  const pubkey = getPublicKey(secretKey);
  const id = getEventHash({ ...unsigned, pubkey });
  const sig = Buffer.from(schnorr.sign(Buffer.from(id, 'hex'), secretKey, auxRand)).toString('hex');
  return { ...unsigned, pubkey, id, sig };
}

/** Said once, here, so the command can refuse it before a channel is opened. */
export const NO_RELAY =
  'no relay to publish to: name one with --relay, or set RELAY_WRITE_ROUTES so every relay with a paid write route is used';

/**
 * Sign `grant` (the inputs `checkGrant` takes) and write it to every relay
 * in `relays` through `writeTo`. Resolves to
 *   { address, event_id, tenant, grant, event, accepted: [relay…], failed: { relay: why } }
 * where `grant` is the content as signed. A relay that refused is reported
 * in `failed`, never thrown: a grant that reached one relay of three is a
 * grant a gateway watching that relay finds.
 *
 * Nothing is signed if `checkGrant` refuses the inputs, and nothing is
 * signed for no relay at all.
 *
 * Addressable on `d = <workload_id>`, so publishing again under the same
 * tenant and workload id REPLACES the grant on a relay rather than adding
 * one (§3.1.3): a later `expiresAt` renews it, another `gateway` rotates it,
 * and there is no other renewal or rotation — a tenant that wants a gateway
 * cut off before the expiry respawns under a new workload id (§6.5).
 */
export async function publishGrant({
  grant, secretKey, relays, writeTo,
  now = () => Math.floor(Date.now() / 1000), sign = signGrant, log = () => {},
}) {
  const unsigned = grantEvent(grant, now());
  if (!Array.isArray(relays) || relays.length === 0) throw new Error(NO_RELAY);

  const event = sign(unsigned, secretKey);
  const report = { accepted: [], failed: {} };
  for (const relay of relays) {
    try {
      const why = await writeTo(relay, event);
      if (why === null) {
        report.accepted.push(relay);
        log(`published kind ${event.kind} ${event.id} to ${relay}`);
      } else {
        report.failed[relay] = why;
        log(`${relay} refused: ${why}`);
      }
    } catch (e) {
      report.failed[relay] = e?.message ?? String(e);
      log(`${relay} failed: ${report.failed[relay]}`);
    }
  }
  return {
    address: grantAddress(event.pubkey, grant.workloadId),
    event_id: event.id,
    tenant: event.pubkey,
    grant: JSON.parse(event.content),
    event,
    ...report,
  };
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

/** `--ports 80,443`: the container ports the spawn asked for, as numbers. */
export function parsePorts(text) {
  if (text === undefined) {
    throw new Error("--ports is required: the container ports the spawn asked for, comma-separated (e.g. 80,443)");
  }
  return String(text)
    .split(',')
    .map((p) => p.trim())
    .map((p) => {
      if (!/^\d+$/.test(p)) throw new Error(`--ports ${JSON.stringify(text)}: ${JSON.stringify(p)} is not a port number`);
      return Number(p);
    });
}

/**
 * The tool's inputs from its parsed flags (`values`, as `node:util`'s
 * `parseArgs` returns them) and the environment:
 *   { grant: <checkGrant's inputs>, relays, secretKey }
 *
 * The tenant key is `--key` or `TOON_TENANT_KEY`, and is checked first: a
 * command that has no key to sign with has nothing else worth reading.
 * Relays are `--relay` (repeatable), else every relay `RELAY_WRITE_ROUTES`
 * names a paid write route for — the same map the directory publisher
 * reads, so a tenant beside one configures both the same way.
 */
export function optionsFrom(values, env, now) {
  const key = values.key ?? env.TOON_TENANT_KEY;
  if (key === undefined || key === '') throw new Error('a tenant key is required: --key <64 hex> or TOON_TENANT_KEY');
  if (!/^[0-9a-f]{64}$/i.test(key)) {
    throw new Error('the tenant key must be 64 hex characters (a Nostr secret key); this tool takes no nsec');
  }
  const secretKey = Uint8Array.from(Buffer.from(key, 'hex'));

  const relays = values.relay?.length ? [...values.relay] : Object.keys(JSON.parse(env.RELAY_WRITE_ROUTES ?? '{}'));

  const grant = {
    workloadId: values.workload,
    gateway: values.gateway,
    httpPort: values['http-port'] === undefined ? undefined : Number(values['http-port']),
    ports: parsePorts(values.ports),
    standbySet: values.standby ?? [],
    expiresAt: parseExpiry({ expiresAt: values['expires-at'], expiresIn: values['expires-in'] }, now),
    name: values.name,
  };
  return { grant, relays, secretKey };
}
