#!/usr/bin/env node
// The handover tool: a tenant chooses a Workload Gateway, or stops one
// serving (spec §6.5.1, §12; TOON_Network #59). It derives the Gateway
// Grant from the lease's root secret and seals the message to the gateway's
// own connector. No key, no signature, no relay, nothing published. And it
// rotates the lease's Continuation Tokens (spec §6.8; TOON_Network #75),
// which is what takes every grant of the old ones back.
//
//   node seal.mjs handover (--root-secret <64 hex> --workload <64 hex> | --lease <lease.json>) \
//       --standby <pubkey> [--standby <pubkey>…] --http-port <container port> \
//       [--ports <port,port,…>] [--name <label>] \
//       (--expires-at <unix seconds> | --expires-in <24h | 90m | 7d | seconds>) \
//       --gateway-route <ilp address> --gateway-seal-key <hex> [--dry-run]
//
//   node seal.mjs withdrawal (--root-secret <64 hex> --workload <64 hex> | --lease <lease.json>) \
//       --standby <pubkey> [--standby <pubkey>…] --expires-at <unix seconds> \
//       --gateway-route <ilp address> --gateway-seal-key <hex> [--dry-run]
//
//   node seal.mjs rotate --lease <lease.json> \
//       --member <pubkey>,<ilp address>,<seal key>[,<connector>] [--member …]
//
//   handover      choose this gateway: the workload id, the Standby Set, the
//                 HTTP container port, the grant's moment, the grant itself
//                 and an optional readable name
//   withdrawal    stop this gateway serving the workload, bearing the grant
//                 currently in force — the moment the handover named
//   rotate        replace the lease's Continuation Token at EVERY member of
//                 its Standby Set (spec §6.8): mint a fresh root secret, send
//                 each member one rotate naming only itself, and record the
//                 new root in the lease file. This is the one thing that also
//                 ends a gateway's READING: every grant of the old root is
//                 `bad_grant` from then on. Hand over again to keep a gateway
//
//   --root-secret the lease's root secret, 64 hex; or TOON_ROOT_SECRET. The
//                 only secret this tool takes: there is no Nostr key here.
//                 Refused together with --lease, which names one instead
//   --workload    the workload id the spawn was signed with. Refused
//                 together with --lease, which names one instead
//   --standby     the Standby Set, primary FIRST, one flag per member; a
//                 standalone lease's is its one provider. One grant is
//                 derived PER MEMBER, because a grant derives from that
//                 member's own Continuation Token (spec §6.1.1, §7)
//   --http-port   which of the spawn's container ports carries HTTP — the
//                 port the gateway forwards to; must be one of --ports
//   --ports       every `container_port` the spawn asked for, so the port
//                 above can be checked against them before anything is sent
//   --expires-at  the moment the grant is derived for, or
//   --expires-in  the same as a duration from now (handover only; a
//                 withdrawal names the moment its handover named)
//   --name        an optional short name the gateway may serve the workload
//                 at beside the canonical one: a single DNS label
//   --gateway-route     the ILP address the gateway's connector terminates
//   --gateway-seal-key  that connector's PINNED secp256k1 key, hex. It is
//                 pinned out of band exactly as a Provider Profile's is
//                 (ADR 0011): nothing is fetched to learn it
//   --dry-run     derive the message, print it, and stop. Nothing is paid
//                 for, no channel is opened and nothing is installed. Not for
//                 `rotate`, which is nothing until the members have it
//   --lease       the lease file — a JSON object holding the `workload_id`
//                 and the `root_secret` (the sandbox's spawn.mjs writes
//                 one), and while a rotation is unfinished, `rotation`
//                 (spec §6.8): `{ root_secret: <new>, members, confirmed }`.
//                 handover and withdrawal READ it: each member's grant is
//                 derived from ITS OWN current root — the new one where
//                 confirmed, the old one otherwise — and --root-secret /
//                 --workload are refused alongside it. rotate reads it AND
//                 writes it back: the new root secret goes in BEFORE a
//                 request leaves, and replaces the old one only once every
//                 member has confirmed. A file that records an unfinished
//                 rotation is resumed, by rotate, and READ AROUND, by the
//                 other two — either way this tool prints a warning, with no
//                 secret in it, when the file names one
//   --member      rotate: one member of the Standby Set, primary first, as
//                 <pubkey>,<ilp address>,<seal key> — its Profile's
//                 `ilp_address` and pinned `connector_seal_key` (ADR 0011) —
//                 plus, ONLY for a member reached directly rather than
//                 through the connector TOON_CONNECTOR_URL names, a fourth
//                 field: the URL to dial it at. A Hidden Provider's is such a
//                 member (spec §10, §12.8; TOON_Network #81): its connector is
//                 an `.anyone` address a hub does not peer with, so it is
//                 dialled over anon — TOON_SOCKS_PROXY is then required — on
//                 its own chain and RPC port (TOON_HIDDEN_*, below). Free
//                 routes need no channel, so nothing is paid for there
//
// Prints one JSON report on stdout and progress on stderr. Exit 0 when the
// gateway took the message (or on a dry run) or every member rotated, 1 when
// it did not, and 2 for a refusal before anything was derived or paid for.
//
// A GRANT ROTATES BY RE-DERIVATION AT A LATER MOMENT. The same root secret,
// Standby Set and `expires_at` give the same grant on any machine, so run
// `handover` again with a later `--expires-at` and the gateway holds a grant
// that outlives the one it had.
//
// A WITHDRAWAL ENDS SERVING, NOT READING. The withdrawn gateway keeps the
// grant it was handed and reads the lease's `status` until `expires_at`. To
// end the reading too, `rotate`: that revokes every grant derived from the
// old token at once (spec §6.5.1, §6.8).
//
// The message is sealed to the gateway's pinned key by the connector
// client's OWN sealing path — `sealTo`, the same path a tenant's request to a
// provider takes (ADR 0011) — so the channel is the one the protocol already
// relies on to be unauthenticated and deniable, and there is no second
// sealing implementation here. Reaching a gateway's connector is a packet
// like any other, so this process holds a payment channel exactly as the
// directory publisher does (tools/publisher).

import { mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { parseArgs } from 'node:util';

import {
  checkHandover,
  checkWithdrawal,
  gatewayProblem,
  handOver,
  handoverFor,
  optionsFrom,
  rotationWarning,
  sealedSender,
  withdraw,
  withdrawalFor,
} from './handover.mjs';
import { directedAsk, membersProblem, parseMember, readLease, resumeProblem, rotateLease, sealedAsker } from './rotate.mjs';

// The payer's configuration, name for name what tools/publisher reads, so a
// tenant beside a sandbox provider sets one environment for both. There is no
// RELAY_WRITE_ROUTES: this tool writes to no relay.
const CONNECTOR = process.env.TOON_CONNECTOR_URL ?? 'http://localhost:3200';
const CHAIN = process.env.TOON_CHAIN ?? 'solana';
const RPC_URL = process.env.TOON_RPC_URL ?? 'http://127.0.0.1:8899';
const MNEMONIC = process.env.TOON_MNEMONIC;
const ACCOUNT_INDEX = Number(process.env.TOON_ACCOUNT_INDEX ?? 0);
const CHANNEL_STORE = process.env.TOON_CHANNEL_STORE ?? '.toon-client/channels.json';
const DEPOSIT = BigInt(process.env.TOON_DEPOSIT ?? '10000000'); // 10 USDC at 6dp
const TIMEOUT_MS = Number(process.env.TOON_TIMEOUT_MS ?? 60_000);
// Advertised connector endpoint prefix -> where this process can reach it
// (tools/publisher/README.md, TOON_ENDPOINT_REWRITE).
const ENDPOINT_REWRITE = Object.entries(JSON.parse(process.env.TOON_ENDPOINT_REWRITE ?? '{}'));

// `rotate` ONLY (spec §10, §12.8; TOON_Network #81): a Hidden Provider's
// connector is an `.anyone` address a hub does not peer with, so a `--member`
// naming one (its optional fourth field, `parseMember`) is dialled DIRECTLY,
// over anon, rather than through the client above. TOON_SOCKS_PROXY is
// required whenever a member does; the rest default to what the sandbox's
// hidden path already uses (`infra/sandbox/scripts/smoke-milestone4.mjs`) —
// its own chain, its own RPC port on the member's own connector host, and no
// deposit, because `<addr>.rotate` and `<addr>.status` are free routes (spec
// §5, §6.8): a hidden member's client never opens a channel at all.
const SOCKS_PROXY = process.env.TOON_SOCKS_PROXY;
const HIDDEN_CHAIN = process.env.TOON_HIDDEN_CHAIN ?? 'evm';
const HIDDEN_RPC_PORT = process.env.TOON_HIDDEN_RPC_PORT ?? '8545';
const HIDDEN_ACCOUNT_INDEX = Number(process.env.TOON_HIDDEN_ACCOUNT_INDEX ?? ACCOUNT_INDEX);
const HIDDEN_CHANNEL_STORE = process.env.TOON_HIDDEN_CHANNEL_STORE ?? '.toon-client/hidden-channels.json';

const log = (m) => console.error(`[handover] ${m}`);

/** A refusal before anything is derived or paid for: say why, and stop. */
function refuse(problem) {
  console.error(`[handover] ${problem}`);
  process.exit(2);
}

/**
 * The header comment above, as the command's own help.
 *
 * The LEADING block only — the lines from the shebang to the first line that
 * is not a comment. Everything below that is a note to whoever is reading the
 * code, and a tenant asking `--help` is not.
 */
function usage(problem) {
  if (problem) console.error(`[handover] ${problem}\n`);
  const header = [];
  for (const line of readFileSync(new URL(import.meta.url), 'utf8').split('\n').slice(1)) {
    if (!line.startsWith('//')) break;
    header.push(line.slice(3));
  }
  console.error(header.join('\n'));
  process.exit(problem ? 2 : 0);
}

/** The URL a request really goes to: every advertised prefix swapped. */
const rewrite = (input) => {
  let url = typeof input === 'string' ? input : input?.url ?? String(input);
  for (const [from, to] of ENDPOINT_REWRITE) {
    if (url.startsWith(from)) {
      url = to + url.slice(from.length);
      break;
    }
  }
  return url;
};

/**
 * One paying client, opened only once a message has passed every check.
 *
 * `@toon-protocol/client` is imported HERE and not at the top of the file, so
 * that `--dry-run` — which sends nothing — runs on a checkout where `npm
 * install` has never been run. Deriving a grant needs nothing but Node.
 */
async function openClient() {
  const { ToonClient } = await import('@toon-protocol/client');
  mkdirSync(dirname(CHANNEL_STORE), { recursive: true });
  const client = await ToonClient.create({
    connector: CONNECTOR,
    mnemonic: MNEMONIC,
    accountIndex: ACCOUNT_INDEX,
    chain: CHAIN,
    rpcUrl: RPC_URL,
    channelStore: CHANNEL_STORE,
    deposit: DEPOSIT,
    timeoutMs: TIMEOUT_MS,
    // One-shot and stateless, which is what handing over is (tools/publisher).
    transport: 'http',
    fetch: (input, init) => fetch(rewrite(input), init),
  });
  const opened = await client.channel.open({ deposit: DEPOSIT });
  log(
    `paying ${CONNECTOR} from ${client.identity?.solanaPublicKey ?? '(unknown)'} ` +
      `on channel ${opened.channelId ?? '(id unreported)'}`,
  );
  return client;
}

/**
 * `rotate` only: a client that dials `connector` DIRECTLY, over anon when it
 * names an `.anyone` host, instead of through the shared client above — the
 * one path a Hidden Provider's own connector allows (spec §10, Appendix A;
 * TOON_Network #81). No channel is opened: `<addr>.rotate` and `<addr>.status`
 * are free routes (spec §5, §6.8), so nothing here is paid for. The RPC port
 * is the member's own connector host on `HIDDEN_RPC_PORT` — the same address
 * the sandbox's hidden path already reaches its chain at
 * (`infra/sandbox/scripts/smoke-milestone4.mjs`).
 */
async function openHiddenClient(connector) {
  const { ToonClient } = await import('@toon-protocol/client');
  const rpcUrl = `${new URL(connector).origin.replace(/:\d+$/, '')}:${HIDDEN_RPC_PORT}`;
  mkdirSync(dirname(HIDDEN_CHANNEL_STORE), { recursive: true });
  const client = await ToonClient.create({
    connector,
    socksProxy: SOCKS_PROXY,
    mnemonic: MNEMONIC,
    accountIndex: HIDDEN_ACCOUNT_INDEX,
    chain: HIDDEN_CHAIN,
    rpcUrl,
    channelStore: HIDDEN_CHANNEL_STORE,
    deposit: 0n,
    timeoutMs: TIMEOUT_MS,
  });
  log(
    `reaching ${connector} directly${SOCKS_PROXY ? ` over anon (${SOCKS_PROXY})` : ''} as ` +
      `${client.identity?.evmAddress ?? client.identity?.senderId ?? '(unknown)'} — rotate and status are free, so nothing is paid for`,
  );
  return client;
}

async function main() {
  let parsed;
  try {
    parsed = parseArgs({
      allowPositionals: true,
      options: {
        'root-secret': { type: 'string' },
        workload: { type: 'string' },
        standby: { type: 'string', multiple: true },
        'http-port': { type: 'string' },
        ports: { type: 'string' },
        'expires-at': { type: 'string' },
        'expires-in': { type: 'string' },
        name: { type: 'string' },
        'gateway-route': { type: 'string' },
        'gateway-seal-key': { type: 'string' },
        'dry-run': { type: 'boolean' },
        lease: { type: 'string' },
        member: { type: 'string', multiple: true },
        help: { type: 'boolean', short: 'h' },
      },
    });
  } catch (e) {
    usage(e.message);
  }
  const { values, positionals } = parsed;
  if (values.help) usage();
  if (positionals.length > 1) {
    usage(`one thing is sealed at a time, not ${positionals.join(' and ')}`);
  }
  if (positionals[0] === 'rotate') return rotate(values);
  if (values.member !== undefined) refuse(`--member is rotate's: a ${positionals[0] ?? 'message'} takes --standby and a root secret`);

  const now = Math.floor(Date.now() / 1000);

  // --lease is the lease file rotate.mjs also reads: a handover or a
  // withdrawal off it reads each member's OWN current token (spec §6.8;
  // TOON_Network #80) instead of one flat root secret, and --root-secret /
  // TOON_ROOT_SECRET / --workload have nowhere to go alongside it.
  let leaseRecord;
  if (values.lease !== undefined) {
    for (const flag of ['root-secret', 'workload']) {
      if (values[flag] !== undefined) {
        refuse(`--${flag} is read from --lease ${values.lease}; pass one or the other`);
      }
    }
    try {
      leaseRecord = readLease(values.lease);
    } catch (e) {
      refuse(e.message);
    }
    const warning = rotationWarning(leaseRecord.rotation);
    if (warning !== null) log(`warning: ${warning}`);
  }

  // Every refusal below happens before a channel is opened and before a
  // packet leaves: a message a gateway would act on wrongly, or a grant a
  // provider would refuse, is not worth a paid packet.
  let options;
  try {
    options = optionsFrom(positionals[0], values, process.env, now, leaseRecord);
  } catch (e) {
    refuse(e.message);
  }
  // Which of the two messages this is, asked once: everything below differs
  // only in which pure function derives it and which name it is reported
  // under, because a withdrawal goes to the same place over the same channel.
  const withdrawing = options.handover === undefined;
  const subject = withdrawing ? options.withdrawal : options.handover;
  const { gateway } = options;

  const problem =
    (withdrawing ? checkWithdrawal(subject) : checkHandover(subject, now)) ??
    gatewayProblem(gateway);
  if (problem !== null) refuse(`refused before sealing: ${problem}`);

  const members = subject.standbySet.length;
  log(
    `${withdrawing ? 'withdrawal' : 'handover'} of workload ${subject.workloadId} ` +
      `to ${gateway.route}: ` +
      `${members === 1 ? 'one grant' : `${members} grants, one per member of the Standby Set`} ` +
      `for ${subject.expiresAt} (${new Date(subject.expiresAt * 1000).toISOString()})`,
  );

  if (values['dry-run']) {
    const message = withdrawing
      ? { withdrawal: withdrawalFor(subject) }
      : { handover: handoverFor(subject, now) };
    console.log(
      JSON.stringify(
        {
          dry_run: true,
          workload_id: subject.workloadId,
          gateway: { route: gateway.route, seal_key: gateway.sealKey },
          ...message,
        },
        null,
        2,
      ),
    );
    return 0;
  }

  if (!MNEMONIC) {
    refuse(
      'TOON_MNEMONIC is required: a packet to a gateway\'s connector is paid for, ' +
        'and this is what pays for it',
    );
  }

  const client = await openClient();
  try {
    const send = sealedSender(client, gateway.sealKey);
    const report = withdrawing
      ? await withdraw({ withdrawal: subject, gateway, send, log })
      : await handOver({ handover: subject, gateway, send, now: () => now, log });
    console.log(JSON.stringify(report, null, 2));
    return report.delivered ? 0 : 1;
  } finally {
    await client.close?.();
  }
}

/**
 * `rotate`: every member of the Standby Set, one request each, and the lease
 * file kept true throughout (`rotate.mjs`, spec §6.8).
 *
 * The root secret is the lease file's and nothing else's. `--root-secret` and
 * `TOON_ROOT_SECRET` are not read: a rotation WRITES a root secret, and one
 * taken from the command line would have nowhere to be written back to.
 */
async function rotate(values) {
  for (const flag of ['root-secret', 'workload', 'standby', 'http-port', 'ports', 'expires-at', 'expires-in', 'name', 'gateway-route', 'gateway-seal-key']) {
    if (values[flag] !== undefined) {
      refuse(`--${flag} is not rotate's: a rotation reads the workload and the root secret from --lease, and reaches each member through --member`);
    }
  }
  if (values['dry-run']) {
    refuse('a rotation has no dry run: the new root secret is nothing until the members hold it, and it is written to the lease file before anything is sent');
  }
  if (values.lease === undefined) refuse('--lease <lease.json> is required: the file holding the workload id and the root secret, which the new one is written back to');

  let members;
  let lease;
  try {
    members = (values.member ?? []).map(parseMember);
    lease = readLease(values.lease);
  } catch (e) {
    refuse(e.message);
  }
  const problem = membersProblem(members) ?? resumeProblem(values.lease, lease, members);
  if (problem !== null) refuse(`refused before sending: ${problem}`);

  // A member naming its own connector (`parseMember`'s optional fourth field)
  // is a Hidden Provider, dialled DIRECTLY over anon rather than through the
  // shared client (spec §10, §12.8; TOON_Network #81) — split them apart
  // before anything is opened, so only the clients this run actually needs
  // get opened at all.
  const hidden = members.filter((m) => m.connector !== undefined);
  const clearnet = members.filter((m) => m.connector === undefined);
  if (hidden.length > 0 && !SOCKS_PROXY) {
    refuse(
      `TOON_SOCKS_PROXY is required to reach ${hidden.map((m) => m.provider.slice(0, 12)).join(', ')} at its connector: ` +
        'an .anyone address is never resolved or dialled directly (spec §10, §12.8) — socks5h://<host>:<port> to a running anon daemon',
    );
  }
  if (!MNEMONIC) {
    refuse(
      'TOON_MNEMONIC is required: it derives this process\'s identity' +
        (clearnet.length > 0 ? ', and pays the hub fee on a clearnet member\'s free route' : ''),
    );
  }

  log(
    `rotate ${members.length === 1 ? 'the one member' : `all ${members.length} members of the Standby Set`}, one request each` +
      (hidden.length > 0 ? ` (${hidden.length} of them dialled directly, over anon: ${hidden.map((m) => m.provider.slice(0, 12)).join(', ')})` : ''),
  );

  const clients = [];
  const unopened = (kind) => () => { throw new Error(`no ${kind} member named, yet one was asked that way`); };
  try {
    let clearnetAsk = unopened('clearnet');
    if (clearnet.length > 0) {
      const client = await openClient();
      clients.push(client);
      clearnetAsk = sealedAsker(client);
    }
    let hiddenAsk = unopened('hidden');
    if (hidden.length > 0) {
      // Every hidden member dialled here shares ONE connector in the sandbox
      // today; a distinct client is still opened per distinct connector, so a
      // Standby Set naming two different hidden providers works the same way.
      const askByConnector = new Map();
      for (const member of hidden) {
        if (!askByConnector.has(member.connector)) {
          const client = await openHiddenClient(member.connector);
          clients.push(client);
          askByConnector.set(member.connector, sealedAsker(client));
        }
      }
      hiddenAsk = (destination, body, member) => askByConnector.get(member.connector)(destination, body, member);
    }

    const report = await rotateLease({ leaseFile: values.lease, members, ask: directedAsk(clearnetAsk, hiddenAsk), log });
    console.log(JSON.stringify(report, null, 2));
    if (report.rotated) log('every grant derived from the old root secret is refused now: hand over again (`handover`) to keep a gateway');
    return report.rotated ? 0 : 1;
  } finally {
    for (const client of clients) await client.close?.();
  }
}

main().then(
  (code) => process.exit(code),
  (e) => {
    console.error(`[handover] failed: ${e?.message ?? e}`);
    process.exit(1);
  },
);
