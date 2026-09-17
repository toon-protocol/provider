#!/usr/bin/env node
// The grant tool: a tenant signs and publishes a Gateway Grant from its own
// key (spec §3.1.3; TOON_Network #48), so that a Workload Gateway can read
// its workload's lease state without ever holding that key.
//
//   node publish.mjs --workload <64 hex> --gateway <pubkey> \
//       --http-port <container port> --ports <port,port,…> \
//       --standby <pubkey> [--standby <pubkey>…] \
//       (--expires-at <unix seconds> | --expires-in <24h | 90m | 7d | seconds>) \
//       [--name <label>] [--relay <ws://…>…] [--key <64 hex>] [--dry-run]
//
//   --workload    the workload id the spawn was signed with
//   --gateway     the Workload Gateway's Nostr public key: the ONE key the
//                 grant admits to `status`
//   --http-port   which of the spawn's container ports carries HTTP — the
//                 port the gateway forwards to; must be one of --ports
//   --ports       every `container_port` the spawn asked for, so the port
//                 above can be checked against them before anything is signed
//   --standby     the Standby Set, primary FIRST, one flag per member; a
//                 standalone lease's is its one provider
//   --expires-at  when the grant stops admitting the gateway, or
//   --expires-in  the same as a duration from now; there is no other
//                 revocation, so keep it short and publish again to renew
//   --name        an optional short name the gateway may serve the workload
//                 at beside its canonical label: a single DNS label
//   --relay       a relay to publish to (repeatable); default: every relay
//                 RELAY_WRITE_ROUTES names a paid write route for
//   --key         the tenant's Nostr secret key, hex; or TOON_TENANT_KEY
//   --dry-run     sign, print the event, and stop: nothing is paid for
//
// Prints one JSON report on stdout — the address, the event id, the content
// as signed, and which relays accepted it — and exits 0 when at least one
// relay did. Progress goes to stderr. Exit 2 is a refusal before anything was
// signed or paid for; exit 1 is a publication no relay accepted.
//
// RENEWAL AND ROTATION ARE THE SAME ACT AS PUBLISHING. The grant is
// addressable on `d = <workload_id>`, so running this again under the same
// tenant key and workload id REPLACES the grant on a relay: a later expiry
// renews it, another --gateway moves the workload to that gateway. There is
// no "renew" and no "rotate" command because there is nothing else to do —
// and no revocation before expiry other than respawning under a new workload
// id (spec §6.5).
//
// A relay write on the TOON Network is a PAID packet (ADR 0007), bought
// exactly as the directory publisher buys the provider's (tools/publisher):
// one @toon-protocol/client on one payment channel, one write per relay on
// the paid route RELAY_WRITE_ROUTES maps that relay to, never on the free
// ephemeral lane. The tenant's Nostr key signs the grant; the channel's
// mnemonic pays for it; they need not be the same person's.

import { mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { parseArgs } from 'node:util';
import { ToonClient } from '@toon-protocol/client';
import { getPublicKey } from 'nostr-tools/pure';
import { checkGrant, grantAddress, grantEvent, optionsFrom, publishGrant, signGrant } from './grant.mjs';

// The payer's configuration, name for name what tools/publisher reads, so a
// tenant beside a sandbox provider sets one environment for both. Hidden
// providers' TOON_SOCKS_PROXY and TOON_HIDDEN are absent on purpose: a grant
// is a TENANT's publication, and a tenant is not what §10 hides.
const CONNECTOR = process.env.TOON_CONNECTOR_URL ?? 'http://localhost:3200';
const CHAIN = process.env.TOON_CHAIN ?? 'solana';
const RPC_URL = process.env.TOON_RPC_URL ?? 'http://127.0.0.1:8899';
const MNEMONIC = process.env.TOON_MNEMONIC;
const ACCOUNT_INDEX = Number(process.env.TOON_ACCOUNT_INDEX ?? 0);
const CHANNEL_STORE = process.env.TOON_CHANNEL_STORE ?? '.toon-client/channels.json';
const DEPOSIT = BigInt(process.env.TOON_DEPOSIT ?? '10000000'); // 10 USDC at 6dp
const TIMEOUT_MS = Number(process.env.TOON_TIMEOUT_MS ?? 60_000);
// Relay READ url -> the paid ILP destination that writes to it, exactly as
// the directory publisher has it: RELAY_WRITE_ROUTES='{"ws://relay:7100":"g.toon.relay"}'
const WRITE_ROUTES = JSON.parse(process.env.RELAY_WRITE_ROUTES ?? '{}');
// Advertised connector endpoint prefix -> where this process can reach it
// (tools/publisher/README.md, TOON_ENDPOINT_REWRITE).
const ENDPOINT_REWRITE = Object.entries(JSON.parse(process.env.TOON_ENDPOINT_REWRITE ?? '{}'));

const log = (m) => console.error(`[grant] ${m}`);

/** A refusal before anything is signed or paid for: say why, and stop. */
function refuse(problem) {
  console.error(`[grant] ${problem}`);
  process.exit(2);
}

/** The header comment above, as the command's own help. */
function usage(problem) {
  if (problem) console.error(`[grant] ${problem}\n`);
  console.error(
    readFileSync(new URL(import.meta.url), 'utf8')
      .split('\n')
      .filter((l) => l.startsWith('//'))
      .map((l) => l.slice(3))
      .join('\n'),
  );
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

/** One paying client, opened once a grant has passed every check. */
async function openClient() {
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
    // One-shot and stateless, which is what publishing is (tools/publisher).
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

/** Buy one write of `event` to one relay through `client`. Null on success. */
const paidWriter = (client) => async (relay, event) => {
  const destination = WRITE_ROUTES[relay];
  const answer = await client.send(destination, {
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ event }),
  });
  if (!answer.fulfilled) {
    return `${destination} refused by ${answer.refusedBy}: ${answer.code} ${answer.message}`;
  }
  if (answer.status !== 200) {
    return `${destination} answered HTTP ${answer.status}: ${answer.text().slice(0, 200)}`;
  }
  return null;
};

async function main() {
  let parsed;
  try {
    parsed = parseArgs({
      allowPositionals: false,
      options: {
        workload: { type: 'string' },
        gateway: { type: 'string' },
        'http-port': { type: 'string' },
        ports: { type: 'string' },
        standby: { type: 'string', multiple: true },
        'expires-at': { type: 'string' },
        'expires-in': { type: 'string' },
        name: { type: 'string' },
        relay: { type: 'string', multiple: true },
        key: { type: 'string' },
        'dry-run': { type: 'boolean' },
        help: { type: 'boolean', short: 'h' },
      },
    });
  } catch (e) {
    usage(e.message);
  }
  const { values } = parsed;
  if (values.help) usage();

  const now = Math.floor(Date.now() / 1000);

  // Every refusal here happens before a key signs anything and before a
  // channel is opened: a grant a provider would refuse, or a gateway would
  // act on wrongly, is not worth a relay write.
  let options;
  try {
    options = optionsFrom(values, process.env, now);
  } catch (e) {
    refuse(e.message);
  }
  const { grant, relays, secretKey } = options;
  const problem = checkGrant(grant, now);
  if (problem !== null) refuse(`refused before signing: ${problem}`);

  const tenant = getPublicKey(secretKey);
  log(`tenant ${tenant} grants ${grant.gateway} status on workload ${grant.workloadId}`);
  log(
    `until ${grant.expiresAt} (${new Date(grant.expiresAt * 1000).toISOString()}); ` +
      `http_port ${grant.httpPort} of ${grant.ports.join(', ')}; ` +
      `standby set ${grant.standbySet.join(', ')}` +
      (grant.name === undefined ? '' : `; name ${grant.name}`),
  );

  if (values['dry-run']) {
    const event = signGrant(grantEvent({ ...grant, createdAt: now, now }), secretKey);
    console.log(JSON.stringify({ address: grantAddress(tenant, grant.workloadId), event_id: event.id, relays, event }, null, 2));
    return 0;
  }

  if (relays.length === 0) {
    refuse('no relay to publish to: name one with --relay, or set RELAY_WRITE_ROUTES so every relay with a paid write route is used');
  }
  for (const relay of relays) {
    const destination = WRITE_ROUTES[relay];
    if (!destination) refuse(`no paid write route configured for ${relay} (set RELAY_WRITE_ROUTES)`);
    if (destination.endsWith('.ephemeral')) {
      refuse(
        `RELAY_WRITE_ROUTES maps ${relay} to ${destination}, the FREE EPHEMERAL LANE. ` +
          'A grant is a paid addressable event and must not be sent on it (ADR 0007).',
      );
    }
  }
  if (!MNEMONIC) refuse('TOON_MNEMONIC is required: a relay write is a paid packet, and this is what pays for it');

  const client = await openClient();
  try {
    const report = await publishGrant({ ...grant, secretKey, relays, writeTo: paidWriter(client), now: () => now, log });
    const { event, ...printed } = report;
    console.log(JSON.stringify({ ...printed, event }, null, 2));
    log(`kind ${event.kind} ${event.id.slice(0, 12)}…: ${report.accepted.length} accepted, ${Object.keys(report.failed).length} failed`);
    return report.accepted.length > 0 ? 0 : 1;
  } finally {
    await client.close?.();
  }
}

main().then(
  (code) => process.exit(code),
  (e) => {
    console.error(`[grant] failed: ${e?.message ?? e}`);
    process.exit(1);
  },
);
