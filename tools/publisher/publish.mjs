// The directory publisher: the provider's payer for relay writes.
//
// A relay write on the TOON Network is a PAID packet (ADR 0007), and paying
// one means holding a payment channel on Solana or EVM, signing a balance
// proof per packet and sealing an ILP prepare to the terminating connector's
// key. There is exactly one proven implementation of that — @toon-protocol/
// client — and it is not a Rust crate. So the provider app decides WHAT to
// publish and this process decides HOW it is paid for. The seam between them
// is one HTTP call:
//
//   POST /publish  { "event": <signed nostr event>, "relays": ["ws://…"] }
//   -> 200         { "accepted": ["ws://…"], "failed": { "ws://…": "why" } }
//
// Nothing here signs or inspects the event: the provider's Nostr key never
// leaves the provider. This process holds money, not identity.
//
// The write goes on the PAID relay route and never on the free ephemeral lane,
// whose rate limit is keyed by remote address and is therefore shared by every
// provider behind one connector (ADR 0007). RELAY_WRITE_ROUTES is what makes
// that explicit: it names, per relay, the paid ILP destination to buy.

import { createServer } from 'node:http';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { ToonClient } from '@toon-protocol/client';

const PORT = Number(process.env.PORT ?? 8081);
const BIND = process.env.BIND_ADDR ?? '0.0.0.0';
const CONNECTOR = process.env.TOON_CONNECTOR_URL ?? 'http://localhost:3200';
const CHAIN = process.env.TOON_CHAIN ?? 'solana';
const RPC_URL = process.env.TOON_RPC_URL ?? 'http://127.0.0.1:8899';
const MNEMONIC = process.env.TOON_MNEMONIC;
const ACCOUNT_INDEX = Number(process.env.TOON_ACCOUNT_INDEX ?? 0);
const CHANNEL_STORE = process.env.TOON_CHANNEL_STORE ?? '/var/lib/toon-publisher/channels.json';
const DEPOSIT = BigInt(process.env.TOON_DEPOSIT ?? '10000000'); // 10 USDC at 6dp
const TIMEOUT_MS = Number(process.env.TOON_TIMEOUT_MS ?? 60_000);

// A connector's self-description advertises the endpoint a client should dial,
// and the client dials THAT, not the URL it was configured with — one free GET
// is the whole of bootstrapping. When the advertised address is one this
// process cannot reach, this rewrites it. That is a deployment fact, not a
// protocol one: the sandbox's hub advertises `http://127.0.0.1:3200/ilp`
// because its smoke tests run on the host, and a container on the compose
// network reaches the same node at `http://relay-connector:3000`.
//   TOON_ENDPOINT_REWRITE='{"http://127.0.0.1:3200":"http://relay-connector:3000"}'
const ENDPOINT_REWRITE = Object.entries(JSON.parse(process.env.TOON_ENDPOINT_REWRITE ?? '{}'));

/** `fetch`, with every advertised prefix in ENDPOINT_REWRITE swapped. */
const rewritingFetch = (input, init) => {
  let url = typeof input === 'string' ? input : input?.url ?? String(input);
  for (const [from, to] of ENDPOINT_REWRITE) {
    if (url.startsWith(from)) {
      url = to + url.slice(from.length);
      break;
    }
  }
  return fetch(url, init);
};

// Relay READ url -> the paid ILP destination that writes to it. The provider
// knows relays by the URL it publishes and a tenant reads; only this process
// needs to know what buying a write to one costs and where to buy it.
//   RELAY_WRITE_ROUTES='{"ws://relay:7100":"g.toon.relay"}'
const WRITE_ROUTES = JSON.parse(process.env.RELAY_WRITE_ROUTES ?? '{}');

if (!MNEMONIC) {
  console.error('[publisher] TOON_MNEMONIC is required: this process pays for every relay write.');
  process.exit(1);
}
for (const [relay, destination] of Object.entries(WRITE_ROUTES)) {
  if (destination.endsWith('.ephemeral')) {
    console.error(
      `[publisher] RELAY_WRITE_ROUTES maps ${relay} to ${destination}, the FREE EPHEMERAL LANE. ` +
        'Directory events are paid replaceable events and must not be sent on it (ADR 0007).',
    );
    process.exit(1);
  }
}

/** One client, created once, shared by every publication. */
let clientPromise = null;

async function client() {
  if (!clientPromise) {
    clientPromise = (async () => {
      mkdirSync(dirname(CHANNEL_STORE), { recursive: true });
      const c = await ToonClient.create({
        connector: CONNECTOR,
        mnemonic: MNEMONIC,
        accountIndex: ACCOUNT_INDEX,
        chain: CHAIN,
        rpcUrl: RPC_URL,
        channelStore: CHANNEL_STORE,
        deposit: DEPOSIT,
        timeoutMs: TIMEOUT_MS,
        // One-shot and stateless, which is what publishing is: a handful of
        // packets a minute, already serialized below. BTP's ordered socket
        // buys nothing here and would bypass the endpoint rewrite.
        transport: 'http',
        fetch: rewritingFetch,
      });
      const opened = await c.channel.open({ deposit: DEPOSIT });
      console.log(
        `[publisher] paying ${CONNECTOR} from ${c.identity?.solanaPublicKey ?? '(unknown)'} ` +
          `on channel ${opened.channelId ?? '(id unreported)'}`,
      );
      return c;
    })().catch((e) => {
      // Do not cache a failed bring-up: the validator or the hub may simply
      // not be up yet, and the next publication should try again.
      clientPromise = null;
      throw e;
    });
  }
  return clientPromise;
}

// A channel claim carries a strictly increasing nonce per channel, so two
// packets in flight at once on one channel race each other. Publications are
// therefore serialized through this tail.
let queue = Promise.resolve();

function serialize(work) {
  const result = queue.then(work, work);
  // Keep the chain alive past a rejection, but never leave one unhandled.
  queue = result.then(
    () => {},
    () => {},
  );
  return result;
}

/** Buy one write of `event` to one relay. Returns null on success. */
async function writeTo(relay, event) {
  const destination = WRITE_ROUTES[relay];
  if (!destination) {
    return `no paid write route configured for ${relay} (set RELAY_WRITE_ROUTES)`;
  }

  const c = await client();
  const answer = await c.send(destination, {
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
}

async function publish({ event, relays }) {
  const report = { accepted: [], failed: {} };
  for (const relay of relays ?? []) {
    try {
      const why = await writeTo(relay, event);
      if (why === null) {
        report.accepted.push(relay);
      } else {
        report.failed[relay] = why;
      }
    } catch (e) {
      report.failed[relay] = e?.message ?? String(e);
    }
  }
  console.log(
    `[publisher] kind ${event?.kind} ${event?.id?.slice(0, 12)}…: ` +
      `${report.accepted.length} accepted, ${Object.keys(report.failed).length} failed` +
      (Object.keys(report.failed).length
        ? ` (${Object.entries(report.failed)
            .map(([r, w]) => `${r}: ${w}`)
            .join('; ')})`
        : ''),
  );
  return report;
}

const server = createServer((req, res) => {
  const answer = (status, body) => {
    const payload = JSON.stringify(body);
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(payload);
  };

  if (req.method === 'GET' && req.url === '/health') {
    return answer(200, { status: 'ok' });
  }
  if (req.method !== 'POST' || req.url !== '/publish') {
    return answer(404, { error: 'not found' });
  }

  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    let request;
    try {
      request = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch (e) {
      return answer(400, { error: `body is not JSON: ${e.message}` });
    }
    if (!request?.event?.id || !request?.event?.sig) {
      return answer(400, { error: 'body must be { event, relays }' });
    }
    serialize(() => publish(request)).then(
      (report) => answer(200, report),
      // The publication could not be ATTEMPTED — no channel, no hub. That is
      // an error, not a per-relay refusal, and the provider logs it and
      // carries on.
      (e) => answer(502, { error: e?.message ?? String(e) }),
    );
  });
});

server.listen(PORT, BIND, () => {
  console.log(`[publisher] listening on ${BIND}:${PORT}; write routes ${JSON.stringify(WRITE_ROUTES)}`);
});
