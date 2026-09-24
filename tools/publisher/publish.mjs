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
import { createHiddenServiceTransport } from '@toon-protocol/client/hidden-service';
import { lookup } from 'node:dns/promises';
import { isNearUrl, isRpcTarget, isTrue, proxyFor, startupRefusal } from './proxy.mjs';

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

// Which ILP carriage the packets are paid over. `http` — a one-shot POST per
// packet — is the default and was the only behaviour: publishing is a handful
// of packets a minute, already serialized below, and BTP's ordered socket buys
// nothing for that. But a node may PIN a route to one carriage. The devnet
// relay pins `g.toon.relay` to BTP, and an HTTP one-shot there is refused with
// `extra.requiredTransport` — so a publisher against such a relay writes
// nothing at all until this is `auto`, which dials whatever the node's own
// self-description asks for. `proxy.mjs`'s `transportRefusal` is where the two
// things the HTTP carriage carries and a websocket does not are refused rather
// than lost: the SOCKS5h proxy and the endpoint rewrite, both of which live
// inside this process's `fetch`.
const TRANSPORT = process.env.TOON_TRANSPORT ?? 'http';

// Hiding this process's own hop (spec §10, ADR 0008). The provider app sends
// the proxy IN each publish request — it is the process that knows whether it
// is hidden — and these two are the operator's side of the same fact:
// TOON_SOCKS_PROXY is the default for requests that name none, and TOON_HIDDEN
// says this publisher sits beside a hidden provider, where running without a
// proxy is a refusal to start rather than a quiet leak.
const SOCKS_PROXY = process.env.TOON_SOCKS_PROXY;
const HIDDEN = isTrue(process.env.TOON_HIDDEN);

// Whether the chain RPC is near enough to dial directly: loopback, a private
// range, or a name resolving only to those — what a hidden provider's own
// settlement RPC has to be (ADR 0008), and what `anon` can build no circuit
// to. Resolved once, on the first proxied request, because it is a fact about
// the deployment and not about the publication. Anywhere else, the RPC leaves
// this host like everything else and rides the proxy with it.
let rpcIsNear = null;
const rpcNear = () => (rpcIsNear ??= isNearUrl(RPC_URL, lookup));

// A connector's self-description advertises the endpoint a client should dial,
// and the client dials THAT, not the URL it was configured with — one free GET
// is the whole of bootstrapping. When the advertised address is one this
// process cannot reach, this rewrites it. That is a deployment fact, not a
// protocol one: the sandbox's hub advertises `http://127.0.0.1:3200/ilp`
// because its smoke tests run on the host, and a container on the compose
// network reaches the same node at `http://relay-connector:3000`.
//   TOON_ENDPOINT_REWRITE='{"http://127.0.0.1:3200":"http://relay-connector:3000"}'
const ENDPOINT_REWRITE = Object.entries(JSON.parse(process.env.TOON_ENDPOINT_REWRITE ?? '{}'));

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
 * The `fetch` this process pays through, and how to shut it down.
 *
 * With no proxy it is the global one, rewritten — exactly what this process
 * did before hidden providers existed. With one it is the client library's
 * SOCKS5h carriage, and it applies to EVERY host, not only `.anyone` ones: a
 * hidden provider whose payer reached a clearnet hub directly would have named
 * this host to the hub, whatever the connector's address looked like. The
 * chain RPC is the one exception, and `isRpcTarget` says why.
 */
function carriageThrough(socksProxy) {
  if (socksProxy === undefined) {
    return { fetch: (input, init) => fetch(rewrite(input), init), close: async () => {} };
  }
  const transport = createHiddenServiceTransport(socksProxy);
  return {
    fetch: async (input, init) => {
      const url = rewrite(input);
      if (isRpcTarget(url, RPC_URL) && (await rpcNear())) return fetch(url, init);
      return transport.fetch(url, init);
    },
    close: () => transport.close(),
  };
}

// Relay READ url -> the paid ILP destination that writes to it. The provider
// knows relays by the URL it publishes and a tenant reads; only this process
// needs to know what buying a write to one costs and where to buy it.
//   RELAY_WRITE_ROUTES='{"ws://relay:7100":"g.toon.relay"}'
const WRITE_ROUTES = JSON.parse(process.env.RELAY_WRITE_ROUTES ?? '{}');

if (!MNEMONIC) {
  console.error('[publisher] TOON_MNEMONIC is required: this process pays for every relay write.');
  process.exit(1);
}
const refusal = startupRefusal({
  hidden: HIDDEN,
  socksProxy: SOCKS_PROXY,
  transport: TRANSPORT,
  endpointRewrite: Object.fromEntries(ENDPOINT_REWRITE),
});
if (refusal !== null) {
  console.error(`[publisher] ${refusal}`);
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

/**
 * One client, created once and shared by every publication — but keyed by the
 * proxy it dials through.
 *
 * Keyed rather than global because the route is a property of the PUBLICATION:
 * a provider that becomes hidden (or stops being) says so in its next request,
 * and a channel opened over the old route would keep paying over it. In
 * practice the key never changes after the first request, so this is one
 * client for the life of the process, as before. Publications are serialized
 * (`serialize`), so nothing is in flight while it is swapped.
 */
let current = null;

async function client(socksProxy) {
  if (current !== null && current.proxy !== socksProxy) {
    const stale = current;
    current = null;
    await stale.carriage.close().catch(() => {});
  }
  if (current === null) {
    const carriage = carriageThrough(socksProxy);
    const entry = { proxy: socksProxy, carriage, promise: null };
    entry.promise = (async () => {
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
        // One-shot and stateless by default, which is what publishing is: a
        // handful of packets a minute, already serialized below. `auto` is
        // for a relay that PINS its write route to BTP, where a one-shot is
        // refused outright; TOON_TRANSPORT, above, says what that costs.
        transport: TRANSPORT,
        // The carriage, never `socksProxy:` — the library's own option
        // refuses a proxy beside a clearnet connector as pointless
        // misdirection, and for a hidden PROVIDER (as opposed to a tenant
        // dialling a hidden connector) covering the clearnet hop is the whole
        // point.
        fetch: carriage.fetch,
      });
      const opened = await c.channel.open({ deposit: DEPOSIT });
      console.log(
        `[publisher] paying ${CONNECTOR} from ${c.identity?.solanaPublicKey ?? '(unknown)'} ` +
          `on channel ${opened.channelId ?? '(id unreported)'}` +
          (socksProxy === undefined ? '' : ` through ${socksProxy}`),
      );
      return c;
    })().catch(async (e) => {
      // Do not cache a failed bring-up: the validator or the hub may simply
      // not be up yet, and the next publication should try again.
      if (current === entry) current = null;
      await carriage.close().catch(() => {});
      throw e;
    });
    current = entry;
  }
  return current.promise;
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
async function writeTo(relay, event, socksProxy) {
  const destination = WRITE_ROUTES[relay];
  if (!destination) {
    return `no paid write route configured for ${relay} (set RELAY_WRITE_ROUTES)`;
  }

  const c = await client(socksProxy);
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

async function publish({ event, relays, proxy }) {
  const report = { accepted: [], failed: {} };
  for (const relay of relays ?? []) {
    try {
      const why = await writeTo(relay, event, proxy);
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
      return answer(400, { error: 'body must be { event, relays, proxy? }' });
    }
    // The route this publication takes, decided before anything is paid for:
    // a request that names a proxy this process cannot honour must not be
    // answered by quietly going direct.
    let proxy;
    try {
      proxy = proxyFor(request, SOCKS_PROXY);
    } catch (e) {
      return answer(400, { error: e.message });
    }
    serialize(() => publish({ ...request, proxy })).then(
      (report) => answer(200, report),
      // The publication could not be ATTEMPTED — no channel, no hub. That is
      // an error, not a per-relay refusal, and the provider logs it and
      // carries on.
      (e) => answer(502, { error: e?.message ?? String(e) }),
    );
  });
});

server.listen(PORT, BIND, () => {
  console.log(
    `[publisher] listening on ${BIND}:${PORT}; write routes ${JSON.stringify(WRITE_ROUTES)}; ` +
      (SOCKS_PROXY === undefined
        ? 'dialling directly unless a request names a proxy'
        : `dialling through ${SOCKS_PROXY}`),
  );
});
