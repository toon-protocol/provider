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
import { ToonClient, JsonFileChannelStore } from '@toon-protocol/client';
import { createHiddenServiceTransport } from '@toon-protocol/client/hidden-service';
import { lookup } from 'node:dns/promises';
import {
  carriageThrough,
  chainRpcRoute,
  clientRouteOptions,
  isTrue,
  proxyFor,
  startupRefusal,
} from './proxy.mjs';
import { estimateSpendPerCadence, loadChannelStatus, noChannelStatusBody, statusBody } from './status.mjs';
import { topup } from './topup.mjs';

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

// How often this provider writes a Liveness (TOON_Network#171, ADR 0029 §3).
// Optional: `/status` reports a runway only when it knows both this and a
// price, and says so either way rather than guessing a cadence nobody
// configured. `undefined`, not a default, when unset — 60s is true of the
// devnet compose profile but not a fact this process should assume.
const LIVENESS_CADENCE_S = (() => {
  const raw = process.env.TOON_LIVENESS_CADENCE_S;
  if (raw === undefined) return undefined;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) {
    console.error(`[publisher] TOON_LIVENESS_CADENCE_S must be a positive number of seconds, got ${JSON.stringify(raw)}.`);
    process.exit(1);
  }
  return n;
})();

// Which ILP carriage the packets are paid over. `http` — a one-shot POST per
// packet — is the default and was the only behaviour: publishing is a handful
// of packets a minute, already serialized below, and BTP's ordered socket buys
// nothing for that. But a node may PIN a route to one carriage. The devnet
// relay pins `g.toon.relay` to BTP, and an HTTP one-shot there is refused with
// `extra.requiredTransport` — so a publisher against such a relay writes
// nothing at all until this is `btp` (or `auto`, which dials whatever the
// node's own self-description asks for). Either rides the proxy and the
// endpoint rewrite exactly as HTTP does: `carriageThrough` hands the client a
// socket factory that takes the same route as its `fetch` (TOON_Network#165).
const TRANSPORT = process.env.TOON_TRANSPORT ?? 'http';

// Hiding this process's own hop (spec §10, ADR 0008). The provider app sends
// the proxy IN each publish request — it is the process that knows whether it
// is hidden — and these two are the operator's side of the same fact:
// TOON_SOCKS_PROXY is the default for requests that name none, and TOON_HIDDEN
// says this publisher sits beside a hidden provider, where running without a
// proxy is a refusal to start rather than a quiet leak.
const SOCKS_PROXY = process.env.TOON_SOCKS_PROXY;
const HIDDEN = isTrue(process.env.TOON_HIDDEN);

// Whether the chain RPC rides the proxy beside one (spec §10, ADR 0030). A
// hidden payer's chain RPC does by default — the public preset, on a circuit
// pinned per chain — and TOON_PROXY_RPC=false sends it directly, for a node
// the operator runs on a private address, which no exit could reach. The
// hidden overlay sets it exactly when the operator self-hosts; unset, a
// private address literal or compose name is dialled directly and anything
// else rides the proxy (`chainRpcRoute`). Decided once, at startup, because
// it is a fact about the deployment and not about the publication.
const PROXY_RPC = process.env.TOON_PROXY_RPC;

// A connector's self-description advertises the endpoint a client should dial,
// and the client dials THAT, not the URL it was configured with — one free GET
// is the whole of bootstrapping. When the advertised address is one this
// process cannot reach, this rewrites it, for the `fetch` and the BTP socket
// alike (`proxy.mjs`, `rewriteUrl`). That is a deployment fact, not a protocol
// one: the sandbox's hub advertises `http://127.0.0.1:3200/ilp` because its
// smoke tests run on the host, and a container on the compose network reaches
// the same node at `http://relay-connector:3000`.
//   TOON_ENDPOINT_REWRITE='{"http://127.0.0.1:3200":"http://relay-connector:3000"}'
const ENDPOINT_REWRITE = Object.entries(JSON.parse(process.env.TOON_ENDPOINT_REWRITE ?? '{}'));

/** What `carriageThrough` dials with: this host's own, and the library's proxy. */
const DIAL = {
  createHiddenServiceTransport,
  fetch: (input, init) => fetch(input, init),
  WebSocket: globalThis.WebSocket,
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
const rpcRoute = await chainRpcRoute({ hidden: HIDDEN, rpcUrl: RPC_URL, proxyRpc: PROXY_RPC }, lookup);
const refusal =
  startupRefusal({ hidden: HIDDEN, socksProxy: SOCKS_PROXY, transport: TRANSPORT }) ??
  rpcRoute.refusal ??
  null;
if (refusal !== null) {
  console.error(`[publisher] ${refusal}`);
  process.exit(1);
}
const RPC_PROXIED = rpcRoute.proxyRpc;
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
    // The client first: beside a proxy it owns the circuits its own
    // `socksProxy` opened, and holds them open until it is closed.
    await stale.promise.then((c) => c.close()).catch(() => {});
    await stale.carriage.close().catch(() => {});
  }
  if (current === null) {
    const carriage = carriageThrough(socksProxy, ENDPOINT_REWRITE, DIAL);
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
        // handful of packets a minute, already serialized below. `btp` is
        // for a relay that PINS its write route to BTP, where a one-shot is
        // refused outright; TOON_TRANSPORT, above, says what that costs.
        transport: TRANSPORT,
        // The route (`clientRouteOptions`). Beside a proxy that is the
        // client's own `socksProxy`, which makes it a HIDDEN PAYER
        // (TOON_Network#167): the edge, the BTP socket and the chain RPC all
        // ride it, each chain's RPC on a pinned circuit of its own, failing
        // closed — so a hidden provider's publisher can pay from the public
        // preset RPC rather than a node of its own (spec §10, ADR 0030), and
        // `proxyRpc: false` only for an RPC on a private address. With no
        // proxy, the direct carriage, rewritten.
        ...clientRouteOptions(socksProxy, carriage, RPC_PROXIED),
      });
      const opened = await c.channel.open({ deposit: DEPOSIT });
      console.log(
        `[publisher] paying ${CONNECTOR} from ${c.identity?.solanaPublicKey ?? '(unknown)'} ` +
          `on channel ${opened.channelId ?? '(id unreported)'}` +
          (socksProxy === undefined
            ? ''
            : ` through ${socksProxy}, chain RPC ${RPC_PROXIED ? 'through it too' : 'direct (a private address)'}`),
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

// The channel store this process's client already writes
// (`ChannelManager`/`JsonFileChannelStore`, `channels.json` +
// `channels.peers.json`). `/status` reads it directly rather than through a
// live client — a status read must never build one, since building one can
// open a channel (`ChannelFacade.open`/`ensure`).
const channelStore = new JsonFileChannelStore(CHANNEL_STORE);

const server = createServer((req, res) => {
  const answer = (status, body) => {
    const payload = JSON.stringify(body);
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(payload);
  };

  if (req.method === 'GET' && req.url === '/health') {
    return answer(200, { status: 'ok' });
  }

  // `/status` and `/topup` are private in exactly the way `/publish` is: this
  // process listens on `BIND_ADDR`/`PORT` only, the compose file never
  // publishes it (`expose:`, no `ports:`), and nothing here checks who is
  // asking — reaching this listener at all is what the deploy shape treats as
  // authorization (tools/publisher/README.md, deploy/README.md "Privacy and
  // exposure invariants").
  if (req.method === 'GET' && req.url === '/status') {
    const channel = loadChannelStatus(channelStore);
    if (channel === null) {
      return answer(200, noChannelStatusBody(LIVENESS_CADENCE_S));
    }
    // Only ask the connector what a write costs right now if this process has
    // already talked to it — a status read must not be what causes the first
    // connection, let alone the first channel.
    const priceOf =
      current === null
        ? undefined
        : async (destination) => {
            const c = await current.promise;
            return c.price(destination);
          };
    const assumptions = [];
    return estimateSpendPerCadence(WRITE_ROUTES, priceOf, assumptions)
      .then((pricePerCadence) => {
        const body = statusBody({ ...channel, pricePerCadence, cadenceS: LIVENESS_CADENCE_S });
        body.assumptions = [...assumptions, ...body.assumptions];
        answer(200, body);
      })
      .catch((e) => answer(502, { error: e?.message ?? String(e) }));
  }

  if (req.method === 'POST' && req.url === '/topup') {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      let request;
      try {
        request = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      } catch (e) {
        return answer(400, { error: `body is not JSON: ${e.message}` });
      }
      if (request?.amount === undefined) {
        return answer(400, { error: 'body must be { amount }' });
      }
      // Serialized behind the same queue as `/publish`: a deposit and a claim
      // both touch this channel's tracked state, and the client is not safe
      // to use from two calls at once.
      serialize(() => topup(() => client(SOCKS_PROXY), request.amount)).then(
        (body) => {
          console.log(`[publisher] topped up channel ${body.channelId} to ${body.deposit}`);
          answer(200, body);
        },
        (e) => {
          const badRequest = e instanceof RangeError || e instanceof TypeError;
          answer(badRequest ? 400 : 502, { error: e?.message ?? String(e) });
        },
      );
    });
    return;
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
