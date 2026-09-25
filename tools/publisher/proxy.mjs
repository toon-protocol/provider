// Which proxy one publication goes through, and where it does NOT apply.
//
// Kept apart from `publish.mjs` because that file starts a server and demands
// a mnemonic the moment it is imported: these are the decisions worth testing
// on their own (`node --test`). They are pure; the one that builds the
// carriage, `carriageThrough`, is handed everything it dials with, and the
// two that look at the chain RPC are handed the DNS lookup.

/** Truthy env flags, as compose writes them. */
export function isTrue(value) {
  return /^(1|true|yes|on)$/i.test(String(value ?? '').trim());
}

/**
 * The `socks5h://` URL, or a thrown explanation.
 *
 * `socks5h`, never `socks5`: the trailing `h` is what makes the PROXY resolve
 * the destination's name. Under plain `socks5` this process resolves it
 * first, which for an `.anyone` connector means putting the hidden service it
 * is about to talk to into a plaintext DNS query — the one fact the hidden
 * service exists to withhold.
 */
export function validateProxy(socksProxy, where) {
  if (typeof socksProxy !== 'string' || !socksProxy.startsWith('socks5h://')) {
    const got = typeof socksProxy === 'string' ? JSON.stringify(socksProxy) : typeof socksProxy;
    throw new Error(
      `${where} must be socks5h://<host>:<port>, not ${got}: only a socks5h proxy resolves the ` +
        'destination itself, and a hidden provider must never resolve one locally.',
    );
  }
  let parsed;
  try {
    parsed = new URL(socksProxy.replace(/^socks5h:\/\//, 'http://'));
  } catch {
    throw new Error(`${where} is not a URL: ${JSON.stringify(socksProxy)}`);
  }
  if (!parsed.hostname || !parsed.port) {
    throw new Error(`${where} must name both a host and a port: ${JSON.stringify(socksProxy)}`);
  }
  return socksProxy;
}

/**
 * The proxy one publish request rides: what the request names, else what this
 * process was started with, else none at all.
 *
 * The REQUEST decides, because the provider is the process that knows whether
 * it is hidden — this one is a payer, and a payer told "pay for this, and go
 * this way" needs no second copy of the hiding config to keep in step. The
 * environment is there for the operator who wants every publication proxied
 * whatever a caller asks, and for the startup refusal below.
 *
 * Absent everywhere means direct, which is what a provider that is not hidden
 * sends and what every publisher did before the field existed.
 */
export function proxyFor(request, envProxy) {
  const named = request?.proxy;
  if (named !== undefined && named !== null) {
    return validateProxy(named, 'the publish request\'s `proxy`');
  }
  return envProxy ?? undefined;
}

/**
 * Why this publisher must not start, or `null` if it may.
 *
 * A publisher deployed beside a HIDDEN provider with no proxy is the leak the
 * provider's own hiding cannot cover: every relay write would reach the
 * connector from this host's real address, whatever the Profile claims. So it
 * is a refusal at startup rather than a per-request failure — a hidden
 * provider that cannot publish anonymously must not publish at all.
 */
export function startupRefusal({ hidden, socksProxy, transport }) {
  if (socksProxy !== undefined) {
    try {
      validateProxy(socksProxy, 'TOON_SOCKS_PROXY');
    } catch (e) {
      return e.message;
    }
  }
  if (hidden && socksProxy === undefined) {
    return (
      'TOON_HIDDEN is set, so TOON_SOCKS_PROXY is required: a publisher beside a hidden ' +
      'provider would otherwise reach the connector from this host\'s real address, which is ' +
      'the one thing the provider is hiding (spec §10, ADR 0008).'
    );
  }
  return transportRefusal({ transport });
}

/**
 * Whether the client's chain RPC rides the proxy (`{ proxyRpc: true }`), is
 * dialled directly (`{ proxyRpc: false }`), or must not be used at all
 * (`{ refusal }`). It matters only beside a proxy: with none, every dial is
 * direct, as it always was.
 *
 * Beside a proxy the client is a HIDDEN PAYER (`@toon-protocol/client` 3.3,
 * TOON_Network#167): its chain RPC rides the proxy too, on a circuit pinned
 * per chain, and fails closed. That is the default, and what a Hidden
 * Provider's publisher does with the public preset RPC (spec §10, ADR 0030).
 * The one exception is an RPC the operator runs on a private address, which
 * no exit could reach — `proxyRpc: false` sends it directly.
 *
 * `TOON_PROXY_RPC` (`proxyRpc` here) says which outright; the deploy
 * bundle's hidden overlay sets it `false` exactly when the operator
 * self-hosts. Unset, it is decided by where the RPC is, WITHOUT a lookup of
 * any name with a dot in it: a lookup from this host of the public RPC it
 * hides its address from is a leak of its own. So only an address literal,
 * `localhost`, or a one-label compose-network name (`solana-validator`) can
 * be near; anything else rides the proxy, the safe way to be wrong.
 *
 * A hidden publisher TOLD to dial directly is refused unless the RPC really
 * is near: a public RPC would see every channel open and deposit arrive from
 * this host's real address. `lookup` is `dns.promises.lookup`, as for
 * `isNearUrl`.
 */
export async function chainRpcRoute({ hidden, rpcUrl, proxyRpc }, lookup) {
  const said = String(proxyRpc ?? '').trim();
  if (said !== '' && !isTrue(said) && !isFalse(said)) {
    return { refusal: `TOON_PROXY_RPC must be true or false, not ${JSON.stringify(proxyRpc)}.` };
  }
  if (isTrue(said)) return proxied(rpcUrl);
  if (isFalse(said)) {
    if (hidden && !(await isNearUrl(rpcUrl, lookup))) {
      return {
        refusal:
          `TOON_HIDDEN is set and TOON_PROXY_RPC=false, so TOON_RPC_URL must be your own node on a ` +
          `private address, not ${JSON.stringify(rpcUrl)}: dialled directly, a public RPC would see ` +
          "this host's real address on every channel operation. Leave TOON_PROXY_RPC unset to " +
          'reach it through the proxy instead (spec §10, ADR 0030).',
      };
    }
    return { proxyRpc: false };
  }
  let host;
  try {
    host = new URL(rpcUrl).hostname.replace(/^\[|\]$/g, '');
  } catch {
    return { proxyRpc: true };
  }
  const literal = host.toLowerCase() === 'localhost' || /^[\d.]+$/.test(host) || host.includes(':');
  if (!literal && host.includes('.')) return proxied(rpcUrl);
  return (await isNearUrl(rpcUrl, lookup)) ? { proxyRpc: false } : proxied(rpcUrl);
}

/**
 * `{ proxyRpc: true }`, unless `rpcUrl` is plain `http://` to a clearnet
 * host: through an exit relay, every answer — a deposit, a receipt — could be
 * read and rewritten. The provider's gate and the connector refuse the same
 * thing; `@toon-protocol/client` does not, so it is refused here. Plain http
 * to an `.anyone` host is fine: its address authenticates the service.
 */
function proxied(rpcUrl) {
  let url;
  try {
    url = new URL(rpcUrl);
  } catch {
    return { refusal: `TOON_RPC_URL is not a URL: ${JSON.stringify(rpcUrl)}` };
  }
  if (url.protocol === 'http:' && !url.hostname.toLowerCase().endsWith('.anyone')) {
    return {
      refusal:
        `TOON_RPC_URL ${JSON.stringify(rpcUrl)} is plain http, and it would ride the proxy through ` +
        "an exit relay that can read and rewrite every answer. Use the RPC's https URL " +
        '(spec §10, ADR 0030).',
    };
  }
  return { proxyRpc: true };
}

/** Falsy env flags, as an operator writes them. */
function isFalse(value) {
  return /^(0|false|no|off)$/i.test(String(value ?? '').trim());
}

/**
 * What the client is handed about its route, for `ToonClient.create`.
 *
 * With no proxy: the direct carriage (`carriageThrough`), rewritten. Beside
 * one: `socksProxy`, which makes the client a hidden payer, plus
 * `proxyRpc: false` only when the chain RPC is to be dialled directly
 * (`chainRpcRoute`); and the carriage only when there is one, which is when
 * `TOON_ENDPOINT_REWRITE` needs its own `fetch` — itself built on
 * `createHiddenServiceTransport`, so the edge still rides the proxy.
 */
export function clientRouteOptions(socksProxy, carriage, proxyRpc) {
  const options = {};
  if (socksProxy !== undefined) {
    options.socksProxy = socksProxy;
    if (proxyRpc === false) options.proxyRpc = false;
  }
  if (carriage.fetch !== undefined) options.fetch = carriage.fetch;
  if (carriage.createWebSocket !== undefined) options.createWebSocket = carriage.createWebSocket;
  return options;
}

/** The carriages this publisher may pay over. `auto` lets the node's own route policy decide. */
export const TRANSPORTS = ['http', 'auto', 'btp'];

/**
 * Whether `TOON_TRANSPORT` names a carriage at all.
 *
 * `http` is the default: a one-shot POST per packet, which is what publishing
 * is — a handful of packets a minute, already serialized. But a node may PIN a
 * route to one carriage, and the devnet relay pins `g.toon.relay` to BTP; an
 * HTTP one-shot there comes back refused with `extra.requiredTransport` and no
 * directory event is ever written. `btp` names the socket outright, and `auto`
 * reads the pin out of the node's own self-description.
 *
 * Every carriage is allowed beside every setting. Until TOON_Network#165 a
 * proxy or an endpoint rewrite refused `btp` and `auto`, because both lived
 * only in this process's `fetch` and the BTP socket went round it — from this
 * host's real address, on a hidden box. `carriageThrough` now hands the client
 * a socket factory that takes the same route as the `fetch`, so there is
 * nothing left for the socket to go round.
 */
export function transportRefusal({ transport }) {
  if (transport === undefined || transport === '') return null;
  if (!TRANSPORTS.includes(transport)) {
    return `TOON_TRANSPORT must be one of ${TRANSPORTS.join(', ')}, not ${JSON.stringify(transport)}.`;
  }
  return null;
}

/**
 * The URL a dial really goes to: the first advertised prefix in `rewrite`
 * (`[from, to]` pairs, from `TOON_ENDPOINT_REWRITE`) swapped for the address
 * this process reaches it at.
 *
 * A websocket URL is matched against the same `http(s)://` prefixes and keeps
 * its own scheme: a node advertises `ws://host/ilp/btp` beside
 * `http://host/ilp`, and the operator names the node once, not per carriage.
 * `ws` pairs with `http` and `wss` with `https`, never across.
 */
export function rewriteUrl(url, rewrite) {
  const socket = /^wss?:\/\//.exec(url);
  const asHttp = socket ? url.replace(/^ws/, 'http') : url;
  for (const [from, to] of rewrite) {
    if (asHttp.startsWith(from)) {
      const rewritten = to + asHttp.slice(from.length);
      return socket ? rewritten.replace(/^http/, 'ws') : rewritten;
    }
  }
  return url;
}

/**
 * How this process's packets leave it: the `fetch` for the client edge and
 * the `createWebSocket` for the BTP carriage, which must always take the SAME
 * route, and how to shut them down.
 *
 * With no proxy both are this host's own, rewritten — what this process did
 * before hidden providers existed.
 *
 * Beside a proxy the client's own `socksProxy` carries everything
 * (`clientRouteOptions`): the edge, the BTP socket and the chain RPC. So
 * there is nothing to hand it, and handing it a `fetch` anyway would win over
 * its own for the edge. The one case that needs a carriage is
 * `TOON_ENDPOINT_REWRITE`, which the client does not know about: then both
 * halves are the client library's SOCKS5h carriage
 * (`createHiddenServiceTransport`), rewritten, for EVERY host — a `fetch`
 * alone is not enough, because the client would open its BTP socket itself
 * (TOON_Network#165). Chain RPC never goes through either under a proxy.
 *
 * `deps` is what it dials with — `createHiddenServiceTransport`, `fetch` and
 * `WebSocket` — so the routing is testable without a network.
 */
export function carriageThrough(socksProxy, rewrite, deps) {
  const url = (input) => rewriteUrl(typeof input === 'string' ? input : input?.url ?? String(input), rewrite);
  if (socksProxy === undefined) {
    return {
      fetch: (input, init) => deps.fetch(url(input), init),
      createWebSocket: (target) => new deps.WebSocket(url(target)),
      close: async () => {},
    };
  }
  if (rewrite.length === 0) {
    return { fetch: undefined, createWebSocket: undefined, close: async () => {} };
  }
  const transport = deps.createHiddenServiceTransport(socksProxy);
  return {
    fetch: (input, init) => transport.fetch(url(input), init),
    createWebSocket: (target) => transport.createWebSocket(url(target)),
    close: () => transport.close(),
  };
}

/** Loopback, an RFC 1918 or link-local range, ULA, or the unspecified address. */
export function isPrivateAddress(ip) {
  const address = String(ip).replace(/^\[|\]$/g, '');
  if (/^\d+\.\d+\.\d+\.\d+$/.test(address)) {
    const [a, b] = address.split('.').map(Number);
    if ([a, b].some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
    return (
      a === 127 || a === 10 || a === 0 || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 169 && b === 254)
    );
  }
  const v6 = address.toLowerCase();
  if (v6 === '::1' || v6 === '::') return true;
  // An IPv4-mapped address is the IPv4 one (`::ffff:10.0.0.4`).
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(v6);
  if (mapped) return isPrivateAddress(mapped[1]);
  // ULA fc00::/7, link-local fe80::/10.
  return /^f[cd][0-9a-f]{0,2}:/.test(v6) || /^fe[89ab][0-9a-f]?:/.test(v6);
}

/**
 * Whether reaching `url` takes no packet off this host or its own private
 * network — the same rule the provider applies to its directory publisher
 * (`is_private_url`, spec §10), and the same reason.
 *
 * The one destination a proxied publisher may still dial directly is a chain
 * RPC the operator runs on loopback or a private address (spec §10, ADR 0030):
 * `anon` builds no circuit to such an address, so proxying it would fail
 * rather than hide anything, and the packet never crosses a network anyone
 * outside can watch (`chainRpcRoute`).
 *
 * `lookup` is `dns.promises.lookup`, passed in so this is testable without
 * DNS. A name that does not resolve is not near: the safe way to be wrong
 * about a host is to proxy it.
 */
export async function isNearUrl(url, lookup) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  const host = parsed.hostname.replace(/^\[|\]$/g, '');
  if (host.toLowerCase() === 'localhost') return true;
  if (/^[\d.]+$/.test(host) || host.includes(':')) return isPrivateAddress(host);
  try {
    const addresses = await lookup(host, { all: true });
    return addresses.length > 0 && addresses.every((a) => isPrivateAddress(a.address));
  } catch {
    return false;
  }
}
