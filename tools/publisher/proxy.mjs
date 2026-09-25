// Which proxy one publication goes through, and where it does NOT apply.
//
// Kept apart from `publish.mjs` because that file starts a server and demands
// a mnemonic the moment it is imported: these are the decisions worth testing
// on their own (`node --test`). They are pure; the one that builds the
// carriage, `carriageThrough`, is handed everything it dials with.

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
 * Why a hidden publisher must not start with this chain RPC, or `null`.
 *
 * `carriageThrough` covers what the client sends through the `fetch` and the
 * socket it is handed. The client's channel does not use either: opening,
 * depositing and the chain reads behind them dial `TOON_RPC_URL` with the
 * platform's own `fetch` (`@toon-protocol/client` routes chain RPC through a
 * proxy only under its own `socksProxy:` option, which refuses a clearnet
 * connector). So beside a hidden provider the RPC must be near: its own
 * node on a private address, which no exit could reach and whose traffic
 * crosses no watched network. A far one would see this host's real address
 * on every channel operation, so it is a refusal to start.
 *
 * `lookup` is `dns.promises.lookup`, as for `isNearUrl`.
 */
export async function hiddenRpcRefusal({ hidden, rpcUrl }, lookup) {
  if (!hidden || (await isNearUrl(rpcUrl, lookup))) return null;
  return (
    `TOON_HIDDEN is set, so TOON_RPC_URL must be your own node on a private address, not ` +
    `${JSON.stringify(rpcUrl)}: the payment channel dials its chain RPC directly, never ` +
    "through the proxy, and a public RPC would see this host's real address (spec §10, " +
    'ADR 0008).'
  );
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
 * before hidden providers existed. With one, both are the client library's
 * SOCKS5h carriage (`createHiddenServiceTransport`), for EVERY host, not only
 * `.anyone` ones: a hidden provider whose payer reached a clearnet relay
 * directly would have named this host to it, whatever the connector's address
 * looked like. Handing over only the `fetch` is not enough, and was the gap
 * TOON_Network#165 closed: the client would open its BTP socket itself, from
 * this host's real address.
 *
 * The chain RPC is the one exception to the proxy, and `isNearUrl` says why.
 *
 * `deps` is what it dials with — `createHiddenServiceTransport`, `fetch`,
 * `WebSocket`, the configured `rpcUrl` and `rpcNear()` (whether that RPC is
 * near) — so the routing is testable without a network.
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
  const transport = deps.createHiddenServiceTransport(socksProxy);
  return {
    fetch: async (input, init) => {
      const target = url(input);
      if (isRpcTarget(target, deps.rpcUrl) && (await deps.rpcNear())) return deps.fetch(target, init);
      return transport.fetch(target, init);
    },
    createWebSocket: (target) => transport.createWebSocket(url(target)),
    close: () => transport.close(),
  };
}

/** Whether `url` is the chain RPC this process was configured with. */
export function isRpcTarget(url, rpcUrl) {
  try {
    return new URL(url).origin === new URL(rpcUrl).origin;
  } catch {
    return false;
  }
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
 * This is the ONE destination a proxied publisher still dials directly, and
 * it is decided by where the destination IS rather than by a flag. A hidden
 * provider runs its own settlement RPC on loopback or a private address (ADR
 * 0008) — the provider refuses to start otherwise — and `anon` builds no
 * circuit to such an address, so proxying it would fail rather than hide
 * anything: the packet never crosses a network anyone outside can watch. An
 * RPC that is anywhere else DOES leave: what reaches it through the `fetch`
 * rides the proxy, and the channel's own calls, which do not, are why a
 * hidden publisher refuses to start beside one (`hiddenRpcRefusal`).
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
