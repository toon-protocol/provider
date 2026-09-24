// Which proxy one publication goes through, and where it does NOT apply.
//
// Kept apart from `publish.mjs` because that file starts a server and demands
// a mnemonic the moment it is imported: these are the decisions worth testing
// on their own (`node --test`), and they are pure.

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
export function startupRefusal({ hidden, socksProxy, transport, endpointRewrite }) {
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
  return transportRefusal({ transport, socksProxy, hidden, endpointRewrite });
}

/** The carriages this publisher may pay over. `auto` lets the node's own route policy decide. */
export const TRANSPORTS = ['http', 'auto', 'btp'];

/**
 * Which ILP carriage this publisher pays over, and where that choice is not
 * this publisher's to make.
 *
 * `http` is the default and was until now the only behaviour: a one-shot POST
 * per packet, which is what publishing is — a handful of packets a minute,
 * already serialized. But a node may PIN a route to one carriage, and the
 * devnet relay pins `g.toon.relay` to BTP; an HTTP one-shot there comes back
 * refused with `extra.requiredTransport` and no directory event is ever
 * written. `auto` reads the pin out of the node's own self-description and
 * dials what it asks for, which is what a deployment against such a relay
 * needs.
 *
 * TWO THINGS THE HTTP CARRIAGE CARRIES THAT A WEBSOCKET DOES NOT, and both are
 * refusals at startup rather than warnings:
 *
 *   * THE PROXY. A SOCKS5h carriage is installed as this process's `fetch`.
 *     BTP opens a websocket instead, which never passes through it — so a
 *     hidden publisher on BTP would reach the connector from this host's real
 *     address while every log line still said it was proxied. That is the leak
 *     TOON_HIDDEN exists to prevent.
 *   * THE ENDPOINT REWRITE. `TOON_ENDPOINT_REWRITE` is applied inside that
 *     same `fetch`. A deployment that needs one (the sandbox, whose hub
 *     advertises a host-side address) would have BTP dial the advertised
 *     address verbatim and fail to connect for a reason nothing names.
 */
export function transportRefusal({ transport, socksProxy, hidden, endpointRewrite }) {
  if (transport === undefined || transport === '') return null;
  if (!TRANSPORTS.includes(transport)) {
    return `TOON_TRANSPORT must be one of ${TRANSPORTS.join(', ')}, not ${JSON.stringify(transport)}.`;
  }
  if (transport === 'http') return null;
  if (socksProxy !== undefined || hidden) {
    return (
      `TOON_TRANSPORT=${transport} cannot be used with a proxy: the SOCKS5h carriage is this ` +
      "process's `fetch`, and BTP opens a websocket that never passes through it. A hidden " +
      "publisher on BTP would reach the connector from this host's real address (spec §10, " +
      'ADR 0008). Leave TOON_TRANSPORT unset, or drop the proxy.'
    );
  }
  if (endpointRewrite !== undefined && Object.keys(endpointRewrite).length > 0) {
    return (
      `TOON_TRANSPORT=${transport} cannot be used with TOON_ENDPOINT_REWRITE: the rewrite is ` +
      "applied inside this process's `fetch`, and BTP dials a websocket that never passes " +
      'through it — so the advertised address would be dialled verbatim and nothing would say why.'
    );
  }
  return null;
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
 * RPC that is anywhere else DOES leave, so it rides the proxy like everything
 * else, and no flag can leave it uncovered by mistake.
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
