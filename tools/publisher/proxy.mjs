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
export function startupRefusal({ hidden, socksProxy }) {
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
  return null;
}

/**
 * Whether `url` is the chain RPC this process was configured with.
 *
 * The one destination a proxied publisher still dials directly. A hidden
 * provider runs its OWN settlement RPC, on loopback or a private address
 * (ADR 0008) — the provider refuses to start otherwise — and `anon` builds no
 * circuit to a private address, so sending it through the proxy would fail
 * rather than hide anything: the packet never leaves the box to begin with.
 * `TOON_PROXY_RPC=true` overrides it for an operator who points this at a
 * public RPC anyway, where the hop does leave and must be covered.
 */
export function isRpcTarget(url, rpcUrl) {
  try {
    return new URL(url).origin === new URL(rpcUrl).origin;
  } catch {
    return false;
  }
}
