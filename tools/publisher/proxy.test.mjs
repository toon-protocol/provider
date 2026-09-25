// The publisher's routing decisions (`proxy.mjs`), which need no network, no
// chain and no mnemonic. Run with `npm test` in this directory.

import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';

import {
  carriageThrough,
  chainRpcRoute,
  clientRouteOptions,
  isNearUrl,
  isPrivateAddress,
  isTrue,
  proxyFor,
  rewriteUrl,
  startupRefusal,
  TRANSPORTS,
  transportRefusal,
  validateProxy,
} from './proxy.mjs';

describe('validateProxy', () => {
  it('accepts a socks5h URL with a host and a port', () => {
    assert.equal(validateProxy('socks5h://anon:9050', 'x'), 'socks5h://anon:9050');
  });

  it('refuses socks5, saying why the h matters', () => {
    assert.throws(() => validateProxy('socks5://anon:9050', 'TOON_SOCKS_PROXY'), (e) => {
      assert.match(e.message, /socks5h/);
      assert.match(e.message, /resolves the destination/);
      return true;
    });
  });

  it('refuses a proxy with no port', () => {
    assert.throws(() => validateProxy('socks5h://anon', 'x'), /host and a port/);
  });
});

describe('proxyFor', () => {
  it('takes the proxy the request names', () => {
    assert.equal(
      proxyFor({ proxy: 'socks5h://anon:9050' }, undefined),
      'socks5h://anon:9050',
    );
  });

  it('falls back to the environment when the request names none', () => {
    assert.equal(proxyFor({}, 'socks5h://anon:9050'), 'socks5h://anon:9050');
  });

  it('is direct when neither names one — what a provider that is not hidden sends', () => {
    assert.equal(proxyFor({ event: {}, relays: [] }, undefined), undefined);
  });

  it('refuses a request whose proxy is not socks5h rather than going direct', () => {
    assert.throws(() => proxyFor({ proxy: 'socks5://anon:9050' }, undefined), /socks5h/);
  });
});

describe('startupRefusal', () => {
  it('refuses a publisher beside a hidden provider with no proxy', () => {
    const why = startupRefusal({ hidden: true, socksProxy: undefined });
    assert.match(why, /TOON_SOCKS_PROXY is required/);
  });

  it('refuses a proxy that is not socks5h, hidden or not', () => {
    assert.match(startupRefusal({ hidden: true, socksProxy: 'socks5://a:9050' }), /socks5h/);
    assert.match(startupRefusal({ hidden: false, socksProxy: 'socks5://a:9050' }), /socks5h/);
  });

  it('lets a hidden publisher with a proxy start, and a plain one with none', () => {
    assert.equal(startupRefusal({ hidden: true, socksProxy: 'socks5h://anon:9050' }), null);
    assert.equal(startupRefusal({ hidden: false, socksProxy: undefined }), null);
  });

  it('carries the transport refusal, so one call is the whole of "may this start"', () => {
    assert.match(
      startupRefusal({ hidden: true, socksProxy: 'socks5h://anon:9050', transport: 'websocket' }),
      /must be one of/,
    );
  });

  it('lets a hidden publisher pay over BTP, which the devnet relay pins (TOON_Network#165)', () => {
    for (const transport of ['btp', 'auto']) {
      assert.equal(
        startupRefusal({ hidden: true, socksProxy: 'socks5h://anon:9050', transport }),
        null,
        transport,
      );
    }
  });
});

describe('transportRefusal', () => {
  it('lets the default through, and the absent case with it', () => {
    assert.equal(transportRefusal({}), null);
    assert.equal(transportRefusal({ transport: '' }), null);
    assert.equal(transportRefusal({ transport: 'http' }), null);
  });

  it('names what it will take when given something else', () => {
    assert.match(transportRefusal({ transport: 'websocket' }), /must be one of http, auto, btp/);
    assert.deepEqual(TRANSPORTS, ['http', 'auto', 'btp']);
  });

  it('lets a clearnet publisher ask the node which carriage it wants', () => {
    // What a deployment against the devnet relay needs: that node pins
    // `g.toon.relay` to BTP, and an HTTP one-shot there is refused outright.
    assert.equal(transportRefusal({ transport: 'auto' }), null);
    assert.equal(transportRefusal({ transport: 'btp', endpointRewrite: {} }), null);
  });

  it('lets a websocket ride beside a proxy, because the socket rides it too', () => {
    // Until TOON_Network#165 this was a refusal: the proxy was only this
    // process's `fetch`, and a BTP socket went round it. The carriage now
    // hands the client the proxy's `createWebSocket` as well (`carriageThrough`).
    assert.equal(transportRefusal({ transport: 'auto', socksProxy: 'socks5h://anon:9050' }), null);
    assert.equal(transportRefusal({ transport: 'btp', hidden: true }), null);
  });
});

describe('rewriteUrl', () => {
  const rewrite = [['http://127.0.0.1:3200', 'http://relay-connector:3000']];

  it('swaps an advertised prefix for the address this process reaches', () => {
    assert.equal(rewriteUrl('http://127.0.0.1:3200/ilp', rewrite), 'http://relay-connector:3000/ilp');
  });

  it('rewrites the websocket to the same node, keeping its scheme', () => {
    // The node advertises its BTP endpoint as `ws://` beside an `http://` one;
    // the operator names the node once, by its http address.
    assert.equal(
      rewriteUrl('ws://127.0.0.1:3200/ilp/btp', rewrite),
      'ws://relay-connector:3000/ilp/btp',
    );
    assert.equal(
      rewriteUrl('wss://relay.example/btp', [['https://relay.example', 'https://10.0.0.9:8443']]),
      'wss://10.0.0.9:8443/btp',
    );
  });

  it('does not cross http and https', () => {
    assert.equal(rewriteUrl('wss://127.0.0.1:3200/btp', rewrite), 'wss://127.0.0.1:3200/btp');
  });

  it('leaves everything else alone', () => {
    assert.equal(rewriteUrl('http://elsewhere:3200/ilp', rewrite), 'http://elsewhere:3200/ilp');
    assert.equal(rewriteUrl('ws://elsewhere/btp', []), 'ws://elsewhere/btp');
  });
});

describe('carriageThrough', () => {
  const rewrite = [['http://127.0.0.1:3200', 'http://relay-connector:3000']];

  /** Records where each dial went, instead of dialling. */
  function world() {
    const dialled = [];
    const hs = {
      fetch: async (url) => dialled.push(['proxy fetch', url]),
      createWebSocket: (url) => dialled.push(['proxy socket', url]) && 'proxied socket',
      close: async () => dialled.push(['proxy closed']),
    };
    return {
      dialled,
      deps: {
        createHiddenServiceTransport: (proxy) => {
          dialled.push(['proxy built', proxy]);
          return hs;
        },
        fetch: async (url) => dialled.push(['direct fetch', url]),
        WebSocket: class {
          constructor(url) {
            dialled.push(['direct socket', url]);
          }
        },
      },
    };
  }

  it('beside a proxy and no rewrite, hands the client nothing: its own socksProxy carries every byte', async () => {
    // A hidden PAYER (@toon-protocol/client 3.3, TOON_Network#167): the
    // client edge, the BTP socket and the chain RPC all ride the proxy the
    // client is given. An injected `fetch` would win over the client's own
    // for the edge, so none is injected unless a rewrite needs one.
    const { dialled, deps } = world();
    const carriage = carriageThrough('socks5h://anon:9050', [], deps);
    assert.equal(carriage.fetch, undefined);
    assert.equal(carriage.createWebSocket, undefined);
    await carriage.close();
    assert.deepEqual(dialled, [], 'nothing built, nothing dialled');
  });

  it('beside a proxy AND a rewrite, sends both halves through the proxy, rewritten', async () => {
    const { dialled, deps } = world();
    const carriage = carriageThrough('socks5h://anon:9050', rewrite, deps);

    assert.equal(carriage.createWebSocket('ws://127.0.0.1:3200/ilp/btp'), 'proxied socket');
    await carriage.fetch('http://127.0.0.1:3200/ilp');
    // The chain RPC is no business of this carriage any more: under a proxy
    // the client never hands chain RPC to an injected `fetch`.
    await carriage.fetch('https://api.devnet.solana.com/');
    await carriage.close();

    assert.deepEqual(dialled, [
      ['proxy built', 'socks5h://anon:9050'],
      ['proxy socket', 'ws://relay-connector:3000/ilp/btp'],
      ['proxy fetch', 'http://relay-connector:3000/ilp'],
      ['proxy fetch', 'https://api.devnet.solana.com/'],
      ['proxy closed'],
    ]);
  });

  it('with no proxy dials directly, the socket rewritten like the fetch', async () => {
    const { dialled, deps } = world();
    const carriage = carriageThrough(undefined, rewrite, deps);

    carriage.createWebSocket('ws://127.0.0.1:3200/ilp/btp');
    await carriage.fetch('http://127.0.0.1:3200/ilp');
    await carriage.close();

    assert.deepEqual(dialled, [
      ['direct socket', 'ws://relay-connector:3000/ilp/btp'],
      ['direct fetch', 'http://relay-connector:3000/ilp'],
    ]);
  });
});

describe('clientRouteOptions', () => {
  const direct = { fetch: 'direct fetch', createWebSocket: 'direct socket' };

  it('with no proxy passes the direct carriage and nothing else', () => {
    assert.deepEqual(clientRouteOptions(undefined, direct, true), {
      fetch: 'direct fetch',
      createWebSocket: 'direct socket',
    });
  });

  it('beside a proxy makes the client a hidden payer, its chain RPC through the proxy', () => {
    assert.deepEqual(clientRouteOptions('socks5h://anon:9050', {}, true), {
      socksProxy: 'socks5h://anon:9050',
    });
  });

  it('says proxyRpc: false only when the chain RPC is to be dialled directly', () => {
    assert.deepEqual(clientRouteOptions('socks5h://anon:9050', {}, false), {
      socksProxy: 'socks5h://anon:9050',
      proxyRpc: false,
    });
  });

  it('keeps an injected carriage only when there is one (a rewrite)', () => {
    const proxied = { fetch: 'proxy fetch', createWebSocket: 'proxy socket' };
    assert.deepEqual(clientRouteOptions('socks5h://anon:9050', proxied, true), {
      socksProxy: 'socks5h://anon:9050',
      fetch: 'proxy fetch',
      createWebSocket: 'proxy socket',
    });
  });
});

describe('chainRpcRoute', () => {
  const PUBLIC = 'https://api.devnet.solana.com';
  const near = async () => [{ address: '10.0.0.5' }];
  const far = async () => [{ address: '203.0.113.7' }];
  const noLookup = async (host) => {
    throw new Error(`looked up ${host}`);
  };

  it('by default sends a public RPC through the proxy, and never looks its name up', async () => {
    // A lookup of the public RPC's name from this host is the one query a
    // hidden box must not make for a host it reaches only through anon.
    assert.deepEqual(await chainRpcRoute({ hidden: true, rpcUrl: PUBLIC }, noLookup), { proxyRpc: true });
    assert.deepEqual(
      await chainRpcRoute({ hidden: true, rpcUrl: 'https://8.8.8.8:8899' }, noLookup),
      { proxyRpc: true },
    );
  });

  it('by default dials an RPC on this box or its compose network directly', async () => {
    // No exit could reach it; proxying it would fail, not hide.
    assert.deepEqual(
      await chainRpcRoute({ hidden: true, rpcUrl: 'http://10.0.0.5:8899' }, noLookup),
      { proxyRpc: false },
    );
    assert.deepEqual(
      await chainRpcRoute({ hidden: true, rpcUrl: 'http://solana-validator:8899' }, near),
      { proxyRpc: false },
    );
    // A one-label name that turns out public is proxied.
    assert.deepEqual(await chainRpcRoute({ hidden: true, rpcUrl: 'https://rpc:8899' }, far), { proxyRpc: true });
  });

  it('refuses plain http through the proxy, which an exit relay could rewrite', async () => {
    const { refusal } = await chainRpcRoute({ hidden: true, rpcUrl: 'http://api.devnet.solana.com' }, noLookup);
    assert.match(refusal, /plain http/);
    const onion = `http://${'r'.repeat(56)}.anyone:8899`;
    assert.deepEqual(await chainRpcRoute({ hidden: true, rpcUrl: onion }, noLookup), { proxyRpc: true });
  });

  it('takes TOON_PROXY_RPC=true or false over where the RPC is', async () => {
    assert.deepEqual(
      await chainRpcRoute({ hidden: true, rpcUrl: 'http://rpc.lan.example:8899', proxyRpc: 'false' }, near),
      { proxyRpc: false },
    );
    assert.deepEqual(
      await chainRpcRoute({ hidden: true, rpcUrl: 'https://10.0.0.5:8899', proxyRpc: 'true' }, noLookup),
      { proxyRpc: true },
    );
    assert.deepEqual(await chainRpcRoute({ hidden: true, rpcUrl: PUBLIC, proxyRpc: '' }, noLookup), {
      proxyRpc: true,
    });
    const { refusal } = await chainRpcRoute({ hidden: false, rpcUrl: PUBLIC, proxyRpc: 'maybe' }, noLookup);
    assert.match(refusal, /TOON_PROXY_RPC/);
  });

  it('refuses a hidden publisher told to dial a public RPC directly', async () => {
    const { refusal } = await chainRpcRoute({ hidden: true, rpcUrl: PUBLIC, proxyRpc: 'false' }, far);
    assert.match(refusal, /TOON_RPC_URL/);
    assert.match(refusal, /private address/);
    // Not hidden, the operator may send it where they like.
    assert.deepEqual(await chainRpcRoute({ hidden: false, rpcUrl: PUBLIC, proxyRpc: 'false' }, far), {
      proxyRpc: false,
    });
  });
});

describe('isPrivateAddress', () => {
  it('knows loopback, RFC 1918, link-local and ULA', () => {
    for (const near of [
      '127.0.0.1', '10.0.0.4', '172.16.0.1', '172.31.255.254', '192.168.1.1',
      '169.254.1.1', '0.0.0.0', '::1', '::', 'fd00::1', 'fe80::1', '::ffff:10.0.0.4',
    ]) {
      assert.equal(isPrivateAddress(near), true, near);
    }
  });

  it('and everything else is not', () => {
    for (const far of ['8.8.8.8', '203.0.113.7', '172.32.0.1', '172.15.0.1', '2001:db8::1']) {
      assert.equal(isPrivateAddress(far), false, far);
    }
  });
});

describe('isNearUrl', () => {
  const resolving = (addresses) => async () => addresses.map((address) => ({ address }));
  const failing = async () => {
    throw new Error('ENOTFOUND');
  };

  it('takes an address literal at its word, without a lookup', async () => {
    assert.equal(await isNearUrl('http://127.0.0.1:8899', failing), true);
    assert.equal(await isNearUrl('http://solana:8899', failing), false);
    assert.equal(await isNearUrl('http://8.8.8.8:8899', failing), false);
    assert.equal(await isNearUrl('http://localhost:8899', failing), true);
  });

  it('is near only when every address a name resolves to is', async () => {
    assert.equal(await isNearUrl('http://solana-validator:8899', resolving(['172.18.0.5'])), true);
    assert.equal(
      await isNearUrl('http://split:8899', resolving(['10.0.0.1', '8.8.8.8'])),
      false,
      'one public address anywhere in the answer is enough',
    );
    assert.equal(await isNearUrl('http://nothing:8899', resolving([])), false);
  });

  it('is not near when the name does not resolve — the safe way to be wrong', async () => {
    assert.equal(await isNearUrl('http://gone:8899', failing), false);
  });
});

describe('isTrue', () => {
  it('reads the flags compose writes', () => {
    for (const yes of ['1', 'true', 'TRUE', 'yes', 'on', ' true ']) {
      assert.equal(isTrue(yes), true, yes);
    }
    for (const no of ['0', 'false', '', undefined, null, 'no']) {
      assert.equal(isTrue(no), false, String(no));
    }
  });
});
