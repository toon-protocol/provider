// The publisher's routing decisions (`proxy.mjs`), which need no network, no
// chain and no mnemonic. Run with `npm test` in this directory.

import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';

import {
  isNearUrl,
  isPrivateAddress,
  isRpcTarget,
  isTrue,
  proxyFor,
  startupRefusal,
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
});

describe('isRpcTarget', () => {
  it('knows the configured RPC by origin, whatever the path', () => {
    assert.equal(isRpcTarget('http://127.0.0.1:8899/', 'http://127.0.0.1:8899'), true);
    assert.equal(isRpcTarget('http://127.0.0.1:8899/rpc', 'http://127.0.0.1:8899'), true);
  });

  it('is not fooled by another host or another port', () => {
    assert.equal(isRpcTarget('http://relay-connector:3000/ilp', 'http://127.0.0.1:8899'), false);
    assert.equal(isRpcTarget('http://127.0.0.1:8900/', 'http://127.0.0.1:8899'), false);
    assert.equal(isRpcTarget('not a url', 'http://127.0.0.1:8899'), false);
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
