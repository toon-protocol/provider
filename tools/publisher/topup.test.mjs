// `POST /topup`'s logic (`topup.mjs`), against a STUBBED client — no server,
// no chain, no mnemonic. Run with `npm test` in this directory.

import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';

import { TopupUnsupportedError, parseAmount, topup } from './topup.mjs';

describe('parseAmount', () => {
  it('accepts a positive integer string', () => {
    assert.equal(parseAmount('5000000'), 5000000n);
  });

  it('accepts a positive integer number', () => {
    assert.equal(parseAmount(5000000), 5000000n);
  });

  it('trims surrounding whitespace', () => {
    assert.equal(parseAmount(' 5000000 \n'), 5000000n);
  });

  it('refuses zero', () => {
    assert.throws(() => parseAmount('0'), RangeError);
  });

  it('refuses a negative number', () => {
    assert.throws(() => parseAmount(-5), RangeError);
  });

  it('refuses a decimal amount', () => {
    assert.throws(() => parseAmount('5.5'), RangeError);
  });

  it('refuses non-numeric text', () => {
    assert.throws(() => parseAmount('five million'), RangeError);
  });

  it('refuses anything that is not a string or number', () => {
    assert.throws(() => parseAmount({ amount: 5 }), TypeError);
    assert.throws(() => parseAmount(undefined), TypeError);
    assert.throws(() => parseAmount(null), TypeError);
  });
});

describe('topup', () => {
  function stubClient(depositResult) {
    const calls = [];
    return {
      calls,
      channel: {
        async deposit(amount) {
          calls.push(amount);
          return depositResult;
        },
      },
    };
  }

  it('calls channel.deposit with the parsed amount and reports the new state', async () => {
    // What client 4.x's `channel.deposit` resolves to: a `BatchChannelSummary`.
    const client = stubClient({
      channel: { chain: 'evm', channelId: '0xchan', network: 'eip155:84532', config: {} },
      depositTotal: 15000000n,
      signed: 1000n,
    });
    const result = await topup(() => client, '5000000', 'evm');
    assert.deepEqual(client.calls, [5000000n]);
    assert.deepEqual(result, {
      channelId: '0xchan',
      chain: 'evm',
      deposit: '15000000',
      spent: '1000',
      remaining: '14999000',
    });
  });

  it('reports nothing remaining, not a negative amount, when signed exceeds the deposit', async () => {
    const client = stubClient({
      channel: { chain: 'evm', channelId: '0xchan' },
      depositTotal: 1000n,
      signed: 1500n,
    });
    const result = await topup(() => client, '1', 'evm');
    assert.equal(result.remaining, '0');
  });

  it('refuses on Solana, where a channel is replaced rather than topped up, before building a client', async () => {
    // x402's Solana channel has no top-up through the sponsor: the next
    // payment it cannot cover opens a fresh sponsored one (client 4.0.0).
    let built = false;
    const getClient = () => {
      built = true;
      return stubClient({});
    };
    await assert.rejects(() => topup(getClient, '5000000', 'solana'), TopupUnsupportedError);
    await assert.rejects(() => topup(getClient, '5000000', 'solana'), /opens a fresh sponsored one/);
    assert.equal(built, false);
  });

  it('never builds a client when the amount is invalid', async () => {
    let built = false;
    const getClient = () => {
      built = true;
      return stubClient({});
    };
    await assert.rejects(() => topup(getClient, 'not-a-number', 'evm'), RangeError);
    assert.equal(built, false);
  });

  it('propagates a rejection from the client (e.g. no channel open)', async () => {
    const client = {
      channel: {
        async deposit() {
          throw new Error('no open channel');
        },
      },
    };
    await assert.rejects(() => topup(() => client, '5000000', 'evm'), /no open channel/);
  });
});
