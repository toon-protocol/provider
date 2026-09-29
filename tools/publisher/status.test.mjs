// `GET /status`'s maths (`status.mjs`), against channel files the real client
// writes — no network, no chain, no mnemonic. Run with `npm test` in this
// directory.
//
// The channel files are written by @toon-protocol/client's own
// `BatchChannelManager` into a scratch directory, not hand-made, so what is
// proved is that `/status` reads exactly what this client version leaves on
// the publisher's volume. The one hand-made fixture is the file a 3.x client
// left behind (`test/fixtures/toon-channel`), which a 4.x volume may still
// hold after an upgrade.

import { strict as assert } from 'node:assert';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { BatchChannelManager, JsonFileChannelStore, InMemoryChannelStore } from '@toon-protocol/client';

import { estimateSpendPerCadence, loadChannelStatus, noChannelStatusBody, statusBody } from './status.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name) => join(here, 'test', 'fixtures', name, 'channels.json');

const CONNECTOR = 'http://relay-connector:3000';
const scratch = [];
after(() => {
  for (const dir of scratch) rmSync(dir, { recursive: true, force: true });
});

/** A fresh `channels.json` path, as `TOON_CHANNEL_STORE` names one. */
function freshStore() {
  const dir = mkdtempSync(join(tmpdir(), 'publisher-status-'));
  scratch.push(dir);
  return join(dir, 'channels.json');
}

const solanaChannel = (channelId, salt = 1n) => ({
  chain: 'solana',
  channelId,
  network: 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1',
  sponsor: 'GzvGVjq3dnNM79MpWRvYCvVcAgPWzDdYisMwGxHF4u9F',
  config: {
    payer: 'W6yK72j365eK7t4Qj5An1AaYtUEJcJK7TBPvGeDk1LV',
    payerAuthorizer: 'W6yK72j365eK7t4Qj5An1AaYtUEJcJK7TBPvGeDk1LV',
    receiver: 'GzvGVjq3dnNM79MpWRvYCvVcAgPWzDdYisMwGxHF4u9F',
    token: '34eSxY7qxQ4GzyhDJ8GpUcTz1WWzruGbJbR8q6TtxfQU',
    withdrawDelay: 86400,
    salt,
    openSlot: 1000n,
  },
});

const evmChannel = (channelId) => ({
  chain: 'evm',
  channelId,
  network: 'eip155:84532',
  config: {
    payer: '0x0657330A600bfb6CeaDe39FFa4fDBE7a98CBfeBE',
    payerAuthorizer: '0x0657330A600bfb6CeaDe39FFa4fDBE7a98CBfeBE',
    receiver: '0x3f43d923a611bcb2d0bfb5d6ee2c3ac3efeaf308',
    receiverAuthorizer: '0x3f43d923a611bcb2d0bfb5d6ee2c3ac3efeaf308',
    token: '0x0C996d7c934c79a6255254875607Fe69df25C0E1',
    withdrawDelay: 86400,
    salt: `0x${'00'.repeat(31)}01`,
  },
});

describe('loadChannelStatus', () => {
  it('joins the watermark and the binding the client wrote for its one channel', () => {
    const path = freshStore();
    const manager = new BatchChannelManager(new JsonFileChannelStore(path));
    manager.adopt(CONNECTOR, solanaChannel('chan-basic-1'), 10_000_000n);
    manager.reserve('chan-basic-1', 1_500_000n);

    const status = loadChannelStatus(new JsonFileChannelStore(path));
    assert.equal(status.channelId, 'chan-basic-1');
    assert.equal(status.chain, 'solana');
    assert.equal(status.depositTotal, 10_000_000n);
    assert.equal(status.entry.cumulativeAmount, 1_500_000n);
    assert.equal(status.entry.signedCeiling, 1_500_000n);
  });

  it('reads an EVM channel as evm', () => {
    const path = freshStore();
    new BatchChannelManager(new JsonFileChannelStore(path)).adopt(CONNECTOR, evmChannel('0xabc'), 5_000_000n);

    const status = loadChannelStatus(new JsonFileChannelStore(path));
    assert.equal(status.channelId, '0xabc');
    assert.equal(status.chain, 'evm');
    assert.equal(status.depositTotal, 5_000_000n);
  });

  it('picks the channel that replaced an exhausted one, not the archived one', () => {
    // A Solana channel is never topped up: the payment it cannot cover opens
    // a fresh sponsored one, and the client archives the old binding.
    const path = freshStore();
    const manager = new BatchChannelManager(new JsonFileChannelStore(path));
    manager.adopt(CONNECTOR, solanaChannel('chan-old', 1n), 1_000_000n);
    manager.reserve('chan-old', 1_000_000n);
    manager.adopt(CONNECTOR, solanaChannel('chan-new', 2n), 5_000_000n);
    manager.reserve('chan-new', 200_000n);

    const status = loadChannelStatus(new JsonFileChannelStore(path));
    assert.equal(status.channelId, 'chan-new');
    assert.equal(status.depositTotal, 5_000_000n);
    assert.equal(status.entry.cumulativeAmount, 200_000n);
  });

  it('skips a channel the client has started leaving', () => {
    const path = freshStore();
    const manager = new BatchChannelManager(new JsonFileChannelStore(path));
    manager.adopt(CONNECTOR, evmChannel('0xclosing'), 5_000_000n);
    manager.markClosing('0xclosing', 1_000n, 87_400n);

    assert.equal(loadChannelStatus(new JsonFileChannelStore(path)), null);
  });

  it('ignores the toon-channel binding a 3.x client left on the volume', () => {
    // The x402-only client never resumes one (toon-protocol/provider#52), so
    // reporting it would describe a channel nothing pays from any more.
    assert.equal(loadChannelStatus(new JsonFileChannelStore(fixture('toon-channel'))), null);
  });

  it('returns null when no channel has ever been opened', () => {
    const store = new InMemoryChannelStore();
    assert.equal(loadChannelStatus(store), null);
  });
});

describe('estimateSpendPerCadence', () => {
  it('is undefined, with an assumption, when no client has talked to the connector yet', async () => {
    const assumptions = [];
    const spend = await estimateSpendPerCadence({ 'ws://relay:7100': 'g.toon.relay' }, undefined, assumptions);
    assert.equal(spend, undefined);
    assert.ok(assumptions.some((a) => /not known yet/.test(a)));
  });

  it('sums the advertised price across every configured write route', async () => {
    const assumptions = [];
    const priceOf = async (destination) =>
      ({ 'g.toon.relay-a': 1n, 'g.toon.relay-b': 2n })[destination];
    const spend = await estimateSpendPerCadence(
      { 'ws://a': 'g.toon.relay-a', 'ws://b': 'g.toon.relay-b' },
      priceOf,
      assumptions,
    );
    assert.equal(spend, 3n);
    assert.deepEqual(assumptions, []);
  });

  it('leaves out a route the connector prices null, and says so', async () => {
    const assumptions = [];
    const priceOf = async () => null;
    const spend = await estimateSpendPerCadence({ 'ws://a': 'g.toon.relay-a' }, priceOf, assumptions);
    assert.equal(spend, 0n);
    assert.ok(assumptions.some((a) => a.includes('g.toon.relay-a')));
  });

  it('is zero, with an assumption, when nothing is configured to write anywhere', async () => {
    const assumptions = [];
    const spend = await estimateSpendPerCadence({}, async () => 1n, assumptions);
    assert.equal(spend, 0n);
    assert.ok(assumptions.some((a) => /no RELAY_WRITE_ROUTES/.test(a)));
  });
});

describe('statusBody', () => {
  it('computes remaining and runway from a funded channel', () => {
    const body = statusBody({
      channelId: 'chan-1',
      chain: 'solana',
      entry: { cumulativeAmount: 1000n },
      depositTotal: 10000n,
      pricePerCadence: 100n,
      cadenceS: 60,
    });
    assert.equal(body.channelId, 'chan-1');
    assert.equal(body.chain, 'solana');
    assert.equal(body.deposit, '10000');
    assert.equal(body.spent, '1000');
    assert.equal(body.remaining, '9000');
    assert.equal(body.signedCeiling, null);
    assert.equal(body.watermarkUncertain, false);
    // remaining(9000) * cadence(60) / pricePerCadence(100) = 5400s
    assert.equal(body.runway_s, 5400);
    assert.ok(body.assumptions.some((a) => /60s/.test(a)));
  });

  it('never reports remaining below zero when spent exceeds deposit', () => {
    const body = statusBody({
      channelId: 'chan-1',
      chain: 'solana',
      entry: { cumulativeAmount: 20000n },
      depositTotal: 10000n,
      pricePerCadence: 100n,
      cadenceS: 60,
    });
    assert.equal(body.remaining, '0');
    assert.equal(body.runway_s, 0);
  });

  it('carries signedCeiling and watermarkUncertain through', () => {
    const body = statusBody({
      channelId: 'chan-1',
      chain: 'solana',
      entry: { cumulativeAmount: 1000n, signedCeiling: 1500n, watermarkUncertain: true },
      depositTotal: 10000n,
      pricePerCadence: undefined,
      cadenceS: undefined,
    });
    assert.equal(body.signedCeiling, '1500');
    assert.equal(body.watermarkUncertain, true);
    assert.equal(body.runway_s, null);
  });

  it('reports runway null and explains why when the cadence is not configured', () => {
    const body = statusBody({
      channelId: 'chan-1',
      chain: 'solana',
      entry: { cumulativeAmount: 1000n },
      depositTotal: 10000n,
      pricePerCadence: 100n,
      cadenceS: undefined,
    });
    assert.equal(body.runway_s, null);
    assert.ok(body.assumptions.some((a) => /TOON_LIVENESS_CADENCE_S/.test(a)));
  });

  it('reports runway null and explains why the price is unknown', () => {
    const body = statusBody({
      channelId: 'chan-1',
      chain: 'solana',
      entry: { cumulativeAmount: 1000n },
      depositTotal: 10000n,
      pricePerCadence: undefined,
      cadenceS: 60,
    });
    assert.equal(body.runway_s, null);
  });

  it('reports deposit and remaining as null when the binding has none, and says so', () => {
    const body = statusBody({
      channelId: 'chan-1',
      chain: 'evm',
      entry: { cumulativeAmount: 1000n },
      depositTotal: undefined,
      pricePerCadence: 100n,
      cadenceS: 60,
    });
    assert.equal(body.deposit, null);
    assert.equal(body.remaining, null);
    assert.equal(body.runway_s, null);
    assert.ok(body.assumptions.some((a) => /predates deposit tracking/.test(a)));
  });

  it('treats a zero advertised price as unbounded runway, not a divide by zero', () => {
    const body = statusBody({
      channelId: 'chan-1',
      chain: 'solana',
      entry: { cumulativeAmount: 0n },
      depositTotal: 10000n,
      pricePerCadence: 0n,
      cadenceS: 60,
    });
    assert.equal(body.runway_s, null);
    assert.ok(body.assumptions.some((a) => /unbounded/.test(a)));
  });
});

describe('noChannelStatusBody', () => {
  it('is an all-null/zero body that says no channel exists yet', () => {
    const body = noChannelStatusBody(60);
    assert.equal(body.channelId, null);
    assert.equal(body.spent, '0');
    assert.equal(body.remaining, null);
    assert.equal(body.runway_s, null);
    assert.ok(body.assumptions.some((a) => /no channel/.test(a)));
  });
});
