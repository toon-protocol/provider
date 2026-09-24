// `GET /status`'s maths (`status.mjs`), against real fixture channel files —
// no network, no chain, no mnemonic. Run with `npm test` in this directory.

import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { JsonFileChannelStore, InMemoryChannelStore } from '@toon-protocol/client';

import { estimateSpendPerCadence, loadChannelStatus, noChannelStatusBody, statusBody } from './status.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name) => join(here, 'test', 'fixtures', name, 'channels.json');

describe('loadChannelStatus', () => {
  it('joins the watermark file and the binding for the one active channel', () => {
    const store = new JsonFileChannelStore(fixture('basic'));
    const status = loadChannelStatus(store);
    assert.equal(status.channelId, 'chan-basic-1');
    assert.equal(status.chain, 'solana');
    assert.equal(status.depositTotal, 10000000n);
    assert.equal(status.entry.cumulativeAmount, 1500000n);
  });

  it('ignores a superseded binding and picks the active one', () => {
    const store = new JsonFileChannelStore(fixture('superseded'));
    const status = loadChannelStatus(store);
    assert.equal(status.channelId, 'chan-new');
    assert.equal(status.depositTotal, 5000000n);
    assert.equal(status.entry.cumulativeAmount, 200000n);
    assert.equal(status.entry.signedCeiling, 250000n);
    assert.equal(status.entry.watermarkUncertain, true);
  });

  it('reports a binding with no recorded deposit as depositTotal undefined', () => {
    const store = new JsonFileChannelStore(fixture('no-deposit'));
    const status = loadChannelStatus(store);
    assert.equal(status.channelId, 'chan-nodep');
    assert.equal(status.chain, 'evm');
    assert.equal(status.depositTotal, undefined);
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
