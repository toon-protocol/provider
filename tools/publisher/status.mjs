// `GET /status`'s maths (TOON_Network#171, ADR 0029 §3 "Publisher").
//
// Everything here is pure and file-based on purpose: an operator asking "am I
// funded?" should get an answer without this process building a client,
// dialling the connector or (worse) opening a channel as a side effect of a
// read. So this reads exactly the two files the client's own
// `JsonFileChannelStore` already writes —
//
//   channels.json         { [channelId]: { cumulativeAmount, signedCeiling, … } }
//   channels.peers.json   { [bindingKey]: { channelId, depositTotal, batchSettlement, … } }
//
// through that same class, and joins them: `cumulativeAmount` (the running
// total of every voucher signed) lives on the watermark file, `depositTotal`
// (what was actually funded — kept current by `BatchChannelManager` on every
// deposit) on the binding. Neither file alone answers "how much is left".

/**
 * The channel this publisher is paying from, read from `store` (a
 * `JsonFileChannelStore`, or anything shaped like one — tests pass the real
 * class, written by the client's own `BatchChannelManager`). `null` when no
 * channel is open.
 *
 * Only x402 `batch-settlement` channels count (client 4.x, connector ADR
 * 0075): a binding without `batchSettlement` is a `toon-channel` one that a
 * 3.x client left on the volume, and nothing pays from it any more. Nor does
 * a binding the client archived (`supersededAt`: a newer channel replaced it,
 * as an exhausted Solana channel always is) or one it has started leaving
 * (`closedAt` on its watermark).
 *
 * A publisher pays exactly one connector on one chain for its whole life
 * (`TOON_CONNECTOR_URL` / `TOON_CHAIN` are process config, not per-request),
 * so exactly one channel is normally left. If more than one somehow is — a
 * config that changed connector or chain mid-flight — the first listed wins.
 */
export function loadChannelStatus(store) {
  const bindings = typeof store.listBindings === 'function' ? store.listBindings() : [];
  for (const { binding } of bindings) {
    if (binding.batchSettlement === undefined || binding.supersededAt !== undefined) continue;
    const entry = store.load(binding.channelId);
    if (entry?.closedAt !== undefined) continue;
    return {
      channelId: binding.channelId,
      chain: binding.batchSettlement.chain,
      depositTotal: binding.depositTotal,
      entry,
    };
  }
  return null;
}

/**
 * The token cost of one cadence's worth of writes: one write per configured
 * relay (`RELAY_WRITE_ROUTES`), at that route's price exactly as the
 * connector advertises it right now.
 *
 * `priceOf` is `undefined` when nothing is "already known" — no client has
 * talked to this connector yet, so `/status` has nothing to ask without
 * building one, and building a client is not a side effect a status read
 * should have. Given a `priceOf`, a route the connector prices `null` (no
 * matching route) is left out of the sum and named in `assumptions` rather
 * than treated as free.
 */
export async function estimateSpendPerCadence(writeRoutes, priceOf, assumptions) {
  if (priceOf === undefined) {
    assumptions.push(
      "the relay's advertised write price is not known yet — this publisher has not talked to its connector — so the runway cannot be estimated.",
    );
    return undefined;
  }
  const destinations = Object.values(writeRoutes ?? {});
  if (destinations.length === 0) {
    assumptions.push('no RELAY_WRITE_ROUTES are configured, so nothing is charged per cadence.');
    return 0n;
  }
  let total = 0n;
  const unpriced = [];
  for (const destination of destinations) {
    const price = await priceOf(destination);
    if (price === null || price === undefined) {
      unpriced.push(destination);
      continue;
    }
    total += price;
  }
  if (unpriced.length > 0) {
    assumptions.push(
      `${unpriced.join(', ')} priced no matching route at the connector and ` +
        `${unpriced.length === destinations.length ? 'is' : 'are'} left out of the runway estimate.`,
    );
  }
  return total;
}

/** Seconds of runway at `pricePerCadence` base units every `cadenceS` seconds, or `null` (with an assumption recorded) when an input is missing. */
function runwaySeconds({ remaining, pricePerCadence, cadenceS }, assumptions) {
  if (cadenceS === undefined) {
    assumptions.push(
      'TOON_LIVENESS_CADENCE_S is not set, so the runway cannot be estimated.',
    );
    return null;
  }
  if (remaining === undefined) {
    assumptions.push(
      "this channel's binding has no recorded deposit total, so remaining and the runway are unknown.",
    );
    return null;
  }
  if (pricePerCadence === undefined) {
    // estimateSpendPerCadence already recorded why.
    return null;
  }
  if (pricePerCadence === 0n) {
    assumptions.push(
      `assumes a ${cadenceS}s cadence (TOON_LIVENESS_CADENCE_S); every configured write route is advertised free right now, so the runway is unbounded and reported as null.`,
    );
    return null;
  }
  assumptions.push(
    `runway = remaining ÷ (price per write × writes per cadence): a ${cadenceS}s cadence ` +
      `(TOON_LIVENESS_CADENCE_S) at ${pricePerCadence.toString()} base units per cadence, ` +
      "summed across every configured write route at the connector's currently advertised price.",
  );
  return Number((remaining * BigInt(cadenceS)) / pricePerCadence);
}

/**
 * The `GET /status` body for a channel `loadChannelStatus` found.
 *
 * `pricePerCadence` — a bigint, or `undefined` when it is not known — and
 * `cadenceS` — a number of seconds, or `undefined` when
 * `TOON_LIVENESS_CADENCE_S` is unset — are passed in rather than read from
 * `process.env` here, so this stays a pure function fixtures can drive
 * directly.
 */
export function statusBody({ channelId, chain, entry, depositTotal, pricePerCadence, cadenceS }) {
  const assumptions = [];
  const spent = entry?.cumulativeAmount ?? 0n;
  const deposit = depositTotal;
  const remaining = deposit === undefined ? undefined : deposit > spent ? deposit - spent : 0n;

  const runway_s = runwaySeconds({ remaining, pricePerCadence, cadenceS }, assumptions);

  if (deposit === undefined) {
    assumptions.push(
      "this channel's binding predates deposit tracking, so deposit and remaining are reported as null.",
    );
  }

  return {
    channelId: channelId ?? null,
    chain: chain ?? null,
    deposit: deposit === undefined ? null : deposit.toString(),
    spent: spent.toString(),
    remaining: remaining === undefined ? null : remaining.toString(),
    signedCeiling: entry?.signedCeiling !== undefined ? entry.signedCeiling.toString() : null,
    watermarkUncertain: entry?.watermarkUncertain ?? false,
    runway_s,
    assumptions,
  };
}

/** The `GET /status` body before this publisher has ever opened a channel. */
export function noChannelStatusBody(cadenceS) {
  const assumptions = ['no channel has been opened yet.'];
  if (cadenceS === undefined) {
    assumptions.push('TOON_LIVENESS_CADENCE_S is not set.');
  }
  return {
    channelId: null,
    chain: null,
    deposit: null,
    spent: '0',
    remaining: null,
    signedCeiling: null,
    watermarkUncertain: false,
    runway_s: null,
    assumptions,
  };
}
