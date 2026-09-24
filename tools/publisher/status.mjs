// `GET /status`'s maths (TOON_Network#171, ADR 0029 §3 "Publisher").
//
// Everything here is pure and file-based on purpose: an operator asking "am I
// funded?" should get an answer without this process building a client,
// dialling the connector or (worse) opening a channel as a side effect of a
// read. So this reads exactly the two files the client's own
// `JsonFileChannelStore` already writes —
//
//   channels.json         { [channelId]: { nonce, cumulativeAmount, … } }
//   channels.peers.json   { [peerKey]:  { channelId, context, depositTotal, … } }
//
// through that same class, and joins them: `cumulativeAmount` (spent) lives on
// the watermark file, `depositTotal` (what was actually funded — kept current
// by `ChannelManager.setDepositTotal` on every deposit, ChannelManager.ts) on
// the binding. Neither file alone answers "how much is left".

/**
 * The channel this publisher is using, read from `store` (a
 * `JsonFileChannelStore`, or anything shaped like one — tests pass the real
 * class pointed at a fixture directory). `null` when no channel has ever been
 * opened.
 *
 * A publisher pays exactly one connector on one chain for its whole life
 * (`TOON_CONNECTOR_URL` / `TOON_CHAIN` are process config, not per-request),
 * so there is normally exactly one binding that isn't superseded. If more
 * than one somehow is — a config that changed connector or chain mid-flight —
 * the most recently opened one wins, since that is the channel a fresh
 * `deposit()` would resume.
 */
export function loadChannelStatus(store) {
  const bindings = typeof store.listBindings === 'function' ? store.listBindings() : [];
  const active = bindings
    .filter(({ binding }) => binding.supersededAt === undefined)
    .sort((a, b) => (b.binding.openedAt ?? '').localeCompare(a.binding.openedAt ?? ''));
  const chosen = active[0];
  if (chosen === undefined) return null;
  const entry = store.load(chosen.binding.channelId);
  return {
    channelId: chosen.binding.channelId,
    chain: chosen.binding.context?.chainType ?? null,
    depositTotal: chosen.binding.depositTotal,
    entry,
  };
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
