// `POST /topup`'s logic (TOON_Network#171, ADR 0029 "Money": top-up).
//
// Kept out of `publish.mjs` so it is testable against a STUBBED client — no
// server, no chain, no mnemonic — the same way `proxy.mjs` and `blob.mjs`
// keep the pure half of their decisions separate from the process that holds
// money and network sockets.

/**
 * `amount` as `channel.deposit` wants it: a positive integer, in the token's
 * smallest unit, exactly like `TOON_DEPOSIT`. No unit conversion happens
 * here — the caller (the CLI, or whoever calls `/topup` directly) says base
 * units, same as everywhere else this publisher talks about money.
 *
 * @throws {RangeError} `amount` is not a positive integer.
 * @throws {TypeError} `amount` is not a string or a number.
 */
export function parseAmount(amount) {
  if (typeof amount !== 'string' && typeof amount !== 'number') {
    throw new TypeError(`amount must be a string or number, got ${typeof amount}`);
  }
  const trimmed = String(amount).trim();
  if (!/^[0-9]+$/.test(trimmed)) {
    throw new RangeError(
      `amount must be a positive integer in the token's smallest unit, got ${JSON.stringify(amount)}`,
    );
  }
  const parsed = BigInt(trimmed);
  if (parsed <= 0n) {
    throw new RangeError('amount must be greater than zero');
  }
  return parsed;
}

/**
 * A top-up this publisher's chain cannot do: an x402 Solana channel is opened
 * through the connector's sponsor, which only opens, so a channel that runs
 * short is replaced by a fresh sponsored one on the next payment instead
 * (client 4.0.0). A caller's error, not the connector's.
 */
export class TopupUnsupportedError extends Error {}

/**
 * Add collateral to the open channel and report the new state.
 *
 * `getClient` is a factory, not the client itself, and is called ONLY once
 * `amount` has already parsed and `chain` can be topped up at all — a refused
 * request must never build a client (dial the connector, and beside a hidden
 * provider open a hidden-service circuit) just to be refused. It resolves to
 * anything shaped like `ChannelFacade`'s owner — real (`ToonClient`) in
 * production, a stub `{ channel: { deposit: async () => … } }` in tests.
 * `client.channel.deposit` resolves to the channel's `BatchChannelSummary`,
 * and is monotonic (a deposit can never decrease it), so this never needs to
 * read the channel first.
 */
export async function topup(getClient, amount, chain) {
  const parsed = parseAmount(amount);
  if (chain === 'solana') {
    throw new TopupUnsupportedError(
      'a Solana channel is not topped up: the next payment it cannot cover opens a fresh sponsored one (TOON_DEPOSIT sizes it)',
    );
  }
  const client = await getClient();
  const summary = await client.channel.deposit(parsed);
  const remaining = summary.depositTotal > summary.signed ? summary.depositTotal - summary.signed : 0n;
  return {
    channelId: summary.channel.channelId,
    chain: summary.channel.chain,
    deposit: summary.depositTotal.toString(),
    spent: summary.signed.toString(),
    remaining: remaining.toString(),
  };
}
