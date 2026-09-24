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
 * Add collateral to the open channel and report the new state.
 *
 * `getClient` is a factory, not the client itself, and is called ONLY once
 * `amount` has already parsed — an invalid amount must never build a client
 * (dial the connector, and beside a hidden provider open a hidden-service
 * circuit) just to be refused. It resolves to anything shaped like
 * `ChannelFacade`'s owner — real (`ToonClient`) in production, a stub
 * `{ channel: { deposit: async () => … } }` in tests.
 * `client.channel.deposit` is monotonic on both chains (a deposit can never
 * decrease it), so this never needs to read the channel first.
 */
export async function topup(getClient, amount) {
  const parsed = parseAmount(amount);
  const client = await getClient();
  const state = await client.channel.deposit(parsed);
  return {
    channelId: state.channelId,
    chain: state.chain,
    deposit: state.depositTotal.toString(),
    spent: state.spent.toString(),
    remaining: state.available.toString(),
  };
}
