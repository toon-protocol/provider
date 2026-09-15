# The directory publisher

The provider's payer for relay writes.

A provider publishes its Provider Profile, its Listings and its Liveness to
every relay in its Relay Set, and on the TOON Network **every relay write is a
paid packet** — on the paid relay route, never on the free ephemeral lane
(ADR 0007). Paying one means holding a payment channel on Solana or EVM,
signing a balance proof per packet, and sealing an ILP prepare to the
terminating connector's key.

There is one proven implementation of all of that, `@toon-protocol/client`,
and it is not a Rust crate. Rather than put the marketplace's money on a
second, unproven payer, the provider app splits the decision:

| Who | Decides |
|---|---|
| `toon-provider` (Rust) | **what** to publish, and signs it with the provider's Nostr key |
| this process (Node) | **how** it is paid for, and holds the payment channel |

The seam is one HTTP call, `ConnectorDirectory` in `src/directory.rs`:

```
POST /publish  { "event": <signed nostr event>, "relays": ["ws://relay:7100"] }
->  200        { "accepted": ["ws://relay:7100"], "failed": { } }
->  502        { "error": "…" }          the write could not be ATTEMPTED
```

A per-relay refusal is reported in `failed`, not raised: a provider that
reaches three of its four relays is still discoverable, and one that crashed
because a relay was down would take its paid workloads with it.

The provider's Nostr secret key never reaches this process. It holds money,
not identity — it cannot forge a directory event, only decline to pay for one.

## Configuration

Environment only; there is no config file.

| Variable | Default | Meaning |
|---|---|---|
| `PORT` / `BIND_ADDR` | `8081` / `0.0.0.0` | Where `/publish` listens. PRIVATE — only the provider app should reach it. |
| `TOON_CONNECTOR_URL` | `http://localhost:3200` | The connector client edge this process pays through. |
| `TOON_MNEMONIC` | — | **Required.** The BIP-39 phrase whose key signs the balance proofs. |
| `TOON_ACCOUNT_INDEX` | `0` | Which account of that phrase, so a publisher need not share a wallet with anything else. |
| `TOON_CHAIN` | `solana` | Settlement chain of the channel it opens. |
| `TOON_RPC_URL` | `http://127.0.0.1:8899` | That chain's RPC. |
| `TOON_CHANNEL_STORE` | `/var/lib/toon-publisher/channels.json` | The channel watermark. Must outlive a restart and die with the chain. |
| `TOON_DEPOSIT` | `10000000` | Channel deposit in the token's smallest unit (10 USDC at 6 dp). |
| `TOON_TIMEOUT_MS` | `60000` | Per-packet timeout. |
| `RELAY_WRITE_ROUTES` | `{}` | JSON map of relay READ url -> the PAID ILP destination that writes to it, e.g. `{"ws://relay:7100":"g.toon.relay"}`. |

`RELAY_WRITE_ROUTES` is what keeps the ephemeral lane out: a destination
ending in `.ephemeral` is refused at startup by name.

## Why the provider knows relays by URL and this process knows them by route

The Relay Set is a list of relay URLs — that is what the Profile publishes and
what a tenant reads from. What it costs to write to one, and which ILP address
sells that write, is a fact about *this provider's* money, not about the relay
a tenant reads. Keeping the two apart means adding a relay to the Relay Set is
a provider config change and pointing at a different paid route is a publisher
config change, and neither forces the other.
