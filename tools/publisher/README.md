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
POST /publish  { "event": <signed nostr event>,
                 "relays": ["ws://relay:7100"],
                 "proxy": "socks5h://anon:9050" }   optional; absent = direct
->  200        { "accepted": ["ws://relay:7100"], "failed": { } }
->  400        { "error": "…" }          the body, or the proxy, is unusable
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
| `TOON_ENDPOINT_REWRITE` | `{}` | JSON map of advertised URL prefix -> the address this process can actually reach it at. |
| `TOON_SOCKS_PROXY` | — | `socks5h://<host>:<port>` used when a publish request names none. |
| `TOON_HIDDEN` | `false` | This publisher sits beside a **hidden** provider. Then `TOON_SOCKS_PROXY` is **required** and a missing one is a startup refusal. |
| `TOON_PROXY_RPC` | `false` | Send the chain RPC through the proxy too. Leave off for a self-hosted RPC; turn on for a public one. |

`RELAY_WRITE_ROUTES` is what keeps the ephemeral lane out: a destination
ending in `.ephemeral` is refused at startup by name.

`TOON_ENDPOINT_REWRITE` exists because a client dials the endpoint a
connector's **self-description advertises**, not the URL it was configured
with — one free `GET /ilp` is the whole of bootstrapping. Normally those are
the same node by the same name and this stays empty. It is not empty in the
sandbox: the hub advertises `http://127.0.0.1:3200/ilp` so the host-run smokes
can dial it, and a container on the compose network reaches the same node at
`http://relay-connector:3000`.

## Publishing from a hidden provider

A [Hidden Provider](../../README.md#hidden-provider) (spec §10, ADR 0008)
hides where it is, and this process is part of its outbound: every relay write
it buys is a packet to a connector, and one sent from the host's real address
would name the operator's location to that connector whatever the provider's
Profile claims.

So a publish request from a hidden provider **carries the proxy**, and this
process dials through it — **for every host, not only `.anyone` ones**. A
hidden provider whose payer reached a clearnet hub directly would have named
this host to the hub, connector address notwithstanding. The scheme must be
`socks5h`: under plain `socks5` this process resolves the destination first,
which for an `.anyone` connector puts the hidden service into a plaintext DNS
query. A request naming anything else is answered `400`, never quietly dialled
direct.

`TOON_SOCKS_PROXY` is the same thing from the operator's side: the proxy for
requests that name none. `TOON_HIDDEN=true` says this publisher sits beside a
hidden provider, and then **starting without a proxy is refused**:

```
[publisher] TOON_HIDDEN is set, so TOON_SOCKS_PROXY is required: a publisher
beside a hidden provider would otherwise reach the connector from this host's
real address, which is the one thing the provider is hiding (spec §10, ADR 0008).
```

Set both in the sandbox's `hs` profile: the provider's `anon.socks_proxy` and
this process's `TOON_SOCKS_PROXY` name the same daemon, and `TOON_HIDDEN=true`
makes a half-wired deployment fail loudly at start rather than leak quietly at
the first publication.

**The chain RPC is the exception.** A hidden provider runs its own settlement
RPC on loopback or a private address — the provider refuses to start
otherwise — and `anon` builds no circuit to a private address, so routing it
through the proxy would fail rather than hide anything; the packet never
leaves the box to begin with. Set `TOON_PROXY_RPC=true` only when this process
is pointed at a public RPC, where that hop does leave.

A provider that is not hidden sends no `proxy` field and this process behaves
exactly as it did before the field existed — absent means direct.

## Tests

`npm test` (`node --test`) covers `proxy.mjs`: which proxy a publication
rides, what is refused at startup, and what stays direct. It needs no network,
no chain and no mnemonic.

## Why the provider knows relays by URL and this process knows them by route

The Relay Set is a list of relay URLs — that is what the Profile publishes and
what a tenant reads from. What it costs to write to one, and which ILP address
sells that write, is a fact about *this provider's* money, not about the relay
a tenant reads. Keeping the two apart means adding a relay to the Relay Set is
a provider config change and pointing at a different paid route is a publisher
config change, and neither forces the other.
