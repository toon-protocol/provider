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

## `GET /status` and `POST /topup`: the operator's view of the channel

(TOON_Network#171, ADR 0029 §3 "Publisher" and "Money": top-up.) Two more
routes on the same private listener as `/publish` — same host, same port,
same rule that reaching this process at all is what the deploy shape treats
as authorization. Neither is ever in `docker-compose.yml`'s `ports:`.

```
GET /status
-> 200  { "channelId": "…", "chain": "solana",
          "deposit": "10000000", "spent": "1500000", "remaining": "8500000",
          "signedCeiling": null, "watermarkUncertain": false,
          "runway_s": 5400,
          "assumptions": [ "runway = remaining ÷ (price per write × writes per cadence): …" ] }

POST /topup  { "amount": "5000000" }
-> 200       { "channelId": "…", "chain": "solana",
               "deposit": "15000000", "spent": "1500000", "remaining": "13500000" }
-> 400       { "error": "…" }   amount is not a positive integer
-> 502       { "error": "…" }   the deposit could not be made (no channel, chain error, …)
```

`GET /status` never builds a client and never dials the connector on its own
— it reads exactly the two files `@toon-protocol/client`'s
`JsonFileChannelStore` already writes for the channel this process pays on:

- `TOON_CHANNEL_STORE` (default `channels.json`) — the watermark: `spent`
  (`cumulativeAmount`), `signedCeiling` and `watermarkUncertain`.
- its sibling `channels.peers.json` — the binding: `deposit` (`depositTotal`,
  kept current on every deposit) and which chain it is on.

`remaining` is `deposit - spent`, floored at zero. `runway_s` is
`remaining ÷ (price per write × writes per cadence)`: the cadence comes from
`TOON_LIVENESS_CADENCE_S`, and the price is the connector's **currently
advertised** price for every configured `RELAY_WRITE_ROUTES` destination,
summed — asked live (`ToonClient.price`), but only when this process has
already talked to that connector (i.e. it has already published something).
Either input missing — no cadence configured, or nothing published yet —
means `runway_s: null`, and `assumptions` always says exactly what the figure
does or does not rest on, rather than leaving a number to be trusted blind or
a `null` to be guessed at.

`POST /topup` calls the client's own `channel.deposit(amount)` on the channel
already open with this connector — `amount` is validated (a positive integer,
in the token's smallest unit, same units as `TOON_DEPOSIT`) **before** this
process builds or reuses a client, so a bad request never dials the connector
(or, beside a hidden provider, opens a hidden-service circuit) only to be
refused. It shares `/publish`'s serialization queue: a deposit and a claim
both touch this channel's tracked state, and the client is not safe to use
from two calls at once.

`toon-provider topup <amount>` (the provider CLI) is the guided way to call
this from the box: `docker compose exec provider toon-provider topup 5000000`,
the same way `evict` is run, confirming first unless `--yes` is given.

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
| `TOON_LIVENESS_CADENCE_S` | — | Seconds between this provider's Liveness writes, used by `GET /status` to estimate a runway. Optional: unset means `/status` reports `runway_s: null` and says why. |
| `TOON_TRANSPORT` | `http` | The ILP carriage the packets are paid over: `http`, `auto` or `btp`. See below. |
| `RELAY_WRITE_ROUTES` | `{}` | JSON map of relay READ url -> the PAID ILP destination that writes to it, e.g. `{"ws://relay:7100":"g.toon.relay"}`. |
| `TOON_ENDPOINT_REWRITE` | `{}` | JSON map of advertised URL prefix -> the address this process can actually reach it at. Applies to the BTP socket's `ws://` URL too. |
| `TOON_SOCKS_PROXY` | — | `socks5h://<host>:<port>` used when a publish request names none. |
| `TOON_HIDDEN` | `false` | This publisher sits beside a **hidden** provider. Then `TOON_SOCKS_PROXY` is **required** and a missing one is a startup refusal. |
| `TOON_PROXY_RPC` | — | Beside a proxy, whether `TOON_RPC_URL` rides it (`true`) or is dialled directly (`false`, only for your own node on a private address). Unset: a private address or one-label compose name is direct, anything else rides the proxy. See below. |

`RELAY_WRITE_ROUTES` is what keeps the ephemeral lane out: a destination
ending in `.ephemeral` is refused at startup by name.

### Which carriage the packets ride

`TOON_TRANSPORT` defaults to `http`, a one-shot POST per packet, because
that is what publishing is: a handful of packets a minute, serialized through
one channel. BTP's ordered socket buys nothing for that.

But **a node may pin a route to one carriage**, and the devnet relay pins
`g.toon.relay` to BTP. An HTTP one-shot there comes back refused carrying
`extra.requiredTransport`, and the provider's Profile, Listings and Liveness
are never written at all. `TOON_TRANSPORT=btp` names the socket outright,
which is what a deployment against that relay wants. `auto` reads the pin out
of the node's own self-description, and that relay's `GET /ilp` did not
publish it when last checked (2026-09-22, see `deploy/docker-compose.yml`),
so there `auto` falls back to HTTP and is refused.

**Every carriage rides the same route** (`proxy.mjs`, `carriageThrough` and
`clientRouteOptions`), so the client edge and the BTP socket cannot disagree:

* **Beside a proxy** the client is given `socksProxy` and nothing to dial
  with: `@toon-protocol/client` 3.3 then carries every byte through it — the
  client edge, the BTP socket and the chain RPC (see "Publishing from a
  hidden provider"). Handing it a `fetch` anyway would win over its own for
  the edge, so none is handed over unless `TOON_ENDPOINT_REWRITE` needs one.
* **`TOON_ENDPOINT_REWRITE`** applies to both halves. With no proxy they are
  this host's own `fetch` and `WebSocket`, rewritten; beside one they are the
  client library's SOCKS5h carriage (`createHiddenServiceTransport`),
  rewritten — both of them, because given only the `fetch` the client would
  open the socket itself, from this host's real address (the gap
  TOON_Network#165 closed). A `ws://`/`wss://` URL is matched against the same
  `http://`/`https://` prefixes and keeps its own scheme, so the node is
  named once.

`TOON_ENDPOINT_REWRITE` exists because a client dials the endpoint a
connector's **self-description advertises**, not the URL it was configured
with — one free `GET /ilp` is the whole of bootstrapping. Normally those are
the same node by the same name and this stays empty. It is not empty in the
sandbox: the hub advertises `http://127.0.0.1:3200/ilp` so the host-run smokes
can dial it, and a container on the compose network reaches the same node at
`http://relay-connector:3000`.

## Publishing from a hidden provider

A [Hidden Provider](../../README.md#hidden-provider) (spec §10, ADR 0008, ADR 0030)
hides where it is, and this process is part of its outbound: every relay write
it buys is a packet to a connector, and one sent from the host's real address
would name the operator's location to that connector whatever the provider's
Profile claims.

So a publish request from a hidden provider **carries the proxy**, and this
process dials through it — **for every host, not only `.anyone` ones, and on
every carriage**: the HTTP one-shot and the BTP socket alike, so a hidden
publisher can write to a relay that pins BTP. A
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

**The chain RPC rides the proxy too** (spec §10, ADR 0030). Beside a proxy
this process is a *hidden payer* (`@toon-protocol/client` 3.3,
TOON_Network#167): its channel opens, deposits, closes and the chain reads
behind them go through the proxy, each chain on a circuit pinned by SOCKS
username (`toon-client-rpc-evm`, `toon-client-rpc-solana`), and a proxy that
is down fails the call — nothing falls back to a direct dial. So a hidden
provider's publisher pays from the **public** preset RPC
(`https://api.devnet.solana.com`), and needs no chain node of its own. The RPC
provider still sees this wallet's queries and transactions, which are public
on chain anyway; it sees an exit relay's address, not this host's. Use a
keyless RPC: an API key ties every query to the account that holds it, proxy
or not.

Until TOON_Network#167 the client refused `socksProxy` beside a clearnet
connector, this process had to hand it a proxied `fetch` that never carried
chain RPC, and a hidden publisher refused to start beside any RPC but a
private one. That refusal is gone.

**The one exception is your own node.** An RPC on loopback or a private
address — what `HIDDEN_SETTLEMENT_SOLANA_RPC_URL` names in the deploy bundle
— is one no exit could reach, so it is dialled directly (`proxyRpc: false`),
and it never crosses a network anyone outside can watch. `TOON_PROXY_RPC`
says which:

* `false`: dial `TOON_RPC_URL` directly. Beside a hidden provider it must then
  be **near** — loopback, a private or link-local range, or a name resolving
  only to those — or this process refuses to start:

  ```
  [publisher] TOON_HIDDEN is set and TOON_PROXY_RPC=false, so TOON_RPC_URL must
  be your own node on a private address, not "https://api.devnet.solana.com":
  dialled directly, a public RPC would see this host's real address on every
  channel operation. …
  ```
* `true`: through the proxy, whatever it is.
* unset: an address literal, `localhost` or a one-label compose-network name
  (`solana-validator`) is dialled directly when it is near; **any name with a
  dot in it rides the proxy without being looked up**, because a DNS query
  from this host for the public RPC it hides from is a small leak of its own.

The deploy bundle's hidden overlay sets `TOON_PROXY_RPC=false` exactly when
the operator self-hosts, and leaves it unset otherwise.

A provider that is not hidden sends no `proxy` field and this process behaves
exactly as it did before the field existed — absent means direct.

## Tests

`npm test` (`node --test`) covers `proxy.mjs` — which proxy a publication
rides, what is refused at startup, whether the chain RPC rides it, what the
client is handed, and that the `fetch` and the BTP socket take the same
route — `blob.mjs` below,
`status.mjs` (`status.test.mjs`, against real fixture channel files in
`test/fixtures/`) and `topup.mjs` (`topup.test.mjs`, against a stubbed
client). None of these needs network, a chain or a mnemonic.

## Deciding a Blob Record's shape: `blob.mjs`

A Blob Record's content (spec §8.2, §11 item 2, TOON_Network #73) carries
EXACTLY ONE of `parts` (today's shape) or `pages` — the large-blob shape a
record over roughly 700 parts (~70 MB at the sandbox's 100 KiB part size)
needs, since that many parts do not fit inline in one TOON store data item.
`blob.mjs` is the pure half of that decision: bytes in, a plan out — which
shape the record gets, the ordered parts either way, and the exact bytes
every upload (a part, or a page) would carry. Like `publish.mjs`, it holds no
identity and touches no network: signing the record and uploading these
bytes to a real store is the caller's job (the sandbox's
`infra/sandbox/scripts/publisher`, which imports `planBlobRecord` from here
for the decision and keeps only the signing and the paying — `make
smoke-m7` publishes a paged image through it — or any other deployment).
The threshold is measured on the WHOLE signed event, escaped content and
tags included: at the 100 KiB part size, 689 parts stay inline and 690 page.

```js
import { planBlobRecord } from './blob.mjs';
const plan = planBlobRecord({ bytes, partSize, dataItemMax });
// plan.parts XOR plan.pages is non-null; plan.uploads is every upload
// (`{ kind: 'part' | 'page', txid, bytes }`) in the order a real storer
// would pay for them.
```

`blob-cli.mjs` is a thin driver over it — `node blob-cli.mjs plan <file>
[--part-size N] [--data-item-max N] [--parts-per-page N]` prints the plan as
JSON (byte fields as `bytes_hex`) — so the decision can be watched from
OUTSIDE this process: `toon-provider`'s own `tests/publisher_blob_tool.rs`
runs it as a subprocess on both sides of its threshold and hands what it
planned to this provider's real `BlobFetcher`, proving the tool's output and
the provider's reader agree on the same bytes whichever shape the record
took (the pattern `tests/gateway_handover.rs` already uses for
`tools/grant/seal.mjs`). The switch point (`dataItemMax`, `partSize`) is this
tool's own choice, never the protocol's.

## Why the provider knows relays by URL and this process knows them by route

The Relay Set is a list of relay URLs — that is what the Profile publishes and
what a tenant reads from. What it costs to write to one, and which ILP address
sells that write, is a fact about *this provider's* money, not about the relay
a tenant reads. Keeping the two apart means adding a relay to the Relay Set is
a provider config change and pointing at a different paid route is a publisher
config change, and neither forces the other.
