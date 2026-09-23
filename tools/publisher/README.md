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
| `TOON_TRANSPORT` | `http` | The ILP carriage the packets are paid over: `http`, `auto` or `btp`. See below. |
| `RELAY_WRITE_ROUTES` | `{}` | JSON map of relay READ url -> the PAID ILP destination that writes to it, e.g. `{"ws://relay:7100":"g.toon.relay"}`. |
| `TOON_ENDPOINT_REWRITE` | `{}` | JSON map of advertised URL prefix -> the address this process can actually reach it at. |
| `TOON_SOCKS_PROXY` | — | `socks5h://<host>:<port>` used when a publish request names none. |
| `TOON_HIDDEN` | `false` | This publisher sits beside a **hidden** provider. Then `TOON_SOCKS_PROXY` is **required** and a missing one is a startup refusal. |

`RELAY_WRITE_ROUTES` is what keeps the ephemeral lane out: a destination
ending in `.ephemeral` is refused at startup by name.

### Which carriage the packets ride

`TOON_TRANSPORT` defaults to `http` — a one-shot POST per packet — because
that is what publishing is: a handful of packets a minute, serialized through
one channel. BTP's ordered socket buys nothing for that.

But **a node may pin a route to one carriage**, and the devnet relay pins
`g.toon.relay` to BTP. An HTTP one-shot there comes back refused carrying
`extra.requiredTransport`, and the provider's Profile, Listings and Liveness
are never written at all. `TOON_TRANSPORT=auto` reads the pin out of the
node's own self-description and dials whatever it asks for, which is what a
deployment against such a relay wants.

**A pin is published on the route that enforces it** (connector ADR 0072,
TOON_Network#111): each entry in `routes[]` carries a `requiredTransport` where
that route pins one, and a node-wide `requiredTransport` beside them summarises
the routes covering the node's own addresses — stated only where they agree. The
relay's do not agree (`g.toon.relay` is pinned, `g.toon.relay.ephemeral` is not),
which is why for a while it published no pin at all while refusing every
HTTP-carried write to the first prefix, and why `deploy/docker-compose.yml` names
`btp` outright until the relay box runs a connector that publishes the per-route
field. `curl -s <relay>/ilp | jq '.routes[] | select(.prefix == "g.toon.relay")'`
is the whole check.

**Two things the HTTP carriage carries that a websocket does not**, and both
are startup refusals rather than warnings, because both fail silently:

* **`TOON_SOCKS_PROXY` / `TOON_HIDDEN`.** The SOCKS5h carriage is installed as
  this process's `fetch`. BTP opens a websocket that never passes through it,
  so a hidden publisher on BTP would reach the connector from this host's real
  address while every log line still said it was proxied — the exact leak
  `TOON_HIDDEN` exists to prevent (spec §10, ADR 0008).
* **`TOON_ENDPOINT_REWRITE`.** The rewrite is applied inside that same `fetch`,
  so BTP would dial the advertised address verbatim and fail to connect for a
  reason nothing names.

Either combination refuses to start, by name. The sandbox sets both a rewrite
and (on the `hs` profile) a proxy, so it stays on `http`; a devnet box sets
neither and uses `auto`.

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

**The chain RPC is the one exception, and it is decided by where the RPC is,
not by a flag.** A hidden provider runs its own settlement RPC on loopback or
a private address — the provider refuses to start otherwise — and `anon`
builds no circuit to such an address, so routing it through the proxy would
fail rather than hide anything; the packet never crosses a network anyone
outside can watch. So `TOON_RPC_URL` is dialled directly exactly when it is
**near**: loopback, a private or link-local range, or a name resolving only to
those — the same rule the provider applies to this publisher's own address.
An RPC anywhere else does leave, and rides the proxy like everything else.
There is no flag to get that wrong with.

A provider that is not hidden sends no `proxy` field and this process behaves
exactly as it did before the field existed — absent means direct.

## Tests

`npm test` (`node --test`) covers `proxy.mjs` — which proxy a publication
rides, what is refused at startup, and what stays direct — and `blob.mjs`
below. Neither needs network, a chain or a mnemonic.

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
