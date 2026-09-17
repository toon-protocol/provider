# The grant tool

The tenant's side of a Workload Gateway: one command that signs and
publishes a **Gateway Grant** from the tenant's own key.

A [Gateway Grant](https://github.com/toon-protocol/TOON_Network/blob/main/CONTEXT.md) is a tenant's signed,
published delegation that lets **one** Workload Gateway read **one**
workload's lease state and access details until the grant expires (spec
§3.1.3). The gateway carries it inside its own signed `status` request, and
the provider accepts the gateway's signature exactly when a valid grant names
it (§6.5). The tenant's key signs the grant once, here, and never reaches the
gateway, the provider or a relay.

| Who | Holds |
|---|---|
| the tenant (this process) | the Nostr key that signs the grant, and the payment channel that buys the relay write |
| the Workload Gateway | its own key, which the grant names; it reads the grant from a relay |
| the provider | nothing: it verifies the grant out of the `status` request that carried it, and stores none |

## Usage

```
node publish.mjs --workload <64 hex> --gateway <pubkey> \
    --http-port <container port> --ports <port,port,…> \
    --standby <pubkey> [--standby <pubkey>…] \
    (--expires-at <unix seconds> | --expires-in <24h | 90m | 7d | seconds>) \
    [--name <label>] [--relay <ws://…>…] [--key <64 hex>] [--dry-run]
```

| Flag | Meaning |
|---|---|
| `--workload` | The workload id the spawn was signed with: the grant's `d` tag and its content's `workload_id`. |
| `--gateway` | The Workload Gateway's Nostr public key, hex. The **one** key the grant admits to `status`; also the grant's `p` tag, which is how a gateway finds every grant naming it with one relay filter. |
| `--http-port` | Which of the spawn's `ports` carries HTTP, as the **container** port the spawn asked for. The gateway forwards to the host port the provider's `access` maps it to. |
| `--ports` | Every `container_port` the spawn asked for, comma-separated, so `--http-port` can be checked against them before anything is signed. |
| `--standby` | The Standby Set, **primary first**, one flag per member. A standalone lease's is its one provider. The gateway asks each member's `status` to find where the workload runs. |
| `--expires-at` / `--expires-in` | When the grant stops admitting the gateway (unix seconds, or a duration from now). Exactly one of the two. |
| `--name` | Optional: a short name the gateway may serve the workload at beside the canonical name it derives from the workload id. A single DNS label. |
| `--relay` | A relay to publish to; repeatable. Default: every relay `RELAY_WRITE_ROUTES` names a paid write route for. |
| `--key` | The tenant's Nostr secret key, hex. Or `TOON_TENANT_KEY`. |
| `--dry-run` | Sign, print the event, and stop. Nothing is paid for and no channel is opened. |

Stdout is one JSON report; progress goes to stderr:

```json
{
  "address": "30438:<tenant pubkey>:<workload_id>",
  "event_id": "…",
  "tenant": "<tenant pubkey>",
  "grant": { "workload_id": "…", "gateway": "…", "http_port": 443,
             "standby_set": ["…"], "expires_at": 1700086400, "name": "blog" },
  "accepted": ["ws://relay:7100"],
  "failed": { "ws://other:7100": "g.other.relay refused by g.hub: F02 …" },
  "event": { "kind": 30438, "…": "the signed event, as published" }
}
```

Exit `0` when at least one relay accepted the grant, `1` when none did, and
`2` for a refusal before anything was signed or paid for. A relay that
refused is reported in `failed`, never raised: a grant that reached one relay
of three is a grant a gateway watching that relay finds.

## What it refuses, before signing

A provider checks a grant from the request that carried it and refuses
anything wrong with it as `bad_grant` — after a Workload Gateway has already
built its request around it (spec §6.5). The Workload Gateway acts on
`http_port`, `standby_set` and `name` without a provider ever checking them
(§3.1.3). So everything
either party would trip on is refused **here**, with a message naming the
problem, and nothing is signed:

| Refused | Because |
|---|---|
| an expiry already past, or this very second | the provider would answer `bad_grant` to every request carrying it (its rule is `now <= expires_at`, and a grant expiring now is expired by the time a Workload Gateway has read it) |
| an `--http-port` that is not one of `--ports` | the gateway would forward to a port the workload never asked for |
| a gateway key, or a Standby Set member, that is not 64 lowercase hex | not a public key — or, for the gateway, a spelling its own `#p` filter would not match |
| a `--name` that is not a single DNS label | the gateway serves `<name>.<gateway-domain>`: 1–63 lowercase letters, digits and hyphens, no leading or trailing hyphen, no dots |
| a workload id that is not 64 lowercase hex | not a workload id |

Each rule is named on its own (`name "Blog" must be lowercase`, not "invalid
name"), because the fix is one character and the message should say which.

## Renewal and rotation are the same act as publishing

The grant is addressable on `d = <workload_id>`, so publishing again under
the same tenant key and workload id **replaces** the grant on a relay rather
than adding a second one (spec §3.1.3):

- run it again with a later `--expires-at` and the grant is **renewed**;
- run it again with a different `--gateway` and the workload **moves** to
  that gateway — the old gateway's next `status` is refused, because the
  grant it finds no longer names it.

There is no `renew` and no `rotate` command because there is nothing else to
do. And there is **no revocation before expiry**: the provider checks only
the grant it is handed and never reads a relay, so a tenant that wants a
gateway cut off before its grant expires respawns under a new workload id —
exactly how Standby Set membership is changed (§6.5, §7). Those two —
republishing and respawning — are the only rotation mechanisms. Choose short
expiries and renew.

## Configuration

Environment, name for name what the [directory publisher](../publisher/README.md)
reads, so a tenant beside a sandbox provider sets one environment for both.
A relay write on the TOON Network is a **paid packet** on the paid relay
route, never the free ephemeral lane (ADR 0007), and this process pays for it
the same way the publisher pays for the provider's: one `@toon-protocol/client`
on one payment channel.

| Variable | Default | Meaning |
|---|---|---|
| `TOON_TENANT_KEY` | — | The tenant's Nostr secret key, hex. Or `--key`. **Required.** |
| `TOON_MNEMONIC` | — | **Required to publish** (not for `--dry-run`). The BIP-39 phrase whose key signs the balance proofs. Need not be the tenant's own: the Nostr key signs, the mnemonic pays. |
| `TOON_CONNECTOR_URL` | `http://localhost:3200` | The connector client edge this process pays through. |
| `TOON_ACCOUNT_INDEX` | `0` | Which account of that phrase. |
| `TOON_CHAIN` | `solana` | Settlement chain of the channel it opens. |
| `TOON_RPC_URL` | `http://127.0.0.1:8899` | That chain's RPC. |
| `TOON_CHANNEL_STORE` | `.toon-client/channels.json` | The channel watermark, relative to the working directory. The sandbox's smokes keep theirs at the same path under `infra/sandbox`; one store admits one client at a time. |
| `TOON_DEPOSIT` | `10000000` | Channel deposit in the token's smallest unit (10 USDC at 6 dp). |
| `TOON_TIMEOUT_MS` | `60000` | Per-packet timeout. |
| `RELAY_WRITE_ROUTES` | `{}` | JSON map of relay READ url → the PAID ILP destination that writes to it, e.g. `{"ws://localhost:7100":"g.toon.relay"}`. With no `--relay`, every key is published to. |
| `TOON_ENDPOINT_REWRITE` | `{}` | JSON map of advertised connector URL prefix → the address this process can reach it at (see the publisher's README). |

A destination ending in `.ephemeral` is refused by name. `TOON_SOCKS_PROXY`
and `TOON_HIDDEN` are deliberately absent: a grant is a tenant's publication,
and a tenant is not what spec §10 hides.

In the sandbox, against a running stack (`make up` in `infra/sandbox`):

```sh
cd tools/grant && npm install
TOON_TENANT_KEY=<hex> TOON_MNEMONIC="<the sandbox tenant's phrase>" \
RELAY_WRITE_ROUTES='{"ws://localhost:7100":"g.toon.relay"}' \
node publish.mjs --workload <id> --gateway <pubkey> --http-port 8080 --ports 8080 \
    --standby <primary pubkey> --standby <standby pubkey> --expires-in 24h --name blog
```

## Tests

`npm test` (`node --test`) covers `grant.mjs` and needs no network, no chain
and no mnemonic. It proves the tool against the real thing rather than
against itself:

- **The bytes.** Over the wire fixtures' tenant key, clock and zero signing
  randomness, the tool signs `tests/fixtures/wire/gateway_grant.json`'s event
  **byte for byte** — kind `30438`, the `d`, `p` and `L` tags, the content in
  §3.1.3's declaration order, the `id` and the `sig`. Kind and label are read
  from `constants.json`, not restated.
- **The provider.** `status.granted.json` — generated by the provider's own
  HTTP surface — carries exactly that event and was answered `200` with the
  tenant's own answer; `error.bad_grant.json` shows the refusal for the one
  defect a tenant tool cannot check, another signer. The provider's Rust
  suite (`tests/gateway_grant.rs`) then drives the same fixture event through
  the provider: accepted while in force, `bad_grant` the second after
  `expires_at`.
- **The refusals.** Each one fires with a message naming the problem, and a
  signer that must never be reached proves it fired before signing.
- **Renewal and rotation.** A later expiry and another gateway both publish
  to the same address with the same `d`.

The relay writer is the one seam (`writeTo(relay, event) → null | why`, the
publisher's own shape); the tests hand in a fake and read what it was given.

## Why the content is not sorted

The content is serialised in the order §3.1.3 declares its fields —
`workload_id, gateway, http_port, standby_set, expires_at, name?` — because
the provider's own builder does, the fixture's `id` is the hash of that exact
string, and the spec repository's fixture checker copies the signed string
rather than rebuilding it. A tool that sorted keys would sign a perfectly
valid event that is not the one the fixtures prove.
