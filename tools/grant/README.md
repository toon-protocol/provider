# The handover tool

The tenant's side of a Workload Gateway: one command that **derives** a
[Gateway Grant](https://github.com/toon-protocol/TOON_Network/blob/main/CONTEXT.md)
from a lease's **Root Secret** and **seals** it to the gateway's own
connector. It holds no Nostr key, signs nothing, publishes nothing and reads
no relay. Its third command, [`rotate`](#rotating-the-token), replaces the
lease's Continuation Token at every member of its Standby Set — the one act
that also takes a grant back.

A Gateway Grant is a value, not an event (spec §6.5.1):

```
continuation(provider) = HKDF-SHA256(root_secret, "toon-network-continuation:" || provider_pubkey)
gateway_sub(provider, expires_at) = HKDF-SHA256(continuation(provider), "toon-network-gateway:" || expires_at)
```

The gateway presents that value as its `status` request's `continuation` and
names the moment in `gateway_expires_at`; the provider recomputes it from the
Continuation Token it already stores and answers the gateway exactly what it
would have answered the tenant. Nothing is stored per gateway and no relay is
read — by anybody.

| Who | Holds |
|---|---|
| the tenant (this process) | the lease's root secret, and the payment channel that buys the packet |
| the Workload Gateway | the grant it was handed, and its pinned connector sealing key |
| the provider | the lease's Continuation Token, which it already had; nothing per gateway |

## The two messages

Both go to the same place, over the same channel, in the same shape:

**Gateway Handover** — the tenant chooses this gateway. It carries what the
gateway needs and can read nowhere else:

```json
{ "handover": {
    "workload_id": "…",
    "standby_set": [
      { "provider": "<primary>", "grant": "<64 hex>" },
      { "provider": "<standby>", "grant": "<64 hex>" }
    ],
    "http_port": 443,
    "expires_at": 1700086400,
    "name": "blog" } }
```

Neither message carries a `gateway` field: being sealed to that connector is
what names it. The report this tool prints does name one, for the tenant's own
record — it is not part of what is sealed.

**Gateway Withdrawal** — the tenant stops this gateway serving the workload.
It names the workload and bears the grant currently in force, which is what
makes it safe with no signature: only a party holding the lease's root secret
can derive that value.

```json
{ "withdrawal": {
    "workload_id": "…",
    "expires_at": 1700086400,
    "standby_set": [ { "provider": "…", "grant": "<64 hex>" } ] } }
```

The members are spelled exactly as a handover spells them: the same fact, so
a gateway that can read one can read the other.

### One grant per member of the Standby Set

`standby_set` is the set in its own order, primary first, and **each entry
carries the grant derived for its own key** — because `gateway_sub` derives
from `continuation(provider)`, which is per provider (spec §6.1.1, §7). A
single value would read the lease at one member and be `bad_grant` at every
other, and a gateway resolving a workload asks **all** of them (§12.4). The
per-member derivation is what stops one member of a set acting as the tenant
against another, and the tool does not undo it.

A member and its grant are **one entry** rather than two lists to line up, so
there is nothing to fall out of step and no member that can reach a gateway
without the value that reads its lease (spec §12.1).

## A withdrawal ends serving, not reading

**A withdrawal is not a revocation, and must not be read as one.** The
withdrawn gateway keeps the grant it was handed, and that grant reads the
lease's `status` until its `expires_at` whether or not a withdrawal was ever
sent. A withdrawal asks a gateway to stop *serving* a workload; it takes no
derived value back.

**Rotating the lease's token is the revocation** (spec §6.5.1, §6.8,
ADR 0018). `rotate` replaces the Continuation Token every member holds, and
a provider recomputes a grant from the one token it stores — so every grant
derived from the old token is `bad_grant` at once, at every member, and the
gateway that held one stops *reading* too. A tenant that wants to keep its
gateway runs `handover` again afterwards: the lease file now holds the new
root secret, the grants derive from the new tokens, and the gateway's
ordinary admission round replaces what it held.

## A grant rotates by re-derivation; a token rotates by `rotate`

A grant has no rotation of its own. The same root secret, Standby Set and
`expires_at` produce the same grant byte for byte on any machine, so:

- run `handover` again with a **later `--expires-at`** and the gateway holds a
  grant that outlives the one it had — the old one keeps working until its own
  moment passes, which is what makes handing out a later grant an ordinary
  second derivation rather than a migration;
- run `handover` against a **different gateway** and that gateway can read the
  lease too; withdraw from the first one to stop it serving (above), and
  `rotate` to stop it reading.

## Rotating the token

```
node seal.mjs rotate --lease <lease.json> \
    --member <pubkey>,<ilp address>,<seal key> [--member …]
```

One command rotates the **whole Standby Set** (spec §6.8):

1. It mints a **fresh root secret** — never re-used, never derived from the
   old one — so if the old root secret is what leaked, it derives nothing that
   works afterwards.
2. It writes the new root secret into the lease file, as
   `rotation.root_secret`, **before any request leaves**. A crash straight
   after a member accepted cannot lose the only secret that now reads it there.
3. It sends **one rotate request per member**, each naming only that member,
   presenting the token the old root derives for it and naming as `next` the
   token the new root derives for it. Every member ends with a different
   token, exactly as at spawn.
4. As each member confirms it is recorded (`rotation.confirmed`). Once
   **every** member has, `root_secret` becomes the new one and the old one is
   dropped. Until then the file keeps **both**, because a member that has not
   rotated is still read with the old root.

**A lost answer is recovered by reading, not by retrying.** The same rotate
again is `stale_request`, and a new one with the old token after the first
took effect is `not_tenant`. So when no answer comes back — or the answer is
`not_tenant`, which is what an earlier run's lost answer looks like — the
tool asks `status` presenting the **new** token: accepted means the rotation
took effect (`"recovered": true` in the report), and `not_tenant` means it did
not and the old token still holds.

**A partly rotated set is a valid state.** A member that cannot be reached
does not block the others. The tool exits `1`, the file records which members
confirmed, and running the same command again **resumes** the rotation with
the same new root secret, leaving the confirmed members alone. It refuses to
resume naming other members than it started with, because a member left out
would be read with a root secret the file no longer holds.

The lease file is any JSON object holding `workload_id` and `root_secret` —
the sandbox's `scripts/spawn.mjs` writes one — and every other key in it is
kept as it was. It is replaced atomically, mode `0600`. The root secret is
read from it and **only** from it: `--root-secret` and `TOON_ROOT_SECRET` are
refused on `rotate`, because a rotation writes a root secret back and one
from the command line would have nowhere to go.

Each `--member` is a member's public key, the `ilp_address` its Provider
Profile names (the tool sends to `<ilp address>.rotate`, and `.status` to
recover) and its connector's **pinned** `connector_seal_key` (ADR 0011), as
hex, with or without `0x`. There is no `--dry-run`: a new root secret is
nothing until the members hold it. The report names each member and whether
it rotated, and carries no secret:

```json
{ "workload_id": "…", "rotated": true,
  "members": [ { "provider": "…", "rotated": true },
               { "provider": "…", "rotated": true, "recovered": true } ] }
```

## Usage

```
node seal.mjs handover --workload <64 hex> \
    --standby <pubkey> [--standby <pubkey>…] --http-port <container port> \
    [--ports <port,port,…>] [--name <label>] \
    (--expires-at <unix seconds> | --expires-in <24h | 90m | 7d | seconds>) \
    --gateway-route <ilp address> --gateway-seal-key <hex> \
    [--root-secret <64 hex>] [--dry-run]

node seal.mjs withdrawal --workload <64 hex> \
    --standby <pubkey> [--standby <pubkey>…] --expires-at <unix seconds> \
    --gateway-route <ilp address> --gateway-seal-key <hex> \
    [--root-secret <64 hex>] [--dry-run]

node seal.mjs rotate --lease <lease.json> \
    --member <pubkey>,<ilp address>,<seal key> [--member …]
```

`rotate`'s two flags are its own and are described [above](#rotating-the-token);
the table below is `handover`'s and `withdrawal`'s.

| Flag | Meaning |
|---|---|
| `--root-secret` | The lease's root secret, 64 hex. Or `TOON_ROOT_SECRET`, which is where it belongs: argv is readable by every process on the host. The **only** secret this tool takes. |
| `--workload` | The workload id the spawn was signed with. |
| `--standby` | The Standby Set, **primary first**, one flag per member. A standalone lease's is its one provider. One grant is derived for each. |
| `--http-port` | Which of the spawn's `ports` carries HTTP, as the **container** port. The gateway forwards to the host port the provider's `access` maps it to. |
| `--ports` | Every `container_port` the spawn asked for, comma-separated, so `--http-port` can be checked against them before anything is sealed. |
| `--expires-at` / `--expires-in` | The moment the grant is derived for (unix seconds, or a duration from now). Exactly one, and a **withdrawal takes `--expires-at` only**: it names the moment its handover named. |
| `--name` | Optional: a short name the gateway may serve the workload at beside the canonical one it derives from the workload id. A single DNS label. |
| `--gateway-route` | The ILP address the gateway's connector terminates for handovers. |
| `--gateway-seal-key` | That connector's **pinned** secp256k1 key, hex — 65-byte uncompressed (`04…`, as a connector's `GET /ilp` reports it) or 33-byte compressed. Pinned out of band exactly as a Provider Profile's is (ADR 0011); nothing is fetched to learn it. |
| `--dry-run` | Derive the message, print it, and stop. Nothing is paid for, no channel is opened — and no `npm install` is needed, because deriving a grant needs nothing but Node. |

Stdout is one JSON report; progress goes to stderr:

```json
{
  "workload_id": "…",
  "gateway": { "route": "g.toon.workload-gateway.handover", "seal_key": "04…" },
  "handover": { "…": "the message, as sealed" },
  "delivered": true
}
```

Exit `0` when the gateway took the message (and on a `--dry-run`) or every
member rotated, `1` when it did not, and `2` for a refusal before anything was
derived or paid for. A
gateway that refused is reported in `failed` beside the message, never raised:
a tenant must be able to see what it derived and send it again.

## What it refuses, before sealing

A provider refuses a grant it cannot use as `bad_grant`, after the gateway has
already built a request around it (spec §6.5.1), and a gateway acts on
`http_port`, `standby_set` and `name` with no provider ever checking them. So
everything either party would trip on is refused **here**, with a message
naming the problem, and nothing is derived or sent:

| Refused | Because |
|---|---|
| an `expires_at` already past, or this very second | the provider's rule is `now <= expires_at`, so a past moment is `bad_grant` at every member, and a grant expiring now is expired by the time a gateway holds it |
| an `--http-port` that is not one of `--ports`, when `--ports` is given | the gateway would forward to a port the workload never asked for. `--ports` is optional, and the check is only as good as the list it is given |
| a root secret that is not 64 lowercase hex | not a root secret — and the value is **never quoted back**, whatever is wrong with it |
| a Standby Set member that is not 64 lowercase hex, or one named twice | not a public key; the key is spelled into the derivation exactly as the provider spells it |
| a `--name` that is not a single DNS label | the gateway serves `<name>.<gateway-domain>`: 1–63 lowercase letters, digits and hyphens, no leading or trailing hyphen, no dots |
| a gateway route that is not an ILP address, or a sealing key that is not a secp256k1 point | there is nothing to seal to |
| `--http-port`, `--ports` or `--name` on a **withdrawal** | they are a handover's: a withdrawal names the workload and bears its grant, and the gateway already holds everything else. Named rather than dropped |

Each rule is named on its own (`name "Blog" must be lowercase`, not "invalid
name"), because the fix is one character and the message should say which.

## How it reaches the gateway

The message is sealed to the gateway's pinned key by the connector client's
**own** sealing path — `sealTo`, the same path a tenant's request to a
provider takes and the same one the sandbox's smokes take to a provider's
pinned edge. There is no second sealing implementation here (ADR 0011), and
the key is handed over as bytes: it was pinned out of band, so there is no
`GET /ilp` to fetch it from and no hop that could name it on the gateway's
behalf.

Reaching a gateway's connector is an ordinary packet, so this process holds a
payment channel exactly as the [directory publisher](../publisher/README.md)
does, and reads the same environment name for name.

| Variable | Default | Meaning |
|---|---|---|
| `TOON_ROOT_SECRET` | — | The lease's root secret, hex. Or `--root-secret`. **Required.** |
| `TOON_MNEMONIC` | — | **Required to seal** (not for `--dry-run`). The BIP-39 phrase whose key signs the balance proofs. It pays; it is not an identity. |
| `TOON_CONNECTOR_URL` | `http://localhost:3200` | The connector client edge this process pays through. |
| `TOON_ACCOUNT_INDEX` | `0` | Which account of that phrase. |
| `TOON_CHAIN` | `solana` | Settlement chain of the channel it opens. |
| `TOON_RPC_URL` | `http://127.0.0.1:8899` | That chain's RPC. |
| `TOON_CHANNEL_STORE` | `.toon-client/channels.json` | The channel watermark, relative to the working directory. One store admits one client at a time. |
| `TOON_DEPOSIT` | `10000000` | Channel deposit in the token's smallest unit (10 USDC at 6 dp). |
| `TOON_TIMEOUT_MS` | `60000` | Per-packet timeout. |
| `TOON_ENDPOINT_REWRITE` | `{}` | JSON map of advertised connector URL prefix → the address this process can reach it at (see the publisher's README). |

There is no `RELAY_WRITE_ROUTES`: this tool writes to no relay. `TOON_SOCKS_PROXY`
and `TOON_HIDDEN` are deliberately absent — a tenant is not what spec §10 hides.

Deriving needs none of it:

```sh
# no npm install, no channel, no network
TOON_ROOT_SECRET=<hex> node seal.mjs handover --workload <id> \
    --standby <primary pubkey> --standby <standby pubkey> \
    --http-port 8080 --ports 8080 --expires-in 24h --name blog \
    --gateway-route g.toon.workload-gateway.handover \
    --gateway-seal-key 04… --dry-run
```

Against a running sandbox stack (`make up` in `infra/sandbox`), drop
`--dry-run` and add `npm install` and a `TOON_MNEMONIC`.

## Tests

`npm test` (`node --test`) needs no network, no chain and no mnemonic.

- **`handover.test.mjs`** — the derivation, the two messages, and every
  refusal, against the wire fixtures the **provider's own** derivation
  generated (`../../tests/fixtures/wire/`): `continuation.vector.json` and
  `gateway_sub.vector.json` for the vectors, and `status.delegated.json` —
  a request the provider's HTTP surface answered `200` — for the grant. A
  sender that must never be reached proves each refusal fired before sealing.
- **`rotate.test.mjs`** — rotation against in-memory members that apply
  spec §6.8 to the one token each stores: the fresh root secret, one request
  per member naming only itself, the lease file keeping both roots until
  every member confirmed, a lost answer recovered through `status`, and a
  partly rotated set resumed. The request's bytes are checked against the
  provider's `lease_request.rotate.json`.
- **`seal.test.mjs`** — the command as a process: the flags, the environment,
  the report, and the exit codes. Each run gets a **bare** environment — no
  mnemonic, no connector, no chain — so a `--dry-run` that works there is one
  that works before any of it is configured. (`@toon-protocol/client` is
  imported lazily, inside the function that opens the channel, which is what
  additionally keeps a dry run free of `npm install`.)

**And the provider proves the rest.** `../../tests/gateway_handover.rs` runs
*this command* — `node seal.mjs handover … --dry-run` — against a real
provider: the grant the run derived is presented as a delegated `status` and
answered `200`, byte for byte what the lease's own tenant is answered. The
two-member case there proves each member takes its own grant and refuses the
other's as `bad_grant`, and a third run proves that re-deriving is how a
grant rotates. `../../tests/rotate_tool.rs` runs this tool's `rotateLease`
against two providers served on real TCP ports: every member of a two-member
set rotated and the lease file updated, a partly rotated set answering each
member with its own current token, and a lost answer recovered through
`status`. Nothing in either file is a mock of anything.

The one seam a message crosses is the sender it is handed
(`send(route, body) → null | why`, the directory publisher's own shape); the
Node tests hand in a fake and read what it was given.
