# The provider box

One host, five containers, and the workloads it sells.

```
                      ┌────────────────────────────────────────────────┐
 tenant ──seal──▶ 443 │ nginx ──▶ provider-connector :4000             │
                      │              │                                 │
                      │              ▼                                 │
                      │           provider :8080 ──▶ directory-publisher│──▶ relay
                      │              │                                 │
                      └──────────────┼─────────────────────────────────┘
                                     │ /var/run/docker.sock
                                     ▼
                       toon-<id> (+ toon-<id>-dind on a `docker` tier)
                       on THIS host's daemon, ports published on its own
                       public address — never through nginx.
```

| File | What it is |
|---|---|
| `docker-compose.yml` | The five services. The connector's pin lives here and nowhere else. |
| `provider.toml.template` | Who this provider is, filled in from `.env`. Rendered — **and the rendered file is a secret.** |
| `listings.example.toml` | What a provider sells: the devnet box's own tiers. Copy it to `listings.toml` (gitignored) and make it yours. |
| `connector.toml.template` | The connector's config. Its `[[routes]]` are *generated* at render time, not written. |
| `nginx/node.conf.template` | Two server blocks: the paid edge, and `GET /health`. Rendered. |
| `render.sh` | Renders the above from `.env` and the listings file. Idempotent. |
| `bootstrap.sh` | Fresh host → running box, including the sealing-key handshake. Idempotent. |
| `init-letsencrypt.sh` | Issues or reuses the certificate. Idempotent. |
| `auto-apply.sh` + the two units | The box half of GitOps: follow the branch, apply what merged. |
| `.env.example` | Every variable, with what it is and how to generate it, and the devnet's relay and settlement values as a preset. |

The guard is `../tests/deploy_bundle.rs`, and it runs under the ordinary
`cargo test`. It is not a regex suite: it runs the **real** `render.sh` on the
devnet preset in `.env.example` and on `listings.example.toml`, with the
**real** `toon-provider` binary generating the routes, and puts what comes out
through the **real** config loader. So the strongest thing it asserts is that
`toon-provider routes` on the rendered `provider.toml` prints exactly the
`[[routes]]` the rendered `connector.toml` carries. It also renders a second
operator, with an address and tiers of its own, and checks that nothing of the
devnet box's comes along.

`.env`, `listings.toml`, the rendered `provider.toml` and `connector.toml`,
the operator credentials, `nginx/conf.d/` and all key material are gitignored.
**Only templates and examples are committed**, so everything that makes a box
yours lives outside the checkout, and the checkout stays clean enough for
`auto-apply.sh` to keep fast-forwarding it.

## What is different about a provider box

Three things, and all three follow from what a provider sells.

**It holds the Docker socket.** `toon-provider` shells out to the `docker`
CLI, so a lease's workload is a sibling container on *this host's* daemon. That
is, plainly, root on this box. Everything else here is arranged so that the
only way to reach the process holding it is a paid packet through the
connector: the app's listener is `expose`-only, nginx proxies exactly one path
of it by exact match and 404s the rest, and the operator endpoint (which takes
an eviction with no signature and no payment) is loopback *inside* the
container and published nowhere.

**It opens a wide range of public ports.** A tenant reaches its workload at
`PUBLIC_IP:<host port>` — the SSH forward for its lease, and the sixteen
published ports of its block. That is raw TCP on this box's address: **40000 to
40099** for the forwards and **41000 to 42599** for the blocks. `bootstrap.sh`
opens exactly those, and the guard checks the ranges against `provider.toml`,
because a mismatch is a workload nobody can reach on a lease that was still
paid for.

**Its rendered config is a secret.** `provider.toml` carries
`nostr_private_key` *inline* — the app takes the value, not a path to it. That
key signs the Profile, every Listing, every Liveness and every Eviction Notice,
and it is the identity a Lease Request is addressed to. So `render.sh` writes
it `0600`, root-owned, and `.gitignore` refuses it. Every other rendered config
in this fleet names key files and is not a secret; this one is.

## The chicken and the egg: `connector_seal_key`

A tenant seals its spawn to the key this box's connector answers with, and
**refuses to proceed if the Profile names a different one** (ADR 0011). So
`provider.toml`'s `connector_seal_key` is not a setting — it is a copy of a
fact, 130 hex characters long, and the only correct way to get it is to read it
off the connector.

`bootstrap.sh` does that rather than asking anyone to transcribe it:

1. render just enough for the connector, and bring up **only** the connector
   (it terminates routes whose handler is not up yet, which is a 502 to whoever
   pays one, not a refusal to boot);
2. poll `GET /ilp/identity` until it answers;
3. append `CONNECTOR_SEAL_KEY=0x04…` to `.env`;
4. render everything and bring the rest up.

`render.sh` refuses to render without it, and says this. **Regenerate
`signer.key` and you must delete that line and re-run `bootstrap.sh`** — a
Profile naming a stale sealing key is a provider every tenant silently refuses.

## Sizing the box

There is no minimum in the provider's own documentation, deliberately:
*"capacity is declared rather than measured — a tier is a slice of hardware the
provider has decided to sell, and only the provider knows how many slices its
box holds."* So here is this box's arithmetic, honestly.

| | |
|---|---|
| **Plan** | Linode 4 GB (`g6-standard-2`): 2 vCPU, 4096 MiB, 80 GB |
| Sold, at full capacity | `basic` 3 × 512 MiB + `ci` 1 × 1024 MiB = **2560 MiB** |
| The five containers | ≈ 600 MiB (a Rust app, a Rust connector, a Node publisher, nginx, an idle certbot) |
| The host | ≈ 250 MiB |
| Left for page cache and headroom | ≈ 700 MiB |

That is tight on purpose rather than by accident. `render.sh` reads the memory
of the box it runs on and warns when the listings, sold out, leave less than
about 1 GiB for the five containers and the host.
If `dmesg` ever shows the OOM killer, the two knobs are a `capacity` and the
plan — raise them together.

**A nanode cannot do this job.** 1 GiB runs the five containers — themselves
≈600 MiB — and has nothing left to sell: the `basic`/`ci` capacity this table
sells is 2560 MiB on its own, before the host's own overhead. If the `ci` tier
gets real use, `g6-standard-4` (8 GiB, 4 vCPU) is the next honest step.

(Before TOON_Network#151, this box also had to *compile* the provider — this
is the one box in the fleet that built its own app — and a Rust release build
of this crate needed more memory than a nanode has on top of everything above.
`provider` and `directory-publisher` are published images now, pulled like the
connector already was, so that floor is gone; the sold-capacity arithmetic
above is what actually sizes this box.)

**Disk.** 20 GiB of the 80 GB is the verified-blob cache
(`blob_cache_max_bytes`). There is no eviction yet: a blob that would cross the
cap is not kept and the spawn answers `no_capacity`, which is the same answer a
full disk gives.

**There is no Kata, no Firecracker and no VM isolation**, and the Profile says
so: `isolation = "shared-kernel"`. `backend = "docker"` is the only
`ComputeBackend` there is, and `dedicated-host` would be a claim this
deployment cannot make — Linode's shared-CPU plans offer no nested
virtualization to build a hypervisor on, and `/dev/kvm` is not present to pass
through. The `nesting` capability is refused at config load for the same
reason. A tenant filters on that tag, so it has to be true.

## Standing one up

**Before you start** you need a host, two DNS A-records pointing at it —
`proxy.provider.<your-domain>` and `provider.<your-domain>` — an ILP address of
your own, three key files, and two funded identities.

**1. Clone and configure.** Two files are yours, both gitignored: `.env` and
the listings file. Nothing else in the checkout is edited, ever.

```bash
git clone https://github.com/toon-protocol/provider /root/provider
cd /root/provider/deploy
git checkout main
cp .env.example .env
$EDITOR .env          # every variable is documented in the file
cp listings.example.toml listings.toml
$EDITOR listings.toml # what you sell; see § "Make it yours"
```

In `.env`, three values say who you are and have no default: `DOMAIN`,
`PROVIDER_NAME` and `ILP_ADDRESS`. Pick an address of your own, such as
`g.<your-name>.provider`; `render.sh` refuses one under `g.toon.`, the TOON
fleet's namespace. The relay and settlement block is the **devnet preset**:
leave it as it is to join the TOON devnet, which settles in mock USDC.

The box follows `main`, and `auto-apply.sh` tracks `main` unless `.env` says
otherwise. To run ahead of `main` — the way the devnet provider box does while a
milestone is unmerged — check out that branch here instead and set
`TRACK_BRANCH` to the same name in `.env`. Keep the two in agreement: the
timer fast-forwards whatever is checked out to `origin/$TRACK_BRANCH`, and it
applies only a fast-forward, so a checkout that is not an ancestor of that
branch stops it. So does a dirty one: if `git status` in `/root/provider` is
ever not clean, something was edited that belongs in `.env` or the listings
file instead.

**2. Generate the key material.** Four secrets, none of them ever committed.

```bash
# The connector's three. 32 bytes as 64 hex characters is the only format it
# reads — never base58, never a Solana CLI JSON array.
openssl rand -hex 32 > signer.key             # THE SEALING KEY
openssl rand -hex 32 > settlement.key         # the EVM settlement key
openssl rand -hex 32 > settlement-solana.key  # the Solana settlement key

# The provider's own identity, into .env as NOSTR_PRIVATE_KEY.
openssl rand -hex 32
```

`render.sh` sets each key's mode and hands the connector's three to uid 10001,
which is what it runs as. That used to be a step in a runbook, and a step a
human has to remember is a step a human forgets — the failure is a container
that restarts forever with `failed to read signer key_file at
/app/data/signer.key: Permission denied` while everything around it looks fine.

You also need a BIP-39 phrase of its own for `PUBLISHER_MNEMONIC`, shared with
nothing else: two payers on one channel share one nonce watermark, and the loser of
that race has every later claim refused.

Record how each was derived, somewhere off this box. A lost `NOSTR_PRIVATE_KEY`
is a lost provider — new pubkey, empty directory entry, and every tenant
holding a lease addressed to the old one left talking to nobody.

**3. Fund the two identities.** See § "The two funded identities", below. Do
the Solana settlement key **before** the first `up -d`.

**4. Bring it up.**

```bash
./bootstrap.sh
```

Firewall, Docker, journald cap, the `dind` sidecar pre-pull, the sealing-key
handshake, render, build, start, certificate, timer. Idempotent — re-run it to
reconcile a box.

**5. Go to production TLS.** `bootstrap.sh` starts on Let's Encrypt *staging*
so a DNS mistake does not burn the real rate limit. Once
`https://provider.<domain>/health` answers (with a certificate warning), set
`LETSENCRYPT_STAGING=0` in `.env` and re-run `./init-letsencrypt.sh`.

## The two funded identities

**The connector's Solana settlement key — required to boot.**
`SolanaSettlementBackend::connect` submits and confirms a real transaction at
startup (an idempotent associated-token-account create), paid by this key. An
unfunded key is a refuse-to-start and the container restart-loops; the log
names it. **1–2 devnet SOL is plenty**, from <https://faucet.solana.com>.

The connector's **EVM** key needs nothing to boot: Base Sepolia startup is
read-only (chain id, the token network resolved through the registry, the
token's own `decimals()`). It needs ETH only when it transacts — a redeem. No
balance is checked anywhere, so under-funding surfaces as an ordinary
settlement error later, never at load time.

**The publisher's wallet — required to publish.** It opens a payment channel
against the devnet relay and buys one write per directory event. Fund its
Solana address with devnet SOL (fees, and the channel's own rent) and with mock
USDC:

```bash
curl -X POST https://faucet.devnet.toonprotocol.dev/api/solana/usdc-request \
  -H 'content-type: application/json' -d '{"address":"<the publisher address>"}'
```

At 1 µUSDC a write and a 60-second Liveness cadence this provider spends about
**1,500 µUSDC a day** — 0.0015 USDC. The 10 USDC deposit is three orders of
magnitude more than a year of that, because topping a channel up is the fiddly
part, not funding it once.

Print the connector's two addresses from the key files:

```bash
cast wallet address --private-key "0x$(cat settlement.key)"          # EVM

# --print-keyid gives the raw ed25519 public key in hex; Solana spells the
# same bytes in base58.
docker run --rm -v "$PWD:/d:ro" ghcr.io/toon-protocol/connector:rust-2026.09.11.1 \
  send --operator-key /d/settlement-solana.key --print-keyid
```

Both are also served, already derived, by `GET /ilp` once the node is up —
which is the copy to trust, because the connector proved each of them against a
live chain when it booted. The publisher prints its own address on its first
successful channel open.

## Checking it works

```bash
docker compose ps                                    # five services; three healthy

curl https://provider.<domain>/health                # {"status":"ok"}
curl https://proxy.provider.<domain>/ilp/identity    # the sealing key a tenant pins
curl https://proxy.provider.<domain>/ilp             # every route, every price

# the sealing key the Profile claims must be this, byte for byte
grep CONNECTOR_SEAL_KEY .env
```

Then read the directory back off the relay — a Profile (kind 10432), a Listing
per tier (30432) and a Liveness (10433) under this provider's pubkey, all
tagged `["L","toon.network"]`. If they are not there, `docker compose logs
directory-publisher` is where the reason is: it is the one container here that
spends money.

To prove the paid path, spawn against `<ILP_ADDRESS>.<tier>.v1.spawn` at this
edge (`g.toon.provider.basic.v1.spawn` on the devnet box). The infra
repository's sandbox tooling drives exactly that.

## Changing a listing's price

A price or resource change is a **new version** — bump `version`, keep the old
entry until its last lease ends — so running leases keep the price they started
at. The listings file is the only thing you edit; the connector's routes follow
from it.

1. edit your listings file (`listings.toml`, or whatever `LISTINGS_FILE`
   names);
2. `./render.sh`. It re-renders `provider.toml` and regenerates the
   connector's `[[routes]]` from it, reading the live lease table so a retired
   version keeps its rows while a lease still runs on it;
3. restart the **connector first and the app second**:

   ```bash
   docker compose restart provider-connector
   docker compose restart provider
   ```

   That is the harmless order: for the moment between the two, a stale
   connector prices a route the app still serves. The other way round, the app
   would have stopped selling a tier the connector was still charging for — a
   packet taken and then refused, and a refusal on a paid route is still billed
   (ADR 0003).

The timer does not do this for you: the listings file is not in git, so
editing it moves nothing `auto-apply.sh` watches, and a render it did not run
is not one it knows to restart for. Do all three steps together.

The devnet box is the exception: its `.env` sets
`LISTINGS_FILE=listings.example.toml`, so its tiers are a reviewed commit and
the timer applies a change to them like any other.

Delete a retired version's entry once `render.sh` stops putting its rows in
`connector.toml`, which is the signal that its last lease has ended.

## How updates arrive

The box follows a branch, `main` unless `TRACK_BRANCH` in `.env` names
another. Every five minutes `toon-auto-apply.timer` runs
`auto-apply.sh`, which fast-forwards the checkout, re-renders both configs,
**pulls** the provider, publisher and connector images, brings the stack up,
waits for the provider, the connector and the publisher to report healthy, and
then **verifies**: the running connector's `GET /ilp` must advertise exactly
what the rendered config says it should.

It refuses rather than guesses: a dirty working tree stops it loudly, only a
fast-forward is ever applied, a failed pull fails the apply rather than
running on a stale container, and a box that comes back unhealthy exits
non-zero so `systemctl status` and the journal show it.

A `restart provider` does **not** end a lease. The lease table is on a named
volume and is reloaded, and a running workload is a sibling container on the
host daemon that the app never stopped.

This bundle has **no Watchtower**, same as the store and relay boxes' own
reason for having none of the connector: every image here — `provider`,
`directory-publisher` and `provider-connector` — is an **immutable** pin, not
a moving `:release` tag, so there is nothing for a Watchtower to follow. A pin
moves only by a reviewed commit to `docker-compose.yml` — the same discipline
as § "Bumping the connector pin", below, now covering all three images —
and the box picks it up on its next fast-forward like any other file change:
pull, then `up -d`. `.github/workflows/publish-provider-image.yml` is what
publishes the provider and publisher candidates a pin bump chooses between.
Nothing here compiles anything any more (TOON_Network#151); the checkout this
script fast-forwards is config, not a build input.

```bash
systemctl status toon-auto-apply.timer
journalctl -u toon-auto-apply.service -n 50
systemctl start toon-auto-apply.service   # apply now, rather than waiting
```

## Bumping the connector pin

The `image:` line in `docker-compose.yml` is the pin of record, and
`tests/deploy_bundle.rs` fails the build if a second `image:` naming a
connector appears anywhere else in the bundle.

Pin an immutable tag — a `rust-sha-<short>` build or a `rust-<handle>` release
alias — never the floating `rust-main`, and never the fleet's old
`rust-release` pointer, which is retired and frozen on a build whose peerings
can accept but never pay.

The config parser is `deny_unknown_fields` and startup is fail-closed, so a
schema drift under you is a refuse-to-start rather than a degraded run. **Land
a config change before the build that requires it.** Here the pin and the
config it was validated against are the same commit and the box takes both with
one fast-forward, so a build can never reach this box ahead of the config it
needs.

The current pin is `rust-2026.09.11.1` (= `rust-sha-f278cd6`), the build the
sandbox proves this provider against end to end. The rest of the devnet fleet
is a release behind on `rust-2026.08.28.1`; the 09.11 release is purely
additive to the config schema (`[[tokens]]`, `[[rates]]`, `socks_proxy`, all
optional and all absent here), so the two interoperate.

## Privacy and exposure invariants

**The app's listener is never published.** Its one port carries `/health` *and*
every spawn, extend, standby, status, terminate and rotate handler. The
connector is the only thing that may reach it, because the connector is what
charged for the packet.

**The operator endpoint is never published.** `POST /operator/evict` carries no
signature and no payment: reaching it at all is what authorises an eviction.
The config validator refuses a non-loopback bind, and it is in no `ports:` row.

**`ports:` bypasses ufw.** Docker manages its own iptables rules ahead of
ufw's, so a container published with `ports:` is reachable from the internet
*regardless of what `ufw status` shows*. Never drop the `127.0.0.1:` prefix
from the connector's publish, and never convert an `expose:` into a bare
`ports:`. The workload ranges are the deliberate exception — they are supposed
to be reachable, and `bootstrap.sh` opens them in ufw so that `ufw status`
tells the truth about a box that already was.

**The provider app is payment-oblivious.** By the time a request reaches it the
payment is proven; it reads no `X-TOON-*` header and contains no ILP, claim or
settlement logic. Keep it that way — that separation is what lets the app be
restarted, rebuilt and rolled back without touching anything that holds money.

## Make it yours

Nothing committed in this directory names an operator, and nothing committed
is yours to edit. Everything that makes a box yours is in two gitignored files:

- **`.env`** — who you are (`DOMAIN`, `PROVIDER_NAME`, `ILP_ADDRESS`, your
  keys) and where you are listed and paid (the relay and settlement block,
  shipped as the devnet preset). The settlement values are rendered into both
  `provider.toml`'s `[[settlement]]` and the connector's `[settlement.*]`, so
  the Profile can never advertise a token the connector does not settle.
- **the listings file** — `listings.toml` unless `LISTINGS_FILE` says
  otherwise, started from `listings.example.toml`. Replace the devnet tiers
  with what your box actually holds; `render.sh` warns if they do not fit its
  memory.

The connector's `[[routes]]` are not in either: `render.sh` generates them by
running `toon-provider routes` on the `provider.toml` it has just rendered, so
a price is written once and the two configs cannot drift. On a box the binary
comes from the provider image in `docker-compose.yml`, which `render.sh` pulls
or builds first so the rows come from the build that will serve them. Off a
box, point it at a binary of your own:

```bash
cargo build --release --bin toon-provider
TOON_PROVIDER_BIN=../target/release/toon-provider ./render.sh
```

Because the checkout stays unmodified, `auto-apply.sh` follows `main` with no
fork: `git status` stays clean, and a merge here reaches your box like any
other.

**`ILP_ADDRESS` is refused under `g.toon.`** unless `.env` also sets
`TOON_DEVNET_BOX=1`. That namespace is the TOON fleet's, and a second box
answering for `g.toon.provider` would take payment for another box's routes.
Only the fleet's own boxes set the flag.

`../provider.example.toml` documents every configuration key there is,
including the `[anon]` tables this box does not use — a **Hidden Provider**
(spec §10, ADR 0008) publishes no host at all and is reached only at an
`.anyone` address, which is a different deployment and not this one.
