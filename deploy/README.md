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
| `keys.sh` + `keys.py` | Generates every missing key and prints every address to fund, before anything boots. Needs only `python3`. |
| `bootstrap.sh` | Fresh host → running box, including the sealing-key handshake. Idempotent. |
| `pull-images.sh` | Gets the pinned images onto the box: pulls them, or builds one from the checkout while its pin is still the `sha-0000000` placeholder. |
| `init-letsencrypt.sh` | Issues or reuses the certificate. Idempotent. |
| `auto-apply.sh` + the two units | The box half of GitOps: follow the branch, apply what merged. |
| `docker-compose.hidden.yml` | The overlay a **hidden** box adds (`HIDDEN=1`): the anon daemon, its two pinned networks, and no nginx. § "Running hidden". |
| `anon/Dockerfile`, `anon/anonrc` | The hidden box's anon daemon, built here from a digest-pinned base and a checksummed release, and its config. Committed, not rendered. |
| `hidden-firewall.sh` + `toon-hidden-firewall.service` | A hidden box's DOCKER-USER rules: no lease port reachable from outside. |
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
connector already was, so that floor is gone once their pins name a published
build, and they do (`sha-dce2bd2`). The sold-capacity arithmetic above is what
sizes this box.)

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
your own, and devnet SOL and mock USDC for two identities that `keys.sh`
generates and names in step 2.

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

**2. Generate the key material.** One command, on the box, before anything
else runs on it. It needs only `python3`, which every Ubuntu release ships:

```bash
./keys.sh init
```

It writes whatever is missing and never replaces what exists, so it is safe to
re-run and safe to run over keys you brought yourself. Put your own in place
first if you have them.

| What | Where | What it is |
|---|---|---|
| `signer.key` | file | The connector's sealing key: what a tenant seals to. |
| `settlement.key` | file | The connector's EVM settlement key. |
| `settlement-solana.key` | file | The connector's Solana settlement key. |
| `NOSTR_PRIVATE_KEY` | `.env` | The provider's own identity. It signs the Profile, every Listing and every Liveness. |
| `PUBLISHER_MNEMONIC` | `.env` | A 12-word BIP-39 phrase of its own for the publisher's wallet, shared with nothing else: two payers on one channel share one nonce watermark, and the loser of that race has every later claim refused. |
| `OPERATOR_BEARER_TOKEN` | `.env` | Gates the connector's `/metrics` and redeem endpoints. |
| `OPERATOR_WRITE_KEY` | `.env` | The **public** half of a fresh ed25519 key for signing operator writes. |

The three files are 32 bytes as 64 hex characters, the only format the
connector reads, and `0600`. `render.sh` later hands them to uid 10001, which
is what the connector runs as. That used to be a step in a runbook, and a step
a human has to remember is a step a human forgets. The failure is a container
that restarts forever with `failed to read signer key_file at
/app/data/signer.key: Permission denied` while everything around it looks fine.

The operator write key's **private** half is printed once and stored nowhere
on the box. Save it as a file on the machine you administer from: it is what
`connector send --operator-key <file>` signs with. To use a key you already
hold instead, set `OPERATOR_WRITE_KEY` to what `connector send --operator-key
<file> --print-keyid` prints for it before you run `init`.

Back the rest up somewhere off this box, as `init` reminds you. A lost
`NOSTR_PRIVATE_KEY` is a lost provider: a new pubkey, an empty directory
entry, and every tenant holding a lease addressed to the old one left talking
to nobody.

**3. Fund what `./keys.sh addresses` prints.**

```bash
./keys.sh addresses
```

It lists every address to fund in the form a faucet takes (base58 for Solana,
`0x` for EVM), what each needs, and the faucet command or URL for it. It also
prints this provider's `npub`. § "The two funded identities" says why each
needs what it does. Fund the connector's Solana settlement address **before**
the first `up -d`. `bootstrap.sh` checks both Solana balances with a free
`getBalance` before it touches the host, and stops with the same list if
either is short, rather than letting the connector restart-loop.

**4. Bring it up.**

```bash
./bootstrap.sh
```

Firewall, Docker, journald cap, the `dind` sidecar pre-pull, the sealing-key
handshake, render, pull (or, before the first publish, build), start,
certificate, timer. Idempotent — re-run it to
reconcile a box.

`init-letsencrypt.sh` warns first if either A-record — `proxy.provider.<domain>`
or `provider.<domain>` — does not yet resolve to `PUBLIC_IP`. If issuance
itself fails, it exits non-zero naming the likely cause (almost always that
one of those A-records isn't pointed here yet), and `bootstrap.sh` stops there
with that message and the command to re-run, rather than reporting the box up
on no valid certificate. A certificate that is still valid and outside its
renewal window — the case on every idempotent re-run — is reused without going
near any of this.

**5. Go to production TLS.** `bootstrap.sh` starts on Let's Encrypt *staging*
so a DNS mistake does not burn the real rate limit. Once step 4 succeeds, set
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

`./keys.sh addresses` prints this command with the address already filled in.

At 1 µUSDC a write and a 60-second Liveness cadence this provider spends about
**1,500 µUSDC a day** — 0.0015 USDC. The 10 USDC deposit is three orders of
magnitude more than a year of that, because topping a channel up is the fiddly
part, not funding it once.

`./keys.sh addresses` prints all three addresses from the key files and
`PUBLISHER_MNEMONIC`, before anything has booted. Each is derived the way its
component derives it, and `../tests/deploy_keys.rs` holds each derivation to
the component's own on fixed keys:

- the connector's Solana address is the ed25519 public key of
  `settlement-solana.key`, in base58: the same bytes `connector send
  --operator-key settlement-solana.key --print-keyid` prints in hex;
- its EVM address comes from `settlement.key`, printed with EIP-55 casing.
  `GET /ilp` prints the same address in lowercase;
- the publisher's address is `PUBLISHER_MNEMONIC` at `m/44'/501'/0'/0'`,
  which is what `@toon-protocol/client` derives and what Phantom and the
  Solana CLI derive from the same phrase.

Once the node is up, `GET /ilp` serves the connector's two addresses as well,
after the connector has proved each of them against a live chain.

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

**A render or apply failure is retried, and reported, forever — never
silently sat on (TOON_Network#160).** Once everything above succeeds, this
script records the commit it just applied in `deploy/.applied` (gitignored).
The *next* run compares `HEAD` to `.applied`, not to whatever `git fetch`
just brought back — so if `render.sh`, `pull-images.sh` or anything after it
fails partway through, the box is left on the new commit with the OLD
rendered config and containers, but `.applied` still names the OLD one, and
the very next timer tick treats that as work to do even though the fetch
brings back nothing new. It fails the same way, by the same name, on every
run — `systemctl status` and the journal keep showing it — until whatever
`render.sh` named (most often a newly-required `.env` variable;
`.env.example` lists every one, with the devnet preset for settlement) is
fixed and a run finally succeeds and rewrites `.applied`.

On a box with no `deploy/.applied` yet — an existing box's first run under
this check, or one where the file was lost — that absence is read as
*needing* an apply, not as "must already be applied": the run re-renders,
re-verifies and writes `.applied` once everything reports healthy. That run
is a harmless no-op if the box was already caught up (nothing on disk or in
the running containers has anything to change), which is why treating a
missing file this way, rather than having `bootstrap.sh` write it, is the
safer of the two: the box's first-ever apply IS this script's first run, and
it proves itself exactly like every later one does.

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
Once the pins name published builds, nothing here compiles anything
(TOON_Network#151), and the checkout this script fast-forwards is config, not
a build input.

**The placeholder pin.** Before the workflow's first publish the pins read
`sha-0000000`, git's all-zero "no commit", which no registry has, and
`pull-images.sh` still honours it: for that one tag, and only for the
`provider` and `directory-publisher` images, it builds the image from the
checkout and tags it with the pinned name. That is what a fork that has not
published yet can use. Any other pin that will not pull fails the apply.

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

**The operator endpoint is never published.** `POST /operator/evict` and
`GET /operator/status` carry no signature and no payment: reaching the port at
all is what authorises an eviction or a status read.
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
comes from the provider image in `docker-compose.yml`, which `render.sh` gets
first through `pull-images.sh` (pulled, or built from the checkout while the
pin is the placeholder), so the rows come from the build that will serve them.
Off a box, point it at a binary of your own:

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
including the `[anon]` tables a public box does not use. A **Hidden
Provider** (spec §10, ADR 0008) publishes no host at all and is reached only
at `.anyone` addresses; the same bundle stands one up with `HIDDEN=1`, next.

## Running hidden

A Hidden Provider's Profile says `hidden: true` and carries no `host`, every
Listing it publishes is labelled `["l", "hidden:true", "toon.network"]`, and
nothing of it is reachable except over Anyone: the connector at the box's own
`.anyone` address, and each lease at an `.anyone` address of its own. The
provider README's § "Hidden Provider" is the reference for what that means;
this section is how the bundle does it, and what it costs.

**Read the settlement RPC part before anything else.** It is the one
requirement that decides whether hidden is for you.

### What changes

| | Public box | Hidden box (`HIDDEN=1`) |
|---|---|---|
| The connector is reached at | `https://proxy.provider.<DOMAIN>/ilp`, through nginx | `http://<HIDDEN_ADDRESS>/ilp`, through the anon daemon's hidden service |
| A lease is reached at | `PUBLIC_IP:<port>` | its own `.anyone` address, made per lease over the daemon's control port |
| A workload's own traffic | the host's network | an internal network whose only way out is the daemon's transparent proxy |
| The provider's and publisher's outbound | direct | through the daemon's SOCKS port (`socks5h`) |
| Settlement RPCs | the preset's public ones | **your own nodes**, on a private address |
| DNS, nginx, Let's Encrypt | yes | none: `DOMAIN` and `PUBLIC_IP` are never rendered |
| ufw | 22, 80, 443 and both workload ranges | 22, and the workload ranges from the daemon's address only |
| Extra services | none | `anon` |

It is one bundle, not two. `HIDDEN=1` in `.env` is the switch and
`COMPOSE_FILE=docker-compose.yml:docker-compose.hidden.yml` beside it adds the
overlay (docker compose reads that line itself, so every `docker compose`
command in this directory, auto-apply's included, sees the hidden stack);
`render.sh` refuses a `.env` where the two disagree. `provider.toml.template`
carries both shapes, and `render.sh` keeps the `@hidden-only` blocks
(`hidden = true` and the `[anon]` tables) and drops the `@public-only` one
(`public_ip`). The listings, the routes, the keys and `auto-apply.sh` work the
same way on both.

### The settlement RPCs: you run them

The connector reads chain state and submits transactions, on both chains, at
boot and for every settlement. **It dials its settlement RPC directly.** Its
`socks_proxy` key covers the ILP wire to `.anyone` peers and nothing else, by
decision (connector ADR 0070, decision 4: "Settlement RPC and `handler_url`
dial direct"), and this box has no peers. So a public RPC on a hidden box
would see every query and every transaction of this box's settlement keys
arrive from this box's real address, which undoes the hiding for anyone who
can read that RPC's logs. This is also the provider's own rule:
`anon.settlement_rpc_url` must be loopback, private, or a name resolving only
to private addresses, and the app refuses to load otherwise.

So `.env` names your own nodes, one per chain, and `render.sh` refuses to
render without both:

```bash
HIDDEN_SETTLEMENT_EVM_RPC_URL=http://10.0.0.5:8545     # Base Sepolia
HIDDEN_SETTLEMENT_SOLANA_RPC_URL=http://10.0.0.5:8899  # Solana devnet
```

They replace the preset's `SETTLEMENT_*_RPC_URL` in the connector's config;
the rest of the preset (chain id, registry, program, tokens) is unchanged.
`render.sh` puts **both** through the app's own rule, in the real loader, and
refuses a public one before the connector reads a byte from it. It also
refuses loopback: the connector is a container, and its `127.0.0.1` is
itself. Use an address the container can route to: this host's address on a
private network, or another machine of yours over a private link.

**What that costs, as far as we can state it.** Neither figure below was
measured for this bundle, and neither is specific to the devnets; they are the
chains' own published requirements, read on 2026-09-24:

- **Solana** (Anza, [validator requirements](https://docs.anza.xyz/operations/requirements)):
  an RPC node wants 12 cores / 24 threads or more, **256 GB of RAM or more**,
  and separate NVMe disks for accounts (1 TB or more), ledger (1 TB or more)
  and account indexes (512 GB or more). That is for the chain Anza documents;
  whether a devnet-only RPC can run smaller is unverified.
- **Base Sepolia** (Base, [node README](https://github.com/base/node)): a
  multi-core CPU, **32 GB of RAM (64 GB recommended)**, NVMe storage sized at
  twice the chain plus a snapshot, **and an Ethereum L1 (Sepolia) RPC and
  beacon endpoint** of your own (`BASE_NODE_L1_ETH_RPC`, `BASE_NODE_L1_BEACON`).
  Whether that L1 node must itself be private is your threat model: it serves
  the rollup node, not this box's settlement keys.

That is heavy on purpose, and it is the honest price of the claim. Two things
are **not** a way round it:

- **A local forwarder to a public RPC through anon** (a private address that
  relays to `api.devnet.solana.com` over a circuit) would pass the app's
  check and hide the address, but it is a *proxied* settlement RPC, which is
  not what spec §10 asks a Hidden Provider to run, and connector ADR 0070
  deliberately leaves circuits out of settlement ("circuit latency interacts
  with confirmation semantics and nonce handling on both backends"). Allowing
  it is a spec decision, not a bundle setting, and this bundle does not ship
  one.
- **A private address that forwards in the clear to a public RPC** from
  another machine of yours moves the linkage to that machine. It hides this
  box only as well as that machine is unlinkable to you.

### What the connector's own outbound is, on a hidden box

Checked against the pinned connector (`rust-2026.09.11.1`), loading the config
this bundle renders: it accepts the `http://`/`ws://` `.anyone` endpoints,
and the first thing it dials is `[settlement.evm].rpc_url`, directly
("failed to construct the configured settlement backend … tcp connect error"
against an unreachable private RPC). Its other outbound is the provider app,
on the compose network. There is no setting that sends the settlement RPC
through anon (see above), which is why the bundle makes both RPCs yours
rather than setting `socks_proxy`, which would change nothing here.

### Known gap: directory writes on the devnet

The directory publisher pays the relay over **HTTP** on a hidden box, and has
to: its SOCKS carriage is its `fetch`, a BTP websocket never passes through
it, and it refuses to start with a proxy beside `btp` or `auto`
(tools/publisher/README.md). The devnet relay **pins `g.toon.relay` to BTP**
and refuses an HTTP write. So on the devnet today, a hidden box runs, its
connector is reachable and its leases work, but its Profile, Listings and
Liveness are refused by the relay, and it does not appear in the directory.

Two things close it, either one: the publisher carrying BTP through the proxy
too (`@toon-protocol/client`'s hidden-service transport already has a
`createWebSocket`; the publisher passes only `fetch`), or the relay unpinning
its write route. Whether the pin still stands:

```bash
curl -s https://proxy.relay.devnet.toonprotocol.dev/ilp \
  | jq '.routes[] | select(.prefix == "g.toon.relay")'
```

### Standing one up hidden

As § "Standing one up", with these differences.

1. **In `.env`**: `PROVIDER_NAME`, `ILP_ADDRESS` and the keys as usual; leave
   `DOMAIN` and `PUBLIC_IP` empty (they are never rendered); and uncomment
   the "Running hidden" block: `HIDDEN=1`, the `COMPOSE_FILE` line and your
   two RPCs. No DNS records.
2. **Bring the RPC nodes up first and let them sync.** The connector submits a
   Solana transaction at boot through yours.
3. **`./bootstrap.sh`.** Before the sealing-key handshake it builds the anon
   image (`pull-images.sh anon`; there is no published image of the release
   that writes `.anyone` addresses, and `anon/Dockerfile` pins what it builds
   from), starts the daemon alone, reads the address it generated and appends
   `HIDDEN_ADDRESS=<56 characters>.anyone` to `.env`: a copy of a fact, like
   `CONNECTOR_SEAL_KEY`. It opens only SSH in ufw, pre-pulls the pinned
   `alpine:3.20` sidecar every hidden lease runs, installs
   `toon-hidden-firewall.service`, and skips Let's Encrypt.
4. **Back up the `anon_data` volume with the key files.** It holds the
   private key of `HIDDEN_ADDRESS`. Lose it and the address changes under
   every tenant that read the old one; `bootstrap.sh` then refuses until you
   restore the volume or delete the `HIDDEN_ADDRESS` line to move.

The address answers only once the daemon has bootstrapped and published its
descriptor (`docker compose logs anon | grep Bootstrapped`). From any machine
with an anon client:

```bash
curl --socks5-hostname 127.0.0.1:9050 http://<HIDDEN_ADDRESS>/ilp/identity
```

### The host

- **The lease ports.** A hidden lease's ports are still published on the host
  (its ingress forwarder holds them, and the daemon forwards the lease's
  address to them), and docker's rules run ahead of ufw. A tenant who found
  its own workload answering at this box's IP would have found the box. So
  `hidden-firewall.sh` drops, in DOCKER-USER, every connection to both ranges
  forwarded in from outside, and ufw lets the daemon's pinned address, and
  nothing else, reach them from inside. The unit re-applies it after every
  boot and docker restart, which leave DOCKER-USER empty.
- **`br_netfilter`.** With it loaded (`net.bridge.bridge-nf-call-iptables =
  1`), Docker's isolation of the internal egress network drops every
  transparently proxied packet; `hidden-firewall.sh` then accepts
  bridge-to-bridge traffic on that network's bridge, `toon-hegress`. It
  prints when it does.
- **SSH stays on port 22 of the real address.** That is the operator's way
  in, and it is not in anything a tenant is told. Moving it behind an anon
  address of its own is possible and not done here.
- **The two pinned networks**, `172.30.2.0/24` and `10.204.0.0/24`. A
  collision shows up at `up` as "Pool overlaps"; moving one means changing
  it in `docker-compose.hidden.yml`, `anon/anonrc` and
  `provider.toml.template` together, and `tests/deploy_bundle.rs` checks the
  three agree.
- **amd64 only**, for now: `anon/Dockerfile` carries the amd64 release's
  checksum.

### Other limits, stated plainly

- **Workloads on musl cannot resolve names.** The daemon's DNSPort answers an
  `AAAA` query with NXDOMAIN, and musl's resolver (Alpine, BusyBox) takes
  that as "no such name" for the `A` answer too. glibc images resolve and
  connect normally. Connecting by IP works on both. Observed with this
  bundle's daemon; fixing it is a provider or anon change, not a bundle one.
- **The IP-to-chain linkage is public either way.** Hiding hides where the
  box is, not that it was paid: every claim names an on-chain channel.

### What has been run, and what has not

Run locally against the real Anyone network, with this bundle's files: the
anon image builds and reports `0.4.10.2`; the daemon bootstraps to 100%,
installs its redirects and publishes an address; that address, dialled from a
separate anon client, reaches `172.30.2.3:4000` (a stand-in for the
connector); the SOCKS port carries a fetch of the devnet relay's `GET /ilp`
from an exit address that is not the host's; a container on the egress
network, routed at the daemon, reaches the internet by IP through the
TransPort (and by name on glibc); the provider's own `ADD_ONION` test
(`cargo test --test anon_control -- --ignored`) passes against the daemon's
control port; an address added with `forward_host = 172.30.2.1` reaches a
port published on the host; the provider starts hidden in this stack,
authenticates to the control port and hands directory events to the
publisher, which opens its channel through the proxy (and stops there,
unfunded). The DOCKER-USER rule and the ufw allowance were checked in an
isolated dind. The rendered `connector.toml` loads in the pinned connector.

**Not run end to end:** a connector booted against real self-hosted RPCs, a
paid spawn of a hidden lease, a tenant paying over the circuit, and
`make smoke-m4`. The sandbox's `hs` profile (infra/sandbox), which this
overlay is built from, is where that suite runs, against its own chains; the
bundle differs from it in its addresses, in running one daemon rather than
the sandbox's three, and in settling against the operator's RPCs rather than
the sandbox's `anvil`.
