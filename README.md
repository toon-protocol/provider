# toon-provider

Sell leases on workloads over the [TOON Network](https://github.com/toon-protocol/TOON_Network).

A **provider** runs this on hardware it controls. It publishes what it sells to
its relays, and a **tenant** pays a listing's route over a TOON payment channel
to spawn a workload and to buy each further **Lease Interval**. When the
payments stop the lease expires and the workload is destroyed.

The app is an ordinary HTTP app that runs behind the provider's own TOON
connector. The connector terminates payment, seals and unseals the payload, and
forwards a plain HTTP request — so this app reads no `X-TOON-*` header, and a
tenant paying through hops is served identically to one paying directly.

## Status

Milestone 1 is in progress. Today the app serves the whole lease lifecycle —
a paid **spawn** (a tenant-signed Lease Request in, a running workload and its
access details out), a paid **extension**, and the free **status**,
**termination** and **availability** routes — applies its **image policy** to
every spawn and every availability answer, sweeps expired leases, evicts a
lease on an operator's command with a signed Eviction Notice, publishes its
Provider Profile, Listings, Liveness and Eviction Notices to its Relay Set,
and prints the connector route table it expects. A listing's price or
resources can be changed without repricing the leases already running (see
[Changing a listing's price](#changing-a-listings-price)). The milestone's
acceptance test is `make smoke-m1` in the sandbox — see
[Milestone 1 acceptance test](#milestone-1-acceptance-test).

Milestone 2 is in progress: an image named by its **Image Registry entry**,
or by its **digest alone**, is resolved and fetched through the TOON store,
upstream registries and the **Blob Records** on this provider's Relay Set,
verified blob by blob, cached across leases, and run — see
[Spawning](#spawning) and
[the resolution order](#availability-and-image-policy).

## Spec, decisions and vocabulary

They live in the [`TOON_Network`](https://github.com/toon-protocol/TOON_Network)
repository, not here:

| What | Where |
|---|---|
| Protocol spec | `docs/spec/toon-network-v1.md` |
| Glossary — the normative vocabulary this code uses | `CONTEXT.md` |
| Architecture decision records | `docs/adr/0001`–`0011` |

## A fork of Paygress, with most of it removed

This is a hard fork of [Paygress](https://github.com/DhananjayPurohit/Paygress)
(Apache-2.0) at commit `c92b870`. See [`NOTICE`](NOTICE) for attribution;
[`LICENSE`](LICENSE) is Paygress's, unchanged.

**Kept:** the `ComputeBackend` trait and the Docker backend, lease accounting
and the expiry sweep, workload persistence across restarts, and the axum HTTP
app. Warm Standby is wired as far as roles, reservations, the watch that
announces a Takeover and a primary's own self-stop (Milestone 3). Paygress's takeover state machine
(`durable_workload`) is gone: its lease-revocation event — published by a
primary on its own eviction — and the respawn path it drove are replaced by
ADR 0010's Takeover on Liveness expiry, which a crashed primary need not
announce. The reputation math stays in the tree, compiling, with nothing
calling it.

**Removed**, because TOON replaces each of them:

| Removed | Replaced by |
|---|---|
| Cashu (`cdk`, `cdk-sqlite`, `bip39`), the mint whitelist, the wallet CLI and the Lightning sweep | A TOON payment channel, terminated by the provider's connector |
| `ngx_l402` and its nginx config | The TOON connector |
| The NIP-04/NIP-17 direct-message transport | Sealed HTTP through the connector |
| The offer (`38383`), heartbeat (`38384`, `20384`), lease revocation (`38385`) and standby promotion (`38386`) event kinds | Provider Profile, Listing, Liveness, Eviction Notice and Takeover events. None of the Paygress kind numbers is reused — `38383` collides with NIP-69 |
| The Blossom client and its content-addressed encryption | The TOON store, with image bytes verified by digest |
| The vetted template registry | Any image runs; a listing grants capabilities |
| The consumer CLI, the MCP server, offer discovery and the observatory | Tenant tooling, elsewhere |
| The LXD, Proxmox and KVM backends, and the Bitcoin stake bond | Out of scope for Milestone 1. `ComputeBackend` stays backend-agnostic so they can return |

## Configuration

One TOML file, no environment variables. Copy
[`provider.example.toml`](provider.example.toml) and edit it. The important
parts:

- `ilp_address`: the provider's ILP address, e.g. `g.acme`. Every route is a
  suffix of it.
- `[[listings]]`: one per tier and version — `name`, `version`, `resources
  {cpu_millicores, memory_mb, storage_gb, gpu?}`, `arch`, `lease_interval_s`,
  `price` (integer µUSDC per Lease Interval), `capabilities` (see
  [Capabilities](#capabilities) — `docker` and `nesting` are refused at load),
  `capacity`.
  A price change is a new version with its own routes (ADR 0009). `capacity`
  is how many leases of that name may run at once, across its versions.
- `handler_base_url`: where the *connector* reaches this app; the origin of
  every `handler_url` in the route table.
- `nostr_private_key`: the provider's identity. A Lease Request is addressed
  to its public key, and it signs everything this provider publishes.
- `ended_retention_s`: how long an ended lease is still answerable by
  `status` before the sweep forgets it. Default 86400 (one day).
- `[image_policy]`: what this provider refuses to run — `deny_digests`
  (exact `sha256:…` digests), `deny_references` (cheap prefix denial on
  `image.reference`, a trailing `*` matches a suffix), `max_image_bytes`
  (total size cap). All optional; the default is permissive. See
  [Availability and image policy](#availability-and-image-policy).
- `gateway_url_pattern`: where the TOON store's uploads are read from, with
  `{txid}` standing for the transaction id — e.g.
  `https://arweave.net/raw/{txid}`, or a sandbox gateway's
  `http://envoy:3000/raw/{txid}`. Unset, an image whose bytes are in the
  TOON store is `refused_image`. See
  [Availability and image policy](#availability-and-image-policy).
- `blob_cache_dir`: where verified image blobs are kept, by digest, across
  leases and restarts. Default: `blobs/` beside `lease_state_path`. Give it
  room for every image this provider will run; there is no eviction yet.
  `blob_cache_max_bytes` caps it — a blob that would cross the cap is not
  kept and the spawn is `no_capacity`, the same answer a full disk gives.
  See [Spawning](#spawning).
- `relay_set`, `connector_url`, `connector_seal_key`, `[[settlement]]`,
  `isolation`, `liveness_cadence_s`, `geohash`, `publish_url`: the Provider
  Directory — see [The Provider Directory](#the-provider-directory).
- `operator_bind_addr` (default `127.0.0.1:8090`) and `operator_url` (default
  `http://127.0.0.1:8090`): the loopback-only operator endpoint `toon-provider
  evict` talks to. See [Eviction](#eviction) — **this port must never be
  exposed off the host the provider runs on.**

## Routes and the connector

The provider's connector terminates payment and forwards each ILP route to
one HTTP path here:

| ILP route | HTTP path | Price |
|---|---|---|
| `<addr>.<listing>.v<n>.spawn` | `POST /listings/<listing>/v<n>/spawn` | listing price |
| `<addr>.<listing>.v<n>.extend` | `POST /listings/<listing>/v<n>/extend` | listing price |
| `<addr>.<listing>.v<n>.standby` | `POST /listings/<listing>/v<n>/standby` | listing `standby_price` |
| `<addr>.<listing>.v<n>.standby.extend` | `POST /listings/<listing>/v<n>/standby/extend` | listing `standby_price` |
| `<addr>.availability` | `POST /availability` | 0 |
| `<addr>.status` | `POST /status` | 0 |
| `<addr>.terminate` | `POST /terminate` | 0 |

The two standby rows are printed **only for a listing that sets
`standby_price`** (spec §7): a listing that prices no Warm Standby gets
neither, so a connector never terminates a route this provider did not price,
and an unset price is never read as free. A `.standby` spawn paid on a listing
that prices none is refused `wrong_listing_version` — that route is not on
sale there. `.standby.extend` still refuses every request with
`invalid_request`: paying a reservation lands later in Milestone 3, and until
it does `.extend` refuses a reserved lease the same way rather than selling it
a running lease's interval at the running price.

`toon-provider routes --config provider.toml` prints these as connector
`[[routes]]` rows, ready to paste into the connector's config. It prints two
rows per **live** listing version — four for one that prices standbys — the
version on sale plus every retired version that still has a running lease, so
it reads the lease table at
`lease_state_path` (read-only) to find out which those are. Run it from the
provider's own working directory, or make `lease_state_path` absolute:
reading the wrong table would leave out the routes running leases extend on,
and the command warns on stderr when it finds no table at all. Every answer
is JSON; a refusal is `{ "error": "<code>", "message": "…" }` with a 4xx
status and the spec's code, and on a paid route it is still billed.

## Changing a listing's price

A connector route has one fixed price, so repricing a route would reprice
every lease already running on it at its next Extension. A provider must not
be able to do that to a tenant locked in by running state, so a price or
resource change is a **new listing version** instead (ADR 0009, spec §4.2):
new routes at the new price, and the old routes left in place until the
leases on them end.

Nothing about this is live. The connector has no runtime write for a route
(spec §11 item 5), so every step below is a config edit followed by a
restart.

1. **Add a version.** In `provider.toml`, add a second `[[listings]]` entry
   with the same `name`, a higher `version`, and the new `price`,
   `lease_interval_s` or `resources`. **Keep the old entry.** Every version
   of a name must declare the same `capacity`: it is one slice of hardware,
   sold under two prices.

   ```toml
   [[listings]]           # the retired version — keep it while it has leases
   name = "basic"
   version = 1
   price = 1000
   # …

   [[listings]]           # the version on sale from now on
   name = "basic"
   version = 2
   price = 1500
   # …
   ```

2. **Regenerate the route rows.** `toon-provider routes --config
   provider.toml` now prints `…basic.v1.spawn`/`.extend` *and*
   `…basic.v2.spawn`/`.extend`. Replace the provider's `[[routes]]` block in
   the connector's config with the new output.

3. **Restart the connector, then the provider.** The connector so the v2
   routes exist to be paid; the provider so it serves them and republishes
   the Listing.

4. **Retire v1.** Keep running `toon-provider routes`. Once v1's last lease
   has ended, the command stops printing its two rows. Delete the v1
   `[[listings]]` entry, update the connector's `[[routes]]` block from the
   new output, and restart both again.

What the switch changes, from step 3 onwards:

- **v2 is the Listing.** The Listing event is addressable on `d = basic`, so
  the republished event *replaces* the old one — same `d`, `version: 2`, new
  price. There is never more than one Listing per name in the directory.
- **v1 sells nothing.** A spawn (or an `availability` question) on
  `…basic.v1.spawn` is refused `wrong_listing_version`, whether or not any
  lease is still running on it. A paid refusal is still billed, which is why
  the row stays: the connector needs a route for every prefix that can be
  paid.
- **v1 still extends.** A lease spawned on v1 extends on `…basic.v1.extend`,
  for v1's `lease_interval_s` at v1's price — the deal it was sold under.
  Extending it on `…basic.v2.extend` is refused `wrong_listing_version`, and
  so is extending a v2 lease on v1's route.
- **Capacity is shared.** `capacity` is per listing *name*, across versions,
  and Liveness publishes one `available` figure per name.

In the sandbox this is the same edit in `infra/sandbox/conf/provider.toml`
plus the regenerated rows in `conf/connector-provider.toml` (and
`conf/connector-relay.toml` if the relay leg changed), followed by `docker
compose restart provider-connector relay-connector` and a rebuild of the
`provider` service.

## Spawning

The spawn body is `{ "request": <Lease Request> }`: a Nostr event of kind
`K_LEASE_REQUEST` signed by the tenant, with tags `p` (this provider's
pubkey — one per member for a [Standby Set](#standby-sets), which is the only
request that may name more than this provider), `op` = `spawn` and
`expiration` (at most 300 s after `created_at`), whose content is

```json
{ "workload_id": "<32 random bytes, hex>",
  "image": { "reference": "docker.io/library/alpine", "digest": "sha256:…" },
  "env": { "KEY": "value" }, "ports": [ { "container_port": 443, "protocol": "tcp" } ],
  "volume_gb": 2, "ssh_public_key": "ssh-ed25519 AAAA… tenant",
  "entrypoint": ["/bin/sh"], "args": ["-c", "…"] }
```

`image` may take any of the three forms spec §6.2 allows, and all three run:

| Form | Meaning | Where the bytes come from |
|---|---|---|
| `{ "reference", "digest" }` | Pull `reference@digest` from an upstream OCI registry | The daemon pulls it |
| `{ "digest", "registry_entry": { "address", "relay" } }` | The Image Registry entry at `address` lists every blob and where its bytes are (spec §8.1) | This provider fetches each blob from the source the entry names |
| `{ "digest" }` | Nothing but the content address (spec §8.4) | This provider finds each blob's Blob Record on its own Relay Set |

Anything else — a `reference` and a `registry_entry` together, a `digest`
that is not `sha256:` plus 64 lowercase hex, a `registry_entry` whose
`address` is not `30434:<pubkey>:<name>:<tag>` — is a fourth shape and
`invalid_request`. An image this provider cannot find the bytes of is
`refused_image` rather than `invalid_request`: the request is exactly what
the spec allows, and it is the provider that has nowhere to fetch from.
`availability` reports that for free before a tenant pays for the same
answer.

**Through the Image Registry.** An image named by its entry, or by its
digest alone, is resolved the way §8.4 says — for the entry form the entry
is read from the relay hinted at first — and the index, the manifest for
the listing's `arch` and its config are fetched and verified down
[the resolution order](#availability-and-image-policy); that much
`availability` does too, and it also checks that every remaining blob has
somewhere to come from. A paid spawn then, once the slot is reserved,
fetches every layer the same way — a `toon-store` source as its Blob
Record and parts from `gateway_url_pattern`, an `oci` source by digest from
the registry the entry names, a Blob Record from the Relay Set as its parts
— checks each part against its recorded sha256 and size and each blob
against its digest, and keeps every verified blob in the
[blob cache](#configuration) (`blob_cache_dir`). The blobs are
then assembled into an OCI image layout, loaded into the backend (`docker
load`), and the workload is started by the image id the load produced:
never by a tag, and never from bytes this provider did not check. A layer
shared with an image spawned before is served from the cache without a
fetch, and the cache survives a restart. A layer no source can serve is
`refused_image`; a cache the disk or `blob_cache_max_bytes` has no room in
is `no_capacity`; either way the slot is released and no container exists
afterwards. The refusal is still billed (ADR 0003) — a layer that fails
only on the full fetch can only be found out on the paid route — which is
why `availability` resolves the manifest and config first. The Docker
backend needs a daemon whose `docker load` reads an OCI image layout (any
current Docker; verified on 29 with the containerd image store).

**By digest alone**, nothing names a source, so every blob is found by
asking each relay in [`relay_set`](#configuration) for the Blob Records
tagged `#x = <hex>`, whoever signed them. That is safe because no signer is
trusted: each part is checked against its recorded sha256 and size and each
blob against the digest that was asked for, so a wrong record is discarded
and the next one is tried (ADR 0006). Relay reads are free, so this needs
no `publish_url` — only relays; a provider with none configured finds none
and refuses every bare digest.

**Through an upstream reference**, the image is pulled by the daemon as
`reference@digest`, so the daemon verifies the bytes and picks the manifest
for its own architecture.

Whichever form the image took, `template` — the `30436:<pubkey>:<name>` a
tenant expanded its values from — is parsed, kept with the lease and
reported by `status`, and never read: the provider makes no relay lookup
for it, and a spawn that names one gets exactly the capabilities of the
listing it was bought on and no more. A Template grants nothing, and only
the listing decides what privileges a workload gets (ADR 0004). Expanding a
Template into a spawn is the TENANT's job and happens in the sandbox
harness, never here. Anything else in the content — a runtime flag, a host
mount, a device, a capability — is refused as
`invalid_request`. That includes every way of asking for a Docker daemon
inside the workload: see [Capabilities](#capabilities).

**SSH.** The tenant's key is handed to the workload as the environment
variable `SSH_PUBLIC_KEY`, and `access.ssh_port` forwards to the workload's
port 22. An image whose sshd installs that variable serves SSH as-is; any other
image can bridge it with the spawn's own `entrypoint` and `args` (e.g.
`["/bin/sh"]` + `["-c", "PUBLIC_KEY=\"$SSH_PUBLIC_KEY\" exec /init"]` for
`linuxserver/openssh-server`). No password is ever issued. A volume, when
asked for, is mounted at `/data`.

## Standby Sets

A tenant that wants a workload to survive its provider buys a **Standby Set**:
one primary that runs it, and one or more **Warm Standbys** that hold capacity
to take it over (spec §7). The tenant signs **one** spawn, whose content
carries the members' pubkeys primary-first under one `workload_id` —

```json
{ "workload_id": "…", "image": { … }, "ssh_public_key": "…",
  "standby_set": ["<primary pubkey>", "<standby pubkey>", "…"] }
```

— gives it one `p` tag per member, and posts the same bytes to each. Nothing
in the request singles out a member: a provider's role is its **position** in
the set together with the **route** the packet was paid on.

| Position | Route | What this provider does | Answer |
|---|---|---|---|
| index 0 | `<addr>.<listing>.v<n>.spawn`, at `price` | Runs the workload, exactly as a standalone spawn does | `role: "primary"`, with `access` |
| any other index | `<addr>.<listing>.v<n>.standby`, at `standby_price` | Reserves capacity and sets `expires_at`. Starts **nothing** | `role: "standby"`, **no** `access` |

Every other combination is `invalid_request` and does nothing — no
`standby_set` on `.standby`, a set that does not name this provider, a `p` tag
naming a provider outside the set, a member listed twice, index 0 on
`.standby`, another index on `.spawn` — and a `.standby` spawn on a listing
that prices no standby is `wrong_listing_version`. None of them touches the
compute backend. Membership never changes: a different set is a new spawn
under a new workload id.

**A reservation is a lease.** It counts against the listing's capacity exactly
as a running lease does, so Liveness `available` and `availability` both
subtract it and nobody else is sold the slot; it is persisted, so it survives
this provider's restarts — the backend has never heard of it, so nothing asks
the backend whether it still exists; the expiry sweep ends it with `expiry`
when nothing pays it; and its tenant's `terminate` releases it. `status`
answers `role: "standby"`, `state: "reserved"` and no `access` throughout.
Nothing is ever loaded, created, started or destroyed for it — that is what
"nothing runs until a Takeover" means. The one thing a reservation does ask
the backend is which workload id is free, the same question every spawn asks
(`find_available_id`), because the id, the SSH forward and the host ports are
held from the moment the capacity is.

### Watching the primary

A reservation is not idle. Every `WATCHDOG_INTERVAL_SECS` (10 s) the
provider steps a watchdog over every reserved lease it holds, beside the
expiry sweep (spec §7.1):

1. It reads the **primary's Provider Profile** — the pubkey at index 0 of the
   lease's `standby_set`, or the winner of a Takeover this provider lost
   (step 7) — through the Directory, on this provider's own Relay Set, to
   learn the primary's `relays` and `liveness_cadence_s`.
2. It asks each of **the primary's relays**, one by one, whether it holds an
   unexpired Liveness from the primary: live, expired or absent. This
   provider's own Relay Set is never consulted for that — the primary
   publishes to the relays *its* Profile lists, and nothing was ever sent to
   this provider's.
3. The primary is **silent** when its Liveness is expired or absent on a
   strict majority of its Relay Set — one of one, two of three — and has
   been so **continuously for one cadence**. One flaky relay never triggers
   anything; a majority that comes back inside the cadence, even once,
   restarts the count. A relay this provider cannot reach holds no Liveness
   it can see, and counts as absent. The count lives in memory: a restart
   starts it again, because a provider that was down cannot vouch for the
   gap.
4. When the trigger holds it publishes **one Takeover** (kind `30433`,
   `d` = the workload id, content `{ workload_id, primary }`, signed by this
   provider) to the **primary's** Relay Set through the same directory
   publisher everything else goes through, and records on the lease — and
   on disk — that it announced, when, in what cadence, and to which relays.
   An announced reservation is not watched further, and never announces
   twice. A publisher that could not be reached is not an announcement: the
   count stands and the next step tries again.
5. **Two cadences after its own announcement** it settles the race: it
   reads every Takeover on the workload id back from the relays the claim
   went to, restricted to the pubkeys in the `standby_set` — a claim from
   any other signer is ignored, however early — and to claims naming the
   same `primary` this one did, because a claim against an earlier primary
   is an earlier race, already settled. Its own claim counts whether or not
   a relay hands it back. The **earliest `created_at` wins; a tie goes to
   the lower index** in the set. Nothing is read, and nothing starts, before
   the window is up, however early the other claims are visible. A read
   that fails settles nothing and is tried again on the next step.
6. **If it won**, it starts the workload **from the image exactly as a
   spawn would** — the same image resolution, the same fetch, the same
   container from the spawn the reservation kept — with no state carried
   over (ADR 0010). The lease becomes `running`: `status` answers `access`,
   `role` stays `standby`, and `takeover.winner` names this provider.
   Winning buys no time: the reservation's own `expires_at` stands, so a
   **full-price `.extend`** is due before it or the sweep stops the workload
   and ends the lease with `expiry`; `.standby.extend` is refused
   `not_standby`. A start the backend refuses leaves the lease reserved and
   the backend clean, and the next step tries again.
7. **If it lost**, it stays `reserved` — still paid on `.standby.extend`,
   still `not_running` on `.extend` — `status` says who won in
   `takeover.winner`, and from the next step on it **watches the winner** as
   its primary: the winner's Profile, the winner's Relay Set, a count of
   silence that starts from nothing. It forgets its own claim, so that if
   the winner goes silent too it announces again — naming the winner as
   `primary` — and the set survives a second failure.

What the lease keeps on disk through all of this: the announcement (when,
in what cadence, to which relays) until the race is settled, and then the
winner. A standby that restarts after announcing settles from what it kept
rather than announcing again; one that restarts after winning and before
the workload started still starts it.

A provider with no `publish_url` watches and decides like any other, and
announces nothing, exactly as it publishes nothing. A step for a provider
holding no reservation reads nothing at all.

### Stopping itself

The same rule from the primary's end (spec §7.1, *Primary self-stop*). A
partitioned primary cannot see that its standbys have stopped seeing it, but
it can see the half of the silence that is its own: every Liveness
publication reports which relays of the Relay Set took it, and the provider
counts that report each cadence.

- **Five cadences** in a row that reached less than a **strict majority** of
  its own Relay Set stop the workload of every **primary** lease it holds.
  One publication that reached a majority, anywhere inside the five, starts
  the count again; a publication that could not be attempted at all — no
  publisher, an event that would not build — is a cadence on which no relay
  took it. A **standalone** lease is never stopped by this rule: it is in no
  Standby Set, so nobody is waiting to take it over. A provider with **no
  Relay Set** is exempt entirely — nothing it publishes reaches anyone, so
  nothing can take its workloads over either.
- **Stopping is not ending.** The lease stays live and paid to its
  `expires_at`: it holds its capacity slot, its workload id and its host
  ports, `.extend` still buys it another interval at the running price, and
  the sweep still ends it — destroying the stopped container — when nobody
  pays. `status` answers `state: "stopped"` with no `access`, and the state
  is persisted, so a provider that restarts does not start again what it
  stopped.
- **Starting again.** The cadence that regains a majority asks the Relay Set
  for a Takeover of that workload id from a pubkey in the lease's
  `standby_set` (kind `30433`, `d` = the workload id). None, and the same
  container — never a new one — is started again. One found, and the lease is
  marked `taken_over` on disk and stays stopped **for the rest of the
  lease**: another provider is running that workload now, and the claim is
  remembered as a fact rather than re-read, so a relay that later drops it
  cannot put a second copy beside the new primary's. A Relay Set that cannot
  be read at all leaves the workload stopped and is asked again next cadence.
- **At startup**, before anything is served, every live primary lease with a
  Standby Set asks the same question: a provider whose PROCESS was down is
  the loudest partition there is — its containers keep running on the host
  daemon beside it, its standbys see no Liveness and take over, and it comes
  back to a lease table that says `running`. A Takeover found there stops the
  workload and marks the lease `taken_over`. None found, or a Relay Set that
  cannot be read, changes nothing: a primary is innocent until a claim says
  otherwise, because the alternative is stopping a healthy workload over an
  unreachable relay.

## Capabilities

A capability is a privilege beyond an ordinary workload that a **listing**
grants, never a spawn (ADR 0004). Spec §4.4 defines two, and **this backend
delivers neither yet**:

| Capability | What granting it obliges | Here |
|---|---|---|
| `docker` | A Docker-compatible daemon of the **lease's own** at `/var/run/docker.sock`, scoped to that lease, with everything it runs counted against the listing's `resources` | Not built |
| `nesting` | The workload may create containers or VMs of its own, which means tenant code holding kernel privileges | Not built |

So `capabilities = ["docker"]` **fails at config load**, on the operator who
wrote it, rather than on the first tenant who buys the tier and finds nothing
on the socket: a tenant picks a listing by its `t` tags alone, so a tag this
provider cannot honour is a listing that lies. A capability of your own —
between you and your tenants until the spec defines one — goes in prefixed
`x-`, and loads.

**The host daemon is never a workload's.** This app drives the host's Docker
daemon to create workloads, which is why its own container mounts
`/var/run/docker.sock`. That socket is on the provider's side of the workload
boundary and is never passed through: `DockerBackend::run_args` gives a
workload a name, CPU and memory limits, port forwards, environment and a
*named volume* — no `--privileged`, no `--device`, no host path, no
`DOCKER_HOST`. Mounting it into a workload would hand one tenant every other
tenant's containers, and the spec forbids it outright (§4.4). A unit test
asserts on the real argv so a future ticket cannot cross that line by
accident.

**What building `docker` would take** (not in this milestone): a per-lease
`dind` sidecar sharing a private network with the workload, whose socket is
the only one the workload sees, torn down with the lease — plus resource
accounting across the pair, since §4.4 requires the listing's
`cpu_millicores` and `memory_mb` to bound the workload, its daemon and every
container that daemon runs *as one unit*, which is the part the current
one-container-per-lease shape has no answer for.

## Extending, checking and ending a lease

**`POST /listings/<listing>/v<n>/extend`** (paid) takes `{ "workload_id": "…" }`
and no signature: an extension only adds time, so any payer may buy one for any
lease (ADR 0005) and a sponsor can pay for a lease it does not own. It adds
exactly one Lease Interval to the lease's expiry — extensions stack, and the
time is added to the expiry, not to `now` — and answers
`{ "workload_id", "expires_at" }`. It is refused with `unknown_workload` when
no lease of that id is held, `expired` when the lease has ended — by expiry,
termination or eviction, and including an expiry the sweep has not reached
yet, because there is no grace period — and `wrong_listing_version` when the lease was
spawned on another listing version: a lease keeps the price it started at
(ADR 0009), so its extensions are bought on its own route.

**`POST /status`** (free) and **`POST /terminate`** (free) both take
`{ "request": <Lease Request> }` with `op` = `status` or `terminate` and the
content `{ "workload_id": "…" }`. The request is validated exactly as a
spawn's is, replay included, and **the signer must be the lease's tenant** —
anyone else is refused `not_tenant`.

Status answers:

```json
{ "workload_id": "…", "role": "standalone", "state": "running",
  "expires_at": 1757350000,
  "access": { "host": "203.0.113.7", "ssh_port": 40000,
              "ports": [ { "container_port": 443, "host_port": 41000 } ] },
  "template": "30436:<pubkey>:<name>" }
```

`state` is the §6.7 lease state: `"provisioning"`, `"reserved"`, `"running"`,
`"stopped"`, or `{ "ended": "expiry" | "termination" | "eviction" }`.
`"reserved"` is a Warm Standby before Takeover — capacity held and paid for,
with nothing running and so no `access` (see [Standby Sets](#standby-sets));
`"stopped"` is a primary that stopped its own workload after five cadences
without a relay majority — the lease is paid and live, and there is nothing to
reach until it starts again (see [Stopping itself](#stopping-itself)). Once a
Takeover on the workload has settled at this member, the answer also carries
`"takeover": { "winner": "<pubkey>" }` — the member that runs the workload
now, whether that is this provider (`state` is then `"running"`, with
`access`) or another (`"reserved"` still, and no `access`); see [Watching
the primary](#watching-the-primary). It is the
lease record
as it stands, so between an expiry and the sweep that reaps it a lease still
reads `"running"` with an `expires_at` in the past — extend and terminate
refuse it as `expired` all the same. `access` is absent once
the lease has ended — the workload is gone, and there is nothing left to
reach. The same encoding is what the lease table holds on disk.

`template` is the one the spawn named, echoed back unchanged, and absent when
the spawn named none. It is the whole of what a `template` is for: the
provider kept it with the lease so tooling can show where a workload's values
came from, and it survives a restart like the rest of the record. Nothing
reads it: the provider never fetches a Template (see **Spawn** above).

Terminate stops and deletes the workload immediately and answers
`{ "workload_id": "…", "state": { "ended": "termination" } }`. Nothing is
refunded, here or anywhere (ADR 0003). Terminating a lease that has already
ended is refused `expired`.

**Expiry.** A sweep runs every `SWEEP_INTERVAL_SECS` (30 s) and ends every
lease whose `expires_at` has passed, with no grace period: `expires_at` is the
first instant the lease no longer applies. An ended lease stops counting
against capacity and stops holding its workload id at once, but its record is
**kept for `ended_retention_s`** (one day by default) so `status` can still
tell its tenant how it ended rather than that its id is unknown; after that
the record is pruned and `status` answers `unknown_workload`. A lease whose
workload the backend refused to delete is marked ended anyway and retried by
every later sweep until the backend confirms the container is gone, so a
failed delete never leaves a workload running for free. All of this survives a
restart: running leases keep their expiry, tenant, listing version and access
details, and ended leases restore as ended.

## Eviction

An **eviction** ends a lease before expiry on the *provider's* decision —
abuse, a policy violation, maintenance — rather than the tenant's (spec
§6.7). It stops and deletes the workload immediately, the same as a
termination, and publishes a signed **Eviction Notice**: a public record that
this provider evicted this lease, and why. Nothing is refunded.

**`toon-provider evict --config <path> --workload-id <hex> --reason <code>
[--message <text>]`** is the operator command. It does not touch the lease
state file: it sends `{ "workload_id", "reason", "message"? }` to the
*running* provider process's operator endpoint (`POST /operator/evict` at
`operator_url`, default `http://127.0.0.1:8090`), because only that process
holds the lease table and the compute backend needed to act on it. It prints
the JSON answer and exits non-zero if the provider refused it.

Reason codes (`--reason`), this provider's own vocabulary for the spec's "a
reason code" — pick the closest and use `message` for anything it doesn't say:

| Code | Meaning |
|---|---|
| `abuse` | The workload abused this provider or something reachable from it |
| `policy` | The workload violated a policy stated outside this protocol |
| `maintenance` | The provider needs the capacity back (e.g. host maintenance) |
| `other` | Anything else — say what in `message` |

A successful eviction answers:

```json
{ "workload_id": "…", "state": { "ended": "eviction" }, "notice_published": true }
```

`state` is the same §6.7 encoding `status` and `terminate` use.
`notice_published` says whether the Eviction Notice reached every relay of
the Relay Set; a relay refusal, or the directory publisher being unreachable,
does not undo the eviction — the workload is already gone by the time the
notice is built, the same log-don't-raise discipline as the Provider Profile,
Listings and Liveness (see [The Provider Directory](#the-provider-directory)).
Evicting an id this provider does not hold, or one whose lease has already
ended, is refused `unknown_workload` and publishes nothing. After an
eviction, `status` reports `{ "ended": "eviction" }` with no `access`, and
`extend` refuses `expired`, exactly as after a termination or an expiry.

The Eviction Notice is `K_EVICTION` (`nostr/kinds.rs`), a REGULAR kind — one
event per eviction, replacing nothing — signed by the provider's Nostr key
and carrying `["x", "<workload_id>"]` and `["L","toon.network"]`. Content:

```json
{ "workload_id": "…", "reason": "maintenance", "message": "…" }
```

**The operator endpoint must never be exposed.** `POST /operator/evict`
carries no signature and no payment — reaching it at all is what authorises
an eviction — so it is served on its own listener, bound to
`operator_bind_addr` (default `127.0.0.1:8090`, and `validate` refuses
anything that is not a loopback address), and it is never part of the
connector's route table (`toon-provider routes` output is unchanged by this
feature). Do not publish this port through the connector, through a compose
port mapping, or through anything else reachable off the box.

## Availability and image policy

`POST /availability` (free, unsigned) answers whether a spawn would run,
without starting anything — advice, not a reservation: a spawn that later
fails is still billed (ADR 0003). Body:

```json
{ "listing": "basic", "version": 1,
  "image": { "reference": "docker.io/library/alpine", "digest": "sha256:…" },
  "role": "primary" }
```

This is the ticket's shape, not the spec draft's flatter `image_digest`; an
unknown field (including `image_digest`) is `invalid_request`. `role`
(spec §6.4) is optional and takes `"primary"` or `"standby"` — never
`"standalone"`, which is a lease role rather than a question, since a spawn
with no Standby Set is standalone already; any other value is
`invalid_request`. Omitting it asks the ordinary question. With
`"standby"` the answer is whether a Warm Standby **would be reserved** here,
and nothing is reserved by asking: a listing that prices no standby is
refused `wrong_listing_version`, exactly as its `.standby` route would have
been, and capacity is counted with the reservations this provider already
holds subtracted. The route
always answers HTTP 200 — the answer *is* the payload:

```json
{ "would_run": true }
{ "would_run": false, "error": "wrong_listing_version", "message": "…" }
```

It applies, in order: the listing version exists (`wrong_listing_version`),
the image — its form first, then its resolution and the image policy below
(`invalid_request` / `refused_image` / `no_matching_arch`) — and capacity
(`no_capacity`). A paid spawn applies the identical image check at the same
point in its own validation order (§6.2 step 5, between `workload_id_taken`
and `no_capacity`), so a positive `availability` answer and a spawn's
outcome never disagree, and `availability` never calls the compute backend.

**Resolving the image** (spec §8.4) finds the manifest that would actually
run and fetches only what that takes — an index, the manifest matching the
listing's `arch` (`no_matching_arch` if none matches), and its config; never
a layer. It also checks that every remaining blob the manifest names has
*somewhere* to come from, so an image with an unfetchable layer is refused
here rather than on the paid spawn that would have discovered it.

**The resolution order** is the same for every blob, whatever it is — an
index, a manifest, a config, a layer — and whichever form named the image:

1. **The blob cache.** Bytes already verified for any earlier lease. A hit
   here contacts nothing: no relay, no gateway, no registry.
2. **The source the image's own description names.** For
   `{ reference, digest }` that is the upstream OCI registry the reference
   names — and *only* that, because the spec gives this form "no Image
   Registry lookup at all" (§6.2): a registry that will not serve a blob of
   it ends the chain rather than starting a search for someone else's copy.
   It is read over plain HTTP(S) (`docker.io` references resolve against
   `registry-1.docker.io`, with an anonymous token from the challenge in
   `Www-Authenticate` when the registry answers 401 — the generic bearer
   flow every OCI-distribution registry supports; other registries are
   tried anonymously first). For `{ digest, registry_entry }` it is the
   `source` the entry lists for that blob: a `toon-store` source is a Blob
   Record read from the TOON store by its own upload's txid at
   `gateway_url_pattern`, then each part from the same pattern; an `oci`
   source is a pull by digest from the registry and repository the entry
   names. The entry itself is read from the relay the request hints at, and
   must be the entry named — signed by the address's pubkey, under its
   `<name>:<tag>`, describing this digest. A bare digest names nothing, so
   this step is skipped.
3. **Blob Records on the Relay Set**, for the two content-address forms.
   Every relay in `relay_set` is asked
   for the kind-30435 events tagged `#x = <hex>`, and each is tried as a
   part list. **Any signer's record is safe to try**: the provider checks
   each part against its recorded sha256 and size and the reassembled blob
   against the digest that was asked for, so a record from a stranger — or
   a deliberately wrong one — fails verification and the next is tried
   (ADR 0006). This step is taken lazily and per blob: it costs a relay
   round trip, so it happens only for a blob the cache and step 2 did not
   serve.

Fallthrough is per blob, not per image: a gateway that is 5xx for one part,
a part that does not hash to its record, an upstream registry that refuses
— each sends that one blob to its next source, leaves blobs already
verified alone, and fails nothing. Only when every source for a blob is
exhausted is the image `refused_image`. There is no distinct "registry
down" code: a tenant's availability check or spawn has no use for anything
but a refusal right now. Verified blobs are kept on disk in the blob cache
(`blob_cache_dir`), keyed by digest and checked again on every read, across
leases and restarts, so a repeated check — or a spawn of an image already
fetched — reads nothing from the network.

**Image policy** (`[image_policy]` in the config) is a deny list of exact
digests — the digest a request names, or the concrete per-arch manifest an
index resolves to — a cheap deny list of reference prefixes, and a maximum
image size: the config blob plus every layer's declared size in the
resolved manifest.

## The Provider Directory

The provider publishes these events to every relay in its Relay Set (spec
§4, §6.7), all signed with `nostr_private_key` and all carrying
`["L","toon.network"]`:

| Event | Class | Carries |
|---|---|---|
| **Provider Profile** | replaceable | `ilp_address`, `connector_url`, `connector_seal_key`, `relays`, `settlement[]`, `isolation`, `hidden`, `host`, `liveness_cadence_s` |
| **Listing**, one per tier | addressable, `d` = listing name | content `{version, resources, arch, lease_interval_s, price, capabilities}`; tags `a` (the Profile), `L`, `l isolation:…`, `l arch:…`, `l gpu:…`, one `t` per capability, optional `g` |
| **Liveness** | replaceable | `{ "available": { "<listing>": n } }` with `n` = capacity − live leases, and `["expiration", now + 5 × cadence]` (ADR 0007) |
| **Eviction Notice**, one per eviction | regular | `{ "workload_id", "reason", "message" }`; tag `x` = the workload id. See [Eviction](#eviction). |
| **Takeover**, one per workload this provider claims | addressable, `d` = workload id | `{ "workload_id", "primary" }`, signed by this provider as a Warm Standby — and published to the **primary's** Relay Set, not this provider's. See [Watching the primary](#watching-the-primary). |

Everything a relay should filter on is a single-letter tag; numbers stay in
content, because NIP-01 filters never match inside content (ADR 0002).

The provider also **reads** the directory, and reads are free (a NIP-01
`REQ`, no payment): another provider's Profile and Liveness, relay by relay,
and the Takeovers claimed on a workload by the members of a Standby Set —
everything a Warm Standby needs — plus Image Registry entries and Blob
Records for [spawning](#spawning). A provider with no `publish_url` still
reads.

The Profile and the Listings go out at startup and change only when the config
does — which is a restart. Liveness goes out every `liveness_cadence_s`, and
each publication reports which relays of the Relay Set took it, relay by
relay — the count a primary keeps against its own majority (spec §7.1). An
Eviction Notice goes out once, immediately, whenever `toon-provider evict`
succeeds. A Takeover goes out once, when a watched primary has been silent
for a cadence.

Exactly one Listing is published per listing *name*: the newest `version` in
the config. A retired version is served but never advertised — two events
under one `d` would not be two Listings on a relay, only a race to be the one
that survives (see [Changing a listing's price](#changing-a-listings-price)).

**Publishing costs money.** A relay write on the TOON Network is a paid packet
on the paid relay route, never the free ephemeral lane (ADR 0007). The
provider app states *what* to publish; `publish_url` names the process that
decides *how* it is paid for — the directory publisher in
[`tools/publisher`](tools/publisher/README.md), which holds the payment
channel so the provider's Nostr key never has to share a process with money.
Leave `publish_url` unset and the provider publishes nothing, which is legal:
it simply does not appear in the directory.

## Milestone 1 acceptance test

**`make smoke-m1` in `infra/sandbox` is Milestone 1's acceptance test**
(TOON_Network #1, "Testing Decisions → Acceptance"; spec Appendix A). It runs
`scripts/smoke-milestone1.mjs` against `make up-payments` (or `make up`):
the real sandbox connector in front of this app, the real relay, the real
Solana mock-USDC channels — and the assertions are the connectors' own claim
books and the relay's own store, never this app's internals.

It proves, in order:

1. **The directory.** The Provider Profile, one Listing per `[[listings]]`
   entry and an unexpired Liveness are read back off the sandbox relay by
   the provider's pubkey and `#L = toon.network`, and Liveness's
   `available.<listing>` is `capacity − live leases` — the provider's own
   count, checked before anything is spawned, again while the lease runs
   (one less) and again after it expires (back to capacity).
2. **Availability**, the free route, end to end: `{ "would_run": true }` for
   the listing and the smoke's sshd image; 0 arrives at the provider and the
   provider connector's book does not move.
3. **Spawn**, paid: a tenant-signed Lease Request buys
   `g.toon.provider.<listing>.v1.spawn`; the answer names the workload,
   `expires_at = now + lease_interval_s` and the access block; the
   workload is running on the host as a `toon-<id>` container by
   `reference@digest`.
4. **Extension**, paid, unsigned: `expires_at` grows by exactly one Lease
   Interval; `ssh -i <tenant key>` opens the workload; the free,
   tenant-signed **status** reports `running`, the new expiry and the same
   workload id, role and access; the next Liveness counts the lease.
5. **Expiry**: once `expires_at` passes and the sweep (≤ 30 s) has run, the
   workload is gone from the host and status reports
   `{ "ended": "expiry" }` with no access; the next Liveness has the
   capacity back.
6. **The money**, per leg, to the unit: the payer's channel book grew by
   exactly spawn + extend at the route price — plus, through the hub, the
   hub's fee on **every** packet, the free ones included, because the hub
   charges its fee to forward and `100 − 100 = 0` is what arrives — the
   provider connector's book by exactly spawn + extend at the listing
   price, and the free routes added nothing at the provider.

All of it runs **twice**, with the same tenant ceremony:

- **via the hub** — the tenant's channel is against the sandbox hub
  (`:3200`), packets are sealed to the provider connector and forwarded over
  the `relay-provider` peering; the hub's client book and the provider
  connector's peer-book watermark on the committed peering channel are
  asserted;
- **direct** — the tenant opens a channel against the provider connector's
  own client edge (`:3240`) and pays the listing price with no hub and no
  fee; the provider connector's client book is asserted.

The two runs' answers (`availability`, `spawn`, `extend`, `status` running
and ended — the same fields, the same role, state and `would_run`, with only
the per-run workload id, expiry and port blanked) and lease lifecycles are
then compared: the provider cannot tell how it was paid, which is the point
of ADR 0005.

It buys the sandbox-only `smoke` listing (`infra/sandbox/conf/provider.toml`:
`basic`'s price and resources with a **30 s** Lease Interval, capacity 2),
so spawn + one extension + the sweep is about 90 s per run and the whole
test takes **three to four minutes**. `TOON_M1_LISTING=basic` runs the same
test on the three-minute tier (budget about fifteen minutes). The
ticket-level smokes — `make smoke-provider`, `make smoke-directory`,
`make smoke-eviction` — still run on `basic`, end their leases through the
provider (terminate, eviction), and can be run back to back with
`make smoke-m1` in any order.

## Wire fixtures for tenant implementations

`tests/wire_fixtures.rs` generates golden files under `tests/fixtures/wire/`
from the real HTTP surface and the real event builders: a signed Lease
Request per `op` with its packet body, request and response bodies for
spawn, extend, availability, status and terminate, one refusal per spec §5
error code in validation order, one Profile, Listing, Liveness, Eviction
Notice and Takeover each, the two roles a Standby Set gives (`spawn.primary`,
`spawn.standby` and a `status` for each), the `status` of a standby that
won a Takeover and of one that lost (`status.won`, `status.lost` — driven
through the real watchdog over the fake Directory), and the route table a
Listing generates. Everything is produced
over fixed test-only keys, a fixed clock and BIP-340 signatures with all-zero
auxiliary randomness, so the bytes are reproducible and a tenant can re-derive
every id and signature (TOON_Network #16).

`cargo test` verifies the files byte-for-byte and fails on drift, so a wire
change that is not reflected in the fixtures fails CI. After an intended
change:

```sh
make fixtures                                  # regenerate tests/fixtures/wire/
make fixtures TOON_SPEC_DIR=../TOON_Network    # ... and sync the spec's docs/spec/fixtures/wire/
make fixtures-check                            # verify without touching them (what CI runs)
```

The spec repository's copy and its README (`docs/spec/fixtures/README.md`
there) are what tenant implementations test against; keep them in sync with
the same commit that changes the wire.

## Build, test and run

```sh
cargo build
cargo test                 # no Docker daemon needed
cargo test -- --ignored    # the Docker backend, and a registry-entry spawn, against a real daemon
cargo clippy --all-targets
cargo run -- --config provider.toml
```

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
