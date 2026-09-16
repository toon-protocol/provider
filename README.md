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

Milestone 2 is in progress: an image named by its **Image Registry entry**
is resolved and fetched through the TOON store and upstream registries,
verified blob by blob, cached across leases, and run — see
[Spawning](#spawning). An image named by digest alone is not resolved yet.

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
app. Warm standby and the reputation math stay in the tree, compiling, but
nothing calls them — they are Milestone 3 work.

**Removed**, because TOON replaces each of them:

| Removed | Replaced by |
|---|---|
| Cashu (`cdk`, `cdk-sqlite`, `bip39`), the mint whitelist, the wallet CLI and the Lightning sweep | A TOON payment channel, terminated by the provider's connector |
| `ngx_l402` and its nginx config | The TOON connector |
| The NIP-04/NIP-17 direct-message transport | Sealed HTTP through the connector |
| The offer (`38383`), heartbeat (`38384`, `20384`), lease revocation (`38385`) and standby promotion (`38386`) event kinds | Provider Profile, Listing, Liveness and Eviction Notice events. None of the Paygress kind numbers is reused — `38383` collides with NIP-69 |
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
| `<addr>.availability` | `POST /availability` | 0 |
| `<addr>.status` | `POST /status` | 0 |
| `<addr>.terminate` | `POST /terminate` | 0 |

`toon-provider routes --config provider.toml` prints these as connector
`[[routes]]` rows, ready to paste into the connector's config. It prints two
rows per **live** listing version — the version on sale, plus every retired
version that still has a running lease — so it reads the lease table at
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
pubkey), `op` = `spawn` and `expiration` (at most 300 s after `created_at`),
whose content is

```json
{ "workload_id": "<32 random bytes, hex>",
  "image": { "reference": "docker.io/library/alpine", "digest": "sha256:…" },
  "env": { "KEY": "value" }, "ports": [ { "container_port": 443, "protocol": "tcp" } ],
  "volume_gb": 2, "ssh_public_key": "ssh-ed25519 AAAA… tenant",
  "entrypoint": ["/bin/sh"], "args": ["-c", "…"] }
```

`image` may take any of the three forms spec §6.2 allows, and two of them
run today:

| Form | Meaning | Today |
|---|---|---|
| `{ "reference", "digest" }` | Pull `reference@digest` from an upstream OCI registry | Runs: the daemon pulls it |
| `{ "digest", "registry_entry": { "address", "relay" } }` | The Image Registry entry at `address` lists every blob and where its bytes are (spec §8.1) | Runs: this provider fetches it |
| `{ "digest" }` | The blobs are found by Blob Record lookup on the Relay Set (spec §8.4) | `refused_image` |

Anything else — a `reference` and a `registry_entry` together, a `digest`
that is not `sha256:` plus 64 lowercase hex, a `registry_entry` whose
`address` is not `30434:<pubkey>:<name>:<tag>` — is a fourth shape and
`invalid_request`. A bare digest is `refused_image` rather than
`invalid_request` because the request is exactly what the spec allows; this
provider simply does not resolve it yet, and `availability` reports that
for free before a tenant pays for the same answer.

**Through the Image Registry.** An image named by its entry is resolved the
way §8.4 says — the entry is read from the relay hinted at, and the index,
the manifest for the listing's `arch` and its config are fetched and
verified through the entry's sources (see
[Availability and image policy](#availability-and-image-policy)); that
much `availability` does too. A paid spawn then, once the slot is reserved,
fetches every layer the same way — a `toon-store` source as its Blob
Record and parts from `gateway_url_pattern`, an `oci` source by digest from
the registry the entry names — checks each part against its recorded
sha256 and size and each blob against its digest, and keeps every verified
blob in the [blob cache](#configuration) (`blob_cache_dir`). The blobs are
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

**Through an upstream reference**, the image is pulled by the daemon as
`reference@digest`, so the daemon verifies the bytes and picks the manifest
for its own architecture. `template` — the
`30436:<pubkey>:<name>` a tenant expanded its values from — is parsed and
never read: a Template grants nothing, and only the listing decides what
privileges a workload gets (ADR 0004). Anything else in the content — a
runtime flag, a host mount, a device, a capability — is refused as
`invalid_request`. That includes every way of asking for a Docker daemon
inside the workload: see [Capabilities](#capabilities).

**SSH.** The tenant's key is handed to the workload as the environment
variable `SSH_PUBLIC_KEY`, and `access.ssh_port` forwards to the workload's
port 22. An image whose sshd installs that variable serves SSH as-is; any other
image can bridge it with the spawn's own `entrypoint` and `args` (e.g.
`["/bin/sh"]` + `["-c", "PUBLIC_KEY=\"$SSH_PUBLIC_KEY\" exec /init"]` for
`linuxserver/openssh-server`). No password is ever issued. A volume, when
asked for, is mounted at `/data`.

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
              "ports": [ { "container_port": 443, "host_port": 41000 } ] } }
```

`state` is the §6.7 lease state: `"provisioning"`, `"running"`, or
`{ "ended": "expiry" | "termination" | "eviction" }`. It is the lease record
as it stands, so between an expiry and the sweep that reaps it a lease still
reads `"running"` with an `expires_at` in the past — extend and terminate
refuse it as `expired` all the same. `access` is absent once
the lease has ended — the workload is gone, and there is nothing left to
reach. The same encoding is what the lease table holds on disk.

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
  "image": { "reference": "docker.io/library/alpine", "digest": "sha256:…" } }
```

This is the ticket's shape, not the spec draft's flatter `image_digest`; an
unknown field (including `image_digest`) is `invalid_request`. The route
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
a layer. Where the bytes come from depends on the form:

- `{ reference, digest }`: from the upstream OCI registry the reference
  names, over plain HTTP(S) (`docker.io` references resolve against
  `registry-1.docker.io`, with an anonymous token from the challenge in
  `Www-Authenticate` when the registry answers 401 — the generic bearer flow
  every OCI-distribution registry supports; other registries are tried
  anonymously first).
- `{ digest, registry_entry }`: the Image Registry entry is read from the
  relay the request hints at, and must be the entry named — signed by the
  address's pubkey, under its `<name>:<tag>`, describing this digest. Each
  blob is then fetched from the source the entry lists for it: a
  `toon-store` source is a Blob Record read from the TOON store by its own
  upload's txid at `gateway_url_pattern`, then each part from the same
  pattern, each checked against its recorded sha256 and size and
  concatenated in order; an `oci` source is a pull by digest from the
  registry and repository the entry names. An entry that omits a blob the
  manifest needs, a relay that holds no entry at the address, or a source
  that cannot serve a blob is `refused_image`.

Every blob, wherever it came from, is verified against its digest before
anything is read out of it; bytes that do not match are discarded. A
mismatch, or a gateway or registry that cannot be reached at all, is
`refused_image` — there is no distinct "registry down" code, since a
tenant's availability check or spawn has no use for anything but a refusal
right now. Verified blobs are kept on disk in the blob cache
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

Everything a relay should filter on is a single-letter tag; numbers stay in
content, because NIP-01 filters never match inside content (ADR 0002).

The Profile and the Listings go out at startup and change only when the config
does — which is a restart. Liveness goes out every `liveness_cadence_s`. An
Eviction Notice goes out once, immediately, whenever `toon-provider evict`
succeeds.

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
error code in validation order, one Profile, Listing, Liveness and Eviction
Notice each, and the route table a Listing generates. Everything is produced
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
