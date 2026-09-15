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
access details out), a paid **extension**, and the free **status** and
**termination** routes — sweeps expired leases, and prints the connector route
table it expects. Availability, the directory events and the image policy are
being added ticket by ticket; their routes answer `invalid_request` "not
implemented" until then.

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
  `price` (integer µUSDC per Lease Interval), `capabilities`, `capacity`.
  A price change is a new version with its own routes (ADR 0009). `capacity`
  is how many leases of that name may run at once, across its versions.
- `handler_base_url`: where the *connector* reaches this app; the origin of
  every `handler_url` in the route table.
- `nostr_private_key`: the provider's identity. A Lease Request is addressed
  to its public key.
- `ended_retention_s`: how long an ended lease is still answerable by
  `status` before the sweep forgets it. Default 86400 (one day).

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
`[[routes]]` rows, ready to paste into the connector's config. Every answer
is JSON; a refusal is `{ "error": "<code>", "message": "…" }` with a 4xx
status and the spec's code, and on a paid route it is still billed.

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

The image is pulled as `reference@digest`, so the daemon verifies the bytes
and picks the manifest for its own architecture. Anything else in the
content — a runtime flag, a host mount, a device, a capability — is refused
as `invalid_request`; privileges come only from the listing (ADR 0004).

**SSH.** The tenant's key is handed to the workload as the environment
variable `SSH_PUBLIC_KEY`, and `access.ssh_port` forwards to the workload's
port 22. An image whose sshd installs that variable serves SSH as-is; any other
image can bridge it with the spawn's own `entrypoint` and `args` (e.g.
`["/bin/sh"]` + `["-c", "PUBLIC_KEY=\"$SSH_PUBLIC_KEY\" exec /init"]` for
`linuxserver/openssh-server`). No password is ever issued. A volume, when
asked for, is mounted at `/data`.

## Extending, checking and ending a lease

**`POST /listings/<listing>/v<n>/extend`** (paid) takes `{ "workload_id": "…" }`
and no signature: an extension only adds time, so any payer may buy one for any
lease (ADR 0005) and a sponsor can pay for a lease it does not own. It adds
exactly one Lease Interval to the lease's expiry — extensions stack, and the
time is added to the expiry, not to `now` — and answers
`{ "workload_id", "expires_at" }`. It is refused with `unknown_workload` when
no lease of that id is held, `expired` when the lease has ended (by expiry,
termination or eviction), and `wrong_listing_version` when the lease was
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
`{ "ended": "expiry" | "termination" | "eviction" }`. `access` is absent once
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

## Build, test and run

```sh
cargo build
cargo test                 # no Docker daemon needed
cargo test -- --ignored    # the Docker backend against a real daemon
cargo clippy --all-targets
cargo run -- --config provider.toml
```

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
