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

Milestone 1 is in progress. Today the app serves `/health` and sweeps expired
leases; the lease routes, the directory events and the image path are being
added ticket by ticket.

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
[`provider.example.toml`](provider.example.toml) and edit it.

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
