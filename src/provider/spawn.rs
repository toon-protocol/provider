// Spawn: the paid request that starts a lease and buys its first Lease
// Interval (spec §6.2).
//
// ONE function serves both paid spawn routes, because they are one request:
// a tenant forming a Standby Set signs a single spawn and posts it to every
// member, and only the route it arrives on says whether this provider was
// meant to run the workload (`.spawn`) or to hold capacity for it
// (`.standby`). Splitting them would be two copies of the same six
// validation steps that could drift apart on the one thing they must agree
// about — what the set means.
//
// Validation runs in the spec's order and refuses with the FIRST failing
// code: (1) the Lease Request — signature, addressee, freshness, replay;
// (2) the listing version — it must exist AND be the one on sale
// (`ProviderConfig::sellable_listing`, shared with `availability`), it must
// price standbys when the route is `.standby`, and the volume and ports must
// fit it; (3) the role (`standby::membership`); (4) the workload id;
// (5) the image; (6) capacity. Then the workload is started — or, for a Warm
// Standby, deliberately not: the lease is Reserved, the capacity is held, and
// nothing runs until a Takeover (spec §6.7, §7.1). A refusal on either route
// is still billed (ADR 0003), so the order is the whole of what a tenant can
// rely on: the first reason is the one reported.
//
// Step 5 is the resolution `availability` also does (`image_policy::check`:
// the entry if there is one, the index, the manifest for the listing's
// arch, its config). For an image named by content address — through its
// Image Registry entry or by digest alone — the bytes then have to be
// FETCHED — every layer down §8.4's chain, verified,
// cached, assembled into an OCI layout and loaded into the backend — and
// that happens after the slot is reserved and outside the lease-table lock,
// since a layer can take minutes and nothing else should wait on it. A
// fetch that fails releases the slot again and is answered `refused_image`
// (no source could serve a blob) or `no_capacity` (the cache is full); no
// container exists after either. Milestone 1's `reference` form keeps its
// own path: the backend pulls `reference@digest` itself.

use std::collections::HashMap;

use tracing::{error, info, warn};

use super::config::{Listing, MAX_PORTS_PER_WORKLOAD};
use super::image_policy::{self, ResolvedImage};
use super::oci_layout::write_layout_tar;
use super::persistence::{count_live, persist_leases, LeaseRecord, LeaseState};
use super::standby::{self, SpawnRoute};
use crate::compute::{container_name, ContainerConfig, PortMapping};
use crate::nostr::image_events::SpawnImage;
use crate::nostr::lease_request::{self, Op};
use crate::nostr::wire::{
    is_lower_hex, Access, ErrorCode, ErrorResponse, PortAccess, PortRequest, Role, SpawnContent,
    SpawnResponse,
};
use crate::provider_http::AppState;

/// Where a workload's persistent volume is mounted when the spawn asks for
/// one. Milestone 1 fixes the path; the size is validated against the
/// listing but not enforced by the backend.
pub const VOLUME_MOUNT_PATH: &str = "/data";

fn invalid(message: impl Into<String>) -> ErrorResponse {
    ErrorResponse::new(ErrorCode::InvalidRequest, message)
}

/// Serve one standby spawn on `<addr>.<listing>.v<version>.standby`: the
/// same request `spawn` serves, paid at the listing's `standby_price`,
/// buying a Warm Standby's reservation instead of a running workload.
pub async fn standby_spawn(
    state: &AppState,
    listing_name: &str,
    version: u32,
    body: &[u8],
) -> Result<SpawnResponse, ErrorResponse> {
    serve(state, listing_name, version, body, SpawnRoute::Standby).await
}

/// Serve one spawn on `<addr>.<listing>.v<version>.spawn`: a standalone
/// lease, or a Standby Set's primary.
pub async fn spawn(
    state: &AppState,
    listing_name: &str,
    version: u32,
    body: &[u8],
) -> Result<SpawnResponse, ErrorResponse> {
    serve(state, listing_name, version, body, SpawnRoute::Spawn).await
}

async fn serve(
    state: &AppState,
    listing_name: &str,
    version: u32,
    body: &[u8],
    route: SpawnRoute,
) -> Result<SpawnResponse, ErrorResponse> {
    let now = state.clock.now();

    // ── 1. the Lease Request ────────────────────────────────────────────
    let request = lease_request::accept(
        body,
        &state.keys.public_key(),
        Op::Spawn,
        now,
        &state.accepted_requests,
    )?;
    let content: SpawnContent = serde_json::from_str(&request.content)
        .map_err(|e| invalid(format!("spawn content: {}", e)))?;
    check_shape(&content)?;
    refuse_until_per_lease_addresses(&state.config)?;

    // ── 2. the listing version, and the fit ─────────────────────────────
    let listing = state
        .config
        .sellable_listing(listing_name, version)?
        .clone();
    // …and, on `.standby`, that this listing sells Warm Standbys at all —
    // the same check, with the same code and message, that `availability`
    // answers the standby question with (`Listing::sells_standbys`).
    if route == SpawnRoute::Standby {
        listing.sells_standbys()?;
    }
    if let Some(volume) = content.volume_gb {
        if volume > listing.resources.storage_gb {
            return Err(invalid(format!(
                "volume_gb {} exceeds the listing's storage_gb {}",
                volume, listing.resources.storage_gb
            )));
        }
    }
    check_ports(&content.ports)?;

    // ── 3. the role ─────────────────────────────────────────────────────
    // Position in the set and route together (spec §6.2 step 3): standalone,
    // the set's primary, or one of its Warm Standbys.
    let membership = standby::membership(
        content.standby_set.as_deref(),
        &state.keys.public_key(),
        &request.addressees,
        route,
    )?;
    let role = membership.role;
    let reserving = role == Role::Standby;

    // ── 4. the workload id, 5. the image, 6. capacity ───────────────────
    // Held under one lock with the insert, so two spawns racing for the
    // last slot or the same id cannot both pass.
    let tenant_hex = request.tenant.to_hex();
    let ssh_port;
    let ports;
    let id;
    // Which of the three forms §6.2 allows the `image` is, and what it
    // resolved to.
    let image;
    let resolved;
    {
        let mut leases = state.leases.lock().await;
        if leases
            .values()
            .any(|l| l.state.is_live() && l.workload_id == content.workload_id)
        {
            // The same tenant re-spawning an id it holds is refused too: a
            // spawn buys a NEW lease, and the id names a lease that exists.
            return Err(ErrorResponse::new(
                ErrorCode::WorkloadIdTaken,
                "a lease with this workload_id is already held on this provider",
            ));
        }
        // Step 5: which of the three forms §6.2 allows the `image` is — a
        // fourth shape is `invalid_request` — and then whether this
        // provider will run it: the provider's own image policy — a deny
        // list and a size cap — applied to what the image resolves to
        // (spec §8.4). The same check `availability` applies, so a
        // positive `availability` answer and a paid spawn's outcome never
        // disagree (spec §9). This holds the lease-table lock across the
        // resolution's network reads; deliberately so, to keep the same
        // atomicity `workload_id_taken`/capacity/insert already relied on,
        // at the cost of serialising spawns behind an uncached image lookup
        // (a repeat digest is served from the blob cache without another
        // fetch). Only resolution happens here; the layers are fetched
        // below, after the slot is taken and the lock released.
        image = SpawnImage::parse(&content.image)?;
        resolved = image_policy::check(
            &state.fetcher,
            state.directory.clone(),
            &state.image_policy,
            &listing,
            &image,
        )
        .await?;
        let running = count_live(&leases, &listing.name);
        if running >= state.config.capacity_of(&listing.name) as usize {
            return Err(ErrorResponse::new(
                ErrorCode::NoCapacity,
                format!("every {} slot is taken", listing.name),
            ));
        }
        id = free_workload_id(state, &leases).await.ok_or_else(|| {
            ErrorResponse::new(
                ErrorCode::NoCapacity,
                "no free workload id on this provider",
            )
        })?;
        ssh_port = state.config.ssh_host_port(id);
        ports = content
            .ports
            .iter()
            .enumerate()
            .map(|(index, port)| {
                state
                    .config
                    .workload_host_port(id, index as u16)
                    .map(|host_port| PortAccess {
                        container_port: port.container_port,
                        host_port,
                    })
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| {
                ErrorResponse::new(ErrorCode::NoCapacity, "no free host port for this workload")
            })?;

        leases.insert(
            id,
            LeaseRecord {
                id,
                workload_id: content.workload_id.clone(),
                tenant: tenant_hex.clone(),
                listing: listing.name.clone(),
                listing_version: listing.version,
                role,
                // A Warm Standby is Reserved from the start and never
                // Provisioning: there is nothing to provision. Both states
                // are live, so either way the slot, the workload id and the
                // ports are held from this instant (spec §6.7).
                state: if reserving {
                    LeaseState::Reserved
                } else {
                    LeaseState::Provisioning
                },
                standby_set: membership.set,
                // Only a reservation keeps it: it is what a Takeover would
                // start, and a lease that is about to start its own workload
                // needs nothing kept.
                reserved_spawn: reserving.then(|| content.clone()),
                takeover: None,
                settled: None,
                // Nothing has taken this workload over: a spawn is the
                // start of the lease, not a restart after one (spec §7.1).
                taken_over: false,
                created_at: now,
                // The same interval buys either role (spec §6.2): the
                // standby paid less for it, at the listing's standby price.
                expires_at: now + listing.lease_interval_s,
                ended_at: None,
                destroyed: false,
                // Kept, never read: `status` hands it back so tooling can
                // show which Template the tenant expanded (spec §6.2).
                template: content.template.clone(),
                ssh_port,
                ports: ports.clone(),
            },
        );
        persist_leases(&leases, &state.config.lease_state_path);
    }

    // ── a Warm Standby stops here ───────────────────────────────────────
    // The capacity is held and paid for and NOTHING RUNS. Step 5 above
    // RESOLVED the image — the index, the manifest for the listing's arch
    // and its config, exactly as `availability` does — so a reservation is
    // never sold for an image this provider would refuse; what does not
    // happen is everything below: no layer is fetched, no layout is loaded,
    // no container is made, and the answer carries no `access` because there
    // is nowhere to reach until a Takeover (spec §6.2, §7.1). That is what
    // the tenant bought.
    if reserving {
        info!(
            "reserved {} ({} v{}) for tenant {} as a Warm Standby until {}",
            content.workload_id,
            listing.name,
            listing.version,
            tenant_hex,
            now + listing.lease_interval_s
        );
        return Ok(SpawnResponse {
            workload_id: content.workload_id,
            role,
            expires_at: now + listing.lease_interval_s,
            access: None,
        });
    }

    // ── fetch it and start it ───────────────────────────────────────────
    // The same two steps a Takeover's start goes through (`fetch_and_start`,
    // shared with `settle`): a standby that won starts from the image
    // exactly as this spawn does (ADR 0010).
    info!(
        "spawning workload {} ({} v{}) for tenant {} as {}",
        content.workload_id,
        listing.name,
        listing.version,
        tenant_hex,
        container_name(id)
    );
    let launch = Launch {
        id,
        listing: &listing,
        content: &content,
        ssh_port,
        ports: &ports,
    };
    if let Err(e) = fetch_and_start(state, &image, &resolved, launch).await {
        // Nothing runs and nothing is left on the backend, so there is
        // nothing to destroy: just give the slot and the id back so the
        // tenant's next try can succeed. Nothing is refunded (ADR 0003),
        // which is why `availability` resolves the image for free first —
        // but a layer that fails only on the full fetch, or a daemon that
        // refuses the start, can only be found out here.
        let mut leases = state.leases.lock().await;
        leases.remove(&id);
        persist_leases(&leases, &state.config.lease_state_path);
        return Err(e);
    }

    let mut leases = state.leases.lock().await;
    let Some(expires_at) = mark_running(&mut leases, id) else {
        // The lease ended while it was being provisioned — its tenant
        // terminated it, or the sweep reaped it. Whoever ended it
        // destroyed a workload that did not exist yet, so this one is
        // ours to clean up. Nothing is refunded (ADR 0003).
        warn!("lease {} ended while it was being provisioned", id);
        persist_leases(&leases, &state.config.lease_state_path);
        drop(leases);
        if let Err(cleanup) = state.backend.delete_container(id).await {
            warn!("could not clean up {}: {}", container_name(id), cleanup);
        }
        return Err(ErrorResponse::new(
            ErrorCode::Expired,
            "this lease was ended while its workload was being started",
        ));
    };
    persist_leases(&leases, &state.config.lease_state_path);
    Ok(SpawnResponse {
        workload_id: content.workload_id,
        role,
        expires_at,
        access: Some(Access {
            host: state.config.access_host().to_string(),
            ssh_port,
            ports,
        }),
    })
}

/// PLACEHOLDER, removed by M4-2 (TOON_Network #39). A Hidden Provider owes
/// every lease a `.anyone` address of its own (spec §10), and until the
/// spawn creates one through the `HiddenService` port there is nothing a
/// tenant could reach: `access.host` would be an IP the provider promised
/// never to publish, or nothing. So a spawn on a hidden provider is refused
/// before a slot is taken — `invalid_request`, since the request is fine
/// and it is this provider that cannot serve it yet — and `availability`
/// answers the same for free first, so nobody pays for an address the
/// provider cannot give (spec §9). Both call sites go with this function.
pub(super) fn refuse_until_per_lease_addresses(
    config: &super::config::ProviderConfig,
) -> Result<(), ErrorResponse> {
    if !config.hidden {
        return Ok(());
    }
    Err(invalid(
        "this is a Hidden Provider, and per-lease .anyone addresses land later in Milestone 4: \
         it starts no lease until then",
    ))
}

/// What a workload is started from: the lease's slot and the spawn that
/// describes it. One value for the two callers that start workloads — a
/// paid spawn on `.spawn`, and a Warm Standby that won a Takeover
/// (`settle`) — so the two cannot start a workload differently: ADR 0010
/// promises that a Takeover starts from the image exactly as a spawn would.
pub(super) struct Launch<'a> {
    pub id: u32,
    pub listing: &'a Listing,
    pub content: &'a SpawnContent,
    pub ssh_port: u16,
    pub ports: &'a [PortAccess],
}

/// Fetch the image's bytes if this provider holds them, then create and
/// start the workload: the last two steps of a spawn, and the whole of what
/// a Takeover's start does. `image` and `resolved` are step 5's outcome —
/// the caller resolved the image first, because a spawn does that under the
/// lease-table lock and a Takeover does not.
///
/// The lease table is NOT touched: the caller owns the record and decides
/// what a failure means for it — a spawn gives the slot back, a standby that
/// won keeps its reservation and tries again on the next step. Nothing is
/// left on the backend after a failure: a container that was created and
/// did not start is deleted here. A layer no source serves is
/// `refused_image`; a cache or a daemon with no room, or a start the backend
/// refused, is `no_capacity`.
pub(super) async fn fetch_and_start(
    state: &AppState,
    image: &SpawnImage,
    resolved: &ResolvedImage,
    launch: Launch<'_>,
) -> Result<(), ErrorResponse> {
    // What the backend is told to run: `<reference>@<digest>` for the form
    // the backend pulls itself, or the id the backend gave the image this
    // provider fetched, verified and loaded.
    let run_image = match image.upstream_pull() {
        Some(pull) => pull,
        None => materialise(state, resolved).await.inspect_err(|e| {
            warn!(
                "image {} for workload {} could not be fetched: {}",
                resolved.manifest_digest, launch.content.workload_id, e.message
            );
        })?,
    };

    let config = container_config(
        launch.id,
        launch.listing,
        launch.content,
        &run_image,
        launch.ssh_port,
        launch.ports,
    );
    let started = match state.backend.create_container(&config).await {
        Ok(_) => state.backend.start_container(launch.id).await,
        Err(e) => Err(e),
    };
    match started {
        Ok(()) => Ok(()),
        Err(e) => {
            // Leave no half-made workload behind: the caller may retry, and
            // a container by this name would make the retry fail too.
            error!("starting workload {} failed: {}", config.name, e);
            if let Err(cleanup) = state.backend.delete_container(launch.id).await {
                warn!(
                    "could not clean up {} after a failed start: {}",
                    config.name, cleanup
                );
            }
            Err(ErrorResponse::new(
                ErrorCode::NoCapacity,
                format!("the workload could not be started: {}", e),
            ))
        }
    }
}

/// Fetch every layer of an image whose bytes THIS PROVIDER holds — the two
/// content-address forms, through an Image Registry entry or by digest
/// alone — assemble the verified blobs into an OCI layout and load it into
/// the backend; answer the image id the backend runs it by (spec §8.4).
///
/// Each layer goes down the same chain resolution came down, and down the
/// same `BlobSources` value, so a Blob Record the Relay Set already
/// answered for is not looked up twice.
///
/// The manifest and the config are already in the cache — resolution put
/// them there — so the layout is written straight out of the cache once
/// every layer has joined them. A layer no source can serve is
/// `refused_image`; one the cache has no room for is `no_capacity`. The
/// layout tar lives in the cache's scratch directory only for the length of
/// the load.
async fn materialise(state: &AppState, image: &ResolvedImage) -> Result<String, ErrorResponse> {
    for layer in image.layer_digests() {
        state.fetcher.fetch(layer, &image.sources).await?;
    }

    let cache = state.fetcher.cache().clone();
    let layout = cache.scratch_dir().join(format!(
        "{}.oci.tar",
        image
            .manifest_digest
            .strip_prefix("sha256:")
            .unwrap_or(&image.manifest_digest)
    ));
    let written = {
        let cache = cache.clone();
        let image = image.clone();
        let layout = layout.clone();
        tokio::task::spawn_blocking(move || write_layout_tar(&cache, &image, &layout))
            .await
            .map_err(|e| anyhow::anyhow!("writing the image layout panicked: {}", e))
            .and_then(|r| r)
    };
    let loaded = match written {
        Ok(()) => state.backend.load_image(&layout).await,
        Err(e) => Err(e),
    };
    let _ = tokio::fs::remove_file(&layout).await;
    loaded.map_err(|e| {
        // The blobs are all verified and on disk; what failed is the
        // provider's own disk or daemon, which is the provider being out of
        // room to run this — `no_capacity`, so the tenant tries elsewhere
        // rather than concluding the image is bad.
        ErrorResponse::new(
            ErrorCode::NoCapacity,
            format!(
                "image {} could not be loaded into the backend: {:#}",
                image.manifest_digest, e
            ),
        )
    })
}

/// The lowest workload id in range that neither the backend nor a LIVE lease
/// holds. Both are asked: the backend knows what runs, and the table knows
/// what is still leased — a workload that vanished from the daemon keeps its
/// id until its lease ends, or a re-spawn could land on a lease the sweep is
/// about to reap.
///
/// A retained ENDED record does not hold its id: retention keeps what
/// `status` answers, and it must never cost a tenant a slot. Taking the id
/// back drops that record early, which is the same answer a tenant gets once
/// retention runs out.
async fn free_workload_id(state: &AppState, leases: &HashMap<u32, LeaseRecord>) -> Option<u32> {
    let end = state.config.workload_id_range_end;
    let mut from = state.config.workload_id_range_start;
    while from <= end {
        let id = state.backend.find_available_id(from, end).await.ok()?;
        if leases.get(&id).is_none_or(|l| !l.state.is_live()) {
            return Some(id);
        }
        from = id.checked_add(1)?;
    }
    None
}

/// Promote a lease whose workload has started, and answer its expiry.
///
/// `None` when the lease is no longer the Provisioning one this spawn
/// inserted: a Termination or a sweep may end a lease between the insert and
/// the start, and an ended lease must never be brought back to Running — its
/// workload has already been destroyed, or is about to be.
fn mark_running(leases: &mut HashMap<u32, LeaseRecord>, id: u32) -> Option<u64> {
    let lease = leases.get_mut(&id)?;
    if lease.state != LeaseState::Provisioning {
        return None;
    }
    lease.state = LeaseState::Running;
    Some(lease.expires_at)
}

/// The shape checks that need no listing: the workload id, the SSH key and
/// the entrypoint are well-formed or the request is invalid.
fn check_shape(content: &SpawnContent) -> Result<(), ErrorResponse> {
    if !is_lower_hex(&content.workload_id, 64) {
        return Err(invalid(
            "workload_id must be 32 random bytes as 64 lowercase hex characters",
        ));
    }
    if !looks_like_ssh_public_key(&content.ssh_public_key) {
        return Err(invalid(
            "ssh_public_key must be one OpenSSH public key line (`ssh-ed25519 AAAA… comment`)",
        ));
    }
    if matches!(&content.entrypoint, Some(e) if e.is_empty()) {
        return Err(invalid("entrypoint: an empty list names no executable"));
    }
    Ok(())
}

/// The ports fit what a lease may publish: at most a workload's block, no
/// port 0, no `port/protocol` twice.
fn check_ports(ports: &[PortRequest]) -> Result<(), ErrorResponse> {
    if ports.len() > usize::from(MAX_PORTS_PER_WORKLOAD) {
        return Err(invalid(format!(
            "at most {} ports may be published per workload",
            MAX_PORTS_PER_WORKLOAD
        )));
    }
    for (i, port) in ports.iter().enumerate() {
        if port.container_port == 0 {
            return Err(invalid("ports: container_port 0 is not a port"));
        }
        if ports[..i]
            .iter()
            .any(|p| p.container_port == port.container_port && p.protocol == port.protocol)
        {
            return Err(invalid(format!(
                "ports: {}/{} is listed twice",
                port.container_port,
                port.protocol.as_str()
            )));
        }
    }
    Ok(())
}

fn looks_like_ssh_public_key(key: &str) -> bool {
    let key = key.trim();
    if key.is_empty() || key.contains('\n') || key.contains('\r') {
        return false;
    }
    let mut parts = key.split_ascii_whitespace();
    let (Some(kind), Some(blob)) = (parts.next(), parts.next()) else {
        return false;
    };
    let known = kind.starts_with("ssh-")
        || kind.starts_with("ecdsa-sha2-")
        || kind.starts_with("sk-ssh-")
        || kind.starts_with("sk-ecdsa-");
    known && blob.len() >= 16
}

fn container_config(
    id: u32,
    listing: &Listing,
    content: &SpawnContent,
    pull: &str,
    ssh_port: u16,
    ports: &[PortAccess],
) -> ContainerConfig {
    let (entrypoint, leading_args) = match &content.entrypoint {
        Some(e) => (e.first().cloned(), e[1..].to_vec()),
        None => (None, vec![]),
    };
    let mut args = leading_args;
    args.extend(content.args.clone().unwrap_or_default());
    ContainerConfig {
        id,
        name: container_name(id),
        image: pull.to_string(),
        cpu_millicores: listing.resources.cpu_millicores,
        memory_mb: listing.resources.memory_mb,
        storage_gb: listing.resources.storage_gb,
        ssh_key: Some(content.ssh_public_key.trim().to_string()),
        host_port: Some(ssh_port),
        ports: ports
            .iter()
            .zip(&content.ports)
            .map(|(access, request)| PortMapping {
                host_port: access.host_port,
                container_port: access.container_port,
                protocol: request.protocol.as_str().to_string(),
            })
            .collect(),
        env: content.env.clone().into_iter().collect(),
        entrypoint,
        args,
        data_path: content
            .volume_gb
            .filter(|gb| *gb > 0)
            .map(|_| VOLUME_MOUNT_PATH.to_string()),
        capabilities: listing.capabilities.clone(),
        // The egress policy a hidden workload is attached with comes from
        // the `HiddenService` port; the Docker backend acts on it from M4-4
        // (TOON_Network #41), and no hidden lease is started before then.
        egress: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_public_key_lines_are_recognised() {
        assert!(looks_like_ssh_public_key(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxvbmdlbm91Z2g tenant@host"
        ));
        assert!(looks_like_ssh_public_key(
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ"
        ));
        assert!(!looks_like_ssh_public_key(""));
        assert!(!looks_like_ssh_public_key("password123"));
        assert!(!looks_like_ssh_public_key(
            "ssh-ed25519 AAAA\nssh-ed25519 BBBB"
        ));
    }
}
