// Spawn: the paid request that starts a lease and buys its first Lease
// Interval (spec §6.2).
//
// Validation runs in the spec's order and refuses with the FIRST failing
// code: (1) the Lease Request — signature, addressee, freshness, replay;
// (2) the listing version and whether the volume and ports fit it; (3) the
// role; (4) the workload id; (5) the image; (6) capacity. Then the workload
// is started. A refusal on this route is still billed (ADR 0003), so the
// order is the whole of what a tenant can rely on: the first reason is the
// one reported.

use std::collections::HashMap;

use tracing::{error, info, warn};

use super::config::{Listing, MAX_PORTS_PER_WORKLOAD};
use super::persistence::{persist_leases, LeaseRecord, LeaseState};
use crate::compute::{container_name, ContainerConfig, PortMapping};
use crate::nostr::lease_request::{self, Op};
use crate::nostr::wire::{
    Access, ErrorCode, ErrorResponse, LeaseRequestEnvelope, PortAccess, Role, SpawnContent,
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

/// Serve one spawn on `<addr>.<listing>.v<version>.spawn`.
pub async fn spawn(
    state: &AppState,
    listing_name: &str,
    version: u32,
    body: &[u8],
) -> Result<SpawnResponse, ErrorResponse> {
    let now = state.clock.now();

    // ── 1. the Lease Request ────────────────────────────────────────────
    let envelope: LeaseRequestEnvelope = serde_json::from_slice(body)
        .map_err(|e| invalid(format!("body is not {{ \"request\": <event> }}: {}", e)))?;
    let request =
        lease_request::validate(&envelope.request, &state.keys.public_key(), Op::Spawn, now)?;
    if !state
        .accepted_requests
        .accept(request.id, request.expiration, now)
    {
        return Err(ErrorResponse::new(
            ErrorCode::StaleRequest,
            "this Lease Request was already accepted; sign a new one",
        ));
    }
    let content: SpawnContent = serde_json::from_str(&request.content)
        .map_err(|e| invalid(format!("spawn content: {}", e)))?;
    check_shape(&content)?;

    // ── 2. the listing version, and the fit ─────────────────────────────
    let listing = state
        .config
        .listing(listing_name, version)
        .ok_or_else(|| {
            ErrorResponse::new(
                ErrorCode::WrongListingVersion,
                format!("this provider sells no {} v{}", listing_name, version),
            )
        })?
        .clone();
    if let Some(volume) = content.volume_gb {
        if volume > listing.resources.storage_gb {
            return Err(invalid(format!(
                "volume_gb {} exceeds the listing's storage_gb {}",
                volume, listing.resources.storage_gb
            )));
        }
    }

    // ── 3. the role ─────────────────────────────────────────────────────
    if content.standby_set.is_some() {
        return Err(invalid(
            "standby_set: Standby Sets are not sold in this milestone",
        ));
    }

    // ── 4. the workload id, 5. the image, 6. capacity ───────────────────
    // Held under one lock with the insert, so two spawns racing for the
    // last slot or the same id cannot both pass.
    let tenant_hex = request.tenant.to_hex();
    let ssh_port;
    let ports;
    let id;
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
        check_image(&content)?;
        let running = leases
            .values()
            .filter(|l| l.state.is_live() && l.listing == listing.name)
            .count();
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
                role: Role::Standalone,
                state: LeaseState::Provisioning,
                created_at: now,
                expires_at: now + listing.lease_interval_s,
                ssh_port,
                ports: ports.clone(),
            },
        );
        persist_leases(&leases, &state.config.lease_state_path);
    }

    // ── start it ────────────────────────────────────────────────────────
    let config = container_config(id, &listing, &content, ssh_port, &ports);
    info!(
        "spawning workload {} ({} v{}) for tenant {} as {}",
        content.workload_id, listing.name, listing.version, tenant_hex, config.name
    );
    let started = match state.backend.create_container(&config).await {
        Ok(_) => state.backend.start_container(id).await,
        Err(e) => Err(e),
    };
    let mut leases = state.leases.lock().await;
    match started {
        Ok(()) => {
            let expires_at = mark_running(&mut leases, id, now + listing.lease_interval_s);
            persist_leases(&leases, &state.config.lease_state_path);
            Ok(SpawnResponse {
                workload_id: content.workload_id,
                role: Role::Standalone,
                expires_at,
                access: Some(Access {
                    host: state.config.public_ip.clone(),
                    ssh_port,
                    ports,
                }),
            })
        }
        Err(e) => {
            // Provisioning failed after payment. Nothing is refunded (ADR
            // 0003); release the id and the slot so the tenant's next try
            // can succeed, and leave no half-made workload behind.
            error!("provisioning workload {} failed: {}", config.name, e);
            leases.remove(&id);
            persist_leases(&leases, &state.config.lease_state_path);
            if let Err(cleanup) = state.backend.delete_container(id).await {
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

/// The lowest workload id in range that neither the backend nor the lease
/// table holds. Both are asked: the backend knows what runs, and the table
/// knows what is still leased — a workload that vanished from the daemon
/// keeps its id until its lease ends, or a re-spawn could land on a lease
/// the sweep is about to reap.
async fn free_workload_id(state: &AppState, leases: &HashMap<u32, LeaseRecord>) -> Option<u32> {
    let end = state.config.workload_id_range_end;
    let mut from = state.config.workload_id_range_start;
    while from <= end {
        let id = state.backend.find_available_id(from, end).await.ok()?;
        if !leases.contains_key(&id) {
            return Some(id);
        }
        from = id.checked_add(1)?;
    }
    None
}

fn mark_running(leases: &mut HashMap<u32, LeaseRecord>, id: u32, expires_at: u64) -> u64 {
    match leases.get_mut(&id) {
        Some(lease) => {
            lease.state = LeaseState::Running;
            lease.expires_at
        }
        // Ended between insert and start (an eviction that fast is not a
        // path this milestone has, but the table must not grow a ghost).
        None => expires_at,
    }
}

/// The shape checks that need no listing: the workload id, the SSH key, the
/// ports and the entrypoint are well-formed or the request is invalid.
fn check_shape(content: &SpawnContent) -> Result<(), ErrorResponse> {
    let wid = &content.workload_id;
    if wid.len() != 64
        || !wid
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(invalid(
            "workload_id must be 32 random bytes as 64 lowercase hex characters",
        ));
    }
    if !looks_like_ssh_public_key(&content.ssh_public_key) {
        return Err(invalid(
            "ssh_public_key must be one OpenSSH public key line (`ssh-ed25519 AAAA… comment`)",
        ));
    }
    if content.ports.len() > usize::from(MAX_PORTS_PER_WORKLOAD) {
        return Err(invalid(format!(
            "at most {} ports may be published per workload",
            MAX_PORTS_PER_WORKLOAD
        )));
    }
    for (i, port) in content.ports.iter().enumerate() {
        if port.container_port == 0 {
            return Err(invalid("ports: container_port 0 is not a port"));
        }
        if content.ports[..i]
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
    if matches!(&content.entrypoint, Some(e) if e.is_empty()) {
        return Err(invalid("entrypoint: an empty list names no executable"));
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

/// Milestone 1 image checks: the shape of `reference@digest`, and no Image
/// Registry entry. Policy (`refused_image`) and arch selection
/// (`no_matching_arch`) are the availability ticket's.
fn check_image(content: &SpawnContent) -> Result<(), ErrorResponse> {
    let image = &content.image;
    if image.registry_entry.is_some() {
        return Err(invalid(
            "image.registry_entry: Image Registry entries are not read in this milestone",
        ));
    }
    let hex = image.digest.strip_prefix("sha256:").unwrap_or("");
    if hex.len() != 64
        || !hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(invalid("image.digest must be `sha256:<64 lowercase hex>`"));
    }
    if !looks_like_repository(&image.reference) {
        return Err(invalid(
            "image.reference must be an OCI repository (`registry/repo`), with no tag or digest",
        ));
    }
    Ok(())
}

/// `[registry[:port]/]repo[/path…]` in the character set OCI references
/// allow, with no `@digest` and no `:tag` on the last segment.
fn looks_like_repository(reference: &str) -> bool {
    if reference.is_empty()
        || reference.contains('@')
        || !reference.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-' | '/' | ':')
        })
    {
        return false;
    }
    let mut segments = reference.split('/');
    let first = segments.next().unwrap_or("");
    let rest: Vec<&str> = segments.collect();
    // A colon is only legal in the first segment as a registry port, and
    // never in the last segment (that would be a tag).
    let colon_ok = |seg: &str| match seg.split_once(':') {
        None => true,
        Some((_, port)) => !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()),
    };
    if rest.is_empty() {
        return !first.contains(':') && !first.is_empty();
    }
    colon_ok(first) && rest.iter().all(|s| !s.is_empty() && !s.contains(':'))
}

fn container_config(
    id: u32,
    listing: &Listing,
    content: &SpawnContent,
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
        image: format!("{}@{}", content.image.reference, content.image.digest),
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repositories_with_ports_and_paths_pass_and_tags_and_digests_do_not() {
        assert!(looks_like_repository("docker.io/library/alpine"));
        assert!(looks_like_repository("localhost:5000/team/app"));
        assert!(looks_like_repository("lscr.io/linuxserver/openssh-server"));
        assert!(looks_like_repository("alpine"));
        assert!(!looks_like_repository("alpine:3.20"), "a tag is mutable");
        assert!(!looks_like_repository("docker.io/library/alpine:latest"));
        assert!(!looks_like_repository("alpine@sha256:abc"));
        assert!(!looks_like_repository("Docker.io/Alpine"));
        assert!(!looks_like_repository(""));
        assert!(!looks_like_repository("a//b"));
    }

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
