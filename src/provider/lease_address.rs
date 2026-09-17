// A lease's own `.anyone` address: the one place the lease lifecycle talks
// to the `HiddenService` port (spec §10, ADR 0008).
//
// A Hidden Provider publishes no host, so `access.host` cannot be an IP:
// every lease gets an address of its own, mapping its SSH forward and each
// port it published, created before its workload starts and destroyed when
// the lease ends. Everything a route or a loop needs of that is here —
// create one, destroy one, re-establish them all after a restart — so that
// `spawn`, `settle` and `cleanup` each carry one call rather than a copy of
// the rule.
//
// Every function is a NO-OP on a provider that is not hidden. That is the
// gate, and it is `config.hidden` rather than "is a `HiddenService`
// installed": a test installs a fake on every provider so it can assert
// that a public one never touched it.

use std::sync::Arc;

use tracing::{error, info, warn};

use super::persistence::persist_leases;
use crate::hidden_service::{AddressPort, HiddenAddress, HiddenService};
use crate::nostr::wire::{ErrorCode, ErrorResponse, PortAccess};
use crate::provider_http::AppState;

/// The daemon a hidden lease's address is made on, or `None` on a provider
/// that is not hidden — which asks nothing of the port, ever.
fn daemon(state: &AppState) -> Option<&Arc<dyn HiddenService>> {
    state
        .hidden_service
        .as_ref()
        .filter(|_| state.config.hidden)
}

/// The ports a lease's address must answer on: its SSH forward and every
/// port it published, each on the SAME number it has on the host — a tenant
/// dials what its access details told it, and those are the host's numbers
/// (spec §6.2, §10).
fn ports_of(ssh_port: u16, ports: &[PortAccess]) -> Vec<AddressPort> {
    std::iter::once(AddressPort::same(ssh_port))
        .chain(ports.iter().map(|port| AddressPort::same(port.host_port)))
        .collect()
}

/// A Hidden Provider that cannot reach its `anon` daemon can start no lease:
/// the address IS how a tenant reaches the workload, and there is nothing
/// to fall back on — an IP is exactly what this provider promised never to
/// publish. `no_capacity`, because the request is fine and it is this
/// provider that cannot serve it; `availability` answers the same for free
/// first, so nobody pays to find out (spec §9, §10).
pub(super) fn refuse_without_a_daemon(state: &AppState) -> Result<(), ErrorResponse> {
    if !state.config.hidden || state.hidden_service.is_some() {
        return Ok(());
    }
    Err(no_daemon())
}

/// The refusal itself, so the free answer and the paid one are the same
/// words. Deliberately not logged: `availability` is free and unsigned, and
/// a line per call would be a log anyone could fill. The message says what
/// is wrong, and it reaches the operator's own `availability` too.
fn no_daemon() -> ErrorResponse {
    ErrorResponse::new(
        ErrorCode::NoCapacity,
        "this Hidden Provider cannot reach its anon daemon, so it can give this lease no \
         .anyone address",
    )
}

/// Create the `.anyone` address `workload_id`'s lease is reached at, mapping
/// its SSH forward and every port it published (spec §10). `None` on a
/// provider that is not hidden: its leases are reached at its `public_ip`,
/// and nothing here is asked.
///
/// An error is a lease that must not start. A workload behind an address the
/// daemon would not make is one no tenant could ever reach, and this
/// provider has no second way to offer it.
pub(super) async fn create(
    state: &AppState,
    workload_id: &str,
    ssh_port: u16,
    ports: &[PortAccess],
) -> Result<Option<HiddenAddress>, ErrorResponse> {
    if !state.config.hidden {
        return Ok(None);
    }
    // The same refusal `spawn` and `availability` already answered before a
    // slot was taken (`refuse_without_a_daemon`); reached here only by a
    // Takeover's start, which passes through no route.
    let Some(daemon) = daemon(state) else {
        return Err(no_daemon());
    };
    let ports = ports_of(ssh_port, ports);
    match daemon.create_address(workload_id, &ports).await {
        Ok(address) => {
            info!(
                "workload {} is reachable at {} ({} port(s))",
                workload_id,
                address.host,
                ports.len()
            );
            Ok(Some(address))
        }
        Err(e) => {
            error!(
                "no .anyone address could be made for workload {}: {:#}",
                workload_id, e
            );
            Err(ErrorResponse::new(
                ErrorCode::NoCapacity,
                format!("this lease could not be given a .anyone address: {}", e),
            ))
        }
    }
}

/// Destroy the address of a workload whose lease holds no record of one yet:
/// the spawn that made an address and then could not start its workload, and
/// the Takeover start that did the same. Nothing else will ever ask for it,
/// so an address left here would outlive every lease.
pub(super) async fn destroy_unrecorded(state: &AppState, workload_id: &str) {
    let Some(daemon) = daemon(state) else {
        return;
    };
    if let Err(e) = daemon.destroy_address(workload_id).await {
        warn!(
            "the .anyone address of workload {} could not be destroyed ({:#}); it will \
             outlive its lease, and the daemon drops it on its next restart",
            workload_id, e
        );
    }
}

/// Destroy the address lease `id` holds ON ITS RECORD, as part of its
/// ending — the pair of `destroy_unrecorded` above.
///
/// `true` when there is nothing left to destroy — a lease that never had an
/// address, or one the daemon has now confirmed gone. The record's address
/// is CLEARED on success, so a later sweep asks for nothing; `false` leaves
/// it in place, the lease is not recorded destroyed, and the next sweep
/// tries again — exactly what a container that would not stop gets
/// (`cleanup::destroy_workload`, spec §6.7).
pub(super) async fn destroy_recorded(state: &AppState, id: u32) -> bool {
    let workload_id = {
        let leases = state.leases.lock().await;
        match leases.get(&id) {
            Some(lease) if lease.hidden_address.is_some() => lease.workload_id.clone(),
            // No address, or no lease at all: nothing to destroy either way.
            _ => return true,
        }
    };
    let Some(daemon) = daemon(state) else {
        // A provider that stopped being hidden between the lease and its
        // ending has no daemon to ask, and holding the lease undestroyed
        // forever would be worse than forgetting one address. The record
        // stops claiming an address this provider can no longer account for.
        forget_address(state, id).await;
        return true;
    };
    if let Err(e) = daemon.destroy_address(&workload_id).await {
        error!(
            "failed to destroy the .anyone address of workload {} ({:#}); retrying on the \
             next sweep",
            workload_id, e
        );
        return false;
    }

    info!("the .anyone address of workload {} is gone", workload_id);
    forget_address(state, id).await;
    true
}

/// Take the address off lease `id`'s record: it no longer has one, and
/// nothing should ask the daemon about it again.
async fn forget_address(state: &AppState, id: u32) {
    let mut leases = state.leases.lock().await;
    if let Some(lease) = leases.get_mut(&id) {
        lease.hidden_address = None;
        persist_leases(&leases, &state.config.lease_state_path);
    }
}

/// Re-establish every live lease's address after a restart of the provider
/// (spec §10; `ProviderService::restore_leases` calls this once the table is
/// back).
///
/// An address made over the daemon's control port lives only as long as the
/// daemon, and a provider restart is usually its restart too. A lease that
/// kept its KEY is given the SAME address back, so its tenant reaches it
/// where the spawn said it would; one with no key stored is given a fresh
/// address, and `status` answers that one from then on — it is all the
/// tenant can be told, and a lease nobody can reach at all would be worse.
///
/// A failure takes the address OFF the record and is logged with what an
/// operator can do about it. `status` then answers the lease with no
/// `access` at all, which is the truth — there is nowhere to reach — rather
/// than naming a host nothing answers on, which a tenant would keep dialling.
/// The commonest cause is a provider that restarted while its daemon did
/// not: the daemon is still serving the key and refuses to add it twice, and
/// restarting the daemon is the fix.
pub(super) async fn restore_all(state: &AppState) {
    let Some(daemon) = daemon(state) else {
        return;
    };
    // Decided under the lock, asked outside it: the daemon takes its time
    // and the HTTP app is already serving.
    let live: Vec<Reachable> = {
        let leases = state.leases.lock().await;
        leases
            .values()
            .filter(|lease| lease.state.is_live() && lease.hidden_address.is_some())
            .map(|lease| Reachable {
                id: lease.id,
                workload_id: lease.workload_id.clone(),
                key: lease
                    .hidden_address
                    .as_ref()
                    .and_then(|address| address.key.clone()),
                ports: ports_of(lease.ssh_port, &lease.ports),
            })
            .collect()
    };
    if live.is_empty() {
        return;
    }

    let mut restored = 0usize;
    let mut fresh = 0usize;
    let mut lost = 0usize;
    for lease in live {
        let address = match &lease.key {
            Some(key) => daemon
                .restore_address(&lease.workload_id, key, &lease.ports)
                .await
                .map(|host| HiddenAddress {
                    host,
                    key: Some(key.clone()),
                }),
            // Nothing to restore it from, so the lease gets a NEW address
            // rather than none: the tenant reads it from `status`.
            None => {
                daemon
                    .create_address(&lease.workload_id, &lease.ports)
                    .await
            }
        };
        match address {
            Ok(address) => {
                if lease.key.is_some() {
                    restored += 1;
                } else {
                    fresh += 1;
                    warn!(
                        "lease {} kept no key for its address, so workload {} is reachable at a \
                         NEW one, {}; its tenant reads it from status",
                        lease.id, lease.workload_id, address.host
                    );
                }
                let mut leases = state.leases.lock().await;
                if let Some(record) = leases.get_mut(&lease.id) {
                    record.hidden_address = Some(address);
                    persist_leases(&leases, &state.config.lease_state_path);
                }
            }
            Err(e) => {
                error!(
                    "lease {}: the .anyone address of workload {} could not be \
                     re-established ({:#}); its status now answers no access at all. If the \
                     daemon outlived this provider it is still serving that address and \
                     refusing to add it twice — restart the daemon, and this provider will \
                     give the lease a fresh address.",
                    lease.id, lease.workload_id, e
                );
                forget_address(state, lease.id).await;
                lost += 1;
            }
        }
    }
    info!(
        "re-established {} .anyone address(es) from the lease table ({} given a fresh one, {} \
         lease(s) left with none)",
        restored + fresh,
        fresh,
        lost
    );
}

/// One live lease whose address has to be re-established: everything the
/// daemon needs, read off the record under the lock so nothing is held
/// while the daemon is asked.
struct Reachable {
    id: u32,
    workload_id: String,
    /// The key its address is derived from, when one was stored. `None`
    /// means a fresh address.
    key: Option<String>,
    ports: Vec<AddressPort>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_addresss_ports_are_the_ssh_forward_then_every_published_port() {
        let ports = ports_of(
            40000,
            &[
                PortAccess {
                    container_port: 443,
                    host_port: 41000,
                },
                PortAccess {
                    container_port: 80,
                    host_port: 41001,
                },
            ],
        );
        assert_eq!(
            ports,
            vec![
                AddressPort::same(40000),
                AddressPort::same(41000),
                AddressPort::same(41001)
            ],
            "the same number on both sides: a tenant dials what access told it"
        );
        assert_eq!(ports_of(40000, &[]), vec![AddressPort::same(40000)]);
    }
}
