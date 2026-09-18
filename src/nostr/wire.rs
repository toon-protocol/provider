// The request and response shapes on the provider's HTTP surface, as the
// spec writes them (§5, §6). Everything here is plain serde: a Lease Request
// arrives as a JSON object inside `{ "request": ... }`, its `content` is one
// of the per-op JSON shapes below, and every answer is JSON.
//
// Deserialisation DENIES UNKNOWN FIELDS on purpose. A spawn may set only the
// image, env, ports, a volume, an SSH key and the entrypoint/args (ADR 0004):
// a runtime flag, a host mount, a device mapping or a capability is not a
// field this provider knows, and an unknown field is refused as
// `invalid_request` rather than silently dropped — dropping it would let a
// tenant believe a privilege was granted.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::continuation::ContinuationToken;

/// The body of every authenticated route (`.spawn`, `.standby`, `status`,
/// `terminate`): one Lease Request. Validating it is `nostr::lease_request`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRequestEnvelope {
    pub request: LeaseRequest,
}

/// What a Lease Request asks for, and which route may serve it (spec §6.1).
///
/// One value per route rather than one per shape: a Warm Standby's spawn
/// carries the same content a primary's does, and `standby` is what says
/// which of the two paid spawn routes the tenant meant this one for. A route
/// that finds another `op` refuses the request rather than guessing —
/// `nostr::lease_request` is where that happens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Op {
    Spawn,
    Standby,
    Status,
    Terminate,
}

impl Op {
    pub fn as_str(self) -> &'static str {
        match self {
            Op::Spawn => "spawn",
            Op::Standby => "standby",
            Op::Status => "status",
            Op::Terminate => "terminate",
        }
    }
}

/// A Lease Request (spec §6.1): a plain JSON object, signed by nobody.
///
/// Nothing here is hashed or canonically serialised, which is why
/// `request_id` is the tenant's own 32 random bytes rather than a digest of
/// the rest: two implementations cannot disagree about what was hashed if
/// nothing was. `provider` replaces the old `p` tag and is singular on every
/// op, a spawn forming a Standby Set included (§7).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRequest {
    /// 32 random bytes, hex, chosen by the tenant. The replay set's key.
    pub request_id: String,
    pub op: Op,
    /// The provider this request is for: its Nostr public key, hex. Exactly
    /// one; a provider refuses a request naming any other.
    pub provider: String,
    /// Unix seconds. Past it, or further ahead than the request window, the
    /// request is `stale_request`.
    pub expiration: u64,
    /// The lease's Continuation Token (§6.1, ADR 0016). On a spawn it is
    /// what the new lease stores; on every other op it is what the stored
    /// one is compared against.
    ///
    /// Optional in the SHAPE so that a request presenting no token is
    /// refused on its authority rather than on its spelling: `not_tenant` on
    /// `status` and `terminate`, `invalid_request` on a spawn, which would
    /// otherwise buy a lease nobody could act on (§6.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation: Option<ContinuationToken>,
    /// The op's own JSON object: `SpawnContent` or `WorkloadContent` below.
    pub content: serde_json::Value,
}

/// The resources one lease gets. Shared by the listing config, the Listing
/// event and the availability answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    pub cpu_millicores: u32,
    pub memory_mb: u32,
    pub storage_gb: u32,
    /// GPU model, when the tier includes one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<String>,
}

/// `"tcp"` or `"udp"`; nothing else is a port a workload can publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
}

/// One port the tenant asks to have published. The host port is the
/// provider's to choose and comes back in `Access::ports`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortRequest {
    pub container_port: u16,
    pub protocol: Protocol,
}

/// Exactly `len` lowercase hex characters: the one shape check a workload
/// id (64 of them) and a digest's hex (also 64) share, so there is one
/// answer to "is this hex?" rather than one per caller.
pub fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.chars()
            .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'))
}

/// The Image Registry entry a spawn or a Template points at: the NIP-01
/// coordinate `30434:<publisher pubkey>:<name>:<tag>` and a relay to look it
/// up on (spec §6.2, §8.3).
///
/// The relay is a HINT, not an authority: the entry is addressed by its
/// signer, so an entry fetched anywhere else is as good, and one served by
/// this relay under another signer is not the entry that was named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryEntryRef {
    pub address: String,
    pub relay: String,
}

/// The image a spawn (or an availability) names, in any of the three forms
/// spec §6.2 allows:
///
/// - `{ reference, digest }` — pull `reference@digest` from an upstream OCI
///   registry (Milestone 1's only form);
/// - `{ digest, registry_entry }` — the Image Registry entry lists the blobs
///   and where their bytes are (§8.1);
/// - `{ digest }` — the blobs are found by Blob Record lookup on the
///   provider's Relay Set (§8.4).
///
/// This struct is only the PARSE: which form was given, and whether it is
/// one of the three at all, is `image_events::SpawnImage`, which every
/// caller goes through. Both optional fields present, or neither plus a
/// malformed digest, is a fourth shape and `invalid_request`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageRef {
    /// An upstream OCI repository, e.g. `docker.io/library/alpine`. Absent
    /// for the two Image Registry forms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// `sha256:<64 hex>`, naming an OCI index or manifest. The one field
    /// every form carries.
    pub digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_entry: Option<RegistryEntryRef>,
}

impl ImageRef {
    /// `{ reference, digest }`: pulled from an upstream OCI registry.
    pub fn upstream(reference: impl Into<String>, digest: impl Into<String>) -> Self {
        Self {
            reference: Some(reference.into()),
            digest: digest.into(),
            registry_entry: None,
        }
    }

    /// `{ digest, registry_entry }`: resolved through the Image Registry.
    pub fn from_registry(
        digest: impl Into<String>,
        address: impl Into<String>,
        relay: impl Into<String>,
    ) -> Self {
        Self {
            reference: None,
            digest: digest.into(),
            registry_entry: Some(RegistryEntryRef {
                address: address.into(),
                relay: relay.into(),
            }),
        }
    }

    /// `{ digest }` alone: resolved by Blob Record lookup.
    pub fn by_digest(digest: impl Into<String>) -> Self {
        Self {
            reference: None,
            digest: digest.into(),
            registry_entry: None,
        }
    }
}

/// Content of a Lease Request with `op = spawn` (spec §6.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpawnContent {
    /// 32 random bytes, hex, chosen by the tenant.
    pub workload_id: String,
    pub image: ImageRef,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub ports: Vec<PortRequest>,
    /// Persistent volume, ≤ the listing's `storage_gb`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_gb: Option<u32>,
    /// The tenant's SSH public key. No password is ever issued.
    pub ssh_public_key: String,
    /// Overrides the image's entrypoint, OCI-style: element 0 is the
    /// executable, the rest are its leading arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    /// Parsed only so it can be refused: Standby Sets are not sold in
    /// Milestone 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standby_set: Option<Vec<String>>,
    /// Informational: the Template the values came from. Never read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
}

/// Content of a Lease Request with `op = status` or `op = terminate`: the
/// workload it is about, and nothing else. Authority is the request's
/// Continuation Token (spec §6.1), which is not part of the content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadContent {
    pub workload_id: String,
}

/// Body of `.extend`: no signature, any payer may extend any lease (ADR 0005).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtendRequest {
    pub workload_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Standalone,
    Primary,
    Standby,
}

/// One published port as the tenant reaches it: `host:host_port`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortAccess {
    pub container_port: u16,
    pub host_port: u16,
}

/// How a tenant reaches its workload. SSH with the tenant's key only; ports
/// as `host:host_port`; no hostnames, no TLS (spec §9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Access {
    pub host: String,
    pub ssh_port: u16,
    pub ports: Vec<PortAccess>,
}

/// The answer to a successful spawn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpawnResponse {
    pub workload_id: String,
    pub role: Role,
    pub expires_at: u64,
    /// Absent for a standby until Takeover.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<Access>,
}

/// Why a lease ended (spec §6.7). Serialised in snake_case: `"expiry"`,
/// `"termination"`, `"eviction"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseEnd {
    /// No payment bought another Lease Interval.
    Expiry,
    /// The tenant asked for it to end.
    Termination,
    /// The provider decided it should end.
    Eviction,
}

/// What a lease is doing (spec §6.7):
///
/// ```text
/// standalone:           Provisioning → Running → Ended(…)
/// primary:              Provisioning → Running ⇄ Stopped → Ended(…)
/// standby:              Reserved → (takeover) → Running → Ended(…)
///                       Reserved → Ended(…)
/// ```
///
/// On the wire and on disk this is serde's externally tagged form — the
/// encoding spec §6.7 fixes — which is what `status` and `terminate` answer
/// and what the lease table holds:
///
/// ```json
/// "provisioning" | "reserved" | "running" | "stopped"
///   | { "ended": "expiry" | "termination" | "eviction" }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    /// Accepted and paid; the workload is being started. Holds the workload
    /// id and counts against capacity already, so a racing spawn cannot take
    /// either.
    Provisioning,
    /// A Warm Standby before Takeover: the capacity is held and paid for,
    /// and NOTHING RUNS. It counts against capacity exactly as a running
    /// lease does — that is what the tenant bought — and `status` answers it
    /// with no `access`.
    Reserved,
    Running,
    /// A PRIMARY that stopped its own workload because it could not publish
    /// Liveness to a strict majority of its own Relay Set for five cadences
    /// (spec §7.1). A partitioned primary must not keep running beside the
    /// Takeover its standbys are about to announce.
    ///
    /// Nothing about the LEASE ended: it is paid to its `expires_at`, it
    /// still holds its capacity slot, its workload id and its host ports,
    /// `.extend` still buys it another interval, and the sweep still ends it
    /// when nobody does. Only the workload is off — the container is stopped
    /// rather than deleted, so regaining a majority with no Takeover in
    /// sight starts the same one again.
    Stopped,
    Ended(LeaseEnd),
}

impl LeaseState {
    /// Whether the lease still holds its workload id and its capacity slot.
    /// A reservation does: a standby is holding the capacity it was paid
    /// for, and nobody else may be sold it.
    pub fn is_live(self) -> bool {
        !matches!(self, LeaseState::Ended(_))
    }

    /// Whether a workload exists for this lease on the provider's backend:
    /// what an ending has to destroy. A `Reserved` standby has none until
    /// Takeover; an `Ended` lease's has been destroyed already.
    /// `Provisioning` counts, because the container may exist by the time
    /// the question is asked, and so does `Stopped`: a self-stopped primary
    /// stopped its container, it did not delete it, and a lease that ended
    /// without deleting it would leave it on the host forever.
    pub fn has_workload(self) -> bool {
        matches!(
            self,
            LeaseState::Provisioning | LeaseState::Running | LeaseState::Stopped
        )
    }

    /// Whether the tenant can reach the workload right now: what `status`
    /// answers `access` for, since a host and port that reach nothing would
    /// be a lie. Everything `has_workload` covers except `Stopped`, where
    /// the container exists and nothing in it is listening.
    pub fn is_reachable(self) -> bool {
        matches!(self, LeaseState::Provisioning | LeaseState::Running)
    }
}

/// What `status` says about a Takeover once one has settled on the lease's
/// workload (spec §6.5, §7.1 steps 3–5): who won.
///
/// One field, because one is what a tenant asking any member of the set
/// needs: the winner is the member that runs the workload now, so a
/// reservation that lost can still say WHERE the workload went. A standby
/// that won names itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TakeoverStatus {
    /// The member of the `standby_set` that won: 64 lowercase hex characters.
    pub winner: String,
}

/// The answer to a successful status (spec §6.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusResponse {
    pub workload_id: String,
    pub role: Role,
    pub state: LeaseState,
    pub expires_at: u64,
    /// Absent once the lease has ended: the workload is gone, and naming a
    /// host and port that no longer reach it would be a lie.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<Access>,
    /// The Template the spawn said its values came from, echoed back for
    /// tooling. Absent when the spawn named none. The provider never read it
    /// (spec §8.3, ADR 0004).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// Present once a Takeover on this workload has settled here (spec
    /// §7.1): a standby that won answers it beside `running`, one that lost
    /// beside `reserved`. Absent until then, and always for a lease that was
    /// never in a Standby Set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takeover: Option<TakeoverStatus>,
}

/// The answer to a successful termination (spec §6.6). The state is always
/// `{ "ended": "termination" }`; it is echoed so a tenant needs no second
/// call to see that its lease is over.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminateResponse {
    pub workload_id: String,
    pub state: LeaseState,
}

/// Body of the free `<addr>.availability` route (spec §6.4, ADR 0015): the
/// listing version and the same three-form `image` object a spawn carries,
/// so the same policy answers both. There is no `role` until Milestone 3
/// decides what a standby check is; it, like any other unknown field, is
/// refused as `invalid_request`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AvailabilityRequest {
    pub listing: String,
    pub version: u32,
    pub image: ImageRef,
    /// Which role the question is about (spec §6.4). Absent asks the
    /// ordinary question: would a spawn run here?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<AvailabilityRole>,
}

/// The role an `availability` question is about (spec §6.4): a primary —
/// which is what an ordinary spawn buys — or a Warm Standby.
///
/// Deliberately NOT `Role`: `standalone` is a lease role, not a question.
/// Every spawn with no Standby Set is standalone already, so asking about
/// it is asking the default, and §6.4 names only these two values. An
/// unknown value is `invalid_request` like any other shape this provider
/// does not know.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AvailabilityRole {
    Primary,
    Standby,
}

/// The answer to `availability`. Always HTTP 200: the answer IS the payload,
/// including a refusal (`provider_http::availability_route` never maps this
/// to a 4xx the way `refuse` does for paid/signed routes).
///
/// `Refused` is listed first: an untagged enum tries variants in order, and
/// `Refused` requires fields `Runnable` lacks, so a runnable answer only
/// ever matches `Runnable` while a refusal is never mistaken for one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AvailabilityResponse {
    Refused {
        would_run: bool,
        error: ErrorCode,
        message: String,
    },
    Runnable {
        would_run: bool,
    },
}

impl AvailabilityResponse {
    pub fn would_run() -> Self {
        Self::Runnable { would_run: true }
    }

    pub fn refused(error: ErrorCode, message: impl Into<String>) -> Self {
        Self::Refused {
            would_run: false,
            error,
            message: message.into(),
        }
    }
}

/// The answer to a successful extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtendResponse {
    pub workload_id: String,
    pub expires_at: u64,
}

/// Why a provider evicted a lease: spec §6.7's four reason codes, serialised
/// in snake_case and carried, as a plain string, in an Eviction Notice's
/// content. Broad enough to cover the cases §6.7 names (abuse, policy,
/// maintenance) plus a catch-all that requires the provider to explain itself
/// in `message`. A READER of notices must not refuse a code it does not know
/// (§6.7); this enum is only what this provider's operator may send.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvictionReason {
    /// The workload abused this provider or something reachable from it.
    Abuse,
    /// The workload violated a policy the provider states outside this
    /// protocol (e.g. an acceptable-use policy).
    Policy,
    /// The provider needs the capacity back, e.g. for host maintenance.
    Maintenance,
    /// Anything else; `message` should say what.
    Other,
}

/// Body of the loopback-only `POST /operator/evict`. No signature and no
/// payment: this is not a tenant route reached through the connector, it is
/// the operator of this box telling its own provider process to stop a
/// lease, so the only thing that authenticates it is being able to reach the
/// port at all (`ProviderConfig::operator_bind_addr` refuses to be anything
/// but loopback).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvictRequest {
    pub workload_id: String,
    pub reason: EvictionReason,
    /// Published verbatim in the Eviction Notice; empty when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// The answer to a successful eviction (spec §6.7). The lease is always
/// ended, even when the Eviction Notice could not be published to every
/// relay — `notice_published` says whether it was (the per-relay detail is
/// in the log, the way every other directory publication reports it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvictResponse {
    pub workload_id: String,
    pub state: LeaseState,
    pub notice_published: bool,
}

/// Every refusal code the spec names (§5). Serialised in snake_case, exactly
/// as the spec writes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    UnknownWorkload,
    WrongListingVersion,
    NotTenant,
    WorkloadIdTaken,
    RefusedImage,
    NoCapacity,
    NoMatchingArch,
    InvalidRequest,
    Expired,
    NotStandby,
    /// `.extend` on a Warm Standby reservation (spec §6.3): the mirror of
    /// `NotStandby`, which `.standby.extend` answers a running lease with.
    /// A lease is always billed at the price for what it is doing, and a
    /// reservation is not running — it is paid on `.standby.extend` instead.
    NotRunning,
    StaleRequest,
    /// A `status` asserted a gateway delegation that does not apply here
    /// (spec §6.5). Distinct from `NotTenant`, which is what a request
    /// asserting no delegation hears, so the two refusals stay tellable
    /// apart: one says *you are not the tenant*, the other *your delegation
    /// does not apply here*.
    ///
    /// No route answers it today: the published Gateway Grant went with kind
    /// `30438` (ADR 0016), and the derived sub-token that replaces it is
    /// TOON_Network#58's. The code stays in the taxonomy because §5 keeps
    /// it, and a tenant implementation must know it before it can meet it.
    BadGrant,
}

/// Every error answer, on free and paid routes alike. On a paid route it is
/// still billed (ADR 0003): there is nothing to refund, only this to say.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorResponse {
    pub error: ErrorCode,
    pub message: String,
}

impl ErrorResponse {
    pub fn new(error: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            error,
            message: message.into(),
        }
    }
}
