// The request and response shapes on the provider's HTTP surface, as the
// spec writes them (§5, §6). Everything here is plain serde: a Lease Request
// arrives as a signed Nostr event inside `{ "request": ... }`, its content is
// one of the per-op JSON shapes below, and every answer is JSON.
//
// Deserialisation DENIES UNKNOWN FIELDS on purpose. A spawn may set only the
// image, env, ports, a volume, an SSH key and the entrypoint/args (ADR 0004):
// a runtime flag, a host mount, a device mapping or a capability is not a
// field this provider knows, and an unknown field is refused as
// `invalid_request` rather than silently dropped — dropping it would let a
// tenant believe a privilege was granted.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The body of every signed route (`.spawn`, `status`, `terminate`): one
/// Lease Request event. Validation of the event is `nostr::lease_request`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRequestEnvelope {
    pub request: nostr_sdk::Event,
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

/// Content of a Lease Request with `op = status` or `op = terminate`.
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

/// `Provisioning → Running → Ended(…)` for a standalone or primary lease
/// (spec §6.7). A standby's `Reserved` state is a later milestone.
///
/// On the wire and on disk this is serde's externally tagged form, which is
/// what `status` answers and what the lease table holds:
///
/// ```json
/// "provisioning" | "running" | { "ended": "expiry" | "termination" | "eviction" }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    /// Accepted and paid; the workload is being started. Holds the workload
    /// id and counts against capacity already, so a racing spawn cannot take
    /// either.
    Provisioning,
    Running,
    Ended(LeaseEnd),
}

impl LeaseState {
    /// Whether the lease still holds its workload id and its capacity slot.
    pub fn is_live(self) -> bool {
        !matches!(self, LeaseState::Ended(_))
    }
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

/// Body of the free `<addr>.availability` route (spec §6.4; ticket M1-5 uses
/// this shape rather than the spec draft's `image_digest`, so a mis-shaped
/// spec-style body is refused as `invalid_request` like any other unknown
/// field).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AvailabilityRequest {
    pub listing: String,
    pub version: u32,
    pub image: ImageRef,
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

/// Why a provider evicted a lease (spec §6.7: "a reason code"). Serialised in
/// snake_case and carried, as a plain string, in an Eviction Notice's content.
///
/// The spec names no fixed vocabulary beyond "a reason code", so these four
/// are this provider's own choice, documented in the README: broad enough to
/// cover the cases spec §6.7 gives as examples (abuse, policy, maintenance)
/// plus a catch-all that pushes the provider to explain itself in `message`.
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
    BadSignature,
    StaleRequest,
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
