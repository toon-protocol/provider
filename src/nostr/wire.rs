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

/// The image a spawn names.
///
/// Milestone 1: `reference` is an upstream OCI repository (e.g.
/// `docker.io/library/alpine`) and the workload is pulled by
/// `reference@digest`, so the backend verifies the digest and picks the
/// manifest for the host's architecture. The Image Registry replaces
/// `reference` in a later milestone; `registry_entry` is parsed so that it
/// can be refused by name rather than as an unknown field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageRef {
    pub reference: String,
    /// `sha256:<64 hex>`, naming an OCI index or manifest.
    pub digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_entry: Option<serde_json::Value>,
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
