//! The capability strings a provider grants on a listing (`docker`,
//! `nesting`, …): matching them, and deciding which this build may publish.
//!
//! One place, because the provider grants a capability and the tenant checks
//! for it, and the two disagreeing is exactly the bug worth designing out: a
//! tenant that skips a provider it could have used is a wasted search, and one
//! that buys from a provider that cannot serve it is a wasted lease.
//!
//! Matching is trimmed and case-insensitive — these strings are hand-written
//! in provider config files — but never fuzzy. A near-miss like `nested` does
//! not grant `nesting`: a typo should cost the provider work, not hand out a
//! capability it did not mean to.
//!
//! Spec §4.4 gives `docker` and `nesting` a normative meaning, and says a
//! Listing MUST NOT carry a `t` tag for a capability it does not grant. This
//! backend supplies neither yet (see `grant_refusal`), so the one caller is
//! `ProviderConfig::validate`: the refusal lands at config load, on the
//! operator who wrote the line, rather than on the first tenant who buys the
//! tier and finds an empty `/var/run/docker.sock`.
#![allow(dead_code)]

/// A workload-scoped Docker-compatible daemon at `/var/run/docker.sock`
/// (spec §4.4).
pub const DOCKER: &str = "docker";

/// Permission for the workload to create isolation units of its own
/// (spec §4.4).
pub const NESTING: &str = "nesting";

/// What a provider prefixes a capability of its own with, until one is
/// specified (spec §4.4). Those are between that provider and its tenants,
/// so this crate neither defines nor blocks them.
pub const EXPERIMENTAL_PREFIX: &str = "x-";

/// Why this build may not publish a grant of `capability`, or `None` if it
/// may. The message is written to be read by an operator with a config file
/// open, so it names the value, what granting it would oblige, and the way out.
///
/// Both capabilities the spec defines are refused here, for the same reason:
/// granting either obliges the provider to give the workload something the
/// Docker backend does not build. `docker` needs a daemon of the lease's own
/// (a `dind` sidecar or equivalent), and `nesting` needs the workload to hold
/// kernel privileges this backend never hands out. Until one of them is built,
/// publishing the grant would be publishing a lie.
pub fn grant_refusal(capability: &str) -> Option<String> {
    let value = capability.trim();
    if value.is_empty() {
        return Some("a capability may not be an empty string".to_string());
    }
    if value.to_ascii_lowercase().starts_with(EXPERIMENTAL_PREFIX) {
        return None;
    }
    if value.eq_ignore_ascii_case(DOCKER) {
        return Some(format!(
            "{:?}: granting it obliges this provider to give the workload a Docker daemon of \
             its own at /var/run/docker.sock, scoped to the lease (spec §4.4). The Docker \
             backend runs no such per-lease daemon, and it MUST NOT hand a workload the host \
             daemon it creates workloads with — so this tier would publish a `t` tag it \
             cannot honour. Drop it until the backend supplies one.",
            capability
        ));
    }
    if value.eq_ignore_ascii_case(NESTING) {
        return Some(format!(
            "{:?}: granting it lets the workload create containers or VMs of its own, which \
             means handing tenant code kernel privileges (spec §4.4). The Docker backend runs \
             every workload unprivileged, with no device mappings, so this tier would publish \
             a `t` tag it cannot honour. Drop it.",
            capability
        ));
    }
    Some(format!(
        "{:?} is not a capability the label vocabulary defines (spec §4.4 lists {:?} and \
         {:?}). Prefix a capability of your own with {:?}.",
        capability, DOCKER, NESTING, EXPERIMENTAL_PREFIX
    ))
}

/// Whether `capabilities` advertises `wanted`.
pub fn advertises<S: AsRef<str>>(capabilities: &[S], wanted: &str) -> bool {
    let wanted = wanted.trim();
    capabilities
        .iter()
        .any(|c| c.as_ref().trim().eq_ignore_ascii_case(wanted))
}

/// Which of `wanted` the provider does not advertise, in the order asked for.
/// Empty means every requirement is met.
pub fn missing<S: AsRef<str>>(capabilities: &[S], wanted: &[String]) -> Vec<String> {
    wanted
        .iter()
        .map(|w| w.trim())
        .filter(|w| !w.is_empty())
        .filter(|w| !advertises(capabilities, w))
        .map(str::to_string)
        .collect()
}

/// Split a comma-separated capability list, as a config file or a request
/// carries one. Empty entries are dropped, so `""` is "no capabilities" rather
/// than one capability named "".
pub fn parse_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_is_trimmed_and_case_insensitive() {
        assert!(advertises(&["lxc", "Nesting"], "nesting"));
        assert!(advertises(&[" nesting "], "NESTING"));
        assert!(advertises(&["nesting"], " nesting"));
    }

    #[test]
    fn a_near_miss_does_not_match() {
        assert!(!advertises(&["nested", "nesting-vm"], "nesting"));
        assert!(!advertises::<&str>(&[], "nesting"));
    }

    #[test]
    fn missing_reports_only_what_is_absent() {
        let caps = ["lxc", "nesting"];
        assert!(missing(&caps, &["nesting".into()]).is_empty());
        assert_eq!(
            missing(&caps, &["nesting".into(), "ci-sandbox".into()]),
            vec!["ci-sandbox".to_string()]
        );
    }

    #[test]
    fn the_defined_capabilities_may_not_be_granted_by_this_backend() {
        // Spec §4.4: a Listing MUST NOT carry a `t` tag for a capability it
        // does not grant, and neither of these is built. The message has to
        // say what was refused and why, because it is the only thing the
        // operator sees.
        for value in [DOCKER, "Docker", " docker ", NESTING] {
            let why = grant_refusal(value).expect("neither is grantable yet");
            assert!(why.contains("§4.4"), "{}", why);
        }
        assert!(grant_refusal(DOCKER).unwrap().contains("docker.sock"));
        assert!(grant_refusal(NESTING).unwrap().contains("privileges"));
    }

    #[test]
    fn an_unknown_capability_is_refused_unless_it_is_an_experiment() {
        // A typo must cost the provider work rather than publish a grant no
        // tenant can read (§4.4), but a provider's own `x-` capability is
        // between it and its tenants.
        assert!(grant_refusal("nested").is_some());
        assert!(grant_refusal("").is_some());
        assert!(grant_refusal("x-ci-sandbox").is_none());
        assert!(grant_refusal("X-CI-SANDBOX").is_none());
    }

    #[test]
    fn blank_requirements_are_not_requirements() {
        assert!(missing(&["lxc"], &["".into(), "  ".into()]).is_empty());
        assert!(parse_list("").is_empty());
        assert_eq!(
            parse_list(" nesting , ci-sandbox ,"),
            vec!["nesting", "ci-sandbox"]
        );
    }
}
