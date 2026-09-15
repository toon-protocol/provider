//! Matching for the free-form capability strings a provider grants on a listing
//! (`nesting`, `docker`, `vm`, …).
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
//! Nothing calls this yet: the listing that grants capabilities and the spawn
//! that asks for them both land in a later ticket. It is kept, rather than
//! deleted and rewritten, because the grant-and-check pair is the whole point.
#![allow(dead_code)]

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
    fn blank_requirements_are_not_requirements() {
        assert!(missing(&["lxc"], &["".into(), "  ".into()]).is_empty());
        assert!(parse_list("").is_empty());
        assert_eq!(
            parse_list(" nesting , ci-sandbox ,"),
            vec!["nesting", "ci-sandbox"]
        );
    }
}
