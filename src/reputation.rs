// Pure scoring math over signed completion receipts. A receipt only counts when
// it is co-signed by tenant and provider, bound to a verifiable payment, and
// survives the Sybil weighting: the tenant needs enough history, and any one
// tenant-provider pair is capped at 20% of that tenant's receipt volume.
//
// Kept for Milestone 3, unwired. Nothing in the app calls any of this: no
// receipt kind is allocated and nothing publishes one. Paygress bound each
// receipt to a Cashu spend proof; that is replaced here by a reference to a
// TOON payment-channel claim, which an aggregator can verify against the
// channel contract without trusting a mint.
#![allow(dead_code)]

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Reference to the payment-channel claim that paid for a lease, pasted into
/// the receipt the provider co-signs. An aggregator checks it against the
/// channel contract on `chain`, so nothing here has to be trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelClaim {
    /// Settlement chain the channel is anchored on, e.g. `solana` or `evm`.
    pub chain: String,
    pub channel_id: String,
    /// Cumulative claimed amount, in integer µUSDC.
    pub cumulative_amount: u64,
    /// The payer's signature over the balance proof.
    pub signature: String,
}

/// Co-signed completion receipt. Both parties sign the canonicalized JSON of
/// `(lease_id, provider_npub, tenant_npub, duration_paid, duration_delivered,
/// success_flag, channel_claim, version)`; missing either signature means the
/// receipt does not score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompletionReceipt {
    pub lease_id: String,
    pub provider_npub: String,
    pub tenant_npub: String,
    pub duration_paid: u64,
    /// Provider-reported, cross-checkable against published Liveness.
    pub duration_delivered: u64,
    /// 1.0 = success, 0.0 = failure. A float so partial credit (delivered but
    /// with SLA violations) stays expressible.
    pub success_flag: f32,
    pub channel_claim: ChannelClaim,
    pub version: u8,
    /// Schnorr signature over the canonical content by the tenant's Nostr key.
    pub tenant_signature: Option<String>,
    pub provider_co_signature: Option<String>,
    /// Provider-stamped unix time; aggregators window by it.
    pub completed_at: u64,
}

/// Anti-Sybil knobs, operator-tunable via the observatory config.
#[derive(Debug, Clone, Copy)]
pub struct SybilHeuristics {
    /// Receipts from tenants younger than this don't count.
    pub min_tenant_history_secs: u64,
    /// Share of one tenant's receipts that may point at a single provider
    /// before the excess is weighted down.
    pub max_same_counterparty_share: f32,
}

impl Default for SybilHeuristics {
    fn default() -> Self {
        Self {
            // 30 days, so a brand-new tenant can't single-handedly
            // score a brand-new provider.
            min_tenant_history_secs: 30 * 24 * 3600,
            max_same_counterparty_share: 0.20,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TenantProfile {
    pub npub: String,
    /// Unix timestamp of the tenant's earliest known Nostr activity.
    pub first_seen: u64,
}

/// Cheap structural checks. `false` means the receipt must not contribute to
/// score; signature verification is a separate, caller-supplied step.
fn receipt_well_formed(r: &CompletionReceipt) -> bool {
    r.tenant_signature.is_some()
        && r.provider_co_signature.is_some()
        && r.success_flag >= 0.0
        && r.success_flag <= 1.0
        && r.version > 0
}

/// Sum of weighted success flags from the receipts that survive, in order:
/// well-formedness, `verify_signatures`, `verify_channel_claim`, the
/// tenant-history floor, and the per-tenant Sybil cap.
///
/// The two verifiers are closures so tests can stub them; production wires them
/// to nostr-sdk Schnorr verification and the channel contract on the claim's chain.
pub fn score_provider<S, P>(
    provider_npub: &str,
    receipts: &[CompletionReceipt],
    tenants: &HashMap<String, TenantProfile>,
    now: u64,
    heuristics: &SybilHeuristics,
    verify_signatures: S,
    verify_channel_claim: P,
) -> f32
where
    S: Fn(&CompletionReceipt) -> bool,
    P: Fn(&CompletionReceipt) -> bool,
{
    // Pre-count each tenant's receipts so the Sybil cap has a
    // denominator. Cheap predicates only — the crypto checks run in
    // the second pass, over just the receipts we might count.
    let mut per_tenant_total: HashMap<&str, u32> = HashMap::new();
    let mut per_tenant_for_provider: HashMap<&str, u32> = HashMap::new();
    for r in receipts {
        if !receipt_well_formed(r) {
            continue;
        }
        let cons = r.tenant_npub.as_str();
        *per_tenant_total.entry(cons).or_insert(0) += 1;
        if r.provider_npub == provider_npub {
            *per_tenant_for_provider.entry(cons).or_insert(0) += 1;
        }
    }

    let mut weighted_sum = 0.0f32;
    for r in receipts {
        if r.provider_npub != provider_npub {
            continue;
        }
        if !receipt_well_formed(r) {
            continue;
        }
        if !verify_signatures(r) {
            continue;
        }
        if !verify_channel_claim(r) {
            continue;
        }

        let Some(profile) = tenants.get(&r.tenant_npub) else {
            continue;
        };
        let tenant_age = now.saturating_sub(profile.first_seen);
        if tenant_age < heuristics.min_tenant_history_secs {
            continue;
        }

        // Sybil cap: scale the weight down so this tenant's total
        // contribution to this provider equals max_share.
        let total = *per_tenant_total.get(r.tenant_npub.as_str()).unwrap_or(&0);
        let same = *per_tenant_for_provider
            .get(r.tenant_npub.as_str())
            .unwrap_or(&0);
        if total == 0 {
            continue;
        }
        let share = same as f32 / total as f32;
        let weight = if share > heuristics.max_same_counterparty_share {
            heuristics.max_same_counterparty_share / share
        } else {
            1.0
        };

        weighted_sum += r.success_flag * weight;
    }

    weighted_sum
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim() -> ChannelClaim {
        ChannelClaim {
            chain: "solana".to_string(),
            channel_id: "chan-1".to_string(),
            cumulative_amount: 5_000,
            signature: "deadbeef".to_string(),
        }
    }

    pub(super) fn signed_receipt(
        lease_id: &str,
        provider: &str,
        tenant: &str,
        success: f32,
    ) -> CompletionReceipt {
        CompletionReceipt {
            lease_id: lease_id.to_string(),
            provider_npub: provider.to_string(),
            tenant_npub: tenant.to_string(),
            duration_paid: 3600,
            duration_delivered: 3600,
            success_flag: success,
            channel_claim: claim(),
            version: 1,
            tenant_signature: Some("c-sig".to_string()),
            provider_co_signature: Some("p-sig".to_string()),
            completed_at: 1_700_000_000,
        }
    }

    fn tenant(npub: &str, first_seen: u64) -> TenantProfile {
        TenantProfile {
            npub: npub.to_string(),
            first_seen,
        }
    }

    fn always_valid(_r: &CompletionReceipt) -> bool {
        true
    }

    #[test]
    fn single_tenant_with_single_provider_is_capped_to_share() {
        let receipts = vec![signed_receipt("l1", "P", "C", 1.0)];
        let mut tenants = HashMap::new();
        tenants.insert("C".to_string(), tenant("C", 1_700_000_000 - 60 * 24 * 3600));
        let score = score_provider(
            "P",
            &receipts,
            &tenants,
            1_700_000_000,
            &SybilHeuristics::default(),
            always_valid,
            always_valid,
        );
        assert!((score - 0.20).abs() < 1e-6, "score = {}", score);
    }

    #[test]
    fn diversified_tenants_each_contributing_one_receipt_sum() {
        // Five tenants × one receipt each, capped to 0.20 → 1.0.
        let mut receipts = Vec::new();
        let mut tenants = HashMap::new();
        for i in 0..5 {
            let c = format!("C{}", i);
            receipts.push(signed_receipt(&format!("l{}", i), "P", &c, 1.0));
            tenants.insert(c.clone(), tenant(&c, 1_700_000_000 - 60 * 24 * 3600));
        }
        let score = score_provider(
            "P",
            &receipts,
            &tenants,
            1_700_000_000,
            &SybilHeuristics::default(),
            always_valid,
            always_valid,
        );
        assert!((score - 1.0).abs() < 1e-4, "score = {}", score);
    }

    #[test]
    fn missing_provider_co_signature_drops_receipt() {
        let mut r = signed_receipt("l1", "P", "C", 1.0);
        r.provider_co_signature = None;
        let mut tenants = HashMap::new();
        tenants.insert("C".to_string(), tenant("C", 1_700_000_000 - 60 * 24 * 3600));
        let score = score_provider(
            "P",
            &[r],
            &tenants,
            1_700_000_000,
            &SybilHeuristics::default(),
            always_valid,
            always_valid,
        );
        assert_eq!(score, 0.0);
    }

    #[test]
    fn signature_verification_failure_drops_receipt() {
        let receipts = vec![signed_receipt("l1", "P", "C", 1.0)];
        let mut tenants = HashMap::new();
        tenants.insert("C".to_string(), tenant("C", 1_700_000_000 - 60 * 24 * 3600));
        let score = score_provider(
            "P",
            &receipts,
            &tenants,
            1_700_000_000,
            &SybilHeuristics::default(),
            |_| false, // verify_signatures rejects everything
            always_valid,
        );
        assert_eq!(score, 0.0);
    }

    #[test]
    fn channel_claim_failure_drops_receipt() {
        let receipts = vec![signed_receipt("l1", "P", "C", 1.0)];
        let mut tenants = HashMap::new();
        tenants.insert("C".to_string(), tenant("C", 1_700_000_000 - 60 * 24 * 3600));
        let score = score_provider(
            "P",
            &receipts,
            &tenants,
            1_700_000_000,
            &SybilHeuristics::default(),
            always_valid,
            |_| false, // verify_channel_claim rejects everything
        );
        assert_eq!(score, 0.0);
    }

    #[test]
    fn fresh_tenant_under_min_history_does_not_count() {
        let receipts = vec![signed_receipt("l1", "P", "Cnew", 1.0)];
        let mut tenants = HashMap::new();
        // Only 1 day of history < default 30-day floor.
        tenants.insert("Cnew".to_string(), tenant("Cnew", 1_700_000_000 - 86400));
        let score = score_provider(
            "P",
            &receipts,
            &tenants,
            1_700_000_000,
            &SybilHeuristics::default(),
            always_valid,
            always_valid,
        );
        assert_eq!(score, 0.0);
    }

    #[test]
    fn same_counterparty_cap_caps_contribution() {
        // 9 of the tenant's 10 receipts point at P, so the 20% cap
        // limits P's credit to 2.0 rather than 9.0.
        let mut receipts = Vec::new();
        for i in 0..9 {
            receipts.push(signed_receipt(&format!("lp{}", i), "P", "C", 1.0));
        }
        receipts.push(signed_receipt("lq", "Q", "C", 1.0));
        let mut tenants = HashMap::new();
        tenants.insert("C".to_string(), tenant("C", 1_700_000_000 - 60 * 24 * 3600));

        let score = score_provider(
            "P",
            &receipts,
            &tenants,
            1_700_000_000,
            &SybilHeuristics::default(),
            always_valid,
            always_valid,
        );

        let expected = 9.0 * (0.20 / 0.90);
        assert!(
            (score - expected).abs() < 1e-4,
            "score should be capped near {} (got {})",
            expected,
            score
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// A single tenant firing N of M receipts at one provider
        /// can never push that provider's score past
        /// `max_share * M`.
        #[test]
        fn single_tenant_cannot_exceed_share_cap(
            same_count in 1u32..200,
            other_count in 0u32..200,
        ) {
            let tenant_npub = "C".to_string();
            let mut receipts = Vec::new();
            for i in 0..same_count {
                receipts.push(super::tests::signed_receipt(
                    &format!("p{}", i),
                    "P",
                    &tenant_npub,
                    1.0,
                ));
            }
            for i in 0..other_count {
                receipts.push(super::tests::signed_receipt(
                    &format!("q{}", i),
                    "Q",
                    &tenant_npub,
                    1.0,
                ));
            }
            let mut tenants = HashMap::new();
            tenants.insert(
                tenant_npub.clone(),
                TenantProfile {
                    npub: tenant_npub.clone(),
                    first_seen: 1_700_000_000 - 60 * 24 * 3600,
                },
            );
            let h = SybilHeuristics::default();
            let score = score_provider(
                "P",
                &receipts,
                &tenants,
                1_700_000_000,
                &h,
                |_| true,
                |_| true,
            );
            let total = (same_count + other_count) as f32;
            let cap = h.max_same_counterparty_share * total;
            prop_assert!(
                score <= cap + 1e-3,
                "score {} exceeds Sybil cap {}",
                score,
                cap
            );
        }
    }
}
