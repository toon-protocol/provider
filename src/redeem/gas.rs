//! What a redeem costs in gas, per chain: an ESTIMATE, shown beside each
//! channel so an operator can tell a redeem worth making from one that
//! costs more than it collects. The connector exposes no estimate of its
//! own, so this derives a conservative one, and says "unknown" rather than
//! guess when it cannot. It never blocks a redeem.
//!
//! Which chain a channel is on comes from its id's shape, the rule the
//! connector itself uses (`client_edge_channel_key` in
//! `connector-operator`): an EVM id is `0x`-optional 64 hex characters, a
//! Solana one is base58 decoding to exactly 32 bytes.
//!
//! - **EVM** (`TokenNetwork.claimFromChannel`): [`EVM_REDEEM_GAS`] gas ×
//!   the chain's current `eth_gasPrice`, read from the settlement EVM RPC.
//!   On an L2 such as Base, the L1 data fee comes on top and is not
//!   included.
//! - **Solana** (`[Ed25519SigVerify, ClaimFromChannel]` in one
//!   transaction): [`SOLANA_REDEEM_LAMPORTS`], the base fee for that
//!   transaction's signatures. The connector sets no priority fee, so there
//!   is nothing else to read.
//!
//! Gas is paid by the connector's settlement key on that chain, in the
//! chain's native coin — not out of the channel.

use std::fmt;
use std::time::Duration;

use serde_json::Value;

use crate::outbound_proxy::{is_private_url, SettlementRpcRoute};

/// Gas for one `claimFromChannel`, rounded up: the connector's own
/// `forge test --gas-report` for `TokenNetwork` (tag 2026.09.11.1) puts the
/// call at 127,255 gas at most, plus 21,000 intrinsic and its calldata.
pub const EVM_REDEEM_GAS: u64 = 160_000;

/// Lamports for one Solana redeem: 5,000 per signature, and the
/// transaction carries two — the fee payer's and the one the Ed25519
/// precompile instruction verifies, which Solana also charges for.
pub const SOLANA_REDEEM_LAMPORTS: u64 = 10_000;

/// Which chain a channel settles on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Chain {
    Evm,
    Solana,
    Unknown,
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Chain::Evm => "evm",
            Chain::Solana => "solana",
            Chain::Unknown => "?",
        })
    }
}

/// The chain `channel_id` is on, from its shape alone.
pub fn chain_of(channel_id: &str) -> Chain {
    let bare = channel_id
        .strip_prefix("evm:")
        .or_else(|| channel_id.strip_prefix("solana:"))
        .unwrap_or(channel_id);
    let hex = bare.strip_prefix("0x").unwrap_or(bare);
    if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Chain::Evm;
    }
    if base58_len(bare) == Some(32) {
        return Chain::Solana;
    }
    Chain::Unknown
}

/// How many bytes `text` decodes to as base58 (Bitcoin alphabet), or
/// `None` if it is not base58.
fn base58_len(text: &str) -> Option<usize> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if text.is_empty() {
        return None;
    }
    let mut bytes: Vec<u8> = Vec::new(); // little-endian
    for c in text.bytes() {
        let mut carry = ALPHABET.iter().position(|&a| a == c)? as u32;
        for b in bytes.iter_mut() {
            carry += u32::from(*b) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let leading_ones = text.bytes().take_while(|&c| c == b'1').count();
    Some(bytes.len() + leading_ones)
}

/// One chain's estimate for one redeem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Estimate {
    Evm { gas: u64, wei_per_gas: u128 },
    Solana { lamports: u64 },
    Unknown(String),
}

impl Estimate {
    /// The short form for a table cell.
    pub fn short(&self) -> String {
        match self {
            Estimate::Evm { gas, wei_per_gas } => format!(
                "~{} ETH",
                format_units(u128::from(*gas).saturating_mul(*wei_per_gas), 18)
            ),
            Estimate::Solana { lamports } => {
                format!("~{} SOL", format_units(u128::from(*lamports), 9))
            }
            Estimate::Unknown(_) => "unknown".to_string(),
        }
    }

    /// How it was arrived at, for the line under the table.
    pub fn basis(&self) -> String {
        match self {
            Estimate::Evm { gas, wei_per_gas } => format!(
                "{gas} gas x {} gwei (eth_gasPrice); an L2's L1 data fee is extra",
                format_units(*wei_per_gas, 9)
            ),
            Estimate::Solana { lamports } => format!(
                "{lamports} lamports: 2 signatures (fee payer, Ed25519 precompile) at 5000, no \
                 priority fee"
            ),
            Estimate::Unknown(why) => why.clone(),
        }
    }
}

/// `amount` base units at `decimals` places, trailing zeros dropped.
pub fn format_units(amount: u128, decimals: u32) -> String {
    let scale = 10u128.pow(decimals);
    let whole = amount / scale;
    let fraction = amount % scale;
    if fraction == 0 {
        return whole.to_string();
    }
    let fraction = format!("{fraction:0width$}", width = decimals as usize);
    format!("{whole}.{}", fraction.trim_end_matches('0'))
}

/// The estimate for `chain`. EVM asks `evm_rpc` for its gas price — by the
/// route it names, and never a public RPC dialled directly from a hidden
/// box; Solana needs no RPC.
pub async fn estimate(
    chain: Chain,
    evm_rpc: Option<&SettlementRpcRoute>,
    hidden: bool,
) -> Estimate {
    match chain {
        Chain::Solana => Estimate::Solana {
            lamports: SOLANA_REDEEM_LAMPORTS,
        },
        Chain::Unknown => {
            Estimate::Unknown("the channel id is neither an EVM nor a Solana id".into())
        }
        Chain::Evm => match evm_rpc.filter(|r| !r.url.trim().is_empty()) {
            None => Estimate::Unknown(
                "no EVM RPC to ask for a gas price: set TOON_SETTLEMENT_EVM_RPC_URL or \
                 --evm-rpc-url"
                    .into(),
            ),
            Some(route) if hidden && route.via.is_none() && !is_private_url(&route.url) => {
                Estimate::Unknown(format!(
                    "not asked: the EVM RPC is not on this box's private network, and a hidden \
                     provider dials nothing else directly ({})",
                    crate::status::origin(&route.url).unwrap_or_default()
                ))
            }
            Some(route) => match gas_price(route).await {
                Ok(wei_per_gas) => Estimate::Evm {
                    gas: EVM_REDEEM_GAS,
                    wei_per_gas,
                },
                Err(e) => Estimate::Unknown(e),
            },
        },
    }
}

/// `eth_gasPrice` at `route`'s RPC, by the route it names, in wei.
async fn gas_price(route: &SettlementRpcRoute) -> Result<u128, String> {
    let url = route.url.trim();
    let shown = crate::status::origin(url).unwrap_or_else(|| "the EVM RPC".into());
    let timeout = route.timeout(Duration::from_secs(10));
    let client = route.client(timeout).map_err(|e| format!("{e:#}"))?;
    let answer: Value = client
        .post(url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "eth_gasPrice", "params": [],
        }))
        .send()
        .await
        .map_err(|e| {
            format!(
                "eth_gasPrice at {shown} failed: {}",
                crate::status::error_chain(&e)
            )
        })?
        .json()
        .await
        .map_err(|e| format!("eth_gasPrice at {shown} did not answer JSON: {e}"))?;
    let hex = answer
        .get("result")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("eth_gasPrice at {shown} answered no result"))?;
    u128::from_str_radix(hex.trim_start_matches("0x"), 16)
        .map_err(|_| format!("eth_gasPrice at {shown} answered {hex:?}, not a hex quantity"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_channel_ids_shape_names_its_chain() {
        let evm = format!("0x{}", "ab".repeat(32));
        assert_eq!(chain_of(&evm), Chain::Evm);
        assert_eq!(chain_of(&evm[2..]), Chain::Evm);
        assert_eq!(chain_of(&format!("evm:{evm}")), Chain::Evm);
        assert_eq!(
            chain_of("2aEVJ8koKD8LTZrLRSGtAtU7LBt4e7QjjCgf1kzQ7Rip"),
            Chain::Solana
        );
        assert_eq!(
            chain_of("solana:9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"),
            Chain::Solana
        );
        // The system program: 32 zero bytes, all leading ones.
        assert_eq!(chain_of(&"1".repeat(32)), Chain::Solana);
        assert_eq!(chain_of("0xabc"), Chain::Unknown);
        assert_eq!(chain_of("not-an-id"), Chain::Unknown);
        assert_eq!(chain_of("2aEVJ8koKD8LTZ"), Chain::Unknown);
    }

    #[test]
    fn units_format_without_trailing_zeros() {
        assert_eq!(format_units(10_000, 9), "0.00001");
        assert_eq!(format_units(1_000_000_000, 9), "1");
        assert_eq!(format_units(160_000 * 30_000_000, 18), "0.0000048");
        assert_eq!(format_units(0, 18), "0");
    }

    #[tokio::test]
    async fn solana_needs_no_rpc_and_evm_without_one_is_unknown() {
        assert_eq!(
            estimate(Chain::Solana, None, false).await,
            Estimate::Solana { lamports: 10_000 }
        );
        assert!(matches!(
            estimate(Chain::Evm, None, false).await,
            Estimate::Unknown(_)
        ));
        let public = SettlementRpcRoute::direct("https://base-sepolia.example");
        let hidden = estimate(Chain::Evm, Some(&public), true).await;
        assert!(
            matches!(&hidden, Estimate::Unknown(why) if why.contains("not asked")),
            "{hidden:?}"
        );
    }
}
