//! The provider binary: one config file in, a lease-serving HTTP app out —
//! or, with `routes`, the connector route table that config implies.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use toon_provider::nostr::wire::{EvictRequest, EvictionReason};
use toon_provider::{load_config, persisted_leases, render_routes, ProviderService};

#[derive(Parser)]
#[command(name = "toon-provider", version, about = "Sell leases on workloads over the TOON Network", long_about = None)]
struct Cli {
    /// Path to the provider's TOML config file.
    #[arg(short, long, global = true, default_value = "provider.toml")]
    config: String,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Print the connector `[[routes]]` rows this provider expects: one spawn
    /// and one extend row per LIVE listing version at that version's price,
    /// plus the free availability, status and terminate rows.
    ///
    /// A retired listing version keeps its rows until its last lease ends
    /// (ADR 0009), so this reads the persisted lease table at
    /// `lease_state_path` — read-only — to decide which retired versions are
    /// still live. Run it against a running provider's state file: the rows
    /// it stops printing are the rows to delete from the connector config.
    Routes,

    /// Evict a lease right now and publish a signed Eviction Notice.
    ///
    /// This talks to the RUNNING provider process's loopback-only operator
    /// endpoint (`operator_url` in the config, `POST /operator/evict`) rather
    /// than touching the lease state file — the running process holds the
    /// lease table and the compute backend, and only it can stop a workload
    /// and set the lease's state consistently. The provider named by
    /// `--config` must already be running.
    Evict {
        /// The tenant-chosen workload id (hex) to evict.
        #[arg(long = "workload-id")]
        workload_id: String,
        /// Why the lease is being evicted; published in the Eviction Notice.
        #[arg(long, value_enum)]
        reason: ReasonArg,
        /// A human-readable explanation, published in the Eviction Notice.
        #[arg(long)]
        message: Option<String>,
    },
}

/// `EvictionReason` as a `clap` value: `toon_provider::nostr::wire` stays
/// free of a CLI dependency, so the CLI's own copy converts into it.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum ReasonArg {
    Abuse,
    Policy,
    Maintenance,
    Other,
}

impl From<ReasonArg> for EvictionReason {
    fn from(reason: ReasonArg) -> Self {
        match reason {
            ReasonArg::Abuse => EvictionReason::Abuse,
            ReasonArg::Policy => EvictionReason::Policy,
            ReasonArg::Maintenance => EvictionReason::Maintenance,
            ReasonArg::Other => EvictionReason::Other,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = load_config(&cli.config).with_context(|| format!("config: {}", cli.config))?;

    match cli.command {
        Some(Command::Routes) => {
            // A retired listing version keeps its rows only while a lease is
            // live on it, so reading the WRONG lease table silently drops the
            // routes those leases extend on. `lease_state_path` is usually
            // relative to the provider's working directory, and this command
            // is run from wherever the operator happens to be — so say so
            // rather than print a table that looks fine and is not. On
            // stderr, so the rows on stdout still pipe into a config file.
            let path = std::path::Path::new(&config.lease_state_path);
            if !path.exists() {
                eprintln!(
                    "warning: no lease table at {} — the rows below assume this provider has \
                     no running lease, so any retired listing version is left out. Run this \
                     from the provider's working directory, or make lease_state_path absolute.",
                    config.lease_state_path
                );
            }
            let leases = persisted_leases(&config.lease_state_path);
            print!("{}", render_routes(&config, &leases));
            Ok(())
        }
        Some(Command::Evict {
            workload_id,
            reason,
            message,
        }) => {
            let request = EvictRequest {
                workload_id,
                reason: reason.into(),
                message,
            };
            let url = format!(
                "{}/operator/evict",
                config.operator_url.trim_end_matches('/')
            );
            let response = reqwest::Client::new()
                .post(&url)
                .json(&request)
                .send()
                .await
                .with_context(|| {
                    format!(
                        "reaching the operator endpoint at {} — is the provider running?",
                        url
                    )
                })?;
            let status = response.status();
            let body: serde_json::Value = response
                .json()
                .await
                .context("reading the operator endpoint's answer")?;
            println!("{}", serde_json::to_string_pretty(&body)?);
            if !status.is_success() {
                anyhow::bail!("eviction refused: {}", status);
            }
            Ok(())
        }
        None => {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
                )
                .init();
            ProviderService::new(config)?.run().await
        }
    }
}
