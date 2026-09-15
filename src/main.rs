//! The provider binary: one config file in, a lease-serving HTTP app out.

use anyhow::{Context, Result};
use clap::Parser;
use toon_provider::{load_config, ProviderService};

#[derive(Parser)]
#[command(name = "toon-provider", version, about = "Sell leases on workloads over the TOON Network", long_about = None)]
struct Cli {
    /// Path to the provider's TOML config file.
    #[arg(short, long, default_value = "provider.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let config = load_config(&cli.config).with_context(|| format!("config: {}", cli.config))?;

    ProviderService::new(config)?.run().await
}
