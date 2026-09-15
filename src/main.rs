//! The provider binary: one config file in, a lease-serving HTTP app out —
//! or, with `routes`, the connector route table that config implies.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use toon_provider::{load_config, render_routes, ProviderService};

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
    /// and one extend row per listing version at the listing price, plus the
    /// free availability, status and terminate rows.
    Routes,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = load_config(&cli.config).with_context(|| format!("config: {}", cli.config))?;

    match cli.command {
        Some(Command::Routes) => {
            print!("{}", render_routes(&config));
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
