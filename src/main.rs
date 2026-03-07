use anyhow::{Context, Result};
use clap::Parser;

mod api;
mod cli;
mod model;
mod output;

use api::{abuseipdb::fetch_abuseipdb, shodan::fetch_shodan};
use cli::Cli;
use model::ThreatReport;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let shodan_key = std::env::var("SHODAN_API_KEY")
        .context("SHODAN_API_KEY not set")?;
    let abuseipdb_key = std::env::var("ABUSEIPDB_API_KEY")
        .context("ABUSEIPDB_API_KEY not set")?;

    let (shodan_res, abuse_res) = tokio::join!(
        fetch_shodan(&cli.ip, &shodan_key),
        fetch_abuseipdb(&cli.ip, &abuseipdb_key),
    );

    let report = ThreatReport {
        ip: cli.ip.clone(),
        shodan: shodan_res.ok(),
        abuseipdb: abuse_res.ok(),
    };

    if cli.json {
        output::json_print(&report);
    } else {
        output::pretty_print(&report);
    }

    Ok(())
}
