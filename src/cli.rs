use clap::Parser;

#[derive(Parser)]
#[command(name = "scope-recon", about = "IP threat summary from Shodan + AbuseIPDB")]
pub struct Cli {
    /// IP address to investigate
    pub ip: String,

    /// Output as JSON instead of pretty-printed table
    #[arg(long)]
    pub json: bool,
}
