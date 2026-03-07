use std::path::PathBuf;
use clap::Parser;

#[derive(Parser, Clone)]
#[command(
    name = "scope-recon",
    about = "IP threat summary from Shodan, VirusTotal, AbuseIPDB, OTX, GreyNoise, and ThreatFox"
)]
pub struct Cli {
    /// IP address or CIDR range to investigate (e.g. 1.2.3.4 or 1.2.3.0/24)
    #[arg(conflicts_with = "file")]
    pub target: Option<String>,

    /// File containing IPs/CIDRs to investigate, one per line (# for comments)
    #[arg(long, conflicts_with = "target", value_name = "FILE")]
    pub file: Option<PathBuf>,

    /// Output as JSON instead of pretty-printed table
    #[arg(long)]
    pub json: bool,

    /// Show why each source failed instead of silently showing [source unavailable]
    #[arg(long)]
    pub verbose: bool,

    /// Disable color output (auto-enabled when writing to --output file)
    #[arg(long)]
    pub no_color: bool,

    /// Only query specific sources (comma-separated)
    /// Valid values: ipapi, shodan, abuseipdb, virustotal, otx, greynoise, threatfox
    #[arg(long, value_delimiter = ',', value_name = "SOURCES")]
    pub only: Vec<String>,

    /// Write output to file instead of stdout
    #[arg(long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Cache TTL in seconds; 0 disables caching (default: 3600)
    #[arg(long, default_value = "3600", value_name = "SECONDS")]
    pub cache_ttl: u64,
}
