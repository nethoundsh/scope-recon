use std::io::{self, BufWriter, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use ipnet::IpNet;

mod api;
mod cache;
mod cli;
mod model;
mod output;
mod tui;

use api::{
    abuseipdb::fetch_abuseipdb,
    bgpview::fetch_bgpview,
    greynoise::fetch_greynoise,
    internetdb::fetch_internetdb,
    ipapi::fetch_ipapi,
    ipinfo::fetch_ipinfo,
    ipqs::fetch_ipqs,
    openrouter::fetch_openrouter,
    otx::fetch_otx,
    pulsedive::fetch_pulsedive,
    retry::with_retry,
    shodan::fetch_shodan,
    threatfox::fetch_threatfox,
    virustotal::fetch_virustotal,
};
use cli::Cli;
use model::ThreatReport;

const RETRY_DELAY: Duration = Duration::from_secs(2);
const MAX_CIDR_HOSTS: usize = 256;
// Courtesy delay between IPs in bulk mode to avoid hammering APIs
const BULK_DELAY: Duration = Duration::from_millis(500);

struct ApiKeys {
    shodan: Option<String>,
    abuseipdb: Option<String>,
    virustotal: Option<String>,
    otx: Option<String>,
    greynoise: Option<String>,
    ipqs: Option<String>,
    pulsedive: Option<String>,
    ipinfo: Option<String>,
    threatfox: Option<String>,
    openrouter: Option<String>,
}

impl ApiKeys {
    fn from_env() -> Self {
        Self {
            shodan: std::env::var("SHODAN_API_KEY").ok(),
            abuseipdb: std::env::var("ABUSEIPDB_API_KEY").ok(),
            virustotal: std::env::var("VIRUSTOTAL_API_KEY").ok(),
            otx: std::env::var("OTX_API_KEY").ok(),
            greynoise: std::env::var("GREYNOISE_API_KEY").ok(),
            ipqs: std::env::var("IPQS_API_KEY").ok(),
            pulsedive: std::env::var("PULSEDIVE_API_KEY").ok(),
            ipinfo: std::env::var("IPINFO_TOKEN").ok(),
            threatfox: std::env::var("THREATFOX_API_KEY").ok(),
            openrouter: std::env::var("OPENROUTER_API_KEY").ok(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.no_color || cli.output.is_some() {
        colored::control::set_override(false);
    }

    let targets = resolve_targets(&cli)?;
    let keys = ApiKeys::from_env();

    // TUI mode: single IP, no --json/--output/--file flags
    let use_tui = cli.target.is_some()
        && !cli.json
        && cli.output.is_none()
        && cli.file.is_none()
        && targets.len() == 1;

    if use_tui {
        return tui::run_tui(&targets[0], &keys, &cli).await;
    }

    let mut writer: Box<dyn Write> = match &cli.output {
        Some(path) => Box::new(BufWriter::new(
            std::fs::File::create(path)
                .with_context(|| format!("Cannot create output file '{}'", path.display()))?,
        )),
        None => Box::new(io::stdout()),
    };

    let mut all_reports: Vec<(ThreatReport, Vec<(String, String)>)> = Vec::new();

    for (i, target) in targets.iter().enumerate() {
        if i > 0 {
            tokio::time::sleep(BULK_DELAY).await;
        }

        // Cache check
        if cli.cache_ttl > 0 {
            if let Some(cached) = cache::load(target, cli.cache_ttl) {
                if cli.verbose {
                    eprintln!("[cache hit] {} — queried at {}", target, cached.queried_at);
                }
                all_reports.push((cached, vec![]));
                continue;
            }
        }

        let (report, errors) = query_ip(target, &keys, &cli).await;

        if cli.cache_ttl > 0 {
            if let Err(e) = cache::save(&report) {
                if cli.verbose {
                    eprintln!("[cache] Failed to save {}: {}", target, e);
                }
            }
        }

        all_reports.push((report, errors));
    }

    // Output
    if cli.json && all_reports.len() > 1 {
        let reports: Vec<&ThreatReport> = all_reports.iter().map(|(r, _)| r).collect();
        writeln!(writer, "{}", serde_json::to_string_pretty(&reports)?)?;
    } else {
        for (i, (report, errors)) in all_reports.iter().enumerate() {
            if i > 0 && !cli.json {
                writeln!(writer, "\n{}", "━".repeat(50))?;
            }
            if cli.json {
                output::json_print(report, &mut *writer)?;
            } else {
                output::pretty_print(report, errors, cli.verbose, &mut *writer);
            }
        }
    }

    writer.flush()?;
    Ok(())
}

async fn query_ip(ip: &str, keys: &ApiKeys, cli: &Cli) -> (ThreatReport, Vec<(String, String)>) {
    let only = &cli.only;

    let (ipapi_res, shodan_res, abuse_res, vt_res, otx_res, gn_res, tf_res, bgp_res, ipqs_res, pd_res, ii_res) = tokio::join!(
        async {
            if !should_run(only, "ipapi") {
                return Err(anyhow::anyhow!("__skipped__"));
            }
            with_retry("ip-api", RETRY_DELAY, || fetch_ipapi(ip)).await
        },
        async {
            if !should_run(only, "shodan") {
                return Err(anyhow::anyhow!("__skipped__"));
            }
            match keys.shodan.as_deref() {
                Some(k) => with_retry("Shodan", RETRY_DELAY, || fetch_shodan(ip, k)).await,
                None => {
                    // Free fallback — no key required
                    with_retry("Shodan InternetDB", RETRY_DELAY, || fetch_internetdb(ip)).await
                }
            }
        },
        async {
            if !should_run(only, "abuseipdb") {
                return Err(anyhow::anyhow!("__skipped__"));
            }
            match keys.abuseipdb.as_deref() {
                Some(k) => with_retry("AbuseIPDB", RETRY_DELAY, || fetch_abuseipdb(ip, k)).await,
                None => Err(anyhow::anyhow!("ABUSEIPDB_API_KEY not set")),
            }
        },
        async {
            if !should_run(only, "virustotal") {
                return Err(anyhow::anyhow!("__skipped__"));
            }
            match keys.virustotal.as_deref() {
                Some(k) => {
                    with_retry("VirusTotal", RETRY_DELAY, || fetch_virustotal(ip, k)).await
                }
                None => Err(anyhow::anyhow!("VIRUSTOTAL_API_KEY not set")),
            }
        },
        async {
            if !should_run(only, "otx") {
                return Err(anyhow::anyhow!("__skipped__"));
            }
            match keys.otx.as_deref() {
                Some(k) => with_retry("OTX", RETRY_DELAY, || fetch_otx(ip, k)).await,
                None => Err(anyhow::anyhow!("OTX_API_KEY not set")),
            }
        },
        async {
            if !should_run(only, "greynoise") {
                return Err(anyhow::anyhow!("__skipped__"));
            }
            with_retry("GreyNoise", RETRY_DELAY, || {
                fetch_greynoise(ip, keys.greynoise.as_deref())
            })
            .await
        },
        async {
            if !should_run(only, "threatfox") {
                return Err(anyhow::anyhow!("__skipped__"));
            }
            match keys.threatfox.as_deref() {
                Some(k) => with_retry("ThreatFox", RETRY_DELAY, || fetch_threatfox(ip, k)).await,
                None => Err(anyhow::anyhow!("THREATFOX_API_KEY not set")),
            }
        },
        async {
            if !should_run(only, "bgpview") {
                return Err(anyhow::anyhow!("__skipped__"));
            }
            with_retry("BGPView", RETRY_DELAY, || fetch_bgpview(ip)).await
        },
        async {
            if !should_run(only, "ipqs") {
                return Err(anyhow::anyhow!("__skipped__"));
            }
            match keys.ipqs.as_deref() {
                Some(k) => with_retry("IPQualityScore", RETRY_DELAY, || fetch_ipqs(ip, k)).await,
                None => Err(anyhow::anyhow!("IPQS_API_KEY not set")),
            }
        },
        async {
            if !should_run(only, "pulsedive") {
                return Err(anyhow::anyhow!("__skipped__"));
            }
            match keys.pulsedive.as_deref() {
                Some(k) => with_retry("Pulsedive", RETRY_DELAY, || fetch_pulsedive(ip, k)).await,
                None => Err(anyhow::anyhow!("PULSEDIVE_API_KEY not set")),
            }
        },
        async {
            if !should_run(only, "ipinfo") {
                return Err(anyhow::anyhow!("__skipped__"));
            }
            with_retry("IPInfo", RETRY_DELAY, || {
                fetch_ipinfo(ip, keys.ipinfo.as_deref())
            })
            .await
        },
    );

    let mut errors: Vec<(String, String)> = Vec::new();

    let queried_at = chrono::Utc::now().to_rfc3339();

    // Build partial report from the 11 sources first
    let partial = ThreatReport {
        queried_at,
        ip: ip.to_string(),
        ipapi: collect("ip-api", ipapi_res, &mut errors),
        shodan: collect("Shodan", shodan_res, &mut errors),
        abuseipdb: collect("AbuseIPDB", abuse_res, &mut errors),
        virustotal: collect("VirusTotal", vt_res, &mut errors),
        otx: collect("OTX", otx_res, &mut errors),
        greynoise: collect("GreyNoise", gn_res, &mut errors),
        threatfox: collect("ThreatFox", tf_res, &mut errors),
        bgpview: collect("BGPView", bgp_res, &mut errors),
        ipqs: collect("IPQualityScore", ipqs_res, &mut errors),
        pulsedive: collect("Pulsedive", pd_res, &mut errors),
        ipinfo: collect("IPInfo", ii_res, &mut errors),
        ai_analysis: None,
    };

    // Sequential AI call — naturally waits since join! already finished
    let ai_res = if should_run(only, "openrouter") {
        match keys.openrouter.as_deref() {
            Some(k) => fetch_openrouter(&partial, k).await,
            None => Err(anyhow::anyhow!("OPENROUTER_API_KEY not set")),
        }
    } else {
        Err(anyhow::anyhow!("__skipped__"))
    };

    let report = ThreatReport {
        ai_analysis: collect("AI Analysis", ai_res, &mut errors),
        ..partial
    };

    (report, errors)
}

fn collect<T>(
    name: &str,
    result: anyhow::Result<T>,
    errors: &mut Vec<(String, String)>,
) -> Option<T> {
    match result {
        Ok(v) => Some(v),
        Err(e) => {
            let msg = e.to_string();
            if msg != "__skipped__" {
                errors.push((name.to_string(), msg));
            }
            None
        }
    }
}

fn should_run(only: &[String], source: &str) -> bool {
    only.is_empty() || only.iter().any(|s| s.eq_ignore_ascii_case(source))
}

fn resolve_targets(cli: &Cli) -> Result<Vec<String>> {
    if let Some(path) = &cli.file {
        read_ips_from_file(path)
    } else if let Some(target) = &cli.target {
        expand_target(target)
    } else {
        anyhow::bail!("provide an IP address/CIDR or --file <FILE>")
    }
}

fn expand_target(target: &str) -> Result<Vec<String>> {
    if let Ok(ip) = IpAddr::from_str(target) {
        return Ok(vec![ip.to_string()]);
    }
    if let Ok(net) = IpNet::from_str(target) {
        let hosts: Vec<String> = net
            .hosts()
            .take(MAX_CIDR_HOSTS + 1)
            .map(|ip| ip.to_string())
            .collect();
        if hosts.is_empty() {
            anyhow::bail!("CIDR '{}' contains no host addresses", target);
        }
        if hosts.len() > MAX_CIDR_HOSTS {
            anyhow::bail!(
                "CIDR '{}' exceeds the {} host limit. Use a smaller range.",
                target,
                MAX_CIDR_HOSTS
            );
        }
        return Ok(hosts);
    }
    anyhow::bail!("'{}' is not a valid IP address or CIDR range", target)
}

fn read_ips_from_file(path: &PathBuf) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Cannot read file '{}'", path.display()))?;

    let mut ips: Vec<String> = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let expanded = expand_target(line)
            .with_context(|| format!("Invalid target '{}' in '{}'", line, path.display()))?;
        ips.extend(expanded);
    }

    if ips.is_empty() {
        anyhow::bail!("No targets found in '{}'", path.display());
    }
    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_single_ipv4() {
        let result = expand_target("8.8.8.8").unwrap();
        assert_eq!(result, vec!["8.8.8.8"]);
    }

    #[test]
    fn expand_single_ipv6() {
        let result = expand_target("2001:4860:4860::8888").unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn expand_cidr_slash30() {
        let result = expand_target("192.168.1.0/30").unwrap();
        assert_eq!(result, vec!["192.168.1.1", "192.168.1.2"]);
    }

    #[test]
    fn expand_cidr_too_large() {
        assert!(expand_target("10.0.0.0/8").is_err());
    }

    #[test]
    fn expand_invalid_rejects() {
        assert!(expand_target("not-an-ip").is_err());
        assert!(expand_target("999.999.999.999").is_err());
        assert!(expand_target("google.com").is_err());
    }

    #[test]
    fn should_run_empty_only_allows_all() {
        assert!(should_run(&[], "shodan"));
        assert!(should_run(&[], "virustotal"));
    }

    #[test]
    fn should_run_filters_correctly() {
        let only = vec!["shodan".to_string(), "virustotal".to_string()];
        assert!(should_run(&only, "shodan"));
        assert!(should_run(&only, "SHODAN")); // case-insensitive
        assert!(!should_run(&only, "abuseipdb"));
    }
}
