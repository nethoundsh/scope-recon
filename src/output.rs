use colored::Colorize;
use crate::model::ThreatReport;

const DIVIDER: &str = "══════════════════════════════════";
const MAX_PULSE_NAMES: usize = 5;

pub fn pretty_print(report: &ThreatReport) {
    println!("IP: {}", report.ip.bold());
    println!("{}", DIVIDER.dimmed());

    // --- GEOLOCATION ---
    println!();
    println!("{}", "GEOLOCATION  (ip-api.com)".bold().underline());
    match &report.ipapi {
        None => println!("  {}", "[source unavailable]".dimmed()),
        Some(g) => {
            println!("  {:14} {}", "Country:".dimmed(), opt_str(&g.country));
            println!("  {:14} {}", "Region:".dimmed(), opt_str(&g.region));
            println!("  {:14} {}", "City:".dimmed(), opt_str(&g.city));
            println!("  {:14} {}", "ISP:".dimmed(), opt_str(&g.isp));
            println!("  {:14} {}", "Org:".dimmed(), opt_str(&g.org));
            println!("  {:14} {}", "ASN:".dimmed(), opt_str(&g.asn));
        }
    }

    // --- SHODAN ---
    println!();
    println!("{}", "SHODAN".bold().underline());
    match &report.shodan {
        None => println!("  {}", "[source unavailable]".dimmed()),
        Some(s) => {
            println!("  {:14} {}", "Org:".dimmed(), opt_str(&s.org));
            println!("  {:14} {}", "ISP:".dimmed(), opt_str(&s.isp));
            println!("  {:14} {}", "Country:".dimmed(), opt_str(&s.country));
            println!("  {:14} {}", "Open Ports:".dimmed(), join_u16(&s.open_ports));
            println!("  {:14} {}", "Hostnames:".dimmed(), join_str(&s.hostnames));
            println!("  {:14} {}", "Tags:".dimmed(), join_str(&s.tags));
            println!("  {:14} {}", "Vulns:".dimmed(), join_str(&s.vulns));
        }
    }

    // --- ABUSEIPDB ---
    println!();
    println!("{}", "ABUSEIPDB".bold().underline());
    match &report.abuseipdb {
        None => println!("  {}", "[source unavailable]".dimmed()),
        Some(a) => {
            let score_str = format!("{}/100", a.abuse_confidence);
            let label = if a.abuse_confidence >= 75 {
                format!("{}  {}", score_str.red(), "[HIGH]".red().bold())
            } else if a.abuse_confidence >= 25 {
                format!("{}  {}", score_str.yellow(), "[MEDIUM]".yellow().bold())
            } else {
                format!("{}  {}", score_str.green(), "[LOW]".green().bold())
            };
            println!("  {:14} {}", "Abuse Score:".dimmed(), label);
            println!("  {:14} {}", "Reports:".dimmed(), a.total_reports);
            println!("  {:14} {}", "Country:".dimmed(), opt_str(&a.country));
            println!("  {:14} {}", "Domain:".dimmed(), opt_str(&a.domain));
            println!("  {:14} {}", "ISP:".dimmed(), opt_str(&a.isp));
            println!("  {:14} {}", "Tor Exit:".dimmed(), bool_str(a.is_tor));
            println!("  {:14} {}", "Whitelisted:".dimmed(), bool_str(a.is_whitelisted));
        }
    }

    // --- VIRUSTOTAL ---
    println!();
    println!("{}", "VIRUSTOTAL".bold().underline());
    match &report.virustotal {
        None => println!("  {}", "[source unavailable]".dimmed()),
        Some(v) => {
            let verdict = if v.malicious > 0 {
                format!(
                    "{} malicious / {} suspicious / {} harmless / {} undetected",
                    v.malicious.to_string().red().bold(),
                    v.suspicious,
                    v.harmless,
                    v.undetected
                )
            } else if v.suspicious > 0 {
                format!(
                    "{} malicious / {} suspicious / {} harmless / {} undetected",
                    v.malicious,
                    v.suspicious.to_string().yellow().bold(),
                    v.harmless,
                    v.undetected
                )
            } else {
                format!(
                    "{} malicious / {} suspicious / {} harmless / {} undetected",
                    v.malicious.to_string().green(),
                    v.suspicious,
                    v.harmless,
                    v.undetected
                )
            };
            println!("  {}", verdict);
        }
    }

    // --- ALIENVAULT OTX ---
    println!();
    println!("{}", "ALIENVAULT OTX".bold().underline());
    match &report.otx {
        None => println!("  {}", "[source unavailable]".dimmed()),
        Some(o) => {
            let pulse_label = if o.pulse_count == 0 {
                "0".green().to_string()
            } else {
                o.pulse_count.to_string().yellow().bold().to_string()
            };
            println!("  {:14} {}", "Pulses:".dimmed(), pulse_label);
            if !o.pulse_names.is_empty() {
                let shown: Vec<&String> = o.pulse_names.iter().take(MAX_PULSE_NAMES).collect();
                for name in &shown {
                    println!("               - {}", name);
                }
                let remaining = o.pulse_count as usize - shown.len();
                if remaining > 0 {
                    println!("               {} more...", format!("+ {}", remaining).dimmed());
                }
            }
        }
    }

    // --- GREYNOISE ---
    println!();
    println!("{}", "GREYNOISE".bold().underline());
    match &report.greynoise {
        None => println!("  {}", "[source unavailable]".dimmed()),
        Some(g) => {
            let class_colored = match g.classification.as_str() {
                "malicious" => g.classification.red().bold().to_string(),
                "benign" => g.classification.green().bold().to_string(),
                "not seen" => g.classification.dimmed().to_string(),
                _ => g.classification.yellow().to_string(),
            };
            println!("  {:14} {}", "Noise:".dimmed(), bool_str(g.noise));
            println!("  {:14} {}", "RIOT:".dimmed(), bool_str(g.riot));
            println!("  {:14} {}", "Class:".dimmed(), class_colored);
            println!("  {:14} {}", "Actor:".dimmed(), opt_str(&g.name));
            println!("  {:14} {}", "Last Seen:".dimmed(), opt_str(&g.last_seen));
        }
    }
}

pub fn json_print(report: &ThreatReport) {
    println!("{}", serde_json::to_string_pretty(report).unwrap());
}

fn opt_str(v: &Option<String>) -> String {
    v.as_deref().unwrap_or("-").to_string()
}

fn join_str(v: &[String]) -> String {
    if v.is_empty() { "-".to_string() } else { v.join(", ") }
}

fn join_u16(v: &[u16]) -> String {
    if v.is_empty() {
        "-".to_string()
    } else {
        v.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
    }
}

fn bool_str(b: bool) -> &'static str {
    if b { "Yes" } else { "No" }
}
