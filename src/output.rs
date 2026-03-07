use colored::Colorize;
use crate::model::ThreatReport;

pub fn pretty_print(report: &ThreatReport) {
    println!("IP: {}", report.ip.bold());
    println!("{}", "══════════════════════════════════".dimmed());
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
