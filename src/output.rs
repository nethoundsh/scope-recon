use colored::Colorize;
use crate::model::ThreatReport;

const DIVIDER: &str = "══════════════════════════════════";
const MAX_PULSE_NAMES: usize = 5;
const MAX_IOC_DISPLAY: usize = 3;

pub fn pretty_print(report: &ThreatReport) {
    println!("IP: {}", report.ip.bold());
    println!("{}", DIVIDER.dimmed());
    print_summary(report);
    println!("{}", DIVIDER.dimmed());

    // --- GEOLOCATION ---
    println!();
    println!("{}", "GEOLOCATION  (ip-api.com)".bold().underline());
    match &report.ipapi {
        None => println!("  {}", "[source unavailable]".dimmed()),
        Some(g) => {
            println!("  {:16} {}", "Country:".dimmed(), opt_str(&g.country));
            println!("  {:16} {}", "Region:".dimmed(), opt_str(&g.region));
            println!("  {:16} {}", "City:".dimmed(), opt_str(&g.city));
            println!("  {:16} {}", "ISP:".dimmed(), opt_str(&g.isp));
            println!("  {:16} {}", "Org:".dimmed(), opt_str(&g.org));
            println!("  {:16} {}", "ASN:".dimmed(), opt_str(&g.asn));
        }
    }

    // --- SHODAN ---
    println!();
    println!("{}", "SHODAN".bold().underline());
    match &report.shodan {
        None => println!("  {}", "[source unavailable]".dimmed()),
        Some(s) => {
            println!("  {:16} {}", "Org:".dimmed(), opt_str(&s.org));
            println!("  {:16} {}", "ISP:".dimmed(), opt_str(&s.isp));
            println!("  {:16} {}", "Country:".dimmed(), opt_str(&s.country));
            println!("  {:16} {}", "Hostnames:".dimmed(), join_str(&s.hostnames));
            println!("  {:16} {}", "Tags:".dimmed(), join_str(&s.tags));
            println!("  {:16} {}", "Vulns:".dimmed(), join_str(&s.vulns));
            if s.services.is_empty() {
                println!("  {:16} {}", "Services:".dimmed(), "-");
            } else {
                println!("  {}", "Services:".dimmed());
                for svc in &s.services {
                    let proto = svc.transport.as_deref().unwrap_or("tcp");
                    let label = match (&svc.product, &svc.version) {
                        (Some(p), Some(v)) => format!("{} {}", p, v),
                        (Some(p), None) => p.clone(),
                        _ => "-".to_string(),
                    };
                    println!("    {}/{:<8} {}", svc.port, proto, label);
                }
            }
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
            println!("  {:16} {}", "Abuse Score:".dimmed(), label);
            println!("  {:16} {}", "Reports:".dimmed(), a.total_reports);
            println!("  {:16} {}", "Last Reported:".dimmed(), opt_str(&a.last_reported_at));
            println!("  {:16} {}", "Usage Type:".dimmed(), opt_str(&a.usage_type));
            println!("  {:16} {}", "Country:".dimmed(), opt_str(&a.country));
            println!("  {:16} {}", "Domain:".dimmed(), opt_str(&a.domain));
            println!("  {:16} {}", "ISP:".dimmed(), opt_str(&a.isp));
            println!("  {:16} {}", "Tor Exit:".dimmed(), bool_str(a.is_tor));
            println!("  {:16} {}", "Whitelisted:".dimmed(), bool_str(a.is_whitelisted));
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
            if let Some(date) = &v.last_analysis_date {
                println!("  {:16} {}", "Last Scanned:".dimmed(), date);
            }
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
            println!("  {:16} {}", "Pulses:".dimmed(), pulse_label);
            if !o.pulse_names.is_empty() {
                let shown: Vec<&String> = o.pulse_names.iter().take(MAX_PULSE_NAMES).collect();
                for name in &shown {
                    println!("                 - {}", name);
                }
                let remaining = o.pulse_count as usize - shown.len();
                if remaining > 0 {
                    println!("                 {}", format!("+ {} more...", remaining).dimmed());
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
            println!("  {:16} {}", "Noise:".dimmed(), bool_str(g.noise));
            println!("  {:16} {}", "RIOT:".dimmed(), bool_str(g.riot));
            println!("  {:16} {}", "Class:".dimmed(), class_colored);
            println!("  {:16} {}", "Actor:".dimmed(), opt_str(&g.name));
            println!("  {:16} {}", "Last Seen:".dimmed(), opt_str(&g.last_seen));
        }
    }

    // --- THREATFOX ---
    println!();
    println!("{}", "THREATFOX  (abuse.ch)".bold().underline());
    match &report.threatfox {
        None => println!("  {}", "[source unavailable]".dimmed()),
        Some(tf) => {
            let count_label = if tf.ioc_count == 0 {
                "0".green().to_string()
            } else {
                tf.ioc_count.to_string().red().bold().to_string()
            };
            println!("  {:16} {}", "C2 IOCs:".dimmed(), count_label);
            for ioc in tf.iocs.iter().take(MAX_IOC_DISPLAY) {
                println!("    IOC:           {}", ioc.ioc.red());
                println!("    Threat Type:   {}", ioc.threat_type);
                if let Some(m) = &ioc.malware {
                    println!("    Malware:       {}", m);
                }
                println!("    Confidence:    {}%", ioc.confidence_level);
                if let Some(d) = &ioc.first_seen {
                    println!("    First Seen:    {}", d);
                }
                println!();
            }
            if tf.ioc_count > MAX_IOC_DISPLAY {
                println!("    {}", format!("+ {} more IOCs...", tf.ioc_count - MAX_IOC_DISPLAY).dimmed());
            }
        }
    }
}

pub fn json_print(report: &ThreatReport) {
    println!("{}", serde_json::to_string_pretty(report).unwrap());
}

fn print_summary(report: &ThreatReport) {
    let (verdict, findings) = compute_verdict(report);
    let verdict_colored = match verdict {
        "MALICIOUS" => verdict.red().bold().to_string(),
        "SUSPICIOUS" => verdict.yellow().bold().to_string(),
        _ => verdict.green().bold().to_string(),
    };
    println!();
    println!("{}", "SUMMARY".bold().underline());
    println!("  {:16} {}", "Verdict:".dimmed(), verdict_colored);
    if !findings.is_empty() {
        println!("  {:16} {}", "Findings:".dimmed(), findings.join(" · "));
    }
    println!();
}

fn compute_verdict(report: &ThreatReport) -> (&'static str, Vec<String>) {
    let mut findings: Vec<String> = Vec::new();
    let mut severity: u8 = 0; // 0=clean, 1=suspicious, 2=malicious

    if let Some(tf) = &report.threatfox {
        if tf.ioc_count > 0 {
            severity = 2;
            findings.push(format!("{} C2 IOC(s) on ThreatFox", tf.ioc_count));
        }
    }

    if let Some(vt) = &report.virustotal {
        if vt.malicious > 0 {
            severity = 2;
            findings.push(format!("{} malicious VT detections", vt.malicious));
        } else if vt.suspicious > 0 && severity < 1 {
            severity = 1;
            findings.push(format!("{} suspicious VT detections", vt.suspicious));
        }
    }

    if let Some(a) = &report.abuseipdb {
        if a.abuse_confidence >= 75 && severity < 2 {
            severity = 2;
            findings.push(format!("AbuseIPDB score {}/100", a.abuse_confidence));
        } else if a.abuse_confidence >= 25 && severity < 1 {
            severity = 1;
            findings.push(format!("AbuseIPDB score {}/100", a.abuse_confidence));
        }
    }

    if let Some(g) = &report.greynoise {
        match g.classification.as_str() {
            "malicious" if severity < 2 => {
                severity = 2;
                findings.push("GreyNoise: malicious".to_string());
            }
            _ => {}
        }
        if g.riot {
            findings.push("known benign infrastructure (RIOT)".to_string());
        }
    }

    if let Some(o) = &report.otx {
        if o.pulse_count > 0 && severity < 1 {
            severity = 1;
            findings.push(format!("{} OTX pulse(s)", o.pulse_count));
        }
    }

    // Clean-state positive signals
    if severity == 0 {
        if let Some(a) = &report.abuseipdb {
            if a.is_whitelisted {
                findings.push("whitelisted on AbuseIPDB".to_string());
            }
        }
        if let Some(vt) = &report.virustotal {
            if vt.malicious == 0 && vt.suspicious == 0 {
                findings.push("0 VT detections".to_string());
            }
        }
        if let Some(g) = &report.greynoise {
            if g.classification == "benign" {
                findings.push("benign per GreyNoise".to_string());
            }
        }
    }

    let verdict = match severity {
        2 => "MALICIOUS",
        1 => "SUSPICIOUS",
        _ => "CLEAN",
    };

    (verdict, findings)
}

fn opt_str(v: &Option<String>) -> String {
    v.as_deref().unwrap_or("-").to_string()
}

fn join_str(v: &[String]) -> String {
    if v.is_empty() { "-".to_string() } else { v.join(", ") }
}

fn bool_str(b: bool) -> &'static str {
    if b { "Yes" } else { "No" }
}
