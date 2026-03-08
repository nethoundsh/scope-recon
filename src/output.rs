use std::io::{self, Write};
use colored::Colorize;
use crate::model::ThreatReport;

const DIVIDER: &str = "══════════════════════════════════";
const MAX_PULSE_NAMES: usize = 5;
const MAX_IOC_DISPLAY: usize = 3;

pub fn pretty_print(
    report: &ThreatReport,
    errors: &[(String, String)],
    verbose: bool,
    w: &mut dyn Write,
) {
    ln(w, format!("IP: {}", report.ip.bold()));
    ln(w, format!("{}", DIVIDER.dimmed()));
    print_summary(report, w);
    ln(w, format!("{}", DIVIDER.dimmed()));

    // --- GEOLOCATION ---
    ln(w, String::new());
    ln(w, format!("{}", "GEOLOCATION  (ip-api.com)".bold().underline()));
    match &report.ipapi {
        None => ln(w, format!("  {}", "[source unavailable]".dimmed())),
        Some(g) => {
            ln(w, format!("  {:16} {}", "Country:".dimmed(), opt_str(&g.country)));
            ln(w, format!("  {:16} {}", "Region:".dimmed(), opt_str(&g.region)));
            ln(w, format!("  {:16} {}", "City:".dimmed(), opt_str(&g.city)));
            ln(w, format!("  {:16} {}", "ISP:".dimmed(), opt_str(&g.isp)));
            ln(w, format!("  {:16} {}", "Org:".dimmed(), opt_str(&g.org)));
            ln(w, format!("  {:16} {}", "ASN:".dimmed(), opt_str(&g.asn)));
        }
    }

    // --- SHODAN ---
    ln(w, String::new());
    ln(w, format!("{}", "SHODAN".bold().underline()));
    match &report.shodan {
        None => ln(w, format!("  {}", "[source unavailable]".dimmed())),
        Some(s) => {
            ln(w, format!("  {:16} {}", "Org:".dimmed(), opt_str(&s.org)));
            ln(w, format!("  {:16} {}", "ISP:".dimmed(), opt_str(&s.isp)));
            ln(w, format!("  {:16} {}", "Country:".dimmed(), opt_str(&s.country)));
            ln(w, format!("  {:16} {}", "Hostnames:".dimmed(), join_str(&s.hostnames)));
            ln(w, format!("  {:16} {}", "Tags:".dimmed(), join_str(&s.tags)));
            ln(w, format!("  {:16} {}", "Vulns:".dimmed(), join_str(&s.vulns)));
            if s.services.is_empty() {
                ln(w, format!("  {:16} {}", "Services:".dimmed(), "-"));
            } else {
                ln(w, format!("  {}", "Services:".dimmed()));
                for svc in &s.services {
                    let proto = svc.transport.as_deref().unwrap_or("tcp");
                    let label = match (&svc.product, &svc.version) {
                        (Some(p), Some(v)) => format!("{} {}", p, v),
                        (Some(p), None) => p.clone(),
                        _ => "-".to_string(),
                    };
                    ln(w, format!("    {}/{:<8} {}", svc.port, proto, label));
                }
            }
        }
    }

    // --- ABUSEIPDB ---
    ln(w, String::new());
    ln(w, format!("{}", "ABUSEIPDB".bold().underline()));
    match &report.abuseipdb {
        None => ln(w, format!("  {}", "[source unavailable]".dimmed())),
        Some(a) => {
            let score_str = format!("{}/100", a.abuse_confidence);
            let label = if a.abuse_confidence >= 75 {
                format!("{}  {}", score_str.red(), "[HIGH]".red().bold())
            } else if a.abuse_confidence >= 25 {
                format!("{}  {}", score_str.yellow(), "[MEDIUM]".yellow().bold())
            } else {
                format!("{}  {}", score_str.green(), "[LOW]".green().bold())
            };
            ln(w, format!("  {:16} {}", "Abuse Score:".dimmed(), label));
            ln(w, format!("  {:16} {}", "Reports:".dimmed(), a.total_reports));
            ln(w, format!("  {:16} {}", "Last Reported:".dimmed(), opt_str(&a.last_reported_at)));
            ln(w, format!("  {:16} {}", "Usage Type:".dimmed(), opt_str(&a.usage_type)));
            ln(w, format!("  {:16} {}", "Country:".dimmed(), opt_str(&a.country)));
            ln(w, format!("  {:16} {}", "Domain:".dimmed(), opt_str(&a.domain)));
            ln(w, format!("  {:16} {}", "ISP:".dimmed(), opt_str(&a.isp)));
            ln(w, format!("  {:16} {}", "Tor Exit:".dimmed(), bool_str(a.is_tor)));
            ln(w, format!("  {:16} {}", "Whitelisted:".dimmed(), bool_str(a.is_whitelisted)));
        }
    }

    // --- VIRUSTOTAL ---
    ln(w, String::new());
    ln(w, format!("{}", "VIRUSTOTAL".bold().underline()));
    match &report.virustotal {
        None => ln(w, format!("  {}", "[source unavailable]".dimmed())),
        Some(v) => {
            let verdict = if v.malicious > 0 {
                format!(
                    "{} malicious / {} suspicious / {} harmless / {} undetected",
                    v.malicious.to_string().red().bold(),
                    v.suspicious, v.harmless, v.undetected
                )
            } else if v.suspicious > 0 {
                format!(
                    "{} malicious / {} suspicious / {} harmless / {} undetected",
                    v.malicious,
                    v.suspicious.to_string().yellow().bold(),
                    v.harmless, v.undetected
                )
            } else {
                format!(
                    "{} malicious / {} suspicious / {} harmless / {} undetected",
                    v.malicious.to_string().green(),
                    v.suspicious, v.harmless, v.undetected
                )
            };
            ln(w, format!("  {}", verdict));
            if let Some(date) = &v.last_analysis_date {
                ln(w, format!("  {:16} {}", "Last Scanned:".dimmed(), date));
            }
        }
    }

    // --- ALIENVAULT OTX ---
    ln(w, String::new());
    ln(w, format!("{}", "ALIENVAULT OTX".bold().underline()));
    match &report.otx {
        None => ln(w, format!("  {}", "[source unavailable]".dimmed())),
        Some(o) => {
            let pulse_label = if o.pulse_count == 0 {
                "0".green().to_string()
            } else {
                o.pulse_count.to_string().yellow().bold().to_string()
            };
            ln(w, format!("  {:16} {}", "Pulses:".dimmed(), pulse_label));
            if !o.pulse_names.is_empty() {
                let shown: Vec<&String> = o.pulse_names.iter().take(MAX_PULSE_NAMES).collect();
                for name in &shown {
                    ln(w, format!("                 - {}", name));
                }
                let remaining = o.pulse_count as usize - shown.len();
                if remaining > 0 {
                    ln(w, format!("                 {}", format!("+ {} more...", remaining).dimmed()));
                }
            }
        }
    }

    // --- GREYNOISE ---
    ln(w, String::new());
    ln(w, format!("{}", "GREYNOISE".bold().underline()));
    match &report.greynoise {
        None => ln(w, format!("  {}", "[source unavailable]".dimmed())),
        Some(g) => {
            let class_colored = match g.classification.as_str() {
                "malicious" => g.classification.red().bold().to_string(),
                "benign" => g.classification.green().bold().to_string(),
                "not seen" => g.classification.dimmed().to_string(),
                _ => g.classification.yellow().to_string(),
            };
            ln(w, format!("  {:16} {}", "Noise:".dimmed(), bool_str(g.noise)));
            ln(w, format!("  {:16} {}", "RIOT:".dimmed(), bool_str(g.riot)));
            ln(w, format!("  {:16} {}", "Class:".dimmed(), class_colored));
            ln(w, format!("  {:16} {}", "Actor:".dimmed(), opt_str(&g.name)));
            ln(w, format!("  {:16} {}", "Last Seen:".dimmed(), opt_str(&g.last_seen)));
        }
    }

    // --- THREATFOX ---
    ln(w, String::new());
    ln(w, format!("{}", "THREATFOX  (abuse.ch)".bold().underline()));
    match &report.threatfox {
        None => ln(w, format!("  {}", "[source unavailable]".dimmed())),
        Some(tf) => {
            let count_label = if tf.ioc_count == 0 {
                "0".green().to_string()
            } else {
                tf.ioc_count.to_string().red().bold().to_string()
            };
            ln(w, format!("  {:16} {}", "C2 IOCs:".dimmed(), count_label));
            for ioc in tf.iocs.iter().take(MAX_IOC_DISPLAY) {
                ln(w, format!("    IOC:           {}", ioc.ioc.red()));
                ln(w, format!("    Threat Type:   {}", ioc.threat_type));
                if let Some(m) = &ioc.malware {
                    ln(w, format!("    Malware:       {}", m));
                }
                ln(w, format!("    Confidence:    {}%", ioc.confidence_level));
                if let Some(d) = &ioc.first_seen {
                    ln(w, format!("    First Seen:    {}", d));
                }
                ln(w, String::new());
            }
            if tf.ioc_count > MAX_IOC_DISPLAY {
                ln(w, format!("    {}", format!("+ {} more IOCs...", tf.ioc_count - MAX_IOC_DISPLAY).dimmed()));
            }
        }
    }

    // --- BGPVIEW ---
    ln(w, String::new());
    ln(w, format!("{}", "BGPVIEW".bold().underline()));
    match &report.bgpview {
        None => ln(w, format!("  {}", "[source unavailable]".dimmed())),
        Some(b) => {
            let asn_str = match (b.asn, &b.asn_name) {
                (Some(n), Some(name)) => format!("AS{} {}", n, name),
                (Some(n), None) => format!("AS{}", n),
                _ => "-".to_string(),
            };
            ln(w, format!("  {:16} {}", "ASN:".dimmed(), asn_str));
            ln(w, format!("  {:16} {}", "Description:".dimmed(), opt_str(&b.asn_description)));
            ln(w, format!("  {:16} {}", "Country:".dimmed(), opt_str(&b.country_code)));
            ln(w, format!("  {:16} {}", "PTR Record:".dimmed(), opt_str(&b.ptr_record)));
            ln(w, format!("  {:16} {}", "Prefixes:".dimmed(), join_str(&b.prefixes)));
            ln(w, format!("  {:16} {}", "RIR:".dimmed(), opt_str(&b.rir)));
        }
    }

    // --- IPQUALITYSCORE ---
    ln(w, String::new());
    ln(w, format!("{}", "IPQUALITYSCORE".bold().underline()));
    match &report.ipqs {
        None => ln(w, format!("  {}", "[source unavailable]".dimmed())),
        Some(q) => {
            let score_str = format!("{}/100", q.fraud_score);
            let label = if q.fraud_score >= 75 {
                format!("{}  {}", score_str.red(), "[HIGH]".red().bold())
            } else if q.fraud_score >= 30 {
                format!("{}  {}", score_str.yellow(), "[MEDIUM]".yellow().bold())
            } else {
                format!("{}  {}", score_str.green(), "[LOW]".green().bold())
            };
            ln(w, format!("  {:16} {}", "Fraud Score:".dimmed(), label));
            ln(w, format!("  {:16} {}", "Proxy:".dimmed(), bool_str(q.proxy)));
            ln(w, format!("  {:16} {}", "VPN:".dimmed(), bool_str(q.vpn)));
            ln(w, format!("  {:16} {}", "TOR:".dimmed(), bool_str(q.tor)));
            ln(w, format!("  {:16} {}", "Bot:".dimmed(), bool_str(q.bot_status)));
            ln(w, format!("  {:16} {}", "Recent Abuse:".dimmed(), bool_str(q.recent_abuse)));
            ln(w, format!("  {:16} {}", "Abuse Velocity:".dimmed(), &q.abuse_velocity));
            ln(w, format!("  {:16} {}", "ISP:".dimmed(), opt_str(&q.isp)));
            ln(w, format!("  {:16} {}", "Country:".dimmed(), opt_str(&q.country_code)));
        }
    }

    // --- PULSEDIVE ---
    ln(w, String::new());
    ln(w, format!("{}", "PULSEDIVE".bold().underline()));
    match &report.pulsedive {
        None => ln(w, format!("  {}", "[source unavailable]".dimmed())),
        Some(p) => {
            let risk_colored = match p.risk.as_str() {
                "none" => p.risk.green().bold().to_string(),
                "low" | "medium" => p.risk.yellow().bold().to_string(),
                "high" | "critical" => p.risk.red().bold().to_string(),
                _ => p.risk.dimmed().to_string(),
            };
            ln(w, format!("  {:16} {}", "Risk:".dimmed(), risk_colored));
            ln(w, format!("  {:16} {}", "Last Seen:".dimmed(), opt_str(&p.last_seen)));
            if !p.threats.is_empty() {
                ln(w, format!("  {:16}", "Threats:".dimmed()));
                for t in &p.threats {
                    ln(w, format!("                 - {}", t));
                }
            }
            if !p.feeds.is_empty() {
                ln(w, format!("  {:16}", "Feeds:".dimmed()));
                for f in p.feeds.iter().take(5) {
                    ln(w, format!("                 - {}", f));
                }
                if p.feeds.len() > 5 {
                    ln(w, format!("                 {}", format!("+ {} more...", p.feeds.len() - 5).dimmed()));
                }
            }
        }
    }

    // --- IPINFO ---
    ln(w, String::new());
    ln(w, format!("{}", "IPINFO  (ipinfo.io)".bold().underline()));
    match &report.ipinfo {
        None => ln(w, format!("  {}", "[source unavailable]".dimmed())),
        Some(i) => {
            ln(w, format!("  {:16} {}", "Hostname:".dimmed(), opt_str(&i.hostname)));
            ln(w, format!("  {:16} {}", "City:".dimmed(), opt_str(&i.city)));
            ln(w, format!("  {:16} {}", "Region:".dimmed(), opt_str(&i.region)));
            ln(w, format!("  {:16} {}", "Country:".dimmed(), opt_str(&i.country)));
            ln(w, format!("  {:16} {}", "Org:".dimmed(), opt_str(&i.org)));
            ln(w, format!("  {:16} {}", "Timezone:".dimmed(), opt_str(&i.timezone)));
            if i.is_vpn.is_some() || i.is_proxy.is_some() || i.is_tor.is_some() || i.is_hosting.is_some() {
                ln(w, format!("  {:16} {}", "VPN:".dimmed(), opt_bool_str(i.is_vpn)));
                ln(w, format!("  {:16} {}", "Proxy:".dimmed(), opt_bool_str(i.is_proxy)));
                ln(w, format!("  {:16} {}", "TOR:".dimmed(), opt_bool_str(i.is_tor)));
                ln(w, format!("  {:16} {}", "Hosting:".dimmed(), opt_bool_str(i.is_hosting)));
            }
        }
    }

    // --- ERRORS (verbose only) ---
    if verbose && !errors.is_empty() {
        ln(w, String::new());
        ln(w, format!("{}", "SOURCE ERRORS".bold().underline()));
        for (source, reason) in errors {
            ln(w, format!("  {:16} {}", format!("{}:", source).dimmed(), reason));
        }
    }
}

pub fn json_print(report: &ThreatReport, w: &mut dyn Write) -> io::Result<()> {
    writeln!(w, "{}", serde_json::to_string_pretty(report).unwrap())
}

fn print_summary(report: &ThreatReport, w: &mut dyn Write) {
    let (verdict, findings) = compute_verdict(report);
    let verdict_colored = match verdict {
        "MALICIOUS" => verdict.red().bold().to_string(),
        "SUSPICIOUS" => verdict.yellow().bold().to_string(),
        _ => verdict.green().bold().to_string(),
    };
    ln(w, String::new());
    ln(w, format!("{}", "SUMMARY".bold().underline()));
    ln(w, format!("  {:16} {}", "Verdict:".dimmed(), verdict_colored));
    if !findings.is_empty() {
        ln(w, format!("  {:16} {}", "Findings:".dimmed(), findings.join(" · ")));
    }
    ln(w, String::new());
}

pub fn compute_verdict(report: &ThreatReport) -> (&'static str, Vec<String>) {
    let mut findings: Vec<String> = Vec::new();
    let mut severity: u8 = 0;

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
        if g.classification == "malicious" && severity < 2 {
            severity = 2;
            findings.push("GreyNoise: malicious".to_string());
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
    if let Some(q) = &report.ipqs {
        if q.fraud_score >= 75 && severity < 2 {
            severity = 2;
            findings.push(format!("IPQS fraud score {}/100", q.fraud_score));
        } else if q.fraud_score >= 30 && severity < 1 {
            severity = 1;
            findings.push(format!("IPQS fraud score {}/100", q.fraud_score));
        }
        if q.tor   { findings.push("IPQS: TOR exit node".to_string()); }
        if q.proxy { findings.push("IPQS: proxy".to_string()); }
        if q.vpn   { findings.push("IPQS: VPN".to_string()); }
    }
    if let Some(p) = &report.pulsedive {
        if (p.risk == "critical" || p.risk == "high") && severity < 2 {
            severity = 2;
            findings.push(format!("Pulsedive risk: {}", p.risk));
        } else if p.risk == "medium" && severity < 1 {
            severity = 1;
            findings.push(format!("Pulsedive risk: {}", p.risk));
        }
    }
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

fn ln(w: &mut dyn Write, s: String) {
    writeln!(w, "{}", s).unwrap();
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

fn opt_bool_str(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => "Yes",
        Some(false) => "No",
        None => "-",
    }
}
