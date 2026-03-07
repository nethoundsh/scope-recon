use serde::Serialize;

#[derive(Serialize)]
pub struct ThreatReport {
    pub ip: String,
    pub ipapi: Option<IPAPISummary>,
    pub shodan: Option<ShodanSummary>,
    pub abuseipdb: Option<AbuseIPDBSummary>,
    pub virustotal: Option<VirusTotalSummary>,
    pub otx: Option<OTXSummary>,
    pub greynoise: Option<GreyNoiseSummary>,
    pub threatfox: Option<ThreatFoxSummary>,
}

#[derive(Serialize)]
pub struct IPAPISummary {
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    pub org: Option<String>,
    pub asn: Option<String>,
}

#[derive(Serialize)]
pub struct ServiceInfo {
    pub port: u16,
    pub transport: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
}

#[derive(Serialize)]
pub struct ShodanSummary {
    pub org: Option<String>,
    pub isp: Option<String>,
    pub country: Option<String>,
    pub open_ports: Vec<u16>,
    pub services: Vec<ServiceInfo>,
    pub hostnames: Vec<String>,
    pub tags: Vec<String>,
    pub vulns: Vec<String>,
}

#[derive(Serialize)]
pub struct AbuseIPDBSummary {
    pub abuse_confidence: u8,
    pub total_reports: u32,
    pub country: Option<String>,
    pub domain: Option<String>,
    pub isp: Option<String>,
    pub usage_type: Option<String>,
    pub last_reported_at: Option<String>,
    pub is_tor: bool,
    pub is_whitelisted: bool,
}

#[derive(Serialize)]
pub struct VirusTotalSummary {
    pub malicious: u32,
    pub suspicious: u32,
    pub harmless: u32,
    pub undetected: u32,
    pub last_analysis_date: Option<String>,
}

#[derive(Serialize)]
pub struct OTXSummary {
    pub pulse_count: u32,
    pub pulse_names: Vec<String>,
}

#[derive(Serialize)]
pub struct GreyNoiseSummary {
    pub noise: bool,
    pub riot: bool,
    pub classification: String,
    pub name: Option<String>,
    pub last_seen: Option<String>,
}

#[derive(Serialize)]
pub struct ThreatFoxSummary {
    pub ioc_count: usize,
    pub iocs: Vec<ThreatFoxIOC>,
}

#[derive(Serialize)]
pub struct ThreatFoxIOC {
    pub ioc: String,
    pub threat_type: String,
    pub malware: Option<String>,
    pub confidence_level: u8,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
}
