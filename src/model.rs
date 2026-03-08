use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ThreatReport {
    pub queried_at: String,
    pub ip: String,
    pub ipapi: Option<IPAPISummary>,
    pub shodan: Option<ShodanSummary>,
    pub abuseipdb: Option<AbuseIPDBSummary>,
    pub virustotal: Option<VirusTotalSummary>,
    pub otx: Option<OTXSummary>,
    pub greynoise: Option<GreyNoiseSummary>,
    pub threatfox: Option<ThreatFoxSummary>,
    pub bgpview:   Option<BGPViewSummary>,
    pub ipqs:      Option<IPQSSummary>,
    pub pulsedive: Option<PulsediveSummary>,
    pub ipinfo:    Option<IPInfoSummary>,
}

#[derive(Serialize, Deserialize)]
pub struct IPAPISummary {
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    pub org: Option<String>,
    pub asn: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ServiceInfo {
    pub port: u16,
    pub transport: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
}

#[derive(Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize)]
pub struct VirusTotalSummary {
    pub malicious: u32,
    pub suspicious: u32,
    pub harmless: u32,
    pub undetected: u32,
    pub last_analysis_date: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct OTXSummary {
    pub pulse_count: u32,
    pub pulse_names: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct GreyNoiseSummary {
    pub noise: bool,
    pub riot: bool,
    pub classification: String,
    pub name: Option<String>,
    pub last_seen: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ThreatFoxSummary {
    pub ioc_count: usize,
    pub iocs: Vec<ThreatFoxIOC>,
}

#[derive(Serialize, Deserialize)]
pub struct BGPViewSummary {
    pub asn: Option<u32>,
    pub asn_name: Option<String>,
    pub asn_description: Option<String>,
    pub country_code: Option<String>,
    pub ptr_record: Option<String>,
    pub prefixes: Vec<String>,
    pub rir: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct IPQSSummary {
    pub fraud_score: u32,
    pub proxy: bool,
    pub vpn: bool,
    pub tor: bool,
    pub bot_status: bool,
    pub recent_abuse: bool,
    pub abuse_velocity: String,
    pub isp: Option<String>,
    pub country_code: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct PulsediveSummary {
    pub risk: String,
    pub last_seen: Option<String>,
    pub threats: Vec<String>,
    pub feeds: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct IPInfoSummary {
    pub hostname: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub country: Option<String>,
    pub org: Option<String>,
    pub timezone: Option<String>,
    pub is_vpn: Option<bool>,
    pub is_proxy: Option<bool>,
    pub is_tor: Option<bool>,
    pub is_hosting: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct ThreatFoxIOC {
    pub ioc: String,
    pub threat_type: String,
    pub malware: Option<String>,
    pub confidence_level: u8,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
}
