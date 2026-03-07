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
pub struct ShodanSummary {
    pub org: Option<String>,
    pub isp: Option<String>,
    pub country: Option<String>,
    pub open_ports: Vec<u16>,
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
    pub is_tor: bool,
    pub is_whitelisted: bool,
}

#[derive(Serialize)]
pub struct VirusTotalSummary {
    pub malicious: u32,
    pub suspicious: u32,
    pub harmless: u32,
    pub undetected: u32,
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
