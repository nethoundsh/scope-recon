use serde::Serialize;

#[derive(Serialize)]
pub struct ThreatReport {
    pub ip: String,
    pub shodan: Option<ShodanSummary>,
    pub abuseipdb: Option<AbuseIPDBSummary>,
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
