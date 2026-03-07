use anyhow::{Context, Result};
use serde::Deserialize;
use crate::model::AbuseIPDBSummary;

#[derive(Deserialize)]
struct AbuseResponse {
    data: AbuseData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AbuseData {
    abuse_confidence_score: u8,
    total_reports: u32,
    country_code: Option<String>,
    domain: Option<String>,
    isp: Option<String>,
    usage_type: Option<String>,
    last_reported_at: Option<String>,
    is_tor: bool,
    is_whitelisted: Option<bool>,
}

pub async fn fetch_abuseipdb(ip: &str, key: &str) -> Result<AbuseIPDBSummary> {
    let client = reqwest::Client::new();
    let resp = client
        .get("https://api.abuseipdb.com/api/v2/check")
        .query(&[("ipAddress", ip), ("maxAgeInDays", "90")])
        .header("Key", key)
        .header("Accept", "application/json")
        .send()
        .await
        .context("AbuseIPDB request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("AbuseIPDB returned {}: {}", status, body);
    }

    let data: AbuseResponse = resp.json().await.context("Failed to parse AbuseIPDB response")?;
    let d = data.data;

    // Trim ISO 8601 timestamp to date only (YYYY-MM-DD)
    let last_reported_at = d.last_reported_at.map(|s| s.chars().take(10).collect());

    Ok(AbuseIPDBSummary {
        abuse_confidence: d.abuse_confidence_score,
        total_reports: d.total_reports,
        country: d.country_code,
        domain: d.domain,
        isp: d.isp,
        usage_type: d.usage_type,
        last_reported_at,
        is_tor: d.is_tor,
        is_whitelisted: d.is_whitelisted.unwrap_or(false),
    })
}
