use anyhow::{Context, Result};
use chrono::{TimeZone, Utc};
use serde::Deserialize;
use crate::model::VirusTotalSummary;

#[derive(Deserialize)]
struct VTResponse {
    data: VTData,
}

#[derive(Deserialize)]
struct VTData {
    attributes: VTAttributes,
}

#[derive(Deserialize)]
struct VTAttributes {
    last_analysis_stats: VTStats,
    last_analysis_date: Option<i64>,
}

#[derive(Deserialize)]
struct VTStats {
    malicious: u32,
    suspicious: u32,
    harmless: u32,
    undetected: u32,
}

pub async fn fetch_virustotal(ip: &str, key: &str) -> Result<VirusTotalSummary> {
    let url = format!("https://www.virustotal.com/api/v3/ip_addresses/{}", ip);
    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .header("x-apikey", key)
        .send()
        .await
        .context("VirusTotal request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("VirusTotal returned {}: {}", status, body);
    }

    let data: VTResponse = resp.json().await.context("Failed to parse VirusTotal response")?;
    let attrs = data.data.attributes;
    let s = attrs.last_analysis_stats;

    let last_analysis_date = attrs.last_analysis_date.and_then(|ts| {
        Utc.timestamp_opt(ts, 0)
            .single()
            .map(|d| d.format("%Y-%m-%d").to_string())
    });

    Ok(VirusTotalSummary {
        malicious: s.malicious,
        suspicious: s.suspicious,
        harmless: s.harmless,
        undetected: s.undetected,
        last_analysis_date,
    })
}
