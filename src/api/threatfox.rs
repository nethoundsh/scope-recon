use anyhow::{Context, Result};
use serde::Deserialize;
use crate::model::{ThreatFoxIOC, ThreatFoxSummary};

#[derive(Deserialize)]
struct TFResponse {
    query_status: String,
    data: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct TFRecord {
    ioc: String,
    threat_type: String,
    malware_printable: Option<String>,
    confidence_level: u8,
    first_seen: Option<String>,
    last_seen: Option<String>,
}

pub async fn fetch_threatfox(ip: &str) -> Result<ThreatFoxSummary> {
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "query": "search_ioc",
        "search_term": ip
    });

    let resp = client
        .post("https://threatfox-api.abuse.ch/api/v1/")
        .json(&body)
        .send()
        .await
        .context("ThreatFox request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("ThreatFox returned {}: {}", status, text);
    }

    let parsed: TFResponse = resp.json().await.context("Failed to parse ThreatFox response")?;

    if parsed.query_status != "ok" {
        return Ok(ThreatFoxSummary { ioc_count: 0, iocs: vec![] });
    }

    let records: Vec<TFRecord> = match parsed.data {
        Some(v) => serde_json::from_value(v).unwrap_or_default(),
        None => vec![],
    };

    let ioc_count = records.len();
    let iocs = records
        .into_iter()
        .map(|r| ThreatFoxIOC {
            ioc: r.ioc,
            threat_type: r.threat_type,
            malware: r.malware_printable,
            confidence_level: r.confidence_level,
            first_seen: r.first_seen,
            last_seen: r.last_seen,
        })
        .collect();

    Ok(ThreatFoxSummary { ioc_count, iocs })
}
