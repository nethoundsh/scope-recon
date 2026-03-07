use anyhow::{Context, Result};
use serde::Deserialize;
use crate::model::OTXSummary;

#[derive(Deserialize)]
struct OTXResponse {
    pulse_info: PulseInfo,
}

#[derive(Deserialize)]
struct PulseInfo {
    count: u32,
    pulses: Vec<Pulse>,
}

#[derive(Deserialize)]
struct Pulse {
    name: String,
}

pub async fn fetch_otx(ip: &str, key: &str) -> Result<OTXSummary> {
    let url = format!(
        "https://otx.alienvault.com/api/v1/indicators/IPv4/{}/general",
        ip
    );
    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .header("X-OTX-API-KEY", key)
        .send()
        .await
        .context("OTX request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("OTX returned {}: {}", status, body);
    }

    let data: OTXResponse = resp.json().await.context("Failed to parse OTX response")?;

    let pulse_names = data.pulse_info.pulses.into_iter().map(|p| p.name).collect();

    Ok(OTXSummary {
        pulse_count: data.pulse_info.count,
        pulse_names,
    })
}
