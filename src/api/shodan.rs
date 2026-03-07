use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use crate::model::ShodanSummary;

#[derive(Deserialize)]
struct ShodanResponse {
    org: Option<String>,
    isp: Option<String>,
    country_name: Option<String>,
    ports: Option<Vec<u16>>,
    hostnames: Option<Vec<String>>,
    tags: Option<Vec<String>>,
    vulns: Option<HashMap<String, serde_json::Value>>,
}

pub async fn fetch_shodan(ip: &str, key: &str) -> Result<ShodanSummary> {
    let url = format!("https://api.shodan.io/shodan/host/{}?key={}", ip, key);
    let resp = reqwest::get(&url)
        .await
        .context("Shodan request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Shodan returned {}: {}", status, body);
    }

    let data: ShodanResponse = resp.json().await.context("Failed to parse Shodan response")?;

    let mut open_ports = data.ports.unwrap_or_default();
    open_ports.sort_unstable();

    let vulns = data
        .vulns
        .map(|m| m.into_keys().collect())
        .unwrap_or_default();

    Ok(ShodanSummary {
        org: data.org,
        isp: data.isp,
        country: data.country_name,
        open_ports,
        hostnames: data.hostnames.unwrap_or_default(),
        tags: data.tags.unwrap_or_default(),
        vulns,
    })
}
