use anyhow::{Context, Result};
use serde::Deserialize;
use crate::model::GreyNoiseSummary;

#[derive(Deserialize)]
struct GNResponse {
    noise: bool,
    riot: bool,
    classification: Option<String>,
    name: Option<String>,
    last_seen: Option<String>,
}

pub async fn fetch_greynoise(ip: &str, key: Option<&str>) -> Result<GreyNoiseSummary> {
    let url = format!("https://api.greynoise.io/v3/community/{}", ip);
    let client = reqwest::Client::new();
    let mut req = client.get(&url).header("Accept", "application/json");
    if let Some(k) = key {
        req = req.header("key", k);
    }

    let resp = req.send().await.context("GreyNoise request failed")?;

    // 404 means the IP is not in the GreyNoise dataset (not seen scanning)
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(GreyNoiseSummary {
            noise: false,
            riot: false,
            classification: "not seen".to_string(),
            name: None,
            last_seen: None,
        });
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("GreyNoise returned {}: {}", status, body);
    }

    let data: GNResponse = resp.json().await.context("Failed to parse GreyNoise response")?;

    Ok(GreyNoiseSummary {
        noise: data.noise,
        riot: data.riot,
        classification: data.classification.unwrap_or_else(|| "unknown".to_string()),
        name: data.name,
        last_seen: data.last_seen,
    })
}
