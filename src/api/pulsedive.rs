use anyhow::{Context, Result};
use serde::Deserialize;
use crate::model::PulsediveSummary;

#[derive(Deserialize)]
struct PdResponse {
    risk: Option<String>,
    stamp_seen: Option<String>,
    #[serde(default)]
    threats: Vec<PdThreat>,
    #[serde(default)]
    feeds: Vec<PdFeed>,
    // error field present when indicator not found
    #[allow(dead_code)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct PdThreat {
    name: Option<String>,
}

#[derive(Deserialize)]
struct PdFeed {
    name: Option<String>,
}

pub async fn fetch_pulsedive(ip: &str, key: &str) -> Result<PulsediveSummary> {
    let url = format!(
        "https://pulsedive.com/api/info.php?ioc={}&pretty=1&key={}",
        ip, key
    );
    let resp = reqwest::get(&url)
        .await
        .context("Pulsedive request failed")?;

    // 404 = IP not in Pulsedive database — treat as unknown, not an error
    if resp.status() == 404 {
        return Ok(PulsediveSummary {
            risk: "unknown".to_string(),
            last_seen: None,
            threats: vec![],
            feeds: vec![],
        });
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Pulsedive returned {}: {}", status, body);
    }

    let data: PdResponse = resp
        .json()
        .await
        .context("Failed to parse Pulsedive response")?;

    // "Not found" returns an error field with no risk — treat as unknown, not an error
    if data.risk.is_none() {
        return Ok(PulsediveSummary {
            risk: "unknown".to_string(),
            last_seen: None,
            threats: vec![],
            feeds: vec![],
        });
    }

    let last_seen = data
        .stamp_seen
        .map(|s| s.chars().take(10).collect::<String>());

    let threats: Vec<String> = data
        .threats
        .into_iter()
        .filter_map(|t| t.name)
        .collect();

    let feeds: Vec<String> = data
        .feeds
        .into_iter()
        .filter_map(|f| f.name)
        .collect();

    Ok(PulsediveSummary {
        risk: data.risk.unwrap_or_else(|| "unknown".to_string()),
        last_seen,
        threats,
        feeds,
    })
}
