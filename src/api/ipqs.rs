use anyhow::{Context, Result};
use serde::Deserialize;
use crate::model::IPQSSummary;

#[derive(Deserialize)]
struct IpqsResponse {
    success: bool,
    message: Option<String>,
    fraud_score: Option<u32>,
    proxy: Option<bool>,
    vpn: Option<bool>,
    tor: Option<bool>,
    bot_status: Option<bool>,
    recent_abuse: Option<bool>,
    abuse_velocity: Option<String>,
    #[serde(rename = "ISP")]
    isp: Option<String>,
    country_code: Option<String>,
}

pub async fn fetch_ipqs(ip: &str, key: &str) -> Result<IPQSSummary> {
    let url = format!(
        "https://ipqualityscore.com/api/json/ip/{}/{}",
        key, ip
    );
    let resp = reqwest::get(&url)
        .await
        .context("IPQualityScore request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("IPQualityScore returned {}: {}", status, body);
    }

    let data: IpqsResponse = resp
        .json()
        .await
        .context("Failed to parse IPQualityScore response")?;

    if !data.success {
        let msg = data.message.unwrap_or_else(|| "unknown error".to_string());
        anyhow::bail!("IPQualityScore error: {}", msg);
    }

    Ok(IPQSSummary {
        fraud_score: data.fraud_score.unwrap_or(0),
        proxy: data.proxy.unwrap_or(false),
        vpn: data.vpn.unwrap_or(false),
        tor: data.tor.unwrap_or(false),
        bot_status: data.bot_status.unwrap_or(false),
        recent_abuse: data.recent_abuse.unwrap_or(false),
        abuse_velocity: data.abuse_velocity.unwrap_or_else(|| "none".to_string()),
        isp: data.isp,
        country_code: data.country_code,
    })
}
