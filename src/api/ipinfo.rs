use anyhow::{Context, Result};
use serde::Deserialize;
use crate::model::IPInfoSummary;

#[derive(Deserialize)]
struct IpInfoResponse {
    hostname: Option<String>,
    city: Option<String>,
    region: Option<String>,
    country: Option<String>,
    org: Option<String>,
    timezone: Option<String>,
    #[serde(default)]
    privacy: Option<IpInfoPrivacy>,
}

#[derive(Deserialize, Default)]
struct IpInfoPrivacy {
    vpn: Option<bool>,
    proxy: Option<bool>,
    tor: Option<bool>,
    hosting: Option<bool>,
}

pub async fn fetch_ipinfo(ip: &str, token: Option<&str>) -> Result<IPInfoSummary> {
    let url = match token {
        Some(t) => format!("https://ipinfo.io/{}/json?token={}", ip, t),
        None => format!("https://ipinfo.io/{}/json", ip),
    };

    let resp = reqwest::get(&url)
        .await
        .context("IPInfo request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("IPInfo returned {}: {}", status, body);
    }

    let data: IpInfoResponse = resp
        .json()
        .await
        .context("Failed to parse IPInfo response")?;

    let (is_vpn, is_proxy, is_tor, is_hosting) = match data.privacy {
        Some(p) => (p.vpn, p.proxy, p.tor, p.hosting),
        None => (None, None, None, None),
    };

    Ok(IPInfoSummary {
        hostname: data.hostname,
        city: data.city,
        region: data.region,
        country: data.country,
        org: data.org,
        timezone: data.timezone,
        is_vpn,
        is_proxy,
        is_tor,
        is_hosting,
    })
}
