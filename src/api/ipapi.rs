use anyhow::{bail, Context, Result};
use serde::Deserialize;
use crate::model::IPAPISummary;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IPAPIResponse {
    status: String,
    message: Option<String>,
    country: Option<String>,
    region_name: Option<String>,
    city: Option<String>,
    isp: Option<String>,
    org: Option<String>,
    #[serde(rename = "as")]
    asn: Option<String>,
}

pub async fn fetch_ipapi(ip: &str) -> Result<IPAPISummary> {
    let url = format!(
        "http://ip-api.com/json/{}?fields=status,message,country,regionName,city,isp,org,as",
        ip
    );
    let resp = reqwest::get(&url)
        .await
        .context("ip-api request failed")?;

    let data: IPAPIResponse = resp.json().await.context("Failed to parse ip-api response")?;

    if data.status != "success" {
        bail!("ip-api error: {}", data.message.unwrap_or_default());
    }

    Ok(IPAPISummary {
        country: data.country,
        region: data.region_name,
        city: data.city,
        isp: data.isp,
        org: data.org,
        asn: data.asn,
    })
}
