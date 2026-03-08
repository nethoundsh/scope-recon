use anyhow::{Context, Result};
use serde::Deserialize;
use crate::model::BGPViewSummary;

#[derive(Deserialize)]
struct BgpResponse {
    data: BgpData,
}

#[derive(Deserialize)]
struct BgpData {
    ptr_record: Option<String>,
    prefixes: Vec<BgpPrefix>,
    rir_allocation: Option<BgpRir>,
}

#[derive(Deserialize)]
struct BgpPrefix {
    prefix: String,
    asn: Option<BgpAsn>,
}

#[derive(Deserialize)]
struct BgpAsn {
    asn: u32,
    name: Option<String>,
    description: Option<String>,
    country_code: Option<String>,
}

#[derive(Deserialize)]
struct BgpRir {
    rir_name: Option<String>,
}

pub async fn fetch_bgpview(ip: &str) -> Result<BGPViewSummary> {
    let url = format!("https://api.bgpview.io/ip/{}", ip);
    let resp = reqwest::get(&url)
        .await
        .context("BGPView request failed")?;

    if resp.status() == 404 {
        return Ok(BGPViewSummary {
            asn: None,
            asn_name: None,
            asn_description: None,
            country_code: None,
            ptr_record: None,
            prefixes: vec![],
            rir: None,
        });
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("BGPView returned {}: {}", status, body);
    }

    let data: BgpResponse = resp.json().await.context("Failed to parse BGPView response")?;
    let d = data.data;

    // Take ASN info from the first prefix that has it
    let first_asn = d.prefixes.iter().find_map(|p| p.asn.as_ref());

    let prefixes: Vec<String> = d.prefixes.iter().map(|p| p.prefix.clone()).collect();

    Ok(BGPViewSummary {
        asn: first_asn.map(|a| a.asn),
        asn_name: first_asn.and_then(|a| a.name.clone()),
        asn_description: first_asn.and_then(|a| a.description.clone()),
        country_code: first_asn.and_then(|a| a.country_code.clone()),
        ptr_record: d.ptr_record,
        prefixes,
        rir: d.rir_allocation.and_then(|r| r.rir_name),
    })
}
