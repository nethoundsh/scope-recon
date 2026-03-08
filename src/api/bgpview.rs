use anyhow::{Context, Result};
use serde::Deserialize;
use crate::model::BGPViewSummary;

// Uses RIPE Stat API (stat.ripe.net) — free, no key required
#[derive(Deserialize)]
struct RipeResponse {
    data: RipeData,
}

#[derive(Deserialize)]
struct RipeData {
    announced: bool,
    #[serde(default)]
    asns: Vec<RipeAsn>,
    resource: Option<String>,   // the matched prefix, e.g. "8.8.8.0/24"
    block: Option<RipeBlock>,
}

#[derive(Deserialize)]
struct RipeAsn {
    asn: u32,
    holder: Option<String>,     // e.g. "GOOGLE - Google LLC"
}

#[derive(Deserialize)]
struct RipeBlock {
    desc: Option<String>,       // e.g. "Administered by ARIN"
}

pub async fn fetch_bgpview(ip: &str) -> Result<BGPViewSummary> {
    let url = format!(
        "https://stat.ripe.net/data/prefix-overview/data.json?resource={}",
        ip
    );
    let resp = reqwest::get(&url)
        .await
        .context("RIPE Stat request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("RIPE Stat returned {}: {}", status, body);
    }

    let parsed: RipeResponse = resp
        .json()
        .await
        .context("Failed to parse RIPE Stat response")?;
    let d = parsed.data;

    if !d.announced || d.asns.is_empty() {
        return Ok(BGPViewSummary {
            asn: None,
            asn_name: None,
            asn_description: None,
            country_code: None,
            ptr_record: None,
            prefixes: d.resource.into_iter().collect(),
            rir: None,
        });
    }

    let first = &d.asns[0];
    // holder format: "GOOGLE - Google LLC" → name="GOOGLE", description="Google LLC"
    let (asn_name, asn_description) = match &first.holder {
        Some(h) => {
            if let Some(idx) = h.find(" - ") {
                (
                    Some(h[..idx].to_string()),
                    Some(h[idx + 3..].to_string()),
                )
            } else {
                (Some(h.clone()), None)
            }
        }
        None => (None, None),
    };

    // Extract RIR from block desc: "Administered by ARIN" → "ARIN"
    let rir = d.block.as_ref().and_then(|b| b.desc.as_ref()).and_then(|desc| {
        desc.split_whitespace().last().map(|s| s.to_string())
    });

    let prefixes = d.resource.into_iter().collect();

    Ok(BGPViewSummary {
        asn: Some(first.asn),
        asn_name,
        asn_description,
        country_code: None,
        ptr_record: None,
        prefixes,
        rir,
    })
}
