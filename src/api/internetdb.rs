use anyhow::{Context, Result};
use serde::Deserialize;
use crate::model::{ServiceInfo, ShodanSummary};

#[derive(Deserialize)]
struct InternetDBResponse {
    ports: Option<Vec<u16>>,
    hostnames: Option<Vec<String>>,
    tags: Option<Vec<String>>,
    vulns: Option<Vec<String>>,
}

pub async fn fetch_internetdb(ip: &str) -> Result<ShodanSummary> {
    let url = format!("https://internetdb.shodan.io/{}", ip);
    let resp = reqwest::get(&url)
        .await
        .context("Shodan InternetDB request failed")?;

    // 404 = IP not in Shodan's dataset, treat as empty result
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(ShodanSummary {
            org: None,
            isp: None,
            country: None,
            open_ports: vec![],
            services: vec![],
            hostnames: vec![],
            tags: vec![],
            vulns: vec![],
        });
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Shodan InternetDB returned {}: {}", status, body);
    }

    let data: InternetDBResponse = resp
        .json()
        .await
        .context("Failed to parse Shodan InternetDB response")?;

    let mut open_ports = data.ports.unwrap_or_default();
    open_ports.sort_unstable();

    // InternetDB only returns ports, no per-service banner details
    let services: Vec<ServiceInfo> = open_ports
        .iter()
        .map(|&port| ServiceInfo {
            port,
            transport: None,
            product: None,
            version: None,
        })
        .collect();

    Ok(ShodanSummary {
        org: None,
        isp: None,
        country: None,
        open_ports,
        services,
        hostnames: data.hostnames.unwrap_or_default(),
        tags: data.tags.unwrap_or_default(),
        vulns: data.vulns.unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internetdb_response_parses() {
        let json = r#"{
            "ip": "8.8.8.8",
            "ports": [53, 443],
            "hostnames": ["dns.google"],
            "tags": ["cloud"],
            "vulns": [],
            "cpes": []
        }"#;
        let data: InternetDBResponse = serde_json::from_str(json).unwrap();
        assert_eq!(data.ports.unwrap(), vec![53, 443]);
        assert_eq!(data.hostnames.unwrap(), vec!["dns.google"]);
    }
}
