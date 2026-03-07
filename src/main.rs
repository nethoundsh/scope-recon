use anyhow::Result;
use clap::Parser;

mod api;
mod cli;
mod model;
mod output;

use api::{
    abuseipdb::fetch_abuseipdb,
    greynoise::fetch_greynoise,
    ipapi::fetch_ipapi,
    otx::fetch_otx,
    shodan::fetch_shodan,
    threatfox::fetch_threatfox,
    virustotal::fetch_virustotal,
};
use cli::Cli;
use model::ThreatReport;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let shodan_key = std::env::var("SHODAN_API_KEY").ok();
    let abuseipdb_key = std::env::var("ABUSEIPDB_API_KEY").ok();
    let vt_key = std::env::var("VIRUSTOTAL_API_KEY").ok();
    let otx_key = std::env::var("OTX_API_KEY").ok();
    let gn_key = std::env::var("GREYNOISE_API_KEY").ok();

    let ip = cli.ip.as_str();

    let (ipapi_res, shodan_res, abuse_res, vt_res, otx_res, gn_res, tf_res) = tokio::join!(
        fetch_ipapi(ip),
        async {
            match shodan_key.as_deref() {
                Some(k) => fetch_shodan(ip, k).await,
                None => Err(anyhow::anyhow!("SHODAN_API_KEY not set")),
            }
        },
        async {
            match abuseipdb_key.as_deref() {
                Some(k) => fetch_abuseipdb(ip, k).await,
                None => Err(anyhow::anyhow!("ABUSEIPDB_API_KEY not set")),
            }
        },
        async {
            match vt_key.as_deref() {
                Some(k) => fetch_virustotal(ip, k).await,
                None => Err(anyhow::anyhow!("VIRUSTOTAL_API_KEY not set")),
            }
        },
        async {
            match otx_key.as_deref() {
                Some(k) => fetch_otx(ip, k).await,
                None => Err(anyhow::anyhow!("OTX_API_KEY not set")),
            }
        },
        fetch_greynoise(ip, gn_key.as_deref()),
        fetch_threatfox(ip),
    );

    let report = ThreatReport {
        ip: cli.ip.clone(),
        ipapi: ipapi_res.ok(),
        shodan: shodan_res.ok(),
        abuseipdb: abuse_res.ok(),
        virustotal: vt_res.ok(),
        otx: otx_res.ok(),
        greynoise: gn_res.ok(),
        threatfox: tf_res.ok(),
    };

    if cli.json {
        output::json_print(&report);
    } else {
        output::pretty_print(&report);
    }

    Ok(())
}
