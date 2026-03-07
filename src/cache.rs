use std::path::PathBuf;
use anyhow::Result;
use crate::model::ThreatReport;

fn cache_dir() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join(".cache").join("scope-recon"))
}

fn cache_path(ip: &str) -> Option<PathBuf> {
    // Replace colons (IPv6) with underscores for valid filenames
    cache_dir().map(|d| d.join(format!("{}.json", ip.replace(':', "_"))))
}

pub fn load(ip: &str, ttl_secs: u64) -> Option<ThreatReport> {
    let path = cache_path(ip)?;
    let content = std::fs::read_to_string(&path).ok()?;
    let report: ThreatReport = serde_json::from_str(&content).ok()?;

    // Check freshness against queried_at timestamp
    let queried_at = chrono::DateTime::parse_from_rfc3339(&report.queried_at).ok()?;
    let age_secs = chrono::Utc::now()
        .signed_duration_since(queried_at.with_timezone(&chrono::Utc))
        .num_seconds();

    if age_secs < 0 || age_secs as u64 > ttl_secs {
        return None;
    }

    Some(report)
}

pub fn save(report: &ThreatReport) -> Result<()> {
    let path = match cache_path(&report.ip) {
        Some(p) => p,
        None => return Ok(()), // no HOME, skip silently
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(report)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ThreatReport;

    fn make_report(ip: &str) -> ThreatReport {
        ThreatReport {
            queried_at: chrono::Utc::now().to_rfc3339(),
            ip: ip.to_string(),
            ipapi: None,
            shodan: None,
            abuseipdb: None,
            virustotal: None,
            otx: None,
            greynoise: None,
            threatfox: None,
        }
    }

    #[test]
    fn load_returns_none_when_no_file() {
        assert!(load("192.0.2.255", 3600).is_none());
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        // Override HOME so cache writes to our temp dir
        std::env::set_var("HOME", dir.path());

        let report = make_report("192.0.2.1");
        save(&report).unwrap();
        let loaded = load("192.0.2.1", 3600).unwrap();
        assert_eq!(loaded.ip, "192.0.2.1");
    }

    #[test]
    fn load_returns_none_when_expired() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", dir.path());

        // Write a report with an old timestamp
        let mut report = make_report("192.0.2.2");
        report.queried_at = "2000-01-01T00:00:00+00:00".to_string();
        save(&report).unwrap();

        // TTL of 1 second, but data is decades old
        assert!(load("192.0.2.2", 1).is_none());
    }
}
