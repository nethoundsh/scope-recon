use crossterm::event::{Event, KeyCode, KeyModifiers};
use crate::model::{
    AbuseIPDBSummary, BGPViewSummary, GreyNoiseSummary, IPAPISummary, IPInfoSummary,
    IPQSSummary, OTXSummary, PulsediveSummary, ShodanSummary, ThreatFoxSummary, VirusTotalSummary,
};

pub enum SourceState<T> {
    Loading,
    Done(T),
    Error(String),
    Skipped,
}

pub enum SourceUpdate {
    IpApi(anyhow::Result<IPAPISummary>),
    Shodan(anyhow::Result<ShodanSummary>),
    AbuseIPDB(anyhow::Result<AbuseIPDBSummary>),
    VirusTotal(anyhow::Result<VirusTotalSummary>),
    Otx(anyhow::Result<OTXSummary>),
    GreyNoise(anyhow::Result<GreyNoiseSummary>),
    ThreatFox(anyhow::Result<ThreatFoxSummary>),
    BgpView(anyhow::Result<BGPViewSummary>),
    Ipqs(anyhow::Result<IPQSSummary>),
    Pulsedive(anyhow::Result<PulsediveSummary>),
    IpInfo(anyhow::Result<IPInfoSummary>),
}

pub const SOURCE_NAMES: &[&str] = &[
    "Geolocation",
    "Shodan",
    "AbuseIPDB",
    "VirusTotal",
    "OTX",
    "GreyNoise",
    "ThreatFox",
    "BGPView",
    "IPQS",
    "Pulsedive",
    "IPInfo",
];

pub struct App {
    pub ip: String,
    pub selected: usize,
    pub detail_scroll: u16,
    pub tick: u64,
    pub should_quit: bool,
    pub refresh_requested: bool,
    pub ipapi: SourceState<IPAPISummary>,
    pub shodan: SourceState<ShodanSummary>,
    pub abuseipdb: SourceState<AbuseIPDBSummary>,
    pub virustotal: SourceState<VirusTotalSummary>,
    pub otx: SourceState<OTXSummary>,
    pub greynoise: SourceState<GreyNoiseSummary>,
    pub threatfox: SourceState<ThreatFoxSummary>,
    pub bgpview:   SourceState<BGPViewSummary>,
    pub ipqs:      SourceState<IPQSSummary>,
    pub pulsedive: SourceState<PulsediveSummary>,
    pub ipinfo:    SourceState<IPInfoSummary>,
}

impl App {
    pub fn new(ip: String) -> Self {
        Self {
            ip,
            selected: 0,
            detail_scroll: 0,
            tick: 0,
            should_quit: false,
            refresh_requested: false,
            ipapi: SourceState::Loading,
            shodan: SourceState::Loading,
            abuseipdb: SourceState::Loading,
            virustotal: SourceState::Loading,
            otx: SourceState::Loading,
            greynoise: SourceState::Loading,
            threatfox: SourceState::Loading,
            bgpview:   SourceState::Loading,
            ipqs:      SourceState::Loading,
            pulsedive: SourceState::Loading,
            ipinfo:    SourceState::Loading,
        }
    }

    pub fn reset_for_refresh(&mut self) {
        self.ipapi = SourceState::Loading;
        self.shodan = SourceState::Loading;
        self.abuseipdb = SourceState::Loading;
        self.virustotal = SourceState::Loading;
        self.otx = SourceState::Loading;
        self.greynoise = SourceState::Loading;
        self.threatfox = SourceState::Loading;
        self.bgpview   = SourceState::Loading;
        self.ipqs      = SourceState::Loading;
        self.pulsedive = SourceState::Loading;
        self.ipinfo    = SourceState::Loading;
        self.detail_scroll = 0;
        self.refresh_requested = false;
    }

    pub fn handle_key(&mut self, event: Event) {
        if let Event::Key(key) = event {
            match (key.code, key.modifiers) {
                (KeyCode::Char('q'), _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                    self.should_quit = true;
                }
                (KeyCode::Up, _) | (KeyCode::Char('k'), _) => {
                    if self.selected > 0 {
                        self.selected -= 1;
                        self.detail_scroll = 0;
                    }
                }
                (KeyCode::Down, _) | (KeyCode::Char('j'), _) => {
                    if self.selected < SOURCE_NAMES.len() - 1 {
                        self.selected += 1;
                        self.detail_scroll = 0;
                    }
                }
                (KeyCode::PageUp, _) | (KeyCode::Char('['), _) => {
                    self.detail_scroll = self.detail_scroll.saturating_sub(5);
                }
                (KeyCode::PageDown, _) | (KeyCode::Char(']'), _) => {
                    self.detail_scroll = self.detail_scroll.saturating_add(5);
                }
                (KeyCode::Char('r'), _) => {
                    self.refresh_requested = true;
                }
                _ => {}
            }
        }
    }

    pub fn apply_update(&mut self, update: SourceUpdate) {
        match update {
            SourceUpdate::IpApi(r) => {
                self.ipapi = match r {
                    Ok(v) => SourceState::Done(v),
                    Err(e) => {
                        if e.to_string() == "__skipped__" {
                            SourceState::Skipped
                        } else {
                            SourceState::Error(e.to_string())
                        }
                    }
                };
            }
            SourceUpdate::Shodan(r) => {
                self.shodan = match r {
                    Ok(v) => SourceState::Done(v),
                    Err(e) => {
                        if e.to_string() == "__skipped__" {
                            SourceState::Skipped
                        } else {
                            SourceState::Error(e.to_string())
                        }
                    }
                };
            }
            SourceUpdate::AbuseIPDB(r) => {
                self.abuseipdb = match r {
                    Ok(v) => SourceState::Done(v),
                    Err(e) => {
                        if e.to_string() == "__skipped__" {
                            SourceState::Skipped
                        } else {
                            SourceState::Error(e.to_string())
                        }
                    }
                };
            }
            SourceUpdate::VirusTotal(r) => {
                self.virustotal = match r {
                    Ok(v) => SourceState::Done(v),
                    Err(e) => {
                        if e.to_string() == "__skipped__" {
                            SourceState::Skipped
                        } else {
                            SourceState::Error(e.to_string())
                        }
                    }
                };
            }
            SourceUpdate::Otx(r) => {
                self.otx = match r {
                    Ok(v) => SourceState::Done(v),
                    Err(e) => {
                        if e.to_string() == "__skipped__" {
                            SourceState::Skipped
                        } else {
                            SourceState::Error(e.to_string())
                        }
                    }
                };
            }
            SourceUpdate::GreyNoise(r) => {
                self.greynoise = match r {
                    Ok(v) => SourceState::Done(v),
                    Err(e) => {
                        if e.to_string() == "__skipped__" {
                            SourceState::Skipped
                        } else {
                            SourceState::Error(e.to_string())
                        }
                    }
                };
            }
            SourceUpdate::ThreatFox(r) => {
                self.threatfox = match r {
                    Ok(v) => SourceState::Done(v),
                    Err(e) => {
                        if e.to_string() == "__skipped__" {
                            SourceState::Skipped
                        } else {
                            SourceState::Error(e.to_string())
                        }
                    }
                };
            }
            SourceUpdate::BgpView(r) => {
                self.bgpview = match r {
                    Ok(v) => SourceState::Done(v),
                    Err(e) => {
                        if e.to_string() == "__skipped__" { SourceState::Skipped } else { SourceState::Error(e.to_string()) }
                    }
                };
            }
            SourceUpdate::Ipqs(r) => {
                self.ipqs = match r {
                    Ok(v) => SourceState::Done(v),
                    Err(e) => {
                        if e.to_string() == "__skipped__" { SourceState::Skipped } else { SourceState::Error(e.to_string()) }
                    }
                };
            }
            SourceUpdate::Pulsedive(r) => {
                self.pulsedive = match r {
                    Ok(v) => SourceState::Done(v),
                    Err(e) => {
                        if e.to_string() == "__skipped__" { SourceState::Skipped } else { SourceState::Error(e.to_string()) }
                    }
                };
            }
            SourceUpdate::IpInfo(r) => {
                self.ipinfo = match r {
                    Ok(v) => SourceState::Done(v),
                    Err(e) => {
                        if e.to_string() == "__skipped__" { SourceState::Skipped } else { SourceState::Error(e.to_string()) }
                    }
                };
            }
        }
    }
}
