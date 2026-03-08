use std::time::Duration;

use anyhow::Result;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture, EventStream},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use futures::StreamExt;
use ratatui::{Terminal, backend::CrosstermBackend};
use tokio::sync::mpsc;

use crate::{
    ApiKeys,
    api::{
        abuseipdb::fetch_abuseipdb,
        bgpview::fetch_bgpview,
        greynoise::fetch_greynoise,
        internetdb::fetch_internetdb,
        ipapi::fetch_ipapi,
        ipinfo::fetch_ipinfo,
        ipqs::fetch_ipqs,
        otx::fetch_otx,
        pulsedive::fetch_pulsedive,
        retry::with_retry,
        shodan::fetch_shodan,
        threatfox::fetch_threatfox,
        virustotal::fetch_virustotal,
    },
    cache,
    cli::Cli,
};

pub mod app;
pub mod ui;

use app::{App, SourceUpdate};

const RETRY_DELAY: Duration = Duration::from_secs(2);

pub async fn run_tui(ip: &str, keys: &ApiKeys, cli: &Cli) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_loop(&mut terminal, ip, keys, cli).await;

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

async fn run_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    ip: &str,
    keys: &ApiKeys,
    cli: &Cli,
) -> Result<()> {
    let mut app = App::new(ip.to_string());
    let mut tick = tokio::time::interval(Duration::from_millis(100));

    // Check cache first, if hit apply immediately
    if cli.cache_ttl > 0 {
        if let Some(cached) = cache::load(ip, cli.cache_ttl) {
            apply_cached_report(&mut app, cached);
        }
    }

    let (tx, mut rx) = mpsc::channel::<SourceUpdate>(32);

    // Only spawn queries for sources not already Done from cache
    spawn_queries(ip, keys, cli, tx.clone(), &app).await;

    let mut event_stream = EventStream::new();

    loop {
        tokio::select! {
            _ = tick.tick() => {
                app.tick = app.tick.wrapping_add(1);
            }
            Some(Ok(ev)) = event_stream.next() => {
                app.handle_key(ev);
            }
            Some(update) = rx.recv() => {
                app.apply_update(update);
            }
        }

        terminal.draw(|f| ui::render(f, &app))?;

        if app.should_quit {
            break;
        }

        if app.refresh_requested {
            app.reset_for_refresh();
            // Drain any pending updates from old tasks
            while let Ok(_) = rx.try_recv() {}
            let (new_tx, new_rx) = mpsc::channel::<SourceUpdate>(32);
            rx = new_rx;
            // Bypass cache on refresh
            let mut no_cache_cli = cli.clone();
            no_cache_cli.cache_ttl = 0;
            spawn_queries(ip, keys, &no_cache_cli, new_tx, &app).await;
        }
    }

    Ok(())
}

fn apply_cached_report(app: &mut App, report: crate::model::ThreatReport) {
    if let Some(v) = report.ipapi {
        app.ipapi = app::SourceState::Done(v);
    }
    if let Some(v) = report.shodan {
        app.shodan = app::SourceState::Done(v);
    }
    if let Some(v) = report.abuseipdb {
        app.abuseipdb = app::SourceState::Done(v);
    }
    if let Some(v) = report.virustotal {
        app.virustotal = app::SourceState::Done(v);
    }
    if let Some(v) = report.otx {
        app.otx = app::SourceState::Done(v);
    }
    if let Some(v) = report.greynoise {
        app.greynoise = app::SourceState::Done(v);
    }
    if let Some(v) = report.threatfox {
        app.threatfox = app::SourceState::Done(v);
    }
    if let Some(v) = report.bgpview {
        app.bgpview = app::SourceState::Done(v);
    }
    if let Some(v) = report.ipqs {
        app.ipqs = app::SourceState::Done(v);
    }
    if let Some(v) = report.pulsedive {
        app.pulsedive = app::SourceState::Done(v);
    }
    if let Some(v) = report.ipinfo {
        app.ipinfo = app::SourceState::Done(v);
    }
}

async fn spawn_queries(
    ip: &str,
    keys: &ApiKeys,
    cli: &Cli,
    tx: mpsc::Sender<SourceUpdate>,
    app: &App,
) {
    let only = &cli.only;

    macro_rules! skip_if_done {
        ($state:expr) => {
            matches!($state, app::SourceState::Done(_))
        };
    }

    // ipapi
    if !skip_if_done!(app.ipapi) {
        let ip = ip.to_string();
        let tx = tx.clone();
        let should = should_run(only, "ipapi");
        tokio::spawn(async move {
            let result = if !should {
                Err(anyhow::anyhow!("__skipped__"))
            } else {
                with_retry("ip-api", RETRY_DELAY, || fetch_ipapi(&ip)).await
            };
            let _ = tx.send(SourceUpdate::IpApi(result)).await;
        });
    }

    // shodan
    if !skip_if_done!(app.shodan) {
        let ip = ip.to_string();
        let tx = tx.clone();
        let should = should_run(only, "shodan");
        let shodan_key = keys.shodan.clone();
        tokio::spawn(async move {
            let result = if !should {
                Err(anyhow::anyhow!("__skipped__"))
            } else {
                match shodan_key.as_deref() {
                    Some(k) => with_retry("Shodan", RETRY_DELAY, || fetch_shodan(&ip, k)).await,
                    None => with_retry("Shodan InternetDB", RETRY_DELAY, || fetch_internetdb(&ip)).await,
                }
            };
            let _ = tx.send(SourceUpdate::Shodan(result)).await;
        });
    }

    // abuseipdb
    if !skip_if_done!(app.abuseipdb) {
        let ip = ip.to_string();
        let tx = tx.clone();
        let should = should_run(only, "abuseipdb");
        let key = keys.abuseipdb.clone();
        tokio::spawn(async move {
            let result = if !should {
                Err(anyhow::anyhow!("__skipped__"))
            } else {
                match key.as_deref() {
                    Some(k) => with_retry("AbuseIPDB", RETRY_DELAY, || fetch_abuseipdb(&ip, k)).await,
                    None => Err(anyhow::anyhow!("ABUSEIPDB_API_KEY not set")),
                }
            };
            let _ = tx.send(SourceUpdate::AbuseIPDB(result)).await;
        });
    }

    // virustotal
    if !skip_if_done!(app.virustotal) {
        let ip = ip.to_string();
        let tx = tx.clone();
        let should = should_run(only, "virustotal");
        let key = keys.virustotal.clone();
        tokio::spawn(async move {
            let result = if !should {
                Err(anyhow::anyhow!("__skipped__"))
            } else {
                match key.as_deref() {
                    Some(k) => with_retry("VirusTotal", RETRY_DELAY, || fetch_virustotal(&ip, k)).await,
                    None => Err(anyhow::anyhow!("VIRUSTOTAL_API_KEY not set")),
                }
            };
            let _ = tx.send(SourceUpdate::VirusTotal(result)).await;
        });
    }

    // otx
    if !skip_if_done!(app.otx) {
        let ip = ip.to_string();
        let tx = tx.clone();
        let should = should_run(only, "otx");
        let key = keys.otx.clone();
        tokio::spawn(async move {
            let result = if !should {
                Err(anyhow::anyhow!("__skipped__"))
            } else {
                match key.as_deref() {
                    Some(k) => with_retry("OTX", RETRY_DELAY, || fetch_otx(&ip, k)).await,
                    None => Err(anyhow::anyhow!("OTX_API_KEY not set")),
                }
            };
            let _ = tx.send(SourceUpdate::Otx(result)).await;
        });
    }

    // greynoise
    if !skip_if_done!(app.greynoise) {
        let ip = ip.to_string();
        let tx = tx.clone();
        let should = should_run(only, "greynoise");
        let key = keys.greynoise.clone();
        tokio::spawn(async move {
            let result = if !should {
                Err(anyhow::anyhow!("__skipped__"))
            } else {
                with_retry("GreyNoise", RETRY_DELAY, || fetch_greynoise(&ip, key.as_deref())).await
            };
            let _ = tx.send(SourceUpdate::GreyNoise(result)).await;
        });
    }

    // threatfox
    if !skip_if_done!(app.threatfox) {
        let ip = ip.to_string();
        let tx = tx.clone();
        let should = should_run(only, "threatfox");
        let key = keys.threatfox.clone();
        tokio::spawn(async move {
            let result = if !should {
                Err(anyhow::anyhow!("__skipped__"))
            } else {
                match key.as_deref() {
                    Some(k) => with_retry("ThreatFox", RETRY_DELAY, || fetch_threatfox(&ip, k)).await,
                    None => Err(anyhow::anyhow!("THREATFOX_API_KEY not set")),
                }
            };
            let _ = tx.send(SourceUpdate::ThreatFox(result)).await;
        });
    }

    // bgpview
    if !skip_if_done!(app.bgpview) {
        let ip = ip.to_string();
        let tx = tx.clone();
        let should = should_run(only, "bgpview");
        tokio::spawn(async move {
            let result = if !should {
                Err(anyhow::anyhow!("__skipped__"))
            } else {
                with_retry("BGPView", RETRY_DELAY, || fetch_bgpview(&ip)).await
            };
            let _ = tx.send(SourceUpdate::BgpView(result)).await;
        });
    }

    // ipqs
    if !skip_if_done!(app.ipqs) {
        let ip = ip.to_string();
        let tx = tx.clone();
        let should = should_run(only, "ipqs");
        let key = keys.ipqs.clone();
        tokio::spawn(async move {
            let result = if !should {
                Err(anyhow::anyhow!("__skipped__"))
            } else {
                match key.as_deref() {
                    Some(k) => with_retry("IPQualityScore", RETRY_DELAY, || fetch_ipqs(&ip, k)).await,
                    None => Err(anyhow::anyhow!("IPQS_API_KEY not set")),
                }
            };
            let _ = tx.send(SourceUpdate::Ipqs(result)).await;
        });
    }

    // pulsedive
    if !skip_if_done!(app.pulsedive) {
        let ip = ip.to_string();
        let tx = tx.clone();
        let should = should_run(only, "pulsedive");
        let key = keys.pulsedive.clone();
        tokio::spawn(async move {
            let result = if !should {
                Err(anyhow::anyhow!("__skipped__"))
            } else {
                match key.as_deref() {
                    Some(k) => with_retry("Pulsedive", RETRY_DELAY, || fetch_pulsedive(&ip, k)).await,
                    None => Err(anyhow::anyhow!("PULSEDIVE_API_KEY not set")),
                }
            };
            let _ = tx.send(SourceUpdate::Pulsedive(result)).await;
        });
    }

    // ipinfo
    if !skip_if_done!(app.ipinfo) {
        let ip = ip.to_string();
        let tx = tx.clone();
        let should = should_run(only, "ipinfo");
        let token = keys.ipinfo.clone();
        tokio::spawn(async move {
            let result = if !should {
                Err(anyhow::anyhow!("__skipped__"))
            } else {
                with_retry("IPInfo", RETRY_DELAY, || fetch_ipinfo(&ip, token.as_deref())).await
            };
            let _ = tx.send(SourceUpdate::IpInfo(result)).await;
        });
    }
}

fn should_run(only: &[String], source: &str) -> bool {
    only.is_empty() || only.iter().any(|s| s.eq_ignore_ascii_case(source))
}
