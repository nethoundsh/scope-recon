use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
};

use crate::model::ThreatReport;
use crate::output::compute_verdict;
use super::app::{App, SOURCE_NAMES, SourceState};

const SPINNER_FRAMES: &[&str] = &["⠋", "⠙", "⠸", "⠴", "⠦", "⠇"];

pub fn render(f: &mut Frame, app: &App) {
    let area = f.area();

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(0),    // body
            Constraint::Length(3), // footer
        ])
        .split(area);

    render_header(f, app, outer[0]);
    render_body(f, app, outer[1]);
    render_footer(f, outer[2]);
}

fn render_header(f: &mut Frame, app: &App, area: Rect) {
    let partial = build_partial_report(app);
    let (verdict, _) = compute_verdict(&partial);
    let (verdict_color, verdict_dot) = match verdict {
        "MALICIOUS" => (Color::Red, "●"),
        "SUSPICIOUS" => (Color::Yellow, "●"),
        _ => (Color::Green, "●"),
    };

    let line = Line::from(vec![
        Span::raw("  IP: "),
        Span::styled(app.ip.clone(), Style::default().add_modifier(Modifier::BOLD)),
        Span::raw("    VERDICT: "),
        Span::styled(verdict_dot, Style::default().fg(verdict_color)),
        Span::raw(" "),
        Span::styled(verdict, Style::default().fg(verdict_color).add_modifier(Modifier::BOLD)),
    ]);

    let block = Block::default()
        .title(" scope-recon ")
        .borders(Borders::ALL);
    let paragraph = Paragraph::new(line).block(block);
    f.render_widget(paragraph, area);
}

fn render_body(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(25), Constraint::Percentage(75)])
        .split(area);

    render_sources(f, app, chunks[0]);
    render_detail(f, app, chunks[1]);
}

fn render_sources(f: &mut Frame, app: &App, area: Rect) {
    let spin = SPINNER_FRAMES[(app.tick as usize / 2) % SPINNER_FRAMES.len()];

    let items: Vec<ListItem> = SOURCE_NAMES
        .iter()
        .enumerate()
        .map(|(i, &name)| {
            let (icon, icon_style): (String, Style) = match i {
                0 => source_icon(&app.ipapi, spin),
                1 => source_icon(&app.shodan, spin),
                2 => source_icon(&app.abuseipdb, spin),
                3 => source_icon(&app.virustotal, spin),
                4 => source_icon(&app.otx, spin),
                5 => source_icon(&app.greynoise, spin),
                6 => source_icon(&app.threatfox, spin),
                _ => ("?".to_string(), Style::default()),
            };
            let line = Line::from(vec![
                Span::raw("  "),
                Span::styled(icon, icon_style),
                Span::raw(" "),
                Span::raw(name),
            ]);
            ListItem::new(line)
        })
        .collect();

    let mut list_state = ListState::default();
    list_state.select(Some(app.selected));

    let list = List::new(items)
        .block(Block::default().title(" SOURCES ").borders(Borders::ALL))
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    f.render_stateful_widget(list, area, &mut list_state);
}

fn source_icon<T>(state: &SourceState<T>, spinner: &str) -> (String, Style) {
    match state {
        SourceState::Loading => (spinner.to_string(), Style::default().fg(Color::Yellow)),
        SourceState::Done(_) => ("✓".to_string(), Style::default().fg(Color::Green)),
        SourceState::Error(_) => ("✗".to_string(), Style::default().fg(Color::Red)),
        SourceState::Skipped => ("-".to_string(), Style::default().fg(Color::DarkGray)),
    }
}

fn render_detail(f: &mut Frame, app: &App, area: Rect) {
    let (title, lines) = match app.selected {
        0 => ("GEOLOCATION  (ip-api.com)", detail_ipapi(app)),
        1 => ("SHODAN", detail_shodan(app)),
        2 => ("ABUSEIPDB", detail_abuseipdb(app)),
        3 => ("VIRUSTOTAL", detail_virustotal(app)),
        4 => ("ALIENVAULT OTX", detail_otx(app)),
        5 => ("GREYNOISE", detail_greynoise(app)),
        6 => ("THREATFOX  (abuse.ch)", detail_threatfox(app)),
        _ => ("", vec![]),
    };

    let block = Block::default()
        .title(format!(" {} ", title))
        .borders(Borders::ALL);
    let paragraph = Paragraph::new(lines)
        .block(block)
        .scroll((app.detail_scroll, 0));
    f.render_widget(paragraph, area);
}

fn render_footer(f: &mut Frame, area: Rect) {
    let line = Line::from(vec![
        Span::styled(" q ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw("quit   "),
        Span::styled("↑↓/jk ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw("navigate   "),
        Span::styled("PgUp/PgDn ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw("scroll   "),
        Span::styled("r ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw("refresh"),
    ]);
    let block = Block::default().borders(Borders::ALL);
    let paragraph = Paragraph::new(line).block(block);
    f.render_widget(paragraph, area);
}

fn dim() -> Style {
    Style::default().fg(Color::DarkGray)
}

fn label<'a>(key: &'a str, val: String) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("  {:16} ", key), dim()),
        Span::raw(val),
    ])
}

fn loading<'a>() -> Vec<Line<'a>> {
    vec![Line::from(Span::styled("  Loading...", Style::default().fg(Color::Yellow)))]
}

fn skipped<'a>() -> Vec<Line<'a>> {
    vec![Line::from(Span::styled("  [skipped]", dim()))]
}

fn detail_ipapi(app: &App) -> Vec<Line<'static>> {
    match &app.ipapi {
        SourceState::Loading => loading(),
        SourceState::Skipped => skipped(),
        SourceState::Error(e) => vec![Line::from(Span::styled(
            format!("  Error: {}", e),
            Style::default().fg(Color::Red),
        ))],
        SourceState::Done(g) => vec![
            Line::raw(""),
            label("Country:", opt_s(&g.country)),
            label("Region:", opt_s(&g.region)),
            label("City:", opt_s(&g.city)),
            label("ISP:", opt_s(&g.isp)),
            label("Org:", opt_s(&g.org)),
            label("ASN:", opt_s(&g.asn)),
        ],
    }
}

fn detail_shodan(app: &App) -> Vec<Line<'static>> {
    match &app.shodan {
        SourceState::Loading => loading(),
        SourceState::Skipped => skipped(),
        SourceState::Error(e) => vec![Line::from(Span::styled(
            format!("  Error: {}", e),
            Style::default().fg(Color::Red),
        ))],
        SourceState::Done(s) => {
            let mut lines = vec![
                Line::raw(""),
                label("Org:", opt_s(&s.org)),
                label("ISP:", opt_s(&s.isp)),
                label("Country:", opt_s(&s.country)),
                label("Hostnames:", join_s(&s.hostnames)),
                label("Tags:", join_s(&s.tags)),
                label("Vulns:", join_s(&s.vulns)),
            ];
            if s.services.is_empty() {
                lines.push(label("Services:", "-".to_string()));
            } else {
                lines.push(Line::from(Span::styled("  Services:", dim())));
                for svc in &s.services {
                    let proto = svc.transport.as_deref().unwrap_or("tcp");
                    let label_str = match (&svc.product, &svc.version) {
                        (Some(p), Some(v)) => format!("{} {}", p, v),
                        (Some(p), None) => p.clone(),
                        _ => "-".to_string(),
                    };
                    lines.push(Line::from(Span::raw(format!(
                        "    {}/{:<8} {}",
                        svc.port, proto, label_str
                    ))));
                }
            }
            lines
        }
    }
}

fn detail_abuseipdb(app: &App) -> Vec<Line<'static>> {
    match &app.abuseipdb {
        SourceState::Loading => loading(),
        SourceState::Skipped => skipped(),
        SourceState::Error(e) => vec![Line::from(Span::styled(
            format!("  Error: {}", e),
            Style::default().fg(Color::Red),
        ))],
        SourceState::Done(a) => {
            let score_str = format!("{}/100", a.abuse_confidence);
            let score_color = if a.abuse_confidence >= 75 {
                Color::Red
            } else if a.abuse_confidence >= 25 {
                Color::Yellow
            } else {
                Color::Green
            };
            let level = if a.abuse_confidence >= 75 {
                "[HIGH]"
            } else if a.abuse_confidence >= 25 {
                "[MEDIUM]"
            } else {
                "[LOW]"
            };

            vec![
                Line::raw(""),
                Line::from(vec![
                    Span::styled("  Abuse Score:     ", dim()),
                    Span::styled(score_str, Style::default().fg(score_color)),
                    Span::raw("  "),
                    Span::styled(level, Style::default().fg(score_color).add_modifier(Modifier::BOLD)),
                ]),
                label("Reports:", a.total_reports.to_string()),
                label("Last Reported:", opt_s(&a.last_reported_at)),
                label("Usage Type:", opt_s(&a.usage_type)),
                label("Country:", opt_s(&a.country)),
                label("Domain:", opt_s(&a.domain)),
                label("ISP:", opt_s(&a.isp)),
                label("Tor Exit:", bool_s(a.is_tor)),
                label("Whitelisted:", bool_s(a.is_whitelisted)),
            ]
        }
    }
}

fn detail_virustotal(app: &App) -> Vec<Line<'static>> {
    match &app.virustotal {
        SourceState::Loading => loading(),
        SourceState::Skipped => skipped(),
        SourceState::Error(e) => vec![Line::from(Span::styled(
            format!("  Error: {}", e),
            Style::default().fg(Color::Red),
        ))],
        SourceState::Done(v) => {
            let mal_color = if v.malicious > 0 { Color::Red } else { Color::Green };
            let sus_color = if v.suspicious > 0 { Color::Yellow } else { Color::Reset };

            let mut lines = vec![
                Line::raw(""),
                Line::from(vec![
                    Span::styled(
                        format!("  {}", v.malicious),
                        Style::default().fg(mal_color).add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(" malicious / "),
                    Span::styled(
                        format!("{}", v.suspicious),
                        Style::default().fg(sus_color),
                    ),
                    Span::raw(format!(" suspicious / {} harmless / {} undetected", v.harmless, v.undetected)),
                ]),
            ];
            if let Some(date) = &v.last_analysis_date {
                lines.push(label("Last Scanned:", date.clone()));
            }
            lines
        }
    }
}

fn detail_otx(app: &App) -> Vec<Line<'static>> {
    match &app.otx {
        SourceState::Loading => loading(),
        SourceState::Skipped => skipped(),
        SourceState::Error(e) => vec![Line::from(Span::styled(
            format!("  Error: {}", e),
            Style::default().fg(Color::Red),
        ))],
        SourceState::Done(o) => {
            let pulse_color = if o.pulse_count == 0 { Color::Green } else { Color::Yellow };
            let mut lines = vec![
                Line::raw(""),
                Line::from(vec![
                    Span::styled("  Pulses:          ", dim()),
                    Span::styled(
                        o.pulse_count.to_string(),
                        Style::default().fg(pulse_color).add_modifier(Modifier::BOLD),
                    ),
                ]),
            ];
            for name in o.pulse_names.iter().take(5) {
                lines.push(Line::from(Span::raw(format!("                 - {}", name))));
            }
            let shown = o.pulse_names.len().min(5);
            let remaining = (o.pulse_count as usize).saturating_sub(shown);
            if remaining > 0 {
                lines.push(Line::from(Span::styled(
                    format!("                 + {} more...", remaining),
                    dim(),
                )));
            }
            lines
        }
    }
}

fn detail_greynoise(app: &App) -> Vec<Line<'static>> {
    match &app.greynoise {
        SourceState::Loading => loading(),
        SourceState::Skipped => skipped(),
        SourceState::Error(e) => vec![Line::from(Span::styled(
            format!("  Error: {}", e),
            Style::default().fg(Color::Red),
        ))],
        SourceState::Done(g) => {
            let class_color = match g.classification.as_str() {
                "malicious" => Color::Red,
                "benign" => Color::Green,
                "not seen" => Color::DarkGray,
                _ => Color::Yellow,
            };
            vec![
                Line::raw(""),
                label("Noise:", bool_s(g.noise)),
                label("RIOT:", bool_s(g.riot)),
                Line::from(vec![
                    Span::styled("  Class:           ", dim()),
                    Span::styled(
                        g.classification.clone(),
                        Style::default().fg(class_color).add_modifier(Modifier::BOLD),
                    ),
                ]),
                label("Actor:", opt_s(&g.name)),
                label("Last Seen:", opt_s(&g.last_seen)),
            ]
        }
    }
}

fn detail_threatfox(app: &App) -> Vec<Line<'static>> {
    match &app.threatfox {
        SourceState::Loading => loading(),
        SourceState::Skipped => skipped(),
        SourceState::Error(e) => vec![Line::from(Span::styled(
            format!("  Error: {}", e),
            Style::default().fg(Color::Red),
        ))],
        SourceState::Done(tf) => {
            let count_color = if tf.ioc_count == 0 { Color::Green } else { Color::Red };
            let mut lines = vec![
                Line::raw(""),
                Line::from(vec![
                    Span::styled("  C2 IOCs:         ", dim()),
                    Span::styled(
                        tf.ioc_count.to_string(),
                        Style::default().fg(count_color).add_modifier(Modifier::BOLD),
                    ),
                ]),
            ];
            for ioc in tf.iocs.iter().take(3) {
                lines.push(Line::raw(""));
                lines.push(Line::from(vec![
                    Span::styled("    IOC:           ", dim()),
                    Span::styled(ioc.ioc.clone(), Style::default().fg(Color::Red)),
                ]));
                lines.push(Line::from(Span::raw(format!("    Threat Type:   {}", ioc.threat_type))));
                if let Some(m) = &ioc.malware {
                    lines.push(Line::from(Span::raw(format!("    Malware:       {}", m))));
                }
                lines.push(Line::from(Span::raw(format!("    Confidence:    {}%", ioc.confidence_level))));
                if let Some(d) = &ioc.first_seen {
                    lines.push(Line::from(Span::raw(format!("    First Seen:    {}", d))));
                }
            }
            if tf.ioc_count > 3 {
                lines.push(Line::from(Span::styled(
                    format!("    + {} more IOCs...", tf.ioc_count - 3),
                    dim(),
                )));
            }
            lines
        }
    }
}

/// Build a partial ThreatReport from current app state for verdict computation.
pub fn build_partial_report(app: &App) -> ThreatReport {
    ThreatReport {
        queried_at: String::new(),
        ip: app.ip.clone(),
        ipapi: if let SourceState::Done(v) = &app.ipapi {
            Some(crate::model::IPAPISummary {
                country: v.country.clone(),
                region: v.region.clone(),
                city: v.city.clone(),
                isp: v.isp.clone(),
                org: v.org.clone(),
                asn: v.asn.clone(),
            })
        } else {
            None
        },
        shodan: if let SourceState::Done(v) = &app.shodan {
            Some(crate::model::ShodanSummary {
                org: v.org.clone(),
                isp: v.isp.clone(),
                country: v.country.clone(),
                open_ports: v.open_ports.clone(),
                services: v.services.iter().map(|s| crate::model::ServiceInfo {
                    port: s.port,
                    transport: s.transport.clone(),
                    product: s.product.clone(),
                    version: s.version.clone(),
                }).collect(),
                hostnames: v.hostnames.clone(),
                tags: v.tags.clone(),
                vulns: v.vulns.clone(),
            })
        } else {
            None
        },
        abuseipdb: if let SourceState::Done(v) = &app.abuseipdb {
            Some(crate::model::AbuseIPDBSummary {
                abuse_confidence: v.abuse_confidence,
                total_reports: v.total_reports,
                country: v.country.clone(),
                domain: v.domain.clone(),
                isp: v.isp.clone(),
                usage_type: v.usage_type.clone(),
                last_reported_at: v.last_reported_at.clone(),
                is_tor: v.is_tor,
                is_whitelisted: v.is_whitelisted,
            })
        } else {
            None
        },
        virustotal: if let SourceState::Done(v) = &app.virustotal {
            Some(crate::model::VirusTotalSummary {
                malicious: v.malicious,
                suspicious: v.suspicious,
                harmless: v.harmless,
                undetected: v.undetected,
                last_analysis_date: v.last_analysis_date.clone(),
            })
        } else {
            None
        },
        otx: if let SourceState::Done(v) = &app.otx {
            Some(crate::model::OTXSummary {
                pulse_count: v.pulse_count,
                pulse_names: v.pulse_names.clone(),
            })
        } else {
            None
        },
        greynoise: if let SourceState::Done(v) = &app.greynoise {
            Some(crate::model::GreyNoiseSummary {
                noise: v.noise,
                riot: v.riot,
                classification: v.classification.clone(),
                name: v.name.clone(),
                last_seen: v.last_seen.clone(),
            })
        } else {
            None
        },
        threatfox: if let SourceState::Done(v) = &app.threatfox {
            Some(crate::model::ThreatFoxSummary {
                ioc_count: v.ioc_count,
                iocs: v.iocs.iter().map(|i| crate::model::ThreatFoxIOC {
                    ioc: i.ioc.clone(),
                    threat_type: i.threat_type.clone(),
                    malware: i.malware.clone(),
                    confidence_level: i.confidence_level,
                    first_seen: i.first_seen.clone(),
                    last_seen: i.last_seen.clone(),
                }).collect(),
            })
        } else {
            None
        },
    }
}

fn opt_s(v: &Option<String>) -> String {
    v.as_deref().unwrap_or("-").to_string()
}

fn join_s(v: &[String]) -> String {
    if v.is_empty() { "-".to_string() } else { v.join(", ") }
}

fn bool_s(b: bool) -> String {
    if b { "Yes".to_string() } else { "No".to_string() }
}
