# scope-recon

A fast Rust CLI tool that queries multiple threat intelligence sources concurrently for a given IP address. Single-IP lookups open a live **ratatui TUI** where results populate in real time as each API call completes. Bulk and JSON modes output to the terminal or a file unchanged.

## Features

- **Live TUI** for single-IP lookups — sources populate with animated spinners as concurrent API calls finish; verdict updates in real time
- Eleven concurrent API lookups with no sequential waiting
- Synthesized **SUMMARY** verdict (CLEAN / SUSPICIOUS / MALICIOUS) recomputed live in the TUI header as each source arrives
- Graceful degradation — missing keys or failed sources show `[source unavailable]` / `✗`, the rest still display
- `--verbose` flag reveals exactly why each source failed (CLI/JSON mode)
- `--only` flag to query a subset of sources; skipped sources show `-` in the TUI
- `--no-color` flag for clean file output
- `--output` to write results directly to a file
- Bulk mode via `--file ips.txt` — processes a list of IPs/CIDRs with rate-limit courtesy delays
- CIDR range support — `scope-recon 10.0.0.0/28` expands and queries each host (max 256)
- On-disk caching under `~/.cache/scope-recon/` with configurable TTL; `r` in the TUI bypasses cache and re-queries all sources
- Shodan InternetDB fallback when no Shodan API key is set (free, no key required)
- `queried_at` timestamp on every report for audit trails and cache freshness checks
- `--json` flag for machine-readable output; bulk JSON output is a JSON array
- No API key required for geolocation (ip-api.com), C2 lookups (ThreatFox), BGP routing data (BGPView), or basic port data (Shodan InternetDB)
- IPinfo works without a token (rate-limited); set `IPINFO_TOKEN` for 50k req/month

## API Sources

| Phase | Source | Purpose | Key Required |
|---|---|---|---|
| 1 | [ip-api.com](http://ip-api.com) | Geolocation, ASN, ISP | No |
| 1 | [Shodan](https://shodan.io) | Open ports, service banners, CVEs | No (InternetDB fallback) / Yes (full) |
| 2 | [VirusTotal](https://virustotal.com) | Vendor reputation consensus | Yes |
| 2 | [AlienVault OTX](https://otx.alienvault.com) | Threat campaigns, pulse correlation | Yes |
| 2 | [AbuseIPDB](https://www.abuseipdb.com) | Abuse confidence score, report history | Yes |
| 3 | [GreyNoise](https://greynoise.io) | Internet noise vs. targeted activity | Optional |
| 3 | [ThreatFox](https://threatfox.abuse.ch) | Malware C2 IOC matching | Yes (free) |
| 4 | [RIPE Stat](https://stat.ripe.net) | BGP routing, ASN, prefix | No |
| 4 | [IPQualityScore](https://ipqualityscore.com) | Fraud score, VPN/proxy/TOR/bot detection | Yes |
| 4 | [Pulsedive](https://pulsedive.com) | Aggregated risk level, threat feed names | Yes |
| 4 | [IPinfo](https://ipinfo.io) | Hostname, org, timezone; privacy flags (paid) | Optional |

## TUI Interface

Running `scope-recon <IP>` without `--json`, `--output`, or `--file` opens a full-screen terminal UI:

```
┌─ scope-recon ──────────────────────────────────────────────────────┐
│  IP: 8.8.8.8                              VERDICT: ● CLEAN         │
├──────────────────┬─────────────────────────────────────────────────┤
│ SOURCES          │ GEOLOCATION  (ip-api.com)                       │
│                  │                                                  │
│ ▶ Geolocation ✓  │   Country:    United States                      │
│   Shodan      ⠸  │   Region:     Virginia                           │
│   AbuseIPDB   ✓  │   City:       Ashburn                            │
│   VirusTotal  ✓  │   ISP:        Google LLC                         │
│   OTX         ✗  │   Org:        Google Public DNS                  │
│   GreyNoise   ✓  │   ASN:        AS15169 Google LLC                 │
│   ThreatFox   ✓  │                                                  │
├──────────────────┴─────────────────────────────────────────────────┤
│  q quit   ↑↓/jk navigate   PgUp/PgDn scroll detail   r refresh    │
└────────────────────────────────────────────────────────────────────┘
```

**Status icons**

| Icon | Meaning |
|---|---|
| `⠋⠙⠸…` (animated) | Loading |
| `✓` green | Done |
| `✗` red | Error / key not set |
| `-` dim | Skipped (`--only` filter) |

**Keybindings**

| Key | Action |
|---|---|
| `q` / `Ctrl-C` | Quit |
| `↑` / `k` | Select previous source |
| `↓` / `j` | Select next source |
| `PgUp` / `[` | Scroll detail pane up |
| `PgDn` / `]` | Scroll detail pane down |
| `r` | Re-query all sources (bypasses cache) |

The TUI activates only for single-IP interactive use. All other modes (`--json`, `--file`, `--output`, CIDR ranges) use the original CLI output path unchanged.

## Installation

### Prerequisites

- [Rust](https://rustup.rs/) 1.70 or later

### Build from source

```bash
git clone https://github.com/youruser/scope-recon
cd scope-recon
cargo build --release
```

The binary will be at `target/release/scope-recon`. Optionally move it to your PATH:

```bash
cp target/release/scope-recon ~/.local/bin/
```

## API Keys

Register for free accounts at each service:

| Service | Registration |
|---|---|
| Shodan | https://account.shodan.io/register |
| VirusTotal | https://www.virustotal.com/gui/join-us |
| AlienVault OTX | https://otx.alienvault.com |
| AbuseIPDB | https://www.abuseipdb.com/register |
| GreyNoise | https://www.greynoise.io (community tier) |
| ThreatFox | https://auth.abuse.ch/ (abuse.ch Authentication Portal) |
| IPQualityScore | https://www.ipqualityscore.com/create-account |
| Pulsedive | https://pulsedive.com/register |
| IPinfo | https://ipinfo.io/signup |

ip-api.com and RIPE Stat require no account or key. Shodan falls back to InternetDB (ports, hostnames, tags, vulns — no service banners) if `SHODAN_API_KEY` is not set. IPinfo works without a token (1,000 req/day shared limit); set `IPINFO_TOKEN` for 50,000 req/month. IPQualityScore and Pulsedive have free tiers (1,000 req/month and 250 req/day respectively).

### Setting your API keys securely

Avoid typing `export KEY=value` directly in your terminal — the command gets saved to your shell history (`~/.zsh_history`, `~/.bash_history`) in plaintext.

**Recommended: add to your shell profile in an editor**

Open `~/.zshrc` (or `~/.bashrc`) in a text editor and add:

```bash
export SHODAN_API_KEY=your_shodan_key_here
export VIRUSTOTAL_API_KEY=your_virustotal_key_here
export OTX_API_KEY=your_otx_key_here
export ABUSEIPDB_API_KEY=your_abuseipdb_key_here
export GREYNOISE_API_KEY=your_greynoise_key_here   # optional
export THREATFOX_API_KEY=your_threatfox_key_here
export IPQS_API_KEY=your_ipqualityscore_key_here
export PULSEDIVE_API_KEY=your_pulsedive_key_here
export IPINFO_TOKEN=your_ipinfo_token_here         # optional
```

Then lock down the file so only your user can read it:

```bash
chmod 600 ~/.zshrc
```

Reload to apply:

```bash
source ~/.zshrc
```

**Alternative: inline per-command (never stored in history)**

Prefix the command directly — keys never touch your history:

```bash
SHODAN_API_KEY=abc VIRUSTOTAL_API_KEY=xyz scope-recon 8.8.8.8
```

> In zsh, set `HIST_IGNORE_SPACE` and prefix the command with a leading space to suppress history recording for that line.

**Alternative: use a secrets manager**

Tools like [`pass`](https://www.passwordstore.org/), [1Password CLI](https://developer.1password.com/docs/cli/) (`op run --`), or Bitwarden CLI can inject secrets at runtime without them residing in any config file:

```bash
op run -- scope-recon 8.8.8.8
```

**What to avoid**

- Typing `export KEY=value` in the terminal (saved to history)
- Storing keys in a `.env` file inside a git repository
- Sharing terminal screenshots that include `printenv` or `env` output

## Usage

```
scope-recon [TARGET] [OPTIONS]

Arguments:
  [TARGET]    IP address or CIDR range to investigate (e.g. 1.2.3.4 or 1.2.3.0/24)

Options:
      --file <FILE>       File containing IPs/CIDRs, one per line (# for comments)
      --json              Output as JSON instead of pretty-printed table
      --verbose           Show why each source failed
      --no-color          Disable color output
      --only <SOURCES>    Comma-separated list of sources to query
      --output <FILE>     Write output to file instead of stdout
      --cache-ttl <SECS>  Cache TTL in seconds; 0 disables caching (default: 3600)
  -h, --help              Print help
```

### Single IP lookup

```bash
scope-recon 8.8.8.8
```

Opens the TUI (see [TUI Interface](#tui-interface) above). Sources populate live with animated spinners; navigate with `↑↓` or `jk` to inspect each source's detail pane. Press `q` to quit, `r` to refresh.

### Bulk mode

Process a list of IPs from a file (one IP or CIDR per line, `#` for comments):

```bash
scope-recon --file targets.txt
scope-recon --file targets.txt --json --output results.json
```

```
# targets.txt
8.8.8.8
1.1.1.1
# 192.168.1.0/28  (commented out)
```

A 500ms courtesy delay is inserted between each target to avoid hammering APIs. JSON bulk output is a JSON array containing one object per IP.

### CIDR range

```bash
scope-recon 192.168.1.0/30
```

Expands to host IPs and queries each one sequentially. Maximum 256 hosts per range.

### Query specific sources only

```bash
scope-recon 8.8.8.8 --only shodan,virustotal
scope-recon 8.8.8.8 --only threatfox,greynoise
```

Sources not in the list are silently skipped — they do not appear as errors in `--verbose` output.

### Verbose error reporting

```bash
scope-recon 8.8.8.8 --verbose
```

Appends a `SOURCE ERRORS` section showing exactly why each unavailable source failed:

```
SOURCE ERRORS
  AbuseIPDB:       ABUSEIPDB_API_KEY not set
  VirusTotal:      VirusTotal rate limited after retry
  OTX:             OTX_API_KEY not set
```

### Disable colors

```bash
scope-recon 8.8.8.8 --no-color
```

Colors are also automatically disabled when `--output` writes to a file.

### Write output to file

```bash
scope-recon 8.8.8.8 --json --output report.json
scope-recon 8.8.8.8 --output report.txt   # pretty output, no color
```

### Caching

Results are cached to `~/.cache/scope-recon/{ip}.json` for 1 hour by default. On a cache hit, the tool skips all API calls and returns the stored report instantly.

```bash
# Use cached data for up to 24 hours
scope-recon 8.8.8.8 --cache-ttl 86400

# Disable caching entirely
scope-recon 8.8.8.8 --cache-ttl 0
```

With `--verbose`, cache hits are reported to stderr:

```
[cache hit] 8.8.8.8 — queried at 2026-03-07T10:00:00+00:00
```

### Rate limit retry

If any source returns HTTP 429 (rate limited), the tool waits 2 seconds and retries once automatically. A warning is printed to stderr:

```
warning: VirusTotal rate limited (429) — retrying in 2s...
```

### SUMMARY verdict logic

| Verdict | Triggers |
|---|---|
| `MALICIOUS` | Any VT malicious detections · AbuseIPDB score ≥ 75 · GreyNoise classification = malicious · ThreatFox C2 IOC match |
| `SUSPICIOUS` | VT suspicious detections only · AbuseIPDB score 25–74 · OTX pulses with no harder signal |
| `CLEAN` | None of the above; positive signals (whitelisted, RIOT, 0 detections) listed |

### Color coding

- **SUMMARY verdict**: green (CLEAN), yellow (SUSPICIOUS), red (MALICIOUS)
- **VirusTotal**: red if any malicious, yellow if suspicious only, green if clean
- **AbuseIPDB score**: green (0–24 LOW), yellow (25–74 MEDIUM), red (75–100 HIGH)
- **GreyNoise classification**: green (benign), red (malicious), yellow (unknown), dimmed (not seen)
- **OTX pulses**: green if 0, yellow/bold if any found
- **ThreatFox C2 IOCs**: green if 0, red/bold if any found

### JSON output

```bash
scope-recon 8.8.8.8 --json
```

```json
{
  "queried_at": "2026-03-07T10:00:00+00:00",
  "ip": "8.8.8.8",
  "ipapi": {
    "country": "United States",
    "region": "Virginia",
    "city": "Ashburn",
    "isp": "Google LLC",
    "org": "Google Public DNS",
    "asn": "AS15169 Google LLC"
  },
  "shodan": {
    "org": "Google LLC",
    "isp": "Google LLC",
    "country": "United States",
    "open_ports": [53, 443],
    "services": [
      { "port": 53, "transport": "udp", "product": null, "version": null },
      { "port": 443, "transport": "tcp", "product": "nginx", "version": "1.14.0" }
    ],
    "hostnames": ["dns.google"],
    "tags": [],
    "vulns": []
  },
  "abuseipdb": {
    "abuse_confidence": 0,
    "total_reports": 53,
    "country": "US",
    "domain": "google.com",
    "isp": "Google LLC",
    "usage_type": "Search Engine Spider",
    "last_reported_at": "2024-10-15",
    "is_tor": false,
    "is_whitelisted": true
  },
  "virustotal": {
    "malicious": 0,
    "suspicious": 0,
    "harmless": 59,
    "undetected": 35,
    "last_analysis_date": "2026-03-06"
  },
  "otx": { "pulse_count": 0, "pulse_names": [] },
  "greynoise": {
    "noise": false,
    "riot": true,
    "classification": "benign",
    "name": "Google Public DNS",
    "last_seen": "2026-03-07"
  },
  "threatfox": { "ioc_count": 0, "iocs": [] }
}
```

Unavailable sources appear as `null`. Bulk output (`--file`) is a JSON array.

### Pipe JSON to jq

```bash
scope-recon 1.2.3.4 --json | jq '.virustotal.malicious'
scope-recon 1.2.3.4 --json | jq '.otx.pulse_names'
scope-recon 1.2.3.4 --json | jq '.threatfox.iocs[].malware'
scope-recon 1.2.3.4 --json | jq '.shodan.services[] | "\(.port)/\(.transport) \(.product // "-")"'
scope-recon 1.2.3.4 --json | jq '{ip, verdict: (if .virustotal.malicious > 0 then "MALICIOUS" else "CLEAN" end)}'
```

## Error Handling

| Situation | Behavior |
|---|---|
| API key env var not set | Source shown as `[source unavailable]`; reason shown with `--verbose` |
| API returns non-2xx | Source shown as `[source unavailable]`; reason shown with `--verbose` |
| API returns 429 (rate limited) | Waits 2s and retries once; warns to stderr |
| Network timeout / DNS failure | Source shown as `[source unavailable]`; tool continues |
| GreyNoise 404 (IP not in dataset) | Shown as `class: not seen` rather than an error |
| ThreatFox no results | Shows `C2 IOCs: 0`, not an error |
| RIPE Stat (IP not announced) | Returns empty result (no prefixes), not an error |
| Pulsedive unknown (IP not in database) | Shows `risk: unknown`, not an error |
| IPinfo without token | Works with shared rate limit (1,000 req/day); privacy fields absent |
| Shodan key not set | Falls back to InternetDB automatically (no key required) |
| Invalid IP or hostname passed | Rejected immediately before any API calls |
| CIDR range exceeds 256 hosts | Rejected with a clear error message |
| Cache entry expired | Silently re-queries all sources |

## Rate Limits (Free Tiers)

| Source | Limit |
|---|---|
| ip-api.com | 45 requests/minute, no key required |
| Shodan InternetDB | No published limit, no key required |
| Shodan (full API) | 1 request/second; free accounts have limited access |
| VirusTotal | 4 requests/minute, 500/day |
| AlienVault OTX | No published hard limit on free tier |
| AbuseIPDB | 1,000 checks/day |
| GreyNoise | Community tier: limited daily lookups |
| ThreatFox | No published limit; free key required |
| RIPE Stat | No published limit; no key required |
| IPQualityScore | 1,000 lookups/month (free tier) |
| Pulsedive | 250 requests/day (free tier) |
| IPinfo | 1,000 req/day unauthenticated; 50,000/month with free token |

## Project Structure

```
scope-recon/
├── Cargo.toml
└── src/
    ├── main.rs           # CLI dispatch, TUI mode detection, bulk/CIDR expansion,
    │                     # cache integration, concurrent query orchestration, tests
    ├── cli.rs            # Clap CLI struct and all flags
    ├── model.rs          # ThreatReport and all summary structs (Serialize + Deserialize)
    ├── cache.rs          # On-disk cache load/save with TTL, tests
    ├── output.rs         # pretty_print(), json_print(), compute_verdict()
    ├── tui/
    │   ├── mod.rs        # run_tui(), terminal setup/teardown, tokio::select! event loop,
    │   │                 # spawn_queries() — one task per source
    │   ├── app.rs        # App state, SourceState<T>, SourceUpdate, handle_key(), apply_update()
    │   └── ui.rs         # render() — header, source list, detail pane, footer
    └── api/
        ├── mod.rs
        ├── retry.rs      # Generic 429-aware retry wrapper
        ├── ipapi.rs      # ip-api.com geolocation (no key)
        ├── shodan.rs     # Shodan full API — open ports, service banners, CVEs
        ├── internetdb.rs # Shodan InternetDB fallback (no key), tests
        ├── abuseipdb.rs  # AbuseIPDB abuse score, usage type, report history
        ├── virustotal.rs # VirusTotal vendor consensus, last analysis date
        ├── otx.rs        # AlienVault OTX pulse/campaign correlation
        ├── greynoise.rs  # GreyNoise noise vs. targeted classification
        ├── threatfox.rs  # ThreatFox malware C2 IOC matching (no key)
        ├── bgpview.rs    # BGPView BGP routing, ASN, prefix, PTR (no key)
        ├── ipqs.rs       # IPQualityScore fraud/proxy/VPN/bot detection
        ├── pulsedive.rs  # Pulsedive aggregated risk and threat feeds
        └── ipinfo.rs     # IPinfo hostname, org, timezone, privacy flags
```

## License

MIT
