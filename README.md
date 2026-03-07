# scope-recon

A fast Rust CLI tool that queries multiple threat intelligence sources concurrently for a given IP address and prints a unified threat summary to the terminal.

## Features

- Seven concurrent API lookups with no sequential waiting
- Synthesized **SUMMARY** verdict (CLEAN / SUSPICIOUS / MALICIOUS) at the top of every report
- Graceful degradation — missing keys or failed sources show `[source unavailable]`, the rest still display
- `--verbose` flag reveals exactly why each source failed
- `--only` flag to query a subset of sources for speed
- `--no-color` flag for clean file output
- `--output` to write results directly to a file
- Bulk mode via `--file ips.txt` — processes a list of IPs/CIDRs with rate-limit courtesy delays
- CIDR range support — `scope-recon 10.0.0.0/28` expands and queries each host (max 256)
- On-disk caching under `~/.cache/scope-recon/` with configurable TTL
- Shodan InternetDB fallback when no Shodan API key is set (free, no key required)
- `queried_at` timestamp on every report for audit trails and cache freshness checks
- `--json` flag for machine-readable output; bulk JSON output is a JSON array
- No API key required for geolocation (ip-api.com), C2 lookups (ThreatFox), or basic port data (Shodan InternetDB)

## API Sources

| Phase | Source | Purpose | Key Required |
|---|---|---|---|
| 1 | [ip-api.com](http://ip-api.com) | Geolocation, ASN, ISP | No |
| 1 | [Shodan](https://shodan.io) | Open ports, service banners, CVEs | No (InternetDB fallback) / Yes (full) |
| 2 | [VirusTotal](https://virustotal.com) | Vendor reputation consensus | Yes |
| 2 | [AlienVault OTX](https://otx.alienvault.com) | Threat campaigns, pulse correlation | Yes |
| 2 | [AbuseIPDB](https://www.abuseipdb.com) | Abuse confidence score, report history | Yes |
| 3 | [GreyNoise](https://greynoise.io) | Internet noise vs. targeted activity | Optional |
| 3 | [ThreatFox](https://threatfox.abuse.ch) | Malware C2 IOC matching | No |

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

ip-api.com and ThreatFox require no account or key. Shodan will fall back to InternetDB (ports, hostnames, tags, vulns — no service banners) if `SHODAN_API_KEY` is not set.

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

```
IP: 8.8.8.8
══════════════════════════════════

SUMMARY
  Verdict:         CLEAN
  Findings:        whitelisted on AbuseIPDB · benign per GreyNoise · 0 VT detections

══════════════════════════════════

GEOLOCATION  (ip-api.com)
  Country:         United States
  Region:          Virginia
  City:            Ashburn
  ISP:             Google LLC
  Org:             Google Public DNS
  ASN:             AS15169 Google LLC

SHODAN
  Org:             Google LLC
  ISP:             Google LLC
  Country:         United States
  Hostnames:       dns.google
  Tags:            -
  Vulns:           -
  Services:
    53/udp     -
    443/tcp    nginx 1.14.0

ABUSEIPDB
  Abuse Score:     0/100  [LOW]
  Reports:         53
  Last Reported:   2024-10-15
  Usage Type:      Search Engine Spider
  Country:         US
  Domain:          google.com
  ISP:             Google LLC
  Tor Exit:        No
  Whitelisted:     Yes

VIRUSTOTAL
  0 malicious / 0 suspicious / 59 harmless / 35 undetected
  Last Scanned:    2026-03-06

ALIENVAULT OTX
  Pulses:          0

GREYNOISE
  Noise:           No
  RIOT:            Yes
  Class:           benign
  Actor:           Google Public DNS
  Last Seen:       2026-03-07

THREATFOX  (abuse.ch)
  C2 IOCs:         0
```

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
| ThreatFox | No published limit; no key required |

## Project Structure

```
scope-recon/
├── Cargo.toml
└── src/
    ├── main.rs           # CLI dispatch, bulk/CIDR expansion, cache integration,
    │                     # concurrent query orchestration, tests
    ├── cli.rs            # Clap CLI struct and all flags
    ├── model.rs          # ThreatReport and all summary structs (Serialize + Deserialize)
    ├── cache.rs          # On-disk cache load/save with TTL, tests
    ├── output.rs         # pretty_print(), json_print(), verdict computation
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
        └── threatfox.rs  # ThreatFox malware C2 IOC matching (no key)
```

## License

MIT
