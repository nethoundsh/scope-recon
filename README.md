# scope-recon

A fast Rust CLI tool that queries multiple threat intelligence sources concurrently for a given IP address and prints a unified threat summary to the terminal.

## Features

- Seven concurrent API lookups with no sequential waiting
- Synthesized **SUMMARY** verdict (CLEAN / SUSPICIOUS / MALICIOUS) at the top of every report
- Graceful degradation — missing keys or failed sources show `[source unavailable]`, the rest still display
- Color-coded verdicts across all sources
- `--json` flag for machine-readable output
- No API key required for geolocation (ip-api.com) or C2 lookups (ThreatFox)

## API Sources

| Phase | Source | Purpose | Key Required |
|---|---|---|---|
| 1 | [ip-api.com](http://ip-api.com) | Geolocation, ASN, ISP | No |
| 1 | [Shodan](https://shodan.io) | Open ports, service banners, CVEs | Yes |
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

ip-api.com and ThreatFox require no account or key.

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
scope-recon <IP> [OPTIONS]

Arguments:
  <IP>    IP address to investigate

Options:
      --json    Output as JSON instead of pretty-printed table
  -h, --help    Print help
```

### Pretty-printed output (default)

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

### SUMMARY verdict logic

The verdict is derived from all available sources:

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

If a source is unavailable (no API key, network error, invalid IP), it shows `[source unavailable]` and the rest of the report continues normally.

### JSON output

```bash
scope-recon 8.8.8.8 --json
```

```json
{
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
  "otx": {
    "pulse_count": 0,
    "pulse_names": []
  },
  "greynoise": {
    "noise": false,
    "riot": true,
    "classification": "benign",
    "name": "Google Public DNS",
    "last_seen": "2026-03-07"
  },
  "threatfox": {
    "ioc_count": 0,
    "iocs": []
  }
}
```

Unavailable sources appear as `null` in JSON output.

### Pipe JSON to jq

```bash
scope-recon 1.2.3.4 --json | jq '.virustotal.malicious'
scope-recon 1.2.3.4 --json | jq '.otx.pulse_names'
scope-recon 1.2.3.4 --json | jq '.threatfox.iocs[].malware'
scope-recon 1.2.3.4 --json | jq '.shodan.services[] | "\(.port)/\(.transport) \(.product // "-")"'
```

## Error Handling

| Situation | Behavior |
|---|---|
| API key env var not set | Source shown as `[source unavailable]`, tool continues |
| API returns non-2xx | Source shown as `[source unavailable]`, tool continues |
| Network timeout / DNS failure | Source shown as `[source unavailable]`, tool continues |
| GreyNoise 404 (IP not in dataset) | Shown as `class: not seen` rather than an error |
| ThreatFox no results | Shows `C2 IOCs: 0`, not an error |
| Invalid IP address | APIs reject it; affected sources shown as `[source unavailable]` |

## Rate Limits (Free Tiers)

| Source | Limit |
|---|---|
| ip-api.com | 45 requests/minute, no key required |
| Shodan | 1 request/second; free accounts have limited host lookup access |
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
    ├── main.rs           # Entry point, env var collection, tokio::join!, output dispatch
    ├── cli.rs            # Clap CLI struct
    ├── model.rs          # ThreatReport and all summary structs
    ├── output.rs         # pretty_print(), json_print(), verdict computation
    └── api/
        ├── mod.rs
        ├── ipapi.rs      # ip-api.com geolocation (no key)
        ├── shodan.rs     # Shodan open ports, service banners, CVEs
        ├── abuseipdb.rs  # AbuseIPDB abuse score, usage type, report history
        ├── virustotal.rs # VirusTotal vendor consensus, last analysis date
        ├── otx.rs        # AlienVault OTX pulse/campaign correlation
        ├── greynoise.rs  # GreyNoise noise vs. targeted classification
        └── threatfox.rs  # ThreatFox malware C2 IOC matching (no key)
```

## License

MIT
