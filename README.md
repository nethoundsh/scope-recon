# scope-recon

A fast CLI tool that queries **Shodan** and **AbuseIPDB** concurrently for a given IP address and prints a unified threat summary to the terminal.

## Features

- Concurrent API lookups (no sequential waiting)
- Graceful degradation — if one source fails, the other still displays
- Color-coded abuse confidence score (green / yellow / red)
- `--json` flag for machine-readable output
- Clear error messages for missing configuration

## Installation

### Prerequisites

- [Rust](https://rustup.rs/) 1.70 or later

### Build from source

```bash
git clone https://github.com/youruser/scope-recon
cd scope-recon
cargo build --release
```

The compiled binary will be at `target/release/scope-recon`. Optionally move it to your PATH:

```bash
cp target/release/scope-recon ~/.local/bin/
```

## API Keys

You need free accounts for both services:

| Service | Sign-up | Key type |
|---|---|---|
| Shodan | https://account.shodan.io/register | API Key (free tier available) |
| AbuseIPDB | https://www.abuseipdb.com/register | API Key (free tier: 1,000 checks/day) |

Export the keys in your shell before running:

```bash
export SHODAN_API_KEY=your_shodan_key_here
export ABUSEIPDB_API_KEY=your_abuseipdb_key_here
```

Or add them to your shell profile (`~/.bashrc`, `~/.zshrc`, etc.) to persist across sessions.

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

SHODAN
  Org:          Google LLC
  ISP:          Google LLC
  Country:      United States
  Open Ports:   53, 443
  Hostnames:    dns.google
  Tags:         cloud
  Vulns:        -

ABUSEIPDB
  Abuse Score:  0/100  [LOW]
  Reports:      0
  Country:      US
  Domain:       google.com
  ISP:          Google LLC
  Tor Exit:     No
  Whitelisted:  No
```

The abuse score is color-coded:
- **Green** — 0–24 (LOW)
- **Yellow** — 25–74 (MEDIUM)
- **Red** — 75–100 (HIGH)

If a source is unavailable (network error, invalid IP, API error), it shows `[source unavailable]` rather than crashing.

### JSON output

```bash
scope-recon 8.8.8.8 --json
```

```json
{
  "ip": "8.8.8.8",
  "shodan": {
    "org": "Google LLC",
    "isp": "Google LLC",
    "country": "United States",
    "open_ports": [53, 443],
    "hostnames": ["dns.google"],
    "tags": ["cloud"],
    "vulns": []
  },
  "abuseipdb": {
    "abuse_confidence": 0,
    "total_reports": 0,
    "country": "US",
    "domain": "google.com",
    "isp": "Google LLC",
    "is_tor": false,
    "is_whitelisted": false
  }
}
```

A missing source will appear as `null` in the JSON:

```json
{
  "ip": "999.999.999.999",
  "shodan": null,
  "abuseipdb": null
}
```

### One-shot invocation (without exporting)

```bash
SHODAN_API_KEY=abc ABUSEIPDB_API_KEY=xyz scope-recon 1.2.3.4
```

### Pipe JSON to jq

```bash
scope-recon 1.2.3.4 --json | jq '.abuseipdb.abuse_confidence'
```

## Error Handling

| Situation | Behavior |
|---|---|
| `SHODAN_API_KEY` not set | Exits immediately with a clear error message |
| `ABUSEIPDB_API_KEY` not set | Exits immediately with a clear error message |
| API returns non-2xx | Source shown as `[source unavailable]`, tool continues |
| Network timeout / DNS failure | Source shown as `[source unavailable]`, tool continues |
| Invalid IP address | APIs reject it; both sources shown as `[source unavailable]` |

## Rate Limits

- **Shodan free tier**: 1 query/second, no monthly cap on host lookups with a paid plan. Free accounts have limited access.
- **AbuseIPDB free tier**: 1,000 checks per day. Results are cached for 90 days per the `maxAgeInDays=90` query parameter used by this tool.

## Project Structure

```
scope-recon/
├── Cargo.toml
└── src/
    ├── main.rs          # Entry point, CLI parsing, tokio::join!, output dispatch
    ├── cli.rs           # Clap CLI struct
    ├── model.rs         # ThreatReport, ShodanSummary, AbuseIPDBSummary
    ├── output.rs        # pretty_print() and json_print()
    └── api/
        ├── mod.rs
        ├── shodan.rs    # Shodan API client
        └── abuseipdb.rs # AbuseIPDB API client
```

## License

MIT
