# scope-recon

A fast Rust CLI tool that queries multiple threat intelligence sources concurrently for a given IP address and prints a unified threat summary to the terminal.

## Features

- Six concurrent API lookups with no sequential waiting
- Graceful degradation — missing keys or failed sources show `[source unavailable]`, the rest still display
- Color-coded verdicts (VirusTotal, AbuseIPDB, GreyNoise)
- `--json` flag for machine-readable output
- No API key required for geolocation (ip-api.com free tier)

## API Sources

Sources are organized by integration phase. The tool always attempts all configured sources in parallel.

| Phase | Source | Purpose | Key Required |
|---|---|---|---|
| 1 | [ip-api.com](http://ip-api.com) | Geolocation, ASN, ISP | No |
| 1 | [Shodan](https://shodan.io) | Open ports, banners, CVEs | Yes |
| 2 | [VirusTotal](https://virustotal.com) | Vendor reputation consensus | Yes |
| 2 | [AlienVault OTX](https://otx.alienvault.com) | Threat campaigns, pulse correlation | Yes |
| 2 | [AbuseIPDB](https://www.abuseipdb.com) | Abuse confidence score, report history | Yes |
| 3 | [GreyNoise](https://greynoise.io) | Internet noise vs. targeted activity | Optional |

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

GEOLOCATION  (ip-api.com)
  Country:       United States
  Region:        California
  City:          Mountain View
  ISP:           Google LLC
  Org:           Google LLC
  ASN:           AS15169 Google LLC

SHODAN
  Org:           Google LLC
  ISP:           Google LLC
  Country:       United States
  Open Ports:    53, 443
  Hostnames:     dns.google
  Tags:          cloud
  Vulns:         -

ABUSEIPDB
  Abuse Score:   0/100  [LOW]
  Reports:       0
  Country:       US
  Domain:        google.com
  ISP:           Google LLC
  Tor Exit:      No
  Whitelisted:   No

VIRUSTOTAL
  0 malicious / 0 suspicious / 90 harmless / 5 undetected

ALIENVAULT OTX
  Pulses:        0

GREYNOISE
  Noise:         No
  RIOT:          Yes
  Class:         benign
  Actor:         Google DNS
  Last Seen:     2024-11-01
```

**Color coding:**
- VirusTotal: red if any malicious detections, yellow if suspicious only, green if clean
- AbuseIPDB score: green (0–24 LOW), yellow (25–74 MEDIUM), red (75–100 HIGH)
- GreyNoise classification: green (benign), red (malicious), yellow (unknown), dimmed (not seen)
- OTX pulses: green if 0, yellow/bold if any found

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
    "region": "California",
    "city": "Mountain View",
    "isp": "Google LLC",
    "org": "Google LLC",
    "asn": "AS15169 Google LLC"
  },
  "shodan": { ... },
  "abuseipdb": { ... },
  "virustotal": {
    "malicious": 0,
    "suspicious": 0,
    "harmless": 90,
    "undetected": 5
  },
  "otx": {
    "pulse_count": 0,
    "pulse_names": []
  },
  "greynoise": {
    "noise": false,
    "riot": true,
    "classification": "benign",
    "name": "Google DNS",
    "last_seen": "2024-11-01"
  }
}
```

Unavailable sources appear as `null` in JSON output.

### One-shot invocation

```bash
SHODAN_API_KEY=abc VIRUSTOTAL_API_KEY=xyz scope-recon 1.2.3.4
```

### Pipe JSON to jq

```bash
scope-recon 1.2.3.4 --json | jq '.virustotal.malicious'
scope-recon 1.2.3.4 --json | jq '.otx.pulse_names'
```

## Error Handling

| Situation | Behavior |
|---|---|
| API key env var not set | Source shown as `[source unavailable]`, tool continues |
| API returns non-2xx | Source shown as `[source unavailable]`, tool continues |
| Network timeout / DNS failure | Source shown as `[source unavailable]`, tool continues |
| GreyNoise 404 (IP not in dataset) | Shown as `classification: not seen` |
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

## Project Structure

```
scope-recon/
├── Cargo.toml
└── src/
    ├── main.rs          # Entry point, env var collection, tokio::join!, output dispatch
    ├── cli.rs           # Clap CLI struct
    ├── model.rs         # ThreatReport and all summary structs
    ├── output.rs        # pretty_print() and json_print()
    └── api/
        ├── mod.rs
        ├── ipapi.rs     # ip-api.com geolocation (no key)
        ├── shodan.rs    # Shodan open ports + CVEs
        ├── abuseipdb.rs # AbuseIPDB abuse score
        ├── virustotal.rs # VirusTotal vendor consensus
        ├── otx.rs       # AlienVault OTX pulse/campaign correlation
        └── greynoise.rs # GreyNoise noise vs. targeted classification
```

## License

MIT
