# Sayyad Recon Framework

> Automated Bug Bounty Reconnaissance Pipeline  
> Feed it a domain — get a full attack surface map.

---

## Table of Contents

1. [Requirements](#requirements)
2. [Installation](#installation)
3. [API Keys Setup](#api-keys-setup)
4. [Usage](#usage)
5. [All Options](#all-options)
6. [Output Structure](#output-structure)
7. [Pipeline Phases](#pipeline-phases)
8. [Examples](#examples)
9. [Security Notes](#security-notes)
10. [Troubleshooting](#troubleshooting)

---

## Requirements

- Kali Linux (or any Debian-based distro)
- `bash` 4+
- `python3` (pre-installed on Kali)
- `curl`, `git`, `nmap` (pre-installed on Kali)
- Go 1.21+ (for ProjectDiscovery tools)

---

## Installation

### Step 1 — Clone or copy the framework

```bash
git clone https://github.com/yourname/sayyad-recon.git
cd sayyad-recon
chmod +x recon.sh install_tools.sh
```

### Step 2 — Install all required tools

```bash
sudo ./install_tools.sh
```

This installs: `subfinder`, `httpx`, `dnsx`, `nuclei`, `katana`, `gau`,
`waybackurls`, `dalfox`, `ffuf`, `paramspider`, `assetfinder`, `amass`, `shodan CLI`

### Step 3 — Reload your shell

```bash
source ~/.zshrc
# or
source ~/.bashrc
```

### Step 4 — Verify tools are ready

```bash
for tool in subfinder httpx dnsx nuclei katana gau waybackurls nmap; do
  command -v "$tool" &>/dev/null && echo "✓ $tool" || echo "✗ $tool MISSING"
done
```

---

## API Keys Setup

API keys are **optional but strongly recommended** — they unlock additional
subdomain sources and significantly improve coverage.

| Service | Free Tier | Sign Up |
|---------|-----------|---------|
| **Shodan** | Limited free | https://account.shodan.io |
| **VirusTotal** | 500 req/day | https://virustotal.com/gui/join-us |
| **SecurityTrails** | 50 req/month | https://securitytrails.com/app/signup |
| **BeVigil** | Free tier | https://bevigil.com/osint-api |
| **LeakIX** | Free with signup | https://leakix.net/signup |

### Set keys permanently

Add to your shell profile (`~/.zshrc` on Kali):

```bash
cat >> ~/.zshrc << 'EOF'

# Sayyad Recon — API Keys
export SHODAN_API_KEY="your_key_here"
export VIRUSTOTAL_API_KEY="your_key_here"
export SECURITYTRAILS_API_KEY="your_key_here"
export BEVIGIL_API_KEY="your_key_here"
export LEAKIX_API_KEY="your_key_here"
EOF

source ~/.zshrc
```

### Verify keys are loaded

```bash
env | grep -E "SHODAN|VIRUSTOTAL|SECURITYTRAILS|BEVIGIL|LEAKIX"
```

> ⚠️ **Never share your API keys.** Never paste them into chat, screenshots,
> or commit them to Git. If exposed, regenerate them immediately on the
> provider's website.

### Running as root (important on Kali)

If you run the script with `sudo`, your user environment variables may be
stripped. Use `-E` to preserve them:

```bash
sudo -E ./recon.sh -d target.com
```

Or simply run as root directly (common on Kali):

```bash
# Add keys to /root/.zshrc instead of /home/user/.zshrc
cat >> /root/.zshrc << 'EOF'
export SHODAN_API_KEY="your_key_here"
...
EOF
source /root/.zshrc
```

---

## Usage

### Basic

```bash
./recon.sh -d example.com
```

### Deep mode (full active scan + broader port coverage)

```bash
./recon.sh -d example.com --deep
```

### Custom output directory

```bash
./recon.sh -d example.com -o /opt/recon
```

### Suppress API key warnings (for clean output when keys aren't needed)

```bash
./recon.sh -d example.com --no-api-warnings
```

---

## All Options

```
Usage: ./recon.sh -d <domain> [options]

Required:
  -d <domain>           Target domain (e.g. example.com)

Options:
  -o <dir>              Output directory         (default: ~/recon)
  -t <threads>          Thread count             (default: 50)
  -s <severity>         Nuclei severity filter   (default: low,medium,high,critical)
  --deep                Deep mode: Amass active + full 5000-port scan
  --skip-nuclei         Skip Nuclei vulnerability scanning
  --skip-portscan       Skip Nmap port scanning
  --skip-crawl          Skip URL/endpoint crawling
  --no-api-warnings     Suppress missing API key warnings
  -h, --help            Show help message
```

---

## Output Structure

Every run creates a timestamped folder:

```
~/recon/
└── example.com/
    └── 20260416_093150/
        ├── subdomains/
        │   ├── subfinder.txt       — Subfinder results
        │   ├── assetfinder.txt     — Assetfinder results
        │   ├── crtsh.txt           — Certificate transparency
        │   ├── wayback.txt         — Wayback Machine historical
        │   ├── otx.txt             — AlienVault OTX passive DNS
        │   ├── hackertarget.txt    — HackerTarget results
        │   ├── rapiddns.txt        — RapidDNS results
        │   ├── urlscan.txt         — URLScan.io results
        │   ├── shodan.txt          — Shodan DNS (if key set)
        │   ├── virustotal.txt      — VirusTotal (if key set)
        │   └── all_subdomains.txt  — Merged & deduplicated
        ├── hosts/
        │   ├── resolved.txt        — DNS-resolved subdomains
        │   ├── live_urls.txt       — Live HTTP/HTTPS hosts
        │   └── live_hosts.json     — httpx full JSON (titles, techs, status)
        ├── urls/
        │   ├── gau.txt             — Historical URLs (GAU)
        │   ├── wayback.txt         — Wayback URLs
        │   ├── katana.txt          — Crawled endpoints
        │   ├── all_urls.txt        — Merged unique URLs
        │   └── interesting_endpoints.txt — API/admin/auth/upload paths
        ├── ports/
        │   ├── target_ips.txt      — IPs scanned
        │   └── nmap_scan.*         — Nmap results (txt, xml, gnmap)
        ├── nuclei/
        │   ├── findings.txt        — All vulnerability findings
        │   ├── findings.json       — Machine-readable findings
        │   └── critical_high.txt   — Critical & high severity only
        ├── js/
        │   ├── js_files.txt        — Discovered JS file URLs
        │   ├── files/              — Downloaded JS files
        │   ├── potential_secrets.txt — API keys / tokens found in JS
        │   └── js_endpoints.txt    — API endpoints extracted from JS
        ├── params/
        │   ├── paramspider.txt     — ParamSpider results
        │   └── discovered_params.txt — Parameters from all URLs
        ├── osint/
        │   └── theharvester.*      — theHarvester output
        └── reports/
            ├── summary.md          — Human-readable summary report
            └── recon.log           — Full timestamped run log
```

---

## Pipeline Phases

| # | Phase | Tools Used | What It Finds |
|---|-------|-----------|---------------|
| 1 | Subdomain Enumeration | subfinder, assetfinder, crt.sh, Wayback, OTX, HackerTarget, RapidDNS, URLScan, ThreatCrowd, Shodan*, VT*, ST*, BeVigil*, LeakIX* | All subdomains across 14 sources |
| 2 | DNS & Live Host Probing | dnsx, httpx | Which subdomains are alive, their tech stack, status codes |
| 3 | Port Scanning | nmap | Open ports and services on resolved IPs |
| 4 | URL & Endpoint Discovery | gau, waybackurls, katana | All URLs, JS files, API paths, admin panels |
| 5 | Parameter Discovery | paramspider, regex extraction | URL parameters across all endpoints |
| 6 | Vulnerability Scanning | nuclei | Template-based CVEs, misconfigs, exposures |
| 7 | JS Secret Analysis | curl + regex | API keys, tokens, secrets in JavaScript files |
| 8 | Report Generation | — | Markdown summary with stats and top findings |

`*` = requires API key

---

## Examples

### Quick scan of a bug bounty target

```bash
./recon.sh -d hackerone.com
```

### Full deep scan, custom output, only critical findings

```bash
./recon.sh -d bugcrowd.com --deep -o /opt/recon -s critical
```

### Scan without port scanning (faster, stealthier)

```bash
./recon.sh -d target.com --skip-portscan
```

### Suppress API warnings (clean output for demo/sharing)

```bash
./recon.sh -d target.com --no-api-warnings
```

### Chain with AI analysis (feed output to Claude)

After the scan, drop these files into Claude for AI-assisted triage:
- `interesting_endpoints.txt` → ask for attack surface analysis
- `potential_secrets.txt` → ask for validation and severity triage
- `live_hosts.json` → ask which tech stacks deserve deeper testing
- `nuclei/findings.txt` → ask for exploitability assessment

---

## Security Notes

- **Only scan targets you are authorised to test.** Always verify scope in
  the programme's policy before running.
- **API keys are sensitive credentials.** Store them only in your shell
  profile. Never paste them into chat, emails, screenshots, or Git commits.
  If exposed, regenerate immediately.
- **Rate limiting is built in** (`--rate-limit 150` by default) to avoid
  triggering WAFs or getting your IP banned mid-scan.
- Nuclei scanning is **active** — it sends HTTP requests to live targets.
  Use `--skip-nuclei` if you want passive-only recon.

---

## Troubleshooting

### Go tools not found after install

```bash
export PATH=$PATH:$HOME/go/bin
source ~/.zshrc
```

### API keys not being read by the script

```bash
# Check they are exported (not just set)
env | grep API_KEY

# If missing, reload your profile
source ~/.zshrc

# If running with sudo, use -E flag
sudo -E ./recon.sh -d target.com
```

### crt.sh / Wayback returning 0 results

These are external services that can be rate-limited or temporarily down.
Wait a few minutes and retry, or check if the domain is very new.

### httpx errors

Usually means the live_urls.txt is empty (no resolved subdomains). Check
that Phase 1 found results and `dnsx` is installed.

### Nuclei skipped

Install with:
```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

---

*Sayyad Recon Framework — Built for Bug Bounty Hunters*
