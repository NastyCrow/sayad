<p align="center">
  <img src="SAYAD_Logo.jpg" alt="Sayad Recon Framework" width="600"/>
</p>

<p align="center">
  <strong>Automated Bug Bounty Reconnaissance Pipeline — Python Edition</strong><br/>
  Feed it a domain. Get a full attack surface map.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python" />
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=flat-square&logo=linux" />
  <img src="https://img.shields.io/badge/LLM-Ollama-black?style=flat-square" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" />
</p>

---

---

## What's New in the Python Edition

| Feature | Bash Version | Python Version |
|---------|-------------|----------------|
| Subdomain sources | Sequential `&` jobs | True `async` — all 14 sources at once |
| JSON parsing | Fragile `grep` | Native `json` — rock solid |
| Resume after crash | ❌ | ✅ Checkpoint after every phase |
| Scan scope control | ❌ | ✅ Choose which targets get deep scanning |
| Terminal output | Basic echo | Rich tables, progress bars, panels |
| API key config | Shell exports only | YAML config file + env var fallback |

---

## Table of Contents

1. [Requirements](#requirements)
2. [Installation](#installation)
3. [API Keys Setup](#api-keys-setup)
4. [Usage](#usage)
5. [Scan Scope Control](#scan-scope-control)
6. [Resume After Interruption](#resume-after-interruption)
7. [All Options](#all-options)
8. [Output Structure](#output-structure)
9. [Pipeline Phases](#pipeline-phases)
10. [Security Notes](#security-notes)
11. [Troubleshooting](#troubleshooting)

---

## Requirements

- Python 3.9+
- Kali Linux (or any Debian-based distro)
- Go 1.21+ (for ProjectDiscovery tools)
- External tools installed via `install_tools.sh`

---

## Installation

### Step 1 — Install Python dependencies

```bash
pip install -r requirements.txt
```

### Step 2 — Install external tools

```bash
chmod +x install_tools.sh && sudo ./install_tools.sh
source ~/.zshrc
```

### Step 3 — Verify

```bash
python3 recon.py --help
```

---

## API Keys Setup

Keys are optional but strongly recommended — they unlock 5 additional sources.

### Option A — Config file (recommended, no exports needed)

```bash
mkdir -p ~/.config/sayad
cat > ~/.config/sayad/config.yaml << 'EOF'
shodan_api_key: "your_key_here"
virustotal_api_key: "your_key_here"
securitytrails_api_key: "your_key_here"
bevigil_api_key: "your_key_here"
leakix_api_key: "your_key_here"
EOF
```

### Option B — Environment variables

```bash
cat >> ~/.zshrc << 'EOF'
export SHODAN_API_KEY="your_key_here"
export VIRUSTOTAL_API_KEY="your_key_here"
export SECURITYTRAILS_API_KEY="your_key_here"
export BEVIGIL_API_KEY="your_key_here"
export LEAKIX_API_KEY="your_key_here"
EOF
source ~/.zshrc
```

> Environment variables take priority over the config file if both are set.

### Where to get free keys

| Service | Free Tier | Sign Up |
|---------|-----------|---------|
| Shodan | Limited free | https://account.shodan.io |
| VirusTotal | 500 req/day | https://virustotal.com/gui/join-us |
| SecurityTrails | 50 req/month | https://securitytrails.com/app/signup |
| BeVigil | Free tier | https://bevigil.com/osint-api |
| LeakIX | Free with signup | https://leakix.net/signup |

> ⚠️ **Never share your API keys.** Never paste them into chat,
> screenshots, or Git commits. If exposed, regenerate immediately.

---

## Usage

```bash
# Quick start
python3 recon.py -d example.com

# Deep mode
python3 recon.py -d example.com --deep

# Resume interrupted scan
python3 recon.py -d example.com --resume

# Suppress API warnings
python3 recon.py -d example.com --no-api-warnings
```

---

## Scan Scope Control

Controls which targets are used for **deep scanning phases**
(URL crawling, parameter discovery, Nuclei).

This matters because running Nuclei or param discovery against every
subdomain can hit out-of-scope targets, trigger WAFs, or get your IP banned.

### `--scan-scope main` *(default — safest)*

Only the root domain is deeply scanned. Best starting point.

```bash
python3 recon.py -d example.com --scan-scope main
```

### `--scan-scope all`

Every discovered live subdomain is deeply scanned.
Use only when the programme explicitly puts all subdomains in scope.

```bash
python3 recon.py -d example.com --scan-scope all
```

### `--scan-scope discovered` *(interactive picker)*

After Phase 2, shows you the discovered live hosts and lets you
choose exactly which ones to deeply scan:

```
  Discovered live hosts:
  ──────────────────────────────────────────────────
  [  1] https://api.example.com
  [  2] https://admin.example.com
  [  3] https://staging.example.com
  [  4] https://mail.example.com
  ──────────────────────────────────────────────────
  [  0] Main domain only  (https://example.com)

  Select targets (e.g. 1,3,5 or 1-10 or 'all' or 0 for main): 1,2
```

```bash
python3 recon.py -d example.com --scan-scope discovered
```

### `--scan-scope <file.txt>` *(custom targets)*

Read targets from a file (one URL per line):

```bash
echo "https://api.example.com"   > targets.txt
echo "https://admin.example.com" >> targets.txt
python3 recon.py -d example.com --scan-scope targets.txt
```

---

## Resume After Interruption

If your terminal crashes, SSH drops, or you press **Ctrl+C** by mistake
— your progress is saved automatically.

### How it works

After every phase completes, `checkpoint.json` is written to the run
directory. On **Ctrl+C**, the signal is caught before exit:

```
──────────────── Interrupted ────────────────
[!] Checkpoint saved → ~/recon/example.com/20260416_093150/checkpoint.json
[+] Resume your scan with:
    python3 recon.py -d example.com --resume
```

### Resuming

```bash
python3 recon.py -d example.com --resume
```

The framework finds the most recent incomplete run automatically:

```
[+] Resumable checkpoint found: ~/recon/example.com/20260416_093150

  Completed phases: phase1, phase2, phase3
  Started:          2026-04-16 09:31:50
  Last saved:       2026-04-16 09:45:12

── PHASE 1 — Skipped (checkpoint) ──
   Loaded 247 subdomains from checkpoint
── PHASE 2 — Skipped (checkpoint) ──
   Loaded 89 live hosts from checkpoint
── PHASE 4 — URL & Endpoint Discovery ──   ← picks up here
```

### What is saved at each phase

| Phase | Data Saved |
|-------|-----------|
| Phase 1 | Full subdomain list |
| Phase 2 | Live host list |
| Phase 3+ | Completion flags |

---

## All Options

```
Usage: python3 recon.py -d <domain> [options]

Required:
  -d, --domain <domain>       Target domain (e.g. example.com)

Options:
  -o, --output <dir>          Output directory         (default: ~/recon)
  -t, --threads <n>           Thread count             (default: 50)
  -s, --severity <levels>     Nuclei severity filter   (default: low,medium,high,critical)
  --deep                      Deep mode: Amass active + full 5000-port scan
  --resume                    Resume from last checkpoint
  --scan-scope <mode>         Scope for deep phases:
                                main        — root domain only (default)
                                all         — all live subdomains
                                discovered  — interactive selection
                                <file.txt>  — custom targets file
  --skip-nuclei               Skip Nuclei scanning
  --skip-portscan             Skip port scanning
  --skip-crawl                Skip URL crawling
  --no-api-warnings           Suppress missing API key warnings
  -h, --help                  Show help
```

---

## Output Structure

```
~/recon/
└── example.com/
    └── 20260416_093150/
        ├── checkpoint.json             ← resume state (auto-managed)
        ├── scope_targets.txt           ← targets used for deep scan
        ├── subdomains/
        │   ├── crtsh.txt
        │   ├── wayback.txt
        │   ├── subfinder.txt
        │   ├── virustotal.txt          (if key set)
        │   ├── shodan.txt              (if key set)
        │   └── all_subdomains.txt      ← merged & deduped
        ├── hosts/
        │   ├── resolved.txt
        │   ├── live_urls.txt
        │   └── live_hosts.json
        ├── urls/
        │   ├── all_urls.txt
        │   └── interesting_endpoints.txt
        ├── ports/
        │   └── nmap_scan.*
        ├── nuclei/
        │   ├── findings.txt
        │   ├── findings.json
        │   └── critical_high.txt
        ├── js/
        │   ├── potential_secrets.txt
        │   └── js_endpoints.txt
        ├── params/
        │   └── discovered_params.txt
        └── reports/
            └── summary.md
```

---

## Pipeline Phases

| # | Phase | Tools | Respects Scope? |
|---|-------|-------|----------------|
| 1 | Subdomain Enumeration | 14 async sources | — |
| 2 | Live Host Probing | dnsx, httpx | — |
| 3 | Port Scanning | nmap | — |
| 4 | URL Discovery | gau, waybackurls, katana | ✅ Yes |
| 5 | Parameter Discovery | paramspider | ✅ Yes |
| 6 | Vulnerability Scanning | nuclei | ✅ Yes |
| 7 | JS Secret Analysis | regex + download | — |
| 8 | Report | — | — |

---

## Security Notes

- **Only test targets you are authorised to scan.**
- Use `--scan-scope main` (default) until you have confirmed which
  subdomains are in scope for the programme.
- Nuclei sends active HTTP requests — use `--skip-nuclei` for passive-only recon.
- Keep your API keys in `~/.config/sayad/config.yaml`. Never commit
  that file to Git — add it to `.gitignore`.

---

## Troubleshooting

### Missing Python dependencies
```bash
pip install -r requirements.txt
```

### Go tools not found after install
```bash
export PATH=$PATH:$HOME/go/bin && source ~/.zshrc
```

### `--resume` says no checkpoint found
The previous run either completed fully or was cancelled before Phase 1
finished. Start a fresh run without `--resume`.

### crt.sh / Wayback returning 0 results
External services can be rate-limited or temporarily down.
Wait a few minutes and retry, or run with `--resume` to skip Phase 1.

---

*Sayad Recon Framework — Python Edition*
