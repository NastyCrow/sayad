#!/bin/bash
# ============================================================
#  SAYAD RECON FRAMEWORK
#  Automated Reconnaissance Pipeline for Bug Bounty Hunting
#  Usage: ./recon.sh -d example.com [OPTIONS]
# ============================================================

set -euo pipefail

# ── Colors ───────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Defaults ─────────────────────────────────────────────────
DOMAIN=""
OUTPUT_BASE="$HOME/recon"
THREADS=50
NUCLEI_SEVERITY="low,medium,high,critical"
SKIP_NUCLEI=false
SKIP_PORTSCAN=false
SKIP_CRAWL=false
DEEP_MODE=false
RATE_LIMIT=150
SUPPRESS_API_WARN=false

# ── API Keys (loaded from environment — never hardcode here) ──
SHODAN_API_KEY="${SHODAN_API_KEY:-}"
VIRUSTOTAL_API_KEY="${VIRUSTOTAL_API_KEY:-}"
SECURITYTRAILS_API_KEY="${SECURITYTRAILS_API_KEY:-}"
BEVIGIL_API_KEY="${BEVIGIL_API_KEY:-}"
LEAKIX_API_KEY="${LEAKIX_API_KEY:-}"

# ── Usage ─────────────────────────────────────────────────────
usage() {
  echo -e ""
  echo -e "${BOLD}${CYAN}  Sayad Recon Framework${RESET}"
  echo -e "  Automated Bug Bounty Reconnaissance Pipeline"
  echo -e ""
  echo -e "${BOLD}Usage:${RESET}"
  echo -e "  $0 -d <domain> [options]"
  echo -e ""
  echo -e "${BOLD}Required:${RESET}"
  echo -e "  ${CYAN}-d <domain>${RESET}          Target domain (e.g. example.com)"
  echo -e ""
  echo -e "${BOLD}Options:${RESET}"
  echo -e "  ${CYAN}-o <dir>${RESET}             Output directory         (default: ~/recon)"
  echo -e "  ${CYAN}-t <threads>${RESET}         Thread count             (default: 50)"
  echo -e "  ${CYAN}-s <severity>${RESET}        Nuclei severity filter   (default: low,medium,high,critical)"
  echo -e "  ${CYAN}--deep${RESET}               Deep mode: Amass active + full port scan"
  echo -e "  ${CYAN}--skip-nuclei${RESET}        Skip Nuclei vulnerability scanning"
  echo -e "  ${CYAN}--skip-portscan${RESET}      Skip Nmap port scanning"
  echo -e "  ${CYAN}--skip-crawl${RESET}         Skip URL/endpoint crawling"
  echo -e "  ${CYAN}--no-api-warnings${RESET}    Suppress missing API key warnings"
  echo -e "  ${CYAN}-h, --help${RESET}           Show this help message"
  echo -e ""
  echo -e "${BOLD}API Keys (optional — set in your shell profile):${RESET}"
  echo -e "  ${YELLOW}export SHODAN_API_KEY=\"xxxx\"${RESET}"
  echo -e "  ${YELLOW}export VIRUSTOTAL_API_KEY=\"xxxx\"${RESET}"
  echo -e "  ${YELLOW}export SECURITYTRAILS_API_KEY=\"xxxx\"${RESET}"
  echo -e "  ${YELLOW}export BEVIGIL_API_KEY=\"xxxx\"${RESET}"
  echo -e "  ${YELLOW}export LEAKIX_API_KEY=\"xxxx\"${RESET}"
  echo -e ""
  echo -e "${BOLD}Examples:${RESET}"
  echo -e "  $0 -d hackerone.com"
  echo -e "  $0 -d hackerone.com --deep"
  echo -e "  $0 -d hackerone.com --skip-portscan --no-api-warnings"
  echo -e "  $0 -d hackerone.com -o /tmp/recon -t 100 -s high,critical"
  echo -e ""
  exit 0
}

# ── Argument Parsing ──────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d) DOMAIN="$2"; shift 2 ;;
    -o) OUTPUT_BASE="$2"; shift 2 ;;
    -t) THREADS="$2"; shift 2 ;;
    -s) NUCLEI_SEVERITY="$2"; shift 2 ;;
    --deep) DEEP_MODE=true; shift ;;
    --skip-nuclei) SKIP_NUCLEI=true; shift ;;
    --skip-portscan) SKIP_PORTSCAN=true; shift ;;
    --skip-crawl) SKIP_CRAWL=true; shift ;;
    --no-api-warnings) SUPPRESS_API_WARN=true; shift ;;
    -h|--help) usage ;;
    *) echo -e "${RED}[!] Unknown option: $1${RESET}"; usage ;;
  esac
done

# ── api_warn: respects --no-api-warnings flag ────────────────
api_warn() {
  $SUPPRESS_API_WARN || warn "$1"
}

[[ -z "$DOMAIN" ]] && echo -e "${RED}[!] Domain is required.${RESET}" && usage

# ── Directory Setup ───────────────────────────────────────────
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUT="$OUTPUT_BASE/$DOMAIN/$TIMESTAMP"
mkdir -p "$OUT"/{subdomains,hosts,urls,ports,nuclei,js,params,screenshots,osint,reports}

LOG="$OUT/reports/recon.log"
SUMMARY="$OUT/reports/summary.md"

# ── Helpers ───────────────────────────────────────────────────
log() { echo -e "$1" | tee -a "$LOG"; }
banner() {
  log ""
  log "${BOLD}${BLUE}╔══════════════════════════════════════╗${RESET}"
  log "${BOLD}${BLUE}║  $1${RESET}"
  log "${BOLD}${BLUE}╚══════════════════════════════════════╝${RESET}"
}
step() { log "${CYAN}[$(date +%H:%M:%S)]${RESET} ${GREEN}[+]${RESET} $1"; }
warn() { log "${YELLOW}[!]${RESET} $1"; }
err()  { log "${RED}[✗]${RESET} $1"; }

check_tool() {
  if ! command -v "$1" &>/dev/null; then
    warn "Tool not found: ${BOLD}$1${RESET} — skipping related step."
    return 1
  fi
  return 0
}

count_lines() { [[ -f "$1" ]] && wc -l < "$1" || echo 0; }

# ── Start ─────────────────────────────────────────────────────
clear
echo -e "${BOLD}${MAGENTA}"
cat << 'EOF'
  ____    _    __   __   __   _    ____
 / ___|  / \   \ \ / /  \ \ / /  / _  |
 \___ \ / _ \   \ V /    \ V /  | |_| |
  ___) / ___ \   | |      | |    \__  |
 |____/_/   \_\  |_|      |_|      |_/
   RECON FRAMEWORK — Bug Bounty
EOF
echo -e "${RESET}"
log "${BOLD}Target   :${RESET} $DOMAIN"
log "${BOLD}Output   :${RESET} $OUT"
log "${BOLD}Deep Mode:${RESET} $DEEP_MODE"
log "${BOLD}Threads  :${RESET} $THREADS"
log "${BOLD}Started  :${RESET} $(date)"
log ""

# ── API Key Status Dashboard ──────────────────────────────────
log "${BOLD}  API Key Status:${RESET}"
_api_status() {
  local name="$1" val="$2" signup="$3"
  if [[ -n "$val" ]]; then
    local masked="${val:0:6}$(printf '%0.s*' {1..12})"
    log "  ${GREEN}✓${RESET} $(printf '%-20s' "$name") ${GREEN}${masked}${RESET}"
  else
    if $SUPPRESS_API_WARN; then
      log "  ${YELLOW}–${RESET} $(printf '%-20s' "$name") ${YELLOW}not set (suppressed)${RESET}"
    else
      log "  ${RED}✗${RESET} $(printf '%-20s' "$name") ${RED}not set${RESET}  →  sign up: ${CYAN}${signup}${RESET}"
    fi
  fi
}
_api_status "Shodan"         "$SHODAN_API_KEY"         "account.shodan.io"
_api_status "VirusTotal"     "$VIRUSTOTAL_API_KEY"     "virustotal.com/gui/join-us"
_api_status "SecurityTrails" "$SECURITYTRAILS_API_KEY" "securitytrails.com/app/signup"
_api_status "BeVigil"        "$BEVIGIL_API_KEY"        "bevigil.com/osint-api"
_api_status "LeakIX"         "$LEAKIX_API_KEY"         "leakix.net/signup"
log ""
_keys_set=0
for _k in "$SHODAN_API_KEY" "$VIRUSTOTAL_API_KEY" "$SECURITYTRAILS_API_KEY" "$BEVIGIL_API_KEY" "$LEAKIX_API_KEY"; do
  [[ -n "$_k" ]] && (( _keys_set++ )) || true
done
log "  ${BOLD}$_keys_set / 5 API keys active.${RESET}"
if [[ $_keys_set -lt 5 ]] && ! $SUPPRESS_API_WARN; then
  log "  ${YELLOW}Tip: add missing keys to ~/.zshrc then run: source ~/.zshrc${RESET}"
  log "  ${YELLOW}Run with --no-api-warnings to suppress these notices.${RESET}"
fi
log ""

# ─────────────────────────────────────────────────────────────
# PHASE 1 — SUBDOMAIN ENUMERATION (Parallel + Multi-Source)
# ─────────────────────────────────────────────────────────────
banner "PHASE 1 — Subdomain Enumeration (Parallel, 14 Sources)"

PIDS=()
SOURCES_USED=()

# ── Shared python3 parser (avoids fragile grep-on-JSON) ──────
# Usage: echo "$json" | py_extract_field "field_name"
py_extract_field() {
  python3 -c "
import sys, json, re
field = '$1'
domain = '$DOMAIN'
pattern = re.compile(r'(?:[a-zA-Z0-9_-]+\.)+' + re.escape(domain), re.I)
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
def walk(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == field and isinstance(v, str):
                for m in pattern.findall(v): print(m.lower().lstrip('*.'))
            else:
                walk(v)
    elif isinstance(obj, list):
        for i in obj: walk(i)
walk(data)
" 2>/dev/null | sort -u
}

# ── clean_subs: filter & normalise raw text output ───────────
# BUG FIX: escape dots in DOMAIN so regex matches literally
clean_subs() {
  local esc="${DOMAIN//./\\.}"
  grep -oiE "([a-zA-Z0-9_-]+\\.)+${esc}" \
  | sed 's/^\*\.//' \
  | tr '[:upper:]' '[:lower:]' \
  | grep -E "\.${esc}$" \
  | sort -u
}

# ══════════════════════════════════════════════════════════════
# GROUP A — Tool-based
# ══════════════════════════════════════════════════════════════

# ── Subfinder ────────────────────────────────────────────────
# BUG FIX: removed -all flag — requires provider keys in
#          ~/.config/subfinder/provider-config.yaml to work.
#          Without them subfinder exits non-zero and produces 0 results.
if check_tool subfinder; then
  step "Spawning Subfinder..."
  SOURCES_USED+=("subfinder")
  (
    set +e
    subfinder -d "$DOMAIN" -silent -t "$THREADS" \
      2>>"$LOG" \
      | tr '[:upper:]' '[:lower:]' \
      | grep -iE "\.${DOMAIN//./\\.}$" \
      | sort -u > "$OUT/subdomains/subfinder.txt"
  ) &
  PIDS+=($!)
fi

# ── Assetfinder ──────────────────────────────────────────────
if check_tool assetfinder; then
  step "Spawning Assetfinder..."
  SOURCES_USED+=("assetfinder")
  (
    set +e
    assetfinder --subs-only "$DOMAIN" 2>>"$LOG" \
      | clean_subs > "$OUT/subdomains/assetfinder.txt"
  ) &
  PIDS+=($!)
fi

# ── Chaos (ProjectDiscovery) ──────────────────────────────────
if check_tool chaos; then
  step "Spawning Chaos..."
  SOURCES_USED+=("chaos")
  (
    set +e
    chaos -d "$DOMAIN" -silent 2>>"$LOG" \
      | clean_subs > "$OUT/subdomains/chaos.txt"
  ) &
  PIDS+=($!)
fi

# ── Amass (deep mode only) ────────────────────────────────────
if $DEEP_MODE && check_tool amass; then
  step "Spawning Amass (deep, 25min timeout)..."
  SOURCES_USED+=("amass")
  (
    set +e
    amass enum -active -d "$DOMAIN" -timeout 25 2>>"$LOG" \
      | clean_subs > "$OUT/subdomains/amass.txt"
  ) &
  PIDS+=($!)
else
  warn "Amass → skipped in standard mode (--deep to enable)."
fi

# ══════════════════════════════════════════════════════════════
# GROUP B — Pure curl/API  (python3 JSON parsing throughout)
# ══════════════════════════════════════════════════════════════

# ── crt.sh — Certificate Transparency ────────────────────────
# BUG FIX: grep-on-JSON broke on multi-line/nested name_value.
#          python3 handles \n-separated wildcard entries correctly.
step "Spawning crt.sh..."
SOURCES_USED+=("crtsh")
(
  set +e
  curl -sk --max-time 60 \
    -H "Accept: application/json" \
    "https://crt.sh/?q=%25.$DOMAIN&output=json" \
  | python3 -c "
import sys, json, re
domain = '$DOMAIN'
pat = re.compile(r'(?:[a-zA-Z0-9_-]+\.)+' + re.escape(domain) + r'$', re.I)
try:
    data = json.load(sys.stdin)
except Exception: sys.exit(0)
seen = set()
for e in data:
    for name in e.get('name_value','').split('\n'):
        name = name.strip().lstrip('*.').lower()
        if pat.match(name) and name not in seen:
            seen.add(name); print(name)
" 2>/dev/null | sort -u > "$OUT/subdomains/crtsh.txt"
) &
PIDS+=($!)

# ── Wayback Machine CDX ───────────────────────────────────────
# BUG FIX: was using http:// — many networks block it. Switched to https.
#          Also added -L for redirects and increased timeout.
step "Spawning Wayback Machine..."
SOURCES_USED+=("wayback")
(
  set +e
  curl -skL --max-time 60 \
    "https://web.archive.org/cdx/search/cdx?url=*.$DOMAIN/*&output=text&fl=original&collapse=urlkey&limit=50000" \
  | clean_subs > "$OUT/subdomains/wayback.txt"
) &
PIDS+=($!)

# ── AlienVault OTX ───────────────────────────────────────────
# BUG FIX: OTX returns {"passive_dns":[{"hostname":"..."},...]}
#          grep was matching wrong field. Now using python3 walker.
step "Spawning AlienVault OTX..."
SOURCES_USED+=("otx")
(
  set +e
  curl -sk --max-time 45 \
    -H "User-Agent: Mozilla/5.0" \
    "https://otx.alienvault.com/api/v1/indicators/domain/$DOMAIN/passive_dns" \
  | py_extract_field "hostname" > "$OUT/subdomains/otx.txt"
) &
PIDS+=($!)

# ── HackerTarget ─────────────────────────────────────────────
step "Spawning HackerTarget..."
SOURCES_USED+=("hackertarget")
(
  set +e
  curl -sk --max-time 30 \
    "https://api.hackertarget.com/hostsearch/?q=$DOMAIN" \
  | cut -d',' -f1 \
  | clean_subs > "$OUT/subdomains/hackertarget.txt"
) &
PIDS+=($!)

# ── RapidDNS ─────────────────────────────────────────────────
step "Spawning RapidDNS..."
SOURCES_USED+=("rapiddns")
(
  set +e
  curl -skL --max-time 30 \
    "https://rapiddns.io/subdomain/$DOMAIN?full=1" \
  | clean_subs > "$OUT/subdomains/rapiddns.txt"
) &
PIDS+=($!)

# ── URLScan.io ───────────────────────────────────────────────
# BUG FIX: field path is results[].page.domain, not top-level "domain".
#          grep was matching the wrong key. python3 walker fixes this.
step "Spawning URLScan.io..."
SOURCES_USED+=("urlscan")
(
  set +e
  curl -sk --max-time 30 \
    -H "User-Agent: Mozilla/5.0" \
    "https://urlscan.io/api/v1/search/?q=domain:$DOMAIN&size=200" \
  | py_extract_field "domain" > "$OUT/subdomains/urlscan.txt"
) &
PIDS+=($!)

# ── ThreatCrowd ──────────────────────────────────────────────
step "Spawning ThreatCrowd..."
SOURCES_USED+=("threatcrowd")
(
  set +e
  curl -sk --max-time 30 \
    "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$DOMAIN" \
  | py_extract_field "subdomain" > "$OUT/subdomains/threatcrowd.txt"
) &
PIDS+=($!)

# ── LeakIX ───────────────────────────────────────────────────
# NOTE: LeakIX now requires a free API key. Sign up at leakix.net.
#       Set LEAKIX_API_KEY to enable.
if [[ -n "${LEAKIX_API_KEY:-}" ]]; then
  step "Spawning LeakIX..."
  SOURCES_USED+=("leakix")
  (
    set +e
    curl -sk --max-time 30 \
      -H "api-key: $LEAKIX_API_KEY" \
      -H "Accept: application/json" \
      "https://leakix.net/api/subdomains/$DOMAIN" \
    | py_extract_field "subdomain" > "$OUT/subdomains/leakix.txt"
  ) &
  PIDS+=($!)
else
  api_warn "LeakIX → requires free API key. Export LEAKIX_API_KEY to enable."
fi

# ── Shodan ────────────────────────────────────────────────────
if [[ -n "$SHODAN_API_KEY" ]]; then
  step "Spawning Shodan..."
  SOURCES_USED+=("shodan")
  (
    set +e
    # DNS endpoint: returns subdomains array directly
    curl -sk --max-time 30 \
      "https://api.shodan.io/dns/domain/$DOMAIN?key=$SHODAN_API_KEY" \
    | python3 -c "
import sys, json, re
domain = '$DOMAIN'
pat = re.compile(r'(?:[a-zA-Z0-9_-]+\.)*' + re.escape(domain) + r'$', re.I)
try: data = json.load(sys.stdin)
except: sys.exit(0)
for s in data.get('subdomains', []):
    full = (s.strip('.').lower() + '.' + domain) if not s.endswith(domain) else s.lower()
    if pat.match(full): print(full)
" 2>/dev/null | sort -u > "$OUT/subdomains/shodan.txt"
  ) &
  PIDS+=($!)
else
  api_warn "Shodan → no API key. Export SHODAN_API_KEY to enable."
fi

# ── VirusTotal ────────────────────────────────────────────────
if [[ -n "$VIRUSTOTAL_API_KEY" ]]; then
  step "Spawning VirusTotal..."
  SOURCES_USED+=("virustotal")
  (
    set +e
    cursor=""
    > "$OUT/subdomains/virustotal.txt"
    for _ in $(seq 1 5); do
      url="https://www.virustotal.com/api/v3/domains/$DOMAIN/subdomains?limit=40"
      [[ -n "$cursor" ]] && url="${url}&cursor=${cursor}"
      resp=$(curl -sk --max-time 20 -H "x-apikey: $VIRUSTOTAL_API_KEY" "$url")
      echo "$resp" | python3 -c "
import sys, json, re
domain = '$DOMAIN'
pat = re.compile(r'(?:[a-zA-Z0-9_-]+\.)+' + re.escape(domain) + r'$', re.I)
try: data = json.load(sys.stdin)
except: sys.exit(0)
for e in data.get('data', []):
    i = e.get('id','').lower()
    if pat.match(i): print(i)
" 2>/dev/null >> "$OUT/subdomains/virustotal.txt"
      cursor=$(echo "$resp" | python3 -c "
import sys,json
try: d=json.load(sys.stdin); print(d.get('meta',{}).get('cursor',''))
except: print('')
" 2>/dev/null)
      [[ -z "$cursor" ]] && break
    done
    sort -u "$OUT/subdomains/virustotal.txt" -o "$OUT/subdomains/virustotal.txt"
  ) &
  PIDS+=($!)
else
  api_warn "VirusTotal → no API key. Export VIRUSTOTAL_API_KEY to enable."
fi

# ── SecurityTrails ────────────────────────────────────────────
if [[ -n "$SECURITYTRAILS_API_KEY" ]]; then
  step "Spawning SecurityTrails..."
  SOURCES_USED+=("securitytrails")
  (
    set +e
    curl -sk --max-time 30 \
      -H "apikey: $SECURITYTRAILS_API_KEY" \
      "https://api.securitytrails.com/v1/domain/$DOMAIN/subdomains?include_inactive=true" \
    | python3 -c "
import sys, json
domain = '$DOMAIN'
try: data = json.load(sys.stdin)
except: sys.exit(0)
for s in data.get('subdomains', []):
    print((s.strip('.').lower() + '.' + domain))
" 2>/dev/null | sort -u > "$OUT/subdomains/securitytrails.txt"
  ) &
  PIDS+=($!)
else
  api_warn "SecurityTrails → no API key. Export SECURITYTRAILS_API_KEY to enable."
fi

# ── BeVigil ───────────────────────────────────────────────────
if [[ -n "$BEVIGIL_API_KEY" ]]; then
  step "Spawning BeVigil..."
  SOURCES_USED+=("bevigil")
  (
    set +e
    curl -sk --max-time 30 \
      -H "X-Access-Token: $BEVIGIL_API_KEY" \
      "https://osint.bevigil.com/api/$DOMAIN/subdomains/" \
    | py_extract_field "subdomain" > "$OUT/subdomains/bevigil.txt"
  ) &
  PIDS+=($!)
else
  api_warn "BeVigil → no API key. Export BEVIGIL_API_KEY to enable."
fi

# ══════════════════════════════════════════════════════════════
# Wait for ALL parallel jobs
# ══════════════════════════════════════════════════════════════
step "Waiting for all ${#PIDS[@]} enumeration jobs..."
for pid in "${PIDS[@]}"; do
  wait "$pid" 2>/dev/null || true
done
step "All enumeration jobs complete."

# ── Combine & deduplicate ─────────────────────────────────────
step "Merging and deduplicating across all sources..."
cat "$OUT/subdomains/"*.txt 2>/dev/null \
  | grep -E "^[a-zA-Z0-9]([a-zA-Z0-9_\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$" \
  | grep -i "\.${DOMAIN}$\|^${DOMAIN}$" \
  | sort -u \
  > "$OUT/subdomains/all_subdomains.txt" || true

TOTAL_SUBS=$(count_lines "$OUT/subdomains/all_subdomains.txt")
step "${BOLD}Total unique subdomains: $TOTAL_SUBS (from ${#SOURCES_USED[@]} sources)${RESET}"

# ── Per-source breakdown ──────────────────────────────────────
log ""
log "  ${BOLD}Source Breakdown:${RESET}"
for src in subfinder assetfinder chaos amass crtsh wayback otx hackertarget \
           rapiddns urlscan leakix shodan virustotal securitytrails bevigil; do
  f="$OUT/subdomains/${src}.txt"
  [[ -f "$f" ]] && log "    ${CYAN}$(printf '%-16s' $src)${RESET} $(count_lines "$f") subdomains"
done
log ""

# ─────────────────────────────────────────────────────────────
# PHASE 2 — DNS RESOLUTION & LIVE HOST PROBING
# ─────────────────────────────────────────────────────────────
banner "PHASE 2 — DNS Resolution & Live Host Probing"

# dnsx — resolve and filter live DNS
if check_tool dnsx; then
  step "Resolving subdomains via dnsx..."
  dnsx -l "$OUT/subdomains/all_subdomains.txt" \
    -silent \
    -o "$OUT/hosts/resolved.txt" \
    -t "$THREADS" 2>>"$LOG" || warn "dnsx encountered errors."
  step "Resolved: $(count_lines "$OUT/hosts/resolved.txt") subdomains"
else
  cp "$OUT/subdomains/all_subdomains.txt" "$OUT/hosts/resolved.txt" 2>/dev/null || true
fi

# httpx — probe HTTP/HTTPS, grab titles, status codes, tech
if check_tool httpx; then
  step "Probing live HTTP hosts via httpx..."
  httpx -l "$OUT/hosts/resolved.txt" \
    -silent \
    -title -status-code -tech-detect -content-length -ip \
    -threads "$THREADS" \
    -rate-limit "$RATE_LIMIT" \
    -o "$OUT/hosts/live_hosts.txt" \
    -json -o "$OUT/hosts/live_hosts.json" 2>>"$LOG" || warn "httpx encountered errors."
  
  # Extract just URLs for downstream use
  httpx -l "$OUT/hosts/resolved.txt" -silent -threads "$THREADS" \
    2>>"$LOG" > "$OUT/hosts/live_urls.txt" || true

  step "Live HTTP hosts: $(count_lines "$OUT/hosts/live_urls.txt")"
fi

# ─────────────────────────────────────────────────────────────
# PHASE 3 — PORT SCANNING
# ─────────────────────────────────────────────────────────────
if ! $SKIP_PORTSCAN; then
  banner "PHASE 3 — Port Scanning"

  if check_tool nmap; then
    if $DEEP_MODE; then
      step "Deep port scan (top 5000 ports)..."
      NMAP_PORTS="--top-ports 5000"
    else
      step "Fast port scan (top 1000 ports)..."
      NMAP_PORTS="--top-ports 1000"
    fi

    # Scan only resolved IPs to keep it targeted
    awk '{print $NF}' "$OUT/hosts/resolved.txt" 2>/dev/null \
      | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' \
      | sort -u > "$OUT/ports/target_ips.txt" || true

    if [[ -s "$OUT/ports/target_ips.txt" ]]; then
      nmap -iL "$OUT/ports/target_ips.txt" \
        $NMAP_PORTS \
        -sV --script=banner,http-title,ssl-cert \
        -T4 --open \
        -oA "$OUT/ports/nmap_scan" 2>>"$LOG" || warn "Nmap encountered errors."
      step "Port scan complete. Results in $OUT/ports/"
    else
      warn "No IPs to scan — skipping Nmap."
    fi
  fi
fi

# ─────────────────────────────────────────────────────────────
# PHASE 4 — URL & ENDPOINT DISCOVERY
# ─────────────────────────────────────────────────────────────
if ! $SKIP_CRAWL; then
  banner "PHASE 4 — URL & Endpoint Discovery"

  # GAU — historical URLs
  if check_tool gau; then
    step "Running GAU (historical URLs)..."
    gau "$DOMAIN" --threads "$THREADS" \
      --blacklist png,jpg,gif,svg,ico,css,woff,ttf,eot \
      --o "$OUT/urls/gau.txt" 2>>"$LOG" || warn "GAU encountered errors."
    step "GAU found: $(count_lines "$OUT/urls/gau.txt") URLs"
  fi

  # Waybackurls
  if check_tool waybackurls; then
    step "Running Waybackurls..."
    echo "$DOMAIN" | waybackurls > "$OUT/urls/wayback.txt" 2>>"$LOG" || warn "Waybackurls errors."
    step "Wayback found: $(count_lines "$OUT/urls/wayback.txt") URLs"
  fi

  # Katana — active crawling on live hosts
  if check_tool katana && [[ -s "$OUT/hosts/live_urls.txt" ]]; then
    step "Running Katana (active crawl)..."
    katana -list "$OUT/hosts/live_urls.txt" \
      -silent \
      -d 3 \
      -jc \
      -kf all \
      -c "$THREADS" \
      -o "$OUT/urls/katana.txt" 2>>"$LOG" || warn "Katana encountered errors."
    step "Katana found: $(count_lines "$OUT/urls/katana.txt") endpoints"
  fi

  # Merge all URLs
  step "Merging all discovered URLs..."
  cat "$OUT/urls/"*.txt 2>/dev/null \
    | sort -u \
    > "$OUT/urls/all_urls.txt" || true
  step "Total unique URLs: $(count_lines "$OUT/urls/all_urls.txt")"

  # Extract JS files
  step "Extracting JS files for analysis..."
  grep -E "\.js(\?|$)" "$OUT/urls/all_urls.txt" 2>/dev/null \
    | sort -u > "$OUT/js/js_files.txt" || true
  step "JS files found: $(count_lines "$OUT/js/js_files.txt")"

  # Extract interesting endpoints (API, admin, auth patterns)
  step "Filtering high-value endpoints..."
  grep -iE "(api|admin|auth|login|upload|dashboard|graphql|swagger|debug|config|backup|\.json|\.xml|\.env|\.git)" \
    "$OUT/urls/all_urls.txt" 2>/dev/null \
    | sort -u > "$OUT/urls/interesting_endpoints.txt" || true
  step "Interesting endpoints: $(count_lines "$OUT/urls/interesting_endpoints.txt")"

fi

# ─────────────────────────────────────────────────────────────
# PHASE 5 — PARAMETER DISCOVERY
# ─────────────────────────────────────────────────────────────
banner "PHASE 5 — Parameter Discovery"

# ParamSpider
if check_tool paramspider; then
  step "Running ParamSpider..."
  paramspider -d "$DOMAIN" \
    -o "$OUT/params/paramspider.txt" 2>>"$LOG" || warn "ParamSpider errors."
  step "ParamSpider found: $(count_lines "$OUT/params/paramspider.txt") params"
fi

# Extract params from all URLs
if [[ -s "$OUT/urls/all_urls.txt" ]]; then
  step "Extracting parameters from discovered URLs..."
  grep "?" "$OUT/urls/all_urls.txt" 2>/dev/null \
    | grep -oP '(?<=\?)[^#]+' \
    | tr '&' '\n' \
    | cut -d'=' -f1 \
    | sort -u > "$OUT/params/discovered_params.txt" || true
  step "Unique parameters: $(count_lines "$OUT/params/discovered_params.txt")"
fi

# ─────────────────────────────────────────────────────────────
# PHASE 6 — NUCLEI VULNERABILITY SCANNING
# ─────────────────────────────────────────────────────────────
if ! $SKIP_NUCLEI; then
  banner "PHASE 6 — Nuclei Vulnerability Scanning"

  if check_tool nuclei && [[ -s "$OUT/hosts/live_urls.txt" ]]; then
    # Update templates first
    step "Updating Nuclei templates..."
    nuclei -update-templates -silent 2>>"$LOG" || warn "Could not update templates."

    # Run on live hosts
    step "Running Nuclei (severity: $NUCLEI_SEVERITY)..."
    nuclei -l "$OUT/hosts/live_urls.txt" \
      -severity "$NUCLEI_SEVERITY" \
      -c "$THREADS" \
      -rate-limit "$RATE_LIMIT" \
      -o "$OUT/nuclei/findings.txt" \
      -json-export "$OUT/nuclei/findings.json" \
      -stats \
      -silent 2>>"$LOG" || warn "Nuclei encountered errors."

    NUCLEI_HITS=$(count_lines "$OUT/nuclei/findings.txt")
    step "${BOLD}Nuclei findings: $NUCLEI_HITS${RESET}"

    # Separate criticals/highs for quick triage
    if [[ -s "$OUT/nuclei/findings.txt" ]]; then
      grep -E "\[critical\]|\[high\]" "$OUT/nuclei/findings.txt" \
        > "$OUT/nuclei/critical_high.txt" 2>/dev/null || true
      step "Critical/High findings: $(count_lines "$OUT/nuclei/critical_high.txt")"
    fi
  fi
fi

# ─────────────────────────────────────────────────────────────
# PHASE 7 — JS SECRET SCANNING
# ─────────────────────────────────────────────────────────────
banner "PHASE 7 — JS & Secret Analysis"

if [[ -s "$OUT/js/js_files.txt" ]]; then
  # Download JS files for offline analysis
  step "Downloading JS files for analysis..."
  mkdir -p "$OUT/js/files"
  while IFS= read -r jsurl; do
    filename=$(echo "$jsurl" | md5sum | cut -d' ' -f1)
    curl -sk --max-time 10 "$jsurl" \
      -o "$OUT/js/files/${filename}.js" 2>/dev/null || true
  done < "$OUT/js/js_files.txt"

  # Grep for secrets/sensitive patterns
  step "Scanning JS files for secrets and sensitive patterns..."
  grep -rhoiE \
    "(api_key|apikey|api-key|secret|password|passwd|token|auth|bearer|aws_access|private_key|client_secret|authorization)['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9+/=_\-]{8,}" \
    "$OUT/js/files/" 2>/dev/null \
    | sort -u > "$OUT/js/potential_secrets.txt" || true
  step "Potential secrets found: $(count_lines "$OUT/js/potential_secrets.txt")"

  # Extract endpoints from JS
  step "Extracting API endpoints from JS files..."
  grep -rhoE "(\"|\')(/api/[a-zA-Z0-9_/\-\.]+)(\"|\')" \
    "$OUT/js/files/" 2>/dev/null \
    | tr -d "\"'" \
    | sort -u > "$OUT/js/js_endpoints.txt" || true
  step "JS endpoints extracted: $(count_lines "$OUT/js/js_endpoints.txt")"
fi

# ─────────────────────────────────────────────────────────────
# PHASE 8 — SUMMARY REPORT
# ─────────────────────────────────────────────────────────────
banner "PHASE 8 — Generating Summary Report"

cat > "$SUMMARY" << MDEOF
# Recon Summary — $DOMAIN
**Date:** $(date)
**Mode:** $(if $DEEP_MODE; then echo "Deep"; else echo "Standard"; fi)

---

## Statistics

| Phase | Result |
|-------|--------|
| Subdomains Discovered | $(count_lines "$OUT/subdomains/all_subdomains.txt") |
| DNS Resolved | $(count_lines "$OUT/hosts/resolved.txt") |
| Live HTTP Hosts | $(count_lines "$OUT/hosts/live_urls.txt") |
| Total URLs | $(count_lines "$OUT/urls/all_urls.txt") |
| Interesting Endpoints | $(count_lines "$OUT/urls/interesting_endpoints.txt") |
| JS Files | $(count_lines "$OUT/js/js_files.txt") |
| Potential Secrets | $(count_lines "$OUT/js/potential_secrets.txt") |
| Parameters Discovered | $(count_lines "$OUT/params/discovered_params.txt") |
| Nuclei Findings | $(count_lines "$OUT/nuclei/findings.txt") |
| Critical/High Findings | $(count_lines "$OUT/nuclei/critical_high.txt") |

---

## Output Structure

\`\`\`
$OUT/
├── subdomains/     — All enumerated & merged subdomains
├── hosts/          — Live hosts with status codes & tech stack
├── urls/           — All URLs, interesting endpoints
├── ports/          — Nmap scan results
├── nuclei/         — Vulnerability findings (JSON + text)
├── js/             — JS files, endpoints, potential secrets
├── params/         — Discovered parameters
├── osint/          — theHarvester output
└── reports/        — This summary + full log
\`\`\`

---

## High Priority Items

### Nuclei Critical/High
$(cat "$OUT/nuclei/critical_high.txt" 2>/dev/null || echo "None found or scan skipped.")

### Potential Secrets in JS
$(head -20 "$OUT/js/potential_secrets.txt" 2>/dev/null || echo "None found or skipped.")

### Interesting Endpoints (top 20)
$(head -20 "$OUT/urls/interesting_endpoints.txt" 2>/dev/null || echo "None found.")

---
*Generated by Sayad Recon Framework*
MDEOF

step "Summary saved to: $SUMMARY"

# ─────────────────────────────────────────────────────────────
# DONE
# ─────────────────────────────────────────────────────────────
log ""
log "${BOLD}${GREEN}╔══════════════════════════════════════════╗${RESET}"
log "${BOLD}${GREEN}║  ✅  RECON COMPLETE                       ║${RESET}"
log "${BOLD}${GREEN}╚══════════════════════════════════════════╝${RESET}"
log ""
log "  ${BOLD}Domain    :${RESET} $DOMAIN"
log "  ${BOLD}Subdomains:${RESET} $(count_lines "$OUT/subdomains/all_subdomains.txt")"
log "  ${BOLD}Live Hosts:${RESET} $(count_lines "$OUT/hosts/live_urls.txt")"
log "  ${BOLD}Findings  :${RESET} $(count_lines "$OUT/nuclei/findings.txt") ($(count_lines "$OUT/nuclei/critical_high.txt") Crit/High)"
log "  ${BOLD}Secrets   :${RESET} $(count_lines "$OUT/js/potential_secrets.txt") potential"
log ""
log "  ${BOLD}Full output:${RESET} $OUT"
log "  ${BOLD}Report    :${RESET} $SUMMARY"
log "  ${BOLD}Log       :${RESET} $LOG"
log ""
log "${YELLOW}Next step:${RESET} Feed '$OUT' to Claude for AI-assisted analysis."