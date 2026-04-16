#!/bin/bash
# ============================================================
#  SAYYAD RECON TOOLKIT — Installer
#  Kali Linux ARM (M3 MacBook) / Debian-based
#  Run as root or with sudo
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}[✓]${RESET} $1"; }
info() { echo -e "${CYAN}[~]${RESET} $1"; }
warn() { echo -e "${YELLOW}[!]${RESET} $1"; }
fail() { echo -e "${RED}[✗]${RESET} $1"; }

# ── Detect Go ────────────────────────────────────────────────
setup_go() {
  if command -v go &>/dev/null; then
    ok "Go already installed: $(go version)"
  else
    info "Installing Go..."
    apt-get install -y golang-go 2>/dev/null \
      || { fail "apt Go install failed. Install manually from https://go.dev/dl/"; exit 1; }
  fi

  # Make sure GOPATH/bin is in PATH
  export GOPATH="${GOPATH:-$HOME/go}"
  export PATH="$PATH:$GOPATH/bin"

  if ! grep -q 'GOPATH' ~/.zshrc 2>/dev/null && ! grep -q 'GOPATH' ~/.bashrc 2>/dev/null; then
    {
      echo ''
      echo '# Go tools'
      echo 'export GOPATH=$HOME/go'
      echo 'export PATH=$PATH:$GOPATH/bin'
    } >> ~/.zshrc
    warn "Added Go paths to ~/.zshrc — run: source ~/.zshrc"
  fi
}

# ── Install Go tool ──────────────────────────────────────────
go_install() {
  local name="$1"
  local pkg="$2"
  if command -v "$name" &>/dev/null; then
    ok "$name already installed"
  else
    info "Installing $name..."
    go install -v "$pkg" 2>/dev/null && ok "$name installed" || fail "$name failed"
  fi
}

# ── Install pip tool ─────────────────────────────────────────
pip_install() {
  local name="$1"
  local pkg="$2"
  if command -v "$name" &>/dev/null || python3 -c "import $name" 2>/dev/null; then
    ok "$name already installed"
  else
    info "Installing $name..."
    pip3 install "$pkg" --break-system-packages -q && ok "$name installed" || fail "$name failed"
  fi
}

# ── Install apt tool ─────────────────────────────────────────
apt_install() {
  local name="$1"
  local pkg="${2:-$1}"
  if command -v "$name" &>/dev/null; then
    ok "$name already installed"
  else
    info "Installing $name..."
    apt-get install -y "$pkg" -q && ok "$name installed" || fail "$name failed"
  fi
}

echo ""
echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  Sayyad Recon Toolkit — Installer${RESET}"
echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

# ── System deps ──────────────────────────────────────────────
info "Updating apt and installing base deps..."
apt-get update -q
apt_install curl
apt_install git
apt_install python3
apt_install pip3 python3-pip
apt_install nmap
apt_install amass
apt_install assetfinder

# ── Go setup ─────────────────────────────────────────────────
echo ""
echo -e "${BOLD}[Go-based tools]${RESET}"
setup_go
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin"

go_install subfinder   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
go_install httpx       "github.com/projectdiscovery/httpx/cmd/httpx@latest"
go_install dnsx        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
go_install nuclei      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
go_install katana      "github.com/projectdiscovery/katana/cmd/katana@latest"
go_install chaos       "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
go_install gau         "github.com/lc/gau/v2/cmd/gau@latest"
go_install waybackurls "github.com/tomnomnom/waybackurls@latest"
go_install anew        "github.com/tomnomnom/anew@latest"
go_install dalfox      "github.com/hahwul/dalfox/v2@latest"
go_install ffuf        "github.com/ffuf/ffuf/v2@latest"

# ── pip tools ────────────────────────────────────────────────
echo ""
echo -e "${BOLD}[Python-based tools]${RESET}"
pip_install paramspider paramspider
pip_install shodan shodan

# ── Nuclei templates ─────────────────────────────────────────
echo ""
if command -v nuclei &>/dev/null; then
  info "Updating Nuclei templates..."
  nuclei -update-templates -silent && ok "Nuclei templates updated"
fi

# ── SecLists ─────────────────────────────────────────────────
echo ""
if [[ ! -d /usr/share/seclists ]]; then
  info "Installing SecLists..."
  apt-get install -y seclists -q && ok "SecLists installed" || warn "SecLists apt failed — try: git clone https://github.com/danielmiessler/SecLists /usr/share/seclists"
else
  ok "SecLists already present"
fi

# ── Shodan CLI setup ──────────────────────────────────────────
echo ""
if command -v shodan &>/dev/null && [[ -n "${SHODAN_API_KEY:-}" ]]; then
  info "Initialising Shodan CLI with your API key..."
  shodan init "$SHODAN_API_KEY" && ok "Shodan CLI ready"
fi

# ── Summary ───────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  Installation complete. Tool check:${RESET}"
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

for tool in subfinder httpx dnsx nuclei katana chaos gau waybackurls \
            dalfox ffuf paramspider nmap amass assetfinder shodan; do
  if command -v "$tool" &>/dev/null; then
    echo -e "  ${GREEN}✓${RESET} $tool"
  else
    echo -e "  ${RED}✗${RESET} $tool — not found (check PATH / reload shell)"
  fi
done

echo ""
warn "Reload your shell after install: source ~/.zshrc"
warn "If Go tools aren't found, run:   export PATH=\$PATH:\$HOME/go/bin"
echo ""
