#!/usr/bin/env bash
# Jan-Karel Visser
# AGPL-3.0-or-later licensed
# https://jan-karel.nl
# https://hacksec.nl
#
# Installatiescript voor Incompetent Bastard
# Controleert en installeert benodigde tooling voor macOS (brew) en Linux (apt).

set -euo pipefail

VERSIE='0.42'
MISSING=()
INSTALLED=()
SKIPPED=()

# Kleuren
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_info() { echo -e "${BLUE}[*]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_fail() { echo -e "${RED}[-]${NC} $1"; }

# ---------------------------------------------------------------------------
# Check of een commando beschikbaar is
# ---------------------------------------------------------------------------
check_cmd() {
	local cmd="$1"
	local label="${2:-$1}"
	if command -v "$cmd" &>/dev/null; then
		INSTALLED+=("$label")
		return 0
	else
		MISSING+=("$label")
		return 1
	fi
}

# ---------------------------------------------------------------------------
# Installatie helpers
# ---------------------------------------------------------------------------
install_brew() {
	local formula="$1"
	local label="${2:-$1}"
	if brew list "$formula" &>/dev/null 2>&1; then
		log_ok "$label (al geinstalleerd via brew)"
	else
		log_info "Installeren: $label via brew..."
		brew install "$formula"
		log_ok "$label geinstalleerd"
	fi
}

install_brew_cask() {
	local cask="$1"
	local label="${2:-$1}"
	if brew list --cask "$cask" &>/dev/null 2>&1; then
		log_ok "$label (al geinstalleerd via brew cask)"
	else
		log_info "Installeren: $label via brew cask..."
		brew install --cask "$cask"
		log_ok "$label geinstalleerd"
	fi
}

install_apt() {
	local pkg="$1"
	local label="${2:-$1}"
	if dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; then
		log_ok "$label (al geinstalleerd via apt)"
	else
		log_info "Installeren: $label via apt..."
		sudo apt-get install -y "$pkg"
		log_ok "$label geinstalleerd"
	fi
}

install_pip() {
	local pkg="$1"
	if python3 -m pip show "$pkg" &>/dev/null 2>&1; then
		log_ok "$pkg (al geinstalleerd via pip)"
	else
		log_info "Installeren: $pkg via pip..."
		python3 -m pip install "$pkg"
		log_ok "$pkg geinstalleerd"
	fi
}

install_pipx() {
	local pkg="$1"
	local cmd="${2:-$1}"
	if command -v "$cmd" &>/dev/null; then
		log_ok "$pkg (al beschikbaar)"
	else
		log_info "Installeren: $pkg via pipx..."
		pipx install "$pkg"
		log_ok "$pkg geinstalleerd"
	fi
}

install_go() {
	local pkg="$1"
	local cmd="$2"
	if command -v "$cmd" &>/dev/null; then
		log_ok "$cmd (al beschikbaar)"
	else
		log_info "Installeren: $cmd via go install..."
		go install "$pkg"
		log_ok "$cmd geinstalleerd"
	fi
}

# ---------------------------------------------------------------------------
# macOS installatie
# ---------------------------------------------------------------------------
install_macos() {
	log_info "Platform: macOS"

	# Brew check
	if ! command -v brew &>/dev/null; then
		log_fail "Homebrew is niet geinstalleerd."
		log_info "Installeer met: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
		exit 1
	fi
	log_ok "Homebrew gevonden"

	# --- Core tools ---
	log_info "=== Core tools ==="
	install_brew python3 "Python 3"
	install_brew screen "GNU Screen"
	install_brew curl "curl"
	install_brew wget "wget"
	install_brew gawk "gawk"
	install_brew netcat "netcat"

	# --- Python venv + project deps ---
	log_info "=== Python dependencies ==="
	if [ ! -d ".venv" ]; then
		log_info "Aanmaken van Python venv..."
		python3 -m venv .venv
	fi
	log_ok "Python venv"
	# shellcheck disable=SC1091
	. .venv/bin/activate
	pip install --upgrade pip
	if [ -f "requirements.txt" ]; then
		pip install -r requirements.txt
		log_ok "Python requirements geinstalleerd"
	fi
	if [ -f "requirements-dev.txt" ]; then
		pip install -r requirements-dev.txt
		log_ok "Python dev requirements geinstalleerd"
	fi

	# --- Netwerk & recon ---
	log_info "=== Netwerk & Recon ==="
	install_brew nmap "nmap"
	install_brew openvpn "OpenVPN"
	install_brew tcpdump "tcpdump"

	# nmaptocsv (pip)
	if ! command -v nmaptocsv &>/dev/null; then
		log_info "Installeren: nmaptocsv via pip..."
		pip install nmaptocsv
	fi
	log_ok "nmaptocsv"

	# whatweb
	install_brew whatweb "whatweb"

	# nuclei
	if ! command -v nuclei &>/dev/null; then
		install_brew nuclei "nuclei"
	else
		log_ok "nuclei"
	fi

	# wafw00f (pip)
	if ! command -v wafw00f &>/dev/null; then
		pip install wafw00f
	fi
	log_ok "wafw00f"

	# nikto
	install_brew nikto "nikto"

	# sqlmap
	install_brew sqlmap "sqlmap"

	# dnsrecon (pip)
	if ! command -v dnsrecon &>/dev/null; then
		pip install dnsrecon
	fi
	log_ok "dnsrecon"

	# sslscan
	install_brew sslscan "sslscan"

	# testssl
	install_brew testssl "testssl"

	# --- Brute force ---
	log_info "=== Brute Force ==="

	# crowbar (pip)
	if ! command -v crowbar &>/dev/null; then
		pip install crowbar
	fi
	log_ok "crowbar"

	# --- Tunneling ---
	log_info "=== Tunneling & Remote ==="
	install_brew sshuttle "sshuttle"

	if ! command -v sshpass &>/dev/null; then
		# sshpass zit niet in de standaard brew tap
		brew install hudochenkov/sshpass/sshpass 2>/dev/null || log_warn "sshpass: handmatig installeren (brew install hudochenkov/sshpass/sshpass)"
	fi
	log_ok "sshpass"

	# xfreerdp
	install_brew freerdp "FreeRDP (xfreerdp)"

	# --- Recording ---
	log_info "=== Recording ==="
	install_brew asciinema "asciinema"

	# --- Exploitation ---
	log_info "=== Exploitation ==="

	# Metasploit
	if ! command -v msfconsole &>/dev/null; then
		install_brew_cask metasploit "Metasploit Framework"
	else
		log_ok "Metasploit Framework"
	fi

	# crackmapexec / netexec
	if ! command -v crackmapexec &>/dev/null && ! command -v netexec &>/dev/null; then
		pip install crackmapexec 2>/dev/null || log_warn "crackmapexec: handmatig installeren"
	fi
	log_ok "crackmapexec"

	# Mono (msbuild/xbuild voor C# payloads)
	if ! command -v msbuild &>/dev/null && ! command -v xbuild &>/dev/null; then
		install_brew mono "Mono (msbuild)"
	else
		log_ok "msbuild/xbuild"
	fi

	# --- Report generatie ---
	log_info "=== Rapportage ==="
	install_brew pandoc "pandoc"

	# --- Fuzzing ---
	log_info "=== Web fuzzing ==="
	if ! command -v wfuzz &>/dev/null; then
		pip install wfuzz
	fi
	log_ok "wfuzz"

	if ! command -v dirb &>/dev/null; then
		log_warn "dirb: niet beschikbaar via brew, handmatig installeren of gebruik feroxbuster/ffuf"
	else
		log_ok "dirb"
	fi

	# --- SMB ---
	log_info "=== SMB ==="
	if ! command -v smbserver.py &>/dev/null; then
		pip install impacket
	fi
	log_ok "impacket (smbserver.py)"

	# ldapsearch
	log_ok "ldapsearch (ingebouwd in macOS)"
}

# ---------------------------------------------------------------------------
# Linux installatie (Debian/Ubuntu/Kali)
# ---------------------------------------------------------------------------
install_linux() {
	log_info "Platform: Linux"

	if ! command -v apt-get &>/dev/null; then
		log_fail "apt-get niet gevonden. Dit script ondersteunt Debian/Ubuntu/Kali."
		exit 1
	fi

	log_info "apt update..."
	sudo apt-get update -qq

	# --- Core tools ---
	log_info "=== Core tools ==="
	install_apt python3 "Python 3"
	install_apt python3-venv "python3-venv"
	install_apt python3-pip "python3-pip"
	install_apt screen "GNU Screen"
	install_apt curl "curl"
	install_apt wget "wget"
	install_apt gawk "gawk"
	install_apt netcat-openbsd "netcat"
	install_apt ftp "ftp"

	# --- Python venv + project deps ---
	log_info "=== Python dependencies ==="
	if [ ! -d ".venv" ]; then
		log_info "Aanmaken van Python venv..."
		python3 -m venv .venv
	fi
	log_ok "Python venv"
	# shellcheck disable=SC1091
	. .venv/bin/activate
	pip install --upgrade pip
	if [ -f "requirements.txt" ]; then
		pip install -r requirements.txt
		log_ok "Python requirements geinstalleerd"
	fi
	if [ -f "requirements-dev.txt" ]; then
		pip install -r requirements-dev.txt
		log_ok "Python dev requirements geinstalleerd"
	fi

	# --- Netwerk & recon ---
	log_info "=== Netwerk & Recon ==="
	install_apt nmap "nmap"
	install_apt openvpn "OpenVPN"
	install_apt tcpdump "tcpdump"

	# nmaptocsv
	if ! command -v nmaptocsv &>/dev/null; then
		pip install nmaptocsv
	fi
	log_ok "nmaptocsv"

	install_apt whatweb "whatweb"

	# nuclei
	if ! command -v nuclei &>/dev/null; then
		if command -v go &>/dev/null; then
			install_go "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" "nuclei"
		else
			log_warn "nuclei: installeer Go eerst, of download van https://github.com/projectdiscovery/nuclei/releases"
		fi
	else
		log_ok "nuclei"
	fi

	# wafw00f
	if ! command -v wafw00f &>/dev/null; then
		install_apt wafw00f "wafw00f" 2>/dev/null || pip install wafw00f
	fi
	log_ok "wafw00f"

	install_apt nikto "nikto"
	install_apt sqlmap "sqlmap"

	# dnsrecon
	if ! command -v dnsrecon &>/dev/null; then
		install_apt dnsrecon "dnsrecon" 2>/dev/null || pip install dnsrecon
	fi
	log_ok "dnsrecon"

	install_apt sslscan "sslscan"

	# testssl
	if ! command -v testssl &>/dev/null; then
		install_apt testssl.sh "testssl" 2>/dev/null || log_warn "testssl: handmatig installeren van https://github.com/drwetter/testssl.sh"
	fi
	log_ok "testssl"

	# --- Brute force ---
	log_info "=== Brute Force ==="
	if ! command -v crowbar &>/dev/null; then
		install_apt crowbar "crowbar" 2>/dev/null || pip install crowbar
	fi
	log_ok "crowbar"

	# --- Tunneling ---
	log_info "=== Tunneling & Remote ==="
	install_apt sshuttle "sshuttle"
	install_apt sshpass "sshpass"
	install_apt freerdp2-x11 "FreeRDP (xfreerdp)"

	# --- Recording ---
	log_info "=== Recording ==="
	install_apt asciinema "asciinema"

	# --- Exploitation ---
	log_info "=== Exploitation ==="

	# Metasploit
	if ! command -v msfconsole &>/dev/null; then
		log_warn "Metasploit: niet gevonden. Installeer via https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html"
	else
		log_ok "Metasploit Framework"
	fi

	# crackmapexec / netexec
	if ! command -v crackmapexec &>/dev/null && ! command -v netexec &>/dev/null; then
		install_apt crackmapexec "crackmapexec" 2>/dev/null || pip install crackmapexec 2>/dev/null || log_warn "crackmapexec: handmatig installeren"
	fi
	log_ok "crackmapexec"

	# ldapsearch
	install_apt ldap-utils "ldap-utils (ldapsearch)"

	# Mono (msbuild/xbuild)
	if ! command -v msbuild &>/dev/null && ! command -v xbuild &>/dev/null; then
		install_apt mono-devel "Mono (msbuild)"
	else
		log_ok "msbuild/xbuild"
	fi

	# --- Report generatie ---
	log_info "=== Rapportage ==="
	install_apt pandoc "pandoc"

	# --- Fuzzing ---
	log_info "=== Web fuzzing ==="
	if ! command -v wfuzz &>/dev/null; then
		pip install wfuzz
	fi
	log_ok "wfuzz"

	install_apt dirb "dirb"

	# --- SMB ---
	log_info "=== SMB ==="
	if ! command -v impacket-smbserver &>/dev/null; then
		install_apt python3-impacket "impacket" 2>/dev/null || pip install impacket
	fi
	log_ok "impacket (smbserver)"
}

# ---------------------------------------------------------------------------
# Verificatie
# ---------------------------------------------------------------------------
verify_tools() {
	log_info "=== Verificatie ==="
	local tools=(
		python3 screen nmap curl wget gawk asciinema
		sshuttle pandoc msfvenom msfconsole
	)
	local ok=0
	local fail=0

	for cmd in "${tools[@]}"; do
		if command -v "$cmd" &>/dev/null; then
			log_ok "$cmd: $(command -v "$cmd")"
			ok=$((ok + 1))
		else
			log_fail "$cmd: niet gevonden"
			fail=$((fail + 1))
		fi
	done

	echo ""
	log_info "Resultaat: ${ok} gevonden, ${fail} ontbrekend"
}

# ---------------------------------------------------------------------------
# Directory structuur
# ---------------------------------------------------------------------------
setup_dirs() {
	log_info "=== Directory structuur ==="
	mkdir -p raw/{recon,local,screenshots,tls,nmap,wget,loot,route,debug,exploits,mirror,spider,tooling}
	mkdir -p meuk/{logs,wordlists}
	mkdir -p http/{payloads,commands,tools}
	mkdir -p rapport
	log_ok "Directories aangemaakt"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}   Incompetent Bastard v${VERSIE} - Installer  ${BLUE}║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════╝${NC}"
echo ""

setup_dirs

if [[ "$OSTYPE" == "darwin"* ]]; then
	install_macos
else
	install_linux
fi

echo ""
verify_tools
echo ""
log_ok "Installatie afgerond."
echo ""
log_info "Volgende stappen:"
echo "  1. bash download_tools.sh     # Offensive tools ophalen (mimikatz, Rubeus, etc.)"
echo "  2. flask --app app:create_app run --host 127.0.0.1 --port 5000"
