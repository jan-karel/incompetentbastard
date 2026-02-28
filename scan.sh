#!/usr/bin/env bash
# Jan-Karel Visser
# AGPL-3.0-or-later licensed
# https://jan-karel.nl
# https://hacksec.nl

source meuk/globalmeuk.sh
startrec "$@"

echo "[*] Incompentent Bastard v${VERSIE}"

# --- Argumenten ---
localnic=${1:-}
naam=${2:-}
HOSTS=${3:-}

if [ -z "$localnic" ]; then
	echo "incompetentbastard scan.sh

	Creates some dirs and scans a network or some host. Forces nmap to scan over a specified nic.

	usage:
	./scan.sh eth0 name-of-the-engegement 10.1.2.0/24

	"
	exit
fi

if [ -z "$naam" ]; then
	echo "[!] Please provide the name of the nmap file"
	echo "[!] You failed..."
	exit 1
fi

if [ -z "$HOSTS" ]; then
	echo "[!] Please provide the range to scan"
	echo "[!] You failed..."
	exit 1
fi

# --- Tool checks ---
function check_tool() {
	if ! command -v "$1" &>/dev/null; then
		if [ "${2:-}" = "required" ]; then
			echo "[!] $1 niet gevonden, kan niet doorgaan."
			exit 1
		else
			echo "[!] $1 niet gevonden, wordt overgeslagen."
			return 1
		fi
	fi
	return 0
}

check_tool nmap required
check_tool screen required
HAS_NMAPTOCSV=false; check_tool nmaptocsv && HAS_NMAPTOCSV=true
HAS_WHATWEB=false;   check_tool whatweb && HAS_WHATWEB=true
HAS_WFUZZ=false;     check_tool wfuzz && HAS_WFUZZ=true
HAS_NUCLEI=false;    check_tool nuclei && HAS_NUCLEI=true

# --- Logging ---
function log() { echo "[$(date +%H:%M:%S)] $*" | tee -a raw/debug/scan.log; }

# --- Mappen aanmaken ---
mkdir -p raw/{recon,local,screenshots,nmap,loot,route,debug,exploits,mirror,spider,tooling}

# --- Lokale configuratie loggen ---
log "Lokale configuratie loggen."
id > raw/local/id.txt
cat /etc/os-release > raw/local/release.txt 2>/dev/null || true
date > raw/local/date.txt
cat raw/local/date.txt
uname -a > raw/local/uname.txt
uname -r > raw/local/unamer.txt
ifconfig > raw/local/ifconfig.txt 2>/dev/null || ip addr > raw/local/ifconfig.txt 2>/dev/null || true
cat raw/local/ifconfig.txt

getpublicip 4 > raw/local/remoteip.txt
getpublicip 6 > raw/local/remoteipv6.txt

# --- Netwerk info (macOS / Linux) ---
if [[ "$OSTYPE" == "darwin"* ]]; then
	networksetup -getinfo "$(networksetup -listallhardwareports | awk -v dev="$localnic" '/Hardware Port/{port=$0} /Device: /{if($2==dev) print port}' | sed 's/Hardware Port: //')" > raw/local/networkinfo.txt 2>/dev/null || true
else
	nmcli dev show "$localnic" > raw/local/nmcli.txt 2>/dev/null || true
fi

# --- Reverseshells genereren ---
if [[ ! -f http/payloads/shell_443.txt ]]; then
	screen -dmS baking_shells ./reverseshells.sh "$localnic"
fi

# --- Quick TCP scan ---
NMAP_HOST=${HOSTS//,/' '}
log "[+] Quick TCP scan op ${NMAP_HOST}..."
nmap -e "$localnic" $NMAP_OPDRACHT_TCP $NMAP_HOST -oA "raw/nmap/${naam}_quick_scan_tcp" || true

if $HAS_NMAPTOCSV; then
	nmaptocsv -i "raw/nmap/${naam}_quick_scan_tcp.nmap" -f ip-fqdn-port-protocol-service > "raw/nmap/${naam}_tcp-poorten.txt"
	brakkesed 's/";"/},{/g' "raw/nmap/${naam}_tcp-poorten.txt"
	brakkesed 's/.$/}/' "raw/nmap/${naam}_tcp-poorten.txt"
	brakkesed 's/"/{/g' "raw/nmap/${naam}_tcp-poorten.txt"

	nmaptocsv -i "raw/nmap/${naam}_quick_scan_tcp.nmap" -f fqdn-service-version-os > "raw/nmap/${naam}_tcp-versies.txt"
	brakkesed 's/";"/},{/g' "raw/nmap/${naam}_tcp-versies.txt"
	brakkesed 's/.$/}/' "raw/nmap/${naam}_tcp-versies.txt"
	brakkesed 's/"/{/g' "raw/nmap/${naam}_tcp-versies.txt"
fi

# --- Quick UDP scan ---
log "[+] Quick UDP scan op ${NMAP_HOST}..."
nmap -e "$localnic" $NMAP_OPDRACHT_UDP $NMAP_HOST -oA "raw/nmap/${naam}_quick_scan_udp" || true

if $HAS_NMAPTOCSV; then
	nmaptocsv -i "raw/nmap/${naam}_quick_scan_udp.nmap" -f ip-fqdn-port-protocol-service > "raw/nmap/${naam}_udp-poorten.txt"
	brakkesed 's/";"/},{/g' "raw/nmap/${naam}_udp-poorten.txt"
	brakkesed 's/.$/}/' "raw/nmap/${naam}_udp-poorten.txt"
	brakkesed 's/"/{/g' "raw/nmap/${naam}_udp-poorten.txt"
fi

# --- Scope CSV ---
if $HAS_NMAPTOCSV; then
	nmaptocsv -i "raw/nmap/${naam}_quick_scan_tcp.nmap" -f fqdn-rdns-ip > "raw/${naam}_scope.csv"
	brakkesed 's/";"/},{/g' "raw/${naam}_scope.csv"
	brakkesed 's/.$/}/' "raw/${naam}_scope.csv"
	brakkesed 's/"/{/g' "raw/${naam}_scope.csv"
fi

# --- Open hosts en HTTP hosts extraheren ---
open_hosts=""
http_hosts=""

if [ -f "raw/nmap/${naam}_quick_scan_tcp.gnmap" ]; then
	open_hosts=$(grep "open" "raw/nmap/${naam}_quick_scan_tcp.gnmap" | awk '{print $2}' | sort -u || true)
	http_hosts=$(grep "http" "raw/nmap/${naam}_quick_scan_tcp.gnmap" | awk '{print $2}' | sort -u || true)
fi

# --- Full-port scans per host via fixscreen ---
for host in $open_hosts; do
	if [[ "$host" == *"Host"* ]] || [[ "$host" == *"#"* ]] || [[ "$host" == *"Nmap"* ]]; then
		continue
	fi
	log "[+] Full-port scan: nmap_${host}"
	fixscreen "nmap_${host}" "nmap -e ${localnic} ${NMAP_OPDRACHT_ALL} ${host} -oA raw/nmap/${host}_full_scan_tcp"
done

# --- Vuln scans per host via fixscreen ---
for host in $open_hosts; do
	if [[ "$host" == *"Host"* ]] || [[ "$host" == *"#"* ]] || [[ "$host" == *"Nmap"* ]]; then
		continue
	fi
	log "[+] Vuln scan: vuln_${host}"
	fixscreen "vuln_${host}" "nmap -e ${localnic} ${NMAP_OPDRACHT_VULN} ${host} -oA raw/nmap/${host}_vuln_scan"
done

# --- Recon scans per HTTP host via fixscreen ---
WORDLIST="${WORDLIST:-/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt}"

for host in $http_hosts; do
	if [[ "$host" == *"Host"* ]] || [[ "$host" == *"#"* ]] || [[ "$host" == *"Nmap"* ]]; then
		continue
	fi
	$HAS_WHATWEB && fixscreen "whatweb_${host}" "whatweb ${host} > raw/recon/whatweb-${host}.txt" && log "[+] whatweb: ${host}"
	$HAS_WFUZZ   && fixscreen "wfuzz_${host}" "wfuzz -c -z file,${WORDLIST} --sc 200,202,204,301,302,307,403 ${host}/FUZZ > raw/recon/wfuzz-${host}.txt" && log "[+] wfuzz: ${host}"
	$HAS_NUCLEI  && fixscreen "nuclei_${host}" "nuclei -u ${host} -o raw/recon/nuclei-${host}.txt" && log "[+] nuclei: ${host}"
done

# --- Samenvatting ---
active_screens=$(screen -ls 2>/dev/null | grep -cE '(nmap_|whatweb_|wfuzz_|nuclei_|vuln_)' || true)

log ""
log "[*] Scan samenvatting:"
log "    Hosts gescand:     ${NMAP_HOST}"
log "    Engagement:        ${naam}"
log "    TCP poorten:       raw/nmap/${naam}_quick_scan_tcp.nmap"
log "    UDP poorten:       raw/nmap/${naam}_quick_scan_udp.nmap"
if $HAS_NMAPTOCSV; then
log "    Scope CSV:         raw/${naam}_scope.csv"
fi
log "    Actieve screens:   ${active_screens}"
log "    Resultaten in:     raw/"
log ""

log "[+] Parallelle scans gestart:"
screen -ls 2>/dev/null | grep -E '(nmap_|whatweb_|wfuzz_|nuclei_|vuln_|baking_)' | while read -r line; do
	log "    ${line}"
done

log "[*] Done. Gebruik 'screen -ls' om actieve scans te bekijken."
