#/bin/bash

set -euo pipefail
#IFS=$'\n\t'
PORT='443'
RE='^[0-9]+$'
REMOTE=''
IP=''
HOST=''
SERVE=$( shuf -i 8000-9000 -n 1 )
DATUM=$(date +%d%m%Y)
NMAP_OPDRACHT_TCP="-Pn -sT -sV -d -A -F --open --max-retries 25 --max-rate 500 --max-scan-delay 50"
NMAP_OPDRACHT_UDP="-sUV -sT -T5 -F --version-intensity 0"
NMAP_OPDRACHT_VULN="-Pn -sT -sV -d --script vuln -F --open --max-retries 25 --max-rate 500 --max-scan-delay 50"
beginswith() { case $2 in "$1"*) true;; *) false;; esac; }
function getip { $(/sbin/ip -o -4 addr list "$1" | awk '{print $4}' | cut -d/ -f1);}

function getpublicip {

	curl -$1 --fail --silent --max-time 15 icanhazip.com 2>/dev/null || /bin/true
}