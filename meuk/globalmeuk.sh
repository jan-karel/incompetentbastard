#/bin/bash

set -euo pipefail
#IFS=$'\n\t'
PORT='443'
RE='^[0-9]+$'
REMOTE=''
IP=''
HOST=''
VERSIE='0.42'
DATUM=$(date +%d%m%Y)
NMAP_OPDRACHT_TCP="-Pn -sT -sV -d -A -F --open --max-retries 25 --max-rate 500 --max-scan-delay 50"
NMAP_OPDRACHT_UDP="-sUV -sT -T5 -F --version-intensity 0"
NMAP_OPDRACHT_VULN="-Pn -sT -sV -d --script vuln -F --open --max-retries 25 --max-rate 500 --max-scan-delay 50"
NMAP_OPDRACHT_ALL="-Pn -sT -sV -A -p- --open --max-retries 25 --max-rate 500 --max-scan-delay 50"
beginswith() { case $2 in "$1"*) true;; *) false;; esac; }

function brakkesed(){

	if [[ "$OSTYPE" == "darwin"* ]]; then

		sed -i '' -e $1

	else

		sed -i  $1

	fi

}

function startrec(){
	# Herstart het aanroepende script onder asciinema rec.
	# Gebruik: startrec "$@" (direct na source globalmeuk.sh)
	if [ -n "${IB_RECORDING:-}" ]; then return; fi
	export IB_RECORDING=1
	mkdir -p meuk/logs
	local caller="${BASH_SOURCE[1]}"
	local script_name
	script_name="$(basename "$caller" .sh)"
	local rec_file="meuk/logs/${script_name}-$(date +%Y%m%d_%H%M%S).rec"
	if command -v asciinema &>/dev/null; then
		exec asciinema rec --overwrite "$rec_file" -c "bash $caller $*"
	fi
}

function fixscreen(){
	mkdir -p meuk/logs
	if [[ "$OSTYPE" == "darwin"* ]]; then
		# macOS: geen -L screen logging beschikbaar
		screen -dmS "$1" asciinema rec --overwrite meuk/logs/"$1".rec --stdin -c "stty sane;$2"
	else
		screen -L -Logfile meuk/logs/"$1".log -t "$1" -dmS "$1" asciinema rec --overwrite meuk/logs/"$1".rec --stdin -c "stty sane;$2"
	fi
}

function getip() { 
if [[ "$OSTYPE" == "darwin"* ]]; then
 	$(ip -o -4 addr list "$1" | grep inet |  awk '{print $2}' | cut -d/ -f1);
else
	$(ip -o -4 addr list "$1" | awk '{print $4}' | cut -d/ -f1);
fi
}

function getpublicip {

	curl -$1 --fail --silent --max-time 15 icanhazip.com 2>/dev/null || /bin/true
}