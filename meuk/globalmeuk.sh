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
	local _asciinema=""
	if [ -x ".venv/bin/asciinema" ]; then _asciinema=".venv/bin/asciinema"
	elif command -v asciinema &>/dev/null; then _asciinema="asciinema"
	fi
	if [ -n "$_asciinema" ]; then
		exec "$_asciinema" rec --overwrite "$rec_file" -c "bash $caller $*"
	fi
}

function fixscreen(){
	mkdir -p meuk/logs
	# Zoek asciinema: eerst venv, dan PATH
	local ASCIINEMA=""
	if [ -x ".venv/bin/asciinema" ]; then
		ASCIINEMA=".venv/bin/asciinema"
	elif command -v asciinema &>/dev/null; then
		ASCIINEMA="asciinema"
	fi

	if [ -n "$ASCIINEMA" ]; then
		if [[ "$OSTYPE" == "darwin"* ]]; then
			screen -dmS "$1" "$ASCIINEMA" rec --overwrite meuk/logs/"$1".rec --stdin -c "stty sane;$2"
		else
			screen -L -Logfile meuk/logs/"$1".log -t "$1" -dmS "$1" "$ASCIINEMA" rec --overwrite meuk/logs/"$1".rec --stdin -c "stty sane;$2"
		fi
	else
		# Geen asciinema beschikbaar — start direct zonder opname
		if [[ "$OSTYPE" == "darwin"* ]]; then
			screen -dmS "$1" sh -c "stty sane;$2"
		else
			screen -L -Logfile meuk/logs/"$1".log -t "$1" -dmS "$1" sh -c "stty sane;$2"
		fi
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