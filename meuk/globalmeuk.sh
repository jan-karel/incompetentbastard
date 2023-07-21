#/bin/bash

set -euo pipefail
#IFS=$'\n\t'
PORT='443'
RE='^[0-9]+$'
REMOTE=''
IP=''
HOST=''
DATUM=$(date +%d%m%Y)
NMAP_OPDRACHT_TCP="-Pn -sT -sV -d -A -F --open --max-retries 25 --max-rate 500 --max-scan-delay 50"
NMAP_OPDRACHT_UDP="-sUV -sT -T5 -F --version-intensity 0"
NMAP_OPDRACHT_VULN="-Pn -sT -sV -d --script vuln -F --open --max-retries 25 --max-rate 500 --max-scan-delay 50"
beginswith() { case $2 in "$1"*) true;; *) false;; esac; }

function brakkesed(){

	if [[ "$OSTYPE" == "darwin"* ]]; then

		sed -i '' -e $1

	else

		sed -i  $1

	fi

}

function fixscreen(){
if [[ "$OSTYPE" == "darwin"* ]]; then
	#geen default screen logging op macos, vieze fix
	screen -dmS "$1" asciinema rec meuk/logs/"$1".rec --stdin -c "$2"

else
	#asciinema rec meuk/logs/"$1".rec 
	screen -L -Logfile meuk/logs/"$1".log -t "$1" -dmS "$1" asciinema rec meuk/logs/"$1".rec --stdin -c "$2"
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