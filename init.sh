#!/usr/bin/env bash
# Jan-Karel Visser
# AGPL-3.0-or-later licensed
# https://jan-karel.nl
# https://hacksec.nl

source meuk/globalmeuk.sh

echo "[*] Incompentent Bastard v${VERSIE}"

locatie="$PWD"

#just in kaas
#rm -rf $locatie/raw
#folders aanmaken
mkdir -p raw/recon raw/route raw/screenshots raw/tls raw/nmap raw/wget meuk/logs meuk/wordlists raw/tooling http/payloads
rm -rf meuk/logs/*.rec

# Virtual environment aanmaken en dependencies installeren
if [ ! -f ".venv/bin/flask" ]; then
	echo '[*] Venv aanmaken en dependencies installeren...'
	python3 -m venv .venv
	.venv/bin/pip install --quiet -r requirements.txt
	echo '[+] Venv klaar.'
fi

echo 'no' | sudo msfdb init || true || true


#rapportage aanmaken
#cp -r $locatie/templates/rapport rapport


if [[ "$OSTYPE" == "darwin"* ]]; then
	#screenshots zetten
	defaults write com.apple.screencapture location $locatie/raw/screenshots/
	killall SystemUIServer || true
fi

#vpn

if [ -e "${locatie}/meuk/client.ovpn" ]; then

	if [[ "$OSTYPE" == "darwin"* ]]; then
	 	screen -dmS vpn openvpn meuk/client.ovpn
	else
	 	screen -L -Logfile meuk/logs/vpn.log -dmS vpn openvpn meuk/client.ovpn
	fi
fi 

if [[ "$OSTYPE" == "darwin"* ]]; then
	screen -dmS smb smbserver.py share http -smb2support


	#screen -dmS http sh -c "cd http && python3 -m http.server 80"
	screen -dmS http sh -c ".venv/bin/flask --app app:create_app db migrate; .venv/bin/flask --app app:create_app db upgrade; .venv/bin/flask --app app:create_app run --host=0.0.0.0 --port=80 --debug > meuk/logs/http.log 2>&1"
	#screen -dmS metasploit sh -c "stty sane; msfconsole"
	screen -dmS tcpdump sh -c "stty sane; tcpdump -i any icmp -w raw/icmp.pcap"

	screen -dmS metasploit asciinema rec meuk/logs/metasploit.rec --stdin -c "stty sane;msfconsole"
	screen -dmS msfrpcd sh -c "stty sane; msfrpcd -P ${MSF_RPC_PASS:-msf} -U ${MSF_RPC_USER:-msf} -p ${MSF_RPC_PORT:-55553} -a 127.0.0.1 -S -f > meuk/logs/msfrpcd.log 2>&1"
	#screen -dmS tcpdump asciinema rec meuk/logs/"$1".rec --stdin -c "stty sane; tcpdump -i any icmp -w raw/icmp.pcap"


else
	screen -L -Logfile meuk/logs/smb.log -dmS smb impacket-smbserver share http -smb2support
	#screen -L -Logfile meuk/logs/http.log -dmS http sh -c "cd http && python3 -m http.server 80"
	screen -L -Logfile meuk/logs/http.log -dmS http sh -c ".venv/bin/flask --app app:create_app db migrate; .venv/bin/flask --app app:create_app db upgrade; .venv/bin/flask --app app:create_app run --host=0.0.0.0 --port=80 --debug"
	screen -L -Logfile meuk/logs/metasploit.log -t metasploit -dmS metasploit asciinema rec meuk/logs/metasploit.rec --stdin -c "stty sane;msfconsole"
	#screen -L -Logfile meuk/logs/metasploit.log -dmS metasploit sh -c "stty sane; msfconsole"
	screen -L -Logfile meuk/logs/msfrpcd.log -dmS msfrpcd sh -c "stty sane; msfrpcd -P ${MSF_RPC_PASS:-msf} -U ${MSF_RPC_USER:-msf} -p ${MSF_RPC_PORT:-55553} -a 127.0.0.1 -S -f"
	screen -dmS tcpdump sh -c "stty sane; tcpdump -i any icmp -w raw/icmp.pcap"
fi 



echo '[+] Screens set...'
screen -list

echo '[+] Logging tool versions...'
_vlog() { "$1" "${2:---version}" 2>&1 | sed "s/\x1b\[[0-9;]*m//g" > "raw/tooling/$3" || true; }
#versies zetten
_vlog wafw00f --version   wafw00f-versie.txt
_vlog curl    --version   curl-versie.txt
_vlog nmap    --version   nmap-versie.txt
_vlog nikto   -Version    nikto-versie.txt
#_vlog wapiti  --version   wapiti-versie.txt
_vlog nuclei  --version   nuclei-versie.txt
_vlog sqlmap  --version   sqlmap-versie.txt
_vlog whatweb --version   whatwheb-versie.txt
_vlog dnsrecon --version  dnsrecon-versie.txt
_vlog sslscan --version   sslscan-versie.txt
testssl --version 2>&1 | sed "s/\x1b\[[0-9;]*m//g" > raw/tooling/testssl-versie.txt || true
#zapversie=$(ls /usr/share/zaproxy/ | grep jar)
#echo $zapversie > raw/tooling/zap-versie.txt
_vlog wget    --version   wget-versie.txt
dirb 2>&1 | head -5 > raw/tooling/dirb-versie.txt || true
_vlog msfconsole --version metasploit-version.txt


