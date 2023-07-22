#!/usr/bin/env bash
# Jan-Karel Visser
# LGPLv3 licensed
# https://jan-karel.nl
# https://hacksec.nl

source meuk/globalmeuk.sh

echo "[*] Incompentent Bastard v${VERSIE}"

locatie="$PWD"

#just in kaas
#rm -rf $locatie/raw
#folders aanmaken
mkdir -p raw/recon raw/route raw/screenshots raw/tls raw/nmap raw/wget meuk/logs meuk/wordlists raw/tooling

echo 'no' | msfdb init


#rapportage aanmaken
#cp -r $locatie/templates/rapport rapport


if [[ "$OSTYPE" == "darwin"* ]]; then
	#screenshots zetten
	defaults write com.apple.screencapture location $locatie/raw/screenshots/
	killall SystemUIServer
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
	screen -dmS http sh -c "cd http && python3 -m http.server 80"
	screen -dmS metasploit sh -c "stty sane; msfconsole"
else
	screen -L -Logfile meuk/logs/smb.log -dmS smb impacket-smbserver share http -smb2support
	screen -L -Logfile meuk/logs/http.log -dmS http sh -c "cd http && python3 -m http.server 80"
	screen -L -Logfile meuk/logs/metasploit.log -dmS metasploit sh -c "stty sane; msfconsole"
fi 


#versies zetten
wafw00f --version > raw/tooling/wafw00f-versie.txt
cat raw/tooling/wafw00f-versie.txt | sed "s/\x1b[^m]*m//g" > raw/tooling/wafw00f-versie.txt
curl --version > raw/tooling/curl-versie.txt
nmap --version > raw/tooling/nmap-versie.txt
nikto -Version > raw/tooling/nikto-versie.txt
#wapiti --version > raw/tooling/wapiti-versie.txt
nuclei --version > raw/tooling/nuclei-versie.txt
sqlmap --version > raw/tooling/sqlmap-versie.txt
whatweb --version > raw/tooling/whatwheb-versie.txt
dnsrecon --version > raw/tooling/dnsrecon-versie.txt
sslscan --version > raw/tooling/sslscan-versie.txt
testssl --version > raw/tooling/testssl-versie.txt
cat raw/tooling/testssl-versie.txt | sed "s/\x1b[^m]*m//g" > raw/tooling/testssl-versie.txt
#zapversie=$(ls /usr/share/zaproxy/ | grep jar)
#echo $zapversie > raw/tooling/zap-versie.txt
wget --version > raw/tooling/wget-versie.txt
dirb > raw/tooling/dirb-versie.txt
msfconsole --version > raw/tooling/metasploit-version.txt