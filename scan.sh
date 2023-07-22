#!/usr/bin/env bash
# Jan-Karel Visser
# LGPLv3 licensed
# https://jan-karel.nl
# https://hacksec.nl

source meuk/globalmeuk.sh

echo "[*] Incompentent Bastard v${VERSIE}"

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
	exit;

fi


if [ -z "$HOSTS" ]; then
  	echo "[!] Please provide the range to scan"
  	echo "[!] You failed..."
	exit;
fi


#evidence folder, speltip: geen spaties
mkdir -p raw/{recon,local,screenshots,nmap,loot,route,debug,exploits,mirror,spider,tooling}


#todo mv template/rapport .

echo "Lokale configuratie loggen."
id > raw/local/id.txt
cat /etc/os-release > raw/local/release.txt
date > raw/local/date.txt
cat raw/local/date.txt
uname -a > raw/local/uname.txt
uname -r > raw/local/unamer.txt
ifconfig > raw/local/ifconfig.txt 
cat raw/local/ifconfig.txt

getpublicip 4 > raw/local/remoteip.txt
getpublicip 6 > raw/local/remoteipv6.txt


NMAP_HOST=${HOSTS//,/' '}
echo "Poortscan op ${NMAP_HOST}..."
nmap -e $localnic $NMAP_OPDRACHT_TCP $NMAP_HOST -oA raw/nmap/${naam}_quick_scan_tcp
nmaptocsv -i raw/nmap/${naam}_quick_scan_tcp.nmap -f ip-fqdn-port-protocol-service > raw/nmap/${naam}_tcp-poorten.txt
sed -i 's/";"/},{/g' raw/nmap/${naam}_tcp-poorten.txt
sed -i 's/.$/}/' raw/nmap/${naam}_tcp-poorten.txt
sed -i 's/"/{/g' raw/nmap/${naam}_tcp-poorten.txt


nmaptocsv -i raw/nmap/${naam}_quick_scan_tcp.nmap -f fqdn-service-version-os > raw/nmap/${naam}_tcp-versies.txt
sed -i 's/";"/},{/g' raw/nmap/${naam}_tcp-versies.txt
sed -i 's/.$/}/' raw/nmap/${naam}_tcp-versies.txt
sed -i 's/"/{/g' raw/nmap/${naam}_tcp-versies.txt


#cat raw/nmap/quick_scan_tcp
nmap -e $localnic $NMAP_OPDRACHT_UDP $NMAP_HOST -oA raw/nmap/${naam}_quick_scan_udp
nmaptocsv -i raw/nmap/${naam}_quick_scan_udp.nmap -f ip-fqdn-port-protocol-service > raw/nmap/${naam}_udp-poorten.txt
sed -i 's/";"/},{/g' raw/nmap/${naam}_udp-poorten.txt
sed -i 's/.$/}/' raw/nmap/${naam}_udp-poorten.txt
sed -i 's/"/{/g' raw/nmap/${naam}_udp-poorten.txt

nmaptocsv -i raw/nmap/${naam}_quick_scan_tcp.nmap -f fqdn-rdns-ip > raw/{naam}_scope.csv
sed -i 's/";"/},{/g' raw/${naam}_scope.csv
sed -i 's/.$/}/' raw/${naam}_scope.csv
sed -i 's/"/{/g' raw/${naam}_scope.csv
#done
