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

if [[ "$OSTYPE" == "darwin"* ]]; then

	#todo
	:
else
	nmcli dev show $localnic > raw/local/nmcli.txt
fi



if [[ ! -f http/payloads/shell_443.txt ]]
	screen -dmS baking_shells ./reverseshells.sh $localnic
fi

NMAP_HOST=${HOSTS//,/' '}
echo "Poortscan op ${NMAP_HOST}..."
nmap -e $localnic $NMAP_OPDRACHT_TCP $NMAP_HOST -oA raw/nmap/${naam}_quick_scan_tcp
nmaptocsv -i raw/nmap/${naam}_quick_scan_tcp.nmap -f ip-fqdn-port-protocol-service > raw/nmap/${naam}_tcp-poorten.txt
brakkesed 's/";"/},{/g' raw/nmap/${naam}_tcp-poorten.txt
brakkesed 's/.$/}/' raw/nmap/${naam}_tcp-poorten.txt
brakkesed 's/"/{/g' raw/nmap/${naam}_tcp-poorten.txt


nmaptocsv -i raw/nmap/${naam}_quick_scan_tcp.nmap -f fqdn-service-version-os > raw/nmap/${naam}_tcp-versies.txt
brakkesed 's/";"/},{/g' raw/nmap/${naam}_tcp-versies.txt
brakkesed 's/.$/}/' raw/nmap/${naam}_tcp-versies.txt
brakkesed 's/"/{/g' raw/nmap/${naam}_tcp-versies.txt


#cat raw/nmap/quick_scan_tcp
nmap -e $localnic $NMAP_OPDRACHT_UDP $NMAP_HOST -oA raw/nmap/${naam}_quick_scan_udp
nmaptocsv -i raw/nmap/${naam}_quick_scan_udp.nmap -f ip-fqdn-port-protocol-service > raw/nmap/${naam}_udp-poorten.txt
brakkesed 's/";"/},{/g' raw/nmap/${naam}_udp-poorten.txt
brakkesed 's/.$/}/' raw/nmap/${naam}_udp-poorten.txt
brakkesed 's/"/{/g' raw/nmap/${naam}_udp-poorten.txt

nmaptocsv -i raw/nmap/${naam}_quick_scan_tcp.nmap -f fqdn-rdns-ip > raw/${naam}_scope.csv
brakkesed 's/";"/},{/g' raw/${naam}_scope.csv
brakkesed 's/.$/}/' raw/${naam}_scope.csv
brakkesed 's/"/{/g' raw/${naam}_scope.csv


#alvast de basis acties
d=$(cat raw/nmap/${naam}_quick_scan_tcp.gnmap | grep "http" | awk {'print $2":"$1'} | awk -F/ {'print $1'} | sort -u)
o=$(cat raw/nmap/${naam}_quick_scan_tcp.gnmap | grep "open" | awk {'print $2":"$1'} | awk -F/ {'print $1'} | sort -u)

for xhost in $o; do

        for yolo in $(echo $xhost | tr ":" "\n"); do

                if [[ $yolo != *"Host"* ]] && [[ $yolo != *"Ports"* ]] && [[ $yolo != *"#"* ]] && [[ $yolo != *"Nmap"* ]]; then

                	echo "[+] screen nmap_${yolo} ...."
        			screen -dmS nmap_${yolo} -e $localnic $NMAP_OPDRACHT_ALL ${yolo} -oA raw/nmap/${yolo}_full_scan_tcp          


                fi

                done

done
for xhost in $d; do

        for yolo in $(echo $xhost | tr ":" "\n"); do

                if [[ $yolo != *"Host"* ]] && [[ $yolo != *"Ports"* ]] && [[ $yolo != *"#"* ]] && [[ $yolo != *"Nmap"* ]]; then

                	whatweb ${yolo} > raw/recon/whatweb-${yolo}.txt 
        			wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --sc 200,202,204,301,302,307,403 ${yolo}/FUZZ > raw/recon/wfuzz-${yolo}.txt  
    				nuclei -h ${yolo} > raw/recon/nuclei-${yolo}.txt 

                fi

                done

done





#done