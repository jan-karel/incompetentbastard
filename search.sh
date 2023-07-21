#!/usr/bin/env bash
# Jan-Karel Visser
# LGPLv3 licensed
# https://jan-karel.nl
# https://hacksec.nl

source meuk/globalmeuk.sh

echo "[.] Incompentent bastard "

naam=${1:-}
zoek=${2:-}

if [ -z "$naam" ]; then
  echo "[!] Please provide the name of the nmap file"
  echo "[!] You failed..."
  exit;
fi

if [ -z "$zoek" ]; then
  echo "[!] Please provide something to search for"
  echo "[!] You failed..."
  exit;
fi

d=$(cat raw/nmap/${naam}_quick_scan_tcp.gnmap | grep "${zoek}" | awk {'print $2":"$1'} | awk -F/ {'print $1'} | sort -u)

for xhost in $d; do

  	for yolo in $(echo $xhost | tr ":" "\n"); do

			if [[ $yolo != *"Host"* ]] && [[ $yolo != *"Ports"* ]] && [[ $yolo != *"#"* ]] && [[ $yolo != *"Nmap"* ]]; then
					echo ${yolo}	
	  	fi

		done

done