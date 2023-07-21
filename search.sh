#!/usr/bin/env bash

source meuk/globalmeuk.sh

echo "[.] Incompentent bastard "

naam=${1:-}
zoek=${2:-}

if [ -z "$naam" ]; then
  echo "naam?"
  exit;
fi

if [ -z "$zoek" ]; then
  echo "zoek?"
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