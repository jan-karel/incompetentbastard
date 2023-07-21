#!/usr/bin/env bash
# Jan-Karel Visser
# LGPLv3 licensed
# https://jan-karel.nl
# https://hacksec.nl

source meuk/globalmeuk.sh

echo "[*] Incompentent Bastard v${VERSIE}"

scanfile=${1:-}

if [ -z "$scanfile" ]; then
  echo "[!] Please provide the name of the nmap file"
  echo "[!] You failed..."
  exit;
fi

result=$(sh -c "./search.sh ${scanfile} ftp")

for xhost in $result; do

  echo "[!] Checking ${xhost}..."
	nmap -T5 -sV -sC -p21 --script ftp-anon --script-args ftp-anon.maxlist=-1 $xhost
  echo "[*] Done..."

done