#!/usr/bin/env bash

source meuk/globalmeuk.sh

scanfile=${1:-}

if [ -z "$scanfile" ]; then
  echo "naam?"
  exit;
fi

result=$(sh -c "./search.sh ${scanfile} ftp")

for xhost in $result; do

  echo "[!] Checking ${xhost}..."
	nmap -T5 -sV -sC -p21 --script ftp-anon --script-args ftp-anon.maxlist=-1 $xhost
  echo "[.] Done..."

done