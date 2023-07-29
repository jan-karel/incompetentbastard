#!/usr/bin/env bash
# Jan-Karel Visser
# LGPLv3 licensed
# https://jan-karel.nl
# https://hacksec.nl

source meuk/globalmeuk.sh

echo "[*] Incompentent Bastard v${VERSIE}"
echo "[.] For already created screens... just use screen -x"
naam=${1:-}
opdracht=${2:-}

if [ -z "$naam" ]; then
  echo "[.] Please provide a name for the screen"
  echo "[!] You failed..."
  exit;
fi

if [ -z "$opdracht" ]; then
  opdracht='/bin/sh -i'
fi 

fixscreen $naam $opdracht

sleep 1

screen -r "$naam"
