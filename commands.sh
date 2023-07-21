#!/usr/bin/env bash
# Jan-Karel Visser
# LGPLv3 licensed
# https://jan-karel.nl
# https://hacksec.nl

source meuk/globalmeuk.sh

sessie=${1:-}
opdracht=${2:-}

echo "[*] Incompentent Bastard v${VERSIE}"

screen -list

echo 'find your commands in http/commands'
if [ -z "$sessie" ]; then
  echo "[!] Give me a screen session"
  echo "[!] You failed..."
  exit;
fi

if [ -z "$opdracht" ]; then
  echo "[!] Give me command_list file from http/command"
  echo "[!] You failed..."
  exit;
fi

opdrachten=$(cat http/commands/${opdracht});

screen -S $sessie -X stuff "${opdrachten}"^M
