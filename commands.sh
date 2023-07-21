#!/usr/bin/env bash

source meuk/globalmeuk.sh

sessie=${1:-}
opdracht=${2:-}

echo "[.] Incompentent bastard "

screen -list

echo 'find your commands in http/commands'
if [ -z "$sessie" ]; then
  echo "[!] Give me a screen session"
  exit;
fi

if [ -z "$opdracht" ]; then
  echo "[!] Give me command_list file from http/command"
  exit;
fi

opdrachten=$(cat http/commands/${opdracht});

screen -S $sessie -X stuff "${opdrachten}"^M
