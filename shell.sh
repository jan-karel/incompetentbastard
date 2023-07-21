#!/usr/bin/env bash

source meuk/globalmeuk.sh

echo "[.] Incompentent bastard "

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
