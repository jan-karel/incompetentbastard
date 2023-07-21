#!/usr/bin/env bash

source meuk/globalmeuk.sh

naam=${1:-}
opdracht=${2:-}

if [ -z "$naam" ]; then
  echo "[.] Please provide one of the named screen sessions above"
  exit;
fi

if [ -z "$opdracht" ]; then
  opdracht='/bin/sh -i'
fi 

fixscreen $naam $opdracht

sleep 1
screen -r "$naam"
