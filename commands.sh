#!/usr/bin/env bash

source meuk/globalmeuk.sh

sessie=${1:-}
opdracht=${2:-}

screen -list

echo 'find your commands in http/commands'
if [ -z "$sessie" ]; then
  echo "give screen session"
  exit;
fi

if [ -z "$opdracht" ]; then
  echo "give command_list"
  exit;
fi

opdrachten=$(cat http/commands/${opdracht});

screen -S $sessie -X stuff "${opdrachten}"^M
