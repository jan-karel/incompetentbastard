#!/usr/bin/env bash

source meuk/globalmeuk.sh

systeem=${1:-}


if [ -z "$systeem" ]; then
  echo "[.] Please provide a system to RDP into"
  exit;
fi

xfreerdp /u:jan-karel /p:C0mpl3x.teit /smart-sizing:1920x1080 +clipboard /v:${systeem} /cert-ignore
