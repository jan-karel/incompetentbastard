#!/usr/bin/env bash
# Jan-Karel Visser
# LGPLv3 licensed
# https://jan-karel.nl
# https://hacksec.nl

source meuk/globalmeuk.sh

echo "[*] Incompentent Bastard v${VERSIE}"

systeem=${1:-}
naam=${2:'jan-karel'}
wachtwoord=${3:'C0mpl3x.teit'}
hash=${4:-}


if [ -z "$systeem" ]; then
  echo "[.] Please provide a system to RDP into"
  echo "[!] You failed..."
  exit;
fi
if [ -z "$hash" ]; then
  echo "[.]xfreerdp /u:${naam} /p:${wachtwoord} /f /smart-sizing:1920x1080 +clipboard /v:${systeem} /cert-ignore"
  xfreerdp /u:${naam} /p:${wachtwoord} /f /smart-sizing:1920x1080 +clipboard /v:${systeem} /cert-ignore
else
  echo "[.]xfreerdp /u:${naam} /pth:${hash} /f /smart-sizing:1920x1080 +clipboard /v:${systeem} /cert-ignore"
  xfreerdp /u:${naam} /pth:${hash} /f /smart-sizing:1920x1080 +clipboard /v:${systeem} /cert-ignore
fi
