#!/usr/bin/env bash
# Jan-Karel Visser
# AGPL-3.0-or-later licensed
# https://jan-karel.nl
# https://hacksec.nl

source meuk/globalmeuk.sh

echo "[*] Incompentent Bastard v${VERSIE}"
echo "[.] Gebruik: $0 <host> [gebruiker] [wachtwoord] [hash] [domein]"

systeem=${1:-}
naam=${2:-jan-karel}
wachtwoord=${3:-C0mpl3x.teit}
hash=${4:-}
domein=${5:-}

if [ -z "$systeem" ]; then
  echo "[.] Geef een systeem op voor RDP"
  echo "[!] You failed..."
  exit 1
fi

# Bouw domein-argument op als opgegeven
dom_arg=""
if [ -n "$domein" ]; then
  dom_arg="/d:${domein}"
fi

if [ -z "$hash" ]; then
  echo "[.] xfreerdp /u:${naam} /p:${wachtwoord} ${dom_arg} /v:${systeem}"
  xfreerdp /u:"${naam}" /p:"${wachtwoord}" ${dom_arg} /f /smart-sizing:1920x1080 +clipboard /v:"${systeem}" /cert-ignore || true
else
  echo "[.] xfreerdp /u:${naam} /pth:${hash} ${dom_arg} /v:${systeem}"
  xfreerdp /u:"${naam}" /pth:"${hash}" ${dom_arg} /f /smart-sizing:1920x1080 +clipboard /v:"${systeem}" /cert-ignore || true
fi
