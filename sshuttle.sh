#!/usr/bin/env bash
# Jan-Karel Visser
# AGPL-3.0-or-later licensed
# https://jan-karel.nl
# https://hacksec.nl

source meuk/globalmeuk.sh

echo "[*] Incompentent Bastard v${VERSIE}"

# Gebruik:
#   bash sshuttle.sh user@host 10.1.0.0/24
#   SSH_KEY=raw/loot/10.0.0.5/id_rsa bash sshuttle.sh user@host 10.1.0.0/24
#   SSH_PASS=wachtwoord bash sshuttle.sh user@host 10.1.0.0/24
#   SSH_KEY=id_rsa SSH_PASS=keypass bash sshuttle.sh user@host 10.1.0.0/24

SSHUTTLE_ARGS=(-r "$1" "$2")

if [ -n "$SSH_KEY" ]; then
	SSHUTTLE_ARGS=(--ssh-cmd "ssh -i $SSH_KEY" "${SSHUTTLE_ARGS[@]}")
fi

if [ -n "$SSH_PASS" ]; then
	screen -dmS "sshuttle_${1}" sshpass -p "$SSH_PASS" sshuttle "${SSHUTTLE_ARGS[@]}"
else
	screen -dmS "sshuttle_${1}" sshuttle "${SSHUTTLE_ARGS[@]}"
fi
