#!/usr/bin/env bash
# Jan-Karel Visser
# LGPLv3 licensed
# https://jan-karel.nl
# https://hacksec.nl

source meuk/globalmeuk.sh

echo "[*] Incompentent Bastard v${VERSIE}"

#met privkey
#screen -dmS sshuttle_${1} sshuttle --ssh-cmd="ssh -i raw/loot/127.0.0.1/id_rsa" -r ${1} ${2}
screen -dmS sshuttle_${1} sshuttle -r ${1} ${2}
