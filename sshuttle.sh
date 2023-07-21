#!/usr/bin/env bash
# Jan-Karel Visser
# LGPLv3 licensed
# https://jan-karel.nl
# https://hacksec.nl

source meuk/globalmeuk.sh

echo "[.] Incompentent Bastard "

screen -dmS sshuttle_${1} sshuttle -r ${1} ${2}
