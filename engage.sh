#!/usr/bin/env bash
# Jan-Karel Visser
# LGPLv3 licensed
# https://jan-karel.nl
# https://hacksec.nl


echo "[*] Incompentent Bastard v${VERSIE}"

screen -dmS openvpn openvpn meuk/client.ovpn
screen -dmS empire powershell-empire server