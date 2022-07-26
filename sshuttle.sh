#/bin/bash


screen -dmS sshuttle_${1} sshuttle -r ${1} ${2}
