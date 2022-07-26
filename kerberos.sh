#!/bin/bash

scanfile=${1:-}

if [ -z "$scanfile" ]; then
  echo "naam?"
  exit;
fi


result=$(sh -c "./search.sh ${scanfile} kerberos")

for xhost in $result; do

	echo "[+] Checking ${xhost}..."
  dcnaam=$(crackmapexec smb ${xhost} | awk '{print $4}')
  domain=$(crackmapexec smb ${xhost} | grep '(domain:' |  cut -d ':' -f 3 | cut -d ')' -f 1) 

  nmap -sV -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm=${domain} $xhost
  ldapsearch -LLL -x -H ldap://${domain} -b '' -s base '(objectclass=User*)'
  echo "[.] Done..."

done