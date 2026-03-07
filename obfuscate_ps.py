#!/usr/bin/python3
"""Gerichte AMSI-obfuscatie voor PowerShell scripts.

Past alleen obfuscatie toe op regels die bekende AMSI-signatures bevatten.
De rest van het script blijft ongewijzigd en leesbaar.

Optioneel: integratie met ClamAV, YARA community rules en Windows Defender
YARA rules voor automatische signature-extractie en verificatie.

Gebruik:
    python3 obfuscate_ps.py <input.ps1> [-o output.ps1] [-v] [-n] [--seed N]
    python3 obfuscate_ps.py --update-sigs [--sources clamav,yara,defender]
    python3 obfuscate_ps.py --scan --check input.ps1
"""

import argparse
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

# ── ClamAV integratie constanten ───────────────────────────────────────

DEFAULT_CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "obfuscate-ps")
CLAMAV_CACHE_FILE = "clamav-ps-sigs.json"
CLAMAV_CACHE_META = "clamav-meta.json"
DAILY_CVD_URL = "https://database.clamav.net/daily.cvd"

# ── YARA / Defender constanten ────────────────────────────────────────

YARA_CACHE_FILE = "yara-ps-sigs.json"
DEFENDER_CACHE_FILE = "defender-ps-sigs.json"

YARA_REPOS = {
    "neo23x0": "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip",
}
DEFENDER_REPO = "https://github.com/roadwy/DefenderYara/archive/refs/heads/main.zip"
DEFENDER_REPO_FALLBACKS = [
    "https://github.com/roadwy/DefenderYara/archive/refs/heads/master.zip",
    "https://github.com/roadwy/DefenderYara/archive/refs/heads/yara-rules.zip",
]

VALID_SOURCES = ("clamav", "yara", "defender")

PS_SIG_KEYWORDS = [
    "rubeus", "mimikatz", "sharphound", "kerberoast", "invoke-",
    "powershell", "amsi", "powerview", "powerup", "bloodhound",
    "safetykatz", "sharpkatz", "seatbelt", "certify", "whisker",
    "covenant", "empire", "cobalt", "beacon", "meterpreter",
    "lazagne", "petitpotam", "printspoofer", "godpotato",
    "sweetpotato", "juicypotato", "psexec", "winpeas",
    "scriptblock", "runspacefactory", "reflection.assembly",
    "net.webclient", "downloadstring", "downloadfile",
    "system.management.automation", "amsiinitfailed",
    "amsiutils", "amsiscanbuffer",
]

# ── Ingebouwde AMSI signature database ──────────────────────────────────

BUILTIN_SIGNATURES = {
    # String signatures: tool namen, commando-strings
    # Worden geobfusceerd met subexpressie/format/chararray
    "string": [
        # Potato familie
        "GodPotato", "PrintSpoofer", "PrintSpoofer64",
        "SweetPotato", "JuicyPotato",
        # Kerberos tools
        "Rubeus",
        # Exploits
        "Invoke-Nightmare", "CVE-2021-1675",
        # Payload generators
        "msfvenom",
        # Credential dumping
        "comsvcs.dll", "MiniDump",
        "lsass",
        # Registry credential dump
        r"HKLM\SAM", r"HKLM\SYSTEM",
    ],

    # Code signatures: type references, cmdlet namen
    # Worden geobfusceerd met backtick insertion
    "code": [
        "[scriptblock]",
        "[runspacefactory]",
        "[powershell]",
        "Invoke-WebRequest",
        "Invoke-RestMethod",
        "Invoke-Expression",
    ],
}


# ── Obfuscatiefuncties ──────────────────────────────────────────────────

def obf_subexpr(s):
    """String naar PowerShell subexpressie: 'GodPotato' -> "$('God'+'Potato')"

    Splitpunt wordt willekeurig gekozen zodat het patroon per run varieert.
    """
    if len(s) < 3:
        return s
    lo = max(1, len(s) // 2 - 2)
    hi = min(len(s) - 1, len(s) // 2 + 2)
    i = random.randint(lo, hi)
    return "$('%s'+'%s')" % (s[:i], s[i:])


def obf_backtick(s):
    """Backtick insertion op strategische posities.

    'Invoke-WebRequest' -> 'Inv`oke-WebR`equest'
    Alleen voor cmdlet-namen — NIET voor type-literals ([scriptblock] etc.),
    want PS zoekt het type letterlijk inclusief backticks.
    Plaatst 1-2 backticks, nooit aan begin/eind, nooit voor speciale
    escape-tekens (n, t, r, 0, a, b, f, v).
    """
    escape_chars = set("ntr0abfvNTR")
    candidates = []
    for i in range(1, len(s) - 1):
        ch = s[i]
        prev = s[i - 1]
        if ch.isalpha() and ch not in escape_chars and prev.isalpha():
            candidates.append(i)
    if not candidates:
        return s
    count = min(random.randint(1, 2), len(candidates))
    positions = sorted(random.sample(candidates, count), reverse=True)
    result = list(s)
    for pos in positions:
        result.insert(pos, '`')
    return ''.join(result)


def obf_type_literal(s):
    """Type literal naar -as [type] constructie.
    '[scriptblock]' -> "(('scri'+'ptblock')-as[type])"

    Werkt via PowerShell type accelerator resolution. Backtick
    werkt NIET in type-literals — PS zoekt letterlijk naar het type
    inclusief backticks.
    """
    inner = s[1:-1]  # strip [ en ]
    if len(inner) < 3:
        return s
    lo = max(1, len(inner) // 2 - 2)
    hi = min(len(inner) - 1, len(inner) // 2 + 2)
    i = random.randint(lo, hi)
    return "(('%s'+'%s')-as[type])" % (inner[:i], inner[i:])


def obf_chararray(s):
    """Char array constructie: 'lsass' -> "$([char[]]@(108,115,97,115,115)-join'')" """
    codes = ','.join(str(ord(c)) for c in s)
    return "$([char[]]@(%s)-join'')" % codes


def obf_format(s):
    """Format string met single quotes, veilig binnen double-quoted strings.
    'GodPotato' -> "$('{0}{1}'-f'God','Potato')"
    """
    if len(s) < 3:
        return s
    lo = max(1, len(s) // 2 - 2)
    hi = min(len(s) - 1, len(s) // 2 + 2)
    i = random.randint(lo, hi)
    return "$('{0}{1}'-f'%s','%s')" % (s[:i], s[i:])


# ── Techniek selectie ───────────────────────────────────────────────────

STRING_TECHNIQUES = {
    "subexpr":   obf_subexpr,
    "format":    obf_format,
    "chararray": obf_chararray,
}


def pick_string_technique(technique_mode):
    """Kies een obfuscatie-techniek voor string signatures."""
    if technique_mode == "mixed":
        return random.choice([obf_subexpr, obf_format])
    if technique_mode in STRING_TECHNIQUES:
        return STRING_TECHNIQUES[technique_mode]
    return obf_subexpr


# ── Engine ───────────────────────────────────────────────────────────────

def _is_comment_line(line):
    """Check of een regel een comment is (begint met # na optionele whitespace)."""
    stripped = line.lstrip()
    return stripped.startswith('#') or stripped.startswith('<#')


def _is_in_param_block(lines, line_idx):
    """Simpele heuristiek: check of we in het param() block zitten (eerste 100 regels)."""
    if line_idx > 100:
        return False
    # Zoek of er een param( is en of we er nog in zitten
    in_param = False
    depth = 0
    for i in range(min(line_idx + 1, len(lines))):
        stripped = lines[i].strip()
        if stripped.lower().startswith('param(') or stripped.lower().startswith('param ('):
            in_param = True
        if in_param:
            depth += stripped.count('(') - stripped.count(')')
            if depth <= 0 and i > 0:
                in_param = False
        if i == line_idx:
            return in_param
    return False


def _compute_param_range(lines):
    """Bereken eenmalig het regelindex-bereik van het param-blok.

    Geeft (start, end) terug als een param-blok gevonden is, anders None.
    Vervangt herhaalde _is_in_param_block-aanroepen in obfuscate_file.
    """
    start = None
    depth = 0
    for i in range(min(101, len(lines))):
        stripped = lines[i].strip()
        s_lower = stripped.lower()
        if start is None and (s_lower.startswith('param(') or s_lower.startswith('param (')):
            start = i
        if start is not None:
            depth += stripped.count('(') - stripped.count(')')
            if depth <= 0 and i > start:
                return (start, i)
    return None


def _already_obfuscated(line, sig):
    """Check of de signature al geobfusceerd is (bevat backtick, split, of -as[type])."""
    # Check of er al een backtick-versie is
    for i in range(1, len(sig) - 1):
        if sig[:i] + '`' + sig[i:] in line:
            return True
    line_lower = line.lower()
    # Check of er al een subexpr/format split is
    if "$(" in line:
        for i in range(1, len(sig)):
            if ("'%s'+'%s'" % (sig[:i], sig[i:])).lower() in line_lower:
                return True
    # Check of er al een -as[type] versie is
    if "-as[type])" in line_lower:
        inner = sig.strip('[]')
        for i in range(1, len(inner)):
            if ("'%s'+'%s'" % (inner[:i], inner[i:])).lower() in line_lower:
                return True
    return False


def _make_pattern(sig):
    """Bouw regex pattern met word boundaries.

    Voorkomt matching binnen variabele namen ($lsassId) of langere
    identifiers (ScriptBlockLogging). Niet-woordtekens in de signature
    (zoals [ ] . \\) fungeren als natuurlijke grenzen.
    """
    escaped = re.escape(sig)
    # Voeg lookbehind/lookahead toe als de signature begint/eindigt
    # met een woordteken (letter, cijfer, underscore)
    prefix = r'(?<![\w$])' if sig[0].isalnum() or sig[0] == '_' else ''
    suffix = r'(?!\w)' if sig[-1].isalnum() or sig[-1] == '_' else ''
    return re.compile(prefix + escaped + suffix, re.IGNORECASE)


# PS-taalsleutelwoorden die niet via $(...) obfusceerd kunnen worden.
# 'foreach ($x in $y)' is een statement — vervanging met $('fo'+'reach')
# is syntactisch ongeldig in statement-positie.
_NONOBFUSCATABLE_KEYWORDS = frozenset({
    'foreach', 'for', 'while', 'do', 'if', 'else', 'elseif', 'switch',
    'try', 'catch', 'finally', 'function', 'class', 'filter', 'return',
    'break', 'continue', 'param', 'begin', 'process', 'end', 'in',
    'throw', 'trap', 'exit', 'until',
})


def _is_ps_statement_keyword(m):
    """True als de match een PS-taalsleutelwoord is dat niet via $(…) obfusceerd mag worden."""
    return m.group(0).lower() in _NONOBFUSCATABLE_KEYWORDS


def _is_inside_type_brackets(line, m):
    """True als de match het type-naam deel is van een [TypeName] literal.

    Detecteert [RunspaceFactory], [powershell] etc. waarbij de haakjes
    voor type-resolutie of casting gebruikt worden. String-obfuscatie
    van de inhoud geeft [$(...)] wat geen geldige PS-syntaxis is.
    """
    start, end = m.start(), m.end()
    return start > 0 and line[start - 1] == '[' and end < len(line) and line[end] == ']'


def _is_after_operator_dash(result, m):
    """True als de match direct na een operator-koppelteken staat.

    PS-operators zoals -replace, -split, -match, -like beginnen met '-'.
    $lijn -$('repla'+'ce') is geen geldige syntaxis — PS herkent de
    operator-naam niet als hij via $(...) opgebouwd wordt.
    """
    before = result[:m.start()].rstrip()
    return before.endswith('-')


def _is_full_cmdlet_name(m):
    """True als de match zelf een volledige PS-cmdletnaam is (Verb-Noun patroon).

    Start-Process, Get-Item, Invoke-Expression etc. zijn complete cmdletnamen.
    Als string-subexpressie $('Start-'+'Process') levert het een string op
    die niet direct als cmdlet uitvoerbaar is — daarvoor is '& $(...)'
    nodig. De obfuscator voegt de call-operator niet automatisch toe.
    """
    return bool(re.match(r'^[A-Za-z]+-[A-Za-z]\w*$', m.group(0), re.IGNORECASE))


def _is_code_structure_token(result, m):
    """True als de match een code-structuurelement is dat niet als string
    subexpressie geobfusceerd kan worden.

    Afgedekte gevallen:
    - Begint met '::' → statische methode-accessor ([Type]::Method)
    - Begint met '[' → type-literal opener ([System.Convert]::...)
    - Bevat ']::' → type + statische methode in één signature
    - Begint met '()' → methode-aanroep keten (().TransformFinalBlock()
    - Voorafgegaan door '.' → method/property-toegang ($obj.Method)

    In al deze gevallen geeft $('...'+'...') een string terug op een positie
    waar PS een type-naam, accessor of aanroepbare identifier verwacht.
    """
    text = m.group(0)
    if text.startswith('::') or text.startswith('[') or text.startswith('()'):
        return True
    if ']::' in text:
        return True
    start = m.start()
    if start > 0 and result[start - 1] == '.':
        return True
    return False


def _is_inside_single_quoted_key(result, m):
    """True als de match zit binnen ['...'] hashtable/array-key notatie.

    $hash['sAMAccountName'] → $hash['$('sAMAc'+'countName')'] is ongeldig:
    single quotes expanderen $(...) niet, en de inner apostrofs breken
    de outer key-aanhalingstekens. Overslaan voorkomt de parse-fout.
    """
    start, end = m.start(), m.end()
    return (start >= 2 and result[start - 2:start] == "['"
            and end + 2 <= len(result) and result[end:end + 2] == "']")


def _is_inside_single_quoted_string(result, m):
    """True als de match binnen een single-quoted PS-string staat.

    Tel het aantal losse apostrofs vóór de match. Als oneven → binnen
    een single-quoted string. PS expandeert $(...) niet in single quotes;
    bovendien breken de apostrofs in de replacement de outer string.

    Beperking: dubbele apostrofs ('') zijn een escaped quote in PS en tellen
    elk mee als één karakter — dit kan in extreme edge-cases misgaan, maar
    dekt 99% van de praktijkgevallen correct.
    """
    before = result[:m.start()]
    return before.count("'") % 2 == 1


def _is_before_dot_extension(result, m):
    """True als de match direct gevolgd wordt door een bestandsextensie.

    Voorkomt dat een partieel woord geobfusceerd wordt terwijl de extensie
    achterblijft: 'rundll32' → $('rund'+'ll32').exe probeert .exe als
    property op te halen van de string in plaats van als bestandsnaam.
    """
    end = m.end()
    if end >= len(result) or result[end] != '.':
        return False
    rest = result[end + 1:]
    return bool(re.match(r'^[a-zA-Z]{1,4}\b', rest))


def _is_followed_by_cmdlet_dash(result, m):
    """True als de match gevolgd wordt door een koppelteken + woord.

    In PS-cmdletnamen (Convert-Path, Invoke-Command) en functienamen
    (Install-ServiceBinary) vormt het eerste deel samen met -Verb de
    volledige naam. $('Con'+'vert')-Path is geen geldige cmdlet-aanroep —
    PS zoekt letterlijk naar de aaneengesloten naam 'Convert-Path'.

    Accepteert ook '$(' na het koppelteken: een eerder verwerkt signature
    kan de tekst na '-' al hebben vervangen (bijv. -Path → -$('Pa'+'th')),
    waarna de '-' nog steeds een cmdlet-scheiding aangeeft.
    """
    end = m.end()
    if end >= len(result) or result[end] != '-':
        return False
    rest = result[end + 1:]
    return bool(re.match(r'^(?:[A-Za-z]\w*|\$\()', rest))


def _is_inside_unclosed_bracket(result, m):
    """True als de match binnen een niet-gesloten '[...]' staat.

    Algemene detectie van type-literals: telt ongebalanceerde '[' vóór de
    match. Dekt zowel '[RunspaceFactory]' (direct) als '[System.Convert]'
    (met prefix) en signatures die de sluit-bracket overspannen
    ('Convert]::FromBase64String('). Subexpressies zijn ongeldig als
    type-naam in '[...]' context.
    """
    before = result[:m.start()]
    return before.count('[') > before.count(']')


def obfuscate_line(line, signatures, technique_mode, stats):
    """Pas obfuscatie toe op één regel. Geeft (nieuwe_regel, wijzigingen) terug."""
    if _is_comment_line(line):
        return line, []

    changes = []
    result = line

    string_patterns = signatures.get("string_patterns") or [_make_pattern(s) for s in signatures["string"]]
    code_patterns = signatures.get("code_patterns") or [_make_pattern(s) for s in signatures["code"]]

    # 1. String signatures
    for sig, pattern in zip(signatures["string"], string_patterns):
        matches = list(pattern.finditer(result))
        if not matches:
            continue
        if _already_obfuscated(result, sig):
            continue
        # Vervang van rechts naar links om offsets te behouden
        for m in reversed(matches):
            # Sla PS-taalsleutelwoorden over: $('fo'+'reach') is ongeldig
            # in statement-positie (foreach/for/while/if etc.)
            if _is_ps_statement_keyword(m):
                continue
            # Sla volledige cmdletnamen over: $('Start-'+'Process') is een
            # string, geen aanroepbare cmdlet — '& $(...)' is nodig maar
            # wordt niet automatisch toegevoegd
            if _is_full_cmdlet_name(m):
                continue
            # Sla type-literal inhoud over: [$('runspacef'+'actory')] is
            # ongeldig — PS verwacht een letterlijke type-naam in [...]
            if _is_inside_type_brackets(result, m):
                continue
            # Sla -operator matches over: -$('repla'+'ce') is geen geldige
            # PS-operator — -replace/-split/-match moeten letterlijk blijven
            if _is_after_operator_dash(result, m):
                continue
            # Sla code-structuurtokens over: ::accessor, [Type, ()keten, .method
            # kunnen niet als string-subexpressie geobfusceerd worden
            if _is_code_structure_token(result, m):
                continue
            # Sla ['key'] matches over: ['$(...)']] expandeert niet in single
            # quotes en breekt de inner apostrofs van de subexpressie
            if _is_inside_single_quoted_key(result, m):
                continue
            # Sla matches binnen single-quoted strings over: '...$('a'+'b')...'
            # expandeert niet en de inner apostrofs breken de outer string
            if _is_inside_single_quoted_string(result, m):
                continue
            # Sla matches over die gevolgd worden door een bestandsextensie:
            # rundll32.exe → $('rund'+'ll32').exe probeert .exe als property
            if _is_before_dot_extension(result, m):
                continue
            # Sla matches over gevolgd door koppelteken+woord (cmdlet/functienaam):
            # Convert-Path → $('Con'+'vert')-Path is geen geldige cmdlet
            # function Install-ServiceBinary → functienaam mag geen $() bevatten
            if _is_followed_by_cmdlet_dash(result, m):
                continue
            # Sla matches over binnen niet-gesloten type-brackets:
            # [System.Convert]::From → 'Convert' valt binnen '[System.'
            # Algemenere versie van _is_inside_type_brackets
            if _is_inside_unclosed_bracket(result, m):
                continue
            original = m.group(0)
            func = pick_string_technique(technique_mode)
            # Signature begint met " → behoud de aanhalingsteken als letterlijke
            # string-opener, obfusceer alleen de inhoud daarna.
            # "PowerShell → "$('Power'+'Shell') ipv $('\"Power'+'Shell')
            if original.startswith('"') and len(original) > 1:
                inner = original[1:]
                replacement = '"' + func(inner)
            else:
                replacement = func(original)
            result = result[:m.start()] + replacement + result[m.end():]
            changes.append(("string", sig, original, replacement))
            stats["string"] += 1

    # 2. Code signatures
    for sig, pattern in zip(signatures["code"], code_patterns):
        is_type = sig.startswith('[') and sig.endswith(']')
        matches = list(pattern.finditer(result))
        if not matches:
            continue
        if _already_obfuscated(result, sig):
            continue
        for m in reversed(matches):
            # Sla code signatures over binnen single-quoted strings:
            # '(('scrip'+'tblock')-as[type])' is een letterlijke string, geen type
            if _is_inside_single_quoted_string(result, m):
                continue
            # Sla code signatures over gevolgd door cmdlet-koppelteken
            if _is_followed_by_cmdlet_dash(result, m):
                continue
            # Sla statische methode-accessors over in code-context
            if _is_code_structure_token(result, m):
                continue
            original = m.group(0)
            if is_type:
                # Type-literals: backtick werkt NIET in [typename]
                # Skip parameter-type declaraties ([type]$var)
                end_pos = m.end()
                if end_pos < len(result) and result[end_pos] == '$':
                    continue
                replacement = obf_type_literal(original)
            else:
                # Cmdlet-namen: backtick werkt hier wel
                if technique_mode in ("backtick", "mixed"):
                    replacement = obf_backtick(original)
                elif technique_mode in STRING_TECHNIQUES:
                    replacement = STRING_TECHNIQUES[technique_mode](original)
                else:
                    replacement = obf_backtick(original)
            result = result[:m.start()] + replacement + result[m.end():]
            changes.append(("code", sig, original, replacement))
            stats["code"] += 1

    return result, changes


def obfuscate_file(lines, signatures, technique_mode, verbose=False):
    """Verwerk alle regels. Geeft (nieuwe_regels, stats) terug."""
    stats = {"string": 0, "code": 0, "lines_changed": 0}
    new_lines = []
    all_changes = []

    in_single_herestring = False  # @'...'@ — geen expansie, nooit obfusceren
    in_double_herestring = False  # @"..."@ — wel expansie, obfuscatie ok

    # Pre-compute param block bereik (O(n) eenmalig i.p.v. O(n²) per regel)
    param_range = _compute_param_range(lines)

    for idx, line in enumerate(lines):
        stripped = line.strip()

        # Here-string state tracking (single-quoted: nooit obfusceren)
        if in_single_herestring:
            if stripped == "'@":
                in_single_herestring = False
            new_lines.append(line)
            continue
        if in_double_herestring:
            if stripped == '"@':
                in_double_herestring = False
        # Detecteer opening van hier-strings (begint altijd met @' of @")
        if stripped in ("@'", "@'") or stripped.endswith(" @'") or stripped.endswith("\t@'"):
            in_single_herestring = True
        elif stripped in ('@"',) or stripped.endswith(' @"') or stripped.endswith('\t@"'):
            in_double_herestring = True

        # Sla param block over (O(1) check via pre-computed bereik)
        if param_range and param_range[0] <= idx <= param_range[1]:
            new_lines.append(line)
            continue

        result, changes = obfuscate_line(line, signatures, technique_mode, stats)
        new_lines.append(result)

        if changes:
            stats["lines_changed"] += 1
            for change in changes:
                all_changes.append((idx + 1, change))
                if verbose:
                    cat, sig, orig, repl = change
                    print("  regel %d [%s] %s → %s" % (idx + 1, cat, orig, repl))

    return new_lines, stats, all_changes


# ── BOM detectie ─────────────────────────────────────────────────────────

UTF8_BOM = b'\xef\xbb\xbf'


def detect_bom(data):
    """Detecteer UTF-8 BOM. Geeft (heeft_bom, content_bytes) terug."""
    if data.startswith(UTF8_BOM):
        return True, data[len(UTF8_BOM):]
    return False, data


# ── Extra patterns laden ─────────────────────────────────────────────────

def load_extra_patterns(path):
    """Laad extra signatures uit een JSON bestand."""
    with open(path, 'r') as f:
        data = json.load(f)
    result = {"string": [], "code": []}
    if "string" in data:
        result["string"] = data["string"]
    if "code" in data:
        result["code"] = data["code"]
    return result


# ── ClamAV hulpfuncties ────────────────────────────────────────────────

def _find_tool(name):
    """Zoek een extern tool (sigtool/clamscan) op PATH."""
    return shutil.which(name)


def _ensure_cache_dir(cache_dir):
    """Maak cache directory aan. sys.exit(1) bij fout."""
    try:
        os.makedirs(cache_dir, exist_ok=True)
        return cache_dir
    except OSError as e:
        print("[!] Kan cache directory niet aanmaken: %s — %s" % (cache_dir, e),
              file=sys.stderr)
        sys.exit(1)


def _hex_to_ascii(hex_str):
    """Converteer hex string naar ASCII. None bij wildcards of niet-printbaar."""
    if not hex_str:
        return None
    for marker in ('??', '*', '{', '(', '|'):
        if marker in hex_str:
            return None
    if len(hex_str) % 2 != 0:
        return None
    try:
        raw = bytes.fromhex(hex_str)
    except ValueError:
        return None
    # Alleen printbare ASCII + whitespace
    for b in raw:
        if b < 0x20 or b > 0x7e:
            if b not in (0x09, 0x0a, 0x0d):  # tab, newline, carriage return
                return None
    try:
        return raw.decode('ascii')
    except (UnicodeDecodeError, ValueError):
        return None


def _is_ps_relevant(sig_name, ascii_content):
    """Check of een signature PS-relevant is op basis van naam of content."""
    combined = (sig_name + " " + ascii_content).lower()
    return any(kw in combined for kw in PS_SIG_KEYWORDS)


def _categorize_signature(ascii_content):
    """Categoriseer als 'code' of 'string'.

    'code' voor type literals ([...]), cmdlets (Verb-Noun), namespaces (a.b.c).
    Anders 'string'.
    """
    stripped = ascii_content.strip()
    # Type literal: [Something]
    if stripped.startswith('[') and stripped.endswith(']'):
        return "code"
    # Cmdlet patroon: Verb-Noun (hoofdletter na streepje)
    if re.match(r'^[A-Z][a-z]+-[A-Z]', stripped):
        return "code"
    # Namespace: System.Management.Automation etc.
    if re.match(r'^[A-Za-z]+\.[A-Za-z]+\.[A-Za-z]+', stripped):
        return "code"
    return "string"


# ── NDB parsing ──────────────────────────────────────────────────────────

def _parse_ndb_file(ndb_path):
    """Parse een ClamAV .ndb bestand en extraheer PS-relevante signatures.

    NDB format: Name:TargetType:Offset:HexSignature[:MinFL[:MaxFL]]
    Filter: TargetType 0 (any) of 7 (ASCII text), pure ASCII hex,
    PS-relevant, min 4 chars.
    """
    result = {"string": set(), "code": set()}
    try:
        with open(ndb_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(':')
                if len(parts) < 4:
                    continue
                sig_name = parts[0]
                try:
                    target_type = int(parts[1])
                except ValueError:
                    continue
                # Alleen TargetType 0 (any) of 7 (ASCII normalized)
                if target_type not in (0, 7):
                    continue
                hex_sig = parts[3]
                ascii_content = _hex_to_ascii(hex_sig)
                if ascii_content is None:
                    continue
                if len(ascii_content) < 4:
                    continue
                if not _is_ps_relevant(sig_name, ascii_content):
                    continue
                category = _categorize_signature(ascii_content)
                result[category].add(ascii_content)
    except OSError as e:
        print("[!] Kan NDB niet lezen: %s — %s" % (ndb_path, e), file=sys.stderr)
    return result


# ── YARA parsing (geen externe deps) ──────────────────────────────────

_YARA_TEXT_RE = re.compile(r'^\s*\$\w+\s*=\s*"([^"]+)"', re.MULTILINE)
_YARA_HEX_RE = re.compile(r'^\s*\$\w+\s*=\s*\{([^}]+)\}', re.MULTILINE)

# Bestandsnaam-keywords die aangeven dat het hele YARA-bestand PS-relevant is
_YARA_FILE_KEYWORDS = [
    "powershell", "empire", "amsi", "mimikatz", "rubeus", "cobalt",
    "covenant", "meterpreter", "sharphound", "bloodhound", "lazagne",
]


def _parse_yara_file(yar_path):
    """Extraheer text- en hex-strings uit een .yar bestand.

    Regex-based: $id = "text" en $id = { hex }.
    Skip regex strings ($id = /pattern/).
    Filter via _is_ps_relevant() op rule-naam + string-content.
    Bestanden met PS-gerelateerde bestandsnaam: alle strings relevant.
    Return {"string": set(), "code": set()}.
    """
    result = {"string": set(), "code": set()}
    try:
        with open(yar_path, 'r', errors='ignore') as f:
            content = f.read()
    except OSError:
        return result

    basename = os.path.basename(yar_path).lower()
    file_is_ps = any(kw in basename for kw in _YARA_FILE_KEYWORDS)

    # Extract text strings
    for m in _YARA_TEXT_RE.finditer(content):
        text = m.group(1)
        if len(text) < 4:
            continue
        if file_is_ps or _is_ps_relevant("", text):
            category = _categorize_signature(text)
            result[category].add(text)

    # Extract hex strings
    for m in _YARA_HEX_RE.finditer(content):
        hex_raw = m.group(1).replace(' ', '').replace('\n', '').replace('\r', '')
        ascii_content = _hex_to_ascii(hex_raw)
        if ascii_content is None or len(ascii_content) < 4:
            continue
        if file_is_ps or _is_ps_relevant("", ascii_content):
            category = _categorize_signature(ascii_content)
            result[category].add(ascii_content)

    return result


def _parse_yara_dir(dir_path):
    """Loop over alle .yar bestanden in directory (recursief). Merge resultaten."""
    result = {"string": set(), "code": set()}
    for root, _dirs, files in os.walk(dir_path):
        for fname in files:
            if fname.endswith('.yar') or fname.endswith('.yara'):
                parsed = _parse_yara_file(os.path.join(root, fname))
                result["string"].update(parsed["string"])
                result["code"].update(parsed["code"])
    return result


# ── Signature cache laden ─────────────────────────────────────────────

def _load_cached_sigs(cache_dir):
    """Laad gecachete signatures uit alle beschikbare JSON caches.

    Merged clamav, yara en defender cache files. None als niets gevonden.
    """
    merged = {"string": [], "code": []}
    found_any = False

    for cache_file, label in [
        (CLAMAV_CACHE_FILE, "ClamAV"),
        (YARA_CACHE_FILE, "YARA"),
        (DEFENDER_CACHE_FILE, "Defender"),
    ]:
        cache_path = os.path.join(cache_dir, cache_file)
        if not os.path.isfile(cache_path):
            continue
        try:
            with open(cache_path, 'r') as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print("[!] %s cache corrupt, wordt genegeerd: %s" % (label, e),
                  file=sys.stderr)
            continue
        merged["string"].extend(data.get("string", []))
        merged["code"].extend(data.get("code", []))
        found_any = True

    if not found_any:
        return None

    # Check leeftijd van ClamAV meta
    meta_path = os.path.join(cache_dir, CLAMAV_CACHE_META)
    if os.path.isfile(meta_path):
        try:
            with open(meta_path, 'r') as f:
                meta = json.load(f)
            updated = meta.get("updated", 0)
            age_days = (time.time() - updated) / 86400
            if age_days > 7:
                print("[!] ClamAV cache is %.0f dagen oud, overweeg --update-sigs" % age_days,
                      file=sys.stderr)
        except (json.JSONDecodeError, OSError):
            pass

    return merged


# ── ClamAV scanning ─────────────────────────────────────────────────────

def _run_clamscan(file_path):
    """Draai clamscan op een bestand. Return (detected, sig_name)."""
    clamscan = _find_tool("clamscan")
    if not clamscan:
        print("[!] clamscan niet gevonden. Installeer ClamAV:", file=sys.stderr)
        print("    brew install clamav  /  apt install clamav", file=sys.stderr)
        sys.exit(1)
    try:
        proc = subprocess.run(
            [clamscan, "--no-summary", file_path],
            capture_output=True, text=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        print("[!] clamscan timeout (120s)", file=sys.stderr)
        return False, ""
    # Exit code 1 = virus found, 0 = clean
    if proc.returncode == 1:
        # Output format: "/path/to/file: SigName FOUND"
        for out_line in proc.stdout.splitlines():
            if "FOUND" in out_line:
                parts = out_line.rsplit(":", 1)
                if len(parts) == 2:
                    sig = parts[1].strip().replace(" FOUND", "")
                    return True, sig
        return True, "unknown"
    return False, ""


def _binary_search_detection(lines, clamscan_path, depth=0):
    """Binary search voor trigger-regels. Max depth 15, stop bij <=5 regels."""
    if depth > 15 or len(lines) <= 0:
        return []
    if len(lines) <= 5:
        return [(i, lines[i]) for i in range(len(lines))]

    mid = len(lines) // 2
    results = []

    for half_lines, offset in [(lines[:mid], 0), (lines[mid:], mid)]:
        if not half_lines:
            continue
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False) as tmp:
            tmp.write(''.join(half_lines))
            tmp_path = tmp.name
        try:
            detected, _ = _run_clamscan(tmp_path)
            if detected:
                sub = _binary_search_detection(half_lines, clamscan_path, depth + 1)
                results.extend((offset + i, line) for i, line in sub)
        finally:
            os.unlink(tmp_path)

    return results


def scan_file(file_path, lines):
    """Scan een bestand met clamscan en zoek trigger-regels via binary search."""
    print("[*] Scannen met clamscan: %s" % file_path)
    detected, sig_name = _run_clamscan(file_path)
    if not detected:
        print("[+] Geen detectie door ClamAV")
        return []

    print("[!] Gedetecteerd: %s" % sig_name)
    print("[*] Binary search voor trigger-regels...")

    clamscan = _find_tool("clamscan")
    triggers = _binary_search_detection(lines, clamscan)

    if triggers:
        print("[!] Trigger-regels gevonden:")
        for idx, line in triggers:
            print("  regel %d: %s" % (idx + 1, line.rstrip()))
    else:
        print("[!] Detectie bevestigd maar trigger-regels niet geïsoleerd")

    return [{"line": idx + 1, "content": line.rstrip()} for idx, line in triggers]


def check_file(file_path):
    """Scan output na obfuscatie. Return True als clean, False als gedetecteerd."""
    print("[*] Verificatie scan: %s" % file_path)
    detected, sig_name = _run_clamscan(file_path)
    if detected:
        print("[!] FAIL — nog steeds gedetecteerd: %s" % sig_name)
        return False
    print("[+] PASS — geen detectie na obfuscatie")
    return True


# ── ClamAV download & unpack ────────────────────────────────────────────

def _download_daily_cvd(cache_dir):
    """Download daily.cvd. Probeert eerst freshclam, valt terug op directe download."""
    _ensure_cache_dir(cache_dir)
    cvd_path = os.path.join(cache_dir, "daily.cvd")

    # Poging 1: freshclam (officieel, omzeilt blokkades)
    freshclam = _find_tool("freshclam")
    if freshclam:
        print("[*] Downloaden via freshclam...")
        try:
            proc = subprocess.run(
                [freshclam, "--datadir", cache_dir, "--no-warnings",
                 "--quiet", "--daemon-notify=/dev/null"],
                capture_output=True, text=True, timeout=180,
            )
            if proc.returncode == 0 and os.path.isfile(cvd_path):
                print("[+] daily.cvd gedownload via freshclam")
                meta_path = os.path.join(cache_dir, CLAMAV_CACHE_META)
                meta = {}
                if os.path.isfile(meta_path):
                    try:
                        with open(meta_path, 'r') as f:
                            meta = json.load(f)
                    except (json.JSONDecodeError, OSError):
                        pass
                meta["updated"] = time.time()
                with open(meta_path, 'w') as f:
                    json.dump(meta, f)
                return cvd_path
            # freshclam geeft exit 1 als database al up-to-date is
            if proc.returncode == 1 and os.path.isfile(cvd_path):
                print("[*] daily.cvd is al up-to-date (freshclam)")
                return cvd_path
            print("[!] freshclam exitcode %d, val terug op directe download" % proc.returncode,
                  file=sys.stderr)
        except (subprocess.TimeoutExpired, OSError) as e:
            print("[!] freshclam mislukt: %s, val terug op directe download" % e,
                  file=sys.stderr)

    # Poging 2: directe download met freshclam User-Agent
    try:
        import requests as req
    except ImportError:
        print("[!] requests niet geïnstalleerd: pip install requests", file=sys.stderr)
        sys.exit(1)

    meta_path = os.path.join(cache_dir, CLAMAV_CACHE_META)

    # database.clamav.net vereist een freshclam-achtige User-Agent
    ua = "ClamAV/1.0.3 (OS: linux-gnu, ARCH: x86_64, CPU: x86_64, FreshClam)"
    headers = {"User-Agent": ua}
    # Conditionele download
    if os.path.isfile(meta_path):
        try:
            with open(meta_path, 'r') as f:
                meta = json.load(f)
            if "etag" in meta:
                headers["If-None-Match"] = meta["etag"]
            if "last_modified" in meta:
                headers["If-Modified-Since"] = meta["last_modified"]
        except (json.JSONDecodeError, OSError):
            pass

    print("[*] Downloaden: %s" % DAILY_CVD_URL)
    try:
        resp = req.get(DAILY_CVD_URL, headers=headers, stream=True, timeout=180)
    except req.RequestException as e:
        print("[!] Download mislukt: %s" % e, file=sys.stderr)
        sys.exit(1)

    if resp.status_code == 304:
        print("[*] daily.cvd is up-to-date (304 Not Modified)")
        return cvd_path

    if resp.status_code == 429:
        print("[!] Rate limited (429). Installeer freshclam voor betrouwbare downloads:",
              file=sys.stderr)
        print("    apt install clamav  /  brew install clamav", file=sys.stderr)
        sys.exit(1)

    if resp.status_code != 200:
        print("[!] Download mislukt: HTTP %d" % resp.status_code, file=sys.stderr)
        print("    Installeer freshclam voor betrouwbare downloads:", file=sys.stderr)
        print("    apt install clamav  /  brew install clamav", file=sys.stderr)
        sys.exit(1)

    # Streaming download
    size = 0
    with open(cvd_path, 'wb') as f:
        for chunk in resp.iter_content(chunk_size=65536):
            f.write(chunk)
            size += len(chunk)
    print("[+] Gedownload: %.1f MB" % (size / 1048576))

    # Meta opslaan
    meta = {"updated": time.time()}
    if "ETag" in resp.headers:
        meta["etag"] = resp.headers["ETag"]
    if "Last-Modified" in resp.headers:
        meta["last_modified"] = resp.headers["Last-Modified"]
    with open(meta_path, 'w') as f:
        json.dump(meta, f)

    return cvd_path


def _unpack_cvd(cvd_path, cache_dir):
    """Unpack CVD bestand. Probeer sigtool, fallback naar Python tarfile."""
    unpack_dir = os.path.join(cache_dir, "unpacked")
    os.makedirs(unpack_dir, exist_ok=True)

    sigtool = _find_tool("sigtool")
    if sigtool:
        print("[*] Uitpakken met sigtool...")
        try:
            subprocess.run(
                [sigtool, "--unpack", cvd_path],
                cwd=unpack_dir, capture_output=True, timeout=60,
            )
            return unpack_dir
        except (subprocess.TimeoutExpired, OSError) as e:
            print("[!] sigtool mislukt: %s, probeer fallback..." % e, file=sys.stderr)

    # Fallback: CVD = 512-byte header + tar.gz
    print("[*] Uitpakken met Python tarfile (skip 512-byte header)...")
    try:
        with open(cvd_path, 'rb') as f:
            f.seek(512)
            remaining = f.read()
        tgz_path = os.path.join(cache_dir, "daily.tar.gz")
        with open(tgz_path, 'wb') as f:
            f.write(remaining)
        with tarfile.open(tgz_path, 'r:gz') as tar:
            tar.extractall(path=unpack_dir, filter='data')
        os.unlink(tgz_path)
        return unpack_dir
    except (tarfile.TarError, OSError) as e:
        print("[!] Kan CVD niet uitpakken: %s" % e, file=sys.stderr)
        sys.exit(1)


def _update_clamav_sigs(cache_dir):
    """Download daily.cvd, parse NDB files, schrijf JSON cache."""
    cvd_path = _download_daily_cvd(cache_dir)

    if not os.path.isfile(cvd_path):
        print("[!] daily.cvd niet gevonden na download", file=sys.stderr)
        return None

    unpack_dir = _unpack_cvd(cvd_path, cache_dir)

    # Parse alle .ndb files
    all_sigs = {"string": set(), "code": set()}
    ndb_count = 0
    for fname in os.listdir(unpack_dir):
        if fname.endswith('.ndb'):
            ndb_count += 1
            parsed = _parse_ndb_file(os.path.join(unpack_dir, fname))
            all_sigs["string"].update(parsed["string"])
            all_sigs["code"].update(parsed["code"])

    print("[*] %d NDB bestanden verwerkt" % ndb_count)

    # Sorteer op lengte (langste eerst) en converteer naar lists
    result = {
        "string": sorted(all_sigs["string"], key=len, reverse=True),
        "code": sorted(all_sigs["code"], key=len, reverse=True),
    }

    # Schrijf cache
    cache_path = os.path.join(cache_dir, CLAMAV_CACHE_FILE)
    with open(cache_path, 'w') as f:
        json.dump(result, f, indent=2)

    # Update meta timestamp
    meta_path = os.path.join(cache_dir, CLAMAV_CACHE_META)
    meta = {}
    if os.path.isfile(meta_path):
        try:
            with open(meta_path, 'r') as mf:
                meta = json.load(mf)
        except (json.JSONDecodeError, OSError):
            pass
    meta["updated"] = time.time()
    with open(meta_path, 'w') as f:
        json.dump(meta, f)

    print("[+] ClamAV signatures gecachet: %d string, %d code → %s" % (
        len(result["string"]), len(result["code"]), cache_path))

    # Cleanup unpacked dir
    try:
        shutil.rmtree(unpack_dir, ignore_errors=True)
    except OSError:
        pass

    return result


# ── ZIP download & YARA/Defender update ───────────────────────────────

def _download_zip(url, cache_dir, name):
    """Download zip van URL naar cache dir. Return pad naar geëxtraheerde directory.

    Gebruikt conditionele headers (ETag) voor efficiënte herhaalde downloads.
    """
    try:
        import requests as req
    except ImportError:
        print("[!] requests niet geïnstalleerd: pip install requests", file=sys.stderr)
        return None

    zip_path = os.path.join(cache_dir, "%s.zip" % name)
    meta_path = os.path.join(cache_dir, "%s-meta.json" % name)
    extract_dir = os.path.join(cache_dir, name)

    headers = {"User-Agent": "obfuscate-ps/1.0"}
    if os.path.isfile(meta_path):
        try:
            with open(meta_path, 'r') as f:
                meta = json.load(f)
            if "etag" in meta:
                headers["If-None-Match"] = meta["etag"]
        except (json.JSONDecodeError, OSError):
            pass

    print("[*] Downloaden: %s" % url)
    try:
        resp = req.get(url, headers=headers, stream=True, timeout=120)
    except req.RequestException as e:
        print("[!] Download mislukt: %s" % e, file=sys.stderr)
        return extract_dir if os.path.isdir(extract_dir) else None

    if resp.status_code == 304:
        print("[*] %s is up-to-date (304 Not Modified)" % name)
        return extract_dir if os.path.isdir(extract_dir) else None

    if resp.status_code != 200:
        print("[!] Download mislukt: HTTP %d" % resp.status_code, file=sys.stderr)
        return None

    # Streaming download
    size = 0
    with open(zip_path, 'wb') as f:
        for chunk in resp.iter_content(chunk_size=65536):
            f.write(chunk)
            size += len(chunk)
    print("[+] Gedownload: %.1f MB" % (size / 1048576))

    # Extract
    if os.path.isdir(extract_dir):
        shutil.rmtree(extract_dir, ignore_errors=True)
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(extract_dir)
    except (zipfile.BadZipFile, OSError) as e:
        print("[!] Zip corrupt: %s" % e, file=sys.stderr)
        return None
    finally:
        try:
            os.unlink(zip_path)
        except OSError:
            pass

    # Meta opslaan
    meta = {"updated": time.time()}
    if "ETag" in resp.headers:
        meta["etag"] = resp.headers["ETag"]
    with open(meta_path, 'w') as f:
        json.dump(meta, f)

    return extract_dir


def _write_sig_cache(cache_dir, cache_file, label, sigs):
    """Schrijf signature dict naar JSON cache. Return sorted result dict."""
    result = {
        "string": sorted(sigs["string"], key=len, reverse=True),
        "code": sorted(sigs["code"], key=len, reverse=True),
    }
    cache_path = os.path.join(cache_dir, cache_file)
    with open(cache_path, 'w') as f:
        json.dump(result, f, indent=2)
    print("[+] %s signatures gecachet: %d string, %d code → %s" % (
        label, len(result["string"]), len(result["code"]), cache_path))
    return result


def _update_yara_sigs(cache_dir):
    """Download Neo23x0 YARA rules, parse, schrijf JSON cache."""
    all_sigs = {"string": set(), "code": set()}

    for name, url in YARA_REPOS.items():
        extract_dir = _download_zip(url, cache_dir, "yara-%s" % name)
        if extract_dir is None or not os.path.isdir(extract_dir):
            print("[!] YARA bron '%s' overgeslagen" % name, file=sys.stderr)
            continue
        parsed = _parse_yara_dir(extract_dir)
        all_sigs["string"].update(parsed["string"])
        all_sigs["code"].update(parsed["code"])
        # Cleanup
        shutil.rmtree(extract_dir, ignore_errors=True)

    if not all_sigs["string"] and not all_sigs["code"]:
        print("[!] Geen PS-relevante YARA signatures gevonden", file=sys.stderr)
        return None

    return _write_sig_cache(cache_dir, YARA_CACHE_FILE, "YARA", all_sigs)


def _update_defender_sigs(cache_dir):
    """Download DefenderYara rules, parse, schrijf JSON cache."""
    extract_dir = None
    for url in [DEFENDER_REPO] + DEFENDER_REPO_FALLBACKS:
        extract_dir = _download_zip(url, cache_dir, "defender-yara")
        if extract_dir is not None and os.path.isdir(extract_dir):
            break
        print("[!] %s mislukt, volgende proberen..." % url, file=sys.stderr)
    if extract_dir is None or not os.path.isdir(extract_dir):
        print("[!] Defender YARA download mislukt (alle URLs geprobeerd)", file=sys.stderr)
        return None

    parsed = _parse_yara_dir(extract_dir)
    shutil.rmtree(extract_dir, ignore_errors=True)

    if not parsed["string"] and not parsed["code"]:
        print("[!] Geen PS-relevante Defender signatures gevonden", file=sys.stderr)
        return None

    return _write_sig_cache(cache_dir, DEFENDER_CACHE_FILE, "Defender", parsed)


def update_signatures(cache_dir, sources=None):
    """Orchestreer signature updates voor opgegeven bronnen.

    sources: lijst van "clamav", "yara", "defender" (default: ["clamav"]).
    """
    if sources is None:
        sources = ["clamav"]
    cache_dir = _ensure_cache_dir(cache_dir)

    results = {}
    for source in sources:
        if source == "clamav":
            results["clamav"] = _update_clamav_sigs(cache_dir)
        elif source == "yara":
            results["yara"] = _update_yara_sigs(cache_dir)
        elif source == "defender":
            results["defender"] = _update_defender_sigs(cache_dir)

    return results


# ── Gedeelde signature builder ────────────────────────────────────────────

def build_signatures(cache_dir=None, extra_patterns=None):
    """Bouw een complete signature database: builtin + cached + extra.

    Return een dict {"string": [...], "code": [...]}, gesorteerd op lengte
    (langste eerst).  Kan vanuit CLI, macro.py en download.py gebruikt worden.

    cache_dir:      pad naar de signature-cache directory (default: DEFAULT_CACHE_DIR)
    extra_patterns: optioneel dict {"string": [...], "code": [...]} met extra sigs
    """
    if cache_dir is None:
        cache_dir = DEFAULT_CACHE_DIR

    signatures = {
        "string": list(BUILTIN_SIGNATURES["string"]),
        "code": list(BUILTIN_SIGNATURES["code"]),
    }

    if extra_patterns:
        existing_str = {s.lower() for s in signatures["string"]}
        existing_code = {s.lower() for s in signatures["code"]}
        for s in extra_patterns.get("string", []):
            if s.lower() not in existing_str:
                signatures["string"].append(s)
                existing_str.add(s.lower())
        for s in extra_patterns.get("code", []):
            if s.lower() not in existing_code:
                signatures["code"].append(s)
                existing_code.add(s.lower())

    cached = _load_cached_sigs(cache_dir)
    if cached:
        existing_lower = {s.lower() for s in signatures["string"]}
        existing_lower.update(s.lower() for s in signatures["code"])
        new_string = [s for s in cached.get("string", [])
                      if s.lower() not in existing_lower]
        new_code = [s for s in cached.get("code", [])
                    if s.lower() not in existing_lower]
        signatures["string"].extend(new_string)
        signatures["code"].extend(new_code)

    signatures["string"].sort(key=len, reverse=True)
    signatures["code"].sort(key=len, reverse=True)
    # Pre-compileer patterns zodat obfuscate_line geen re.compile() per regel/sig aanroept
    signatures["string_patterns"] = [_make_pattern(s) for s in signatures["string"]]
    signatures["code_patterns"] = [_make_pattern(s) for s in signatures["code"]]
    return signatures


# ── CLI ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Gerichte AMSI-obfuscatie voor PowerShell scripts",
        epilog="Alleen signatures worden geobfusceerd, de rest blijft leesbaar."
    )
    parser.add_argument("input", nargs='?', default=None,
                        help="Input PowerShell bestand (.ps1)")
    parser.add_argument("-o", "--output", help="Output bestand (default: input-obf.ps1)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Toon elke vervanging met regelnummer")
    parser.add_argument("-n", "--dry-run", action="store_true",
                        help="Toon wijzigingen zonder te schrijven")
    parser.add_argument("--seed", type=int, default=None,
                        help="Random seed voor reproduceerbare output")
    parser.add_argument("--technique", choices=["mixed", "subexpr", "backtick",
                                                 "chararray", "format"],
                        default="mixed",
                        help="Obfuscatie-techniek (default: mixed)")
    parser.add_argument("--patterns", help="Extra JSON bestand met aanvullende signatures")
    # Signature integratie flags
    parser.add_argument("--update-sigs", action="store_true",
                        help="Download signatures, extraheer PS-sigs, cache als JSON")
    parser.add_argument("--sources",
                        help="Bronnen voor --update-sigs: clamav,yara,defender of all"
                             " (default: clamav)")
    parser.add_argument("--scan", action="store_true",
                        help="Scan input met clamscan, rapporteer trigger-regels")
    parser.add_argument("--check", action="store_true",
                        help="Scan output na obfuscatie, verifieer bypass")
    parser.add_argument("--sig-cache", default=DEFAULT_CACHE_DIR,
                        help="Cache directory (default: %s)" % DEFAULT_CACHE_DIR)
    parser.add_argument("--no-clamav-sigs", action="store_true",
                        help="Laad geen gecachete signatures")

    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    # --update-sigs kan standalone draaien
    if args.update_sigs:
        sources = args.sources.split(',') if args.sources else ["clamav"]
        if "all" in sources:
            sources = list(VALID_SOURCES)
        invalid = [s for s in sources if s not in VALID_SOURCES]
        if invalid:
            parser.error("ongeldige bron(nen): %s (kies uit: %s)"
                         % (', '.join(invalid), ', '.join(VALID_SOURCES)))
        update_signatures(args.sig_cache, sources)
        if args.input is None:
            return

    # Input is verplicht voor de rest
    if args.input is None:
        parser.error("input file is required (of gebruik --update-sigs standalone)")

    if not os.path.isfile(args.input):
        print("[!] Bestand niet gevonden: %s" % args.input, file=sys.stderr)
        sys.exit(1)

    # Output pad bepalen
    if args.output:
        out_path = args.output
    else:
        base, ext = os.path.splitext(args.input)
        out_path = base + "-obf" + ext

    # Lees input met BOM-detectie
    with open(args.input, 'rb') as f:
        raw = f.read()
    has_bom, content_bytes = detect_bom(raw)
    content = content_bytes.decode('utf-8')
    lines = content.splitlines(keepends=True)

    # Bouw signature database
    extra_patterns = None
    if args.patterns:
        extra_patterns = load_extra_patterns(args.patterns)

    cache_dir = None if args.no_clamav_sigs else args.sig_cache
    signatures = build_signatures(cache_dir=cache_dir, extra_patterns=extra_patterns)

    # --scan vóór obfuscatie
    if args.scan:
        scan_file(args.input, lines)
        print()

    print("[*] Obfuscating: %s" % args.input)
    print("[*] Signatures: %d string, %d code" % (
        len(signatures["string"]), len(signatures["code"])))
    print("[*] Techniek: %s" % args.technique)
    if args.dry_run:
        print("[*] DRY RUN - geen output geschreven")
    print()

    # Obfusceer
    new_lines, stats, all_changes = obfuscate_file(
        lines, signatures, args.technique, verbose=args.verbose)

    # Samenvatting
    print()
    print("[+] Klaar: %d string, %d code vervangingen over %d regels" % (
        stats["string"], stats["code"], stats["lines_changed"]))

    if args.dry_run:
        return

    # Schrijf output
    output_bytes = ''.join(new_lines).encode('utf-8')
    if has_bom:
        output_bytes = UTF8_BOM + output_bytes

    with open(out_path, 'wb') as f:
        f.write(output_bytes)
    print("[+] Output geschreven naar: %s" % out_path)

    # --check ná schrijven output
    if args.check:
        print()
        passed = check_file(out_path)
        if not passed:
            sys.exit(2)


if __name__ == "__main__":
    main()
