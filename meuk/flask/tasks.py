import os
import re
import subprocess
import threading
import time
import uuid
from collections import deque
from pathlib import Path

from flask import Blueprint
from flask import jsonify
from flask import render_template
from flask import request

from meuk.flask.security import require_dashboard_access


tasks_bp = Blueprint("tasks_bp", __name__, template_folder="html", static_folder="static")


_MAX_OUTPUT_LINES = 500
_MAX_RUNTIME_SECONDS = 600

# Regex patterns for argument validation
_RE_SAFE_NAME = re.compile(r"^[a-zA-Z0-9_\-]+$")
_RE_IP_OR_IFACE = re.compile(r"^[a-zA-Z0-9._:/%\-]+$")
_RE_SEARCH_TERM = re.compile(r"^[a-zA-Z0-9._:\-/]+$")
_RE_SSH_TARGET = re.compile(r"^[a-zA-Z0-9._@:\-]+$")
_RE_SUBNET = re.compile(r"^[0-9./]+$")
_RE_FILE_PATH = re.compile(r"^[a-zA-Z0-9._/\-]+$")

_TASKS = {
    # --- Dev ---
    "compileall": {
        "label": "Compile Python files",
        "group": "dev",
        "cmd": ["python3", "-m", "compileall", "app.py", "meuk/flask", "tests"],
    },
    "pytest": {
        "label": "Run test suite",
        "group": "dev",
        "cmd": ["pytest", "-q"],
    },
    "git_status": {
        "label": "Show git status",
        "group": "dev",
        "cmd": ["git", "status", "--short"],
    },
    # --- Setup ---
    "init": {
        "label": "Init environment",
        "group": "setup",
        "desc": "Maakt directories, start services, logt tool-versies",
        "cmd": ["bash", "init.sh"],
    },
    "engage": {
        "label": "Engage (VPN + Empire)",
        "group": "setup",
        "desc": "Start OpenVPN en PowerShell Empire in screen sessies",
        "cmd": ["bash", "engage.sh"],
    },
    # --- Recon ---
    "scan": {
        "label": "Network scan (nmap)",
        "group": "recon",
        "desc": "Nmap TCP/UDP scan, nuclei, whatweb, wfuzz",
        "cmd": ["bash", "scan.sh"],
        "args": [
            {"name": "interface", "label": "Interface / IP", "placeholder": "eth0, tun0 of 10.0.0.1", "required": True, "pattern": "ip_or_iface"},
            {"name": "naam", "label": "Scan naam", "placeholder": "engagement-name", "required": True, "pattern": "safe_name"},
            {"name": "hosts", "label": "Hosts / range", "placeholder": "10.1.2.0/24", "required": True, "pattern": "ip_or_iface"},
        ],
    },
    "search": {
        "label": "Search nmap results",
        "group": "recon",
        "desc": "Zoek hosts in nmap scan resultaten op service/poort",
        "cmd": ["bash", "search.sh"],
        "args": [
            {"name": "scanfile", "label": "Scan naam", "placeholder": "engagement-name", "required": True, "pattern": "safe_name"},
            {"name": "zoek", "label": "Zoekterm", "placeholder": "http, ssh, ftp, 3389...", "required": True, "pattern": "search_term"},
        ],
    },
    "kerberos": {
        "label": "Kerberos enum",
        "group": "recon",
        "desc": "Kerberos user enum + LDAP query via nmap/crackmapexec",
        "cmd": ["bash", "kerberos.sh"],
        "args": [
            {"name": "scanfile", "label": "Scan naam", "placeholder": "engagement-name", "required": True, "pattern": "safe_name"},
        ],
    },
    "ftp_anon": {
        "label": "FTP anonymous check",
        "group": "recon",
        "desc": "Test FTP anonymous login op hosts uit nmap scan",
        "cmd": ["bash", "ftp_anon.sh"],
        "args": [
            {"name": "scanfile", "label": "Scan naam", "placeholder": "engagement-name", "required": True, "pattern": "safe_name"},
        ],
    },
    # --- Brute ---
    "gen_passwords": {
        "label": "Generate password wordlist",
        "group": "brute",
        "desc": "Genereer wachtwoord variaties naar meuk/wordlists/passwords.txt",
        "cmd": ["bash", "gen_passwords.sh"],
    },
    "brute_ssh": {
        "label": "Brute force SSH",
        "group": "brute",
        "desc": "Crowbar SSH brute force op hosts uit nmap scan",
        "cmd": ["bash", "brute_ssh.sh"],
        "args": [
            {"name": "scanfile", "label": "Scan naam", "placeholder": "engagement-name", "required": True, "pattern": "safe_name"},
        ],
    },
    "brute_rdp": {
        "label": "Brute force RDP",
        "group": "brute",
        "desc": "Crowbar RDP brute force op hosts uit nmap scan",
        "cmd": ["bash", "brute_rdp.sh"],
        "args": [
            {"name": "scanfile", "label": "Scan naam", "placeholder": "engagement-name", "required": True, "pattern": "safe_name"},
        ],
    },
    "brute_vpn": {
        "label": "Brute force VPN",
        "group": "brute",
        "desc": "Crowbar VPN brute force op hosts uit nmap scan",
        "cmd": ["bash", "brute_vpn.sh"],
        "args": [
            {"name": "scanfile", "label": "Scan naam", "placeholder": "engagement-name", "required": True, "pattern": "safe_name"},
        ],
    },
    "weak_ssh": {
        "label": "Weak SSH keys",
        "group": "brute",
        "desc": "Test Debian weak SSH keys op hosts uit nmap scan",
        "cmd": ["bash", "weak_ssh.sh"],
        "args": [
            {"name": "scanfile", "label": "Scan naam", "placeholder": "engagement-name", "required": True, "pattern": "safe_name"},
        ],
    },
    # --- Exploit ---
    "ftp_asp": {
        "label": "FTP ASP shell upload",
        "group": "exploit",
        "desc": "Upload ASP shell via anonymous FTP + trigger via curl",
        "cmd": ["bash", "ftp_asp.sh"],
        "args": [
            {"name": "interface", "label": "Interface / IP", "placeholder": "eth0 of tun0", "required": True, "pattern": "ip_or_iface"},
            {"name": "host", "label": "Target host", "placeholder": "10.0.0.5", "required": True, "pattern": "ip_or_iface"},
            {"name": "port", "label": "Port", "placeholder": "443", "required": False, "pattern": "safe_name"},
        ],
    },
    "rfi_input": {
        "label": "RFI php://input",
        "group": "exploit",
        "desc": "Remote File Inclusion via php://input",
        "cmd": ["bash", "rfi_input.sh"],
        "args": [
            {"name": "interface", "label": "Interface / IP", "placeholder": "eth0 of tun0", "required": True, "pattern": "ip_or_iface"},
            {"name": "host", "label": "Target URL", "placeholder": "http://10.0.0.5/vuln.php?page=", "required": True, "pattern": "ip_or_iface"},
            {"name": "port", "label": "Port", "placeholder": "443", "required": False, "pattern": "safe_name"},
        ],
    },
    # --- Network ---
    "sshuttle": {
        "label": "SSHuttle tunnel",
        "group": "network",
        "desc": "Start sshuttle VPN tunnel via SSH in screen sessie",
        "cmd": ["bash", "sshuttle.sh"],
        "args": [
            {"name": "target", "label": "SSH target", "placeholder": "user@10.0.0.5", "required": True, "pattern": "ssh_target"},
            {"name": "subnet", "label": "Subnet", "placeholder": "10.1.0.0/24", "required": True, "pattern": "subnet"},
            {"name": "key", "label": "Private key pad", "placeholder": "raw/loot/10.0.0.5/id_rsa", "required": False, "pattern": "file_path", "env": "SSH_KEY"},
            {"name": "password", "label": "SSH wachtwoord", "placeholder": "", "required": False, "type": "password", "env": "SSH_PASS"},
        ],
    },
    # --- Obfuscatie ---
    "update_sigs": {
        "label": "Update AMSI signatures",
        "group": "obfuscate",
        "desc": "Download AMSI signatures van ClamAV, YARA en Defender",
        "cmd": ["python3", "obfuscate_ps.py", "--update-sigs", "--sources", "all"],
        "args": [],
    },
    "obfuscate_ps": {
        "label": "Obfuscate PowerShell",
        "group": "obfuscate",
        "desc": "Pas AMSI-obfuscatie toe op een .ps1 bestand (output: <input>-obf.ps1)",
        "cmd": ["python3", "obfuscate_ps.py"],
        "args": [
            {"name": "input", "label": "Input bestand", "placeholder": "http/payloads/amsi-bypass.ps1",
             "required": True, "pattern": "file_path"},
        ],
    },
    "obfuscate_file": {
        "label": "Obfuscate bestand (multi-taal)",
        "group": "obfuscate",
        "desc": "Pas AV obfuscatie toe op .php/.aspx/.py/.hta/.txt bestanden",
        "cmd": ["python3", "obfuscate_av.py"],
        "args": [
            {"name": "input", "label": "Input bestand", "placeholder": "http/payloads/shell.php",
             "required": True, "pattern": "file_path"},
        ],
    },
}

# Group labels for the UI
_GROUPS = {
    "dev": "Development",
    "setup": "Setup",
    "recon": "Recon",
    "brute": "Brute Force",
    "exploit": "Exploit",
    "network": "Network",
    "obfuscate": "Obfuscatie",
}

_PATTERN_MAP = {
    "safe_name": _RE_SAFE_NAME,
    "ip_or_iface": _RE_IP_OR_IFACE,
    "search_term": _RE_SEARCH_TERM,
    "ssh_target": _RE_SSH_TARGET,
    "subnet": _RE_SUBNET,
    "file_path": _RE_FILE_PATH,
}

_RUNS = {}
_RUNS_LOCK = threading.Lock()


def _validate_arg(value, arg_def):
    """Valideer een taak-argument tegen zijn patroon."""
    if len(value) > 512:
        return f"{arg_def['label']} is te lang"
    # Password args: alleen lengtecheck, geen regex
    if arg_def.get("type") == "password":
        return None
    pattern_name = arg_def.get("pattern", "safe_name")
    regex = _PATTERN_MAP.get(pattern_name, _RE_SAFE_NAME)
    if not regex.match(value):
        return f"Ongeldig karakter in {arg_def['label']}"
    if ".." in value:
        return f"Pad traversal niet toegestaan in {arg_def['label']}"
    return None


@tasks_bp.before_request
def _ensure_access():
    require_dashboard_access()


def _run_task(run_id, task_name, cmd, timeout, extra_env=None):
    started_at = int(time.time())
    output = deque(maxlen=_MAX_OUTPUT_LINES)

    with _RUNS_LOCK:
        _RUNS[run_id] = {
            "id": run_id,
            "task": task_name,
            "cmd": cmd,
            "status": "running",
            "started_at": started_at,
            "finished_at": None,
            "return_code": None,
            "output": output,
        }

    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
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
            _RUNS[run_id]["output"].append(f"Failed to start command: {exc}")
        return

    deadline = time.time() + timeout
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
                output.append(f"Process killed after {timeout}s timeout")
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
            _RUNS[run_id]["output"].append(f"Runner error: {exc}")


@tasks_bp.route("/dashboard/tasks", methods=["GET"])
def tasks_dashboard():
    # Groepeer taken per group
    grouped = {}
    for name, task in _TASKS.items():
        g = task.get("group", "dev")
        grouped.setdefault(g, []).append({"name": name, **task})
    return render_template("tasks.html", tasks=_TASKS, grouped=grouped, groups=_GROUPS)


@tasks_bp.route("/api/tasks", methods=["GET"])
def tasks_list():
    # Return task definitions inclusief args voor de frontend
    out = {}
    for name, task in _TASKS.items():
        out[name] = {
            "label": task["label"],
            "group": task.get("group", "dev"),
            "desc": task.get("desc", ""),
            "args": task.get("args", []),
        }
    return jsonify({"tasks": out, "groups": _GROUPS})


@tasks_bp.route("/api/tasks/run", methods=["POST"])
def tasks_run():
    payload = request.get_json(silent=True) or {}
    task_name = payload.get("task")
    if task_name not in _TASKS:
        return jsonify({"error": "unknown task"}), 400

    task_def = _TASKS[task_name]
    task_cmd = list(task_def["cmd"])

    # Verwerk argumenten als de taak die verwacht
    arg_defs = task_def.get("args", [])
    provided_args = payload.get("args", {})
    extra_env = {}

    for arg_def in arg_defs:
        value = provided_args.get(arg_def["name"], "").strip()
        if arg_def.get("required") and not value:
            return jsonify({"error": f"{arg_def['label']} is verplicht"}), 400
        if value:
            err = _validate_arg(value, arg_def)
            if err:
                return jsonify({"error": err}), 400
            env_name = arg_def.get("env")
            if env_name:
                # Doorgeven als environment variabele
                extra_env[env_name] = value
            else:
                task_cmd.append(value)
        elif not arg_def.get("required"):
            # Optioneel arg niet opgegeven: niet toevoegen
            pass

    run_id = str(uuid.uuid4())
    thread = threading.Thread(
        target=_run_task,
        args=(run_id, task_name, task_cmd, _MAX_RUNTIME_SECONDS, extra_env or None),
        daemon=True,
    )
    thread.start()
    return jsonify({"run_id": run_id, "task": task_name})


@tasks_bp.route("/api/tasks/runs/<run_id>", methods=["GET"])
def tasks_run_status(run_id):
    with _RUNS_LOCK:
        run = _RUNS.get(run_id)
        if not run:
            return jsonify({"error": "run not found"}), 404
        return jsonify(
            {
                "id": run["id"],
                "task": run["task"],
                "cmd": run["cmd"],
                "status": run["status"],
                "started_at": run["started_at"],
                "finished_at": run["finished_at"],
                "return_code": run["return_code"],
                "output": list(run["output"]),
            }
        )
