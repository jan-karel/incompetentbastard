"""Docker container management (read-only) — status/health en image/tooling-overzicht.

Uitsluitend leesbewerkingen via de docker-CLI met een vaste argumentenlijst
(geen shell=True). Faalt netjes als docker ontbreekt of de daemon niet draait.
De destructieve 'rebuild'-actie is bewust NIET geïmplementeerd.
"""

import json
import shutil
import subprocess

from flask import Blueprint, jsonify, render_template

from meuk.flask.security import require_dashboard_access

docker_bp = Blueprint('docker_bp', __name__, template_folder='html')

_TIMEOUT = 8


@docker_bp.before_request
def _check_dashboard_access():
    require_dashboard_access()


def _docker_available():
    return shutil.which('docker') is not None


def _run_docker(args):
    """Voer `docker <args>` uit. Retourneert (ok, stdout|foutmelding)."""
    if not _docker_available():
        return False, 'docker CLI niet gevonden'
    try:
        proc = subprocess.run(
            ['docker'] + args,
            capture_output=True, text=True, timeout=_TIMEOUT,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return False, str(exc)
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout or 'onbekende fout').strip()
    return True, proc.stdout


def _parse_json_lines(output):
    """Parse docker --format '{{json .}}' output (één JSON-object per regel)."""
    rows = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    return rows


@docker_bp.route('/dashboard/docker', methods=['GET'])
def docker_dashboard():
    return render_template('docker_status.html')


@docker_bp.route('/api/docker/status', methods=['GET'])
def api_docker_status():
    """Overzicht van containers (incl. gestopte) met status/health."""
    ok, out = _run_docker(['ps', '-a', '--no-trunc', '--format', '{{json .}}'])
    if not ok:
        return jsonify({'available': False, 'error': out, 'containers': []})
    containers = []
    for c in _parse_json_lines(out):
        containers.append({
            'name': c.get('Names', ''),
            'image': c.get('Image', ''),
            'state': c.get('State', ''),
            'status': c.get('Status', ''),
            'ports': c.get('Ports', ''),
            'created': c.get('CreatedAt', ''),
        })
    return jsonify({'available': True, 'containers': containers})


@docker_bp.route('/api/docker/images', methods=['GET'])
def api_docker_images():
    """Tooling/image-versie-overzicht (repository:tag + grootte)."""
    ok, out = _run_docker(['images', '--format', '{{json .}}'])
    if not ok:
        return jsonify({'available': False, 'error': out, 'images': []})
    images = []
    for i in _parse_json_lines(out):
        images.append({
            'repository': i.get('Repository', ''),
            'tag': i.get('Tag', ''),
            'size': i.get('Size', ''),
            'created': i.get('CreatedSince', ''),
            'id': i.get('ID', ''),
        })
    return jsonify({'available': True, 'images': images})
