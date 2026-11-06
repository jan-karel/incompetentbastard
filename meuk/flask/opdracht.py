"""Opdracht/engagement-planning — registratie van scope, tijdvenster en RoE,
met koppeling van bevindingen aan een opdracht (hoofdstuk 2)."""

import datetime

from flask import Blueprint, request, jsonify, render_template

from meuk.flask.models import db, db_opdracht, db_bevindingen
from meuk.flask.security import require_dashboard_access
from meuk.flask import project as _project

opdracht_bp = Blueprint('opdracht_bp', __name__, template_folder='html')

_VALID_STATUS = {'gepland', 'actief', 'afgerond'}


@opdracht_bp.before_request
def _check_dashboard_access():
    require_dashboard_access()


@opdracht_bp.app_context_processor
def _inject_projects():
    """Lever de projectlijst + actief project aan alle templates (voor de kiezer)."""
    try:
        opdrachten = db_opdracht.query.order_by(db_opdracht.id.desc()).all()
        active = _project.current_opdracht_id()
    except Exception:
        opdrachten, active = [], None
    return {'nav_opdrachten': opdrachten, 'nav_active_opdracht_id': active}


def _parse_date(val):
    if not val:
        return None
    try:
        return datetime.date.fromisoformat(str(val))
    except (ValueError, TypeError):
        return None


def _opdracht_dict(o):
    """Serialiseer een opdracht incl. voortgang (bevindingen + resterende dagen)."""
    actief_findings = [b for b in o.bevindingen if b.deleted_at is None]
    dagen_resterend = None
    if o.eind_datum:
        dagen_resterend = (o.eind_datum - datetime.date.today()).days
    return {
        'id': o.id,
        'naam': o.naam or '',
        'klant': o.klant or '',
        'scope': o.scope or '',
        'roe': o.roe or '',
        'start_datum': o.start_datum.isoformat() if o.start_datum else '',
        'eind_datum': o.eind_datum.isoformat() if o.eind_datum else '',
        'status': o.status or 'gepland',
        'aantal_bevindingen': len(actief_findings),
        'dagen_resterend': dagen_resterend,
    }


@opdracht_bp.route('/dashboard/opdrachten', methods=['GET'])
def opdrachten_dashboard():
    opdrachten = db_opdracht.query.order_by(db_opdracht.id.desc()).all()
    return render_template('opdrachten.html', opdrachten=opdrachten)


@opdracht_bp.route('/api/opdrachten', methods=['GET'])
def api_opdrachten_list():
    opdrachten = db_opdracht.query.order_by(db_opdracht.id.desc()).all()
    return jsonify({'opdrachten': [_opdracht_dict(o) for o in opdrachten]})


@opdracht_bp.route('/api/opdrachten', methods=['POST'])
def api_opdracht_create():
    data = request.get_json(force=True) or {}
    naam = (data.get('naam') or '').strip()
    if not naam:
        return jsonify({'ok': False, 'error': 'Naam is verplicht'}), 400
    status = data.get('status', 'gepland')
    o = db_opdracht(
        naam=naam[:255],
        klant=(data.get('klant') or '').strip()[:255],
        scope=(data.get('scope') or '')[:10000],
        roe=(data.get('roe') or '')[:10000],
        start_datum=_parse_date(data.get('start_datum')),
        eind_datum=_parse_date(data.get('eind_datum')),
        status=status if status in _VALID_STATUS else 'gepland',
    )
    db.session.add(o)
    db.session.commit()
    _project.get_or_create_config(o)
    return jsonify({'ok': True, 'opdracht': _opdracht_dict(o)})


@opdracht_bp.route('/api/opdrachten/<int:opdracht_id>', methods=['POST'])
def api_opdracht_update(opdracht_id):
    o = db.session.get(db_opdracht, opdracht_id)
    if not o:
        return jsonify({'ok': False, 'error': 'niet gevonden'}), 404
    data = request.get_json(force=True) or {}
    if 'naam' in data and (data['naam'] or '').strip():
        o.naam = data['naam'].strip()[:255]
    if 'klant' in data:
        o.klant = (data['klant'] or '').strip()[:255]
    if 'scope' in data:
        o.scope = (data['scope'] or '')[:10000]
    if 'roe' in data:
        o.roe = (data['roe'] or '')[:10000]
    if 'start_datum' in data:
        o.start_datum = _parse_date(data['start_datum'])
    if 'eind_datum' in data:
        o.eind_datum = _parse_date(data['eind_datum'])
    if 'status' in data and data['status'] in _VALID_STATUS:
        o.status = data['status']
    db.session.commit()
    return jsonify({'ok': True, 'opdracht': _opdracht_dict(o)})


@opdracht_bp.route('/api/opdrachten/<int:opdracht_id>', methods=['DELETE'])
def api_opdracht_delete(opdracht_id):
    o = db.session.get(db_opdracht, opdracht_id)
    if not o:
        return jsonify({'ok': False, 'error': 'niet gevonden'}), 404
    # Bevindingen loskoppelen (niet verwijderen)
    for b in list(o.bevindingen):
        b.opdracht_id = None
    db.session.delete(o)
    db.session.commit()
    return jsonify({'ok': True})


@opdracht_bp.route('/api/opdrachten/<int:opdracht_id>/findings', methods=['POST'])
def api_opdracht_assign(opdracht_id):
    """Koppel of ontkoppel bevindingen aan een opdracht."""
    o = db.session.get(db_opdracht, opdracht_id)
    if not o:
        return jsonify({'ok': False, 'error': 'niet gevonden'}), 404
    data = request.get_json(force=True) or {}
    ids = data.get('finding_ids', [])
    unlink = bool(data.get('unlink', False))
    if not isinstance(ids, list):
        return jsonify({'ok': False, 'error': 'finding_ids moet een lijst zijn'}), 400
    changed = 0
    for fid in ids:
        if not str(fid).isdigit():
            continue
        bev = db.session.get(db_bevindingen, int(fid))
        if bev:
            bev.opdracht_id = None if unlink else opdracht_id
            changed += 1
    db.session.commit()
    return jsonify({'ok': True, 'changed': changed})


@opdracht_bp.route('/api/opdrachten/active', methods=['GET'])
def api_opdracht_active():
    """Het huidige actieve project + de volledige projectlijst voor de kiezer."""
    oid = _project.current_opdracht_id()
    opdrachten = db_opdracht.query.order_by(db_opdracht.id.desc()).all()
    return jsonify({
        'active_id': oid,
        'opdrachten': [{'id': o.id, 'naam': o.naam or '', 'klant': o.klant or '',
                        'status': o.status or 'gepland'} for o in opdrachten],
    })


@opdracht_bp.route('/api/opdrachten/<int:opdracht_id>/activeer', methods=['POST'])
def api_opdracht_activeer(opdracht_id):
    """Maak een project actief voor deze sessie."""
    o = db.session.get(db_opdracht, opdracht_id)
    if not o:
        return jsonify({'ok': False, 'error': 'niet gevonden'}), 404
    _project.set_active(opdracht_id)
    _project.get_or_create_config(o)
    return jsonify({'ok': True, 'active_id': opdracht_id, 'naam': o.naam})


@opdracht_bp.route('/api/opdrachten/backfill', methods=['POST'])
def api_opdracht_backfill():
    """Wijs bestaande (niet-toegewezen) data toe aan het standaardproject."""
    result = _project.backfill_to_default()
    return jsonify({'ok': True, **result})


@opdracht_bp.route('/api/opdrachten/<int:opdracht_id>/activeer-rapport', methods=['POST'])
def api_opdracht_naar_rapport(opdracht_id):
    """Compat: activeer het project (config staat nu per project, geen kopie meer nodig)."""
    o = db.session.get(db_opdracht, opdracht_id)
    if not o:
        return jsonify({'ok': False, 'error': 'niet gevonden'}), 404
    _project.set_active(opdracht_id)
    _project.get_or_create_config(o)
    return jsonify({'ok': True, 'active_id': opdracht_id})
