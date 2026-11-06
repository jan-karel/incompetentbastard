"""DefectDojo-integratie — push bevindingen naar DefectDojo (product/engagement).

DefectDojo datamodel: Product -> Engagement -> Test -> Finding.
Om een finding aan te maken is een Test nodig; deze module vindt of maakt een
Test onder het geconfigureerde engagement en pusht daar de bevindingen naartoe.

Mapping:
  - severity: CVSS-basescore -> Critical/High/Medium/Low/Info
  - status:   IB remediation_status -> active/verified/is_mitigated/risk_accepted
  - CWE:      uit de bevinding-template
  - bewijs:   screenshots als finding-attachments (/files/)

Configuratie staat in db_instellingen (dd_url, dd_api_key, dd_product_id,
dd_engagement_id, dd_verify_ssl, dd_auto_push).
"""

import datetime
import os

from flask import Blueprint, request, jsonify

from meuk.flask.models import (
    db, db_bevindingen, db_bevindingen_templates, db_evidence,
    db_defectdojo_sync, db_asset, db_asset_anchor,
)
from meuk.flask.findings import _cvss_to_severity, _get_appdata
from meuk.flask.security import require_dashboard_access

defectdojo_bp = Blueprint('defectdojo_bp', __name__)

_EVIDENCE_SRC = os.path.join(os.path.dirname(__file__), 'db', 'evidence')

# IB severity -> DefectDojo severity
_DD_SEVERITY = {
    'critical': 'Critical',
    'high': 'High',
    'medium': 'Medium',
    'low': 'Low',
    'none': 'Info',
}

# DefectDojo numerical_severity hoort bij de severity (S0=Critical ... S4=Info)
_DD_NUM_SEVERITY = {
    'Critical': 'S0', 'High': 'S1', 'Medium': 'S2', 'Low': 'S3', 'Info': 'S4',
}

# DefectDojo test_type dat we gebruiken voor IB-bevindingen
_DD_TEST_TYPE_NAME = 'Pen Test'


@defectdojo_bp.before_request
def _check_dashboard_access():
    require_dashboard_access()


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _dd_config():
    """Haal DefectDojo-config op uit het actieve project; None indien niet geconfigureerd."""
    from meuk.flask import project as _project
    s = _project.current_config() or _get_appdata()
    if not s:
        return None
    url = (getattr(s, 'dd_url', '') or '').rstrip('/')
    key = getattr(s, 'dd_api_key', '') or ''
    if not url or not key:
        return None
    return {
        'url': url,
        'key': key,
        'product_id': getattr(s, 'dd_product_id', None),
        'engagement_id': getattr(s, 'dd_engagement_id', None),
        'verify_ssl': bool(getattr(s, 'dd_verify_ssl', True)),
    }


def _dd_request(cfg, method, path, *, json_body=None, params=None, files=None, data=None):
    """Voer een DefectDojo API-call uit. Retourneert (ok, status_code, payload|error)."""
    import requests
    url = cfg['url'] + path
    headers = {'Authorization': 'Token ' + cfg['key']}
    if json_body is not None:
        headers['Content-Type'] = 'application/json'
    try:
        resp = requests.request(
            method, url, headers=headers, json=json_body, params=params,
            files=files, data=data, verify=cfg['verify_ssl'], timeout=30,
        )
    except requests.exceptions.RequestException as exc:
        return False, 0, str(exc)
    if resp.status_code >= 400:
        try:
            return False, resp.status_code, resp.json()
        except ValueError:
            return False, resp.status_code, resp.text[:500]
    try:
        return True, resp.status_code, resp.json()
    except ValueError:
        return True, resp.status_code, {}


# ---------------------------------------------------------------------------
# Mapping van IB-bevindingen naar DefectDojo-finding payloads
# ---------------------------------------------------------------------------

def _status_flags(bev):
    """Bepaal DefectDojo status-vlaggen uit de IB remediation/finding status."""
    rem = (getattr(bev, 'remediation_status', '') or 'open').lower()
    flags = {
        'active': True, 'verified': True, 'false_p': False,
        'is_mitigated': False, 'risk_accepted': False, 'out_of_scope': False,
    }
    if rem in ('fixed', 'verified'):
        flags['active'] = False
        flags['is_mitigated'] = True
    elif rem == 'accepted':
        flags['active'] = False
        flags['risk_accepted'] = True
    return flags


def _parse_asset_endpoint(asset):
    """Zet een db_asset om naar DefectDojo-endpoint velden (protocol/host/port/path)."""
    from urllib.parse import urlparse
    waarde = (asset.waarde or '').strip()
    proto = (asset.protocol or '').strip().lower()
    host = waarde
    port = asset.poort
    path = ''
    if '://' in waarde:
        p = urlparse(waarde)
        proto = proto or (p.scheme or '')
        host = p.hostname or host
        port = port or p.port
        path = (p.path or '').lstrip('/')
    ep = {'host': host}
    if proto:
        ep['protocol'] = proto
    if port:
        try:
            ep['port'] = int(port)
        except (TypeError, ValueError):
            pass
    if path:
        ep['path'] = path
    return ep


def _ensure_endpoint(cfg, product_id, ep):
    """Vind of maak een DefectDojo-endpoint onder het product. Retourneert id|None."""
    ok, _code, body = _dd_request(cfg, 'GET', '/api/v2/endpoints/',
                                  params={'product': product_id, 'host': ep['host'], 'limit': 100})
    if ok and isinstance(body, dict):
        for r in body.get('results', []):
            if (r.get('port') == ep.get('port')
                    and (r.get('path') or '') == ep.get('path', '')
                    and (r.get('protocol') or '') == ep.get('protocol', '')):
                return r.get('id')
    create = dict(ep)
    create['product'] = product_id
    ok, _code, body = _dd_request(cfg, 'POST', '/api/v2/endpoints/', json_body=create)
    if ok and isinstance(body, dict) and body.get('id'):
        return body['id']
    return None


def _endpoints_for_finding(cfg, bev):
    """Vind/maak DefectDojo-endpoints voor de assets gekoppeld aan deze bevinding.

    Retourneert een lijst endpoint-ids (leeg als er geen product-ID of geen
    gekoppelde assets zijn — dan valt de payload terug op de locatie-tekst).
    """
    product_id = cfg.get('product_id')
    if not product_id:
        return []
    ids = []
    for anchor in getattr(bev, 'asset_anchors', None) or []:
        asset = anchor.asset
        if asset is None or not (asset.waarde or '').strip():
            continue
        if getattr(asset, 'in_scope', True) is False:
            continue
        eid = _ensure_endpoint(cfg, product_id, _parse_asset_endpoint(asset))
        if eid is not None and eid not in ids:
            ids.append(eid)
    return ids


def _finding_payload(bev, template, test_id, endpoint_ids=None):
    """Bouw een DefectDojo-finding payload voor een IB-bevinding."""
    basescore = bev.basescore or (template.basescore if template else '') or '0'
    sev, _ = _cvss_to_severity(basescore)
    dd_sev = _DD_SEVERITY.get(sev, 'Info')
    beschrijving = ''
    impact = ''
    aanbeveling = ''
    refs = ''
    if template:
        beschrijving = template.nlbeschrijving or template.enbeschrijving or ''
        impact = template.nlimpact or template.enimpact or ''
        aanbeveling = template.nlaanbeveling or template.enaanbeveling or ''
        refs = template.referenties or ''
    descr_parts = []
    if beschrijving:
        descr_parts.append(beschrijving)
    if bev.uitwerken:
        descr_parts.append('## Uitwerking\n\n' + bev.uitwerken)
    if getattr(bev, 'control_ref', ''):
        descr_parts.append('**Controle-referentie:** ' + bev.control_ref)
    description = '\n\n'.join(descr_parts) or (bev.naam or 'Geen beschrijving')

    payload = {
        'title': bev.naam or 'Bevinding #{}'.format(bev.id),
        'test': test_id,
        'severity': dd_sev,
        'description': description,
        'mitigation': aanbeveling,
        'impact': impact,
        'references': refs,
        'date': (bev.discovered_at or bev.created_at or datetime.datetime.utcnow()).strftime('%Y-%m-%d'),
        'numerical_severity': _DD_NUM_SEVERITY.get(dd_sev, 'S4'),
    }
    # CVSS basescore als float
    try:
        payload['cvssv3_score'] = float(basescore)
    except (TypeError, ValueError):
        pass
    # CWE
    cwe = (template.cwe if template else '') or ''
    if str(cwe).isdigit():
        payload['cwe'] = int(cwe)
    # Gestructureerde endpoints (asset-anchors) hebben voorrang; anders locatie-tekst
    if endpoint_ids:
        payload['endpoints'] = endpoint_ids
    elif bev.locatie:
        payload['description'] += '\n\n**Locatie:** ' + bev.locatie
    payload.update(_status_flags(bev))
    return payload


def _ensure_test(cfg, engagement_id):
    """Vind of maak een Test onder het engagement. Retourneert (ok, test_id|error)."""
    # Bestaande test onder dit engagement hergebruiken
    ok, _code, body = _dd_request(cfg, 'GET', '/api/v2/tests/',
                                  params={'engagement': engagement_id, 'limit': 1})
    if ok and isinstance(body, dict) and body.get('results'):
        return True, body['results'][0]['id']

    # test_type id ophalen
    ok, _code, body = _dd_request(cfg, 'GET', '/api/v2/test_types/',
                                  params={'name': _DD_TEST_TYPE_NAME})
    test_type_id = None
    if ok and isinstance(body, dict) and body.get('results'):
        test_type_id = body['results'][0]['id']
    if test_type_id is None:
        # Fallback: eerste beschikbare test_type
        ok, _code, body = _dd_request(cfg, 'GET', '/api/v2/test_types/', params={'limit': 1})
        if ok and isinstance(body, dict) and body.get('results'):
            test_type_id = body['results'][0]['id']
    if test_type_id is None:
        return False, 'Geen test_type beschikbaar in DefectDojo'

    today = datetime.date.today().isoformat()
    ok, _code, body = _dd_request(cfg, 'POST', '/api/v2/tests/', json_body={
        'engagement': engagement_id,
        'test_type': test_type_id,
        'target_start': today,
        'target_end': today,
        'title': 'Incompetent Bastard import',
    })
    if ok and isinstance(body, dict) and body.get('id'):
        return True, body['id']
    return False, body


def _upload_evidence(cfg, dd_finding_id, finding_id):
    """Upload screenshot-bewijs als attachments bij een DefectDojo-finding."""
    uploaded = 0
    for ev in db_evidence.query.filter_by(finding_id=finding_id).all():
        ct = ev.content_type or ''
        if not ct.startswith('image/'):
            continue
        src = os.path.join(_EVIDENCE_SRC, str(finding_id), ev.filename)
        if not os.path.exists(src):
            continue
        try:
            with open(src, 'rb') as fh:
                ok, _code, _body = _dd_request(
                    cfg, 'POST', '/api/v2/findings/{}/files/'.format(dd_finding_id),
                    files={'file': (ev.original_filename or ev.filename, fh, ct)},
                    data={'title': ev.description or ev.original_filename or ev.filename},
                )
            if ok:
                uploaded += 1
        except OSError:
            continue
    return uploaded


def _log_sync(finding_id, dd_finding_id, engagement_id, action, status, message):
    """Schrijf/actualiseer de sync-historie voor een bevinding."""
    row = db_defectdojo_sync.query.filter_by(finding_id=finding_id).order_by(
        db_defectdojo_sync.id.desc()).first()
    if row is None:
        row = db_defectdojo_sync(finding_id=finding_id)
        db.session.add(row)
    if getattr(row, 'opdracht_id', None) is None:
        from meuk.flask import project as _project
        row.opdracht_id = _project.current_opdracht_id()
    if dd_finding_id is not None:
        row.dd_finding_id = dd_finding_id
    row.dd_engagement_id = engagement_id
    row.last_action = action
    row.last_status = status
    row.last_message = (message or '')[:2000]
    row.synced_at = datetime.datetime.utcnow()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@defectdojo_bp.route('/api/defectdojo/test', methods=['GET', 'POST'])
def dd_test_connection():
    """Test de DefectDojo-verbinding en configuratie."""
    cfg = _dd_config()
    if not cfg:
        return jsonify({'ok': False, 'error': 'DefectDojo is niet geconfigureerd (URL + API-sleutel vereist)'}), 400
    ok, code, body = _dd_request(cfg, 'GET', '/api/v2/user_profile/')
    if not ok:
        # user_profile bestaat niet in alle versies; val terug op /products/
        ok, code, body = _dd_request(cfg, 'GET', '/api/v2/products/', params={'limit': 1})
    if not ok:
        return jsonify({'ok': False, 'status': code, 'error': body}), 502
    info = {'ok': True, 'status': code}
    if cfg.get('product_id'):
        p_ok, _c, p_body = _dd_request(cfg, 'GET', '/api/v2/products/{}/'.format(cfg['product_id']))
        info['product'] = p_body.get('name') if p_ok and isinstance(p_body, dict) else None
    if cfg.get('engagement_id'):
        e_ok, _c, e_body = _dd_request(cfg, 'GET', '/api/v2/engagements/{}/'.format(cfg['engagement_id']))
        info['engagement'] = e_body.get('name') if e_ok and isinstance(e_body, dict) else None
    return jsonify(info)


@defectdojo_bp.route('/api/defectdojo/push', methods=['POST'])
def dd_push():
    """Push bevindingen naar DefectDojo. Body: {finding_ids?: [int], only_final?: bool}."""
    cfg = _dd_config()
    if not cfg:
        return jsonify({'ok': False, 'error': 'DefectDojo is niet geconfigureerd'}), 400
    engagement_id = cfg.get('engagement_id')
    if not engagement_id:
        return jsonify({'ok': False, 'error': 'Geen engagement-ID geconfigureerd'}), 400

    data = request.get_json(silent=True) or {}
    finding_ids = data.get('finding_ids')
    only_final = data.get('only_final', True)

    from meuk.flask import project as _project
    query = _project.apply_scope(
        db_bevindingen.query.filter(db_bevindingen.deleted_at.is_(None)),
        db_bevindingen.opdracht_id, _project.current_opdracht_id())
    if finding_ids and isinstance(finding_ids, list):
        query = query.filter(db_bevindingen.id.in_([int(x) for x in finding_ids if str(x).isdigit()]))
    elif only_final:
        query = query.filter(db_bevindingen.status == 'final')
    bevindingen = query.all()
    if not bevindingen:
        return jsonify({'ok': False, 'error': 'Geen bevindingen om te pushen'}), 400

    ok, test_or_err = _ensure_test(cfg, engagement_id)
    if not ok:
        return jsonify({'ok': False, 'error': 'Kon geen test aanmaken', 'detail': test_or_err}), 502
    test_id = test_or_err

    templates = {str(t.id): t for t in db_bevindingen_templates.query.all()}
    results = []
    created = updated = failed = 0
    for bev in bevindingen:
        template = templates.get(str(bev.ref))
        endpoint_ids = _endpoints_for_finding(cfg, bev)
        payload = _finding_payload(bev, template, test_id, endpoint_ids=endpoint_ids)
        # Bestaat er al een DD-finding voor deze bevinding?
        existing = db_defectdojo_sync.query.filter_by(finding_id=bev.id).order_by(
            db_defectdojo_sync.id.desc()).first()
        dd_id = existing.dd_finding_id if existing else None

        if dd_id:
            # Update bestaande finding (test niet meesturen bij PATCH)
            patch = {k: v for k, v in payload.items() if k != 'test'}
            r_ok, _code, r_body = _dd_request(
                cfg, 'PATCH', '/api/v2/findings/{}/'.format(dd_id), json_body=patch)
            if r_ok:
                updated += 1
                _upload_evidence(cfg, dd_id, bev.id)
                _log_sync(bev.id, dd_id, engagement_id, 'update', 'ok', '')
                results.append({'finding_id': bev.id, 'dd_finding_id': dd_id, 'action': 'update'})
            else:
                failed += 1
                _log_sync(bev.id, dd_id, engagement_id, 'update', 'error', str(r_body))
                results.append({'finding_id': bev.id, 'action': 'update', 'error': r_body})
        else:
            r_ok, _code, r_body = _dd_request(
                cfg, 'POST', '/api/v2/findings/', json_body=payload)
            if r_ok and isinstance(r_body, dict) and r_body.get('id'):
                new_id = r_body['id']
                created += 1
                _upload_evidence(cfg, new_id, bev.id)
                _log_sync(bev.id, new_id, engagement_id, 'create', 'ok', '')
                results.append({'finding_id': bev.id, 'dd_finding_id': new_id, 'action': 'create'})
            else:
                failed += 1
                _log_sync(bev.id, None, engagement_id, 'create', 'error', str(r_body))
                results.append({'finding_id': bev.id, 'action': 'create', 'error': r_body})

    db.session.commit()
    return jsonify({
        'ok': failed == 0,
        'created': created, 'updated': updated, 'failed': failed,
        'results': results,
    })


@defectdojo_bp.route('/api/defectdojo/status', methods=['GET'])
def dd_status():
    """Overzicht van de sync-historie per bevinding."""
    rows = db_defectdojo_sync.query.order_by(db_defectdojo_sync.synced_at.desc()).all()
    return jsonify({'synced': [{
        'finding_id': r.finding_id,
        'dd_finding_id': r.dd_finding_id,
        'engagement_id': r.dd_engagement_id,
        'action': r.last_action,
        'status': r.last_status,
        'message': r.last_message,
        'synced_at': r.synced_at.isoformat() if r.synced_at else None,
    } for r in rows]})


# ---------------------------------------------------------------------------
# Import (DefectDojo -> IB) en pull-update van gelinkte bevindingen
# ---------------------------------------------------------------------------

# DefectDojo severity -> representatieve CVSS-basescore (als cvssv3_score ontbreekt)
_DD_SEV_TO_BASESCORE = {
    'Critical': '9.5', 'High': '8.0', 'Medium': '5.5', 'Low': '3.0', 'Info': '0.0',
}


def _reverse_remediation_status(dd):
    """Leid de IB-herstelstatus af uit de DefectDojo-statusvlaggen."""
    if dd.get('false_p'):
        return 'open'
    if dd.get('risk_accepted'):
        return 'accepted'
    if dd.get('is_mitigated') or dd.get('mitigated'):
        return 'fixed'
    return 'open'


def _dd_to_bev_fields(dd):
    """Map een DefectDojo-finding (dict) naar IB-bevindingvelden."""
    sev = dd.get('severity') or 'Info'
    score = dd.get('cvssv3_score')
    if score in (None, ''):
        basescore = _DD_SEV_TO_BASESCORE.get(sev, '0.0')
    else:
        basescore = str(score)
    fields = {
        'naam': (dd.get('title') or 'DefectDojo-finding').strip()[:255],
        'basescore': basescore[:10],
        'uitwerken': dd.get('description') or '',
        'remediation_status': _reverse_remediation_status(dd),
    }
    vector = dd.get('cvssv3') or ''
    if vector:
        fields['cvss'] = str(vector)[:255]
    mitigation = dd.get('mitigation') or ''
    if mitigation:
        fields['uitwerken'] = (fields['uitwerken'] +
                               '\n\n## Mitigatie (DefectDojo)\n\n' + mitigation).strip()
    return fields


def _linked_dd_ids():
    """Set van DefectDojo-finding-ids die al aan een IB-bevinding gekoppeld zijn."""
    out = {}
    for r in db_defectdojo_sync.query.filter(
            db_defectdojo_sync.dd_finding_id.isnot(None)).all():
        out[r.dd_finding_id] = r.finding_id
    return out


@defectdojo_bp.route('/api/defectdojo/import', methods=['POST'])
def dd_import():
    """Haal bevindingen op uit DefectDojo en maak nieuwe IB-bevindingen aan.

    Body: {only_open?: bool (default True), limit?: int (default 100),
           test_id?: int, engagement_id?: int}. Al gekoppelde DD-findings
    worden overgeslagen (gebruik /pull om die bij te werken).
    """
    cfg = _dd_config()
    if not cfg:
        return jsonify({'ok': False, 'error': 'DefectDojo is niet geconfigureerd'}), 400

    data = request.get_json(silent=True) or {}
    only_open = data.get('only_open', True)
    try:
        limit = max(1, min(int(data.get('limit', 100)), 500))
    except (TypeError, ValueError):
        limit = 100
    test_id = data.get('test_id')
    engagement_id = data.get('engagement_id') or cfg.get('engagement_id')

    params = {'limit': limit, 'offset': 0}
    if test_id:
        params['test'] = test_id
    elif engagement_id:
        params['test__engagement'] = engagement_id
    if only_open:
        params['active'] = 'true'

    ok, code, body = _dd_request(cfg, 'GET', '/api/v2/findings/', params=params)
    if not ok:
        return jsonify({'ok': False, 'error': 'Ophalen mislukt', 'detail': body,
                        'status': code}), 502
    dd_findings = body.get('results', []) if isinstance(body, dict) else []

    linked = _linked_dd_ids()
    imported = skipped = 0
    results = []
    for dd in dd_findings:
        dd_id = dd.get('id')
        if dd_id in linked:
            skipped += 1
            continue
        fields = _dd_to_bev_fields(dd)
        bev = db_bevindingen(status='draft', **fields)
        db.session.add(bev)
        db.session.flush()
        _log_sync(bev.id, dd_id, engagement_id, 'import', 'ok', '')
        imported += 1
        results.append({'finding_id': bev.id, 'dd_finding_id': dd_id,
                        'naam': bev.naam})

    db.session.commit()
    return jsonify({'ok': True, 'imported': imported, 'skipped': skipped,
                    'total': len(dd_findings), 'results': results})


@defectdojo_bp.route('/api/defectdojo/pull', methods=['POST'])
def dd_pull():
    """Werk gekoppelde IB-bevindingen bij met de huidige stand in DefectDojo.

    Body: {finding_ids?: [int]} — standaard alle gekoppelde bevindingen.
    Overschrijft naam/basescore/cvss/uitwerking/herstelstatus vanuit DD.
    """
    cfg = _dd_config()
    if not cfg:
        return jsonify({'ok': False, 'error': 'DefectDojo is niet geconfigureerd'}), 400

    data = request.get_json(silent=True) or {}
    finding_ids = data.get('finding_ids')

    from meuk.flask import project as _project
    q = _project.apply_scope(
        db_defectdojo_sync.query.filter(db_defectdojo_sync.dd_finding_id.isnot(None)),
        db_defectdojo_sync.opdracht_id, _project.current_opdracht_id())
    if finding_ids and isinstance(finding_ids, list):
        ids = [int(x) for x in finding_ids if str(x).isdigit()]
        q = q.filter(db_defectdojo_sync.finding_id.in_(ids))
    # Meest recente sync-rij per bevinding
    seen = set()
    links = []
    for r in q.order_by(db_defectdojo_sync.id.desc()).all():
        if r.finding_id in seen:
            continue
        seen.add(r.finding_id)
        links.append(r)

    updated = failed = missing = 0
    results = []
    for link in links:
        bev = db.session.get(db_bevindingen, link.finding_id)
        if not bev or bev.deleted_at is not None:
            missing += 1
            continue
        ok, _code, dd = _dd_request(
            cfg, 'GET', '/api/v2/findings/{}/'.format(link.dd_finding_id))
        if not ok or not isinstance(dd, dict):
            failed += 1
            _log_sync(bev.id, link.dd_finding_id, link.dd_engagement_id,
                      'pull', 'error', str(dd))
            results.append({'finding_id': bev.id, 'error': dd})
            continue
        for k, v in _dd_to_bev_fields(dd).items():
            setattr(bev, k, v)
        _log_sync(bev.id, link.dd_finding_id, link.dd_engagement_id,
                  'pull', 'ok', '')
        updated += 1
        results.append({'finding_id': bev.id, 'dd_finding_id': link.dd_finding_id})

    db.session.commit()
    return jsonify({'ok': failed == 0, 'updated': updated, 'failed': failed,
                    'missing': missing, 'results': results})
