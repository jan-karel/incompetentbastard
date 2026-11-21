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
import re
import threading
import uuid as _uuid

from flask import Blueprint, request, jsonify, current_app

from meuk.flask.models import (
    db, db_bevindingen, db_bevindingen_templates, db_evidence,
    db_defectdojo_sync, db_defectdojo_connection, db_opdracht_config,
    db_asset, db_asset_anchor, db_opdracht, nu_utc,
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

def _to_int_or_none(v):
    try:
        return int(v) if v not in (None, '') else None
    except (ValueError, TypeError):
        return None


def _ensure_default_connection():
    """Seed eenmalig een standaardprofiel uit de legacy globale verbinding."""
    if db_defectdojo_connection.query.first() is not None:
        return
    g = _get_appdata()
    url = (getattr(g, 'dd_url', '') or '').strip()
    key = (getattr(g, 'dd_api_key', '') or '').strip()
    if url and key:
        c = db_defectdojo_connection(
            naam='Standaard', dd_url=url.rstrip('/'), dd_api_key=key,
            dd_verify_ssl=bool(getattr(g, 'dd_verify_ssl', True)), is_default=True)
        db.session.add(c)
        db.session.commit()


def _set_default_connection(cid):
    db_defectdojo_connection.query.update({'is_default': False})
    c = db.session.get(db_defectdojo_connection, cid)
    if c is not None:
        c.is_default = True


def _resolve_connection(p, connection_id=None):
    """Kies de DefectDojo-verbinding: expliciet profiel > opdracht-profiel >
    standaardprofiel > legacy globaal. Retourneert {url,key,verify} of None."""
    _ensure_default_connection()
    c = None
    if connection_id not in (None, '') and str(connection_id).isdigit():
        c = db.session.get(db_defectdojo_connection, int(connection_id))
    if c is None and p is not None and getattr(p, 'dd_connection_id', None):
        c = db.session.get(db_defectdojo_connection, p.dd_connection_id)
    if c is None:
        c = (db_defectdojo_connection.query.filter_by(is_default=True).first()
             or db_defectdojo_connection.query.order_by(
                 db_defectdojo_connection.id.asc()).first())
    if c is not None and (c.dd_url or '').strip() and (c.dd_api_key or '').strip():
        return {'url': (c.dd_url or '').rstrip('/'), 'key': c.dd_api_key or '',
                'verify': bool(c.dd_verify_ssl),
                'user_id': getattr(c, 'dd_user_id', None)}
    # Legacy fallback (nog geen profielen): globale/per-opdracht velden.
    g = _get_appdata()
    url = (getattr(g, 'dd_url', '') or (getattr(p, 'dd_url', '') if p else '') or '').rstrip('/')
    key = getattr(g, 'dd_api_key', '') or (getattr(p, 'dd_api_key', '') if p else '') or ''
    if url and key:
        return {'url': url, 'key': key,
                'verify': bool(getattr(g, 'dd_verify_ssl', True)), 'user_id': None}
    return None


def _dd_config(connection_id=None):
    """Haal DefectDojo-config op; None indien niet geconfigureerd. De verbinding
    komt uit een verbindingsprofiel (expliciet > per-opdracht > standaard >
    legacy globaal); product/engagement zijn per opdracht."""
    from meuk.flask import project as _project
    p = _project.current_config()
    conn = _resolve_connection(p, connection_id)
    if not conn:
        return None
    return {
        'url': conn['url'], 'key': conn['key'], 'verify_ssl': conn['verify'],
        'user_id': conn.get('user_id'),
        'product_id': getattr(p, 'dd_product_id', None) if p is not None else None,
        'engagement_id': getattr(p, 'dd_engagement_id', None) if p is not None else None,
    }


# ---------------------------------------------------------------------------
# Verbindingsprofielen (meerdere DefectDojo-instances)
# ---------------------------------------------------------------------------

@defectdojo_bp.route('/api/defectdojo/connections', methods=['GET'])
def dd_connections_list():
    """Lijst van verbindingsprofielen (API-sleutel gemaskeerd)."""
    _ensure_default_connection()
    rows = db_defectdojo_connection.query.order_by(db_defectdojo_connection.id.asc()).all()
    return jsonify({'ok': True, 'connections': [{
        'id': c.id, 'naam': c.naam or '', 'url': c.dd_url or '',
        'api_key_set': bool(c.dd_api_key or ''),
        'verify_ssl': bool(c.dd_verify_ssl), 'user_id': c.dd_user_id,
        'is_default': bool(c.is_default),
    } for c in rows]})


@defectdojo_bp.route('/api/defectdojo/connections', methods=['POST'])
def dd_connections_create():
    data = request.get_json(silent=True) or {}
    c = db_defectdojo_connection(
        naam=((data.get('naam') or '').strip()[:120] or 'DefectDojo'),
        dd_url=(data.get('dd_url') or '').strip().rstrip('/')[:300],
        dd_api_key=(data.get('dd_api_key') or '').strip()[:300],
        dd_verify_ssl=bool(data.get('dd_verify_ssl', True)),
        dd_user_id=_to_int_or_none(data.get('dd_user_id')))
    db.session.add(c)
    db.session.flush()
    if data.get('is_default') or db_defectdojo_connection.query.count() == 1:
        _set_default_connection(c.id)
    db.session.commit()
    return jsonify({'ok': True, 'id': c.id})


@defectdojo_bp.route('/api/defectdojo/connections/<int:cid>', methods=['POST'])
def dd_connections_update(cid):
    c = db.session.get(db_defectdojo_connection, cid)
    if c is None:
        return jsonify({'ok': False, 'error': 'Profiel niet gevonden'}), 404
    data = request.get_json(silent=True) or {}
    if 'naam' in data:
        c.naam = (data['naam'] or '').strip()[:120]
    if 'dd_url' in data:
        c.dd_url = (data['dd_url'] or '').strip().rstrip('/')[:300]
    if 'dd_api_key' in data and (data['dd_api_key'] or '').strip():
        c.dd_api_key = data['dd_api_key'].strip()[:300]  # leeg = ongewijzigd
    if 'dd_verify_ssl' in data:
        c.dd_verify_ssl = bool(data['dd_verify_ssl'])
    if 'dd_user_id' in data:
        c.dd_user_id = _to_int_or_none(data.get('dd_user_id'))
    if data.get('is_default'):
        _set_default_connection(cid)
    db.session.commit()
    return jsonify({'ok': True})


@defectdojo_bp.route('/api/defectdojo/connections/<int:cid>', methods=['DELETE'])
def dd_connections_delete(cid):
    c = db.session.get(db_defectdojo_connection, cid)
    if c is None:
        return jsonify({'ok': False, 'error': 'Profiel niet gevonden'}), 404
    was_default = bool(c.is_default)
    db_opdracht_config.query.filter_by(dd_connection_id=cid).update(
        {'dd_connection_id': None})
    db.session.delete(c)
    db.session.flush()
    if was_default:
        nxt = db_defectdojo_connection.query.order_by(
            db_defectdojo_connection.id.asc()).first()
        if nxt is not None:
            _set_default_connection(nxt.id)
    db.session.commit()
    return jsonify({'ok': True})


@defectdojo_bp.route('/api/defectdojo/connections/<int:cid>/test', methods=['POST'])
def dd_connections_test(cid):
    cfg = _dd_config(connection_id=cid)
    if not cfg:
        return jsonify({'ok': False, 'error': 'Profiel onvolledig'}), 400
    ok, code, body = _dd_request(cfg, 'GET', '/api/v2/products/', params={'limit': 1})
    if not ok:
        return jsonify({'ok': False, 'status': code, 'error': body}), 502
    return jsonify({'ok': True, 'status': code})


def _dd_request(cfg, method, path, *, json_body=None, params=None, files=None,
                data=None, retries=2):
    """Voer een DefectDojo API-call uit. Retourneert (ok, status_code, payload|error).

    Transiënte fouten (netwerk, 429/5xx) worden met backoff opnieuw geprobeerd,
    behalve bij multipart-uploads (file-handles zijn na een poging verbruikt).
    """
    import requests
    import time as _time
    url = cfg['url'] + path
    headers = {'Authorization': 'Token ' + cfg['key']}
    if json_body is not None:
        headers['Content-Type'] = 'application/json'
    attempt = 0
    while True:
        try:
            resp = requests.request(
                method, url, headers=headers, json=json_body, params=params,
                files=files, data=data, verify=cfg['verify_ssl'], timeout=30,
            )
        except requests.exceptions.RequestException as exc:
            if files is None and attempt < retries:
                _time.sleep(0.5 * (2 ** attempt))
                attempt += 1
                continue
            return False, 0, str(exc)
        if (resp.status_code in (429, 500, 502, 503, 504)
                and files is None and attempt < retries):
            _time.sleep(0.5 * (2 ** attempt))
            attempt += 1
            continue
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
        'active': True, 'verified': False, 'false_p': False,
        'is_mitigated': False, 'risk_accepted': False, 'out_of_scope': False,
    }
    if rem in ('fixed', 'verified'):
        flags['active'] = False
        flags['is_mitigated'] = True
        if rem == 'verified':
            flags['verified'] = True
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


def _dd_md(text):
    r"""Render IB-bevindingtekst (semantische LaTeX-macro's) naar Markdown voor
    DefectDojo. \plaatje{bestand}{bijschrift} wordt ![bijschrift](bestand) met
    alleen de bestandsnaam, zodat import het weer als \plaatje herkent."""
    if not text:
        return ''
    from meuk.flask.rapport import _vrij_latex_naar_opmaak
    md = _vrij_latex_naar_opmaak(text, 'md')

    # \plaatje levert hier ![cap](bestand). De inline access_file-URL is pas
    # bekend na het uploaden van de bijlage, dus coderen we naam+bijschrift in
    # een token dat _push_findings na upload vervangt.
    import base64 as _b64

    def _imgref(m):
        cap = (m.group(1) or '').strip()
        bestand = os.path.basename(m.group(2))
        tb = _b64.urlsafe_b64encode(bestand.encode('utf-8')).decode('ascii')
        tc = _b64.urlsafe_b64encode(cap.encode('utf-8')).decode('ascii')
        return '@@IMG@@%s@@%s@@' % (tb, tc)
    md = re.sub(r'!\[([^\]]*)\]\(([^)]+)\)', _imgref, md)
    return md.strip()


def _md_naar_latex(md):
    r"""Best-effort Markdown -> semantische LaTeX-macro's bij import. Dekt vet,
    cursief, code, koppen en ![..](..)->\plaatje. Footnotes/haakjes/kruis-
    verwijzingen/tabellen hebben geen betrouwbare inverse en blijven as-is."""
    if not md:
        return ''
    s = md.replace('\r\n', '\n')
    prot = []

    def _p(txt):
        prot.append(txt)
        return '\x00P%d\x00' % (len(prot) - 1)

    # Code-spans en afbeeldingen eerst beschermen (bestandsnaam kan _ bevatten).
    s = re.sub(r'`([^`]+)`', lambda m: _p('\\texttt{%s}' % m.group(1)), s)
    def _img_to_plaatje(m):
        alt = m.group(1)
        ref = m.group(2)
        # Onze inline-export: ![caption :: bestand.png](url) -> \plaatje{bestand}{caption}.
        if ' :: ' in alt:
            cap, _sep, bestand = alt.rpartition(' :: ')
            bestand = os.path.basename(bestand.strip())
            if bestand:
                return _p('\\plaatje{%s}{%s}' % (bestand, cap.strip()))
        # Kale bestandsnaam (geen pad/URL) -> \plaatje.
        if '://' not in ref and '/' not in ref:
            return _p('\\plaatje{%s}{%s}' % (os.path.basename(ref), alt))
        # Externe/inline-URL zonder herleidbare naam: laat de markdown staan.
        return m.group(0)
    s = re.sub(r'!\[([^\]]*)\]\(([^)]+)\)', _img_to_plaatje, s)
    # Onze eigen export-tekstvorm van afbeeldingen terug naar \plaatje.
    s = re.sub(r'\*Afbeelding(?: \u2014 (.*?))?\s*\(zie bijlage:\s*([^)]+)\)\*',
               lambda m: _p('\\plaatje{%s}{%s}' % (os.path.basename(m.group(2)), (m.group(1) or '').strip())), s)
    # Vet voor cursief (anders pakt de cursief-regex de losse *).
    s = re.sub(r'\*\*([^*]+)\*\*', r'\\textbf{\1}', s)
    s = re.sub(r'__([^_]+)__', r'\\textbf{\1}', s)
    s = re.sub(r'(?<!\*)\*([^*\n]+)\*(?!\*)', r'\\textit{\1}', s)
    s = re.sub(r'(?<!\w)_([^_\n]+)_(?!\w)', r'\\textit{\1}', s)
    # Koppen -> vette regel.
    s = re.sub(r'(?m)^#{1,6}\s*(.+?)\s*$', r'\\textbf{\1}', s)
    # Beschermde fragmenten terugzetten.
    s = re.sub(r'\x00P(\d+)\x00', lambda m: prot[int(m.group(1))], s)
    return s


def _finding_payload(bev, template, test_id, endpoint_ids=None, found_by=None,
                     reporter=None):
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
        descr_parts.append(_dd_md(beschrijving))
    if getattr(bev, 'control_ref', ''):
        descr_parts.append('**Controle-referentie:** ' + bev.control_ref)
    description = '\n\n'.join([_p for _p in descr_parts if _p]) or (bev.naam or 'Geen beschrijving')
    steps = _dd_md(bev.uitwerken) if bev.uitwerken else ''  

    payload = {
        'title': bev.naam or 'Bevinding #{}'.format(bev.id),
        'test': test_id,
        'severity': dd_sev,
        'description': description,
        'steps_to_reproduce': steps,
        'mitigation': _dd_md(aanbeveling),
        'impact': _dd_md(impact),
        'references': _dd_md(refs),
        'date': (bev.discovered_at or bev.created_at or nu_utc()).strftime('%Y-%m-%d'),
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
    # found_by (test-type) is in sommige DefectDojo-versies verplicht.
    if found_by:
        payload['found_by'] = found_by
    # reporter = DefectDojo user-id uit het verbindingsprofiel (wie meldt).
    if reporter:
        payload['reporter'] = reporter
    # Stabiele sleutel + tags voor dedup/herkenning in DefectDojo.
    payload['unique_id_from_tool'] = 'ib-%s-%s' % (bev.opdracht_id or 0, bev.id)
    payload['tags'] = ['incompetent-bastard', 'ib-opdracht-%s' % (bev.opdracht_id or 0)]
    # Geplande hersteldatum (expliciet of afgeleide SLA-doeldatum).
    _target = getattr(bev, 'remediation_target_date', None)
    if _target is None:
        try:
            from meuk.flask.findings import _sla_doeldatum
            _target = _sla_doeldatum(bev, template)
        except Exception:
            _target = None
    if _target is not None:
        try:
            payload['planned_remediation_date'] = _target.strftime('%Y-%m-%d')
        except Exception:
            pass
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


# DefectDojo accepteert alleen bepaalde beeldextensies voor finding-bijlagen
# (o.a. .png en .jpeg — let op: NIET .jpg). Overige formaten converteren we
# naar PNG zodat screenshots altijd meekomen.
_DD_IMAGE_EXTS = {'.png', '.jpeg'}
_DD_EXT_ALIAS = {'.jpg': '.jpeg', '.jpe': '.jpeg'}
_DD_UP_MIME = {'.png': 'image/png', '.jpeg': 'image/jpeg'}
# Eerste accolade-argument van \plaatje{bestand}{caption}.
_PLAATJE_NAAM_RE = re.compile(r'\\plaatje\s*\{([^{}]+)\}')
# Token dat _dd_md voor een afbeelding plaatst; na upload vervangen door de
# inline access_file-URL (of tekstvorm als de bijlage ontbreekt).
_IMG_TOKEN_RE = re.compile(r'@@IMG@@([^@]*)@@([^@]*)@@')


def _resolve_img_tokens(text, cfg, dd_finding_id, img_map):
    """Vervang @@IMG@@-tokens door ![cap](<dd-url>/access_file/<id>/<finding>/Finding).
    img_map = {bestandsnaam: file-id}. Zonder bijlage -> leesbare tekstvorm."""
    if not text or '@@IMG@@' not in text:
        return text
    import base64 as _b64
    base = (cfg.get('url') or '').rstrip('/')

    def _sub(m):
        try:
            bestand = _b64.urlsafe_b64decode(m.group(1).encode('ascii')).decode('utf-8')
            cap = _b64.urlsafe_b64decode(m.group(2).encode('ascii')).decode('utf-8')
        except Exception:
            return ''
        fid = img_map.get(bestand)
        if fid:
            # Bestandsnaam in de alt-tekst zodat import \plaatje{naam} kan
            # reconstrueren: ![caption :: bestand.png](url).
            alt = '%s :: %s' % (cap, bestand)
            return '![%s](%s/access_file/%s/%s/Finding)' % (alt, base, fid, dd_finding_id)
        if cap:
            return '*Afbeelding \u2014 %s (zie bijlage: %s)*' % (cap, bestand)
        return '*Afbeelding (zie bijlage: %s)*' % bestand
    return _IMG_TOKEN_RE.sub(_sub, text)


def _convert_to_png(src):
    """Converteer een afbeelding naar PNG-bytes; None als dat niet lukt."""
    try:
        import io
        from PIL import Image
        with Image.open(src) as im:
            if im.mode not in ('RGB', 'RGBA'):
                im = im.convert('RGBA')
            buf = io.BytesIO()
            im.save(buf, format='PNG')
            return buf.getvalue()
    except Exception:
        return None


def _upload_image_file(cfg, dd_finding_id, src, titel):
    """Upload één afbeeldingsbestand als DefectDojo-finding-bijlage.

    Normaliseert de extensie (.jpg -> .jpeg) en converteert onbekende
    beeldformaten naar PNG. Retourneert de file-id, of None.
    """
    import io
    if not src or not os.path.exists(src):
        return None
    root = os.path.splitext(os.path.basename(src))[0] or 'afbeelding'
    ext = _DD_EXT_ALIAS.get(os.path.splitext(src)[1].lower(),
                           os.path.splitext(src)[1].lower())
    try:
        if ext in _DD_IMAGE_EXTS:
            with open(src, 'rb') as fh:
                r_ok, _c, _b = _dd_request(
                    cfg, 'POST', '/api/v2/findings/{}/files/'.format(dd_finding_id),
                    files={'file': (root + ext, fh, _DD_UP_MIME.get(ext, 'application/octet-stream'))},
                    data={'title': titel or root},
                )
        else:
            png = _convert_to_png(src)
            if png is None:
                return None
            r_ok, _c, _b = _dd_request(
                cfg, 'POST', '/api/v2/findings/{}/files/'.format(dd_finding_id),
                files={'file': (root + '.png', io.BytesIO(png), 'image/png')},
                data={'title': titel or root},
            )
        return _b.get('id') if (r_ok and isinstance(_b, dict)) else None
    except OSError:
        return None


def _existing_files(cfg, dd_finding_id):
    """{titel: file-id} van reeds aanwezige bijlagen (dedup + inline-URL)."""
    ok, _c, body = _dd_request(cfg, 'GET', '/api/v2/findings/{}/files/'.format(dd_finding_id))
    out = {}
    if ok and isinstance(body, dict):
        for f in body.get('files', []):
            t = (f.get('title') or '').strip()
            if t and f.get('id') is not None:
                out.setdefault(t, f['id'])
    return out


def _upload_evidence(cfg, dd_finding_id, finding_id, existing=None, fails=None):
    """Upload screenshot-bewijs (db_evidence, image/*) als DefectDojo-bijlagen.
    `existing` = reeds aanwezige bijlage-titels (dedup); `fails` verzamelt
    mislukte uploads."""
    existing = existing if existing is not None else {}
    uploaded = 0
    for ev in db_evidence.query.filter_by(finding_id=finding_id).all():
        if not (ev.content_type or '').startswith('image/'):
            continue
        titel = ev.description or ev.original_filename or ev.filename
        if titel in existing:
            continue
        src = os.path.join(_EVIDENCE_SRC, str(finding_id), ev.filename)
        if not os.path.exists(src):
            continue
        fid = _upload_image_file(cfg, dd_finding_id, src, titel)
        if fid:
            existing[titel] = fid
            uploaded += 1
        elif fails is not None:
            fails.append('evidence: %s' % titel)
    return uploaded


def _upload_plaatjes(cfg, dd_finding_id, bev, template, existing=None, fails=None):
    r"""Upload de \plaatje{..}-afbeeldingen uit de bevindingtekst als bijlagen.

    Respecteert lakken/redactie via _plaatje_bronpad (gelakt of niet-gevonden
    materiaal wordt niet meegestuurd). Retourneert {bestandsnaam: file-id}.
    """
    from meuk.flask.findings import _plaatje_bronpad
    existing = existing if existing is not None else {}
    teksten = [getattr(bev, 'uitwerken', '') or '']
    if template is not None:
        for f in ('nlbeschrijving', 'enbeschrijving', 'nlimpact', 'enimpact',
                  'nlaanbeveling', 'enaanbeveling'):
            teksten.append(getattr(template, f, '') or '')
    seen = set()
    img_map = {}
    for tekst in teksten:
        if not tekst or '\\plaatje' not in tekst:
            continue
        for m in _PLAATJE_NAAM_RE.findall(tekst):
            base = os.path.basename((m or '').strip())
            if not base or base in seen:
                continue
            seen.add(base)
            if base in existing:            # al aanwezig -> hergebruik file-id
                img_map[base] = existing[base]
                continue
            pad, _gelakt = _plaatje_bronpad(base)
            if not pad:
                continue
            fid = _upload_image_file(cfg, dd_finding_id, pad, base)
            if fid:
                existing[base] = fid
                img_map[base] = fid
            elif fails is not None:
                fails.append('plaatje: %s' % base)
    return img_map


def _log_sync(finding_id, dd_finding_id, engagement_id, action, status, message,
              content_hash=None):
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
    if content_hash is not None:
        row.content_hash = content_hash
    row.synced_at = nu_utc()


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


def _find_by_unique_id(cfg, uid):
    """Vind een bestaande DefectDojo-finding op onze stabiele sleutel."""
    if not uid:
        return None
    ok, _c, body = _dd_request(cfg, 'GET', '/api/v2/findings/',
                               params={'unique_id_from_tool': uid, 'limit': 1})
    if ok and isinstance(body, dict) and body.get('results'):
        return body['results'][0].get('id')
    return None


def _finding_image_names(bev, template):
    r"""Alle afbeeldingsnamen van een bevinding (evidence image/* + \plaatje)."""
    namen = set()
    for ev in db_evidence.query.filter_by(finding_id=bev.id).all():
        if (ev.content_type or '').startswith('image/'):
            namen.add(ev.original_filename or ev.filename)
    teksten = [getattr(bev, 'uitwerken', '') or '']
    if template is not None:
        for f in ('nlbeschrijving', 'enbeschrijving', 'nlimpact', 'enimpact',
                  'nlaanbeveling', 'enaanbeveling'):
            teksten.append(getattr(template, f, '') or '')
    for tekst in teksten:
        if tekst and '\\plaatje' in tekst:
            for m in _PLAATJE_NAAM_RE.findall(tekst):
                namen.add(os.path.basename((m or '').strip()))
    return namen


def _finding_hash(bev, payload, img_names):
    """Inhoud-hash voor change-detectie bij export."""
    import hashlib
    parts = [str(payload.get(k, '')) for k in (
        'title', 'severity', 'description', 'steps_to_reproduce',
        'mitigation', 'impact', 'references', 'cwe', 'cvssv3_score', 'reporter')]
    parts.append(str(sorted(payload.get('endpoints') or [])))
    parts.append(str(_status_flags(bev)))
    parts.append('|'.join(sorted(img_names)))
    return hashlib.sha256('\x00'.join(parts).encode('utf-8', 'replace')).hexdigest()


def _push_findings(cfg, engagement_id, *, only_final=True, finding_ids=None):
    """Push de bevindingen van het actieve project naar een engagement.

    Retourneert (payload, http_status). Scope't op het actieve project
    (zet eventueel vooraf een override voor een specifieke opdracht).
    """
    from meuk.flask import project as _project
    query = _project.apply_scope(
        db_bevindingen.query.filter(db_bevindingen.deleted_at.is_(None)),
        db_bevindingen.opdracht_id, _project.current_opdracht_id())
    if finding_ids and isinstance(finding_ids, list):
        query = query.filter(db_bevindingen.id.in_([int(x) for x in finding_ids if str(x).isdigit()]))
    elif only_final:
        query = query.filter(db_bevindingen.status == 'final')
    bevindingen = query.all()
    # Lege expliciete selectie -> fout; lege volledige export mag door naar de
    # lifecycle-close (verwijderde findings sluiten).
    if not bevindingen and finding_ids:
        return {'ok': False, 'error': 'Geen bevindingen om te pushen'}, 400

    test_id = None
    found_by = None
    if bevindingen:
        ok, test_or_err = _ensure_test(cfg, engagement_id)
        if not ok:
            return {'ok': False, 'error': 'Kon geen test aanmaken', 'detail': test_or_err}, 502
        test_id = test_or_err
        # Haal de test-type op voor het verplichte found_by-veld.
        _tt_ok, _c, _tbody = _dd_request(cfg, 'GET', '/api/v2/tests/{}/'.format(test_id))
        found_by = ([_tbody.get('test_type')]
                    if _tt_ok and isinstance(_tbody, dict) and _tbody.get('test_type')
                    else None)

    templates = {str(t.id): t for t in db_bevindingen_templates.query.all()}
    results = []
    created = updated = failed = unchanged = images = 0
    img_fails = []
    for bev in bevindingen:
        template = templates.get(str(bev.ref))
        endpoint_ids = _endpoints_for_finding(cfg, bev)
        payload = _finding_payload(bev, template, test_id, endpoint_ids=endpoint_ids,
                                   found_by=found_by, reporter=cfg.get('user_id'))
        img_names = _finding_image_names(bev, template)
        new_hash = _finding_hash(bev, payload, img_names)

        # Bestaande koppeling: lokaal, anders via stabiele sleutel in DefectDojo.
        existing = db_defectdojo_sync.query.filter_by(finding_id=bev.id).order_by(
            db_defectdojo_sync.id.desc()).first()
        dd_id = existing.dd_finding_id if existing else None
        if not dd_id:
            dd_id = _find_by_unique_id(cfg, payload.get('unique_id_from_tool'))

        # Ongewijzigd en vorige sync gelukt? -> overslaan.
        if (dd_id and existing and existing.last_status == 'ok'
                and existing.last_action != 'close'
                and getattr(existing, 'content_hash', '') == new_hash):
            unchanged += 1
            results.append({'finding_id': bev.id, 'dd_finding_id': dd_id, 'action': 'unchanged'})
            continue

        if dd_id:
            img_map = {}
            if img_names:
                _files = _existing_files(cfg, dd_id)
                _before = set(_files)
                images += _upload_evidence(cfg, dd_id, bev.id, existing=_files, fails=img_fails)
                img_map = _upload_plaatjes(cfg, dd_id, bev, template, existing=_files, fails=img_fails)
                images += len(set(img_map) - _before)
            patch = {k: v for k, v in payload.items() if k != 'test'}
            if img_names:
                for _f in ('description', 'steps_to_reproduce', 'mitigation', 'impact'):
                    if _f in patch:
                        patch[_f] = _resolve_img_tokens(patch[_f], cfg, dd_id, img_map)
            r_ok, _code, r_body = _dd_request(
                cfg, 'PATCH', '/api/v2/findings/{}/'.format(dd_id), json_body=patch)
            if r_ok:
                updated += 1
                _log_sync(bev.id, dd_id, engagement_id, 'update', 'ok', '', content_hash=new_hash)
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
                if img_names:
                    _files = _existing_files(cfg, new_id)
                    _before = set(_files)
                    images += _upload_evidence(cfg, new_id, bev.id, existing=_files, fails=img_fails)
                    img_map = _upload_plaatjes(cfg, new_id, bev, template, existing=_files, fails=img_fails)
                    images += len(set(img_map) - _before)
                    _patch = {}
                    for _f in ('description', 'steps_to_reproduce', 'mitigation', 'impact'):
                        if payload.get(_f) and '@@IMG@@' in payload[_f]:
                            _patch[_f] = _resolve_img_tokens(payload[_f], cfg, new_id, img_map)
                    if _patch:
                        _dd_request(cfg, 'PATCH', '/api/v2/findings/{}/'.format(new_id), json_body=_patch)
                _log_sync(bev.id, new_id, engagement_id, 'create', 'ok', '', content_hash=new_hash)
                results.append({'finding_id': bev.id, 'dd_finding_id': new_id, 'action': 'create'})
            else:
                failed += 1
                _log_sync(bev.id, None, engagement_id, 'create', 'error', str(r_body))
                results.append({'finding_id': bev.id, 'action': 'create', 'error': r_body})

    # Lifecycle: sluit eerder gesyncte findings waarvan de IB-bevinding is
    # verwijderd (alleen bij een volledige export, niet bij een selectie).
    closed = 0
    if not finding_ids:
        from meuk.flask import project as _project2
        _q = _project2.apply_scope(
            db_defectdojo_sync.query.filter(
                db_defectdojo_sync.dd_finding_id.isnot(None),
                db_defectdojo_sync.dd_engagement_id == engagement_id),
            db_defectdojo_sync.opdracht_id, _project2.current_opdracht_id())
        _seen = set()
        for _row in _q.order_by(db_defectdojo_sync.id.desc()).all():
            if _row.finding_id in _seen:
                continue
            _seen.add(_row.finding_id)
            if _row.last_action == 'close':
                continue
            _b = db.session.get(db_bevindingen, _row.finding_id)
            if _b is not None and _b.deleted_at is None:
                continue
            r_ok, _c, _b2 = _dd_request(
                cfg, 'PATCH', '/api/v2/findings/{}/'.format(_row.dd_finding_id),
                json_body={'active': False, 'is_mitigated': True, 'out_of_scope': True})
            if r_ok:
                closed += 1
                _log_sync(_row.finding_id, _row.dd_finding_id, engagement_id,
                          'close', 'ok', 'IB-bevinding verwijderd')

    db.session.commit()
    return {
        'ok': failed == 0,
        'created': created, 'updated': updated, 'unchanged': unchanged,
        'closed': closed, 'failed': failed,
        'images_uploaded': images, 'images_failed': len(img_fails),
        'image_errors': img_fails[:10],
        'results': results,
    }, 200


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
    payload, status = _push_findings(
        cfg, engagement_id,
        only_final=data.get('only_final', True),
        finding_ids=data.get('finding_ids'),
    )
    return jsonify(payload), status


# ---------------------------------------------------------------------------
# Asynchrone taken (export/import kunnen bij grote engagements lang duren)
# ---------------------------------------------------------------------------
_dd_runs = {}
_dd_lock = threading.Lock()
_DD_JOB_VIEWS = {}  # kind -> (viewfunc, needs_opdracht)


def _dd_job_worker(run_id, app, kind, opdracht_id, data):
    with _dd_lock:
        _dd_runs[run_id]['status'] = 'running'
    try:
        view, needs_opdracht = _DD_JOB_VIEWS[kind]
        with app.test_request_context(json=data, method='POST'):
            resp = view(opdracht_id) if needs_opdracht else view()
            body, status = resp if isinstance(resp, tuple) else (resp, 200)
            payload = body.get_json()
        with _dd_lock:
            _dd_runs[run_id].update(
                status='done', result=payload, http_status=status,
                finished_at=datetime.datetime.now().isoformat())
    except Exception as exc:  # noqa: BLE001
        with _dd_lock:
            _dd_runs[run_id].update(
                status='failed', error=str(exc),
                finished_at=datetime.datetime.now().isoformat())


@defectdojo_bp.route('/api/defectdojo/jobs', methods=['POST'])
def dd_start_job():
    """Start een achtergrondtaak. Body: {kind: export|import|create-import,
    opdracht_id?, ...}. Retourneert {run_id} om te pollen."""
    data = request.get_json(silent=True) or {}
    kind = data.get('kind')
    if kind not in _DD_JOB_VIEWS:
        return jsonify({'ok': False, 'error': 'Onbekende taak'}), 400
    _, needs_opdracht = _DD_JOB_VIEWS[kind]
    opdracht_id = data.get('opdracht_id')
    if needs_opdracht and not opdracht_id:
        return jsonify({'ok': False, 'error': 'opdracht_id vereist'}), 400
    run_id = str(_uuid.uuid4())
    with _dd_lock:
        _dd_runs[run_id] = {
            'id': run_id, 'kind': kind, 'status': 'queued', 'result': None,
            'error': None, 'started_at': datetime.datetime.now().isoformat(),
            'finished_at': None,
        }
    thread = threading.Thread(
        target=_dd_job_worker,
        args=(run_id, current_app._get_current_object(), kind, opdracht_id, data),
        daemon=True)
    thread.start()
    return jsonify({'ok': True, 'run_id': run_id})


@defectdojo_bp.route('/api/defectdojo/jobs/<run_id>', methods=['GET'])
def dd_job_status(run_id):
    """Poll de status van een achtergrondtaak."""
    with _dd_lock:
        run = _dd_runs.get(run_id)
    if not run:
        return jsonify({'error': 'Taak niet gevonden'}), 404
    return jsonify(run)


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
        return 'verified' if dd.get('verified') else 'fixed'
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
        'uitwerken': _md_naar_latex(dd.get('steps_to_reproduce') or dd.get('description') or ''),
        'remediation_status': _reverse_remediation_status(dd),
    }
    vector = dd.get('cvssv3') or ''
    if vector:
        fields['cvss'] = str(vector)[:255]
    mitigation = dd.get('mitigation') or ''
    if mitigation:
        fields['uitwerken'] = (fields['uitwerken'] +
                               '\n\n\\textbf{Mitigatie (DefectDojo)}\n\n' +
                               _md_naar_latex(mitigation)).strip()
    prd = dd.get('planned_remediation_date')
    if prd:
        try:
            fields['remediation_target_date'] = datetime.date.fromisoformat(str(prd)[:10])
        except (ValueError, TypeError):
            pass
    return fields


def _linked_dd_ids():
    """Set van DefectDojo-finding-ids die al aan een IB-bevinding gekoppeld zijn."""
    out = {}
    for r in db_defectdojo_sync.query.filter(
            db_defectdojo_sync.dd_finding_id.isnot(None)).all():
        out[r.dd_finding_id] = r.finding_id
    return out


# \plaatje{bestand}{bijschrift} — eerste arg is de bestandsnaam, tweede optioneel.
_PLAATJE_REF_RE = re.compile(r'\\plaatje\s*\{([^{}]+)\}(\s*\{[^{}]*\})?')


def _list_local_screenshots():
    """Bestandsnamen in raw/screenshots (+ annot-submap) voor naam-matching."""
    try:
        from meuk.flask.findings import _SCREENSHOT_DIR_REPORT as _dir
    except Exception:
        return set()
    names = set()
    for root in (_dir, os.path.join(_dir, 'annot')):
        try:
            if os.path.isdir(root):
                names.update(os.listdir(root))
        except OSError:
            pass
    return names


def _match_screenshot_name(naam, candidates):
    r"""Slimme match voor een \plaatje-naam onder bestandsnamen (case-insensitief):
    exact > numeriek-prefix (<cijfers>-naam, bv. 4864-bmc1.png) > suffix (..-naam).
    Retourneert de gematchte naam of None."""
    nl = (naam or '').lower()
    if not nl:
        return None
    for c in candidates:
        if c.lower() == nl:
            return c
    pat = re.compile(r'^\d+-' + re.escape(naam) + r'$', re.IGNORECASE)
    for c in candidates:
        if pat.match(c):
            return c
    for c in candidates:
        if c.lower().endswith('-' + nl):
            return c
    return None


def _normalize_plaatje_refs(uitwerken, cfg, dd_finding_id):
    r"""Herschrijf \plaatje{X} naar een bestaande lokale screenshot als X slim
    matcht (numeriek-prefix e.d.), zodat de afbeelding rendert. Meldt waar de
    bijlage alleen in DefectDojo bestaat of ontbreekt. Retourneert
    (nieuwe_tekst, meldingen)."""
    if not uitwerken or '\\plaatje' not in uitwerken:
        return uitwerken, []
    locals_ = _list_local_screenshots()
    att_titles = []
    ok, _c, body = _dd_request(cfg, 'GET', '/api/v2/findings/{}/files/'.format(dd_finding_id))
    if ok and isinstance(body, dict):
        att_titles = [os.path.basename((f.get('title') or '').strip())
                      for f in body.get('files', []) if (f.get('title') or '').strip()]
    meldingen = []

    def _fix(m):
        X = os.path.basename((m.group(1) or '').strip())
        rest = m.group(2) or ''
        if not X or X in locals_:
            return m.group(0)
        lm = _match_screenshot_name(X, locals_)
        if lm:
            meldingen.append({'ref': X, 'resolved': lm, 'bron': 'lokaal'})
            return '\\plaatje{%s}%s' % (lm, rest)
        am = _match_screenshot_name(X, att_titles) or (X if X in att_titles else None)
        if am:
            meldingen.append({'ref': X, 'resolved': am, 'bron': 'defectdojo-bijlage'})
        else:
            meldingen.append({'ref': X, 'resolved': None, 'bron': None})
        return m.group(0)

    return _PLAATJE_REF_RE.sub(_fix, uitwerken), meldingen


def _import_findings(cfg, *, only_open=True, limit=100, test_id=None,
                     engagement_id=None, product_id=None, opdracht_id=None):
    """Kern van de import: haal DefectDojo-findings op en maak IB-bevindingen aan.

    Retourneert (ok, payload). Als `opdracht_id` is opgegeven worden de nieuwe
    bevindingen expliciet aan die opdracht gekoppeld (anders stempelt het
    before_insert-event ze op basis van het actieve project).
    """
    try:
        limit = max(1, min(int(limit), 500))
    except (TypeError, ValueError):
        limit = 100

    base_params = {'limit': limit}
    if test_id:
        base_params['test'] = test_id
    elif engagement_id:
        base_params['test__engagement'] = engagement_id
    elif product_id:
        base_params['test__engagement__product'] = product_id
    if only_open:
        base_params['active'] = 'true'

    # Paginering: haal alle pagina's op (met veiligheidscap).
    dd_findings = []
    offset = 0
    total = None
    while True:
        ok, code, body = _dd_request(cfg, 'GET', '/api/v2/findings/',
                                     params=dict(base_params, offset=offset))
        if not ok:
            return False, {'ok': False, 'error': 'Ophalen mislukt', 'detail': body,
                           'status': code}
        page = body.get('results', []) if isinstance(body, dict) else []
        dd_findings.extend(page)
        if total is None and isinstance(body, dict):
            total = body.get('count')
        offset += limit
        if len(page) < limit:
            break
        if total is not None and offset >= total:
            break
        if offset >= 5000:  # veiligheidscap
            break

    linked = _linked_dd_ids()
    imported = skipped = relinked = 0
    plaatje_hersteld = plaatje_alleen_dd = plaatje_ontbreekt = 0
    plaatje_meldingen = []
    results = []
    for dd in dd_findings:
        dd_id = dd.get('id')
        if dd_id in linked:
            skipped += 1
            continue
        # Komt deze finding uit IB (stabiele sleutel ib-<opdracht>-<id>)? Dan
        # koppelen i.p.v. dupliceren.
        m = re.match(r'^ib-\d+-(\d+)$', dd.get('unique_id_from_tool') or '')
        if m:
            _bid = int(m.group(1))
            _b = db.session.get(db_bevindingen, _bid)
            if _b is not None and _b.deleted_at is None:
                _log_sync(_bid, dd_id, engagement_id, 'link', 'ok', '')
                linked[dd_id] = _bid
                relinked += 1
                continue
        fields = _dd_to_bev_fields(dd)
        if '\\plaatje' in (fields.get('uitwerken') or ''):
            fields['uitwerken'], _prep = _normalize_plaatje_refs(
                fields['uitwerken'], cfg, dd_id)
            for _r in _prep:
                if _r.get('bron') == 'lokaal':
                    plaatje_hersteld += 1
                elif _r.get('bron') == 'defectdojo-bijlage':
                    plaatje_alleen_dd += 1
                else:
                    plaatje_ontbreekt += 1
                if len(plaatje_meldingen) < 50:
                    plaatje_meldingen.append(dict(_r, dd_finding_id=dd_id))
        bev = db_bevindingen(status='draft', **fields)
        if opdracht_id is not None:
            bev.opdracht_id = opdracht_id
        db.session.add(bev)
        db.session.flush()
        _log_sync(bev.id, dd_id, engagement_id, 'import', 'ok', '')
        imported += 1
        results.append({'finding_id': bev.id, 'dd_finding_id': dd_id,
                        'naam': bev.naam})

    db.session.commit()
    return True, {'ok': True, 'imported': imported, 'skipped': skipped,
                  'relinked': relinked, 'total': len(dd_findings),
                  'plaatje_hersteld': plaatje_hersteld,
                  'plaatje_alleen_dd': plaatje_alleen_dd,
                  'plaatje_ontbreekt': plaatje_ontbreekt,
                  'plaatje_meldingen': plaatje_meldingen, 'results': results}


@defectdojo_bp.route('/api/defectdojo/import', methods=['POST'])
def dd_import():
    """Haal bevindingen op uit DefectDojo en maak nieuwe IB-bevindingen aan.

    Body: {only_open?: bool (default True), limit?: int (default 100),
           test_id?: int, engagement_id?: int}. Al gekoppelde DD-findings
    worden overgeslagen (gebruik /pull om die bij te werken). De bevindingen
    komen in het actieve project.
    """
    cfg = _dd_config()
    if not cfg:
        return jsonify({'ok': False, 'error': 'DefectDojo is niet geconfigureerd'}), 400

    data = request.get_json(silent=True) or {}
    ok, payload = _import_findings(
        cfg,
        only_open=data.get('only_open', True),
        limit=data.get('limit', 100),
        test_id=data.get('test_id'),
        engagement_id=data.get('engagement_id') or cfg.get('engagement_id'),
    )
    return jsonify(payload), (200 if ok else 502)


@defectdojo_bp.route('/api/opdrachten/<int:opdracht_id>/defectdojo/import', methods=['POST'])
def dd_import_opdracht(opdracht_id):
    """Importeer DefectDojo-bevindingen rechtstreeks in één opdracht.

    Body: {engagement_id?: int, only_open?: bool (default True), limit?: int}.
    De verbinding is server-breed; het engagement komt uit de body of uit de
    opdracht-config. Een expliciet opgegeven engagement wordt onthouden in de
    opdracht-config. De nieuwe bevindingen worden aan deze opdracht gekoppeld.
    """
    from meuk.flask import project as _project
    o = db.session.get(db_opdracht, opdracht_id)
    if o is None:
        return jsonify({'ok': False, 'error': 'Opdracht niet gevonden'}), 404

    # Richt config-resolutie (engagement/product + sync-logging) op deze opdracht.
    _project.set_override(opdracht_id)

    data = request.get_json(silent=True) or {}
    # Een expliciet engagement/product onthouden in de opdracht-config.
    expliciet = data.get('engagement_id')
    if (expliciet not in (None, '') or data.get('product_id') not in (None, '')
            or data.get('connection_id') not in (None, '')):
        try:
            cfg_row = _project.get_or_create_config(o)
            if expliciet not in (None, ''):
                cfg_row.dd_engagement_id = int(expliciet)
            if data.get('product_id') not in (None, ''):
                cfg_row.dd_product_id = int(data['product_id'])
            if data.get('connection_id') not in (None, ''):
                cfg_row.dd_connection_id = int(data['connection_id'])
            db.session.commit()
        except (ValueError, TypeError):
            db.session.rollback()

    cfg = _dd_config()
    if not cfg:
        return jsonify({'ok': False, 'error': 'DefectDojo is niet geconfigureerd'}), 400

    engagement_id = expliciet or cfg.get('engagement_id')
    ok, payload = _import_findings(
        cfg,
        only_open=data.get('only_open', True),
        limit=data.get('limit', 100),
        test_id=data.get('test_id'),
        engagement_id=engagement_id,
        opdracht_id=opdracht_id,
    )
    return jsonify(payload), (200 if ok else 502)


# ---------------------------------------------------------------------------
# Producten/engagements doorzoeken en (bij export) aanmaken
# ---------------------------------------------------------------------------

@defectdojo_bp.route('/api/defectdojo/products', methods=['GET'])
def dd_products():
    """Doorzoek DefectDojo-producten. Query: ?q=<naam>&limit=<n>&connection=<id>."""
    cfg = _dd_config(request.args.get('connection'))
    if not cfg:
        return jsonify({'ok': False, 'error': 'DefectDojo is niet geconfigureerd'}), 400
    q = (request.args.get('q') or '').strip()
    try:
        limit = max(1, min(int(request.args.get('limit', 50)), 200))
    except (TypeError, ValueError):
        limit = 50
    params = {'limit': limit}
    if q:
        params['name__icontains'] = q
    ok, code, body = _dd_request(cfg, 'GET', '/api/v2/products/', params=params)
    if not ok:
        return jsonify({'ok': False, 'error': 'Ophalen mislukt', 'detail': body}), 502
    rows = body.get('results', []) if isinstance(body, dict) else []
    items = [{'id': r.get('id'), 'name': r.get('name')} for r in rows]
    return jsonify({'ok': True, 'results': items,
                    'count': body.get('count') if isinstance(body, dict) else len(items)})


@defectdojo_bp.route('/api/defectdojo/engagements', methods=['GET'])
def dd_engagements():
    """Doorzoek DefectDojo-engagements. Query: ?q=&product=&limit=&connection=<id>."""
    cfg = _dd_config(request.args.get('connection'))
    if not cfg:
        return jsonify({'ok': False, 'error': 'DefectDojo is niet geconfigureerd'}), 400
    q = (request.args.get('q') or '').strip()
    product = request.args.get('product')
    try:
        limit = max(1, min(int(request.args.get('limit', 50)), 200))
    except (TypeError, ValueError):
        limit = 50
    params = {'limit': limit}
    if q:
        params['name__icontains'] = q
    if product and str(product).isdigit():
        params['product'] = int(product)
    ok, code, body = _dd_request(cfg, 'GET', '/api/v2/engagements/', params=params)
    if not ok:
        return jsonify({'ok': False, 'error': 'Ophalen mislukt', 'detail': body}), 502
    rows = body.get('results', []) if isinstance(body, dict) else []
    items = [{'id': r.get('id'), 'name': r.get('name'), 'product': r.get('product')}
             for r in rows]
    return jsonify({'ok': True, 'results': items,
                    'count': body.get('count') if isinstance(body, dict) else len(items)})


def _first_product_type(cfg):
    ok, _c, body = _dd_request(cfg, 'GET', '/api/v2/product_types/', params={'limit': 1})
    if ok and isinstance(body, dict) and body.get('results'):
        return body['results'][0].get('id')
    return None


def _find_or_create_product(cfg, name):
    """Vind een product op exacte naam of maak het aan. Retourneert (ok, id|error)."""
    name = (name or '').strip()
    if not name:
        return False, 'Lege productnaam'
    ok, _c, body = _dd_request(cfg, 'GET', '/api/v2/products/',
                               params={'name': name, 'limit': 20})
    if ok and isinstance(body, dict):
        for r in body.get('results', []):
            if (r.get('name') or '').strip().lower() == name.lower():
                return True, r['id']
    prod_type = _first_product_type(cfg)
    if prod_type is None:
        return False, 'Geen product_type beschikbaar in DefectDojo'
    ok, _c, body = _dd_request(cfg, 'POST', '/api/v2/products/', json_body={
        'name': name, 'description': name, 'prod_type': prod_type,
    })
    if ok and isinstance(body, dict) and body.get('id'):
        return True, body['id']
    return False, body


def _find_or_create_engagement(cfg, product_id, name):
    """Vind een engagement op naam binnen het product of maak het aan."""
    name = (name or '').strip()
    if not name:
        return False, 'Lege engagementnaam'
    ok, _c, body = _dd_request(cfg, 'GET', '/api/v2/engagements/',
                               params={'product': product_id, 'name': name, 'limit': 20})
    if ok and isinstance(body, dict):
        for r in body.get('results', []):
            if (r.get('name') or '').strip().lower() == name.lower():
                return True, r['id']
    today = datetime.date.today().isoformat()
    ok, _c, body = _dd_request(cfg, 'POST', '/api/v2/engagements/', json_body={
        'name': name, 'product': product_id,
        'target_start': today, 'target_end': today,
        'status': 'In Progress', 'engagement_type': 'Interactive',
    })
    if ok and isinstance(body, dict) and body.get('id'):
        return True, body['id']
    return False, body


@defectdojo_bp.route('/api/opdrachten/<int:opdracht_id>/defectdojo/export', methods=['POST'])
def dd_export_opdracht(opdracht_id):
    """Exporteer de bevindingen van één opdracht naar DefectDojo.

    Body: {product_id?, product_name?, engagement_id?, engagement_name?,
           only_final?, finding_ids?}. Ontbrekend product/engagement wordt
    aangemaakt (standaard op de opdrachtnaam). De gekozen/gemaakte ids worden
    onthouden in de opdracht-config.
    """
    from meuk.flask import project as _project
    o = db.session.get(db_opdracht, opdracht_id)
    if o is None:
        return jsonify({'ok': False, 'error': 'Opdracht niet gevonden'}), 404

    _project.set_override(opdracht_id)
    data = request.get_json(silent=True) or {}
    if data.get('connection_id') not in (None, ''):
        try:
            _cr = _project.get_or_create_config(o)
            _cr.dd_connection_id = int(data['connection_id'])
            db.session.commit()
        except (ValueError, TypeError):
            db.session.rollback()
    cfg = _dd_config()
    if not cfg:
        return jsonify({'ok': False, 'error': 'DefectDojo is niet geconfigureerd'}), 400

    fallback_naam = (o.naam or '').strip() or ('Opdracht %d' % opdracht_id)

    # Product bepalen (gekozen id > gekozen naam > config > opdrachtnaam-aanmaak).
    product_id = data.get('product_id') or cfg.get('product_id')
    if not product_id:
        naam = (data.get('product_name') or '').strip() or fallback_naam
        ok, res = _find_or_create_product(cfg, naam)
        if not ok:
            return jsonify({'ok': False, 'error': 'Kon product niet aanmaken',
                            'detail': res}), 502
        product_id = res

    # Engagement bepalen (gekozen id > gekozen naam-aanmaak > config > aanmaak).
    engagement_id = data.get('engagement_id')
    if not engagement_id:
        naam = (data.get('engagement_name') or '').strip() or fallback_naam
        ok, res = _find_or_create_engagement(cfg, product_id, naam)
        if not ok:
            return jsonify({'ok': False, 'error': 'Kon engagement niet aanmaken',
                            'detail': res}), 502
        engagement_id = res

    # Onthoud de koppeling in de opdracht-config.
    try:
        cfg_row = _project.get_or_create_config(o)
        cfg_row.dd_product_id = int(product_id)
        cfg_row.dd_engagement_id = int(engagement_id)
        db.session.commit()
    except (ValueError, TypeError):
        db.session.rollback()

    # Zorg dat endpoint-koppeling het juiste product gebruikt.
    cfg['product_id'] = int(product_id)
    cfg['engagement_id'] = int(engagement_id)

    payload, status = _push_findings(
        cfg, engagement_id,
        only_final=data.get('only_final', True),
        finding_ids=data.get('finding_ids'),
    )
    payload['product_id'] = int(product_id)
    payload['engagement_id'] = int(engagement_id)
    return jsonify(payload), status


def _dd_object_name(cfg, path, obj_id):
    """Naam van een DefectDojo-object (products/engagements), of leeg."""
    ok, _c, body = _dd_request(cfg, 'GET', '/api/v2/%s/%s/' % (path, obj_id))
    if ok and isinstance(body, dict):
        return (body.get('name') or '').strip()
    return ''


@defectdojo_bp.route('/api/opdrachten/defectdojo-import', methods=['POST'])
def dd_create_opdracht_from_import():
    """Maak een nieuwe opdracht uit een DefectDojo-product/engagement en
    importeer meteen de bevindingen.

    Body: {product_id?, engagement_id?, naam?, only_open?}. Zonder engagement
    wordt op productniveau geimporteerd.
    """
    from meuk.flask import project as _project
    data = request.get_json(silent=True) or {}
    cfg = _dd_config(data.get('connection_id'))
    if not cfg:
        return jsonify({'ok': False, 'error': 'DefectDojo is niet geconfigureerd'}), 400
    product_id = data.get('product_id') or None
    engagement_id = data.get('engagement_id') or None
    if not product_id and not engagement_id:
        return jsonify({'ok': False, 'error': 'Kies een product of engagement'}), 400

    naam = (data.get('naam') or '').strip()
    if not naam and engagement_id:
        naam = _dd_object_name(cfg, 'engagements', engagement_id)
    if not naam and product_id:
        naam = _dd_object_name(cfg, 'products', product_id)
    naam = (naam or 'DefectDojo-import')[:255]

    o = db_opdracht(naam=naam, status='actief')
    db.session.add(o)
    db.session.commit()
    cfg_row = _project.get_or_create_config(o)
    try:
        if product_id:
            cfg_row.dd_product_id = int(product_id)
        if engagement_id:
            cfg_row.dd_engagement_id = int(engagement_id)
        if data.get('connection_id') not in (None, ''):
            cfg_row.dd_connection_id = int(data['connection_id'])
        db.session.commit()
    except (ValueError, TypeError):
        db.session.rollback()

    _project.set_override(o.id)
    ok, payload = _import_findings(
        _dd_config() or cfg,
        only_open=data.get('only_open', True),
        engagement_id=int(engagement_id) if engagement_id else None,
        product_id=int(product_id) if (product_id and not engagement_id) else None,
        opdracht_id=o.id,
    )
    payload['opdracht_id'] = o.id
    payload['naam'] = naam
    return jsonify(payload), (200 if ok else 502)


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


_DD_JOB_VIEWS.update({
    'export': (dd_export_opdracht, True),
    'import': (dd_import_opdracht, True),
    'create-import': (dd_create_opdracht_from_import, False),
})
