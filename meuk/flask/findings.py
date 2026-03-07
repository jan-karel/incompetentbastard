from meuk.hacksec import *
from flask import Blueprint, render_template, redirect, url_for, flash, send_from_directory, abort, request, Response, jsonify
from meuk.flask.models import *
from meuk.flask.forms import *
from meuk.flask.security import require_dashboard_access
from werkzeug.utils import secure_filename
import datetime
import json
import os
import uuid


def _get_appdata():
    return db_instellingen.query.first()


def _get_scope_targets():
    """Haal scope targets op uit instellingen."""
    s = _get_appdata()
    try:
        return json.loads(getattr(s, 'rapport_scope_targets', '[]') or '[]')
    except (json.JSONDecodeError, TypeError):
        return []


# Blueprint Configuration
findings_bp = Blueprint('findings_bp', __name__,
                    template_folder='html',
                    static_folder='static')


# ---------------------------------------------------------------------------
# Helper: CVSS -> severity mapping
# ---------------------------------------------------------------------------

def _cvss_to_severity(basescore):
    try:
        score = float(basescore)
    except (TypeError, ValueError):
        return ('none', 5)
    if score >= 9.0:
        return ('critical', 1)
    elif score >= 7.0:
        return ('high', 2)
    elif score >= 4.0:
        return ('medium', 3)
    elif score > 0:
        return ('low', 4)
    return ('none', 5)


# ---------------------------------------------------------------------------
# Helper: LaTeX escaping
# ---------------------------------------------------------------------------

def _latex_escape(text):
    if not text:
        return ''
    text = str(text)
    for old, new in [('\\', '\\textbackslash{}'), ('&', '\\&'), ('%', '\\%'),
                     ('$', '\\$'), ('#', '\\#'), ('_', '\\_'), ('{', '\\{'),
                     ('}', '\\}'), ('~', '\\textasciitilde{}'), ('^', '\\textasciicircum{}')]:
        text = text.replace(old, new)
    return text


@findings_bp.app_template_filter('latex_escape')
def latex_escape_filter(text):
    return _latex_escape(text)


@findings_bp.before_request
def _check_dashboard_access():
    require_dashboard_access()


# ---------------------------------------------------------------------------
# CVSS 4.0 Calculator API
# ---------------------------------------------------------------------------

_CVSS4_REQUIRED_METRICS = {'AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'}


def _get_cvss4_class():
    try:
        from cvss import CVSS4
        return CVSS4
    except ImportError:
        return None


@findings_bp.route('/api/cvss4/calculate', methods=['GET'])
def cvss4_calculate():
    CVSS4 = _get_cvss4_class()
    if CVSS4 is None:
        return jsonify({'ok': False, 'error': 'cvss package niet beschikbaar'}), 500

    vector = request.args.get('vector', '').strip()
    if not vector:
        return jsonify({'ok': False, 'error': 'vector parameter ontbreekt'}), 400

    # Validate prefix
    if not vector.upper().startswith('CVSS:4.0/'):
        return jsonify({'ok': False, 'error': 'ongeldige CVSS 4.0 vector'}), 400

    # Check all 11 base metrics are present
    parts = vector.split('/')
    present = set()
    for part in parts[1:]:  # skip CVSS:4.0
        kv = part.split(':')
        if len(kv) == 2:
            present.add(kv[0])

    missing = _CVSS4_REQUIRED_METRICS - present
    if missing:
        return jsonify({'ok': False, 'error': 'ontbrekende metrics: ' + ', '.join(sorted(missing))}), 400

    try:
        c = CVSS4(vector)
        score = c.base_score
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 400

    # Severity mapping
    if score == 0:
        severity = 'none'
    elif score < 4.0:
        severity = 'low'
    elif score < 7.0:
        severity = 'medium'
    elif score < 9.0:
        severity = 'high'
    else:
        severity = 'critical'

    return jsonify({'ok': True, 'score': score, 'severity': severity, 'vector': vector})


# ---------------------------------------------------------------------------
# Template categories: prefix van bevtype -> leesbare naam
# ---------------------------------------------------------------------------

_TEMPLATE_CATEGORIES = {
    'web': 'Web Application', 'ad': 'Active Directory', 'windows': 'Windows',
    'network': 'Network & Recon', 'config': 'Misconfiguration', 'cwe': 'CWE Top 25',
    'cloud': 'Cloud', 'infra': 'Infrastructure', 'linux': 'Linux',
    'auth': 'Authentication', 'physical': 'Physical Security', 'mail': 'Email Security',
}


def _group_templates(templates):
    """Groepeer templates op bevtype-prefix voor de overzichtspagina."""
    groups = {}
    for t in templates:
        prefix = (t.bevtype or '').split('-')[0] if t.bevtype else 'other'
        if not prefix:
            prefix = 'other'
        groups.setdefault(prefix, []).append(t)
    order = sorted(groups.keys(), key=lambda k: (k == 'other', _TEMPLATE_CATEGORIES.get(k, k).lower()))
    return [(k, _TEMPLATE_CATEGORIES.get(k, k.title()), groups[k]) for k in order]


#basic vars — NCSC/DigiD richtlijnen (vervangt OWASP 2021)
ncsc_richtlijnen = {
    'U/TV.01': 'Toegangsvoorzieningsmiddelen',
    'U/WA.01': 'Operationeel beleid webapplicaties',
    'U/WA.02': 'Webapplicatiebeheer',
    'U/WA.03': 'Webapplicatie-invoer beperken',
    'U/WA.04': 'Webapplicatie-uitvoer beperken',
    'U/WA.05': 'Vertrouwelijkheid gegevens',
    'U/WA.06': 'Webapplicatie-informatie beperken',
    'U/WA.07': 'Webapplicatie-integratie communiceren',
    'U/WA.08': 'Webapplicatiesessie beëindigen',
    'U/WA.09': 'Webapplicatiearchitectuur',
    'U/PW.01': 'Operationeel beleid platformen',
    'U/PW.02': 'Webprotocollen garanderen',
    'U/PW.03': 'Webserver inrichten',
    'U/PW.04': 'Isolatie processen en bestanden',
    'U/PW.05': 'Toegang beheermechanismen',
    'U/PW.06': 'Platform-netwerkkoppeling filteren',
    'U/PW.07': 'Hardening platformen',
    'U/PW.08': 'Platform- en webserverarchitectuur',
    'U/NW.01': 'Operationeel beleid netwerken',
    'U/NW.02': 'Beschikbaarheid netwerken',
    'U/NW.03': 'Netwerkzonering',
    'U/NW.04': 'Protectie- en detectiefunctie',
    'U/NW.05': 'Beheer- en productieomgeving',
    'U/NW.06': 'Hardening netwerken',
    'U/NW.07': 'Netwerktoegang webapplicaties',
    'U/NW.08': 'Netwerkarchitectuur',
}

# Legacy OWASP 2021 lijst (alleen voor export backwards-compat)
owasptop10 = [
            ('A1 - Broken Access Control'),
            ('A2 - Crypthographic Failures'),
            ('A3 - Injection'),
            ('A4 - Insecure Design'),
            ('A5 - Security Misconfiguration'),
            ('A6 - Vulnerable and Outdated Components'),
            ('A7 - Identification and Authentication Failures'),
            ('A8 - Software and Data Integrity Failures'),
            ('A9 - Security Logging and Monitoring Failures'),
            ('A10 - Server Side Request Forgery')
            ]

owasptop10_2025 = [
            ('A1 - Broken Access Control'),
            ('A2 - Security Misconfiguration'),
            ('A3 - Software Supply Chain Failures'),
            ('A4 - Cryptographic Failures'),
            ('A5 - Injection'),
            ('A6 - Insecure Design'),
            ('A7 - Authentication Failures'),
            ('A8 - Software or Data Integrity Failures'),
            ('A9 - Security Logging and Alerting Failures'),
            ('A10 - Mishandling of Exceptional Conditions')
            ]

# Mapping 2025-code -> 2025-lijst index (1-based)
_OWASP_2025_NUMS = {
    'A01:2025': 1, 'A02:2025': 2, 'A03:2025': 3, 'A04:2025': 4, 'A05:2025': 5,
    'A06:2025': 6, 'A07:2025': 7, 'A08:2025': 8, 'A09:2025': 9, 'A10:2025': 10,
}
_OWASP_2025_CODES = {v: k for k, v in _OWASP_2025_NUMS.items()}


@findings_bp.app_template_filter('owaspcategorie')
def owaspcategorie(num):
    if num:
        return owasptop10[int(num)-1]
    else:
        return 'A5 - Security Misconfiguration'


@findings_bp.app_template_filter('ncsc_richtlijn')
def ncsc_richtlijn_filter(code):
    if code and code in ncsc_richtlijnen:
        return '{} - {}'.format(code, ncsc_richtlijnen[code])
    return code or ''


@findings_bp.app_template_filter('owaspcategorie_2025')
def owaspcategorie_2025(num):
    if num:
        return owasptop10_2025[int(num)-1]
    else:
        return ''

@findings_bp.app_template_filter('bevindingnums')
def bevindingnums(nums):

    reek =','.join(nums)
    return reek


@findings_bp.route('/dashboard/zet_ip/<hostip>', methods=['GET', 'POST'])
def zet_ip(hostip):
    s = _get_appdata()
    s.localhost = 'http://'+hostip
    db.session.commit()
    return '[WOOOOOOOOOOOO] http://'+hostip




# ---------------------------------------------------------------------------
# Template CRUD
# ---------------------------------------------------------------------------

@findings_bp.route('/dashboard/findings/templates/new', methods=['GET'])
def template_nieuw():
    form = BevindingTemplateForm()
    return render_template('template_page.html', form=form, title='Nieuwe template')


@findings_bp.route('/dashboard/findings/templates/edit/<int:template_id>', methods=['GET'])
def template_bewerken(template_id):
    item = db.get_or_404(db_bevindingen_templates, template_id)
    form = BevindingTemplateForm(
        id=item.id,
        titel=item.titel,
        bevtype=item.bevtype,
        ncsc=getattr(item, 'ncsc', '') or '',
        owasp_2025=getattr(item, 'owasp_2025', '') or '',
        cwe=item.cwe,
        mitre=item.mitre,
        cvss=item.cvss,
        basescore=item.basescore,
        nlbeschrijving=item.nlbeschrijving,
        enbeschrijving=item.enbeschrijving,
        nlimpact=item.nlimpact,
        enimpact=item.enimpact,
        nlaanbeveling=item.nlaanbeveling,
        enaanbeveling=item.enaanbeveling,
        referenties=item.referenties,
    )
    return render_template('template_page.html', form=form, title='Template bewerken')


@findings_bp.route('/dashboard/findings/templates/save', methods=['POST'])
def template_opslaan():
    form = BevindingTemplateForm()
    if form.validate_on_submit():
        try:
            if int(form.id.data):
                tmpl = db.session.get(db_bevindingen_templates, form.id.data)
                if not tmpl:
                    abort(404)
                tmpl.titel = form.titel.data
                tmpl.bevtype = form.bevtype.data
                tmpl.ncsc = form.ncsc.data
                tmpl.owasp_2025 = form.owasp_2025.data
                tmpl.cwe = form.cwe.data
                tmpl.mitre = form.mitre.data
                tmpl.cvss = form.cvss.data
                tmpl.basescore = form.basescore.data
                tmpl.nlbeschrijving = form.nlbeschrijving.data
                tmpl.enbeschrijving = form.enbeschrijving.data
                tmpl.nlimpact = form.nlimpact.data
                tmpl.enimpact = form.enimpact.data
                tmpl.nlaanbeveling = form.nlaanbeveling.data
                tmpl.enaanbeveling = form.enaanbeveling.data
                tmpl.referenties = form.referenties.data
                db.session.commit()
        except (ValueError, TypeError):
            tmpl = db_bevindingen_templates(
                titel=form.titel.data,
                bevtype=form.bevtype.data,
                ncsc=form.ncsc.data,
                owasp_2025=form.owasp_2025.data,
                cwe=form.cwe.data,
                mitre=form.mitre.data,
                cvss=form.cvss.data,
                basescore=form.basescore.data,
                nlbeschrijving=form.nlbeschrijving.data,
                enbeschrijving=form.enbeschrijving.data,
                nlimpact=form.nlimpact.data,
                enimpact=form.enimpact.data,
                nlaanbeveling=form.nlaanbeveling.data,
                enaanbeveling=form.enaanbeveling.data,
                referenties=form.referenties.data,
            )
            db.session.add(tmpl)
            db.session.commit()

    return redirect(url_for('findings_bp.bevindingen_overzicht'))


@findings_bp.route('/dashboard/findings/templates/delete/<int:template_id>', methods=['GET'])
def template_verwijderen(template_id):
    tmpl = db.get_or_404(db_bevindingen_templates, template_id)
    db.session.delete(tmpl)
    db.session.commit()
    return '<strong>DELETED!</strong>'


@findings_bp.route('/api/findings/templates')
def api_findings_templates():
    templates = db_bevindingen_templates.query.all()
    return jsonify({'templates': [
        {'id': t.id, 'titel': t.titel, 'bevtype': t.bevtype or '',
         'ncsc': getattr(t, 'ncsc', '') or '',
         'owasp_2025': getattr(t, 'owasp_2025', '') or ''}
        for t in templates
    ]})


@findings_bp.route('/dashboard/findings/add/<bevinding_id>', methods=['GET', 'POST'])
def bevinding_toevoegen(bevinding_id):

    form = BevindingForm(ref=bevinding_id)
    scope_targets = _get_scope_targets()
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        pagina = render_template('bevinding_toevoegen.html', form=form, scope_targets=scope_targets)
    else:
        pagina = render_template('bevinding_page.html', form=form, title='Nieuwe finding', scope_targets=scope_targets)
    return pagina


@findings_bp.route('/dashboard/findings', methods=['GET'])
@findings_bp.route('/dashboard/findings/', methods=['GET'])
def bevindingen_overzicht():
    findings = db_bevindingen.query.all()
    templates = db_bevindingen_templates.query.all()
    template_groups = _group_templates(templates)
    return render_template('findings_index.html', findings=findings, templates=templates, template_groups=template_groups)


@findings_bp.route('/dashboard/findings/edit/<bevinding_id>', methods=['GET', 'POST'])
def bevinding_bewerken(bevinding_id):

    item = db_bevindingen.query.filter_by(id=bevinding_id).first()

    form = BevindingForm(
        id=item.id, naam=item.naam, invoegen=item.invoegen, ref=item.ref,
        uitwerken=item.uitwerken, locatie=item.locatie,
        gebruikersvlag=item.gebruikersvlag, rootvlag=item.rootvlag,
        status=item.status or 'draft',
        remediation_status=getattr(item, 'remediation_status', '') or 'open',
        remediation_target_date=getattr(item, 'remediation_target_date', None),
        remediation_owner=getattr(item, 'remediation_owner', '') or '',
        affected_assets=getattr(item, 'affected_assets', '') or '',
        data_classification=getattr(item, 'data_classification', '') or '',
        business_impact=getattr(item, 'business_impact', '') or '',
        remediation_effort=getattr(item, 'remediation_effort', '') or '',
        retest_status=getattr(item, 'retest_status', '') or 'not_applicable',
        retest_date=getattr(item, 'retest_date', None),
        retest_notes=getattr(item, 'retest_notes', '') or '',
        faalmodus=getattr(item, 'faalmodus', '') or '',
        control_ref=getattr(item, 'control_ref', '') or '',
        detecteerbaarheid=getattr(item, 'detecteerbaarheid', '') or '',
        detectie_notitie=getattr(item, 'detectie_notitie', '') or '',
        kans=getattr(item, 'kans', '') or '',
        impact_niveau=getattr(item, 'impact_niveau', '') or '',
    )
    scope_targets = _get_scope_targets()
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        pagina = render_template('bevinding_toevoegen.html', form=form, scope_targets=scope_targets)
    else:
        pagina = render_template('bevinding_page.html', form=form, title='Finding bewerken', scope_targets=scope_targets)
    return pagina

@findings_bp.route('/dashboard/findings/delete/<int:bevindingen_id>', methods=['GET'])
def bevinding_verwijderen(bevindingen_id):
        verwijder = db_bevindingen.query.filter_by(id=bevindingen_id).first()
        db.session.delete(verwijder)
        db.session.commit()
        return '<strong>DELETED!</strong>'


@findings_bp.route('/dashboard/findings/save', methods=['POST'])
def bevinding_opslaan():

    form = BevindingForm()
    if form.validate_on_submit():

        try:
            if int(form.id.data):
                bev = db.session.get(db_bevindingen, form.id.data)
                bev.naam = form.naam.data
                bev.invoegen = form.invoegen.data
                bev.ref = form.ref.data
                bev.uitwerken = form.uitwerken.data
                bev.locatie = form.locatie.data
                bev.basescore =  form.basescore.data
                bev.cvss =  form.cvss.data
                bev.gebruikersvlag =  form.gebruikersvlag.data
                bev.rootvlag = form.rootvlag.data
                bev.status = form.status.data
                bev.remediation_status = form.remediation_status.data
                bev.remediation_target_date = form.remediation_target_date.data
                bev.remediation_owner = form.remediation_owner.data
                bev.affected_assets = form.affected_assets.data
                bev.data_classification = form.data_classification.data
                bev.business_impact = form.business_impact.data
                bev.remediation_effort = form.remediation_effort.data
                bev.retest_status     = form.retest_status.data
                bev.retest_date       = form.retest_date.data
                bev.retest_notes      = form.retest_notes.data
                bev.faalmodus         = form.faalmodus.data
                bev.control_ref       = form.control_ref.data
                bev.detecteerbaarheid = form.detecteerbaarheid.data
                bev.detectie_notitie  = form.detectie_notitie.data
                bev.kans              = form.kans.data
                bev.impact_niveau     = form.impact_niveau.data
                db.session.commit()
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'ok': True, 'id': bev.id})

        except:

            bevdb = db_bevindingen(
                naam=form.naam.data, invoegen=form.invoegen.data,
                ref=form.ref.data, uitwerken=form.uitwerken.data,
                locatie=form.locatie.data, gebruikersvlag=form.gebruikersvlag.data,
                rootvlag=form.rootvlag.data, basescore=form.basescore.data,
                cvss=form.cvss.data, status=form.status.data,
                remediation_status=form.remediation_status.data,
                remediation_target_date=form.remediation_target_date.data,
                remediation_owner=form.remediation_owner.data,
                affected_assets=form.affected_assets.data,
                data_classification=form.data_classification.data,
                business_impact=form.business_impact.data,
                remediation_effort=form.remediation_effort.data,
                retest_status=form.retest_status.data,
                retest_date=form.retest_date.data,
                retest_notes=form.retest_notes.data,
                faalmodus=form.faalmodus.data,
                control_ref=form.control_ref.data,
                detecteerbaarheid=form.detecteerbaarheid.data,
                detectie_notitie=form.detectie_notitie.data,
                kans=form.kans.data,
                impact_niveau=form.impact_niveau.data,
            )
            db.session.add(bevdb)
            db.session.commit()
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'ok': True, 'id': bevdb.id})

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'ok': False, 'error': 'validatie mislukt'}), 400
    return redirect(url_for('findings_bp.bevindingen_overzicht'))


_VALID_STATUSES = {'draft', 'final', 'closed'}
_VALID_RETEST_STATUSES = {'not_applicable', 'pending_retest', 'retested_fixed', 'retested_open'}


# ---------------------------------------------------------------------------
# Retest workflow
# ---------------------------------------------------------------------------

@findings_bp.route('/dashboard/findings/retest')
def retest_overzicht():
    """Overzicht van alle bevindingen die een retest nodig hebben of ondergaan hebben."""
    findings = db_bevindingen.query.filter(
        db_bevindingen.retest_status != 'not_applicable'
    ).order_by(db_bevindingen.retest_status, db_bevindingen.id).all()
    return render_template('retest_overzicht.html', findings=findings)


@findings_bp.route('/api/findings/<int:finding_id>/retest', methods=['POST'])
def finding_retest_update(finding_id):
    bev = db.session.get(db_bevindingen, finding_id)
    if not bev:
        return jsonify({'ok': False, 'error': 'niet gevonden'}), 404
    data = request.get_json(force=True) or {}
    new_status = data.get('retest_status', '')
    if new_status and new_status not in _VALID_RETEST_STATUSES:
        return jsonify({'ok': False, 'error': 'ongeldige retest status'}), 400
    if new_status:
        bev.retest_status = new_status
    if 'retest_notes' in data:
        bev.retest_notes = str(data['retest_notes'])[:5000]
    if 'retest_date' in data and data['retest_date']:
        try:
            bev.retest_date = datetime.date.fromisoformat(str(data['retest_date']))
        except (ValueError, TypeError):
            pass
    db.session.commit()
    return jsonify({'ok': True, 'id': bev.id, 'retest_status': bev.retest_status})


# ---------------------------------------------------------------------------
# Risicomatrix
# ---------------------------------------------------------------------------

def _score_to_kans_impact(basescore):
    """Leid kans/impact af uit CVSS basescore als niet handmatig ingesteld."""
    try:
        score = float(basescore)
    except (TypeError, ValueError):
        return 3, 3
    if score >= 9.0:
        return 5, 5
    elif score >= 7.0:
        return 4, 4
    elif score >= 4.0:
        return 3, 3
    elif score > 0:
        return 2, 2
    return 1, 1


@findings_bp.route('/api/findings/risicomatrix')
def api_risicomatrix():
    findings = db_bevindingen.query.all()
    matrix = {}
    items = []
    for f in findings:
        kans = int(f.kans) if getattr(f, 'kans', '') and f.kans.isdigit() else None
        impact = int(f.impact_niveau) if getattr(f, 'impact_niveau', '') and f.impact_niveau.isdigit() else None
        if kans is None or impact is None:
            k, i = _score_to_kans_impact(f.basescore)
            kans = kans or k
            impact = impact or i
        cell = f'{kans}-{impact}'
        matrix.setdefault(cell, []).append(f.id)
        items.append({
            'id':        f.id,
            'naam':      f.naam or '',
            'kans':      kans,
            'impact':    impact,
            'basescore': f.basescore or '',
            'status':    f.status or '',
            'retest_status': getattr(f, 'retest_status', '') or '',
        })
    return jsonify({'items': items, 'matrix': matrix})


@findings_bp.route('/api/findings/<int:finding_id>/status', methods=['POST'])
def finding_status_update(finding_id):
    require_dashboard_access()
    bev = db.session.get(db_bevindingen, finding_id)
    if not bev:
        return jsonify({'ok': False, 'error': 'not found'}), 404
    data = request.get_json(force=True)
    new_status = data.get('status', '')
    if new_status not in _VALID_STATUSES:
        return jsonify({'ok': False, 'error': 'ongeldige status'}), 400
    bev.status = new_status
    db.session.commit()
    return jsonify({'ok': True, 'id': bev.id, 'status': bev.status})


# ---------------------------------------------------------------------------
# Evidence directory
# ---------------------------------------------------------------------------

_EVIDENCE_DIR = os.path.join(os.path.dirname(__file__), 'db', 'evidence')

_ALLOWED_EVIDENCE_TYPES = {
    'image/png', 'image/jpeg', 'image/gif', 'image/webp',
    'application/pdf', 'text/plain', 'text/html', 'text/csv',
    'application/json', 'application/xml',
    'application/zip', 'application/octet-stream',
}

_MAX_EVIDENCE_SIZE = 10 * 1024 * 1024  # 10 MB


def _evidence_path(finding_id):
    path = os.path.join(_EVIDENCE_DIR, str(finding_id))
    os.makedirs(path, exist_ok=True)
    return path


# ---------------------------------------------------------------------------
# OWASP nummer <-> code mapping
# ---------------------------------------------------------------------------

_OWASP_CODES = {
    1: 'A01', 2: 'A02', 3: 'A03', 4: 'A04', 5: 'A05',
    6: 'A06', 7: 'A07', 8: 'A08', 9: 'A09', 10: 'A10',
}
_OWASP_NUMS = {v: k for k, v in _OWASP_CODES.items()}


# ---------------------------------------------------------------------------
# Export: GET /api/findings/export
# ---------------------------------------------------------------------------

@findings_bp.route('/api/findings/export', methods=['GET'])
def export_findings():
    bevindingen = db_bevindingen.query.all()
    templates = db_bevindingen_templates.query.all()
    template_map = {str(t.id): t for t in templates}

    catalogs = {
        'ref_owasp_top10': [],
        'ref_ncsc': [],
        'ref_cwe': [],
        'ref_mitre_attack': [],
        'standard_findings': [],
    }

    seen_owasp = set()
    seen_ncsc = set()
    seen_cwe = set()
    seen_mitre = set()

    # Standard findings uit templates
    for t in templates:
        sf = {
            'code': str(t.id),
            'title': t.titel or '',
            'description': t.enbeschrijving or t.nlbeschrijving or '',
            'evidence': '',
            'recommendation': t.enaanbeveling or t.nlaanbeveling or '',
            'cvss_v4_vector': t.cvss or None,
            'cvss_v4_score': float(t.basescore) if t.basescore else None,
            'references': [],
            'owasp_top10': [],
            'ncsc': [],
            'cwe': [],
            'mitre_attack': [],
        }
        ncsc_code = getattr(t, 'ncsc', '') or ''
        if ncsc_code and ncsc_code in ncsc_richtlijnen:
            sf['ncsc'].append({'code': ncsc_code, 'title': ncsc_richtlijnen[ncsc_code]})
            if ncsc_code not in seen_ncsc:
                seen_ncsc.add(ncsc_code)
                catalogs['ref_ncsc'].append({
                    'code': ncsc_code, 'title': ncsc_richtlijnen[ncsc_code],
                })
        if t.owasp:
            try:
                num = int(t.owasp)
                code = _OWASP_CODES.get(num, 'A{:02d}'.format(num))
                sf['owasp_top10'].append({'year': 2021, 'code': code})
                owasp_key = code + ':2021'
                if owasp_key not in seen_owasp:
                    seen_owasp.add(owasp_key)
                    catalogs['ref_owasp_top10'].append({
                        'year': 2021, 'code': code,
                        'title': owasptop10[num - 1] if 1 <= num <= 10 else code,
                        'description': '',
                    })
            except (ValueError, TypeError):
                pass
        if getattr(t, 'owasp_2025', None):
            try:
                num_25 = int(t.owasp_2025)
                code_25 = _OWASP_2025_CODES.get(num_25, 'A{:02d}:2025'.format(num_25))
                sf['owasp_top10'].append({'year': 2025, 'code': code_25})
                if code_25 not in seen_owasp:
                    seen_owasp.add(code_25)
                    catalogs['ref_owasp_top10'].append({
                        'year': 2025, 'code': code_25,
                        'title': owasptop10_2025[num_25 - 1] if 1 <= num_25 <= 10 else code_25,
                        'description': '',
                    })
            except (ValueError, TypeError):
                pass
        if t.cwe:
            try:
                cwe_id = int(t.cwe)
                sf['cwe'].append({'cwe_id': cwe_id})
                if cwe_id not in seen_cwe:
                    seen_cwe.add(cwe_id)
                    catalogs['ref_cwe'].append({
                        'cwe_id': cwe_id, 'name': '', 'description': '',
                    })
            except (ValueError, TypeError):
                pass
        if t.mitre:
            tid = t.mitre.strip()
            if tid:
                sf['mitre_attack'].append({'technique_id': tid})
                if tid not in seen_mitre:
                    seen_mitre.add(tid)
                    catalogs['ref_mitre_attack'].append({
                        'technique_id': tid, 'name': '', 'description': '',
                    })
        if t.referenties:
            for line in t.referenties.strip().splitlines():
                line = line.strip()
                if line:
                    sf['references'].append({'title': line, 'url': line if line.startswith('http') else None})
        catalogs['standard_findings'].append(sf)

    # Project findings
    project_findings = []
    for bev in bevindingen:
        tmpl = template_map.get(str(bev.ref))
        pf = {
            'title': bev.naam or '',
            'description': tmpl.enbeschrijving or tmpl.nlbeschrijving or '' if tmpl else '',
            'impact': tmpl.enimpact or tmpl.nlimpact or '' if tmpl else '',
            'evidence': bev.uitwerken or '',
            'recommendation': tmpl.enaanbeveling or tmpl.nlaanbeveling or '' if tmpl else '',
            'cvss_v4_vector': bev.cvss or (tmpl.cvss if tmpl else None),
            'cvss_v4_score': float(bev.basescore) if bev.basescore else (float(tmpl.basescore) if tmpl and tmpl.basescore else None),
            'urgency': 'unknown',
            'status': bev.status or 'draft',
            'standard_code': str(bev.ref) if bev.ref else None,
            'owasp_top10': [],
            'ncsc': [],
            'cwe': [],
            'mitre_attack': [],
            'references': [],
        }
        if tmpl:
            tmpl_ncsc = getattr(tmpl, 'ncsc', '') or ''
            if tmpl_ncsc and tmpl_ncsc in ncsc_richtlijnen:
                pf['ncsc'].append({'code': tmpl_ncsc, 'title': ncsc_richtlijnen[tmpl_ncsc]})
            if tmpl.owasp:
                try:
                    num = int(tmpl.owasp)
                    pf['owasp_top10'].append({'year': 2021, 'code': _OWASP_CODES.get(num, 'A{:02d}'.format(num))})
                except (ValueError, TypeError):
                    pass
            if getattr(tmpl, 'owasp_2025', None):
                try:
                    num_25 = int(tmpl.owasp_2025)
                    pf['owasp_top10'].append({'year': 2025, 'code': _OWASP_2025_CODES.get(num_25, 'A{:02d}:2025'.format(num_25))})
                except (ValueError, TypeError):
                    pass
            if tmpl.cwe:
                try:
                    pf['cwe'].append({'cwe_id': int(tmpl.cwe)})
                except (ValueError, TypeError):
                    pass
            if tmpl.mitre:
                tid = tmpl.mitre.strip()
                if tid:
                    pf['mitre_attack'].append({'technique_id': tid})
        if bev.locatie:
            pf['location'] = bev.locatie
        if bev.gebruikersvlag:
            pf['user_flag'] = bev.gebruikersvlag
        if bev.rootvlag:
            pf['root_flag'] = bev.rootvlag
        project_findings.append(pf)

    payload = {
        'schema_version': '1.0',
        'exported_at': datetime.datetime.utcnow().isoformat() + 'Z',
        'project': {'name': 'Incompetent Bastard', 'description': ''},
        'catalogs': catalogs,
        'project_findings': project_findings,
    }
    return jsonify(payload)


# ---------------------------------------------------------------------------
# Import: POST /api/findings/import
# ---------------------------------------------------------------------------

@findings_bp.route('/api/findings/import', methods=['POST'])
def import_findings():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'geen JSON body'}), 400

    if 'project_findings' not in data:
        return jsonify({'error': 'project_findings ontbreekt'}), 400

    created = 0
    for pf in data['project_findings']:
        title = (pf.get('title') or '').strip()
        if not title:
            continue

        # Zoek of maak template op basis van standard_code
        template_id = None
        standard_code = pf.get('standard_code')
        if standard_code:
            tmpl = db_bevindingen_templates.query.filter_by(id=int(standard_code)).first() if standard_code.isdigit() else None
            if tmpl:
                template_id = str(tmpl.id)

        # Als geen template via standard_code, probeer te matchen of creeer
        if not template_id and data.get('catalogs', {}).get('standard_findings'):
            for sf in data['catalogs']['standard_findings']:
                if sf.get('code') == standard_code:
                    existing = db_bevindingen_templates.query.filter_by(titel=sf.get('title', '')).first()
                    if existing:
                        template_id = str(existing.id)
                    else:
                        new_tmpl = _create_template_from_standard(sf)
                        db.session.add(new_tmpl)
                        db.session.flush()
                        template_id = str(new_tmpl.id)
                    break

        # CVSS
        cvss_vector = pf.get('cvss_v4_vector', '')
        cvss_score = ''
        if pf.get('cvss_v4_score') is not None:
            cvss_score = str(pf['cvss_v4_score'])

        bev = db_bevindingen(
            naam=title,
            invoegen=pf.get('description', ''),
            ref=template_id or '',
            uitwerken=pf.get('evidence', ''),
            locatie=pf.get('location', ''),
            basescore=cvss_score,
            cvss=cvss_vector,
            gebruikersvlag=pf.get('user_flag', ''),
            rootvlag=pf.get('root_flag', ''),
            status=pf.get('status', 'draft'),
        )
        db.session.add(bev)
        created += 1

    db.session.commit()
    return jsonify({'ok': True, 'created_findings': created})


# ---------------------------------------------------------------------------
# Evidence: upload, list, download, delete
# ---------------------------------------------------------------------------

@findings_bp.route('/api/findings/<int:finding_id>/evidence', methods=['GET'])
def list_evidence(finding_id):
    bev = db.session.get(db_bevindingen, finding_id)
    if not bev:
        return jsonify({'error': 'bevinding niet gevonden'}), 404
    items = db_evidence.query.filter_by(finding_id=finding_id).all()
    return jsonify({'evidence': [
        {
            'id': e.id,
            'filename': e.filename,
            'original_filename': e.original_filename,
            'content_type': e.content_type,
            'created_at': e.created_at.isoformat() + 'Z' if e.created_at else None,
        } for e in items
    ]})


@findings_bp.route('/api/findings/<int:finding_id>/evidence', methods=['POST'])
def upload_evidence(finding_id):
    bev = db.session.get(db_bevindingen, finding_id)
    if not bev:
        return jsonify({'error': 'bevinding niet gevonden'}), 404

    if 'file' not in request.files:
        return jsonify({'error': 'geen bestand meegegeven'}), 400

    f = request.files['file']
    if not f.filename:
        return jsonify({'error': 'geen bestandsnaam'}), 400

    content_type = f.content_type or 'application/octet-stream'

    original = secure_filename(f.filename)
    ext = os.path.splitext(original)[1] if original else ''
    stored_name = uuid.uuid4().hex + ext

    dest_dir = _evidence_path(finding_id)
    f.save(os.path.join(dest_dir, stored_name))

    ev = db_evidence(
        finding_id=finding_id,
        filename=stored_name,
        original_filename=original,
        content_type=content_type,
    )
    db.session.add(ev)
    db.session.commit()

    return jsonify({
        'ok': True,
        'id': ev.id,
        'filename': stored_name,
        'original_filename': original,
    })


@findings_bp.route('/api/findings/evidence/<int:evidence_id>/download', methods=['GET'])
def download_evidence(evidence_id):
    ev = db.session.get(db_evidence, evidence_id)
    if not ev:
        return jsonify({'error': 'evidence niet gevonden'}), 404
    path = _evidence_path(ev.finding_id)
    return send_from_directory(path, ev.filename, as_attachment=True,
                               download_name=ev.original_filename or ev.filename)


@findings_bp.route('/api/findings/evidence/<int:evidence_id>', methods=['DELETE'])
def delete_evidence(evidence_id):
    ev = db.session.get(db_evidence, evidence_id)
    if not ev:
        return jsonify({'error': 'evidence niet gevonden'}), 404
    filepath = os.path.join(_evidence_path(ev.finding_id), ev.filename)
    if os.path.exists(filepath):
        os.remove(filepath)
    db.session.delete(ev)
    db.session.commit()
    return jsonify({'ok': True})


# ---------------------------------------------------------------------------
# Evidence: export all as ZIP
# ---------------------------------------------------------------------------

@findings_bp.route('/api/findings/evidence/export', methods=['GET'])
def export_evidence_zip():
    import zipfile
    import io as _io

    buf = _io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        all_ev = db_evidence.query.all()
        for ev in all_ev:
            src = os.path.join(_evidence_path(ev.finding_id), ev.filename)
            if os.path.exists(src):
                arcname = '{}/{}'.format(ev.finding_id, ev.original_filename or ev.filename)
                zf.write(src, arcname)

    buf.seek(0)
    return Response(
        buf.getvalue(),
        mimetype='application/zip',
        headers={'Content-Disposition': 'attachment; filename=evidence_export.zip'},
    )


# ---------------------------------------------------------------------------
# Import: file upload form (POST with multipart)
# ---------------------------------------------------------------------------

@findings_bp.route('/dashboard/findings/import', methods=['POST'])
def import_findings_upload():
    if 'file' not in request.files:
        flash('Geen bestand geselecteerd', 'danger')
        return redirect(url_for('findings_bp.bevindingen_overzicht'))

    f = request.files['file']
    if not f.filename:
        flash('Geen bestand geselecteerd', 'danger')
        return redirect(url_for('findings_bp.bevindingen_overzicht'))

    try:
        data = json.loads(f.read().decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError):
        flash('Ongeldig JSON bestand', 'danger')
        return redirect(url_for('findings_bp.bevindingen_overzicht'))

    if 'project_findings' not in data:
        flash('project_findings ontbreekt in JSON', 'danger')
        return redirect(url_for('findings_bp.bevindingen_overzicht'))

    created = 0
    for pf in data['project_findings']:
        title = (pf.get('title') or '').strip()
        if not title:
            continue

        template_id = None
        standard_code = pf.get('standard_code')
        if standard_code:
            tmpl = db_bevindingen_templates.query.filter_by(id=int(standard_code)).first() if str(standard_code).isdigit() else None
            if tmpl:
                template_id = str(tmpl.id)

        if not template_id and data.get('catalogs', {}).get('standard_findings'):
            for sf in data['catalogs']['standard_findings']:
                if sf.get('code') == standard_code:
                    existing = db_bevindingen_templates.query.filter_by(titel=sf.get('title', '')).first()
                    if existing:
                        template_id = str(existing.id)
                    else:
                        new_tmpl = _create_template_from_standard(sf)
                        db.session.add(new_tmpl)
                        db.session.flush()
                        template_id = str(new_tmpl.id)
                    break

        cvss_vector = pf.get('cvss_v4_vector', '')
        cvss_score = str(pf['cvss_v4_score']) if pf.get('cvss_v4_score') is not None else ''

        bev = db_bevindingen(
            naam=title,
            invoegen=pf.get('description', ''),
            ref=template_id or '',
            uitwerken=pf.get('evidence', ''),
            locatie=pf.get('location', ''),
            basescore=cvss_score,
            cvss=cvss_vector,
            gebruikersvlag=pf.get('user_flag', ''),
            rootvlag=pf.get('root_flag', ''),
            status=pf.get('status', 'draft'),
        )
        db.session.add(bev)
        created += 1

    db.session.commit()
    flash('{} findings geimporteerd'.format(created), 'success')
    return redirect(url_for('findings_bp.bevindingen_overzicht'))


# ---------------------------------------------------------------------------
# Seed: overwrite templates with standard findings from hacksec-patched
# ---------------------------------------------------------------------------

_STANDARD_FINDINGS_PATH = os.path.join(os.path.dirname(__file__), 'db', 'standard_findings.json')


def _create_template_from_standard(sf):
    """Create a db_bevindingen_templates from a standard finding dict."""
    tmpl = db_bevindingen_templates(
        titel=sf.get('title', ''),
        bevtype=sf.get('code', ''),
        nlbeschrijving=sf.get('description', ''),
        nlimpact=sf.get('impact', ''),
        nlaanbeveling=sf.get('recommendation', ''),
        enbeschrijving=sf.get('en_description', ''),
        enimpact=sf.get('en_impact', ''),
        enaanbeveling=sf.get('en_recommendation', ''),
        cvss=sf.get('cvss_v4_vector') or '',
        basescore=str(sf['cvss_v4_score']) if sf.get('cvss_v4_score') is not None else '',
    )
    # OWASP (2021 + 2025)
    owasp_items = sf.get('owasp_top10', [])
    for oi in owasp_items:
        code = oi.get('code', '')
        year = oi.get('year')
        if year == 2025 or ':2025' in code:
            num_2025 = _OWASP_2025_NUMS.get(code)
            if num_2025 and not tmpl.owasp_2025:
                tmpl.owasp_2025 = str(num_2025)
        else:
            # 2021 of ongespecificeerd jaar
            bare_code = code.split(':')[0]
            num = _OWASP_NUMS.get(bare_code)
            if num and not tmpl.owasp:
                tmpl.owasp = str(num)
    # NCSC/DigiD
    ncsc_items = sf.get('ncsc', [])
    if ncsc_items:
        ncsc_code = ncsc_items[0].get('code', '')
        if ncsc_code in ncsc_richtlijnen:
            tmpl.ncsc = ncsc_code
    elif sf.get('ncsc_code'):
        tmpl.ncsc = sf['ncsc_code']
    # CWE
    cwe_items = sf.get('cwe', [])
    if cwe_items:
        tmpl.cwe = str(cwe_items[0].get('cwe_id', ''))
    # MITRE
    mitre_items = sf.get('mitre_attack', [])
    if mitre_items:
        tmpl.mitre = mitre_items[0].get('technique_id', '')
    # Referenties
    refs = sf.get('references', [])
    if refs:
        tmpl.referenties = '\n'.join(
            r.get('url') or r.get('title', '') for r in refs
        )
    return tmpl


@findings_bp.route('/dashboard/findings/templates/seed', methods=['POST'])
def seed_standard_findings():
    if not os.path.exists(_STANDARD_FINDINGS_PATH):
        flash('Standard findings bestand niet gevonden', 'danger')
        return redirect(url_for('findings_bp.bevindingen_overzicht'))

    with open(_STANDARD_FINDINGS_PATH, 'r', encoding='utf-8') as f:
        data = json.load(f)

    standard_findings = data.get('catalogs', {}).get('standard_findings', [])
    if not standard_findings:
        flash('Geen standard findings gevonden in bestand', 'danger')
        return redirect(url_for('findings_bp.bevindingen_overzicht'))

    # Verwijder bestaande templates
    db_bevindingen_templates.query.delete()
    db.session.flush()

    created = 0
    for sf in standard_findings:
        title = (sf.get('title') or '').strip()
        if not title:
            continue
        tmpl = _create_template_from_standard(sf)
        db.session.add(tmpl)
        created += 1

    db.session.commit()
    flash('{} standaard bevindingen geladen (templates overschreven)'.format(created), 'success')
    return redirect(url_for('findings_bp.bevindingen_overzicht'))


# ---------------------------------------------------------------------------
# Audit trail helper
# ---------------------------------------------------------------------------

def _log_change(table, record_id, field, old, new):
    entry = db_changelog(
        table_name=table,
        record_id=record_id,
        field_name=field,
        old_value=str(old) if old is not None else None,
        new_value=str(new) if new is not None else None,
    )
    db.session.add(entry)


# ---------------------------------------------------------------------------
# Batch actions: POST /api/findings/batch-action
# ---------------------------------------------------------------------------

_VALID_REMEDIATION_STATUSES = {'open', 'in_progress', 'fixed', 'verified', 'accepted'}


@findings_bp.route('/api/findings/batch-action', methods=['POST'])
def batch_action():
    data = request.get_json(force=True)
    ids = data.get('ids', [])
    action = data.get('action', '')
    value = data.get('value', '')

    if not ids or not isinstance(ids, list):
        return jsonify({'ok': False, 'error': 'ids vereist'}), 400

    affected = 0

    if action == 'set_status':
        if value not in _VALID_STATUSES:
            return jsonify({'ok': False, 'error': 'ongeldige status'}), 400
        for fid in ids:
            bev = db.session.get(db_bevindingen, fid)
            if bev:
                old = bev.status
                bev.status = value
                _log_change('db_bevinding', fid, 'status', old, value)
                affected += 1

    elif action == 'set_remediation':
        if value not in _VALID_REMEDIATION_STATUSES:
            return jsonify({'ok': False, 'error': 'ongeldige remediation status'}), 400
        for fid in ids:
            bev = db.session.get(db_bevindingen, fid)
            if bev:
                old = bev.remediation_status
                bev.remediation_status = value
                _log_change('db_bevinding', fid, 'remediation_status', old, value)
                affected += 1

    elif action == 'delete':
        for fid in ids:
            bev = db.session.get(db_bevindingen, fid)
            if bev:
                db.session.delete(bev)
                affected += 1

    else:
        return jsonify({'ok': False, 'error': 'onbekende actie'}), 400

    db.session.commit()
    return jsonify({'ok': True, 'affected': affected})


# ---------------------------------------------------------------------------
# Search / filter: GET /api/findings
# ---------------------------------------------------------------------------

@findings_bp.route('/api/findings', methods=['GET'])
def api_findings_list():
    q = db_bevindingen.query

    severity = request.args.get('severity', '').strip()
    status = request.args.get('status', '').strip()
    ncsc_filter = request.args.get('ncsc', '').strip()
    remediation = request.args.get('remediation', '').strip()
    search = request.args.get('q', '').strip()

    if status and status in _VALID_STATUSES:
        q = q.filter(db_bevindingen.status == status)
    if remediation and remediation in _VALID_REMEDIATION_STATUSES:
        q = q.filter(db_bevindingen.remediation_status == remediation)

    results = q.all()
    templates = db_bevindingen_templates.query.all()
    tmpl_map = {str(t.id): t for t in templates}

    items = []
    for bev in results:
        tmpl = tmpl_map.get(str(bev.ref))
        bs = bev.basescore or (tmpl.basescore if tmpl else '') or '0'
        sev, sort_key = _cvss_to_severity(bs)

        if severity and sev != severity:
            continue

        ncsc_code = getattr(tmpl, 'ncsc', '') if tmpl else ''
        if ncsc_filter and ncsc_code != ncsc_filter:
            continue

        title = bev.naam or ''
        loc = bev.locatie or ''
        if search and search.lower() not in title.lower() and search.lower() not in loc.lower():
            continue

        items.append({
            'id': bev.id,
            'naam': title,
            'locatie': loc,
            'basescore': bs,
            'severity': sev,
            'status': bev.status or 'draft',
            'remediation_status': bev.remediation_status or 'open',
            'remediation_owner': bev.remediation_owner or '',
            'remediation_target_date': str(bev.remediation_target_date) if bev.remediation_target_date else '',
            'remediation_effort': bev.remediation_effort or '',
            'ncsc': '{} - {}'.format(ncsc_code, ncsc_richtlijnen[ncsc_code]) if ncsc_code and ncsc_code in ncsc_richtlijnen else '',
            'ref': bev.ref or '',
            'sort_key': sort_key,
        })

    items.sort(key=lambda f: (f['sort_key'], f['id']))
    return jsonify({'findings': items})


# ---------------------------------------------------------------------------
# Remediation update: POST /api/findings/<id>/remediation
# ---------------------------------------------------------------------------

@findings_bp.route('/api/findings/<int:finding_id>/remediation', methods=['POST'])
def finding_remediation_update(finding_id):
    bev = db.session.get(db_bevindingen, finding_id)
    if not bev:
        return jsonify({'ok': False, 'error': 'not found'}), 404
    data = request.get_json(force=True)

    if 'status' in data:
        new_status = data['status']
        if new_status not in _VALID_REMEDIATION_STATUSES:
            return jsonify({'ok': False, 'error': 'ongeldige remediation status'}), 400
        old = bev.remediation_status
        bev.remediation_status = new_status
        _log_change('db_bevinding', finding_id, 'remediation_status', old, new_status)

    if 'target_date' in data:
        old = str(bev.remediation_target_date) if bev.remediation_target_date else ''
        if data['target_date']:
            try:
                bev.remediation_target_date = datetime.date.fromisoformat(data['target_date'])
            except (ValueError, TypeError):
                return jsonify({'ok': False, 'error': 'ongeldige datum'}), 400
        else:
            bev.remediation_target_date = None
        _log_change('db_bevinding', finding_id, 'remediation_target_date', old, data['target_date'])

    if 'owner' in data:
        old = bev.remediation_owner
        bev.remediation_owner = str(data['owner'])[:200]
        _log_change('db_bevinding', finding_id, 'remediation_owner', old, bev.remediation_owner)

    db.session.commit()
    return jsonify({
        'ok': True, 'id': bev.id,
        'remediation_status': bev.remediation_status,
        'remediation_target_date': str(bev.remediation_target_date) if bev.remediation_target_date else '',
        'remediation_owner': bev.remediation_owner or '',
    })


# ---------------------------------------------------------------------------
# Finding relations
# ---------------------------------------------------------------------------

@findings_bp.route('/api/findings/<int:finding_id>/relations', methods=['GET'])
def finding_relations_list(finding_id):
    bev = db.session.get(db_bevindingen, finding_id)
    if not bev:
        return jsonify({'ok': False, 'error': 'not found'}), 404
    rels_from = db_finding_related.query.filter_by(finding_id=finding_id).all()
    rels_to = db_finding_related.query.filter_by(related_id=finding_id).all()
    items = []
    for r in rels_from:
        rel_bev = db.session.get(db_bevindingen, r.related_id)
        items.append({
            'relation_id': r.id,
            'finding_id': r.related_id,
            'finding_naam': rel_bev.naam if rel_bev else '',
            'relation_type': r.relation_type,
            'direction': 'outgoing',
        })
    for r in rels_to:
        rel_bev = db.session.get(db_bevindingen, r.finding_id)
        items.append({
            'relation_id': r.id,
            'finding_id': r.finding_id,
            'finding_naam': rel_bev.naam if rel_bev else '',
            'relation_type': r.relation_type,
            'direction': 'incoming',
        })
    return jsonify({'relations': items})


@findings_bp.route('/api/findings/<int:finding_id>/relations', methods=['POST'])
def finding_relations_add(finding_id):
    bev = db.session.get(db_bevindingen, finding_id)
    if not bev:
        return jsonify({'ok': False, 'error': 'not found'}), 404
    data = request.get_json(force=True)
    related_id = data.get('related_id')
    relation_type = data.get('relation_type', 'related')
    if not related_id:
        return jsonify({'ok': False, 'error': 'related_id vereist'}), 400
    if relation_type not in ('chain', 'duplicate', 'related'):
        return jsonify({'ok': False, 'error': 'ongeldig relation_type'}), 400
    related_bev = db.session.get(db_bevindingen, related_id)
    if not related_bev:
        return jsonify({'ok': False, 'error': 'gerelateerde finding niet gevonden'}), 404
    if related_id == finding_id:
        return jsonify({'ok': False, 'error': 'kan niet aan zichzelf koppelen'}), 400
    existing = db_finding_related.query.filter_by(
        finding_id=finding_id, related_id=related_id).first()
    if existing:
        return jsonify({'ok': False, 'error': 'relatie bestaat al'}), 409
    rel = db_finding_related(finding_id=finding_id, related_id=related_id, relation_type=relation_type)
    db.session.add(rel)
    db.session.commit()
    return jsonify({'ok': True, 'id': rel.id})


@findings_bp.route('/api/findings/relations/<int:relation_id>', methods=['DELETE'])
def finding_relations_delete(relation_id):
    rel = db.session.get(db_finding_related, relation_id)
    if not rel:
        return jsonify({'ok': False, 'error': 'not found'}), 404
    db.session.delete(rel)
    db.session.commit()
    return jsonify({'ok': True})


# ---------------------------------------------------------------------------
# Changelog: GET /api/changelog
# ---------------------------------------------------------------------------

@findings_bp.route('/api/changelog', methods=['GET'])
def api_changelog():
    q = db_changelog.query
    table = request.args.get('table', '').strip()
    record_id = request.args.get('record_id', '').strip()
    if table:
        q = q.filter(db_changelog.table_name == table)
    if record_id and record_id.isdigit():
        q = q.filter(db_changelog.record_id == int(record_id))
    entries = q.order_by(db_changelog.changed_at.desc()).limit(200).all()
    return jsonify({'entries': [
        {
            'id': e.id,
            'table_name': e.table_name,
            'record_id': e.record_id,
            'field_name': e.field_name,
            'old_value': e.old_value,
            'new_value': e.new_value,
            'changed_by': e.changed_by,
            'changed_at': e.changed_at.isoformat() + 'Z' if e.changed_at else None,
        } for e in entries
    ]})


# ---------------------------------------------------------------------------
# CSV export: GET /api/findings/export/csv
# ---------------------------------------------------------------------------

@findings_bp.route('/api/findings/export/csv', methods=['GET'])
def export_findings_csv():
    import csv
    import io as _io

    bevindingen = db_bevindingen.query.all()
    templates = db_bevindingen_templates.query.all()
    tmpl_map = {str(t.id): t for t in templates}

    buf = _io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        'ID', 'Name', 'Host', 'CVSS', 'Severity', 'Status',
        'Remediation Status', 'Remediation Owner', 'Remediation Target Date',
        'NCSC', 'CWE', 'Template',
    ])
    for bev in bevindingen:
        tmpl = tmpl_map.get(str(bev.ref))
        bs = bev.basescore or (tmpl.basescore if tmpl else '') or '0'
        sev, _ = _cvss_to_severity(bs)
        ncsc_code = getattr(tmpl, 'ncsc', '') if tmpl else ''
        ncsc_label = '{} - {}'.format(ncsc_code, ncsc_richtlijnen[ncsc_code]) if ncsc_code and ncsc_code in ncsc_richtlijnen else ''
        cwe = tmpl.cwe if tmpl else ''
        writer.writerow([
            bev.id, bev.naam or '', bev.locatie or '', bs, sev,
            bev.status or 'draft',
            bev.remediation_status or 'open',
            bev.remediation_owner or '',
            str(bev.remediation_target_date) if bev.remediation_target_date else '',
            ncsc_label, cwe, tmpl.titel if tmpl else '',
        ])

    return Response(
        buf.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=findings_export.csv'},
    )


# ---------------------------------------------------------------------------
# Remediation history: GET /api/findings/<id>/remediation/history
# ---------------------------------------------------------------------------

@findings_bp.route('/api/findings/<int:finding_id>/remediation/history', methods=['GET'])
def finding_remediation_history(finding_id):
    bev = db.session.get(db_bevindingen, finding_id)
    if not bev:
        return jsonify({'ok': False, 'error': 'not found'}), 404
    entries = db_changelog.query.filter(
        db_changelog.table_name == 'db_bevinding',
        db_changelog.record_id == finding_id,
        db_changelog.field_name.in_(['remediation_status', 'remediation_target_date', 'remediation_owner']),
    ).order_by(db_changelog.changed_at.desc()).all()
    return jsonify({'history': [
        {
            'field': e.field_name,
            'old_value': e.old_value,
            'new_value': e.new_value,
            'changed_by': e.changed_by,
            'changed_at': e.changed_at.isoformat() + 'Z' if e.changed_at else None,
        } for e in entries
    ]})
