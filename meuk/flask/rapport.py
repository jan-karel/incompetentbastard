"""Rapport generatie blueprint — afgesplitst van findings.py."""

from meuk.hacksec import lezen, schrijven
from flask import Blueprint, request, send_file, jsonify, render_template, Response
from jinja2 import Environment, FileSystemLoader, StrictUndefined
from jinja2 import TemplateError, TemplateSyntaxError, UndefinedError
from markupsafe import escape as html_escape
from meuk.flask.models import db_bevindingen, db_bevindingen_templates, db_evidence, db_notes, db, db_finding_related, db_instellingen, db_checklist, db_rapport_template, db_opdracht_config, db_asset, db_asset_anchor
from meuk.flask.findings import (_cvss_to_severity, _latex_escape, _latex_markup,
                                  _html_markup, _md_markup, _plain_markup,
                                  owasptop10, _get_appdata, redact_mode,
                                  redact_enabled)
from meuk.flask.security import require_dashboard_access
import datetime
import difflib
import hashlib
import html as html_mod
import json
import math
import os
import re as _re
import shutil
import subprocess
import threading
import uuid as _uuid

rapport_bp = Blueprint('rapport_bp', __name__,
                       template_folder='html',
                       static_folder='static')


# Async generatie state
_async_runs = {}
_async_lock = threading.Lock()


@rapport_bp.before_request
def _check_dashboard_access():
    require_dashboard_access()


# ---------------------------------------------------------------------------
# Rapport generation — LaTeX-native pipeline
# ---------------------------------------------------------------------------

_RAPPORT_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'rapport')
_HANDBOEK_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'handboek')
# LaTeX-layout van de Flask-app zelf: bevat rapport_latex.tex, de uploadbare
# templates en opmaak/packages/rapport.sty (projectmacro's/kaders/lakken).
# Staat in TEXINPUTS zodat \usepackage{opmaak/packages/rapport} hier resolvet.
_LAYOUT_DIR = os.path.join(os.path.dirname(__file__), 'html')
_EVIDENCE_SRC = os.path.join(os.path.dirname(__file__), 'db', 'evidence')
# Pandoc-referentiedocument voor DOCX: rijksblauwe tabelkoppen + gekleurde
# koppen, zodat de Word-uitvoer dichter bij de PDF ligt.
_DOCX_REFERENCE = os.path.join(os.path.dirname(__file__), 'html', 'rapport_reference.docx')
# sRGB-ICC-profiel voor de PDF/A-archiefconversie (ghostscript).
_SRGB_ICC = os.path.join(os.path.dirname(__file__), 'html', 'srgb.icc')
# Projectafbeeldingen (\plaatje{..}); gelakte kopieën in de lakken/-submap.
_SCREENSHOT_SRC = os.path.join(os.path.dirname(__file__), '..', '..',
                               'raw', 'screenshots')

_SEVERITY_LABELS = {
    'critical': 'Kritieke',
    'high': 'Hoge',
    'medium': 'Middelhoge',
    'low': 'Lage',
    'none': 'Informatieve',
}

_SEVERITY_LABELS_EN = {
    'critical': 'Critical',
    'high': 'High',
    'medium': 'Medium',
    'low': 'Low',
    'none': 'Informational',
}

# Risicowoord (kort, hoofdletters) voor de bevindingenlijst-tabel.
_RISK_WORDS = {
    'critical': 'KRITIEK', 'high': 'HOOG', 'medium': 'MIDDEN',
    'low': 'LAAG', 'none': 'INFO',
}
_RISK_WORDS_EN = {
    'critical': 'CRITICAL', 'high': 'HIGH', 'medium': 'MEDIUM',
    'low': 'LOW', 'none': 'INFO',
}

# Severity -> kleuren. HTML-achtergrond gelijk aan severity_colors; LaTeX-namen
# uit handboek/opmaak/packages/colors.sty.
_SEV_HTML_BG = {
    'critical': '#800080', 'high': '#e60000', 'medium': '#f09600',
    'low': '#ffdc00', 'none': '#5bc0de',
}
_SEV_HTML_FG = {
    'critical': '#ffffff', 'high': '#ffffff', 'medium': '#000000',
    'low': '#000000', 'none': '#000000',
}
_SEV_LATEX_COLOR = {
    'critical': 'opaars', 'high': 'ored', 'medium': 'oorange',
    'low': 'oyellow', 'none': 'olichtblauw',
}
_SEV_LATEX_FG = {
    'critical': 'white', 'high': 'white', 'medium': 'black',
    'low': 'black', 'none': 'black',
}


def _bevindingenlijst_rows(findings, taal='nl'):
    """Rijen voor de bevindingenlijst, gesorteerd op ernst (kritiek eerst)."""
    risk_words = _RISK_WORDS_EN if taal == 'en' else _RISK_WORDS
    rows = []
    for f in sorted(findings, key=lambda x: x.get('sort_key', 9)):
        sev = f.get('severity', 'none')
        rows.append({
            'id': str(f['nr']).zfill(3),
            'titel': f['titel'],
            'risk': risk_words.get(sev, sev),
            'color': _SEV_LATEX_COLOR.get(sev, 'olichtblauw'),
            'fg': _SEV_LATEX_FG.get(sev, 'black'),
        })
    return rows


def _bevindingenlijst_intro(taal):
    return ('The table below lists the findings identified during this assessment.'
            if taal == 'en' else
            'In de onderstaande tabel staan de bevindingen die tijdens deze test zijn aangetroffen.')


def _append_bevindingenlijst_html(parts, findings, taal='nl'):
    """Compacte bevindingenlijst (ID | Bevinding | Risico) met klikbare ID+titel
    en een gekleurde risicocel."""
    if not findings:
        return
    _en = taal == 'en'
    risk_words = _RISK_WORDS_EN if _en else _RISK_WORDS
    find_l = 'Finding' if _en else 'Bevinding'
    risk_l = 'Risk' if _en else 'Risico'
    parts.append('<h2>{}</h2>'.format('Findings List' if _en else 'Bevindingenlijst'))
    parts.append('<p>{}</p>'.format(html_escape(_bevindingenlijst_intro(taal))))
    parts.append('<table><tr><th>ID</th><th>{}</th><th>{}</th></tr>'.format(find_l, risk_l))
    for f in sorted(findings, key=lambda x: x.get('sort_key', 9)):
        nr = str(f['nr']).zfill(3)
        sev = f.get('severity', 'none')
        bg = _SEV_HTML_BG.get(sev, '#cccccc')
        fg = _SEV_HTML_FG.get(sev, '#000000')
        risk = risk_words.get(sev, sev)
        parts.append(
            '<tr><td><a href="#bev-{0}">{0}</a></td>'
            '<td><a href="#bev-{0}">{1}</a></td>'
            '<td style="background:{2};color:{3};text-align:center;font-weight:bold">{4}</td></tr>'.format(
                nr, html_escape(f['titel']), bg, fg, html_escape(risk)))
    parts.append('</table>')


def _bevindingenlijst_md_lines(findings, taal='nl'):
    """Bevindingenlijst als Markdown-tabel (platte ID's, risicowoord)."""
    if not findings:
        return []
    _en = taal == 'en'
    risk_words = _RISK_WORDS_EN if _en else _RISK_WORDS
    lines = ['## {}'.format('Findings List' if _en else 'Bevindingenlijst'), '',
             _bevindingenlijst_intro(taal), '',
             '| ID | {} | {} |'.format('Finding' if _en else 'Bevinding',
                                       'Risk' if _en else 'Risico'),
             '|---|---|---|']
    for f in sorted(findings, key=lambda x: x.get('sort_key', 9)):
        sev = f.get('severity', 'none')
        lines.append('| {} | {} | {} |'.format(
            str(f['nr']).zfill(3), str(f['titel']).replace('|', '\\|'),
            risk_words.get(sev, sev)))
    lines.append('')
    return lines

# ---------------------------------------------------------------------------
# Vertaaldict voor rapportgeneratie (NL/EN)
# ---------------------------------------------------------------------------

_T = {
    'nl': {
        'classificatie': 'Classificatie',
        'concept': 'CONCEPT',
        'inleiding': 'Inleiding',
        'management_samenvatting': 'Managementsamenvatting',
        'methodologie': 'Methodologie',
        'samenvatting': 'Samenvatting',
        'bevindingen': 'Bevindingen',
        'aanbevelingen': 'Overzicht aanbevelingen',
        'verkenning': 'Verkenning &amp; ontdekking',
        'totaal': 'Totaal',
        'aantal': 'Aantal',
        'locatie': 'Locatie',
        'uitwerking': 'Uitwerking',
        'impact': 'Impact',
        'aanbeveling': 'Aanbeveling',
        'legs_up': 'Legs Up',
        'startpunten': 'Assumed Breach Startpunten',
        'privilege_niveaus': 'Privilege Niveaus',
        'verstrekte_info': 'Verstrekte Informatie',
        'scenarios': "Scenario's",
        'bevindingen_label': 'bevindingen',
        'pentest_intro': 'Dit rapport bevat de bevindingen van de penetratietest uitgevoerd op {project}. Het doel was het identificeren van kwetsbaarheden die de vertrouwelijkheid, integriteit en beschikbaarheid van de systemen kunnen aantasten.',
        'redteam_intro': 'Dit rapport bevat de bevindingen van het red team assessment uitgevoerd op {project}. Het doel was het simuleren van een realistische aanval om de detectie- en responscapaciteiten van de organisatie te evalueren, evenals het identificeren van kwetsbaarheden in mensen, processen en technologie.',
        'pentest_methode': 'De penetratietest is uitgevoerd conform de OWASP Testing Guide en PTES (Penetration Testing Execution Standard). De test bestond uit de volgende fasen:',
        'redteam_methode': 'Het red team assessment is uitgevoerd conform het MITRE ATT&amp;CK framework en de Cyber Kill Chain. De test bestond uit de volgende fasen:',
        'pentest_fasen': [
            ('Verkenning', 'Informatie verzamelen over de doelomgeving'),
            ('Scanning', 'Diensten en kwetsbaarheden identificeren'),
            ('Exploitatie', 'Kwetsbaarheden bevestigen'),
            ('Post-exploitatie', 'Impact bepalen'),
            ('Rapportage', 'Documenteren'),
        ],
        'redteam_fasen': [
            ('Verkenning', 'OSINT en doelidentificatie'),
            ('Bewapening', 'Tooling en payloads voorbereiden'),
            ('Aflevering', 'Initi&euml;le toegang verkrijgen'),
            ('Exploitatie', 'Kwetsbaarheden benutten'),
            ('Installatie', 'Persistentie vestigen'),
            ('Commando &amp; Controle', 'C2-kanaal opzetten'),
            ('Acties op doel', 'Doelstellingen realiseren'),
        ],
        'scope_blackbox': 'De test is (deels) uitgevoerd als black box assessment. De testers hadden vooraf geen informatie over de interne werking, broncode of architectuur van de doelomgeving. Dit simuleert het perspectief van een externe aanvaller.',
        'scope_greybox': 'De test is (deels) uitgevoerd als grey box assessment. De testers hadden beperkte informatie, zoals netwerktopologie, gebruikersaccounts of API-documentatie. Dit simuleert een aanvaller met beperkte interne kennis.',
        'scope_whitebox': 'De test is (deels) uitgevoerd als white box assessment. De testers hadden volledige toegang tot broncode, architectuurdocumentatie en configuraties. Dit maakt een grondige analyse mogelijk van alle beveiligingslagen.',
    },
    'en': {
        'classificatie': 'Classification',
        'concept': 'DRAFT',
        'inleiding': 'Introduction',
        'management_samenvatting': 'Executive Summary',
        'methodologie': 'Methodology',
        'samenvatting': 'Summary of Findings',
        'bevindingen': 'Findings',
        'aanbevelingen': 'Recommendations Overview',
        'verkenning': 'Reconnaissance &amp; Discovery',
        'totaal': 'Total',
        'aantal': 'Count',
        'locatie': 'Location',
        'uitwerking': 'Elaboration',
        'impact': 'Impact',
        'aanbeveling': 'Recommendation',
        'legs_up': 'Legs Up',
        'startpunten': 'Assumed Breach Starting Points',
        'privilege_niveaus': 'Privilege Levels',
        'verstrekte_info': 'Provided Information',
        'scenarios': 'Scenarios',
        'bevindingen_label': 'findings',
        'pentest_intro': 'This report contains the findings of the penetration test performed on {project}. The objective was to identify vulnerabilities that could compromise the confidentiality, integrity and availability of the systems.',
        'redteam_intro': 'This report contains the findings of the red team assessment performed on {project}. The objective was to simulate a realistic attack to evaluate the detection and response capabilities of the organisation, as well as to identify vulnerabilities in people, processes and technology.',
        'pentest_methode': 'The penetration test was performed in accordance with the OWASP Testing Guide and PTES (Penetration Testing Execution Standard). The test consisted of the following phases:',
        'redteam_methode': 'The red team assessment was performed in accordance with the MITRE ATT&amp;CK framework and the Cyber Kill Chain. The test consisted of the following phases:',
        'pentest_fasen': [
            ('Reconnaissance', 'Gather information about the target environment'),
            ('Scanning', 'Identify services and vulnerabilities'),
            ('Exploitation', 'Confirm vulnerabilities'),
            ('Post-exploitation', 'Determine impact'),
            ('Reporting', 'Document findings'),
        ],
        'redteam_fasen': [
            ('Reconnaissance', 'OSINT and target identification'),
            ('Weaponisation', 'Prepare tooling and payloads'),
            ('Delivery', 'Obtain initial access'),
            ('Exploitation', 'Exploit vulnerabilities'),
            ('Installation', 'Establish persistence'),
            ('Command &amp; Control', 'Set up C2 channel'),
            ('Actions on Objectives', 'Achieve goals'),
        ],
        'scope_blackbox': 'The test was (partially) performed as a black box assessment. The testers had no prior information about the internal workings, source code or architecture of the target environment. This simulates the perspective of an external attacker.',
        'scope_greybox': 'The test was (partially) performed as a grey box assessment. The testers had limited information, such as network topology, user accounts or API documentation. This simulates an attacker with limited internal knowledge.',
        'scope_whitebox': 'The test was (partially) performed as a white box assessment. The testers had full access to source code, architecture documentation and configurations. This allows for a thorough analysis of all security layers.',
    },
}

# TLP 2.0 kleuren (LaTeX kleur-naam, HTML hex, tekst-kleur voor contrast)
_TLP_MAP = {
    'TLP:RED':          ('tlpred',   '#FF2B2B', '#ffffff'),
    'TLP:AMBER':        ('tlpamber', '#FFC000', '#000000'),
    'TLP:AMBER+STRICT': ('tlpamber', '#FFC000', '#000000'),
    'TLP:GREEN':        ('tlpgreen', '#33FF00', '#000000'),
    'TLP:CLEAR':        ('tlpclear', '#000000', '#ffffff'),
}

# Oplostijden (SLA) per severity — maximale hersteltermijn conform
# gangbare NCSC/BIO-richtlijnen. (severity -> (dagen, NL-label, EN-label))
_SLA_DAYS = {
    'critical': (1,   'Binnen 1 dag',     'Within 1 day'),
    'high':     (7,   'Binnen 1 week',    'Within 1 week'),
    'medium':   (30,  'Binnen 1 maand',   'Within 1 month'),
    'low':      (90,  'Binnen 3 maanden', 'Within 3 months'),
    'none':     (365, 'Naar inzicht',     'At discretion'),
}

# WOEF-faalmodus labels
_FAALMODUS_LABELS = {
    'opzet':   ('Opzet',   'Design'),
    'bestaan': ('Bestaan', 'Existence'),
    'werking': ('Werking', 'Operation'),
}

# Detecteerbaarheid labels
_DETECT_LABELS = {
    'ja':    ('Ja',    'Yes'),
    'nee':   ('Nee',   'No'),
    'deels': ('Deels', 'Partial'),
}

# Retest-status labels + kleur (nl, en, html-kleur)
_RETEST_LABELS = {
    'not_applicable': ('Niet van toepassing', 'Not applicable', '#94a3b8'),
    'pending_retest': ('Retest gepland',       'Retest planned', '#f59e0b'),
    'retested_fixed': ('Getest — Opgelost',    'Retested — Fixed', '#22c55e'),
    'retested_open':  ('Getest — Nog open',    'Retested — Still open', '#ef4444'),
}

# Risicomatrix as-labels (1..5)
_KANS_LABELS = {
    1: ('Zeer laag', 'Very low'), 2: ('Laag', 'Low'), 3: ('Middel', 'Medium'),
    4: ('Hoog', 'High'), 5: ('Zeer hoog', 'Very high'),
}
# Heatmap celkleuren per risicoscore (kans * impact, 1..25)
_HEATMAP_COLORS = [
    (17, '#800080', '#ffffff'),  # >=17  kritiek (paars)
    (10, '#e60000', '#ffffff'),  # >=10  hoog
    (5,  '#f09600', '#000000'),  # >=5   midden
    (0,  '#00be00', '#000000'),  # rest  laag
]


def _score_to_ki(basescore):
    """Leid kans/impact (1..5) af uit CVSS basescore als niet handmatig gezet.

    Spiegelt findings._score_to_kans_impact zodat rapport en dashboard gelijk lopen.
    """
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


def _finding_ki(f):
    """Bepaal (kans, impact) voor een finding-dict: handmatig indien gezet, anders afgeleid."""
    kans = int(f['kans']) if str(f.get('kans', '')).isdigit() and 1 <= int(f['kans']) <= 5 else None
    impact = int(f['impact_niveau']) if str(f.get('impact_niveau', '')).isdigit() and 1 <= int(f['impact_niveau']) <= 5 else None
    if kans is None or impact is None:
        dk, di = _score_to_ki(f.get('basescore'))
        kans = kans or dk
        impact = impact or di
    return kans, impact


def _heatmap_color(score):
    """Celkleur (bg, fg) voor een risicoscore (kans*impact)."""
    for threshold, bg, fg in _HEATMAP_COLORS:
        if score >= threshold:
            return bg, fg
    return '#00be00', '#000000'


def _heatmap_latex_color(score):
    """LaTeX kleurnaam (gedefinieerd in rapport_latex.tex) voor risicoscore."""
    if score >= 17:
        return 'opaars'
    if score >= 10:
        return 'ored'
    if score >= 5:
        return 'oorange'
    return 'ogreen'


def _build_rapport_appendices(findings, taal='nl'):
    """Bouw heatmap-, SLA- en mapping-data voor de LaTeX template."""
    sev_labels = _SEVERITY_LABELS_EN if taal == 'en' else _SEVERITY_LABELS

    # Heatmap: rijen kans 5..1, kolommen impact 1..5
    cells = {}
    for f in findings:
        k, i = _finding_ki(f)
        cells.setdefault((k, i), []).append(f['nr'])
    heatmap_rows = []
    for k in range(5, 0, -1):
        row_cells = []
        for i in range(1, 6):
            ids = cells.get((k, i), [])
            id_list = [str(x).zfill(3) for x in ids]
            row_cells.append({
                'color': _heatmap_latex_color(k * i),
                'ids': ', '.join(id_list),
                'id_list': id_list,
            })
        heatmap_rows.append({'kans': k, 'cells': row_cells})

    # SLA-rijen
    sla_rows = []
    for f in findings:
        sev = f['severity']
        _days, nl_lbl, en_lbl = _SLA_DAYS.get(sev, (90, '', ''))
        td = f.get('remediation_target_date')
        sla_rows.append({
            'id': str(f['nr']).zfill(3),
            'titel': f['titel'],
            'severity': sev_labels.get(sev, sev),
            'sla': en_lbl if taal == 'en' else nl_lbl,
            'date': td.strftime('%d-%m-%Y') if td else '-',
            'days': _days,
            'color': _SEV_LATEX_COLOR.get(sev, 'olichtblauw'),
        })

    # OWASP-mapping (alleen OWASP Top 10:2025; label + officiële URL)
    owasp_rows = []
    for f in findings:
        if not f.get('owasp_2025'):
            continue
        _lbl, _url = _owasp2025_label(f.get('owasp_2025'))
        owasp_rows.append({
            'id': str(f['nr']).zfill(3), 'titel': f['titel'],
            'owasp_2025': _lbl, 'owasp_2025_url': _url,
        })

    # NCSC-mapping
    try:
        from meuk.flask.findings import ncsc_richtlijn_filter as _ncsc
    except Exception:
        def _ncsc(code):
            return code or ''
    ncsc_rows = [{
        'id': str(f['nr']).zfill(3), 'titel': f['titel'],
        'ncsc': (_ncsc(f['ncsc']) if f.get('ncsc') else '-'),
    } for f in findings if f.get('ncsc')]

    # ISO 27001 / BIO / NIS2-mapping (afgeleid van CWE via OWASP-categorie)
    controls_rows = []
    for f in findings:
        c = _controls_for_finding(f)
        if not c:
            continue
        controls_rows.append({
            'id': str(f['nr']).zfill(3), 'titel': f['titel'],
            'iso27001': '; '.join(c['iso27001']) or '-',
            'bio': '; '.join(c['bio']) or '-',
            'nis2': '; '.join(c['nis2']) or '-',
        })

    # Detecteerbaarheid
    rated = [f for f in findings if f.get('detecteerbaarheid')]
    det_tally = {'ja': 0, 'deels': 0, 'nee': 0}
    for f in rated:
        d = f.get('detecteerbaarheid')
        if d in det_tally:
            det_tally[d] += 1
    det_label = {k: (_DETECT_LABELS[k][1] if taal == 'en' else _DETECT_LABELS[k][0])
                 for k in det_tally}
    det_gaps = [{
        'id': str(f['nr']).zfill(3), 'titel': f['titel'],
        'label': (_DETECT_LABELS[f['detecteerbaarheid']][1] if taal == 'en'
                  else _DETECT_LABELS[f['detecteerbaarheid']][0]),
        'note': f.get('detectie_notitie', '') or '',
    } for f in rated if f.get('detecteerbaarheid') in ('nee', 'deels')]

    # Exploit chains (kill chain)
    _cd = _chains_data()
    _names = {n['id']: n['naam'] for n in _cd.get('nodes', [])}
    chain_paths = []
    for i, path in enumerate([p for p in _cd.get('paths', []) if len(p) >= 2], 1):
        steps = ['[{}] {}'.format(str(nid).zfill(3), _latex_escape(_names.get(nid, '')))
                 for nid in path]
        nodes = [{'id': str(nid).zfill(3), 'naam': _names.get(nid, '') or ''} for nid in path]
        chain_paths.append({'num': i, 'steps': ' $\\rightarrow$ '.join(steps), 'nodes': nodes})

    detection_bar = [
        {'label': det_label['ja'], 'value': det_tally['ja'], 'color': 'cgreen'},
        {'label': det_label['deels'], 'value': det_tally['deels'], 'color': 'camber'},
        {'label': det_label['nee'], 'value': det_tally['nee'], 'color': 'cred'},
    ]

    # Severity-donut (taartsegmenten), CVSS-histogram en remediation-balk
    sev_lbls = _SEVERITY_LABELS_EN if taal == 'en' else _SEVERITY_LABELS
    sevc = {s: 0 for s in ('critical', 'high', 'medium', 'low', 'none')}
    hist = [0] * 10
    for f in findings:
        sevc[f.get('severity', 'none')] = sevc.get(f.get('severity', 'none'), 0) + 1
        try:
            sc = float(f.get('basescore') or 0)
        except (TypeError, ValueError):
            sc = 0.0
        if sc > 0:
            hist[min(9, int(sc))] += 1
    tot = sum(sevc.values()) or 1
    sev_pie, acc = [], 0.0
    for s in ('critical', 'high', 'medium', 'low', 'none'):
        if sevc[s] <= 0:
            continue
        span = sevc[s] / tot * 360.0
        sev_pie.append({'color': _SEV_LATEX_COLOR[s], 'a0': '%.3f' % acc,
                        'a1': '%.3f' % (acc + span), 'mid': '%.3f' % (acc + span / 2),
                        'label': sev_lbls[s], 'count': sevc[s]})
        acc += span
    cvss_hist = {'bins': [{'x': i, 'count': hist[i]} for i in range(10)],
                 'max': max(hist) if any(hist) else 0}
    _rem_cfg = [('open', 'cred'), ('in_progress', 'camber'), ('fixed', 'cblue'),
                ('verified', 'cgreen'), ('accepted', 'cgray')]
    _rem_lbl = ({'open': 'Open', 'in_progress': 'In progress', 'fixed': 'Fixed',
                 'verified': 'Verified', 'accepted': 'Accepted'} if taal == 'en'
                else {'open': 'Open', 'in_progress': 'In behandeling', 'fixed': 'Opgelost',
                      'verified': 'Geverifieerd', 'accepted': 'Geaccepteerd'})
    remc = {}
    for f in findings:
        st = f.get('remediation_status', 'open') or 'open'
        remc[st] = remc.get(st, 0) + 1
    remediation_bar = [{'label': _rem_lbl.get(k, k), 'value': remc.get(k, 0), 'color': col}
                       for k, col in _rem_cfg]

    return {
        'heatmap_rows': heatmap_rows,
        'sla_rows': sla_rows,
        'owasp_rows': owasp_rows,
        'ncsc_rows': ncsc_rows,
        'controls_rows': controls_rows,
        'detection_tally': det_tally,
        'detection_label': det_label,
        'detection_bar': detection_bar,
        'detection_gaps': det_gaps,
        'detection_rated': bool(rated),
        'chain_paths': chain_paths,
        'sev_pie': sev_pie,
        'cvss_hist': cvss_hist,
        'remediation_bar': remediation_bar,
    }


# Permissiebits voor PDF-lezers (met alleen het lezer-wachtwoord): openen +
# printen (laag + hoog-res) toegestaan; kopiëren/bewerken/annoteren geblokkeerd.
# Het eigenaar-wachtwoord omzeilt deze beperkingen.
_PDF_PERM = 2052
_PDF_ENC_LENGTH = 256  # 256 => AES-256 (R=6/V=5); xdvipdfmx valt terug indien niet ondersteund


def _pdf_encrypt_special(user_password, owner_password=''):
    r"""Bouw de xdvipdfmx-\special voor PDF-versleuteling tijdens de xelatex-build.

    Een los lezer- (user) en eigenaar- (owner) wachtwoord; owner valt terug op
    user. Haakjes/backslashes binnen de ()-literals worden geëscaped."""
    owner_password = owner_password or user_password or ''
    user_password = user_password or ''

    def _esc(p):
        return p.replace('\\', r'\\').replace('(', r'\(').replace(')', r'\)')

    return (r'\special{pdf:encrypt ownerpw (%s) userpw (%s) length %d perm %d}'
            % (_esc(owner_password), _esc(user_password), _PDF_ENC_LENGTH, _PDF_PERM))


def _pdf_is_encrypted(path):
    """True als de PDF versleuteld is (opent niet zonder wachtwoord)."""
    try:
        import pikepdf
    except ImportError:
        return True  # kan niet verifiëren; neem aan dat het goed zit
    try:
        with pikepdf.open(path):
            return False
    except Exception:
        return True


def _make_pdfa(src_pdf, dest_pdf):
    """Converteer een PDF naar PDF/A-2b via ghostscript (archiveerbaar, met
    ingebed sRGB-outputintent). Best-effort: ontbreekt gs/het ICC-profiel of
    faalt de conversie, dan False en blijft de gewone PDF beschikbaar."""
    import shutil
    import tempfile
    gs = shutil.which('gs') or shutil.which('gswin64c') or shutil.which('gswin32c')
    if not gs or not os.path.exists(src_pdf) or not os.path.exists(_SRGB_ICC):
        return False
    icc = os.path.abspath(_SRGB_ICC).replace('\\', '/')
    defps = (
        '%!\n'
        '[ /_objdef {icc_PDFA} /type /stream /OBJ pdfmark\n'
        '[ {icc_PDFA} << /N 3 >> /PUT pdfmark\n'
        '[ {icc_PDFA} (' + icc + ') (r) file /PUT pdfmark\n'
        '[ {icc_PDFA} /CLOSE pdfmark\n'
        '[ /_objdef {OutputIntent_PDFA} /type /dict /OBJ pdfmark\n'
        '[ {OutputIntent_PDFA} << /Type /OutputIntent /S /GTS_PDFA1 '
        '/DestOutputProfile {icc_PDFA} /OutputConditionIdentifier (sRGB) '
        '/Info (sRGB IEC61966-2.1) >> /PUT pdfmark\n'
        '[ {Catalog} << /OutputIntents [ {OutputIntent_PDFA} ] >> /PUT pdfmark\n')
    defpath = None
    try:
        with tempfile.NamedTemporaryFile('w', suffix='.ps', delete=False) as fh:
            fh.write(defps)
            defpath = fh.name
        p = subprocess.run(
            [gs, '-dPDFA=2', '-dBATCH', '-dNOPAUSE', '-sColorConversionStrategy=RGB',
             '-sDEVICE=pdfwrite', '-dPDFACompatibilityPolicy=1',
             '--permit-file-read=' + os.path.abspath(_SRGB_ICC),
             '-sOutputFile=' + dest_pdf, defpath, src_pdf],
            capture_output=True, timeout=180)
        return (p.returncode == 0 and os.path.exists(dest_pdf)
                and os.path.getsize(dest_pdf) > 0)
    except (subprocess.SubprocessError, OSError):
        return False
    finally:
        if defpath:
            try:
                os.unlink(defpath)
            except OSError:
                pass


def _encrypt_pdf(src_path, dest_path, user_password, owner_password=''):
    """Versleutel een PDF met AES-256 (R=6) via pikepdf, met een los eigenaar-
    en lezerwachtwoord. Het lezerwachtwoord (user) is nodig om te openen; het
    eigenaarwachtwoord (owner) geeft volledige rechten. Ontbreekt het
    eigenaarwachtwoord, dan valt het terug op het lezerwachtwoord. Faalt stil als
    pikepdf ontbreekt of beide wachtwoorden leeg zijn. Returns True/False.
    """
    try:
        import pikepdf
    except ImportError:
        return False
    user_password = user_password or ''
    owner_password = owner_password or user_password
    if not user_password and not owner_password:
        return False
    try:
        with pikepdf.open(src_path) as pdf:
            pdf.save(
                dest_path,
                encryption=pikepdf.Encryption(
                    owner=owner_password, user=user_password, R=6,  # R=6 => AES-256
                ),
            )
        return True
    except Exception:
        return False


def _copy_evidence_for_rapport(finding_id, evidence_list, dest_dir):
    """Kopieer evidence images naar rapport/evidence/ met leesbare namen."""
    copied = []
    for ev in evidence_list:
        src = os.path.join(_EVIDENCE_SRC, str(finding_id), ev.filename)
        if not os.path.exists(src):
            continue
        ct = ev.content_type or ''
        if not ct.startswith('image/'):
            continue
        safe_name = 'ev_{}_{}'.format(finding_id, ev.filename)
        dst = os.path.join(dest_dir, safe_name)
        shutil.copy2(src, dst)
        # Vooraf gelakte kopie (optioneel): db/evidence/<id>/lakken/<filename>
        # -> rapport/evidence/lakken/<safe_name>. De gelakte rapportbuild laadt
        # deze; ontbreekt hij, dan toont het rapport een [GELAKT]-placeholder
        # (nooit het origineel).
        lak_src = os.path.join(_EVIDENCE_SRC, str(finding_id), 'lakken', ev.filename)
        if os.path.exists(lak_src):
            lak_dir = os.path.join(dest_dir, 'lakken')
            os.makedirs(lak_dir, exist_ok=True)
            shutil.copy2(lak_src, os.path.join(lak_dir, safe_name))
        copied.append({
            'path': 'evidence/' + safe_name,
            'lakpath': 'evidence/lakken/' + safe_name,
            'caption': ev.original_filename or ev.filename,
            'sha256': ev.sha256 or '',
        })
    return copied


_REF_ENV_LINES = {r'\begin{itemize}', r'\end{itemize}', r'\begin{description}',
                  r'\end{description}', r'\begin{enumerate}', r'\end{enumerate}'}

# Relatie-type -> (NL, EN) label voor gerelateerde bevindingen
_REL_TYPE_LABELS = {
    'chain': ('Aanvalsketen', 'Attack chain'),
    'duplicate': ('Duplicaat', 'Duplicate'),
    'related': ('Gerelateerd', 'Related'),
}


def _clean_ref_lines(raw):
    """Referenties-regels: strip itemize/description-wrappers en leidende \\item.

    Sommige template-referenties bevatten LaTeX-lijstmarkup; die hoort niet als
    losse bullet getoond te worden. Resultaat is een schone lijst URL's/teksten
    die het template zelf in een itemize zet (gerenderd via latex_markup).
    """
    out = []
    seen = set()
    for ln in (raw or '').splitlines():
        s = ln.strip()
        if not s or s in _REF_ENV_LINES:
            continue
        m = _re.match(r'\\item(\[[^\]]*\])?\s*', s)
        if m:
            s = s[m.end():].strip()
        # LaTeX-escapes ontdoen -> formaat-neutrale platte tekst
        s = s.replace(r'\textbackslash{}', '\\')
        s = _re.sub(r'\\([&%#$_{}])', r'\1', s)
        s = s.rstrip('.,; ').strip()
        if not s:
            continue
        # Dedupliceer (ongevoelig voor hoofdletters/trailing slash)
        key = s.lower().rstrip('/')
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


def _aanbeveling_overzicht_tekst(aanbeveling, aanbeveling_kort, maxlen=160):
    """Beknopte aanbeveling voor het overzicht: korte variant indien aanwezig,
    anders de volledige tekst platgeslagen en ingekort. Altijd platte tekst
    (markup verwijderd, witruimte genormaliseerd) zodat het in een tabelcel past."""
    kort = (aanbeveling_kort or '').strip()
    bron = kort if kort else (aanbeveling or '')
    tekst = ' '.join(_plain_markup(bron).split())
    if not kort and len(tekst) > maxlen:
        tekst = tekst[:maxlen - 1].rstrip() + '…'
    return tekst


def _f_aanbeveling_overzicht(f):
    """Beknopte aanbeveling uit een finding-dict; berekent on-the-fly als het
    voorberekende veld ontbreekt (bv. handmatig opgebouwde dicts in tests)."""
    val = f.get('aanbeveling_overzicht')
    if val:
        return val
    return _aanbeveling_overzicht_tekst(f.get('aanbeveling'), f.get('aanbeveling_kort'))


def _build_findings_data(base_query, taal='nl'):
    """Bouw een gesorteerde lijst van finding-dicts voor het LaTeX template."""
    distinct_refs = db.session.query(db_bevindingen.ref).filter(
        db_bevindingen.id.in_([b.id for b in base_query.all()])
    ).distinct().all()
    refs = [r[0] for r in distinct_refs]

    findings = []
    for ref in refs:
        template = db_bevindingen_templates.query.filter_by(id=ref).first()
        items = base_query.filter_by(ref=ref).all()
        if not items:
            continue

        for item in items:
            evidence_db = db_evidence.query.filter_by(finding_id=item.id).all()
            basescore = item.basescore or (template.basescore if template else '') or '0'
            severity, sort_key = _cvss_to_severity(basescore)

            if taal == 'en':
                beschrijving = (template.enbeschrijving if template else '') or (template.nlbeschrijving if template else '') or ''
                impact = (template.enimpact if template else '') or (template.nlimpact if template else '') or ''
                aanbeveling = (template.enaanbeveling if template else '') or (template.nlaanbeveling if template else '') or ''
                impact_kort = (template.enimpactkort if template else '') or (template.nlimpactkort if template else '') or ''
                aanbeveling_kort = (template.enaanbevelingkort if template else '') or (template.nlaanbevelingkort if template else '') or ''
            else:
                beschrijving = (template.nlbeschrijving if template else '') or ''
                impact = (template.nlimpact if template else '') or ''
                aanbeveling = (template.nlaanbeveling if template else '') or ''
                impact_kort = (template.nlimpactkort if template else '') or ''
                aanbeveling_kort = (template.nlaanbevelingkort if template else '') or ''

            # Per-bevinding overrides gaan voor op de template-tekst (indien gevuld).
            _b_ov = (getattr(item, 'beschrijving_override', '') or '').strip()
            _i_ov = (getattr(item, 'impact_override', '') or '').strip()
            _a_ov = (getattr(item, 'aanbeveling_override', '') or '').strip()
            _ik_ov = (getattr(item, 'impact_kort_override', '') or '').strip()
            _ak_ov = (getattr(item, 'aanbeveling_kort_override', '') or '').strip()
            if _b_ov:
                beschrijving = _b_ov
            if _i_ov:
                impact = _i_ov
            if _a_ov:
                aanbeveling = _a_ov
            if _ik_ov:
                impact_kort = _ik_ov
            if _ak_ov:
                aanbeveling_kort = _ak_ov

            # Relaties ophalen
            rels_from = db_finding_related.query.filter_by(finding_id=item.id).all()
            related_items = []
            for r in rels_from:
                rel_bev = db.session.get(db_bevindingen, r.related_id)
                if rel_bev:
                    _rl = _REL_TYPE_LABELS.get(r.relation_type, (r.relation_type, r.relation_type))
                    related_items.append({
                        'id': rel_bev.id,
                        'naam': rel_bev.naam or '',
                        'type': r.relation_type,
                        'type_label': _rl[1] if taal == 'en' else _rl[0],
                    })

            # Gekoppelde assets (anchors) ophalen
            asset_items = []
            for anc in db_asset_anchor.query.filter_by(finding_id=item.id).all():
                ass = db.session.get(db_asset, anc.asset_id)
                if ass:
                    asset_items.append({
                        'waarde': ass.waarde or '',
                        'type': ass.asset_type or '',
                        'relatie': getattr(anc, 'relatie', '') or '',
                    })

            # Scan-evidence (sentinel) -> bewijsblok (zelfde vorm als scan-notitie)
            _uitw = item.uitwerken or ''
            _ev_tex = ''
            _ev_cmd = ''
            _ev_resp = ''
            if _uitw.startswith(_SCAN_EV_SENTINEL):
                try:
                    _ev = json.loads(_uitw[len(_SCAN_EV_SENTINEL):])
                    _ev_cmd = _ev.get('cmd', '') or ''
                    _ev_resp = _ev.get('resp', '') or ''
                    _ev_tex = _finding_evidence_tex(_ev_cmd, _ev_resp, taal)
                except (json.JSONDecodeError, TypeError, ValueError):
                    _ev_tex = ''

            findings.append({
                'id': item.id,
                'evidence_tex': _ev_tex,
                'evidence_cmd': _ev_cmd,
                'evidence_resp': _ev_resp,
                'titel': item.naam or '',
                'beschrijving': beschrijving,
                'impact': impact,
                'aanbeveling': aanbeveling,
                'impact_kort': impact_kort,
                'aanbeveling_kort': aanbeveling_kort,
                'aanbeveling_overzicht': _aanbeveling_overzicht_tekst(aanbeveling, aanbeveling_kort),
                'basescore': basescore,
                'cvss_vector': item.cvss or (template.cvss if template else '') or '',
                'locatie': item.locatie or '',
                'owasp': owasptop10[int(template.owasp) - 1] if template and template.owasp else '',
                'cwe': template.cwe if template else '',
                'severity': severity,
                'sort_key': sort_key,
                'evidence_db': evidence_db,
                'evidence': [],
                'uitwerken': item.uitwerken or '',
                # Vrije uitwerking van de bevinding, getoond vóór Impact.
                # Leeg wanneer het een scan-evidence-sentinel is (al als bewijsblok).
                'uitwerking_detail': ('' if _uitw.startswith(_SCAN_EV_SENTINEL) else _uitw),
                'remediation_status': getattr(item, 'remediation_status', 'open') or 'open',
                'remediation_target_date': getattr(item, 'remediation_target_date', None),
                'remediation_owner': getattr(item, 'remediation_owner', '') or '',
                'tester': getattr(item, 'tester', '') or '',
                'related': related_items,
                'assets': asset_items,
                # WOEF controle-mapping + faalmodus
                'faalmodus': getattr(item, 'faalmodus', '') or '',
                'control_ref': getattr(item, 'control_ref', '') or '',
                'detecteerbaarheid': getattr(item, 'detecteerbaarheid', '') or '',
                'detectie_notitie': getattr(item, 'detectie_notitie', '') or '',
                # Risicomatrix-assen (handmatig of afgeleid)
                'kans': getattr(item, 'kans', '') or '',
                'impact_niveau': getattr(item, 'impact_niveau', '') or '',
                # Retest
                'retest_status': getattr(item, 'retest_status', '') or '',
                'retest_date': getattr(item, 'retest_date', None),
                'retest_notes': getattr(item, 'retest_notes', '') or '',
                # Mapping-referenties uit template
                'owasp_2025': (template.owasp_2025 if template else '') or '',
                'ncsc': (template.ncsc if template else '') or '',
                'mitre': (template.mitre if template else '') or '',
                # Externe referenties (o.a. uit de OWASP-2025-verrijking)
                'referenties': (template.referenties if template else '') or '',
                'referenties_list': _clean_ref_lines(template.referenties if template else ''),
            })

    # Sorteer op severity (critical=1 eerst), db-id als stabiele tiebreak
    findings.sort(key=lambda f: (f['sort_key'], f['id']))
    # Per-opdracht volgnummer (001, 002, ...) voor WEERGAVE; db-id blijft intern
    # (evidence-koppeling, scope, relaties). Zo start elke opdracht bij 001.
    id2nr = {}
    for idx, f in enumerate(findings, 1):
        f['nr'] = idx
        id2nr[f['id']] = idx
    # Gerelateerde bevindingen tonen het volgnummer van de doelbevinding
    for f in findings:
        for rel in f.get('related', []):
            rel['nr'] = id2nr.get(rel['id'])
    return findings


def _build_checklist_appendix(checklist_ids, taal='nl'):
    """Bouw checklist-data voor rapport appendix.

    Returns lijst van dicts met naam, type, target, phases en stats.
    """
    from meuk.flask.checklists import _load_templates

    checklists_data = []
    templates_json = _load_templates()

    for cl in db_checklist.query.filter(db_checklist.id.in_(checklist_ids)).all():
        template = templates_json.get('checklists', {}).get(cl.checklist_type, {})
        item_map = {i.item_ref: i for i in cl.items}

        stats = {'pass': 0, 'fail': 0, 'warn': 0, 'skip': 0, 'na': 0, 'open': 0}
        phases = []
        for phase in template.get('phases', []):
            phase_items = []
            for tpl_item in phase.get('items', []):
                db_item = item_map.get(tpl_item['id'])
                status = db_item.status if db_item else 'open'
                stats[status] = stats.get(status, 0) + 1
                title = tpl_item.get('en_title' if taal == 'en' else 'title', tpl_item.get('title', ''))
                phase_items.append({
                    'ref': tpl_item['id'],
                    'title': title,
                    'status': status,
                })
            phases.append({
                'title': phase.get('title', ''),
                'items': phase_items,
            })

        total = sum(stats.values())
        en_title = template.get('en_title', template.get('title', cl.checklist_type))
        cl_title = en_title if taal == 'en' else template.get('title', cl.checklist_type)

        checklists_data.append({
            'naam': cl.naam,
            'type': cl_title,
            'target': cl.target or '',
            'phases': phases,
            'stats': stats,
            'total': total,
        })

    return checklists_data


# ---------------------------------------------------------------------------
# DigiD knock-out-criteria (managementsamenvatting)
# ---------------------------------------------------------------------------
# Vertaling checklist-itemstatus -> DigiD-normoordeel.
# pass/na -> Voldoet, fail -> Voldoet niet (knock-out),
# warn -> aandachtspunt, open/skip -> nog te bepalen.
_DIGID_OORDEEL = {
    'pass': 'voldoet', 'na': 'voldoet',
    'fail': 'voldoet_niet', 'warn': 'aandacht',
    'open': 'onbepaald', 'skip': 'onbepaald',
}
_DIGID_ERNST = {'voldoet_niet': 3, 'onbepaald': 2, 'aandacht': 1, 'voldoet': 0}
_DIGID_LABELS = {
    'nl': {'voldoet': 'Voldoet', 'voldoet_niet': 'Voldoet niet',
           'aandacht': 'Aandachtspunt', 'onbepaald': 'Nog te bepalen'},
    'en': {'voldoet': 'Compliant', 'voldoet_niet': 'Non-compliant',
           'aandacht': 'Point of attention', 'onbepaald': 'To be determined'},
}


def _digid_knockout(opdracht_id, taal='nl'):
    """Oordeelstabel per DigiD-norm, afgeleid uit de normdekking-fase van de
    aan de opdracht gekoppelde DigiD-checklist(s).

    Returns None als er geen opdracht of geen gekoppelde DigiD-checklist is.
    """
    if not opdracht_id:
        return None
    from meuk.flask.checklists import _load_templates
    from meuk.flask import project as _project
    # Zelfde scoping als de rest van de rapportage: rijen van dit project, en
    # voor het standaardproject ook niet-toegewezen (NULL) checklists.
    cls = _project.apply_scope(
        db_checklist.query.filter(db_checklist.checklist_type == 'digid'),
        db_checklist.opdracht_id, opdracht_id,
    ).all()
    if not cls:
        return None
    template = _load_templates().get('checklists', {}).get('digid', {})
    norm_phase = next((p for p in template.get('phases', [])
                       if p.get('id') == 'digid_norm'), None)
    if not norm_phase:
        return None
    norm_items = norm_phase.get('items', [])

    # Aggregeer per norm-ref over alle gekoppelde checklists (worst-case).
    agg = {}
    for cl in cls:
        status_map = {i.item_ref: i.status for i in cl.items}
        for it in norm_items:
            ref = it['id']
            oordeel = _DIGID_OORDEEL.get(status_map.get(ref, 'open'), 'onbepaald')
            if ref not in agg or _DIGID_ERNST[oordeel] > _DIGID_ERNST[agg[ref]]:
                agg[ref] = oordeel

    labels = _DIGID_LABELS['en' if taal == 'en' else 'nl']
    rows = []
    for it in norm_items:
        oordeel = agg.get(it['id'], 'onbepaald')
        title = it.get('en_title' if taal == 'en' else 'title',
                       it.get('title', it['id']))
        code, _, naam = title.partition(' — ')
        rows.append({'code': code.strip(), 'naam': naam.strip(),
                     'oordeel': oordeel, 'oordeel_label': labels[oordeel]})

    knockouts = [r['code'] for r in rows if r['oordeel'] == 'voldoet_niet']
    if knockouts:
        overall = 'voldoet_niet'
    elif any(r['oordeel'] == 'onbepaald' for r in rows):
        overall = 'onbepaald'
    else:
        overall = 'voldoet'

    if taal == 'en':
        if overall == 'voldoet_niet':
            conclusie = ('Based on the assessed DigiD norms the connection does NOT comply: '
                         'the following norm(s) are non-compliant (knock-out): {}.'.format(', '.join(knockouts)))
        elif overall == 'onbepaald':
            conclusie = ('No knock-out norms were identified, but not all DigiD norms '
                         'have been fully determined yet.')
        else:
            conclusie = ('All assessed DigiD norms are compliant; no knock-out '
                         'criteria were triggered.')
    else:
        if overall == 'voldoet_niet':
            conclusie = ('Op basis van de getoetste DigiD-normen voldoet de aansluiting NIET: '
                         'de volgende norm(en) voldoen niet (knock-out): {}.'.format(', '.join(knockouts)))
        elif overall == 'onbepaald':
            conclusie = ('Er zijn geen knock-out-normen vastgesteld, maar nog niet alle '
                         'DigiD-normen zijn volledig beoordeeld.')
        else:
            conclusie = ('Alle getoetste DigiD-normen voldoen; er zijn geen '
                         'knock-out-criteria geraakt.')

    return {
        'rows': rows,
        'knockouts': knockouts,
        'overall': overall,
        'overall_label': labels[overall],
        'conclusie': conclusie,
        'checklist_namen': [c.naam for c in cls],
    }


def _digid_knockout_latex(data, taal='nl'):
    """LaTeX-blok (subsectie + longtable + conclusie) voor het DigiD-oordeel."""
    if not data:
        return ''
    _en = taal == 'en'
    kop = 'DigiD norm compliance (knock-out criteria)' if _en else 'DigiD-normoordeel (knock-out-criteria)'
    c_code = 'Norm'
    c_naam = 'Topic' if _en else 'Onderwerp'
    c_oordeel = 'Verdict' if _en else 'Oordeel'
    out = [r'\subsection*{%s}' % _latex_escape(kop)]
    out.append(r'\begingroup\small')
    out.append(r'\begin{longtable}{>{\raggedright\arraybackslash}p{2.4cm} '
               r'>{\raggedright\arraybackslash}p{7.3cm} '
               r'>{\raggedright\arraybackslash}p{3.0cm}}')
    out.append(r'\rowcolor{rijkblauw}\textcolor{white}{\textbf{%s}} & \textcolor{white}{\textbf{%s}} & \textcolor{white}{\textbf{%s}} \\ \hline \endhead'
               % (_latex_escape(c_code), _latex_escape(c_naam), _latex_escape(c_oordeel)))
    out.append(r'\ibvervolg{3}\endfoot')
    out.append(r'\endlastfoot')
    for r in data['rows']:
        oordeel = _latex_escape(r['oordeel_label'])
        if r['oordeel'] == 'voldoet_niet':
            oordeel = r'\textbf{\textcolor{red}{%s}}' % oordeel
        out.append(r'%s & %s & %s \\' % (
            _latex_escape(r['code']), _latex_escape(r['naam']), oordeel))
    out.append(r'\end{longtable}\endgroup')
    out.append(r'\vspace{2pt}\noindent\textbf{%s} %s' % (
        _latex_escape('Conclusie:' if not _en else 'Conclusion:'),
        _latex_escape(data['conclusie'])))
    return '\n'.join(out)


def _digid_knockout_html(data, taal='nl'):
    """HTML-tabel voor de managementsamenvatting (preview + tex.html)."""
    if not data:
        return ''
    _en = taal == 'en'
    kop = 'DigiD norm compliance (knock-out criteria)' if _en else 'DigiD-normoordeel (knock-out-criteria)'
    c_code = 'Norm'
    c_naam = 'Topic' if _en else 'Onderwerp'
    c_oordeel = 'Verdict' if _en else 'Oordeel'
    colors = {'voldoet': '#1a7f37', 'voldoet_niet': '#b42318',
              'aandacht': '#b54708', 'onbepaald': '#475467'}
    parts = ['<h3 style="margin-top:14px">{}</h3>'.format(html_escape(kop))]
    parts.append('<table style="width:100%;border-collapse:collapse;font-size:13px">')
    parts.append(('<tr><th style="text-align:left;border-bottom:2px solid #333;padding:4px">{}</th>'
                  '<th style="text-align:left;border-bottom:2px solid #333;padding:4px">{}</th>'
                  '<th style="text-align:left;border-bottom:2px solid #333;padding:4px">{}</th></tr>').format(
        html_escape(c_code), html_escape(c_naam), html_escape(c_oordeel)))
    for r in data['rows']:
        col = colors.get(r['oordeel'], '#475467')
        weight = '700' if r['oordeel'] == 'voldoet_niet' else '400'
        parts.append(('<tr><td style="padding:4px;border-bottom:1px solid #ddd;white-space:nowrap">{}</td>'
                      '<td style="padding:4px;border-bottom:1px solid #ddd">{}</td>'
                      '<td style="padding:4px;border-bottom:1px solid #ddd;color:{};font-weight:{}">{}</td></tr>').format(
            html_escape(r['code']), html_escape(r['naam']), col, weight, html_escape(r['oordeel_label'])))
    parts.append('</table>')
    concl_label = 'Conclusion:' if _en else 'Conclusie:'
    parts.append('<p><strong>{}</strong> {}</p>'.format(
        html_escape(concl_label), html_escape(data['conclusie'])))
    return ''.join(parts)


def _digid_knockout_md(data, taal='nl'):
    """Markdown-tabel voor de docx-export."""
    if not data:
        return ''
    _en = taal == 'en'
    kop = 'DigiD norm compliance (knock-out criteria)' if _en else 'DigiD-normoordeel (knock-out-criteria)'
    c_code = 'Norm'
    c_naam = 'Topic' if _en else 'Onderwerp'
    c_oordeel = 'Verdict' if _en else 'Oordeel'
    lines = ['', '### {}'.format(kop), '',
             '| {} | {} | {} |'.format(c_code, c_naam, c_oordeel),
             '| --- | --- | --- |']
    for r in data['rows']:
        lines.append('| {} | {} | {} |'.format(
            r['code'], r['naam'], r['oordeel_label']))
    concl_label = 'Conclusion:' if _en else 'Conclusie:'
    lines.append('')
    lines.append('**{}** {}'.format(concl_label, data['conclusie']))
    lines.append('')
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Belangrijkste bevindingen + aanbevelingen (managementsamenvatting)
# ---------------------------------------------------------------------------
# Severity -> kleur (HTML-hex en LaTeX-kleurnaam), spiegelt de severity-huisstijl.
_KEY_SEV_HEX = {
    'critical': '#800080', 'high': '#e60000', 'medium': '#f09600',
    'low': '#ffdc00', 'none': '#5bc0de',
}
_KEY_SEV_TEX = {
    'critical': 'opaars', 'high': 'ored', 'medium': 'oorange',
    'low': 'oyellow', 'none': 'olichtblauw',
}
_KEY_SEV_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'none': 4}


def _key_findings(findings, taal='nl', severities=('critical', 'high'), max_items=5):
    """Belangrijkste bevindingen (standaard kritiek+hoog) met de korte impact-
    en aanbevelingsvelden, voor de managementsamenvatting. Gesorteerd op ernst
    en begrensd tot max_items (standaard 5, de ernstigste eerst).
    """
    labels = _SEVERITY_LABELS_EN if taal == 'en' else _SEVERITY_LABELS

    def _pick(sevs):
        s = [f for f in findings if f.get('severity') in sevs]
        s.sort(key=lambda f: _KEY_SEV_ORDER.get(f.get('severity'), 9))
        return s

    sel = _pick(severities)
    if not sel:
        # Terugval: zijn er geen kritieke/hoge bevindingen, toon de midden-bevindingen
        sel = _pick(('medium',))
    # Dedup: bevindingen met identieke korte impact- én aanbevelingstekst (bv.
    # meerdere instanties van dezelfde kwetsbaarheid) komen één keer terug in dit
    # overzicht. De ernstigste representant blijft staan (sel is al op ernst
    # gesorteerd). Bevindingen zonder korte teksten worden niet samengevoegd.
    _seen = set()
    _uniek = []
    for f in sel:
        sig = ((f.get('impact_kort') or '').strip().casefold(),
               (f.get('aanbeveling_kort') or '').strip().casefold())
        if sig != ('', ''):
            if sig in _seen:
                continue
            _seen.add(sig)
        _uniek.append(f)
    sel = _uniek
    if max_items:
        sel = sel[:max_items]
    rows = []
    for f in sel:
        rows.append({
            'id': f['id'],
            'titel': f.get('titel', '') or '',
            'severity': f.get('severity', ''),
            'severity_label': labels.get(f.get('severity', ''), f.get('severity', '')),
            'impact_kort': (f.get('impact_kort') or '').strip(),
            'aanbeveling_kort': (f.get('aanbeveling_kort') or '').strip(),
        })
    return rows


def _key_findings_html(rows, taal='nl'):
    if not rows:
        return ''
    _en = taal == 'en'
    kop = 'Key findings and recommendations' if _en else 'Belangrijkste bevindingen en aanbevelingen'
    l_imp = 'Impact'
    l_rec = 'Recommendation' if _en else 'Aanbeveling'
    parts = ['<h3 style="margin-top:14px">{}</h3>'.format(html_escape(kop))]
    for r in rows:
        col = _KEY_SEV_HEX.get(r['severity'], '#475467')
        parts.append('<div style="margin:0 0 10px">')
        parts.append('<div style="font-weight:700">{} <span style="color:{};font-size:11px">&mdash; {}</span></div>'
                     .format(html_escape(r['titel']), col, html_escape(r['severity_label'])))
        if r['impact_kort']:
            parts.append('<div style="margin-left:14px"><strong>{}:</strong> {}</div>'
                         .format(html_escape(l_imp), html_escape(_plain_markup(r['impact_kort']))))
        if r['aanbeveling_kort']:
            parts.append('<div style="margin-left:14px"><strong>{}:</strong> {}</div>'
                         .format(html_escape(l_rec), html_escape(_plain_markup(r['aanbeveling_kort']))))
        parts.append('</div>')
    return ''.join(parts)


def _key_findings_latex(rows, taal='nl'):
    if not rows:
        return ''
    _en = taal == 'en'
    kop = 'Key findings and recommendations' if _en else 'Belangrijkste bevindingen en aanbevelingen'
    l_imp = 'Impact'
    l_rec = 'Recommendation' if _en else 'Aanbeveling'
    out = [r'\subsection*{%s}' % _latex_escape(kop)]
    for r in rows:
        kleur = _KEY_SEV_TEX.get(r['severity'], 'ogrey')
        out.append(r'\par\noindent\textbf{%s} {\small\textcolor{%s}{(%s)}}'
                   % (_latex_escape(r['titel']), kleur, _latex_escape(r['severity_label'])))
        if r['impact_kort']:
            out.append(r'\par\noindent\textbf{%s:} %s'
                       % (_latex_escape(l_imp), _latex_escape(_plain_markup(r['impact_kort']))))
        if r['aanbeveling_kort']:
            out.append(r'\par\noindent\textbf{%s:} %s'
                       % (_latex_escape(l_rec), _latex_escape(_plain_markup(r['aanbeveling_kort']))))
        out.append(r'\par\vspace{5pt}')
    return '\n'.join(out)


def _key_findings_md(rows, taal='nl'):
    if not rows:
        return ''
    _en = taal == 'en'
    kop = 'Key findings and recommendations' if _en else 'Belangrijkste bevindingen en aanbevelingen'
    l_imp = 'Impact'
    l_rec = 'Recommendation' if _en else 'Aanbeveling'
    lines = ['', '### {}'.format(kop), '']
    for r in rows:
        lines.append('**{}** ({})'.format(r['titel'], r['severity_label']))
        lines.append('')
        if r['impact_kort']:
            lines.append('- **{}:** {}'.format(l_imp, _plain_markup(r['impact_kort'])))
        if r['aanbeveling_kort']:
            lines.append('- **{}:** {}'.format(l_rec, _plain_markup(r['aanbeveling_kort'])))
        lines.append('')
    return '\n'.join(lines)


@rapport_bp.route('/dashboard/report', methods=['GET'])
def rapport_dashboard():
    from meuk.flask import project as _project
    _oid = _project.current_opdracht_id()
    findings = _project.apply_scope(
        db_bevindingen.query, db_bevindingen.opdracht_id, _oid).all()
    notes = _project.apply_scope(
        db_notes.query, db_notes.opdracht_id, _oid
    ).order_by(db_notes.volgorde.asc(), db_notes.id.desc()).all()
    templates = db_bevindingen_templates.query.all()
    template_map = {str(t.id): t for t in templates}
    severity_map = {}
    for f in findings:
        sev, _ = _cvss_to_severity(f.basescore or (template_map.get(f.ref, None) and template_map[f.ref].basescore) or '0')
        severity_map[f.id] = sev
    checklists = _project.apply_scope(
        db_checklist.query, db_checklist.opdracht_id, _oid
    ).order_by(db_checklist.id.desc()).all()
    return render_template('rapport_dashboard.html',
                           findings=findings, notes=notes,
                           template_map=template_map, severity_map=severity_map,
                           checklists=checklists)


@rapport_bp.route('/dashboard/report/generate', methods=['GET'])
def gen_rapport():
    os.makedirs(_RAPPORT_DIR, exist_ok=True)
    evidence_dir = os.path.join(_RAPPORT_DIR, 'evidence')
    os.makedirs(evidence_dir, exist_ok=True)

    # Actief project bepalen (query-arg wint, bv. in de async-thread; anders sessie)
    from meuk.flask import project as _project
    _oid = _project.resolve_opdracht_id(request.args.get('opdracht_id', type=int))
    _project.set_override(_oid)  # alle onderliggende helpers scopen hierop

    # Status filter
    include_draft = request.args.get('include_draft', '0') == '1'
    base_query = _project.apply_scope(
        db_bevindingen.query, db_bevindingen.opdracht_id, _oid)
    if not include_draft:
        base_query = base_query.filter(db_bevindingen.status == 'final')

    # Notities met rapport=True (gescoped op het project), gesorteerd op volgorde
    notities = _project.apply_scope(
        db_notes.query.filter_by(rapport=True), db_notes.opdracht_id, _oid
    ).order_by(db_notes.volgorde.asc()).all()
    notes_data = [{'naam': n.naam or '', 'uitwerken': n.uitwerken or '',
                   'latex_raw': bool(getattr(n, 'latex_raw', False))} for n in notities]

    # Metadata uit de projectconfig (val terug op globale instellingen)
    s = _project.config_for(_oid) or _get_appdata()

    # Taal ophalen
    taal = (getattr(s, 'rapport_taal', '') if s else '') or 'nl'

    # Bouw findings data
    findings = _build_findings_data(base_query, taal=taal)

    # Checklists appendix
    _cl_raw = request.args.get('include_checklists', '')
    checklist_ids = [int(x) for x in _cl_raw.split(',') if x.strip().isdigit()]
    checklists_data = _build_checklist_appendix(checklist_ids, taal=taal) if checklist_ids else []

    # DigiD knock-out-oordeel (alleen als de actieve opdracht een DigiD-checklist heeft)
    digid_ko = _digid_knockout(_oid, taal=taal)

    # Belangrijkste bevindingen + korte impact/aanbeveling voor de samenvatting
    key_findings = _key_findings(findings, taal=taal)

    # Kopieer evidence
    for f in findings:
        f['evidence'] = _copy_evidence_for_rapport(f['id'], f['evidence_db'], evidence_dir)

    # Groepeer per severity
    severity_order = ['critical', 'high', 'medium', 'low', 'none']
    sev_labels = _SEVERITY_LABELS_EN if taal == 'en' else _SEVERITY_LABELS
    grouped = []
    counts = {sv: 0 for sv in severity_order}
    for sev in severity_order:
        group = [f for f in findings if f['severity'] == sev]
        counts[sev] = len(group)
        grouped.append((sev_labels.get(sev, sev), group))

    # Scoped hosts
    scoped_hosts = list(set(f['locatie'] for f in findings if f['locatie']))
    titel = (s.rapport_titel if s else '') or 'Penetration Test Report'
    auteur = (s.rapport_auteur if s else '') or 'Incompetent Bastard'
    subtitel = (s.rapport_subtitel if s else '') or 'Rapportage'
    project = (getattr(s, 'rapport_project', '') if s else '') or ''
    classificatie = (getattr(s, 'rapport_classificatie', '') if s else '') or 'TLP:RED'
    is_draft = getattr(s, 'rapport_isdraft', True) if s else True
    testtype = (getattr(s, 'rapport_testtype', '') if s else '') or 'pentest'
    testscope = (getattr(s, 'rapport_testscope', '') if s else '') or 'blackbox'
    testscopes = [t.strip() for t in testscope.split(',') if t.strip()]
    algeheel_beeld = (getattr(s, 'rapport_algeheel_beeld', '') if s else '') or ''
    management_samenvatting = (getattr(s, 'rapport_management_samenvatting', '') if s else '') or ''
    if not management_samenvatting.strip():
        management_samenvatting = _auto_management_samenvatting(counts, len(findings), taal)
    rapport_omgeving = (getattr(s, 'rapport_omgeving', '') if s else '') or ''
    legsup_startpunt = (getattr(s, 'rapport_legsup_startpunt', '') if s else '') or ''
    legsup_privileges = (getattr(s, 'rapport_legsup_privileges', '') if s else '') or ''
    legsup_informatie = (getattr(s, 'rapport_legsup_informatie', '') if s else '') or ''
    try:
        scenarios = json.loads((getattr(s, 'rapport_scenarios', '[]') if s else '[]') or '[]')
    except (json.JSONDecodeError, TypeError):
        scenarios = []
    try:
        scope_targets = json.loads((getattr(s, 'rapport_scope_targets', '[]') if s else '[]') or '[]')
    except (json.JSONDecodeError, TypeError):
        scope_targets = []
    rapport_roe = (getattr(s, 'rapport_roe', '') if s else '') or ''
    test_start = getattr(s, 'rapport_test_start_date', None) if s else None
    test_end = getattr(s, 'rapport_test_end_date', None) if s else None
    test_start_str = test_start.strftime('%d-%m-%Y') if test_start else ''
    test_end_str = test_end.strftime('%d-%m-%Y') if test_end else ''
    variant = (getattr(s, 'rapport_template_variant', '') if s else '') or 'detailed'
    rapport_versie = (getattr(s, 'rapport_versie', '') if s else '') or ''
    rapport_versie_status = (getattr(s, 'rapport_versie_status', '') if s else '') or 'concept'
    rapport_contact = (getattr(s, 'rapport_contact', '') if s else '') or ''
    try:
        rapport_revisies = json.loads((getattr(s, 'rapport_revisies', '[]') if s else '[]') or '[]')
    except (json.JSONDecodeError, TypeError):
        rapport_revisies = []
    try:
        rapport_distributie = json.loads((getattr(s, 'rapport_distributie', '[]') if s else '[]') or '[]')
    except (json.JSONDecodeError, TypeError):
        rapport_distributie = []
    datum = datetime.date.today().strftime('%d-%m-%Y')
    tlp_latex, tlp_html_bg, tlp_html_fg = _TLP_MAP.get(classificatie, ('tlpred', '#FF2B2B', '#ffffff'))

    # Rapport-template resolven (override > eigen template > ingebouwde variant) + scope
    _ov_tid = request.args.get('template_id', type=int)
    _ov_var = request.args.get('variant') or None
    _rtpl = _resolve_report_template(s, tid=_ov_tid, variant=_ov_var)
    _sections = _rtpl['sections']
    _scope = _rtpl['findings_scope']
    _custom_tex = _rtpl['custom_tex_path']
    findings_scoped, grouped_scoped = _scope_findings(findings, grouped, _scope)

    # Gemeenschappelijke extra kwargs
    _extra_kwargs = dict(
        rapport_roe=rapport_roe,
        test_start=test_start_str,
        test_end=test_end_str,
        variant=variant,
        rapport_versie=rapport_versie,
        rapport_versie_status=rapport_versie_status,
        sections=_sections,
        findings_scope=_scope,
        rapport_omgeving=rapport_omgeving,
        section_order=_rtpl.get('section_order') or [],
        rapport_project=project,
        rapport_contact=rapport_contact,
        rapport_revisies=rapport_revisies,
        rapport_distributie=rapport_distributie,
    )

    # Live preview: alleen de HTML teruggeven (geen xelatex/docx/stix)
    if request.args.get('preview') == '1':
        from flask import g as _g
        _g.report_preview = True  # relaxte CSP: inline styles in zelf-gegenereerde HTML
        html = _generate_html_preview(
            findings, grouped, counts, titel, auteur, subtitel, datum,
            classificatie, is_draft, notes_data, tlp_html_bg, tlp_html_fg,
            management_samenvatting=management_samenvatting, testtype=testtype,
            testscope=testscope, testscopes=testscopes, digid_knockout=digid_ko,
            key_findings=key_findings, algeheel_beeld=algeheel_beeld,
            legsup_startpunt=legsup_startpunt, legsup_privileges=legsup_privileges,
            legsup_informatie=legsup_informatie, scenarios=scenarios, taal=taal,
            scope_targets=scope_targets, checklists=checklists_data, **_extra_kwargs)
        return Response(html, mimetype='text/html')

    # --- Render LaTeX via Jinja2 met aangepaste delimiters ---
    template_dir = os.path.join(os.path.dirname(__file__), 'html')
    latex_env = Environment(
        loader=FileSystemLoader(template_dir),
        block_start_string='[%',
        block_end_string='%]',
        variable_start_string='[[',
        variable_end_string=']]',
        comment_start_string='[#',
        comment_end_string='#]',
        autoescape=False,
    )
    latex_env.filters['latex_escape'] = _latex_escape
    latex_env.filters['latex_markup'] = _latex_markup
    # Eigen .tex-template indien ingesteld, anders de standaard
    if _custom_tex and os.path.exists(_custom_tex):
        try:
            tmpl = latex_env.from_string(lezen(_custom_tex))
        except Exception:
            tmpl = latex_env.get_template('rapport_latex.tex')
    else:
        tmpl = latex_env.get_template('rapport_latex.tex')

    _rp_rows, _rp_open, _rp_ok = _retest_progress(findings_scoped, taal)
    tex_content = tmpl.render(
        titel=_latex_escape(titel),
        subtitel=_latex_escape(subtitel),
        auteur=_latex_escape(auteur),
        project=_latex_escape(project),
        classificatie=_latex_escape(classificatie),
        tlp_color=tlp_latex,
        datum=datum,
        is_draft=is_draft,
        rapport_versie=_latex_escape(rapport_versie),
        rapport_versie_status=rapport_versie_status,
        rapport_omgeving=_latex_escape(rapport_omgeving),
        test_start=test_start_str,
        test_end=test_end_str,
        rapport_contact=_latex_escape(rapport_contact).replace('\n', r'\newline '),
        rapport_revisies=rapport_revisies,
        rapport_distributie=rapport_distributie,
        sections=_sections,
        findings=findings_scoped,
        grouped_findings=grouped_scoped,
        bevindingenlijst_rows=_bevindingenlijst_rows(findings_scoped, taal),
        cia_triad=_cia_triad_tex(findings_scoped, taal),
        subsequent_triad=_subsequent_triad_tex(findings_scoped, taal),
        exploit_profile=_exploit_profile(findings_scoped, taal),
        direct_rows=_bevindingenlijst_rows(_direct_exploitable(findings_scoped), taal),
        direct_intro=_direct_exploitable_intro(len(_direct_exploitable(findings_scoped)), taal),
        impact_gauge=_impact_gauge(findings_scoped, taal),
        top_risk_gauge=_top_risk_gauge(findings_scoped, taal),
        counts=counts,
        scoped_hosts=scoped_hosts,
        scope_targets=scope_targets,
        notes=notes_data,
        testtype=testtype,
        testscope=testscope,
        testscopes=testscopes,
        management_samenvatting=_latex_escape(management_samenvatting),
        digid_knockout_tex=_digid_knockout_latex(digid_ko, taal=taal),
        key_findings_tex=_key_findings_latex(key_findings, taal=taal),
        algeheel_beeld=_latex_escape(algeheel_beeld),
        legsup_startpunt=legsup_startpunt,
        legsup_privileges=legsup_privileges,
        legsup_informatie=legsup_informatie,
        scenarios=scenarios,
        taal=taal,
        checklists=checklists_data,
        faalmodus_labels=_FAALMODUS_LABELS,
        detect_labels=_DETECT_LABELS,
        begrippen_rows=[{'term': _latex_escape(r['term']),
                         'definitie': _latex_escape(r['definitie'])}
                        for r in _begrippen_rows(taal)],
        beperkingen_lines=[_latex_escape(x) for x in _beperkingen_lines(
            taal, testtype=testtype, testscope=testscope, test_start=test_start_str,
            test_end=test_end_str, rapport_omgeving=rapport_omgeving)],
        evidence_register=[{'id': r['id'], 'caption': _latex_escape(r['caption']),
                            'file': _latex_escape(r['file']), 'sha256': r['sha256'],
                            'sha_fmt': ' '.join(r['sha256'][i:i + 16]
                                                for i in range(0, len(r['sha256']), 16))}
                           for r in _evidence_register(findings_scoped)],
        cvss_detail_rows=[{'id': r['id'], 'titel': _latex_escape(r['titel']),
                           'score': _latex_escape(r['score']),
                           'summary': _latex_escape(r['summary'])}
                          for r in _cvss_detail_rows(findings_scoped, taal)],
        retest_progress=[{'label': _latex_escape(r['label']), 'value': r['value'],
                          'color': r['tex']} for r in _rp_rows],
        retest_open=[{'id': r['id'], 'titel': _latex_escape(r['titel'])}
                     for r in _rp_open],
        retest_intro=_latex_escape(_retest_intro(
            taal, sum(r['value'] for r in _rp_rows))) if _rp_ok else '',
        **_build_rapport_appendices(findings, taal=taal),
    )

    # Herorden sectieblokken volgens de gekozen sectievolgorde. Markers zijn
    # LaTeX-commentaar (%SEC:..%), dus onschadelijk als ze onverhoopt blijven
    # staan; bij een eigen .tex zonder markers is dit een no-op.
    tex_content = _reorder_marked(
        tex_content, _rtpl.get('section_order') or [], '%SEC:{k}%', '%SEC-END%')

    # --- PDF-beveiliging: versleuteling tijdens de xelatex-build (xdvipdfmx) ---
    # Los lezer-/eigenaarwachtwoord + permissiebits via \special{pdf:encrypt}.
    pdf_password = (getattr(s, 'rapport_pdf_password', '') if s else '') or ''
    pdf_owner_password = (getattr(s, 'rapport_pdf_owner_password', '') if s else '') or ''
    encrypt = bool(pdf_password or pdf_owner_password)

    # Versleuteling bij voorkeur via pikepdf (post-processing): het wachtwoord
    # wordt als argument doorgegeven en elk teken komt letterlijk door. De
    # \special-route via xelatex mangelt TeX-specialtekens (& $ # % _ ~ ^ \)
    # in het wachtwoord, waardoor het PDF-wachtwoord afwijkt van het ingestelde.
    # Daarom wordt \special alleen nog als terugval gebruikt als pikepdf ontbreekt.
    try:
        import pikepdf as _pikepdf_check  # noqa: F401
        _have_pikepdf = True
    except ImportError:
        _have_pikepdf = False
    use_special = encrypt and not _have_pikepdf

    # Schrijf .tex bestand. De \special met wachtwoorden gaat ALLEEN in de te
    # compileren variant, nooit in de bewaarde rapport.tex of versie-snapshots.
    tex_path = os.path.join(_RAPPORT_DIR, 'rapport.tex')
    if use_special:
        special = _pdf_encrypt_special(pdf_password, pdf_owner_password)
        schrijven(tex_path, tex_content.replace(
            r'\begin{document}', r'\begin{document}' + '\n' + special, 1))
    else:
        schrijven(tex_path, tex_content)

    # Legacy: findings_nl.tex altijd schoon (zonder wachtwoorden) wegschrijven
    schrijven(os.path.join(_RAPPORT_DIR, 'findings_nl.tex'), tex_content)

    # --- PDF compilatie (optioneel) ---
    handboek_abs = os.path.abspath(_HANDBOEK_DIR)
    try:
        env = os.environ.copy()
        env['TEXINPUTS'] = '.:{layout}:{layout}//:{handboek}:{handboek}//:{rapport}:'.format(
            layout=os.path.abspath(_LAYOUT_DIR),
            handboek=handboek_abs, rapport=os.path.abspath(_RAPPORT_DIR))
        for _ in range(3):
            subprocess.run(
                ['xelatex', '-interaction=nonstopmode', '-output-directory',
                 os.path.abspath(_RAPPORT_DIR), tex_path],
                env=env, cwd=os.path.abspath(_RAPPORT_DIR),
                capture_output=True, timeout=120,
            )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass  # xelatex niet beschikbaar

    # Overschrijf de bewaarde .tex met de schone versie: geen wachtwoorden op schijf
    if use_special:
        schrijven(tex_path, tex_content)

    # --- PDF-beveiliging afronden ---
    secure_pdf = os.path.join(_RAPPORT_DIR, 'rapport_secure.pdf')
    plain_pdf = os.path.join(_RAPPORT_DIR, 'rapport.pdf')
    if encrypt and os.path.exists(plain_pdf):
        if use_special:
            # Zonder pikepdf heeft xelatex rapport.pdf al versleuteld; die kan niet
            # meer onversleuteld worden aangeboden. Spiegel naar de beveiligde download.
            try:
                shutil.copyfile(plain_pdf, secure_pdf)
            except OSError:
                pass
        else:
            # rapport.pdf blijft ONVERSLEUTELD (de gewone "PDF"-download); alleen
            # rapport_secure.pdf wordt via pikepdf (AES-256) versleuteld voor de
            # download "PDF (beveiligd)".
            if not _encrypt_pdf(plain_pdf, secure_pdf, pdf_password, pdf_owner_password):
                # Versleutelen mislukt -> geen onbeveiligde "secure" achterlaten
                try:
                    if os.path.exists(secure_pdf):
                        os.remove(secure_pdf)
                except OSError:
                    pass
    elif os.path.exists(secure_pdf) and not encrypt:
        # Oude versleutelde versie opruimen als beide wachtwoorden zijn verwijderd
        try:
            os.remove(secure_pdf)
        except OSError:
            pass

    # --- PDF/A-archiefvariant (ghostscript) ---
    # Archiveerbare PDF/A-2b met ingebed sRGB-outputintent. Best-effort: lukt het
    # niet, dan blijft de gewone PDF beschikbaar en wordt een oude PDF/A opgeruimd.
    pdfa_pdf = os.path.join(_RAPPORT_DIR, 'rapport_pdfa.pdf')
    if not _make_pdfa(plain_pdf, pdfa_pdf):
        try:
            if os.path.exists(pdfa_pdf):
                os.remove(pdfa_pdf)
        except OSError:
            pass

    # --- Gelakte (geredigeerde) rapportvariant ---
    # Zelfde inhoud als het gewone rapport, maar met \weglakken=true: elke
    # \lakken{...} wordt een zwarte balk en afbeeldingen laden hun gelakte kopie
    # uit evidence/lakken/ (met veilige [GELAKT]-placeholder, nooit het origineel).
    # Levert rapport_gelakt.pdf en, bij ingestelde wachtwoorden, een beveiligde
    # variant rapport_gelakt_secure.pdf — spiegelbeeld van de gewone PDF's.
    #
    # De tweede xelatex-build is kostbaar; die loont alleen als er daadwerkelijk
    # iets te lakken valt. Zonder redactiemacro's én zonder gelakte evidence-kopie
    # is de gelakte PDF identiek aan de gewone, dus slaan we hem dan over (en
    # ruimen we een eventuele oude gelakte PDF op zodat die niet verouderd blijft).
    _needs_lak = (r'\lakken{' in tex_content or r'\codelakken{' in tex_content
                  or os.path.isdir(os.path.join(_RAPPORT_DIR, 'evidence', 'lakken'))
                  or os.path.isdir(os.path.join(_SCREENSHOT_SRC, 'lakken')))
    gelakt_pdf = os.path.join(_RAPPORT_DIR, 'rapport_gelakt.pdf')
    gelakt_secure = os.path.join(_RAPPORT_DIR, 'rapport_gelakt_secure.pdf')
    gelakt_tex = os.path.join(_RAPPORT_DIR, 'rapport_gelakt.tex')
    if not _needs_lak:
        # Niets te lakken -> gelakte versie zou identiek zijn. Oude gelakte
        # bestanden opruimen zodat er geen verouderde variant wordt geserveerd.
        for _stale in (gelakt_pdf, gelakt_secure, gelakt_tex):
            try:
                if os.path.exists(_stale):
                    os.remove(_stale)
            except OSError:
                pass
    else:
        gelakt_body = tex_content.replace(
            r'\begin{document}',
            r'\begin{document}' + '\n' + r'\renewcommand{\weglakken}{true}%', 1)
        if use_special:
            schrijven(gelakt_tex, gelakt_body.replace(
                r'\begin{document}', r'\begin{document}' + '\n' + special, 1))
        else:
            schrijven(gelakt_tex, gelakt_body)
        try:
            for _ in range(3):
                subprocess.run(
                    ['xelatex', '-interaction=nonstopmode', '-output-directory',
                     os.path.abspath(_RAPPORT_DIR), gelakt_tex],
                    env=env, cwd=os.path.abspath(_RAPPORT_DIR),
                    capture_output=True, timeout=120,
                )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass  # xelatex niet beschikbaar
        if use_special:
            schrijven(gelakt_tex, gelakt_body)  # schone .tex zonder wachtwoorden

        if encrypt and os.path.exists(gelakt_pdf):
            if use_special:
                try:
                    shutil.copyfile(gelakt_pdf, gelakt_secure)
                except OSError:
                    pass
            elif not _encrypt_pdf(gelakt_pdf, gelakt_secure, pdf_password,
                                  pdf_owner_password):
                try:
                    if os.path.exists(gelakt_secure):
                        os.remove(gelakt_secure)
                except OSError:
                    pass
        elif os.path.exists(gelakt_secure) and not encrypt:
            try:
                os.remove(gelakt_secure)
            except OSError:
                pass

    # --- HTML generatie voor preview ---
    # Closure zodat de gelakte variant exact dezelfde invoer gebruikt (binnen
    # redact_mode vertaalt de markup \lakken{} dan naar zwarte blokken).
    def _gen_html():
        return _generate_html_preview(findings, grouped, counts, titel, auteur, subtitel, datum, classificatie, is_draft, notes_data, tlp_html_bg, tlp_html_fg, management_samenvatting=management_samenvatting, testtype=testtype, testscope=testscope, testscopes=testscopes, legsup_startpunt=legsup_startpunt, legsup_privileges=legsup_privileges, legsup_informatie=legsup_informatie, scenarios=scenarios, taal=taal, scope_targets=scope_targets, checklists=checklists_data, digid_knockout=digid_ko, key_findings=key_findings, algeheel_beeld=algeheel_beeld, **_extra_kwargs)
    html = _gen_html()
    schrijven(os.path.join(_RAPPORT_DIR, 'tex.html'), html)

    # --- STIX 2.1 bundle generatie ---
    from meuk.flask.stix_taxii import build_stix_bundle
    stix_findings = base_query.all()
    stix_templates = db_bevindingen_templates.query.all()
    stix_template_map = {str(t.id): t for t in stix_templates}
    stix = build_stix_bundle(stix_findings, stix_template_map,
                             titel=titel, auteur=auteur)
    schrijven(os.path.join(_RAPPORT_DIR, 'rapport.stix.json'),
              json.dumps(stix, indent=2, ensure_ascii=False))

    # --- DOCX Markdown generatie (altijd, onafhankelijk van pandoc) ---
    def _gen_docx_md():
        return _generate_docx_markdown(
            findings, grouped, counts, titel, auteur, subtitel, datum,
            classificatie, is_draft, notes_data,
            management_samenvatting=management_samenvatting,
            testtype=testtype, testscope=testscope, testscopes=testscopes,
            legsup_startpunt=legsup_startpunt,
            legsup_privileges=legsup_privileges,
            legsup_informatie=legsup_informatie,
            scenarios=scenarios, scoped_hosts=scoped_hosts, taal=taal,
            scope_targets=scope_targets,
            checklists=checklists_data, digid_knockout=digid_ko,
            key_findings=key_findings, algeheel_beeld=algeheel_beeld,
            **_extra_kwargs)
    docx_md = _gen_docx_md()
    docx_md_path = os.path.join(_RAPPORT_DIR, 'rapport_docx.md')
    schrijven(docx_md_path, docx_md)

    # Gelakte Markdown/HTML-bron: zelfde inhoud, maar \lakken{} -> blokken. Alleen
    # als er iets te lakken valt (anders identiek aan de gewone export).
    gelakt_docx_md_path = os.path.join(_RAPPORT_DIR, 'rapport_gelakt_docx.md')
    gelakt_html_path = os.path.join(_RAPPORT_DIR, 'tex_gelakt.html')
    if _needs_lak:
        with redact_mode():
            schrijven(gelakt_docx_md_path, _gen_docx_md())
            schrijven(gelakt_html_path, _gen_html())
    else:
        for _stale in (gelakt_docx_md_path, gelakt_html_path,
                       os.path.join(_RAPPORT_DIR, 'rapport_gelakt.docx')):
            try:
                if os.path.exists(_stale):
                    os.remove(_stale)
            except OSError:
                pass

    # --- SARIF generatie ---
    sarif = _generate_sarif(findings, titel, auteur)
    schrijven(os.path.join(_RAPPORT_DIR, 'rapport.sarif.json'),
              json.dumps(sarif, indent=2, ensure_ascii=False))

    # --- PPTX generatie ---
    try:
        _generate_pptx(findings, grouped, counts, titel, auteur, subtitel, datum,
                       os.path.join(_RAPPORT_DIR, 'rapport.pptx'))
    except Exception:
        pass

    # --- MD + DOCX generatie via pandoc ---
    try:
        from sh import pandoc
        # Legacy: tex.md van HTML preview
        html_path = os.path.join(_RAPPORT_DIR, 'tex.html')
        pandoc(html_path, '-o', os.path.join(_RAPPORT_DIR, 'tex.md'))
        md = lezen(os.path.join(_RAPPORT_DIR, 'tex.md'))
        md_header = '---\ntitle: "{}"\nsubtitle: "{}"\nauthor: {}\ndate: {}\n\n...\n\n'.format(
            html_escape(titel), html_escape(subtitel), html_escape(auteur), datum)
        schrijven(os.path.join(_RAPPORT_DIR, 'tex.md'), md_header + md)
        # DOCX en ODT van dedicated Markdown (spiegelt LaTeX structuur)
        _pandoc_args = ['--toc', '--toc-depth=2',
                        '--resource-path=' + os.path.abspath(_RAPPORT_DIR)]
        if os.path.exists(_DOCX_REFERENCE):
            _pandoc_args.append('--reference-doc=' + os.path.abspath(_DOCX_REFERENCE))
        pandoc(docx_md_path, *_pandoc_args,
               '-o', os.path.join(_RAPPORT_DIR, 'rapport.docx'))
        # Gelakte DOCX uit de gelakte Markdown (indien aanwezig).
        if _needs_lak and os.path.exists(gelakt_docx_md_path):
            pandoc(gelakt_docx_md_path, *_pandoc_args,
                   '-o', os.path.join(_RAPPORT_DIR, 'rapport_gelakt.docx'))
        # ODT en EPUB worden NIET standaard gebouwd: dat zijn nicheformaten en
        # elk een extra pandoc-subprocess. Ze worden lazy gegenereerd bij de
        # eerste download (zie _ensure_lazy_format). Oude versies verwijderen
        # zodat ze niet verouderd worden geserveerd.
        for _stale in ('rapport.odt', 'rapport.epub'):
            _sp = os.path.join(_RAPPORT_DIR, _stale)
            try:
                if os.path.exists(_sp):
                    os.remove(_sp)
            except OSError:
                pass
    except Exception:
        pass  # pandoc niet beschikbaar

    # --- Version snapshot ---
    _snapshot_version()

    return html


def _sha256_file(path):
    """Hex-SHA-256 van een bestand, streaming (geschikt voor grote PDF's)."""
    digest = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


# Deliverables waarvan de integriteit per versie wordt vastgelegd.
_DELIVERABLES = (
    'rapport.pdf', 'rapport_secure.pdf', 'rapport_gelakt.pdf',
    'rapport_gelakt_secure.pdf', 'rapport.docx', 'rapport_gelakt.docx',
    'rapport.tex', 'rapport_gelakt.tex', 'rapport_docx.md',
    'rapport_gelakt_docx.md', 'rapport.stix.json',
    'rapport.sarif.json', 'tex.html', 'tex_gelakt.html',
)


def _snapshot_version():
    """Maak een timestamped snapshot van de gegenereerde rapport bestanden en
    leg een SHA256SUMS-manifest vast over alle deliverables, zodat een auditor
    de geleverde bestanden kan verifiëren (sha256sum -c SHA256SUMS)."""
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    dest = os.path.join(_RAPPORT_DIR, 'versions', ts)
    os.makedirs(dest, exist_ok=True)
    for fname in ('rapport.tex', 'rapport_gelakt.tex', 'rapport_docx.md',
                  'rapport.stix.json', 'rapport.sarif.json', 'tex.html'):
        src = os.path.join(_RAPPORT_DIR, fname)
        if os.path.exists(src):
            shutil.copy2(src, dest)

    # Integriteitsmanifest over alle aanwezige deliverables (incl. de PDF's,
    # die zelf niet in de snapshot worden gekopieerd om de map klein te houden).
    lines = ['# SHA256SUMS — rapport-deliverables, gegenereerd {}Z'.format(
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S'))]
    for fname in _DELIVERABLES:
        src = os.path.join(_RAPPORT_DIR, fname)
        if os.path.exists(src):
            try:
                lines.append('{}  {}'.format(_sha256_file(src), fname))
            except OSError:
                pass
    with open(os.path.join(dest, 'SHA256SUMS'), 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(lines) + '\n')


_STATUS_COLORS = {
    'pass': '#22c55e', 'fail': '#ef4444', 'warn': '#f59e0b',
    'skip': '#94a3b8', 'na': '#94a3b8', 'open': '#d1d5db',
}


def _append_checklist_html(parts, checklists, taal='nl'):
    """Voeg checklist appendix toe aan HTML parts."""
    if not checklists:
        return
    heading = 'Checklist Results' if taal == 'en' else 'Checklist resultaten'
    parts.append('<h2>{}</h2>'.format(heading))
    ref_l = 'Ref'
    item_l = 'Item'
    status_l = 'Status'
    for cl in checklists:
        parts.append('<h3>{} ({}) &mdash; {}</h3>'.format(
            html_escape(cl['naam']), html_escape(cl['type']), html_escape(cl['target'])))
        st = cl['stats']
        parts.append('<p><strong>{} pass, {} fail, {} warn, {} skip, {} n/a, {} open</strong></p>'.format(
            st['pass'], st['fail'], st['warn'], st['skip'], st['na'], st['open']))
        for phase in cl['phases']:
            parts.append('<h4>{}</h4>'.format(html_escape(phase['title'])))
            parts.append('<table><tr><th>{}</th><th>{}</th><th>{}</th></tr>'.format(ref_l, item_l, status_l))
            for item in phase['items']:
                color = _STATUS_COLORS.get(item['status'], '#d1d5db')
                parts.append('<tr><td><code>{}</code></td><td>{}</td><td><span style="color:{}">{}</span></td></tr>'.format(
                    html_escape(item['ref']), html_escape(item['title']),
                    color, html_escape(item['status'].upper())))
            parts.append('</table>')


def _append_heatmap_html(parts, findings, taal='nl'):
    """Voeg een 5x5 risicomatrix (heatmap) toe met finding-IDs in de cellen."""
    if not findings:
        return
    heading = 'Risk Matrix' if taal == 'en' else 'Risicomatrix'
    kans_l = 'Likelihood' if taal == 'en' else 'Kans'
    impact_l = 'Impact'
    parts.append('<h2>{}</h2>'.format(heading))
    cells = {}
    for f in findings:
        k, i = _finding_ki(f)
        cells.setdefault((k, i), []).append(f['nr'])
    parts.append('<table style="table-layout:fixed">')
    parts.append('<tr><th>{} &darr; \\ {} &rarr;</th>'.format(kans_l, impact_l))
    for i in range(1, 6):
        parts.append('<th style="text-align:center">{}</th>'.format(i))
    parts.append('</tr>')
    for k in range(5, 0, -1):
        parts.append('<tr><th>{}</th>'.format(k))
        for i in range(1, 6):
            bg, fg = _heatmap_color(k * i)
            ids = cells.get((k, i), [])
            label = ', '.join(
                '<a href="#bev-{0}" style="color:inherit">#{0}</a>'.format(str(x).zfill(3))
                for x in ids)
            parts.append('<td style="background:{};color:{};text-align:center">{}</td>'.format(
                bg, fg, label or '&nbsp;'))
        parts.append('</tr>')
    parts.append('</table>')


def _append_sla_html(parts, findings, taal='nl'):
    """Voeg oplostijden/SLA-tabel toe op basis van severity + doeldatum."""
    if not findings:
        return
    heading = 'Remediation Timelines' if taal == 'en' else 'Oplostijden'
    intro = ('The recommended maximum remediation time is based on the risk classification '
             'of each finding.' if taal == 'en' else
             'De aanbevolen maximale hersteltermijn is gebaseerd op de risicoclassificatie '
             'van elke bevinding.')
    id_l = 'ID'
    find_l = 'Finding' if taal == 'en' else 'Bevinding'
    sev_l = 'Severity' if taal == 'en' else 'Ernst'
    sla_l = 'Target' if taal == 'en' else 'Streeftermijn'
    sev_labels = _SEVERITY_LABELS_EN if taal == 'en' else _SEVERITY_LABELS
    parts.append('<h2>{}</h2>'.format(heading))
    parts.append('<p>{}</p>'.format(intro))
    parts.append('<table><tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr>'.format(
        id_l, find_l, sev_l, sla_l))
    for f in findings:
        sev = f['severity']
        _days, nl_lbl, en_lbl = _SLA_DAYS.get(sev, (90, '', ''))
        sla_txt = en_lbl if taal == 'en' else nl_lbl
        nr = str(f['nr']).zfill(3)
        parts.append('<tr><td><a href="#bev-{0}">{0}</a></td><td>{1}</td><td>{2}</td><td>{3}</td></tr>'.format(
            nr, html_escape(f['titel']),
            html_escape(sev_labels.get(sev, sev)), html_escape(sla_txt)))
    parts.append('</table>')
    _tl = _sla_timeline_svg(findings, taal)
    if _tl:
        parts.append(_tl)


# ---------------------------------------------------------------------------
# Normatieve mapping: CWE -> OWASP-2025-categorie -> ISO 27001 / BIO / NIS2
# ---------------------------------------------------------------------------
_CONTROLS_PATH = os.path.join(os.path.dirname(__file__), 'db', 'cwe_category_controls.json')
_CWE_CATALOG_PATH = os.path.join(os.path.dirname(__file__), 'db', 'owasp_top10_2025_cwes.json')
_controls_cache = None
_cwe_to_cat_cache = None


def _load_controls():
    """Categorie-code ('A05:2025') -> {iso27001, bio, nis2} uit de koppeltabel."""
    global _controls_cache
    if _controls_cache is None:
        try:
            with open(_CONTROLS_PATH, encoding='utf-8') as fh:
                _controls_cache = json.load(fh).get('categories', {})
        except (OSError, ValueError):
            _controls_cache = {}
    return _controls_cache


_OWASP_2025_BASE = 'https://top10.owasp.org/2025/'
_owasp_meta_cache = None


def _owasp_cat_meta():
    """OWASP-2025-code ('A01:2025') -> {'title', 'slug'} uit de catalogus."""
    global _owasp_meta_cache
    if _owasp_meta_cache is None:
        meta = {}
        try:
            with open(_CWE_CATALOG_PATH, encoding='utf-8') as fh:
                data = json.load(fh)
            for cat in data.get('categories', []):
                code = cat.get('code', '')
                if code:
                    meta[code] = {'title': cat.get('title', ''),
                                  'slug': cat.get('slug', '')}
        except (OSError, ValueError):
            pass
        _owasp_meta_cache = meta
    return _owasp_meta_cache


def _owasp2025_label(raw):
    """Normaliseer een owasp_2025-waarde naar (label, url). label is bv.
    'A01:2025 – Broken Access Control'; url wijst naar de officiële OWASP-pagina.
    Valt terug op de ruwe tekst (zonder url) als de code onbekend is."""
    s = str(raw or '').strip()
    m = _re.match(r'A?0*(\d{1,2})', s)
    if not m or not (1 <= int(m.group(1)) <= 10):
        return (s or '—', '')
    code = 'A{:02d}:2025'.format(int(m.group(1)))
    meta = _owasp_cat_meta().get(code, {})
    title = meta.get('title', '')
    slug = meta.get('slug', '')
    label = '{} – {}'.format(code, title) if title else code
    url = (_OWASP_2025_BASE + slug + '/') if slug else ''
    return (label, url)


def _cwe_to_category():
    """CWE-id (str) -> OWASP-2025-code, afgeleid uit de CWE-catalogus (fallback)."""
    global _cwe_to_cat_cache
    if _cwe_to_cat_cache is None:
        idx = {}
        try:
            with open(_CWE_CATALOG_PATH, encoding='utf-8') as fh:
                data = json.load(fh)
            for cat in data.get('categories', []):
                code = cat.get('code', '')
                for c in cat.get('cwes', []):
                    cid = str(c.get('id', ''))
                    if cid and cid not in idx:
                        idx[cid] = code
        except (OSError, ValueError):
            pass
        _cwe_to_cat_cache = idx
    return _cwe_to_cat_cache


def _category_code(f):
    """OWASP-2025-code ('A05:2025') voor een finding-dict. Accepteert owasp_2025
    als nummer ('5'), als A-code ('A05' / 'A05:2025'); valt terug op CWE->categorie."""
    raw = str(f.get('owasp_2025') or '').strip()
    m = _re.match(r'A?0*(\d{1,2})', raw)
    if m:
        num = int(m.group(1))
        if 1 <= num <= 10:
            return 'A{:02d}:2025'.format(num)
    return _cwe_to_category().get(str(f.get('cwe') or ''))


def _controls_for_finding(f):
    """Resolve {categorie, iso27001, bio, nis2} voor een finding-dict. Primair op
    owasp_2025 van het template; valt terug op CWE->categorie. None als onbekend."""
    cat = _category_code(f)
    if not cat:
        return None
    entry = _load_controls().get(cat)
    if not entry:
        return None
    return {
        'categorie': cat,
        'iso27001': entry.get('iso27001', []),
        'bio': entry.get('bio', []),
        'nis2': entry.get('nis2', []),
    }


def _append_controls_mapping_html(parts, findings, taal='nl'):
    """Voeg ISO 27001 / BIO / NIS2 mapping-bijlage toe (afgeleid van CWE)."""
    rows = [(f, _controls_for_finding(f)) for f in findings]
    rows = [(f, c) for f, c in rows if c]
    if not rows:
        return
    _en = taal == 'en'
    heading = ('Appendix: ISO 27001 / BIO / NIS2 Mapping' if _en
               else 'Bijlage: ISO 27001 / BIO / NIS2 mapping')
    find_l = 'Finding' if _en else 'Bevinding'
    disc = ('Indicative mapping derived from the finding CWE via OWASP Top 10:2025 category; '
            'not a formal certification or complete coverage.' if _en else
            'Indicatieve koppeling, afgeleid van de CWE via de OWASP Top 10:2025-categorie; '
            'geen formele certificering of volledige dekking.')
    parts.append('<h2>{}</h2>'.format(html_escape(heading)))
    parts.append('<p style="color:#667085;font-size:12px"><em>{}</em></p>'.format(html_escape(disc)))
    parts.append('<table><tr><th>ID</th><th>{}</th><th>ISO 27001:2022</th>'
                 '<th>BIO2</th><th>NIS2 art. 21</th></tr>'.format(find_l))
    for f, c in rows:
        nr = str(f['nr']).zfill(3)
        parts.append('<tr><td><a href="#bev-{0}">{0}</a></td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>'.format(
            nr, html_escape(f['titel']),
            html_escape('; '.join(c['iso27001']) or '—'),
            html_escape('; '.join(c['bio']) or '—'),
            html_escape('; '.join(c['nis2']) or '—')))
    parts.append('</table>')


def _controls_mapping_md_lines(findings, taal='nl'):
    """Markdown-regels voor de ISO/BIO/NIS2-mapping-bijlage (DOCX via pandoc)."""
    rows = [(f, _controls_for_finding(f)) for f in findings]
    rows = [(f, c) for f, c in rows if c]
    if not rows:
        return []
    _en = taal == 'en'
    heading = ('ISO 27001 / BIO / NIS2 Mapping' if _en else 'ISO 27001 / BIO / NIS2 mapping')
    find_l = 'Finding' if _en else 'Bevinding'
    disc = ('Indicative mapping derived from the finding CWE via OWASP Top 10:2025 category.'
            if _en else
            'Indicatieve koppeling, afgeleid van de CWE via de OWASP Top 10:2025-categorie.')
    lines = ['', '## {}'.format(heading), '', '*{}*'.format(disc), '',
             '| ID | {} | ISO 27001:2022 | BIO2 | NIS2 art. 21 |'.format(find_l),
             '|----|------|----------------|------|--------------|']
    for f, c in rows:
        lines.append('| {} | {} | {} | {} | {} |'.format(
            str(f['nr']).zfill(3), f['titel'],
            '; '.join(c['iso27001']) or '—',
            '; '.join(c['bio']) or '—',
            '; '.join(c['nis2']) or '—'))
    lines.append('')
    return lines


# ---------------------------------------------------------------------------
# CIA-triade: C/I/A-impact uit de CVSS-vector, geaggregeerd als radar/driehoek
# ---------------------------------------------------------------------------
# CVSS v3: C/I/A = H/L/N; CVSS v2: C/I/A = C/P/N. Numeriek: hoog=2, laag=1, geen=0.
_CIA_IMPACT = {'H': 2, 'C': 2, 'L': 1, 'P': 1, 'N': 0}


def _parse_cia(vector):
    """(C, I, A)-impactwaarden (0/1/2) uit een CVSS-vector; None als onvolledig.
    Ondersteunt CVSS 4.0 (VC/VI/VA = Vulnerable System) en v3/v2 (C/I/A)."""
    if not vector:
        return None
    # CVSS 4.0 gebruikt VC/VI/VA; v3/v2 gebruiken C/I/A.
    if _re.search(r'(?:^|/)V[CIA]:', vector):
        metrics = (('VC', 'C'), ('VI', 'I'), ('VA', 'A'))
    else:
        metrics = (('C', 'C'), ('I', 'I'), ('A', 'A'))
    vals = {}
    for metric, axis in metrics:
        m = _re.search(r'(?:^|/)%s:([HLNCP])' % metric, vector)
        if m:
            vals[axis] = _CIA_IMPACT.get(m.group(1), 0)
    if len(vals) < 3:
        return None
    return (vals['C'], vals['I'], vals['A'])


def _cia_triad(findings):
    """Geaggregeerde relatieve C/I/A-impact (0..100%) over de bevindingen met een
    bruikbare CVSS-vector. None als geen enkele vector C/I/A bevat."""
    rows = [c for c in (_parse_cia(f.get('cvss_vector')) for f in findings) if c]
    if not rows:
        return None
    n = len(rows)
    mx = 2 * n
    sums = [sum(r[k] for r in rows) for k in range(3)]
    pct = [int(round(s / mx * 100)) for s in sums]
    return {'n': n, 'c': pct[0], 'i': pct[1], 'a': pct[2]}


def _cia_labels(taal):
    return (('Confidentiality', 'Integrity', 'Availability') if taal == 'en'
            else ('Vertrouwelijkheid', 'Integriteit', 'Beschikbaarheid'))


def _cia_intro(tri, taal):
    if taal == 'en':
        return ('Aggregate relative impact per security property, derived from the '
                'CVSS C/I/A metrics of %d findings (0%% = never affected, 100%% = '
                'maximum impact on every finding).' % tri['n'])
    return ('Geaggregeerde relatieve impact per beveiligingseigenschap, afgeleid van '
            'de CVSS C/I/A-metrieken van %d bevindingen (0%% = nooit geraakt, 100%% = '
            'maximale impact bij elke bevinding).' % tri['n'])


def _cia_triad_svg(tri, labels):
    """Inline-SVG radar/driehoek voor de CIA-triade."""
    import math
    cx, cy, R = 150, 150, 100
    angs = [-90.0, 30.0, 150.0]  # C boven, I rechtsonder, A linksonder (y omlaag)
    vals = [tri['c'], tri['i'], tri['a']]

    def pt(ang, rad):
        a = math.radians(ang)
        return (cx + rad * math.cos(a), cy + rad * math.sin(a))

    def poly(rad_scale):
        return ' '.join('%.1f,%.1f' % pt(a, R * rad_scale) for a in angs)

    data = ' '.join('%.1f,%.1f' % pt(a, R * v / 100.0) for a, v in zip(angs, vals))
    out = ['<svg width="300" height="300" viewBox="0 0 300 300" '
           'xmlns="http://www.w3.org/2000/svg" role="img">']
    for rs in (1.0, 0.666, 0.333):
        out.append('<polygon points="%s" fill="none" stroke="#d1d5db"/>' % poly(rs))
    for a in angs:
        x, y = pt(a, R)
        out.append('<line x1="%d" y1="%d" x2="%.1f" y2="%.1f" stroke="#d1d5db"/>' % (cx, cy, x, y))
    out.append('<polygon points="%s" fill="#3b82f6" fill-opacity="0.35" '
               'stroke="#2563eb" stroke-width="2"/>' % data)
    anchors = ['middle', 'start', 'end']
    offs = [(0, -12), (10, 6), (-10, 6)]
    for a, lab, anc, (dx, dy), val in zip(angs, labels, anchors, offs, vals):
        x, y = pt(a, R)
        out.append('<text x="%.1f" y="%.1f" text-anchor="%s" font-size="12" '
                   'fill="#334155">%s (%d%%)</text>' % (x + dx, y + dy, anc,
                                                        html_escape(lab), val))
    out.append('</svg>')
    return ''.join(out)


def _append_cia_triad_html(parts, findings, taal='nl'):
    """CIA-triade-bijlage met radar/driehoek (HTML)."""
    tri = _cia_triad(findings)
    if not tri:
        return
    _en = taal == 'en'
    labels = _cia_labels(taal)
    parts.append('<h2>%s</h2>' % ('Appendix: CIA Triad' if _en else 'Bijlage: CIA-triade'))
    parts.append('<p>%s</p>' % html_escape(_cia_intro(tri, taal)))
    parts.append('<div style="text-align:center">%s</div>' % _cia_triad_svg(tri, labels))
    parts.append('<ul>')
    for lab, val in zip(labels, (tri['c'], tri['i'], tri['a'])):
        parts.append('<li>%s: %d%%</li>' % (html_escape(lab), val))
    parts.append('</ul>')


def _cia_triad_md_lines(findings, taal='nl'):
    """CIA-triade als Markdown-tabel (geen radar in platte Markdown)."""
    tri = _cia_triad(findings)
    if not tri:
        return []
    _en = taal == 'en'
    labels = _cia_labels(taal)
    prop_l = 'Property' if _en else 'Eigenschap'
    imp_l = 'Relative impact' if _en else 'Relatieve impact'
    lines = ['', '## {}'.format('CIA Triad' if _en else 'CIA-triade'), '',
             '*{}*'.format(_cia_intro(tri, taal)), '',
             '| {} | {} |'.format(prop_l, imp_l), '|----|----|']
    for lab, val in zip(labels, (tri['c'], tri['i'], tri['a'])):
        lines.append('| {} | {}% |'.format(lab, val))
    lines.append('')
    return lines


def _triad_tex(tri, intro):
    """TeX-context voor een driehoek: percentages + TikZ-straal per as (0..3cm)."""
    if not tri:
        return None
    scale = 3.0
    return {
        'n': tri['n'], 'c': tri['c'], 'i': tri['i'], 'a': tri['a'],
        'c_r': '%.2f' % (scale * tri['c'] / 100.0),
        'i_r': '%.2f' % (scale * tri['i'] / 100.0),
        'a_r': '%.2f' % (scale * tri['a'] / 100.0),
        'intro': intro,
    }


def _cia_triad_tex(findings, taal='nl'):
    tri = _cia_triad(findings)
    return _triad_tex(tri, _cia_intro(tri, taal)) if tri else None


# ---------------------------------------------------------------------------
# Vervolgsysteem-impact (CVSS 4.0 SC/SI/SA) — tweede driehoek
# ---------------------------------------------------------------------------
_SUBSEQ_IMPACT = {'H': 2, 'S': 2, 'L': 1, 'N': 0}  # S = Safety (v4.0)


def _parse_subsequent(vector):
    """(SC, SI, SA)-impact (0/1/2) uit een CVSS 4.0-vector; None als afwezig."""
    if not vector:
        return None
    vals = {}
    for metric, axis in (('SC', 'C'), ('SI', 'I'), ('SA', 'A')):
        m = _re.search(r'(?:^|/)%s:([HLNS])' % metric, vector)
        if m:
            vals[axis] = _SUBSEQ_IMPACT.get(m.group(1), 0)
    if len(vals) < 3:
        return None
    return (vals['C'], vals['I'], vals['A'])


def _subsequent_triad(findings):
    rows = [c for c in (_parse_subsequent(f.get('cvss_vector')) for f in findings) if c]
    if not rows:
        return None
    n = len(rows)
    mx = 2 * n
    sums = [sum(r[k] for r in rows) for k in range(3)]
    return {'n': n, 'c': int(round(sums[0] / mx * 100)),
            'i': int(round(sums[1] / mx * 100)), 'a': int(round(sums[2] / mx * 100))}


def _subseq_intro(tri, taal):
    if taal == 'en':
        return ('Aggregate relative impact on subsequent (downstream) systems, from the '
                'CVSS 4.0 SC/SI/SA metrics of %d findings.' % tri['n'])
    return ('Geaggregeerde relatieve impact op vervolgsystemen (omliggende systemen), '
            'afgeleid van de CVSS 4.0 SC/SI/SA-metrieken van %d bevindingen.' % tri['n'])


def _append_subsequent_triad_html(parts, findings, taal='nl'):
    tri = _subsequent_triad(findings)
    if not tri:
        return
    _en = taal == 'en'
    labels = _cia_labels(taal)
    parts.append('<h2>%s</h2>' % ('Appendix: Subsequent System Impact'
                                  if _en else 'Bijlage: Vervolgsysteem-impact'))
    parts.append('<p>%s</p>' % html_escape(_subseq_intro(tri, taal)))
    parts.append('<div style="text-align:center">%s</div>' % _cia_triad_svg(tri, labels))
    parts.append('<ul>')
    for lab, val in zip(labels, (tri['c'], tri['i'], tri['a'])):
        parts.append('<li>%s: %d%%</li>' % (html_escape(lab), val))
    parts.append('</ul>')


def _subsequent_triad_md_lines(findings, taal='nl'):
    tri = _subsequent_triad(findings)
    if not tri:
        return []
    _en = taal == 'en'
    labels = _cia_labels(taal)
    prop_l = 'Property' if _en else 'Eigenschap'
    imp_l = 'Relative impact' if _en else 'Relatieve impact'
    lines = ['', '## {}'.format('Subsequent System Impact' if _en else 'Vervolgsysteem-impact'),
             '', '*{}*'.format(_subseq_intro(tri, taal)), '',
             '| {} | {} |'.format(prop_l, imp_l), '|----|----|']
    for lab, val in zip(labels, (tri['c'], tri['i'], tri['a'])):
        lines.append('| {} | {}% |'.format(lab, val))
    lines.append('')
    return lines


def _subsequent_triad_tex(findings, taal='nl'):
    tri = _subsequent_triad(findings)
    return _triad_tex(tri, _subseq_intro(tri, taal)) if tri else None


# ---------------------------------------------------------------------------
# Exploiteerbaarheids-profiel (CVSS AV/AC/AT/PR/UI-verdeling)
# ---------------------------------------------------------------------------
# metric -> (NL-naam, EN-naam, {waarde: (NL-label, EN-label)})
_EXP_METRICS = [
    ('AV', 'Attack Vector', 'Attack Vector',
     {'N': ('Netwerk', 'Network'), 'A': ('Aangrenzend', 'Adjacent'),
      'L': ('Lokaal', 'Local'), 'P': ('Fysiek', 'Physical')}),
    ('AC', 'Attack Complexity', 'Attack Complexity',
     {'L': ('Laag', 'Low'), 'H': ('Hoog', 'High')}),
    ('AT', 'Attack Requirements', 'Attack Requirements',
     {'N': ('Geen', 'None'), 'P': ('Aanwezig', 'Present')}),
    ('PR', 'Privileges Required', 'Privileges Required',
     {'N': ('Geen', 'None'), 'L': ('Laag', 'Low'), 'H': ('Hoog', 'High')}),
    ('UI', 'User Interaction', 'User Interaction',
     {'N': ('Geen', 'None'), 'P': ('Passief', 'Passive'),
      'A': ('Actief', 'Active'), 'R': ('Vereist', 'Required')}),
]


# "Ease of exploitation" per metriekwaarde (1 = eenvoudigst, 0 = moeilijkst).
# Indicatief; gebruikt voor de geaggregeerde exploiteerbaarheidsindex (gauge).
_EXP_EASE = {
    'AV': {'N': 1.0, 'A': 0.67, 'L': 0.33, 'P': 0.0},
    'AC': {'L': 1.0, 'H': 0.0},
    'AT': {'N': 1.0, 'P': 0.0},
    'PR': {'N': 1.0, 'L': 0.5, 'H': 0.0},
    'UI': {'N': 1.0, 'P': 0.5, 'A': 0.0, 'R': 0.0},
}


def _exploit_index(vectors):
    """Geaggregeerde exploiteerbaarheidsindex (0..100) over de vectoren: gemiddelde
    'ease' van AV/AC/AT/PR/UI. Hoger = makkelijker/eerder te misbruiken."""
    per = []
    for v in vectors:
        eases = []
        for metric, emap in _EXP_EASE.items():
            m = _re.search(r'(?:^|/)%s:([A-Z])' % metric, v)
            if m and m.group(1) in emap:
                eases.append(emap[m.group(1)])
        if eases:
            per.append(sum(eases) / len(eases))
    if not per:
        return None
    return int(round(sum(per) / len(per) * 100))


def _index_label(pct, taal):
    _en = taal == 'en'
    if pct >= 75:
        return 'Very high' if _en else 'Zeer hoog'
    if pct >= 50:
        return 'High' if _en else 'Hoog'
    if pct >= 25:
        return 'Medium' if _en else 'Middel'
    return 'Low' if _en else 'Laag'


def _gauge_svg(pct, label, value_text=None):
    """Halfronde risicometer (gauge) als inline SVG. value_text vervangt de
    centrale percentagetekst (bv. een CVSS-score)."""
    import math
    cx, cy, R = 160, 150, 120
    sw = 18

    def p(theta_deg, rad):
        a = math.radians(theta_deg)
        return (cx + rad * math.cos(a), cy - rad * math.sin(a))

    # Zones links->rechts (laag->hoog): groen, geel, oranje, rood (180°..0°).
    zones = [(180, 135, '#16a34a'), (135, 90, '#eab308'),
             (90, 45, '#f97316'), (45, 0, '#dc2626')]
    out = ['<svg width="320" height="205" viewBox="0 0 320 205" '
           'xmlns="http://www.w3.org/2000/svg" role="img">']
    for a0, a1, col in zones:
        pts = []
        for s in range(13):
            th = a0 + (a1 - a0) * s / 12.0
            x, y = p(th, R)
            pts.append('%.1f,%.1f' % (x, y))
        out.append('<polyline points="%s" fill="none" stroke="%s" '
                   'stroke-width="%d"/>' % (' '.join(pts), col, sw))
    th = 180 - 1.8 * pct  # 0%% -> 180° (links), 100%% -> 0° (rechts)
    nx, ny = p(th, R * 0.82)
    out.append('<line x1="%d" y1="%d" x2="%.1f" y2="%.1f" stroke="#1f2937" '
               'stroke-width="3"/>' % (cx, cy, nx, ny))
    out.append('<circle cx="%d" cy="%d" r="6" fill="#1f2937"/>' % (cx, cy))
    center = value_text if value_text is not None else '%d%%' % pct
    out.append('<text x="%d" y="%d" text-anchor="middle" font-size="24" '
               'font-weight="bold" fill="#1f2937">%s</text>' % (cx, cy + 30, html_escape(center)))
    out.append('<text x="%d" y="%d" text-anchor="middle" font-size="14" '
               'fill="#475569">%s</text>' % (cx, cy + 50, html_escape(label)))
    out.append('</svg>')
    return ''.join(out)


def _exploit_profile(findings, taal='nl'):
    """Verdeling van exploiteerbaarheidsmetrieken over de bevindingen met vector,
    plus een geaggregeerde exploiteerbaarheidsindex (gauge)."""
    vectors = [f.get('cvss_vector', '') for f in findings if f.get('cvss_vector')]
    if not vectors:
        return None
    idx = 2 if taal == 'en' else 1  # index in (code, NL, EN) labeltupel
    metrics = []
    for metric, nl_name, en_name, valmap in _EXP_METRICS:
        counts = {}
        for v in vectors:
            m = _re.search(r'(?:^|/)%s:([A-Z])' % metric, v)
            if m and m.group(1) in valmap:
                counts[m.group(1)] = counts.get(m.group(1), 0) + 1
        if not counts:
            continue
        items = [{'label': valmap[k][idx - 1], 'count': counts[k]}
                 for k in valmap if k in counts]
        metrics.append({'name': en_name if taal == 'en' else nl_name, 'items': items})
    if not metrics:
        return None
    index = _exploit_index(vectors)
    out = {'n': len(vectors), 'metrics': metrics}
    if index is not None:
        out['index'] = index
        out['index_label'] = _index_label(index, taal)
        out['gauge_angle'] = '%.1f' % (180 - 1.8 * index)
    return out


def _exploit_profile_intro(prof, taal):
    if taal == 'en':
        return ('Distribution of CVSS exploitability metrics across %d findings: how '
                'reachable and how easy to exploit.' % prof['n'])
    return ('Verdeling van de CVSS-exploiteerbaarheidsmetrieken over %d bevindingen: '
            'hoe bereikbaar en hoe eenvoudig te misbruiken.' % prof['n'])


def _append_exploit_profile_html(parts, findings, taal='nl'):
    prof = _exploit_profile(findings, taal)
    if not prof:
        return
    _en = taal == 'en'
    parts.append('<h2>%s</h2>' % ('Appendix: Exploitability Profile'
                                  if _en else 'Bijlage: Exploiteerbaarheids-profiel'))
    parts.append('<p>%s</p>' % html_escape(_exploit_profile_intro(prof, taal)))
    hdr = '<tr><th>%s</th><th>%s</th><th>%s</th></tr>' % (
        'Metric' if _en else 'Metriek', 'Value' if _en else 'Waarde',
        'Count' if _en else 'Aantal')
    rows = [hdr]
    for met in prof['metrics']:
        first = True
        for it in met['items']:
            rows.append('<tr><td>%s</td><td>%s</td><td>%d</td></tr>' % (
                html_escape(met['name']) if first else '', html_escape(it['label']), it['count']))
            first = False
    table = '<table>%s</table>' % ''.join(rows)
    # Links de risicometer, rechts de tabel.
    gauge = ''
    if 'index' in prof:
        idx_cap = ('Aggregate exploitability index (indicative)'
                   if _en else 'Geaggregeerde exploiteerbaarheidsindex (indicatief)')
        gauge = ('<div style="text-align:center">%s<div style="font-size:12px;'
                 'color:#64748b">%s</div></div>' % (
                     _gauge_svg(prof['index'], prof['index_label']), html_escape(idx_cap)))
    parts.append('<div style="display:flex;gap:20px;flex-wrap:wrap;align-items:center">'
                 '<div style="flex:0 0 auto">%s</div>'
                 '<div style="flex:1;min-width:260px">%s</div></div>' % (gauge, table))


def _exploit_profile_md_lines(findings, taal='nl'):
    prof = _exploit_profile(findings, taal)
    if not prof:
        return []
    _en = taal == 'en'
    lines = ['', '## {}'.format('Exploitability Profile' if _en else 'Exploiteerbaarheids-profiel'),
             '', '*{}*'.format(_exploit_profile_intro(prof, taal)), '']
    if 'index' in prof:
        lines.append('**{}: {}% ({})**'.format(
            'Exploitability index' if _en else 'Exploiteerbaarheidsindex',
            prof['index'], prof['index_label']))
        lines.append('')
    lines += ['| {} | {} | {} |'.format('Metric' if _en else 'Metriek',
                                       'Value' if _en else 'Waarde',
                                       'Count' if _en else 'Aantal'),
             '|----|----|----|']
    for met in prof['metrics']:
        first = True
        for it in met['items']:
            lines.append('| {} | {} | {} |'.format(
                met['name'] if first else '', it['label'], it['count']))
            first = False
    lines.append('')
    return lines


# ---------------------------------------------------------------------------
# Direct exploiteerbare bevindingen (AV:N + PR:N + UI:N)
# ---------------------------------------------------------------------------
def _direct_exploitable(findings):
    """Bevindingen die vanaf het netwerk, zonder rechten en zonder interactie te
    misbruiken zijn (AV:N, PR:N, UI:N)."""
    out = []
    for f in findings:
        v = f.get('cvss_vector', '')
        if not v:
            continue
        av = _re.search(r'(?:^|/)AV:([A-Z])', v)
        pr = _re.search(r'(?:^|/)PR:([A-Z])', v)
        ui = _re.search(r'(?:^|/)UI:([A-Z])', v)
        if av and pr and ui and av.group(1) == 'N' and pr.group(1) == 'N' and ui.group(1) == 'N':
            out.append(f)
    return out


def _direct_exploitable_intro(n, taal):
    if taal == 'en':
        return ('%d findings are exploitable from the network without privileges or user '
                'interaction (AV:N / PR:N / UI:N) — prioritise these.' % n)
    return ('%d bevindingen zijn vanaf het netwerk te misbruiken zonder rechten of '
            'gebruikersinteractie (AV:N / PR:N / UI:N) — prioriteer deze.' % n)


def _append_direct_exploitable_html(parts, findings, taal='nl'):
    rows = _direct_exploitable(findings)
    if not rows:
        return
    _en = taal == 'en'
    risk_words = _RISK_WORDS_EN if _en else _RISK_WORDS
    parts.append('<h2>%s</h2>' % ('Appendix: Directly Exploitable Findings'
                                  if _en else 'Bijlage: Direct exploiteerbare bevindingen'))
    parts.append('<p>%s</p>' % html_escape(_direct_exploitable_intro(len(rows), taal)))
    parts.append('<table><tr><th>ID</th><th>%s</th><th>%s</th></tr>' % (
        'Finding' if _en else 'Bevinding', 'Risk' if _en else 'Risico'))
    for f in sorted(rows, key=lambda x: x.get('sort_key', 9)):
        nr = str(f['nr']).zfill(3)
        sev = f.get('severity', 'none')
        bg = _SEV_HTML_BG.get(sev, '#cccccc')
        fg = _SEV_HTML_FG.get(sev, '#000000')
        parts.append('<tr><td><a href="#bev-%s">%s</a></td>'
                     '<td><a href="#bev-%s">%s</a></td>'
                     '<td style="background:%s;color:%s;text-align:center;font-weight:bold">%s</td></tr>' % (
                         nr, nr, nr, html_escape(f['titel']), bg, fg,
                         html_escape(risk_words.get(sev, sev))))
    parts.append('</table>')


def _direct_exploitable_md_lines(findings, taal='nl'):
    rows = _direct_exploitable(findings)
    if not rows:
        return []
    _en = taal == 'en'
    risk_words = _RISK_WORDS_EN if _en else _RISK_WORDS
    lines = ['', '## {}'.format('Directly Exploitable Findings' if _en
                                else 'Direct exploiteerbare bevindingen'),
             '', '*{}*'.format(_direct_exploitable_intro(len(rows), taal)), '',
             '| ID | {} | {} |'.format('Finding' if _en else 'Bevinding',
                                       'Risk' if _en else 'Risico'),
             '|----|------|--------|']
    for f in sorted(rows, key=lambda x: x.get('sort_key', 9)):
        sev = f.get('severity', 'none')
        lines.append('| {} | {} | {} |'.format(
            str(f['nr']).zfill(3), str(f['titel']).replace('|', '\\|'),
            risk_words.get(sev, sev)))
    lines.append('')
    return lines


# ---------------------------------------------------------------------------
# Impact-meter (gauge) uit de CIA-impact (VC/VI/VA resp. C/I/A)
# ---------------------------------------------------------------------------
def _impact_gauge(findings, taal='nl'):
    """Geaggregeerde impact-index (0..100) uit de CIA-triade: gemiddelde van de
    C/I/A-percentages. Hoger = zwaardere impact. None als geen bruikbare vectoren."""
    tri = _cia_triad(findings)
    if not tri:
        return None
    idx = int(round((tri['c'] + tri['i'] + tri['a']) / 3.0))
    return {'n': tri['n'], 'index': idx, 'index_label': _index_label(idx, taal),
            'gauge_angle': '%.1f' % (180 - 1.8 * idx)}


def _impact_gauge_intro(ig, taal):
    if taal == 'en':
        return ('Aggregate impact index across %d findings, from the CVSS C/I/A impact '
                'metrics (indicative).' % ig['n'])
    return ('Geaggregeerde impact-index over %d bevindingen, afgeleid van de CVSS C/I/A-'
            'impactmetrieken (indicatief).' % ig['n'])


def _append_impact_gauge_html(parts, findings, taal='nl'):
    ig = _impact_gauge(findings, taal)
    if not ig:
        return
    _en = taal == 'en'
    cap = 'Impact index (indicative)' if _en else 'Impact-index (indicatief)'
    parts.append('<h2>%s</h2>' % ('Appendix: Impact Meter' if _en else 'Bijlage: Impact-meter'))
    parts.append('<p>%s</p>' % html_escape(_impact_gauge_intro(ig, taal)))
    parts.append('<div style="text-align:center">%s<div style="font-size:12px;'
                 'color:#64748b">%s</div></div>' % (
                     _gauge_svg(ig['index'], ig['index_label']), html_escape(cap)))


def _impact_gauge_md_lines(findings, taal='nl'):
    ig = _impact_gauge(findings, taal)
    if not ig:
        return []
    _en = taal == 'en'
    return ['', '## {}'.format('Impact Meter' if _en else 'Impact-meter'), '',
            '*{}*'.format(_impact_gauge_intro(ig, taal)), '',
            '**{}: {}% ({})**'.format('Impact index' if _en else 'Impact-index',
                                      ig['index'], ig['index_label']), '']


# ---------------------------------------------------------------------------
# Risicometer op basis van de hoogste bevinding (CVSS-basescore)
# ---------------------------------------------------------------------------
def _top_risk_gauge(findings, taal='nl'):
    """Gauge-data voor de hoogste bevinding: hoogste CVSS-basescore (0..10) als
    naaldstand; toont de score en het risicowoord. None als geen scores."""
    best = None
    for f in findings:
        try:
            s = float(f.get('basescore') or 0)
        except (TypeError, ValueError):
            s = 0.0
        if best is None or s > best[0]:
            best = (s, f)
    if not best or best[0] <= 0:
        return None
    s, f = best
    pct = int(round(s / 10.0 * 100))
    risk_words = _RISK_WORDS_EN if taal == 'en' else _RISK_WORDS
    sev = f.get('severity') or 'none'
    return {'score': '%.1f' % s, 'pct': pct, 'label': risk_words.get(sev, sev),
            'nr': str(f['nr']).zfill(3) if f.get('nr') else '',
            'titel': f.get('titel', ''),
            'gauge_angle': '%.1f' % (180 - 1.8 * pct)}


def _top_risk_caption(taal):
    return ('Highest CVSS base score among the findings'
            if taal == 'en' else 'Hoogste CVSS-basescore onder de bevindingen')


def _append_top_risk_gauge_html(parts, findings, taal='nl'):
    g = _top_risk_gauge(findings, taal)
    if not g:
        return
    _en = taal == 'en'
    parts.append('<h3 style="margin-top:14px">%s</h3>' % ('Highest risk' if _en else 'Hoogste risico'))
    parts.append('<div style="text-align:center">%s</div>' % _gauge_svg(
        g['pct'], g['label'], value_text=g['score']))
    ref = ''
    if g['nr']:
        ref = ' &mdash; <a href="#bev-%s">[%s] %s</a>' % (g['nr'], g['nr'], html_escape(g['titel']))
    parts.append('<p style="font-size:12px;color:#64748b;text-align:center">%s%s</p>' % (
        html_escape(_top_risk_caption(taal)), ref))


def _top_risk_gauge_md_lines(findings, taal='nl'):
    g = _top_risk_gauge(findings, taal)
    if not g:
        return []
    _en = taal == 'en'
    ref = ' ([{}] {})'.format(g['nr'], g['titel']) if g['nr'] else ''
    return ['', '### {}'.format('Highest risk' if _en else 'Hoogste risico'), '',
            '**{}: {} ({})**{}'.format(_top_risk_caption(taal), g['score'], g['label'], ref), '']


def _append_owasp_mapping_html(parts, findings, taal='nl'):
    """Voeg OWASP Top 10:2025 mapping-bijlage toe."""
    relevant = [f for f in findings if f.get('owasp_2025')]
    if not relevant:
        return
    heading = 'Appendix: OWASP Top 10 Mapping' if taal == 'en' else 'Bijlage: OWASP Top 10 mapping'
    find_l = 'Finding' if taal == 'en' else 'Bevinding'
    parts.append('<h2>{}</h2>'.format(heading))
    parts.append('<table><tr><th>ID</th><th>{}</th><th>OWASP 2025</th></tr>'.format(find_l))
    for f in relevant:
        nr = str(f['nr']).zfill(3)
        label, url = _owasp2025_label(f.get('owasp_2025'))
        cat = ('<a href="{}">{}</a>'.format(html_escape(url), html_escape(label))
               if url else html_escape(label))
        parts.append('<tr><td><a href="#bev-{0}">{0}</a></td><td>{1}</td><td>{2}</td></tr>'.format(
            nr, html_escape(f['titel']), cat))
    parts.append('</table>')


def _append_ncsc_mapping_html(parts, findings, taal='nl'):
    """Voeg NCSC-richtlijnen mapping-bijlage toe."""
    try:
        from meuk.flask.findings import ncsc_richtlijn_filter as _ncsc
    except Exception:
        def _ncsc(code):
            return code or ''
    relevant = [f for f in findings if f.get('ncsc')]
    if not relevant:
        return
    heading = 'Appendix: NCSC Guidelines Mapping' if taal == 'en' else 'Bijlage: NCSC-richtlijnen mapping'
    find_l = 'Finding' if taal == 'en' else 'Bevinding'
    parts.append('<h2>{}</h2>'.format(heading))
    parts.append('<table><tr><th>ID</th><th>{}</th><th>NCSC</th></tr>'.format(find_l))
    for f in relevant:
        nr = str(f['nr']).zfill(3)
        ncsc_code = f.get('ncsc', '')
        ncsc_txt = _ncsc(ncsc_code) if ncsc_code else '&mdash;'
        parts.append('<tr><td><a href="#bev-{0}">{0}</a></td><td>{1}</td><td>{2}</td></tr>'.format(
            nr, html_escape(f['titel']), html_escape(ncsc_txt)))
    parts.append('</table>')


def _append_detection_html(parts, findings, taal='nl'):
    """Voeg detecteerbaarheid-overzicht + SOC/CDC-aanbevelingen toe."""
    rated = [f for f in findings if f.get('detecteerbaarheid')]
    if not rated:
        return
    heading = 'Detectability & SOC/CDC Recommendations' if taal == 'en' else 'Detecteerbaarheid & SOC/CDC-aanbevelingen'
    parts.append('<h2>{}</h2>'.format(heading))
    tally = {'ja': 0, 'deels': 0, 'nee': 0}
    for f in rated:
        d = f.get('detecteerbaarheid')
        if d in tally:
            tally[d] += 1
    _bar = _hbar_chart_svg([
        {'label': _DETECT_LABELS['ja'][1] if taal == 'en' else _DETECT_LABELS['ja'][0],
         'value': tally['ja'], 'color': _CHART_HEX['cgreen']},
        {'label': _DETECT_LABELS['deels'][1] if taal == 'en' else _DETECT_LABELS['deels'][0],
         'value': tally['deels'], 'color': _CHART_HEX['camber']},
        {'label': _DETECT_LABELS['nee'][1] if taal == 'en' else _DETECT_LABELS['nee'][0],
         'value': tally['nee'], 'color': _CHART_HEX['cred']},
    ], aria='Detecteerbaarheid')
    if _bar:
        parts.append(_bar)
    parts.append('<table><tr><th>{}</th><th>{}</th></tr>'.format(
        'Detectable' if taal == 'en' else 'Detecteerbaar', 'Count' if taal == 'en' else 'Aantal'))
    for k in ('ja', 'deels', 'nee'):
        lbl = _DETECT_LABELS[k][1] if taal == 'en' else _DETECT_LABELS[k][0]
        parts.append('<tr><td>{}</td><td>{}</td></tr>'.format(html_escape(lbl), tally[k]))
    parts.append('</table>')
    # Niet (volledig) detecteerbare bevindingen met toelichting
    gaps = [f for f in rated if f.get('detecteerbaarheid') in ('nee', 'deels')]
    if gaps:
        intro = ('The following findings were not (fully) detectable. Strengthening '
                 'monitoring and detection for these is recommended:' if taal == 'en' else
                 'De volgende bevindingen waren niet (volledig) detecteerbaar. Versterking '
                 'van monitoring en detectie hiervoor wordt aanbevolen:')
        parts.append('<p>{}</p>'.format(intro))
        parts.append('<ul>')
        for f in gaps:
            lbl = _DETECT_LABELS[f['detecteerbaarheid']][1] if taal == 'en' else _DETECT_LABELS[f['detecteerbaarheid']][0]
            note = f.get('detectie_notitie', '') or ''
            parts.append('<li><strong>[{}] {}</strong> ({}){}</li>'.format(
                str(f['nr']).zfill(3), html_escape(f['titel']), html_escape(lbl),
                ' — ' + html_escape(note) if note else ''))
        parts.append('</ul>')


def _detection_md_lines(findings, taal='nl'):
    """Detecteerbaarheid + SOC/CDC-aanbevelingen als Markdown."""
    rated = [f for f in findings if f.get('detecteerbaarheid')]
    if not rated:
        return []
    lines = []
    lines.append('# {}'.format('Detectability & SOC/CDC Recommendations' if taal == 'en'
                               else 'Detecteerbaarheid & SOC/CDC-aanbevelingen'))
    lines.append('')
    tally = {'ja': 0, 'deels': 0, 'nee': 0}
    for f in rated:
        d = f.get('detecteerbaarheid')
        if d in tally:
            tally[d] += 1
    lines.append('| {} | {} |'.format('Detectable' if taal == 'en' else 'Detecteerbaar',
                                      'Count' if taal == 'en' else 'Aantal'))
    lines.append('|---|---|')
    for k in ('ja', 'deels', 'nee'):
        lbl = _DETECT_LABELS[k][1] if taal == 'en' else _DETECT_LABELS[k][0]
        lines.append('| {} | {} |'.format(lbl, tally[k]))
    lines.append('')
    gaps = [f for f in rated if f.get('detecteerbaarheid') in ('nee', 'deels')]
    if gaps:
        if taal == 'en':
            lines.append('The following findings were not (fully) detectable. Strengthening '
                         'monitoring and detection for these is recommended:')
        else:
            lines.append('De volgende bevindingen waren niet (volledig) detecteerbaar. Versterking '
                         'van monitoring en detectie hiervoor wordt aanbevolen:')
        lines.append('')
        for f in gaps:
            lbl = _DETECT_LABELS[f['detecteerbaarheid']][1] if taal == 'en' else _DETECT_LABELS[f['detecteerbaarheid']][0]
            note = f.get('detectie_notitie', '') or ''
            lines.append('- **[{}] {}** ({}){}'.format(
                str(f['nr']).zfill(3), f['titel'], lbl, ' — ' + note if note else ''))
        lines.append('')
    return lines


def _chains_data():
    """Haal exploit-chain-paden op (lazy import om cirkels te vermijden)."""
    try:
        from meuk.flask.chains import build_chains
        return build_chains()
    except Exception:
        return {'nodes': [], 'edges': [], 'paths': []}


def _append_chains_html(parts, taal='nl'):
    """Voeg een kill-chain/exploit-chain-sectie toe aan de HTML."""
    data = _chains_data()
    paths = [p for p in data.get('paths', []) if len(p) >= 2]
    if not paths:
        return
    names = {n['id']: n['naam'] for n in data.get('nodes', [])}
    heading = 'Exploit Chains / Kill Chain' if taal == 'en' else 'Exploit chains / kill chain'
    parts.append('<h2>{}</h2>'.format(heading))
    _flow = _killchain_flow_svg(taal)
    if _flow:
        parts.append(_flow)
    for i, path in enumerate(paths, 1):
        steps = []
        for nid in path:
            nm = names.get(nid, '')
            steps.append('[{}] {}'.format(str(nid).zfill(3), html_escape(nm)))
        parts.append('<p><strong>{} {}:</strong> {}</p>'.format(
            'Chain' if taal == 'en' else 'Keten', i, ' &rarr; '.join(steps)))


def _chains_md_lines(taal='nl'):
    """Exploit-chains als Markdown-regels."""
    data = _chains_data()
    paths = [p for p in data.get('paths', []) if len(p) >= 2]
    if not paths:
        return []
    names = {n['id']: n['naam'] for n in data.get('nodes', [])}
    lines = ['# {}'.format('Exploit Chains / Kill Chain' if taal == 'en'
                           else 'Exploit chains / kill chain'), '']
    for i, path in enumerate(paths, 1):
        steps = ['[{}] {}'.format(str(nid).zfill(3), names.get(nid, '')) for nid in path]
        lines.append('- **{} {}:** {}'.format('Chain' if taal == 'en' else 'Keten', i,
                                              ' -> '.join(steps)))
    lines.append('')
    return lines


def _coverage_data():
    """Haal de asset-coverage-graaf op (lazy import om cirkels te vermijden)."""
    try:
        from meuk.flask.findings import build_asset_graph
        return build_asset_graph()
    except Exception:
        return {'nodes': [], 'edges': [], 'stats': {}}


def _append_coverage_html(parts, taal='nl'):
    """Voeg een asset-dekkingshoofdstuk toe aan de HTML (in scope/getest + tabel)."""
    data = _coverage_data()
    nodes = data.get('nodes', [])
    if not nodes:
        return
    s = data.get('stats', {})
    heading = 'Asset Coverage' if taal == 'en' else 'Asset-dekking'
    parts.append('<h2>{}</h2>'.format(heading))
    if taal == 'en':
        parts.append('<p>In scope: {} &middot; Tested: {} &middot; Derived: {} &middot; Total: {}</p>'.format(
            s.get('in_scope', 0), s.get('tested', 0), s.get('derived_tested', 0), s.get('total', 0)))
        cols = ('Asset', 'Type', 'Status', 'Scope', 'Findings')
        status_lbl = {'untested': 'Untested', 'in_progress': 'In progress',
                      'tested': 'Tested', 'out_of_scope': 'Out of scope'}
    else:
        parts.append('<p>In scope: {} &middot; Getest: {} &middot; Afgeleid: {} &middot; Totaal: {}</p>'.format(
            s.get('in_scope', 0), s.get('tested', 0), s.get('derived_tested', 0), s.get('total', 0)))
        cols = ('Asset', 'Type', 'Status', 'Scope', 'Bevindingen')
        status_lbl = {'untested': 'Ongetest', 'in_progress': 'Bezig',
                      'tested': 'Getest', 'out_of_scope': 'Out of scope'}
    parts.append('<table><thead><tr>' + ''.join('<th>{}</th>'.format(c) for c in cols) +
                 '</tr></thead><tbody>')
    for n in sorted(nodes, key=lambda x: (x.get('label') or '')):
        st = status_lbl.get(n.get('getest', 'untested'), n.get('getest', ''))
        if n.get('derived_tested') and n.get('getest') != 'tested':
            st += ' (via exploration)'
        label = n.get('label', '') + (':' + str(n['poort']) if n.get('poort') else '')
        row = [
            html_escape(label),
            html_escape(n.get('type', '')),
            html_escape(st),
            ('in' if n.get('in_scope') else 'out'),
            str(len(n.get('findings', []))),
        ]
        parts.append('<tr>' + ''.join('<td>{}</td>'.format(c) for c in row) + '</tr>')
    parts.append('</tbody></table>')


def _append_signoff_html(parts, taal='nl'):
    """Voeg sign-off tabel toe aan HTML parts."""
    label = 'Sign-off'
    role_l = 'Role' if taal == 'en' else 'Rol'
    name_l = 'Name' if taal == 'en' else 'Naam'
    date_l = 'Date' if taal == 'en' else 'Datum'
    sig_l = 'Signature' if taal == 'en' else 'Handtekening'
    parts.append('<h2>{}</h2>'.format(label))
    parts.append('<table><tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr>'.format(role_l, name_l, date_l, sig_l))
    for role in (['Lead Tester', 'Reviewer', 'Project Manager'] if taal == 'en' else ['Lead Tester', 'Reviewer', 'Projectmanager']):
        parts.append('<tr><td>{}</td><td>&nbsp;</td><td>&nbsp;</td><td>&nbsp;</td></tr>'.format(role))
    parts.append('</table>')


# ---------------------------------------------------------------------------
# Rapport-template-engine: secties + findings-scope (ingebouwd + eigen)
# ---------------------------------------------------------------------------

# Canonieke, toggelbare rapportsecties (volgorde = logische rapportvolgorde).
_SECTION_KEYS = (
    'managementsamenvatting', 'top_risk_gauge', 'methodologie', 'legsup', 'scenarios',
    'samenvatting_bevindingen', 'bevindingenlijst', 'risicomatrix', 'sla',
    'detecteerbaarheid', 'verkenning', 'bevindingen', 'aanbevelingen',
    'killchain', 'asset_dekking', 'checklists',
    'owasp_mapping', 'ncsc_mapping', 'controls_mapping', 'cia_triad',
    'subsequent_triad', 'exploit_profile', 'direct_exploitable', 'impact_gauge',
    'beperkingen', 'cvss_detail', 'bewijsregister', 'begrippenlijst',
    'retest_voortgang',
)

# Oudere opgeslagen secties: één 'appendices'-sleutel stuurde alle drie de
# mapping-bijlagen aan. Vouw die uit naar de afzonderlijke sleutels.
_LEGACY_SECTION_MAP = {
    'appendices': ('owasp_mapping', 'ncsc_mapping', 'controls_mapping'),
}


def _apply_legacy_sections(secs):
    """Zet verouderde 'appendices'-sleutel om naar de afzonderlijke mapping-
    sleutels, zolang die nog niet expliciet gezet zijn. Muteert en geeft terug."""
    if not isinstance(secs, dict):
        return secs
    for old, news in _LEGACY_SECTION_MAP.items():
        if old in secs and not any(n in secs for n in news):
            val = bool(secs[old])
            for n in news:
                secs.setdefault(n, val)
    return secs


def _all_sections(enabled=True):
    return {k: enabled for k in _SECTION_KEYS}


# Herordenbare hoofdsecties (de appendix-groep blijft als groep achteraan).
_REORDERABLE_SECTIONS = (
    'managementsamenvatting', 'methodologie', 'legsup', 'scenarios',
    'samenvatting_bevindingen', 'bevindingenlijst', 'risicomatrix', 'sla',
    'detecteerbaarheid', 'verkenning', 'bevindingen', 'aanbevelingen',
)


def _normalize_order(order):
    """Geldige, volledige volgorde van de herordenbare secties."""
    seen, out = set(), []
    for k in (order or []):
        if k in _REORDERABLE_SECTIONS and k not in seen:
            seen.add(k)
            out.append(k)
    for k in _REORDERABLE_SECTIONS:
        if k not in seen:
            out.append(k)
    return out


def _reorder_marked(text, order, mk_fmt, end_tok):
    """Herorden sectieblokken die met open-markers (mk_fmt met '{k}') zijn
    gemarkeerd en begrensd door end_tok. Het gebied van de eerste marker t/m
    end_tok wordt op volgorde herschikt; markers + end_tok worden verwijderd."""
    mk_re = _re.compile(_re.escape(mk_fmt).replace(r'\{k\}', r'([a-z_]+)'))
    first = mk_re.search(text)
    if not first:
        return text.replace(end_tok, '')
    end_idx = text.find(end_tok, first.start())
    if end_idx == -1:
        return text.replace(end_tok, '')
    region = text[first.start():end_idx]
    matches = list(mk_re.finditer(region))
    blocks, seen = {}, []
    for i, m in enumerate(matches):
        key = m.group(1)
        b_end = matches[i + 1].start() if i + 1 < len(matches) else len(region)
        blocks[key] = region[m.end():b_end]
        seen.append(key)
    norm = _normalize_order(order)
    keys = [k for k in norm if k in blocks] + [k for k in seen if k not in norm]
    new_region = ''.join(blocks[k] for k in keys)
    return (text[:first.start()] + new_region + text[end_idx:]).replace(end_tok, '')


# Ingebouwde varianten als sectie-presets + findings-scope.
_BUILTIN_VARIANTS = {
    'detailed': {'sections': _all_sections(True), 'findings_scope': 'all'},
    'executive': {'sections': {**_all_sections(False),
                               'managementsamenvatting': True,
                               'samenvatting_bevindingen': True,
                               'risicomatrix': True, 'sla': True,
                               'bevindingen': True, 'aanbevelingen': True},
                  'findings_scope': 'critical_high'},
    'board': {'sections': {**_all_sections(False),
                           'managementsamenvatting': True,
                           'samenvatting_bevindingen': True,
                           'bevindingen': True},
              'findings_scope': 'top3'},
}


def _resolve_report_template(cfg, tid=None, variant=None):
    """Bepaal {naam, sections, findings_scope, custom_tex_path, taal} voor het
    actieve rapport-template: expliciete override (tid/variant) > eigen template
    (rapport_template_id) > ingebouwde variant (rapport_template_variant)."""
    if variant and variant in _BUILTIN_VARIANTS:
        base = _BUILTIN_VARIANTS[variant]
        return {'naam': variant, 'sections': dict(base['sections']),
                'findings_scope': base['findings_scope'], 'custom_tex_path': '', 'taal': '',
                'section_order': _normalize_order([])}
    if tid is None:
        tid = getattr(cfg, 'rapport_template_id', None) if cfg else None
    if tid:
        row = db.session.get(db_rapport_template, tid)
        if row is not None:
            try:
                secs = json.loads(row.sections or '{}')
            except (json.JSONDecodeError, TypeError):
                secs = {}
            secs = _apply_legacy_sections(secs)
            sections = _all_sections(True)
            sections.update({k: bool(v) for k, v in secs.items() if k in _SECTION_KEYS})
            try:
                order = json.loads(row.section_order or '[]')
            except (json.JSONDecodeError, TypeError):
                order = []
            return {
                'naam': row.naam,
                'sections': sections,
                'findings_scope': row.findings_scope or 'all',
                'custom_tex_path': row.custom_tex_path or '',
                'taal': row.taal or '',
                'section_order': _normalize_order(order),
            }
    variant = (getattr(cfg, 'rapport_template_variant', '') if cfg else '') or 'detailed'
    base = _BUILTIN_VARIANTS.get(variant, _BUILTIN_VARIANTS['detailed'])
    return {'naam': variant, 'sections': dict(base['sections']), 'section_order': _normalize_order([]),
            'findings_scope': base['findings_scope'], 'custom_tex_path': '', 'taal': ''}


def _renumber_scoped(f2, g2):
    """Hernummer de gescopede bevindingen aaneengesloten vanaf 001.

    Na filtering (critical_high/top3) zou nr gaten houden (001, 002, 005). De
    gescopede dicts worden hier in weergavevolgorde opnieuw genummerd en de
    gerelateerde verwijzingen bijgewerkt (nr=None als het doel buiten scope valt).
    """
    ordered = [x for _lbl, grp in g2 for x in grp]
    for i, f in enumerate(ordered, 1):
        f['nr'] = i
    id2nr = {f['id']: f['nr'] for f in ordered}
    for f in ordered:
        for rel in f.get('related', []):
            rel['nr'] = id2nr.get(rel['id'])
    return f2, g2


def _scope_findings(findings, grouped, scope):
    """Filter findings/grouped op basis van de scope (all|critical_high|top3).
    counts blijven ongemoeid (samenvatting toont altijd de totalen)."""
    if scope == 'critical_high':
        sevs = ('critical', 'high')
        f2 = [f for f in findings if f['severity'] in sevs]
        g2 = [(lbl, [x for x in grp if x['severity'] in sevs]) for lbl, grp in grouped]
        return _renumber_scoped(f2, g2)
    if scope == 'top3':
        ordered = [x for _lbl, grp in grouped for x in grp]
        keep = {x['id'] for x in ordered[:3]}
        f2 = [f for f in findings if f['id'] in keep]
        g2 = [(lbl, [x for x in grp if x['id'] in keep]) for lbl, grp in grouped]
        return _renumber_scoped(f2, g2)
    return findings, grouped


def _auto_management_samenvatting(counts, total, taal):
    """Genereer een beknopte managementsamenvatting uit de severity-tellingen,
    als fallback wanneer er geen handmatige samenvatting is."""
    labels = _SEVERITY_LABELS_EN if taal == 'en' else _SEVERITY_LABELS
    delen = ['{} {}'.format(counts.get(s, 0), labels.get(s, s).lower())
             for s in ('critical', 'high', 'medium', 'low', 'none') if counts.get(s, 0)]
    urgent = bool(counts.get('critical') or counts.get('high'))
    if taal == 'en':
        opsomming = ', '.join(delen) if delen else 'no'
        tail = ('Immediate attention is required for the critical and high-risk findings.'
                if urgent else 'No critical or high-risk findings were identified.')
        return ('During this assessment {} finding(s) were identified ({}). {} '
                'This summary was generated automatically; refine it where needed.').format(total, opsomming, tail)
    opsomming = ', '.join(delen) if delen else 'geen'
    tail = ('De kritieke en hoge bevindingen vragen directe aandacht.'
            if urgent else 'Er zijn geen kritieke of hoge bevindingen aangetroffen.')
    return ('Tijdens dit onderzoek zijn {} bevinding(en) geïdentificeerd ({}). {} '
            'Deze samenvatting is automatisch gegenereerd; pas \'m desgewenst aan.').format(total, opsomming, tail)


def _severity_donut_svg(counts, taal, sev_labels, severity_colors):
    """Inline-SVG donut van de severity-verdeling (CSP-veilig, geen script)."""
    order = ('critical', 'high', 'medium', 'low', 'none')
    total = sum(int(counts.get(s, 0) or 0) for s in order)
    if not total:
        return ''
    cx = cy = 80
    r = 58
    circ = 2 * math.pi * r
    offset = 0.0
    segs = []
    for s in order:
        v = int(counts.get(s, 0) or 0)
        if not v:
            continue
        seg = (v / total) * circ
        segs.append(
            '<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{col}" '
            'stroke-width="22" stroke-dasharray="{seg:.2f} {rest:.2f}" '
            'stroke-dashoffset="{off:.2f}" transform="rotate(-90 {cx} {cy})"/>'.format(
                cx=cx, cy=cy, r=r, col=severity_colors.get(s, '#ccc'),
                seg=seg, rest=circ - seg, off=-offset))
        offset += seg
    label = 'findings' if taal == 'en' else 'bevindingen'
    parts = ['<div style="display:flex;gap:24px;align-items:center;flex-wrap:wrap;margin:12px 0">']
    parts.append('<svg width="160" height="160" viewBox="0 0 160 160" role="img" '
                 'aria-label="Severity-verdeling">')
    parts.extend(segs)
    parts.append('<text x="80" y="76" text-anchor="middle" font-size="26" '
                 'font-family="sans-serif" font-weight="bold">{}</text>'.format(total))
    parts.append('<text x="80" y="98" text-anchor="middle" font-size="11" '
                 'font-family="sans-serif" fill="#555">{}</text></svg>'.format(label))
    # Legenda
    parts.append('<div>')
    for s in order:
        v = int(counts.get(s, 0) or 0)
        if not v:
            continue
        parts.append('<div style="margin:2px 0"><span style="display:inline-block;width:12px;'
                     'height:12px;border-radius:2px;background:{};margin-right:6px"></span>'
                     '{} &mdash; {}</div>'.format(
                         severity_colors.get(s, '#ccc'), html_escape(sev_labels.get(s, s)), v))
    parts.append('</div></div>')
    return ''.join(parts)


# Hex-equivalenten van de LaTeX-grafiekkleuren (cgreen/camber/… uit rapport_latex.tex)
_CHART_HEX = {
    'cgreen': '#22C55E', 'camber': '#F59E0B', 'cred': '#EF4444',
    'cblue': '#3B82F6', 'cgray': '#94A3B8',
}
# Hex per severity (zelfde palet als de donut/key-findings)
_SEV_HEX = {
    'critical': '#800080', 'high': '#e60000', 'medium': '#f09600',
    'low': '#ffdc00', 'none': '#5bc0de',
}


def _hbar_chart_svg(items, aria='Staafdiagram'):
    """Horizontale staafgrafiek als CSP-veilige inline-SVG.

    items = [{'label': str, 'value': int, 'color': hexkleur}] (None wordt genegeerd).
    """
    items = [it for it in items if it]
    vals = [max(0, int(it.get('value', 0) or 0)) for it in items]
    if not items or (max(vals) if vals else 0) <= 0:
        return ''
    vmax = max(vals)
    row_h, gap, label_w, bar_w, pad = 24, 10, 150, 300, 8
    width = label_w + bar_w + 46
    height = pad * 2 + len(items) * (row_h + gap) - gap
    out = ['<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-label="{a}" '
           'font-family="sans-serif" style="max-width:100%;height:auto;margin:12px 0">'.format(
               w=width, h=height, a=html_escape(aria))]
    y = pad
    for it, v in zip(items, vals):
        w = (v / vmax) * bar_w if vmax else 0
        out.append('<text x="{x}" y="{y:.0f}" text-anchor="end" font-size="12" '
                   'fill="#333">{t}</text>'.format(
                       x=label_w - 8, y=y + row_h * 0.68, t=html_escape(str(it.get('label', '')))))
        out.append('<rect x="{x}" y="{y}" width="{w:.1f}" height="{h}" rx="3" fill="{c}"/>'.format(
            x=label_w, y=y, w=w, h=row_h, c=it.get('color', '#3B82F6')))
        out.append('<text x="{x:.1f}" y="{y:.0f}" font-size="12" font-weight="bold" '
                   'fill="#333">{v}</text>'.format(x=label_w + w + 6, y=y + row_h * 0.68, v=v))
        y += row_h + gap
    out.append('</svg>')
    return ''.join(out)


def _cvss_hist_svg(findings, taal='nl'):
    """Verticaal histogram van de CVSS-basisscoreverdeling (inline-SVG)."""
    hist = [0] * 10
    for f in findings:
        try:
            sc = float(f.get('basescore') or 0)
        except (TypeError, ValueError):
            sc = 0.0
        if sc > 0:
            hist[min(9, int(sc))] += 1
    if not any(hist):
        return ''
    hmax = max(hist)

    def _band(i):
        if i >= 9:
            return '#800080'
        if i >= 7:
            return '#e60000'
        if i >= 4:
            return '#f09600'
        if i >= 1:
            return '#ffdc00'
        return '#5bc0de'

    bar_w, gap, pad_l, pad_top, plot_h = 32, 8, 28, 14, 120
    base_y = pad_top + plot_h
    width = pad_l + 10 * (bar_w + gap) + 8
    height = base_y + 32
    title = 'CVSS base score distribution' if taal == 'en' else 'CVSS-basisscoreverdeling'
    out = ['<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-label="{a}" '
           'font-family="sans-serif" style="max-width:100%;height:auto;margin:12px 0">'.format(
               w=width, h=height, a=html_escape(title))]
    out.append('<line x1="{x}" y1="{y}" x2="{x2}" y2="{y}" stroke="#cbd5e1"/>'.format(
        x=pad_l - 4, y=base_y, x2=width - 4))
    for i in range(10):
        bh = (hist[i] / hmax) * plot_h if hmax else 0
        x = pad_l + i * (bar_w + gap)
        y = base_y - bh
        out.append('<rect x="{x}" y="{y:.1f}" width="{bw}" height="{bh:.1f}" rx="2" '
                   'fill="{c}"/>'.format(x=x, y=y, bw=bar_w, bh=bh, c=_band(i)))
        if hist[i]:
            out.append('<text x="{x:.0f}" y="{y:.0f}" text-anchor="middle" font-size="11" '
                       'font-weight="bold" fill="#333">{v}</text>'.format(
                           x=x + bar_w / 2, y=y - 4, v=hist[i]))
        out.append('<text x="{x:.0f}" y="{y}" text-anchor="middle" font-size="10" '
                   'fill="#777">{a}-{b}</text>'.format(x=x + bar_w / 2, y=base_y + 14, a=i, b=i + 1))
    out.append('<text x="{x:.0f}" y="{y}" text-anchor="middle" font-size="11" '
               'fill="#555">{t}</text>'.format(x=width / 2, y=height - 4, t=html_escape(title)))
    out.append('</svg>')
    return ''.join(out)


def _remediation_bar_svg(findings, taal='nl'):
    """Gestapelde horizontale balk van de remediation-statusverdeling (inline-SVG)."""
    cfg = [('open', 'cred'), ('in_progress', 'camber'), ('fixed', 'cblue'),
           ('verified', 'cgreen'), ('accepted', 'cgray')]
    lbl = ({'open': 'Open', 'in_progress': 'In progress', 'fixed': 'Fixed',
            'verified': 'Verified', 'accepted': 'Accepted'} if taal == 'en'
           else {'open': 'Open', 'in_progress': 'In behandeling', 'fixed': 'Opgelost',
                 'verified': 'Geverifieerd', 'accepted': 'Geaccepteerd'})
    remc = {}
    for f in findings:
        st = f.get('remediation_status', 'open') or 'open'
        remc[st] = remc.get(st, 0) + 1
    total = sum(remc.get(k, 0) for k, _ in cfg)
    if total <= 0:
        return ''
    bar_w, bar_h, pad = 440, 26, 8
    width = bar_w + pad * 2
    out = ['<div style="margin:12px 0">']
    out.append('<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-label="{a}" '
               'font-family="sans-serif" style="max-width:100%;height:auto">'.format(
                   w=width, h=bar_h + pad * 2, a=html_escape('Remediation-status')))
    x = pad
    for k, col in cfg:
        v = remc.get(k, 0)
        if v <= 0:
            continue
        seg = v / total * bar_w
        out.append('<rect x="{x:.1f}" y="{y}" width="{w:.1f}" height="{h}" fill="{c}"/>'.format(
            x=x, y=pad, w=seg, h=bar_h, c=_CHART_HEX[col]))
        if seg > 20:
            out.append('<text x="{x:.1f}" y="{y:.0f}" text-anchor="middle" font-size="12" '
                       'font-weight="bold" fill="#fff">{v}</text>'.format(
                           x=x + seg / 2, y=pad + bar_h * 0.68, v=v))
        x += seg
    out.append('</svg>')
    # Legenda
    out.append('<div style="margin-top:6px">')
    for k, col in cfg:
        v = remc.get(k, 0)
        if v <= 0:
            continue
        out.append('<span style="display:inline-block;margin:2px 12px 2px 0"><span '
                   'style="display:inline-block;width:12px;height:12px;border-radius:2px;'
                   'background:{c};margin-right:5px;vertical-align:middle"></span>{l} ({v})'
                   '</span>'.format(c=_CHART_HEX[col], l=html_escape(lbl[k]), v=v))
    out.append('</div></div>')
    return ''.join(out)


def _sla_timeline_svg(findings, taal='nl'):
    """Log-geschaalde hersteltijdlijn per bevinding (inline-SVG, severity-kleur)."""
    if not findings:
        return ''
    rows = []
    for f in findings:
        sev = f.get('severity', 'none')
        days, nl_lbl, en_lbl = _SLA_DAYS.get(sev, (90, '', ''))
        rows.append((str(f['nr']).zfill(3), days,
                     en_lbl if taal == 'en' else nl_lbl, _SEV_HEX.get(sev, '#5bc0de')))
    if not rows:
        return ''
    row_h, gap, label_w, bar_w, pad = 20, 6, 46, 300, 8
    width = label_w + bar_w + 130
    height = pad * 2 + len(rows) * (row_h + gap) - gap + 18
    dmax = math.log10(max(d for _, d, _, _ in rows) + 1) or 1
    title = 'Remediation timeline (log scale)' if taal == 'en' else 'Hersteltijdlijn (log-schaal)'
    out = ['<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-label="{a}" '
           'font-family="sans-serif" style="max-width:100%;height:auto;margin:12px 0">'.format(
               w=width, h=height, a=html_escape(title))]
    y = pad
    for nr, days, lbl, col in rows:
        w = (math.log10(days + 1) / dmax) * bar_w if dmax else 0
        out.append('<text x="{x}" y="{y:.0f}" text-anchor="end" font-size="11" '
                   'fill="#333">#{t}</text>'.format(x=label_w - 6, y=y + row_h * 0.72, t=nr))
        out.append('<rect x="{x}" y="{y}" width="{w:.1f}" height="{h}" rx="3" fill="{c}"/>'.format(
            x=label_w, y=y, w=max(w, 2), h=row_h, c=col))
        out.append('<text x="{x:.1f}" y="{y:.0f}" font-size="10" fill="#555">{l}</text>'.format(
            x=label_w + max(w, 2) + 6, y=y + row_h * 0.72, l=html_escape(lbl)))
        y += row_h + gap
    out.append('<text x="{x:.0f}" y="{y}" text-anchor="middle" font-size="11" '
               'fill="#555">{t}</text>'.format(x=width / 2, y=height - 4, t=html_escape(title)))
    out.append('</svg>')
    return ''.join(out)


def _killchain_flow_svg(taal='nl'):
    """Kill-chain-paden als horizontale flow (boxen + pijlen) in inline-SVG."""
    data = _chains_data()
    paths = [p for p in data.get('paths', []) if len(p) >= 2]
    if not paths:
        return ''
    names = {n['id']: n['naam'] for n in data.get('nodes', [])}
    box_w, box_h, gap_x, gap_y, pad = 128, 40, 34, 20, 8
    max_len = max(len(p) for p in paths)
    width = pad * 2 + max_len * box_w + (max_len - 1) * gap_x
    height = pad * 2 + len(paths) * (box_h + gap_y) - gap_y
    out = ['<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-label="{a}" '
           'font-family="sans-serif" style="max-width:100%;height:auto;margin:12px 0">'.format(
               w=width, h=height, a=html_escape('Kill chain'))]
    out.append('<defs><marker id="kcarr" markerWidth="8" markerHeight="8" refX="6" refY="3" '
               'orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="#475569"/></marker></defs>')
    y = pad
    for path in paths:
        x = pad
        prev_cx = None
        for nid in path:
            nm = names.get(nid, '') or ''
            if len(nm) > 18:
                nm = nm[:17] + '…'
            if prev_cx is not None:
                out.append('<line x1="{x1}" y1="{y}" x2="{x2:.0f}" y2="{y}" stroke="#475569" '
                           'stroke-width="1.5" marker-end="url(#kcarr)"/>'.format(
                               x1=prev_cx, y=y + box_h / 2, x2=x - 4))
            out.append('<rect x="{x}" y="{y}" width="{bw}" height="{bh}" rx="6" fill="#eef2ff" '
                       'stroke="#6366f1"/>'.format(x=x, y=y, bw=box_w, bh=box_h))
            out.append('<text x="{cx:.0f}" y="{ty:.0f}" text-anchor="middle" font-size="9" '
                       'fill="#4338ca" font-weight="bold">[{i}]</text>'.format(
                           cx=x + box_w / 2, ty=y + 14, i=str(nid).zfill(3)))
            out.append('<text x="{cx:.0f}" y="{ty:.0f}" text-anchor="middle" font-size="10" '
                       'fill="#333">{n}</text>'.format(cx=x + box_w / 2, ty=y + 30, n=html_escape(nm)))
            prev_cx = x + box_w
            x += box_w + gap_x
        y += box_h + gap_y
    out.append('</svg>')
    return ''.join(out)


# ---------------------------------------------------------------------------
# Begrippen- & afkortingenlijst, scope-beperkingen, bewijsregister en
# CVSS-vectordetail. Toegevoegd t.b.v. auditwaarde/leesbaarheid van de
# rapportage. Gedeeld over HTML-preview, DOCX/Markdown en LaTeX/PDF.
# ---------------------------------------------------------------------------

def _md_escape_cell(v):
    """Markdown-tabelcel: pipe ontsnappen en nieuwe regels platslaan."""
    return str(v if v is not None else '').replace('|', '\\|').replace('\n', ' ').strip()


# Vaste begrippen-/afkortingenlijst (term, NL-definitie, EN-definitie). Bewust
# kort en normatief; dit zijn de termen die in vrijwel elk rapport voorkomen.
_GLOSSARY = (
    ('CVSS', 'Common Vulnerability Scoring System — gestandaardiseerde methode '
     '(hier v4.0) om de ernst van een kwetsbaarheid uit te drukken in een score 0,0–10,0.',
     'Common Vulnerability Scoring System — standardised method (here v4.0) to '
     'express the severity of a vulnerability as a score from 0.0 to 10.0.'),
    ('CVE', 'Common Vulnerabilities and Exposures — unieke, publieke identifier '
     'voor een bekende kwetsbaarheid.',
     'Common Vulnerabilities and Exposures — unique public identifier for a '
     'publicly known vulnerability.'),
    ('CWE', 'Common Weakness Enumeration — classificatie van het onderliggende '
     'type zwakte (bijv. CWE-79 voor cross-site scripting).',
     'Common Weakness Enumeration — classification of the underlying weakness '
     'type (e.g. CWE-79 for cross-site scripting).'),
    ('OWASP Top 10', 'Breed gedragen lijst van de tien meest kritieke risico’s '
     'voor webapplicaties, uitgegeven door het Open Worldwide Application '
     'Security Project.',
     'Widely adopted list of the ten most critical web application security '
     'risks, published by the Open Worldwide Application Security Project.'),
    ('NCSC', 'Nationaal Cyber Security Centrum — Nederlandse autoriteit die '
     'beveiligingsrichtlijnen (o.a. voor webapplicaties en TLS) publiceert.',
     'Dutch National Cyber Security Centre — authority that publishes security '
     'guidelines (e.g. for web applications and TLS).'),
    ('ISO 27001', 'Internationale norm voor een managementsysteem voor '
     'informatiebeveiliging (ISMS), inclusief de beheersmaatregelen uit bijlage A.',
     'International standard for an information security management system '
     '(ISMS), including the Annex A controls.'),
    ('BIO', 'Baseline Informatiebeveiliging Overheid — het normenkader voor '
     'informatiebeveiliging bij de Nederlandse overheid (gebaseerd op ISO 27001/27002).',
     'Dutch Government Information Security Baseline, based on ISO 27001/27002.'),
    ('NIS2', 'EU-richtlijn (Network and Information Security 2) met verplichtingen '
     'voor cyberbeveiliging en incidentmelding voor essentiële en belangrijke entiteiten.',
     'EU Network and Information Security 2 directive, imposing cybersecurity and '
     'incident-reporting obligations on essential and important entities.'),
    ('SLA', 'Service Level Agreement — hier: de afgesproken maximale hersteltermijn '
     'per ernstniveau (bijv. kritiek binnen 1 dag).',
     'Service Level Agreement — here: the agreed maximum remediation deadline per '
     'severity level (e.g. critical within 1 day).'),
    ('TLP', 'Traffic Light Protocol — markering (RED/AMBER/GREEN/CLEAR) die '
     'aangeeft met wie dit document gedeeld mag worden.',
     'Traffic Light Protocol — marking (RED/AMBER/GREEN/CLEAR) indicating with '
     'whom this document may be shared.'),
    ('PoC', 'Proof of Concept — reproduceerbaar bewijs dat een kwetsbaarheid '
     'daadwerkelijk misbruikt kan worden.',
     'Proof of Concept — reproducible evidence that a vulnerability can actually '
     'be exploited.'),
    ('Kans', 'De waarschijnlijkheid dat een kwetsbaarheid in de praktijk wordt '
     'misbruikt (as van de risicomatrix, 1–5).',
     'The likelihood that a vulnerability is exploited in practice (axis of the '
     'risk matrix, 1–5).'),
    ('Impact', 'De schade voor de organisatie wanneer een kwetsbaarheid wordt '
     'misbruikt (as van de risicomatrix, 1–5).',
     'The damage to the organisation if a vulnerability is exploited (axis of the '
     'risk matrix, 1–5).'),
    ('Risico', 'De combinatie van kans en impact; bepaalt de prioriteit van '
     'herstel (kans × impact).',
     'The combination of likelihood and impact; determines remediation priority '
     '(likelihood × impact).'),
    ('Kill chain', 'Keten van opeenvolgende stappen waarmee een aanvaller via '
     'meerdere bevindingen een einddoel bereikt.',
     'Chain of consecutive steps by which an attacker reaches an end goal through '
     'multiple findings.'),
    ('Remediation', 'Herstelmaatregel: de actie die een bevinding structureel '
     'oplost of het risico aantoonbaar verlaagt.',
     'Remediation: the action that structurally resolves a finding or demonstrably '
     'reduces the risk.'),
    ('Retest', 'Hertest na herstel om vast te stellen of een eerder gerapporteerde '
     'bevinding daadwerkelijk is opgelost.',
     'Retest after remediation to confirm whether a previously reported finding '
     'has actually been resolved.'),
    ('Assumed breach', 'Teststartpunt waarbij wordt aangenomen dat de aanvaller '
     'al initiële toegang heeft, om de verdediging in de diepte te beoordelen.',
     'Test starting point assuming the attacker already has initial access, to '
     'assess defence in depth.'),
    ('Blackbox / Greybox / Whitebox', 'Toegangsniveau van de tester: geen '
     'voorkennis (black), gedeeltelijke kennis/credentials (grey) of volledige '
     'kennis en broncode (white).',
     'Tester’s level of access: no prior knowledge (black), partial '
     'knowledge/credentials (grey) or full knowledge and source code (white).'),
    ('DigiD-normenkader', 'Verplichte beveiligingsnormen voor aansluitingen op '
     'DigiD; knock-out-criteria moeten alle met een voldoende worden afgesloten.',
     'Mandatory security standards for DigiD connections; the knock-out criteria '
     'must all be met with a pass.'),
)


def _begrippen_rows(taal='nl'):
    i = 2 if taal == 'en' else 1
    return [{'term': g[0], 'definitie': g[i]} for g in _GLOSSARY]


def _append_begrippen_html(parts, taal='nl'):
    parts.append('<h2>{}</h2>'.format(
        'Glossary &amp; abbreviations' if taal == 'en' else 'Begrippen- en afkortingenlijst'))
    parts.append('<table><tr><th style="width:24%">{}</th><th>{}</th></tr>'.format(
        'Term' if taal == 'en' else 'Begrip',
        'Description' if taal == 'en' else 'Omschrijving'))
    for r in _begrippen_rows(taal):
        parts.append('<tr><td><strong>{}</strong></td><td>{}</td></tr>'.format(
            html_escape(r['term']), html_escape(r['definitie'])))
    parts.append('</table>')


def _begrippen_md_lines(taal='nl'):
    out = ['', '## {}'.format(
        'Glossary & abbreviations' if taal == 'en' else 'Begrippen- en afkortingenlijst'), '']
    out.append('| {} | {} |'.format('Term' if taal == 'en' else 'Begrip',
                                     'Description' if taal == 'en' else 'Omschrijving'))
    out.append('| --- | --- |')
    for r in _begrippen_rows(taal):
        out.append('| **{}** | {} |'.format(
            _md_escape_cell(r['term']), _md_escape_cell(r['definitie'])))
    out.append('')
    return out


# ---------------------------------------------------------------------------
# Scope-beperkingen & aannames
# ---------------------------------------------------------------------------
def _beperkingen_lines(taal, testtype='pentest', testscope='', test_start='',
                       test_end='', rapport_omgeving=''):
    """Standaard beperkingen/aannames bij een beveiligingsonderzoek, aangevuld
    met de concrete scope/periode van deze opdracht."""
    en = (taal == 'en')
    concrete = []
    if testscope:
        concrete.append(
            ('The assessment was performed as a {} test.'.format(testscope)) if en
            else ('Het onderzoek is uitgevoerd als {}-test.'.format(testscope)))
    if test_start or test_end:
        per = '{} – {}'.format(test_start or '?', test_end or '?')
        concrete.append(('Testing took place in the period {}.'.format(per)) if en
                        else ('Het testwerk vond plaats in de periode {}.'.format(per)))
    if rapport_omgeving:
        concrete.append(('The tested environment was: {}.'.format(rapport_omgeving)) if en
                        else ('De geteste omgeving betrof: {}.'.format(rapport_omgeving)))
    standaard = ([
        'This report is a point-in-time snapshot: the findings reflect the state '
        'of the systems during the test period and say nothing about changes made '
        'afterwards.',
        'The assessment is scope-bound: only the systems, targets and functionality '
        'explicitly agreed upon were examined. Everything outside that scope was not '
        'assessed.',
        'The absence of findings is not a guarantee of completeness: no security '
        'assessment can prove that a system is free of vulnerabilities.',
        'No denial-of-service or destructive tests were performed unless explicitly '
        'agreed in writing.',
        'Results depend on the information, accounts and access provided; incomplete '
        'or incorrect information can lead to findings being missed.',
        'A test or acceptance environment may differ from production, which can '
        'affect the representativeness of the findings.',
    ] if en else [
        'Dit rapport is een momentopname: de bevindingen weerspiegelen de toestand '
        'van de systemen tijdens de testperiode en zeggen niets over wijzigingen die '
        'daarna zijn doorgevoerd.',
        'Het onderzoek is scope-gebonden: alleen de expliciet overeengekomen systemen, '
        'doelen en functionaliteit zijn onderzocht. Alles buiten die scope is niet '
        'beoordeeld.',
        'De afwezigheid van bevindingen is geen garantie op volledigheid: geen enkel '
        'beveiligingsonderzoek kan aantonen dat een systeem vrij is van kwetsbaarheden.',
        'Er zijn geen denial-of-service- of destructieve tests uitgevoerd, tenzij dit '
        'schriftelijk is overeengekomen.',
        'De resultaten zijn afhankelijk van de verstrekte informatie, accounts en '
        'toegang; onvolledige of onjuiste informatie kan ertoe leiden dat bevindingen '
        'worden gemist.',
        'Een test- of acceptatieomgeving kan afwijken van productie, wat de '
        'representativiteit van de bevindingen kan beïnvloeden.',
    ])
    return concrete + standaard


def _append_beperkingen_html(parts, taal, **kw):
    parts.append('<h2>{}</h2>'.format(
        'Scope limitations &amp; assumptions' if taal == 'en'
        else 'Beperkingen en aannames'))
    parts.append('<ul>')
    for ln in _beperkingen_lines(taal, **kw):
        parts.append('<li>{}</li>'.format(html_escape(ln)))
    parts.append('</ul>')


def _beperkingen_md_lines(taal, **kw):
    out = ['', '## {}'.format(
        'Scope limitations & assumptions' if taal == 'en' else 'Beperkingen en aannames'), '']
    for ln in _beperkingen_lines(taal, **kw):
        out.append('- {}'.format(_md_escape_cell(ln)))
    out.append('')
    return out


# ---------------------------------------------------------------------------
# Bewijsregister: geconsolideerde tabel van alle bewijsbestanden + SHA-256,
# zodat een auditor de integriteit van het aangeleverde bewijs kan verifiëren.
# ---------------------------------------------------------------------------
def _evidence_register(findings):
    rows = []
    for f in findings:
        for ev in f.get('evidence', []):
            h = ev.get('sha256') or ''
            if not h:
                continue
            rows.append({
                'id': str(f['nr']).zfill(3),
                'titel': f.get('titel', '') or '',
                'caption': ev.get('caption', '') or '',
                'file': os.path.basename(ev.get('path', '') or ''),
                'sha256': h,
            })
    return rows


def _append_bewijsregister_html(parts, findings, taal='nl'):
    rows = _evidence_register(findings)
    if not rows:
        return
    en = (taal == 'en')
    parts.append('<h2>{}</h2>'.format('Evidence register' if en else 'Bewijsregister'))
    parts.append('<p>{}</p>'.format(
        'Each evidence file is listed with its SHA-256 hash so that its integrity '
        'can be independently verified.' if en else
        'Elk bewijsbestand is opgenomen met zijn SHA-256-hash, zodat de integriteit '
        'onafhankelijk geverifieerd kan worden.'))
    parts.append('<table><tr><th>ID</th><th>{}</th><th>{}</th><th>SHA-256</th></tr>'.format(
        'Evidence' if en else 'Bewijs', 'File' if en else 'Bestand'))
    for r in rows:
        parts.append('<tr><td><a href="#bev-{0}">{0}</a></td><td>{1}</td><td>{2}</td>'
                     '<td style="font-family:monospace;font-size:11px;word-break:break-all">{3}</td></tr>'.format(
                         r['id'], html_escape(r['caption']), html_escape(r['file']),
                         html_escape(r['sha256'])))
    parts.append('</table>')


def _bewijsregister_md_lines(findings, taal='nl'):
    rows = _evidence_register(findings)
    if not rows:
        return []
    en = (taal == 'en')
    out = ['', '## {}'.format('Evidence register' if en else 'Bewijsregister'), '',
           ('Each evidence file is listed with its SHA-256 hash so that its integrity '
            'can be independently verified.' if en else
            'Elk bewijsbestand is opgenomen met zijn SHA-256-hash, zodat de integriteit '
            'onafhankelijk geverifieerd kan worden.'), '']
    out.append('| ID | {} | {} | SHA-256 |'.format(
        'Evidence' if en else 'Bewijs', 'File' if en else 'Bestand'))
    out.append('| --- | --- | --- | --- |')
    for r in rows:
        out.append('| {} | {} | {} | `{}` |'.format(
            r['id'], _md_escape_cell(r['caption']), _md_escape_cell(r['file']), r['sha256']))
    out.append('')
    return out


# ---------------------------------------------------------------------------
# CVSS-vectordetail: ontleedt de (base) CVSS 4.0-vector naar leesbare assen,
# zodat de scoretoekenning transparant en auditbaar is. Omgevings-/threat-
# metrieken worden getoond zodra ze in de vector aanwezig zijn.
# ---------------------------------------------------------------------------
_CVSS_METRIC_NAMES = {
    'AV': ('Aanvalsvector', 'Attack Vector'),
    'AC': ('Aanvalscomplexiteit', 'Attack Complexity'),
    'AT': ('Aanvalsvereisten', 'Attack Requirements'),
    'PR': ('Vereiste rechten', 'Privileges Required'),
    'UI': ('Gebruikersinteractie', 'User Interaction'),
    'VC': ('Vertrouwelijkheid', 'Confidentiality'),
    'VI': ('Integriteit', 'Integrity'),
    'VA': ('Beschikbaarheid', 'Availability'),
    'SC': ('Vertrouwelijkheid (vervolgsysteem)', 'Confidentiality (subsequent)'),
    'SI': ('Integriteit (vervolgsysteem)', 'Integrity (subsequent)'),
    'SA': ('Beschikbaarheid (vervolgsysteem)', 'Availability (subsequent)'),
    'E':  ('Exploitatie-volwassenheid', 'Exploit Maturity'),
    'CR': ('Vertrouwelijkheidseis', 'Confidentiality Requirement'),
    'IR': ('Integriteitseis', 'Integrity Requirement'),
    'AR': ('Beschikbaarheidseis', 'Availability Requirement'),
}
_CVSS_VALUE_NAMES = {
    'AV': {'N': ('Netwerk', 'Network'), 'A': ('Aangrenzend', 'Adjacent'),
           'L': ('Lokaal', 'Local'), 'P': ('Fysiek', 'Physical')},
    'AC': {'L': ('Laag', 'Low'), 'H': ('Hoog', 'High')},
    'AT': {'N': ('Geen', 'None'), 'P': ('Aanwezig', 'Present')},
    'PR': {'N': ('Geen', 'None'), 'L': ('Laag', 'Low'), 'H': ('Hoog', 'High')},
    'UI': {'N': ('Geen', 'None'), 'P': ('Passief', 'Passive'), 'A': ('Actief', 'Active')},
    '_impact': {'H': ('Hoog', 'High'), 'L': ('Laag', 'Low'), 'N': ('Geen', 'None')},
    'E':  {'A': ('Aangetoond', 'Attacked'), 'P': ('PoC', 'Proof-of-Concept'),
           'U': ('Onbewezen', 'Unreported'), 'X': ('N.v.t.', 'Not defined')},
    '_req': {'H': ('Hoog', 'High'), 'M': ('Middel', 'Medium'), 'L': ('Laag', 'Low'),
             'X': ('N.v.t.', 'Not defined')},
}
# Volgorde waarin assen worden getoond.
_CVSS_ORDER = ('AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA',
               'E', 'CR', 'IR', 'AR')


def _cvss_value_label(metric, val, taal):
    i = 1 if taal == 'en' else 0
    if metric in ('VC', 'VI', 'VA', 'SC', 'SI', 'SA'):
        tbl = _CVSS_VALUE_NAMES['_impact']
    elif metric in ('CR', 'IR', 'AR'):
        tbl = _CVSS_VALUE_NAMES['_req']
    else:
        tbl = _CVSS_VALUE_NAMES.get(metric, {})
    pair = tbl.get(val)
    return pair[i] if pair else val


def _decode_cvss_vector(vector, taal='nl'):
    """Geeft (versie, [(as-label, waarde-label)], heeft_omgeving) terug."""
    if not vector:
        return '', [], False
    parts = str(vector).split('/')
    version = ''
    metrics = {}
    for p in parts:
        if ':' not in p:
            continue
        k, v = p.split(':', 1)
        if k == 'CVSS':
            version = v
            continue
        metrics[k] = v
    i = 1 if taal == 'en' else 0
    out = []
    has_env = any(k in metrics for k in ('E', 'CR', 'IR', 'AR'))
    for k in _CVSS_ORDER:
        if k not in metrics:
            continue
        if k in ('E', 'CR', 'IR', 'AR') and metrics[k] == 'X':
            continue
        name = _CVSS_METRIC_NAMES.get(k, (k, k))[i]
        out.append((name, _cvss_value_label(k, metrics[k], taal)))
    return version, out, has_env


def _cvss_detail_rows(findings, taal='nl'):
    rows = []
    for f in findings:
        vec = f.get('cvss_vector') or ''
        version, decoded, has_env = _decode_cvss_vector(vec, taal)
        if not decoded:
            continue
        summary = ' · '.join('{}: {}'.format(a, b) for a, b in decoded)
        rows.append({
            'id': str(f['nr']).zfill(3),
            'titel': f.get('titel', '') or '',
            'score': str(f.get('basescore', '') or ''),
            'version': version,
            'vector': vec,
            'summary': summary,
            'decoded': decoded,
            'has_env': has_env,
        })
    return rows


def _append_cvss_detail_html(parts, findings, taal='nl'):
    rows = _cvss_detail_rows(findings, taal)
    if not rows:
        return
    en = (taal == 'en')
    parts.append('<h2>{}</h2>'.format(
        'CVSS vector breakdown' if en else 'CVSS-vectordetail'))
    parts.append('<p>{}</p>'.format(
        'Decoding of the CVSS base vector per finding, so the assigned score is '
        'transparent and auditable.' if en else
        'Ontleding van de CVSS-base-vector per bevinding, zodat de toegekende score '
        'transparant en auditbaar is.'))
    parts.append('<table><tr><th>ID</th><th>{}</th><th>CVSS</th><th>{}</th></tr>'.format(
        'Finding' if en else 'Bevinding', 'Metrics' if en else 'Metrieken'))
    for r in rows:
        parts.append('<tr><td><a href="#bev-{0}">{0}</a></td><td>{1}</td>'
                     '<td>{2}</td><td style="font-size:12px">{3}</td></tr>'.format(
                         r['id'], html_escape(r['titel']), html_escape(r['score']),
                         html_escape(r['summary'])))
    parts.append('</table>')


def _cvss_detail_md_lines(findings, taal='nl'):
    rows = _cvss_detail_rows(findings, taal)
    if not rows:
        return []
    en = (taal == 'en')
    out = ['', '## {}'.format('CVSS vector breakdown' if en else 'CVSS-vectordetail'), '',
           ('Decoding of the CVSS base vector per finding, so the assigned score is '
            'transparent and auditable.' if en else
            'Ontleding van de CVSS-base-vector per bevinding, zodat de toegekende score '
            'transparant en auditbaar is.'), '']
    out.append('| ID | {} | CVSS | {} |'.format(
        'Finding' if en else 'Bevinding', 'Metrics' if en else 'Metrieken'))
    out.append('| --- | --- | --- | --- |')
    for r in rows:
        out.append('| {} | {} | {} | {} |'.format(
            r['id'], _md_escape_cell(r['titel']), _md_escape_cell(r['score']),
            _md_escape_cell(r['summary'])))
    out.append('')
    return out


# ---------------------------------------------------------------------------
# PNG-grafieken (PIL) voor DOCX-grafiekpariteit. De DOCX-route gaat via pandoc
# en kan geen inline-SVG tonen; daarom tekenen we de samenvattingsvisuals als
# PNG en verwijzen we ernaar vanuit de Markdown (![..](file.png)). Valt stil
# terug op niets als Pillow niet beschikbaar is.
# ---------------------------------------------------------------------------
def _png_font(size):
    try:
        from PIL import ImageFont
    except Exception:
        return None
    for p in (
        '/System/Library/Fonts/Supplemental/Arial.ttf',
        '/System/Library/Fonts/Helvetica.ttc',
        '/Library/Fonts/Arial.ttf',
        '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
        '/usr/share/fonts/dejavu/DejaVuSans.ttf',
    ):
        try:
            return ImageFont.truetype(p, size)
        except Exception:
            continue
    try:
        return ImageFont.load_default()
    except Exception:
        return None


def _png_text_w(draw, text, font):
    try:
        b = draw.textbbox((0, 0), text, font=font)
        return b[2] - b[0]
    except Exception:
        try:
            return draw.textlength(text, font=font)
        except Exception:
            return len(text) * 7


def _png_hbar(items, path, title=''):
    """Horizontale staafgrafiek. items=[{label,value,color}] (color = hex)."""
    try:
        from PIL import Image, ImageDraw
    except Exception:
        return False
    S = 2  # supersampling voor scherpte
    W = 900 * S
    row_h = 40 * S
    pad = 16 * S
    top = (pad + 28 * S) if title else pad
    H = top + len(items) * row_h + pad
    label_w = 220 * S
    val_w = 70 * S
    bar_x = pad + label_w
    bar_max = W - pad - val_w - bar_x
    img = Image.new('RGB', (W, H), '#ffffff')
    d = ImageDraw.Draw(img)
    f = _png_font(15 * S)
    fb = _png_font(16 * S)
    if title and fb:
        d.text((pad, pad), title, fill='#111827', font=fb)
    mx = max([float(i.get('value', 0) or 0) for i in items] + [1])
    y = top
    for it in items:
        v = float(it.get('value', 0) or 0)
        col = it.get('color', '#3B82F6')
        lbl = str(it.get('label', ''))
        if f:
            d.text((pad, y + row_h // 2 - 9 * S), lbl, fill='#374151', font=f)
        bw = int(bar_max * (v / mx)) if mx else 0
        bh = 22 * S
        by = y + (row_h - bh) // 2
        d.rectangle([bar_x, by, bar_x + max(bw, 2 * S), by + bh], fill=col)
        if f:
            d.text((bar_x + max(bw, 2 * S) + 8 * S, y + row_h // 2 - 9 * S),
                   str(int(v)) if v == int(v) else str(v), fill='#111827', font=f)
        y += row_h
    try:
        img = img.resize((W // S, H // S), Image.LANCZOS)
        img.save(path)
        return True
    except Exception:
        return False


def _png_vhist(bins, path, title='', max_value=None):
    """Verticale histogram. bins=[{label,value,color}]."""
    try:
        from PIL import Image, ImageDraw
    except Exception:
        return False
    S = 2
    W = 900 * S
    H = 340 * S
    pad = 16 * S
    top = (pad + 28 * S) if title else pad
    axis_b = H - pad - 24 * S
    axis_l = pad + 28 * S
    img = Image.new('RGB', (W, H), '#ffffff')
    d = ImageDraw.Draw(img)
    f = _png_font(13 * S)
    fb = _png_font(16 * S)
    if title and fb:
        d.text((pad, pad), title, fill='#111827', font=fb)
    n = len(bins) or 1
    plot_w = W - pad - axis_l
    gap = 8 * S
    bw = (plot_w - (n - 1) * gap) / n
    mx = max_value or max([float(b.get('value', 0) or 0) for b in bins] + [1])
    # as-lijn
    d.line([axis_l, top, axis_l, axis_b], fill='#9ca3af', width=1 * S)
    d.line([axis_l, axis_b, W - pad, axis_b], fill='#9ca3af', width=1 * S)
    x = axis_l + gap
    for b in bins:
        v = float(b.get('value', 0) or 0)
        bh = int((axis_b - top) * (v / mx)) if mx else 0
        col = b.get('color', '#3B82F6')
        d.rectangle([x, axis_b - bh, x + bw, axis_b], fill=col)
        if f:
            lbl = str(b.get('label', ''))
            tw = _png_text_w(d, lbl, f)
            d.text((x + bw / 2 - tw / 2, axis_b + 4 * S), lbl, fill='#374151', font=f)
            if v:
                vs = str(int(v))
                tw2 = _png_text_w(d, vs, f)
                d.text((x + bw / 2 - tw2 / 2, axis_b - bh - 16 * S), vs,
                       fill='#111827', font=f)
        x += bw + gap
    try:
        img = img.resize((W // S, H // S), Image.LANCZOS)
        img.save(path)
        return True
    except Exception:
        return False


def _write_summary_charts(findings, counts, taal, dest_dir):
    """Genereer de samenvattings-PNG's voor DOCX. Geeft een lijst
    (bijschrift, bestandsnaam) terug; leeg als Pillow ontbreekt of faalt."""
    try:
        from PIL import Image  # noqa: F401
    except Exception:
        return []
    en = (taal == 'en')
    sev_lbls = _SEVERITY_LABELS_EN if en else _SEVERITY_LABELS
    out = []

    # 1) Verdeling naar ernst
    sev_items = [{'label': sev_lbls[s], 'value': counts.get(s, 0),
                  'color': _SEV_HTML_BG[s]}
                 for s in ('critical', 'high', 'medium', 'low', 'none')
                 if counts.get(s, 0)]
    if sev_items:
        fn = 'chart_severity.png'
        if _png_hbar(sev_items, os.path.join(dest_dir, fn)):
            out.append(('Severity distribution' if en else 'Verdeling naar ernst', fn))

    # 2) CVSS-scoreverdeling (bins 0..9, bandkleur)
    hist = [0] * 10
    for f in findings:
        try:
            sc = float(f.get('basescore') or 0)
        except (TypeError, ValueError):
            sc = 0.0
        if sc > 0:
            hist[min(9, int(sc))] += 1
    if any(hist):
        def _band(i):
            if i >= 9:
                return '#800080'
            if i >= 7:
                return '#e60000'
            if i >= 4:
                return '#f09600'
            if i >= 1:
                return '#ffdc00'
            return '#5bc0de'
        bins = [{'label': str(i), 'value': hist[i], 'color': _band(i)}
                for i in range(10)]
        fn = 'chart_cvss.png'
        if _png_vhist(bins, os.path.join(dest_dir, fn)):
            out.append(('CVSS score distribution' if en else 'CVSS-scoreverdeling', fn))

    # 3) Remediation-status
    _rem_cfg = [('open', '#EF4444'), ('in_progress', '#F59E0B'), ('fixed', '#3B82F6'),
                ('verified', '#22C55E'), ('accepted', '#94A3B8')]
    _rem_lbl = ({'open': 'Open', 'in_progress': 'In progress', 'fixed': 'Fixed',
                 'verified': 'Verified', 'accepted': 'Accepted'} if en
                else {'open': 'Open', 'in_progress': 'In behandeling', 'fixed': 'Opgelost',
                      'verified': 'Geverifieerd', 'accepted': 'Geaccepteerd'})
    remc = {}
    for f in findings:
        st = f.get('remediation_status', 'open') or 'open'
        remc[st] = remc.get(st, 0) + 1
    rem_items = [{'label': _rem_lbl[k], 'value': remc.get(k, 0), 'color': c}
                 for k, c in _rem_cfg if remc.get(k, 0)]
    if rem_items:
        fn = 'chart_remediation.png'
        if _png_hbar(rem_items, os.path.join(dest_dir, fn)):
            out.append(('Remediation status' if en else 'Remediation-status', fn))

    return out


# ---------------------------------------------------------------------------
# Retest-voortgang: delta/trend-weergave op basis van het retest_status-veld.
# Toont of eerder gerapporteerde bevindingen inmiddels (her)getest en opgelost
# zijn. Verschijnt alleen wanneer er retest-gegevens zijn vastgelegd.
# ---------------------------------------------------------------------------
_RETEST_ORDER = ('retested_fixed', 'retested_open', 'pending_retest', 'not_applicable')
_RETEST_TEX_COLOR = {
    'retested_fixed': 'cgreen', 'retested_open': 'cred',
    'pending_retest': 'camber', 'not_applicable': 'cgray',
}


def _retest_progress(findings, taal='nl'):
    """Tel bevindingen per retest_status. Geeft (rows, open_rows, heeft_data).
    rows=[{key,label,value,hex,tex}], open_rows=[{id,titel}] voor nog-open."""
    rated = [f for f in findings if (f.get('retest_status') or '') in _RETEST_LABELS]
    # Alleen tonen bij daadwerkelijke retest-activiteit: puur 'not_applicable'
    # (de standaardwaarde) is geen zinvolle voortgang.
    if not rated or all(f['retest_status'] == 'not_applicable' for f in rated):
        return [], [], False
    i = 1 if taal == 'en' else 0
    tally = {}
    for f in rated:
        st = f['retest_status']
        tally[st] = tally.get(st, 0) + 1
    rows = []
    for st in _RETEST_ORDER:
        if tally.get(st, 0) <= 0:
            continue
        lbl = _RETEST_LABELS[st]
        rows.append({'key': st, 'label': lbl[i], 'value': tally[st],
                     'hex': lbl[2], 'tex': _RETEST_TEX_COLOR.get(st, 'cgray')})
    open_rows = [{'id': str(f['nr']).zfill(3), 'titel': f.get('titel', '') or ''}
                 for f in rated if f.get('retest_status') == 'retested_open']
    return rows, open_rows, True


def _retest_intro(taal, total):
    return ('Progress of previously reported findings, based on retest results '
            'across {} assessed findings.'.format(total) if taal == 'en' else
            'Voortgang van eerder gerapporteerde bevindingen, op basis van '
            'retestresultaten over {} beoordeelde bevindingen.'.format(total))


def _append_retest_progress_html(parts, findings, taal='nl'):
    rows, open_rows, ok = _retest_progress(findings, taal)
    if not ok:
        return
    en = (taal == 'en')
    parts.append('<h2>{}</h2>'.format('Retest progress' if en else 'Retest-voortgang'))
    parts.append('<p>{}</p>'.format(html_escape(
        _retest_intro(taal, sum(r['value'] for r in rows)))))
    parts.append(_hbar_chart_svg(
        [{'label': r['label'], 'value': r['value'], 'color': r['hex']} for r in rows],
        aria='Retest progress' if en else 'Retest-voortgang'))
    parts.append('<table><tr><th>{}</th><th>{}</th></tr>'.format(
        'Status', 'Count' if en else 'Aantal'))
    for r in rows:
        parts.append('<tr><td><span class="severity-bar" style="background:{}"></span>{}</td>'
                     '<td>{}</td></tr>'.format(r['hex'], html_escape(r['label']), r['value']))
    parts.append('</table>')
    if open_rows:
        parts.append('<p><strong>{}</strong></p>'.format(
            'Still open after retest:' if en else 'Nog open na retest:'))
        parts.append('<ul>')
        for o in open_rows:
            parts.append('<li><a href="#bev-{0}">{0}</a> &mdash; {1}</li>'.format(
                o['id'], html_escape(o['titel'])))
        parts.append('</ul>')


def _retest_progress_md_lines(findings, taal='nl'):
    rows, open_rows, ok = _retest_progress(findings, taal)
    if not ok:
        return []
    en = (taal == 'en')
    out = ['', '## {}'.format('Retest progress' if en else 'Retest-voortgang'), '',
           _retest_intro(taal, sum(r['value'] for r in rows)), '']
    out.append('| Status | {} |'.format('Count' if en else 'Aantal'))
    out.append('| --- | --- |')
    for r in rows:
        out.append('| {} | {} |'.format(_md_escape_cell(r['label']), r['value']))
    out.append('')
    if open_rows:
        out.append('**{}**'.format('Still open after retest:' if en else 'Nog open na retest:'))
        out.append('')
        for o in open_rows:
            out.append('- [{0}] {1}'.format(o['id'], _md_escape_cell(o['titel'])))
        out.append('')
    return out


def _generate_html_preview(findings, grouped, counts, titel, auteur, subtitel, datum, classificatie, is_draft, notes=None, tlp_bg='#FF2B2B', tlp_fg='#ffffff', management_samenvatting='', testtype='pentest', testscope='blackbox', testscopes=None, legsup_startpunt='', legsup_privileges='', legsup_informatie='', scenarios=None, taal='nl', rapport_roe='', test_start='', test_end='', variant='detailed', rapport_versie='', rapport_versie_status='concept', scope_targets=None, checklists=None, digid_knockout=None, key_findings=None, algeheel_beeld='', sections=None, findings_scope=None, rapport_omgeving='', section_order=None, rapport_project='', rapport_contact='', rapport_revisies=None, rapport_distributie=None):
    """Genereer HTML preview van het rapport."""
    t = _T.get(taal, _T['nl'])
    sev_labels = _SEVERITY_LABELS_EN if taal == 'en' else _SEVERITY_LABELS
    severity_colors = {
        'critical': '#800080', 'high': '#e60000', 'medium': '#f09600',
        'low': '#ffdc00', 'none': '#5bc0de',
    }
    # Secties + findings-scope bepalen (val terug op de ingebouwde variant)
    if sections is None:
        _base = _BUILTIN_VARIANTS.get(variant, _BUILTIN_VARIANTS['detailed'])
        sections = _base['sections']
        if findings_scope is None:
            findings_scope = _base['findings_scope']
    if findings_scope is None:
        findings_scope = 'all'

    def _sec(k):
        return sections.get(k, True)

    findings, grouped = _scope_findings(findings, grouped, findings_scope)
    parts = ['<html><head><style>',
             'body{font-family:sans-serif;max-width:900px;margin:0 auto;padding:20px}',
             'pre{background:#f0f0f0;padding:10px;overflow-x:auto}',
             'img{max-width:100%}',
             'table{width:100%;border-collapse:collapse;margin:1em 0}',
             'th,td{border:1px solid #ccc;padding:6px 10px;text-align:left}',
             'th{background:#154273;color:#fff}',
             '.severity-bar{width:4px;display:inline-block;height:1em;margin-right:6px}',
             '.finding{border-left:4px solid #ccc;padding:12px;margin:12px 0}',
             '.tlp-badge{display:inline-block;padding:2px 10px;border-radius:4px;font-weight:bold;font-size:0.9em}',
             '</style></head><body>']

    # Titel + versie + TLP badge
    parts.append('<h1>{}</h1>'.format(html_escape(titel)))
    parts.append('<p><strong>{}</strong></p>'.format(html_escape(subtitel)))
    if rapport_versie:
        _vs_labels = {'concept': 'Concept', 'definitief': 'Definitief', 'herzien': 'Herzien'}
        _vs_label = _vs_labels.get(rapport_versie_status, rapport_versie_status.capitalize())
        parts.append('<p>Versie {} &mdash; {}</p>'.format(html_escape(rapport_versie), html_escape(_vs_label)))
    parts.append('<p>{} &mdash; {}</p>'.format(html_escape(auteur), html_escape(datum)))
    parts.append('<p>{}: <span class="tlp-badge" style="background:{};color:{}">{}</span></p>'.format(
        t['classificatie'], tlp_bg, tlp_fg, html_escape(classificatie)))
    if rapport_omgeving:
        parts.append('<p><strong>{}:</strong> {}</p>'.format(
            'Environment' if taal == 'en' else 'Omgeving', html_escape(rapport_omgeving)))
    if is_draft:
        parts.append('<p style="color:red;font-size:1.2em"><strong>{}</strong></p>'.format(t['concept']))

    # Colofon
    _en = (taal == 'en')
    rapport_revisies = rapport_revisies or []
    _status_lbl = {'concept': 'Draft' if _en else 'Concept',
                   'definitief': 'Final' if _en else 'Definitief',
                   'final': 'Final' if _en else 'Definitief',
                   'herzien': 'Revised' if _en else 'Herzien',
                   'review': 'Under review' if _en else 'Ter review'}.get(
                       rapport_versie_status, (rapport_versie_status or '').capitalize())
    _ttype = ('Red team assessment' if testtype == 'redteam'
              else ('Penetration test' if _en else 'Penetratietest'))
    if testscope:
        _ttype += ' ({})'.format(testscope)
    _periode = ''
    if test_start or test_end:
        _periode = '{} &ndash; {}'.format(test_start or '?', test_end or '?')
    _col_rows = [
        ('Title' if _en else 'Titel', html_escape(titel)),
        ('Subtitle' if _en else 'Subtitel', html_escape(subtitel)),
        ('Version' if _en else 'Versie', html_escape(rapport_versie)),
        ('Status', html_escape(_status_lbl)),
        ('Date' if _en else 'Datum', html_escape(datum)),
        (t['classificatie'], html_escape(classificatie)),
        ('Client' if _en else 'Opdrachtgever', html_escape(rapport_project)),
        ('Author' if _en else 'Opsteller', html_escape(auteur)),
        ('Assessment type' if _en else 'Type onderzoek', html_escape(_ttype)),
        ('Environment' if _en else 'Omgeving', html_escape(rapport_omgeving)),
        ('Test period' if _en else 'Testperiode', _periode),
        ('Contact', str(html_escape(rapport_contact)).replace('\n', '<br>')),
    ]
    parts.append('<h2>{}</h2>'.format('Colophon' if _en else 'Colofon'))
    parts.append('<table class="colofon">')
    for _lbl, _val in _col_rows:
        if _val:
            parts.append('<tr><th style="width:30%">{}</th><td>{}</td></tr>'.format(_lbl, _val))
    parts.append('</table>')
    _vertrouwelijk = (
        'This document is classified {} and is intended solely for the client named above. '
        'Distribution to third parties is only permitted with prior written consent.'.format(html_escape(classificatie))
        if _en else
        'Dit document is geclassificeerd als {} en is uitsluitend bedoeld voor de hierboven genoemde '
        'opdrachtgever. Verspreiding aan derden is alleen toegestaan na voorafgaande schriftelijke '
        'toestemming.'.format(html_escape(classificatie)))
    parts.append('<p style="font-style:italic;font-size:0.9em;color:#555">{}</p>'.format(_vertrouwelijk))

    # Revisiehistorie
    if rapport_revisies:
        parts.append('<h2>{}</h2>'.format('Revision history' if _en else 'Revisiehistorie'))
        parts.append('<table class="revisies">')
        parts.append('<tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr>'.format(
            'Version' if _en else 'Versie', 'Date' if _en else 'Datum',
            'Author' if _en else 'Auteur', 'Change' if _en else 'Wijziging'))
        for _rv in rapport_revisies:
            parts.append('<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>'.format(
                html_escape(_rv.get('versie', '')), html_escape(_rv.get('datum', '')),
                html_escape(_rv.get('auteur', '')), html_escape(_rv.get('wijziging', ''))))
        parts.append('</table>')

    # Distributie
    if rapport_distributie:
        parts.append('<h2>{}</h2>'.format('Distribution' if _en else 'Distributie'))
        parts.append('<table class="revisies">')
        parts.append('<tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr>'.format(
            'Name' if _en else 'Naam', 'Organisation' if _en else 'Organisatie',
            'Role' if _en else 'Rol', 'Version' if _en else 'Versie'))
        for _d in rapport_distributie:
            parts.append('<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>'.format(
                html_escape(_d.get('naam', '')), html_escape(_d.get('organisatie', '')),
                html_escape(_d.get('rol', '')), html_escape(_d.get('versie', ''))))
        parts.append('</table>')

    # Inleiding
    parts.append('<h2>{}</h2>'.format(t['inleiding']))
    intro_key = 'redteam_intro' if testtype == 'redteam' else 'pentest_intro'
    parts.append('<p>{}</p>'.format(t[intro_key].format(project=html_escape(titel))))
    parts.append('<p>{} &mdash; {}</p>'.format(html_escape(auteur), html_escape(datum)))

    # Test timeline
    if test_start or test_end:
        tl_label = 'Test Period' if taal == 'en' else 'Testperiode'
        parts.append('<p><strong>{}:</strong> {} — {}</p>'.format(
            tl_label, html_escape(test_start or '?'), html_escape(test_end or '?')))

    # Rules of Engagement
    if rapport_roe:
        roe_label = 'Rules of Engagement'
        parts.append('<h2>{}</h2>'.format(roe_label))
        parts.append('<p>{}</p>'.format(html_escape(rapport_roe)))

    # Scope targets
    if scope_targets:
        scope_label = 'Scope' if taal == 'en' else 'Scope'
        target_l = 'Target'
        type_l = 'Type'
        desc_l = 'Description' if taal == 'en' else 'Beschrijving'
        parts.append('<h2>{}</h2>'.format(scope_label))
        parts.append('<table><tr><th>{}</th><th>{}</th><th>{}</th></tr>'.format(target_l, type_l, desc_l))
        for st in scope_targets:
            if isinstance(st, dict):
                parts.append('<tr><td>{}</td><td>{}</td><td>{}</td></tr>'.format(
                    html_escape(st.get('target', '')),
                    html_escape(st.get('type', '')),
                    html_escape(st.get('beschrijving', ''))))
        parts.append('</table>')

    # Managementsamenvatting
    if _sec('managementsamenvatting') and management_samenvatting:
        parts.append('<!--SEC:managementsamenvatting-->')
        parts.append('<h2>{}</h2>'.format(t['management_samenvatting']))
        parts.append('<p>{}</p>'.format(html_escape(management_samenvatting)))
        if algeheel_beeld:
            parts.append('<h3 style="margin-top:14px">{}</h3>'.format('Overall assessment' if _en else 'Algeheel beeld'))
            parts.append('<p>{}</p>'.format(html_escape(algeheel_beeld)))
        if _sec('top_risk_gauge'):
            _append_top_risk_gauge_html(parts, findings, taal)
        if key_findings:
            parts.append(_key_findings_html(key_findings, taal))
        if digid_knockout:
            parts.append(_digid_knockout_html(digid_knockout, taal))

    # Methodologie
    if _sec('methodologie'):
        parts.append('<!--SEC:methodologie-->')
        parts.append('<h2>{}</h2>'.format(t['methodologie']))
        methode_key = 'redteam_methode' if testtype == 'redteam' else 'pentest_methode'
        fasen_key = 'redteam_fasen' if testtype == 'redteam' else 'pentest_fasen'
        parts.append('<p>{}</p>'.format(t[methode_key]))
        parts.append('<ol>')
        for fase_naam, fase_beschrijving in t[fasen_key]:
            parts.append('<li><strong>{}</strong> &mdash; {}</li>'.format(fase_naam, fase_beschrijving))
        parts.append('</ol>')

        # Scope type (multi-select)
        scopes = testscopes if testscopes else [testscope or 'blackbox']
        for scope in scopes:
            if scope == 'whitebox':
                parts.append('<p>{}</p>'.format(t['scope_whitebox']))
            elif scope == 'greybox':
                parts.append('<p>{}</p>'.format(t['scope_greybox']))
            else:
                parts.append('<p>{}</p>'.format(t['scope_blackbox']))

    # Legs up (alleen bij redteam)
    if _sec('legsup') and testtype == 'redteam' and (legsup_startpunt or legsup_privileges or legsup_informatie):
        parts.append('<!--SEC:legsup-->')
        parts.append('<h2>{}</h2>'.format(t['legs_up']))
        if legsup_startpunt:
            parts.append('<h3>{}</h3>'.format(t['startpunten']))
            parts.append('<p>{}</p>'.format(html_escape(legsup_startpunt)))
        if legsup_privileges:
            parts.append('<h3>{}</h3>'.format(t['privilege_niveaus']))
            parts.append('<p>{}</p>'.format(html_escape(legsup_privileges)))
        if legsup_informatie:
            parts.append('<h3>{}</h3>'.format(t['verstrekte_info']))
            parts.append('<p>{}</p>'.format(html_escape(legsup_informatie)))

    # Scenario's (alleen bij redteam)
    if _sec('scenarios') and testtype == 'redteam' and scenarios:
        parts.append('<!--SEC:scenarios-->')
        parts.append('<h2>{}</h2>'.format(t['scenarios']))
        for sc in scenarios:
            naam = sc.get('naam', '') if isinstance(sc, dict) else ''
            beschrijving = sc.get('beschrijving', '') if isinstance(sc, dict) else ''
            if naam or beschrijving:
                parts.append('<h3>{}</h3>'.format(html_escape(naam)))
                parts.append('<p>{}</p>'.format(html_escape(beschrijving)))

    # Samenvatting
    if _sec('samenvatting_bevindingen'):
        parts.append('<!--SEC:samenvatting_bevindingen-->')
        parts.append('<h2>{}</h2>'.format(t['samenvatting']))
        # Drie overzichtsvisuals naast elkaar (responsief: wrapt op smalle schermen)
        _cols = [
            ('Severity distribution' if taal == 'en' else 'Verdeling naar ernst',
             _severity_donut_svg(counts, taal, sev_labels, severity_colors)),
            ('CVSS score distribution' if taal == 'en' else 'CVSS-scoreverdeling',
             _cvss_hist_svg(findings, taal)),
            ('Remediation status' if taal == 'en' else 'Remediation-status',
             _remediation_bar_svg(findings, taal)),
        ]
        _cols = [(h, c) for h, c in _cols if c]
        if _cols:
            # Koppen op een gelijke lijn bovenaan; afbeeldingen daaronder verticaal
            # gecentreerd in gelijke-hoogte kolommen.
            parts.append('<div style="display:flex;flex-wrap:wrap;gap:24px;'
                         'align-items:stretch;justify-content:center;margin:12px 0">')
            for h, c in _cols:
                parts.append('<div style="flex:1 1 260px;min-width:240px;display:flex;'
                             'flex-direction:column">'
                             '<h3 style="margin:0 0 8px;text-align:center">{}</h3>'
                             '<div style="flex:1;display:flex;align-items:center;'
                             'justify-content:center">{}</div></div>'.format(
                                 html_escape(h), c))
            parts.append('</div>')
        # Detailtabel met de severity-telling (volle breedte, onder de visuals)
        parts.append('<table><tr><th>{}</th><th>{}</th></tr>'.format(t['classificatie'], t['aantal']))
        for sev in ('critical', 'high', 'medium', 'low', 'none'):
            color = severity_colors[sev]
            label = sev_labels.get(sev, sev)
            parts.append('<tr><td><span class="severity-bar" style="background:{}"></span>{}</td><td>{}</td></tr>'.format(
                color, html_escape(label), counts[sev]))
        parts.append('<tr><td><strong>{}</strong></td><td><strong>{}</strong></td></tr></table>'.format(t['totaal'], len(findings)))

    # Bevindingenlijst (compacte tabel ID | Bevinding | Risico)
    if _sec('bevindingenlijst'):
        parts.append('<!--SEC:bevindingenlijst-->')
        _append_bevindingenlijst_html(parts, findings, taal)

    # Risicomatrix (heatmap) + oplostijden (SLA) + detecteerbaarheid
    if _sec('risicomatrix'):
        parts.append('<!--SEC:risicomatrix-->')
        _append_heatmap_html(parts, findings, taal)
    if _sec('sla'):
        parts.append('<!--SEC:sla-->')
        _append_sla_html(parts, findings, taal)
    if _sec('detecteerbaarheid'):
        parts.append('<!--SEC:detecteerbaarheid-->')
        _append_detection_html(parts, findings, taal)

    # Notities (verkenning & ontdekking)
    if _sec('verkenning') and notes:
        parts.append('<!--SEC:verkenning-->')
        parts.append('<h2>{}</h2>'.format(t['verkenning']))
        for n in notes:
            parts.append('<h3>{}</h3>'.format(html_escape(n['naam'])))
            if n.get('latex_raw'):
                # Rauwe LaTeX: in de PDF gerenderd; in de preview als bron tonen.
                parts.append('<pre style="white-space:pre-wrap;font-size:12px;'
                             'background:#f6f8fa;border:1px solid #ddd;padding:8px;'
                             'border-radius:6px">{}</pre>'.format(html_escape(n['uitwerken'])))
            else:
                parts.append('<p>{}</p>'.format(html_escape(n['uitwerken'])))

    # Bevindingen (volledige inhoud)
    _REM_LABELS = {'open': 'Open', 'in_progress': 'In Progress', 'fixed': 'Fixed', 'verified': 'Verified', 'accepted': 'Accepted'}
    if _sec('bevindingen'):
        parts.append('<!--SEC:bevindingen-->')
        parts.append('<h2>{}</h2>'.format(t['bevindingen']))
    for label, group in (grouped if _sec('bevindingen') else []):
        if not group:
            continue
        parts.append('<h3>{} {}</h3>'.format(html_escape(label), t['bevindingen_label']))
        for f in group:
            color = severity_colors.get(f['severity'], '#ccc')
            parts.append('<div class="finding" style="border-left-color:{}">'.format(color))
            parts.append('<h4 id="bev-{0}">[{0}] {1}</h4>'.format(str(f['nr']).zfill(3), html_escape(f['titel'])))
            parts.append('<p><strong>CVSS:</strong> {} ({})</p>'.format(
                html_escape(str(f['basescore'])), html_escape(f['severity'])))
            # Remediation badge
            rem = f.get('remediation_status', 'open')
            rem_label = _REM_LABELS.get(rem, rem)
            parts.append('<p><strong>Remediation:</strong> <span style="padding:2px 8px;border-radius:3px;background:#eee">{}</span></p>'.format(html_escape(rem_label)))
            if f['locatie']:
                parts.append('<p><strong>{}:</strong> {}</p>'.format(t['locatie'], html_escape(f['locatie'])))
            if f.get('tester'):
                parts.append('<p><strong>{}:</strong> {}</p>'.format(
                    'Tested by' if taal == 'en' else 'Vastgesteld door', html_escape(f['tester'])))
            if f['beschrijving']:
                parts.append(_html_markup(f['beschrijving']))
            if f.get('evidence_cmd') or f.get('evidence_resp'):
                parts.append('<p><strong>{}:</strong></p>'.format('Evidence' if taal == 'en' else 'Bewijs'))
                parts.append('<p>{} <code>{}</code> {}</p>'.format(
                    'The following command' if taal == 'en' else 'De volgende opdracht',
                    html_escape(f.get('evidence_cmd', '')),
                    'gave the following response:' if taal == 'en' else 'gaf de volgende response:'))
                parts.append('<pre style="white-space:pre-wrap;font-family:monospace;font-size:12px;'
                             'background:#f2f2f2;padding:8px;border-radius:4px">{}</pre>'.format(
                                 html_escape(f.get('evidence_resp', ''))))
            if f.get('uitwerking_detail'):
                parts.append(_html_markup(f['uitwerking_detail']))
            if f['impact']:
                parts.append('<p><strong>{}</strong></p>'.format(t['impact']))
                parts.append(_html_markup(f['impact']))
            if f['aanbeveling']:
                parts.append('<p><strong>{}</strong></p>'.format(t['aanbeveling']))
                parts.append(_html_markup(f['aanbeveling']))
            # WOEF controle-mapping, faalmodus en detecteerbaarheid
            _woef = []
            if f.get('faalmodus'):
                _fm = _FAALMODUS_LABELS.get(f['faalmodus'], (f['faalmodus'], f['faalmodus']))
                _woef.append('<strong>{}:</strong> {}'.format(
                    'Failure mode' if taal == 'en' else 'Faalmodus',
                    html_escape(_fm[1] if taal == 'en' else _fm[0])))
            if f.get('control_ref'):
                _woef.append('<strong>{}:</strong> {}'.format(
                    'Control' if taal == 'en' else 'Controle', html_escape(f['control_ref'])))
            if f.get('detecteerbaarheid'):
                _dt = _DETECT_LABELS.get(f['detecteerbaarheid'], (f['detecteerbaarheid'], f['detecteerbaarheid']))
                _woef.append('<strong>{}:</strong> {}'.format(
                    'Detectable' if taal == 'en' else 'Detecteerbaar',
                    html_escape(_dt[1] if taal == 'en' else _dt[0])))
            if _woef:
                parts.append('<p>{}</p>'.format(' &nbsp;|&nbsp; '.join(_woef)))
            if f.get('detectie_notitie'):
                parts.append('<p><em>{}:</em> {}</p>'.format(
                    'Detection notes' if taal == 'en' else 'Detectie-toelichting',
                    html_escape(f['detectie_notitie'])))
            # Externe referenties
            _refs = f.get('referenties_list') or []
            if _refs:
                parts.append('<p><strong>{}:</strong></p><ul>'.format(
                    'References' if taal == 'en' else 'Referenties'))
                for r in _refs:
                    if r.startswith('http'):
                        parts.append('<li><a href="{0}">{0}</a></li>'.format(html_escape(r)))
                    else:
                        parts.append('<li>{}</li>'.format(html_escape(r)))
                parts.append('</ul>')
            # Gekoppelde assets / doelen
            assets = f.get('assets', [])
            if assets:
                _al = 'Affected assets' if taal == 'en' else 'Getroffen assets'
                _parts_a = ['{}{}'.format(
                    html_escape(a['waarde']),
                    ' ({})'.format(html_escape(a['type'])) if a['type'] else '') for a in assets]
                parts.append('<p><strong>{}:</strong> {}</p>'.format(_al, ', '.join(_parts_a)))
            # Finding relaties
            related = f.get('related', [])
            if related:
                rel_parts = []
                for r in related:
                    if r.get('nr'):
                        _nr = str(r['nr']).zfill(3)
                        rel_parts.append('{}: {} (<a href="#bev-{}">{}</a>)'.format(
                            html_escape(r.get('type_label', r['type'])), html_escape(r['naam']), _nr, _nr))
                    else:
                        rel_parts.append('{}: {}'.format(
                            html_escape(r.get('type_label', r['type'])), html_escape(r['naam'])))
                parts.append('<p><strong>Related:</strong> {}</p>'.format(', '.join(rel_parts)))
            for ev in f.get('evidence', []):
                _h = ev.get('sha256') or ''
                _hash_html = (' <span style="color:#667085;font-size:11px">(SHA-256: {})</span>'
                              .format(html_escape(_h)) if _h else '')
                parts.append('<p><em>Evidence: {}</em>{}</p>'.format(
                    html_escape(ev['caption']), _hash_html))
            parts.append('</div>')

    # Aanbevelingen tabel
    if _sec('aanbevelingen'):
        parts.append('<!--SEC:aanbevelingen-->')
        parts.append('<h2>{}</h2>'.format(t['aanbevelingen']))
        parts.append('<table><tr><th>ID</th><th>{}</th><th>CVSS</th><th>{}</th></tr>'.format(t['bevindingen'], t['aanbeveling']))
        for f in findings:
            nr = str(f['nr']).zfill(3)
            parts.append('<tr><td><a href="#bev-{0}">{0}</a></td><td>{1}</td><td>{2}</td><td>{3}</td></tr>'.format(
                nr, html_escape(f['titel']),
                html_escape(str(f['basescore'])), html_escape(_f_aanbeveling_overzicht(f))))
        parts.append('</table>')

    # Einde herordenbaar gebied; appendix-groep blijft vast achteraan
    parts.append('<!--SEC-END-->')

    # Beperkingen & aannames (kwalificeert de bevindingen; vooraan in de bijlagen)
    if _sec('beperkingen'):
        _append_beperkingen_html(parts, taal, testtype=testtype, testscope=testscope,
                                 test_start=test_start, test_end=test_end,
                                 rapport_omgeving=rapport_omgeving)

    # Retest-voortgang (delta t.o.v. eerdere rapportage; alleen bij retest-data)
    if _sec('retest_voortgang'):
        _append_retest_progress_html(parts, findings, taal)

    # Kill chain + asset-dekking (appendix-groep)
    if _sec('killchain'):
        _append_chains_html(parts, taal)
    if _sec('asset_dekking'):
        _append_coverage_html(parts, taal)

    # Mapping-bijlagen (OWASP Top 10 / NCSC-richtlijnen / ISO-BIO-NIS2)
    if _sec('owasp_mapping'):
        _append_owasp_mapping_html(parts, findings, taal)
    if _sec('ncsc_mapping'):
        _append_ncsc_mapping_html(parts, findings, taal)
    if _sec('controls_mapping'):
        _append_controls_mapping_html(parts, findings, taal)
    if _sec('cia_triad'):
        _append_cia_triad_html(parts, findings, taal)
    if _sec('subsequent_triad'):
        _append_subsequent_triad_html(parts, findings, taal)
    if _sec('exploit_profile'):
        _append_exploit_profile_html(parts, findings, taal)
    if _sec('direct_exploitable'):
        _append_direct_exploitable_html(parts, findings, taal)
    if _sec('impact_gauge'):
        _append_impact_gauge_html(parts, findings, taal)

    # CVSS-vectordetail + bewijsregister (technische, auditbare bijlagen)
    if _sec('cvss_detail'):
        _append_cvss_detail_html(parts, findings, taal)
    if _sec('bewijsregister'):
        _append_bewijsregister_html(parts, findings, taal)

    # Checklist appendix
    if _sec('checklists'):
        _append_checklist_html(parts, checklists, taal)

    # Begrippen- en afkortingenlijst (naslag, achteraan)
    if _sec('begrippenlijst'):
        _append_begrippen_html(parts, taal)

    # Sign-off
    _append_signoff_html(parts, taal)

    parts.append('</body></html>')
    html = ''.join(parts)
    return _reorder_marked(html, section_order or [], '<!--SEC:{k}-->', '<!--SEC-END-->')


def _heatmap_md_lines(findings, taal='nl'):
    """Risicomatrix (heatmap) als Markdown-tabel met finding-IDs."""
    if not findings:
        return []
    cells = {}
    for f in findings:
        k, i = _finding_ki(f)
        cells.setdefault((k, i), []).append(f['nr'])
    lines = []
    lines.append('## {}'.format('Risk Matrix' if taal == 'en' else 'Risicomatrix'))
    lines.append('')
    kans_l = 'Likelihood' if taal == 'en' else 'Kans'
    lines.append('| {} \\\\ Impact | 1 | 2 | 3 | 4 | 5 |'.format(kans_l))
    lines.append('|---|---|---|---|---|---|')
    for k in range(5, 0, -1):
        row = ['**{}**'.format(k)]
        for i in range(1, 6):
            ids = cells.get((k, i), [])
            row.append(', '.join('#' + str(x).zfill(3) for x in ids) or ' ')
        lines.append('| ' + ' | '.join(row) + ' |')
    lines.append('')
    return lines


def _sla_md_lines(findings, taal='nl'):
    """Oplostijden/SLA als Markdown-tabel."""
    if not findings:
        return []
    sev_labels = _SEVERITY_LABELS_EN if taal == 'en' else _SEVERITY_LABELS
    lines = []
    lines.append('## {}'.format('Remediation Timelines' if taal == 'en' else 'Oplostijden'))
    lines.append('')
    if taal == 'en':
        lines.append('The recommended maximum remediation time is based on the risk classification '
                     'of each finding.')
        lines.append('')
        lines.append('| ID | Finding | Severity | Target |')
    else:
        lines.append('De aanbevolen maximale hersteltermijn is gebaseerd op de risicoclassificatie '
                     'van elke bevinding.')
        lines.append('')
        lines.append('| ID | Bevinding | Ernst | Streeftermijn |')
    lines.append('|---|---|---|---|')
    for f in findings:
        sev = f['severity']
        _days, nl_lbl, en_lbl = _SLA_DAYS.get(sev, (90, '', ''))
        sla_txt = en_lbl if taal == 'en' else nl_lbl
        lines.append('| {} | {} | {} | {} |'.format(
            str(f['nr']).zfill(3), f['titel'], sev_labels.get(sev, sev), sla_txt))
    lines.append('')
    return lines


def _owasp_mapping_md_lines(findings, taal='nl'):
    """OWASP Top 10 mapping-bijlage als Markdown."""
    relevant = [f for f in findings if f.get('owasp_2025')]
    if not relevant:
        return []
    lines = []
    lines.append('# {}'.format('Appendix: OWASP Top 10 Mapping' if taal == 'en'
                               else 'Bijlage: OWASP Top 10 mapping'))
    lines.append('')
    lines.append('| ID | {} | OWASP 2025 |'.format('Finding' if taal == 'en' else 'Bevinding'))
    lines.append('|---|---|---|')
    for f in relevant:
        label, url = _owasp2025_label(f.get('owasp_2025'))
        label = label.replace('|', '\\|')
        cat = '[{}]({})'.format(label, url) if url else label
        lines.append('| {} | {} | {} |'.format(
            str(f['nr']).zfill(3), str(f['titel']).replace('|', '\\|'), cat))
    lines.append('')
    return lines


def _ncsc_mapping_md_lines(findings, taal='nl'):
    """NCSC-richtlijnen mapping-bijlage als Markdown."""
    try:
        from meuk.flask.findings import ncsc_richtlijn_filter as _ncsc
    except Exception:
        def _ncsc(code):
            return code or ''
    relevant = [f for f in findings if f.get('ncsc')]
    if not relevant:
        return []
    lines = []
    lines.append('# {}'.format('Appendix: NCSC Guidelines Mapping' if taal == 'en'
                               else 'Bijlage: NCSC-richtlijnen mapping'))
    lines.append('')
    lines.append('| ID | {} | NCSC |'.format('Finding' if taal == 'en' else 'Bevinding'))
    lines.append('|---|---|---|')
    for f in relevant:
        ncsc_code = f.get('ncsc', '')
        ncsc_txt = _ncsc(ncsc_code) if ncsc_code else '—'
        lines.append('| {} | {} | {} |'.format(
            str(f['nr']).zfill(3), f['titel'], ncsc_txt))
    lines.append('')
    return lines


def _generate_docx_markdown(findings, grouped, counts, titel, auteur, subtitel,
                            datum, classificatie, is_draft, notes=None,
                            management_samenvatting='', testtype='pentest',
                            testscope='blackbox', testscopes=None,
                            legsup_startpunt='', legsup_privileges='',
                            legsup_informatie='', scenarios=None,
                            scoped_hosts=None, taal='nl',
                            rapport_roe='', test_start='', test_end='',
                            variant='detailed', rapport_versie='',
                            rapport_versie_status='concept',
                            scope_targets=None, checklists=None, digid_knockout=None,
                            key_findings=None, algeheel_beeld='',
                            sections=None, findings_scope=None, rapport_omgeving='',
                            section_order=None, rapport_project='',
                            rapport_contact='', rapport_revisies=None,
                            rapport_distributie=None):
    """Genereer pandoc-Markdown dat de LaTeX template 1:1 spiegelt."""
    t = _T.get(taal, _T['nl'])
    sev_labels = _SEVERITY_LABELS_EN if taal == 'en' else _SEVERITY_LABELS

    def u(text):
        """Unescape HTML entities voor Markdown output."""
        return html_mod.unescape(text)

    if sections is None:
        _base = _BUILTIN_VARIANTS.get(variant, _BUILTIN_VARIANTS['detailed'])
        sections = _base['sections']
        if findings_scope is None:
            findings_scope = _base['findings_scope']
    if findings_scope is None:
        findings_scope = 'all'

    def _sec(k):
        return sections.get(k, True)

    findings, grouped = _scope_findings(findings, grouped, findings_scope)
    lines = []

    # YAML metadata block
    lines.append('---')
    lines.append('title: "{}"'.format(titel.replace('"', '\\"')))
    lines.append('subtitle: "{}"'.format(subtitel.replace('"', '\\"')))
    lines.append('author: "{}"'.format(auteur.replace('"', '\\"')))
    lines.append('date: "{}"'.format(datum))
    lines.append('---')
    lines.append('')

    if rapport_versie:
        _vs_labels = {'concept': 'Concept', 'definitief': 'Definitief', 'herzien': 'Herzien'}
        _vs_label = _vs_labels.get(rapport_versie_status, rapport_versie_status.capitalize())
        lines.append('**Versie {} --- {}**'.format(rapport_versie, _vs_label))
        lines.append('')

    if is_draft:
        lines.append('**{}**'.format(u(t['concept'])))
        lines.append('')

    if rapport_omgeving:
        lines.append('**{}:** {}'.format('Environment' if taal == 'en' else 'Omgeving', rapport_omgeving))
        lines.append('')

    # Colofon
    _en = (taal == 'en')
    rapport_revisies = rapport_revisies or []
    _status_lbl = {'concept': 'Draft' if _en else 'Concept',
                   'definitief': 'Final' if _en else 'Definitief',
                   'final': 'Final' if _en else 'Definitief',
                   'herzien': 'Revised' if _en else 'Herzien',
                   'review': 'Under review' if _en else 'Ter review'}.get(
                       rapport_versie_status, (rapport_versie_status or '').capitalize())
    _ttype = ('Red team assessment' if testtype == 'redteam'
              else ('Penetration test' if _en else 'Penetratietest'))
    if testscope:
        _ttype += ' ({})'.format(testscope)
    _periode = '{} – {}'.format(test_start or '?', test_end or '?') if (test_start or test_end) else ''

    def _mdcell(v):
        return str(v or '').replace('|', '\\|')

    _col_rows = [
        ('Title' if _en else 'Titel', titel),
        ('Subtitle' if _en else 'Subtitel', subtitel),
        ('Version' if _en else 'Versie', rapport_versie),
        ('Status', _status_lbl),
        ('Date' if _en else 'Datum', datum),
        ('Classification' if _en else 'Classificatie', classificatie),
        ('Client' if _en else 'Opdrachtgever', rapport_project),
        ('Author' if _en else 'Opsteller', auteur),
        ('Assessment type' if _en else 'Type onderzoek', _ttype),
        ('Environment' if _en else 'Omgeving', rapport_omgeving),
        ('Test period' if _en else 'Testperiode', _periode),
        ('Contact', (rapport_contact or '').replace('\n', '; ')),
    ]
    lines.append('# {}'.format('Colophon' if _en else 'Colofon'))
    lines.append('')
    lines.append('| {} | {} |'.format('Field' if _en else 'Veld', 'Value' if _en else 'Waarde'))
    lines.append('|---|---|')
    for _lbl, _val in _col_rows:
        if _val:
            lines.append('| {} | {} |'.format(_mdcell(_lbl), _mdcell(_val)))
    lines.append('')
    _vertrouwelijk = (
        'This document is classified {} and is intended solely for the client named above. '
        'Distribution to third parties is only permitted with prior written consent.'.format(classificatie)
        if _en else
        'Dit document is geclassificeerd als {} en is uitsluitend bedoeld voor de hierboven genoemde '
        'opdrachtgever. Verspreiding aan derden is alleen toegestaan na voorafgaande schriftelijke '
        'toestemming.'.format(classificatie))
    lines.append('*{}*'.format(_vertrouwelijk))
    lines.append('')

    # Revisiehistorie
    if rapport_revisies:
        lines.append('# {}'.format('Revision history' if _en else 'Revisiehistorie'))
        lines.append('')
        lines.append('| {} | {} | {} | {} |'.format(
            'Version' if _en else 'Versie', 'Date' if _en else 'Datum',
            'Author' if _en else 'Auteur', 'Change' if _en else 'Wijziging'))
        lines.append('|---|---|---|---|')
        for _rv in rapport_revisies:
            lines.append('| {} | {} | {} | {} |'.format(
                _mdcell(_rv.get('versie', '')), _mdcell(_rv.get('datum', '')),
                _mdcell(_rv.get('auteur', '')), _mdcell(_rv.get('wijziging', ''))))
        lines.append('')

    # Distributie
    if rapport_distributie:
        lines.append('# {}'.format('Distribution' if _en else 'Distributie'))
        lines.append('')
        lines.append('| {} | {} | {} | {} |'.format(
            'Name' if _en else 'Naam', 'Organisation' if _en else 'Organisatie',
            'Role' if _en else 'Rol', 'Version' if _en else 'Versie'))
        lines.append('|---|---|---|---|')
        for _d in rapport_distributie:
            lines.append('| {} | {} | {} | {} |'.format(
                _mdcell(_d.get('naam', '')), _mdcell(_d.get('organisatie', '')),
                _mdcell(_d.get('rol', '')), _mdcell(_d.get('versie', ''))))
        lines.append('')

    # Inleiding
    lines.append('# {}'.format(u(t['inleiding'])))
    lines.append('')
    intro_key = 'redteam_intro' if testtype == 'redteam' else 'pentest_intro'
    lines.append(u(t[intro_key]).format(project=titel))
    lines.append('')
    lines.append('{} — {}'.format(auteur, datum))
    lines.append('')

    # Test timeline
    if test_start or test_end:
        tl_label = 'Test Period' if taal == 'en' else 'Testperiode'
        lines.append('**{}:** {} — {}'.format(tl_label, test_start or '?', test_end or '?'))
        lines.append('')

    # Rules of Engagement
    if rapport_roe:
        lines.append('## Rules of Engagement')
        lines.append('')
        lines.append(rapport_roe)
        lines.append('')

    # Scope subsectie
    lines.append('## Scope')
    lines.append('')
    if taal == 'en':
        lines.append('The following systems were part of the test:')
    else:
        lines.append('De volgende systemen zijn onderdeel van de test:')
    lines.append('')
    if scope_targets:
        target_l = 'Target'
        type_l = 'Type'
        desc_l = 'Description' if taal == 'en' else 'Beschrijving'
        lines.append('| {} | {} | {} |'.format(target_l, type_l, desc_l))
        lines.append('|---|---|---|')
        for st in scope_targets:
            if isinstance(st, dict):
                lines.append('| {} | {} | {} |'.format(
                    st.get('target', ''), st.get('type', ''), st.get('beschrijving', '')))
    elif scoped_hosts:
        for host in scoped_hosts:
            lines.append('- {}'.format(host))
    else:
        if taal == 'en':
            lines.append('- See findings for specific locations')
        else:
            lines.append('- Zie bevindingen voor specifieke locaties')
    lines.append('')

    # Managementsamenvatting
    if _sec('managementsamenvatting') and management_samenvatting:
        lines.append('%%SEC:managementsamenvatting%%')
        lines.append('# {}'.format(u(t['management_samenvatting'])))
        lines.append('')
        lines.append(management_samenvatting)
        lines.append('')
        if algeheel_beeld:
            lines.append('## {}'.format('Overall assessment' if _en else 'Algeheel beeld'))
            lines.append('')
            lines.append(algeheel_beeld)
            lines.append('')
        if _sec('top_risk_gauge'):
            lines.extend(_top_risk_gauge_md_lines(findings, taal))
        if key_findings:
            lines.append(_key_findings_md(key_findings, taal))
        if digid_knockout:
            lines.append(_digid_knockout_md(digid_knockout, taal))

    # Methodologie
    if _sec('methodologie'):
        lines.append('%%SEC:methodologie%%')
        lines.append('# {}'.format(u(t['methodologie'])))
        lines.append('')
        methode_key = 'redteam_methode' if testtype == 'redteam' else 'pentest_methode'
        fasen_key = 'redteam_fasen' if testtype == 'redteam' else 'pentest_fasen'
        lines.append(u(t[methode_key]))
        lines.append('')
        for i, (fase_naam, fase_beschrijving) in enumerate(t[fasen_key], 1):
            lines.append('{}. **{}** — {}'.format(i, u(fase_naam), u(fase_beschrijving)))
        lines.append('')

        # Scope type paragrafen
        scopes = testscopes if testscopes else [testscope or 'blackbox']
        for scope in scopes:
            if scope == 'whitebox':
                lines.append(u(t['scope_whitebox']))
            elif scope == 'greybox':
                lines.append(u(t['scope_greybox']))
            else:
                lines.append(u(t['scope_blackbox']))
            lines.append('')

    # Legs up (alleen redteam)
    if _sec('legsup') and testtype == 'redteam' and (legsup_startpunt or legsup_privileges or legsup_informatie):
        lines.append('%%SEC:legsup%%')
        lines.append('# {}'.format(u(t['legs_up'])))
        lines.append('')
        if legsup_startpunt:
            lines.append('## {}'.format(u(t['startpunten'])))
            lines.append('')
            lines.append(legsup_startpunt)
            lines.append('')
        if legsup_privileges:
            lines.append('## {}'.format(u(t['privilege_niveaus'])))
            lines.append('')
            lines.append(legsup_privileges)
            lines.append('')
        if legsup_informatie:
            lines.append('## {}'.format(u(t['verstrekte_info'])))
            lines.append('')
            lines.append(legsup_informatie)
            lines.append('')

    # Scenario's (alleen redteam)
    if _sec('scenarios') and testtype == 'redteam' and scenarios:
        lines.append('%%SEC:scenarios%%')
        lines.append('# {}'.format(u(t['scenarios'])))
        lines.append('')
        for sc in scenarios:
            naam = sc.get('naam', '') if isinstance(sc, dict) else ''
            beschrijving = sc.get('beschrijving', '') if isinstance(sc, dict) else ''
            if naam or beschrijving:
                lines.append('## {}'.format(naam))
                lines.append('')
                lines.append(beschrijving)
                lines.append('')

    # Risicoinschatting
    lines.append('%%SEC:samenvatting_bevindingen%%')
    if taal == 'en':
        lines.append('# Risk Assessment')
        lines.append('')
        lines.append('The severity of findings is determined using the CVSS 4.0 framework '
                     '(Common Vulnerability Scoring System). The following classification is used:')
        lines.append('')
        lines.append('| Classification | CVSS Score | Colour |')
        lines.append('|---|---|---|')
        lines.append('| Critical | 9.0 -- 10.0 | Dark red |')
        lines.append('| High | 7.0 -- 8.9 | Red |')
        lines.append('| Medium | 4.0 -- 6.9 | Orange |')
        lines.append('| Low | 0.1 -- 3.9 | Yellow |')
        lines.append('| Informational | 0.0 | Green |')
    else:
        lines.append('# Risicoinschatting')
        lines.append('')
        lines.append('De ernst van bevindingen wordt bepaald aan de hand van het CVSS 4.0 framework '
                     '(Common Vulnerability Scoring System). De volgende classificatie wordt gehanteerd:')
        lines.append('')
        lines.append('| Classificatie | CVSS Score | Kleur |')
        lines.append('|---|---|---|')
        lines.append('| Kritiek | 9.0 -- 10.0 | Donkerrood |')
        lines.append('| Hoog | 7.0 -- 8.9 | Rood |')
        lines.append('| Midden | 4.0 -- 6.9 | Oranje |')
        lines.append('| Laag | 0.1 -- 3.9 | Geel |')
        lines.append('| Nihil | 0.0 | Groen |')
    lines.append('')

    # Samenvatting bevindingen
    lines.append('# {}'.format(u(t['samenvatting'])))
    lines.append('')
    if taal == 'en':
        lines.append('A total of **{}** findings were identified:'.format(len(findings)))
    else:
        lines.append('In totaal zijn **{}** bevindingen ge\u00efdentificeerd:'.format(len(findings)))
    lines.append('')
    lines.append('| {} | {} |'.format(u(t['classificatie']), u(t['aantal'])))
    lines.append('|---|---|')
    for sev in ('critical', 'high', 'medium', 'low', 'none'):
        label = sev_labels.get(sev, sev)
        lines.append('| {} | {} |'.format(label, counts[sev]))
    lines.append('| **{}** | **{}** |'.format(u(t['totaal']), len(findings)))
    lines.append('')

    # Samenvattingsgrafieken als PNG (DOCX-grafiekpariteit met HTML/PDF).
    # Degradeert stil naar alleen de tabellen als Pillow ontbreekt.
    try:
        for _cap, _fn in _write_summary_charts(findings, counts, taal, _RAPPORT_DIR):
            lines.append('![{}]({})'.format(_cap, _fn))
            lines.append('')
    except Exception:
        pass

    # Bevindingenlijst (compacte tabel ID | Bevinding | Risico)
    if _sec('bevindingenlijst'):
        lines.append('%%SEC:bevindingenlijst%%')
        lines.extend(_bevindingenlijst_md_lines(findings, taal))

    # Risicomatrix (heatmap) + oplostijden (SLA) + detecteerbaarheid + kill chain
    if _sec('risicomatrix'):
        lines.append('%%SEC:risicomatrix%%')
        lines.extend(_heatmap_md_lines(findings, taal))
    if _sec('sla'):
        lines.append('%%SEC:sla%%')
        lines.extend(_sla_md_lines(findings, taal))
    if _sec('detecteerbaarheid'):
        lines.append('%%SEC:detecteerbaarheid%%')
        lines.extend(_detection_md_lines(findings, taal))

    # Verkenning & ontdekking (notes)
    if _sec('verkenning') and notes:
        lines.append('%%SEC:verkenning%%')
        lines.append('# {}'.format(u(t['verkenning'])))
        lines.append('')
        for n in notes:
            lines.append('## {}'.format(n['naam']))
            lines.append('')
            if n.get('latex_raw'):
                lines.append('```latex')
                lines.append(n['uitwerken'])
                lines.append('```')
            else:
                lines.append(n['uitwerken'])
            lines.append('')

    # Bevindingen
    _REM_LABELS = {'open': 'Open', 'in_progress': 'In Progress', 'fixed': 'Fixed', 'verified': 'Verified', 'accepted': 'Accepted'}
    if _sec('bevindingen'):
        lines.append('%%SEC:bevindingen%%')
        lines.append('# {}'.format(u(t['bevindingen'])))
        lines.append('')
        # alle (gescopede) findings met volledige info
        for label, group in grouped:
            if not group:
                continue
            lines.append('## {} {}'.format(label, u(t['bevindingen_label'])))
            lines.append('')
            for f in group:
                lines.append('### [{0}] {1} (CVSS: {2}) {{#bev-{0}}}'.format(
                    str(f['nr']).zfill(3), f['titel'], f['basescore']))
                lines.append('')
                # Remediation badge
                rem = f.get('remediation_status', 'open')
                lines.append('**Remediation:** {}'.format(_REM_LABELS.get(rem, rem)))
                lines.append('')
                if f.get('tester'):
                    lines.append('**{}:** {}'.format(
                        'Tested by' if taal == 'en' else 'Vastgesteld door', u(f['tester'])))
                    lines.append('')
                if f['beschrijving']:
                    lines.append(_md_markup(f['beschrijving']))
                    lines.append('')
                if f.get('evidence_cmd') or f.get('evidence_resp'):
                    lines.append('**{}:**'.format('Evidence' if taal == 'en' else 'Bewijs'))
                    lines.append('')
                    lines.append('{} `{}` {}'.format(
                        'The following command' if taal == 'en' else 'De volgende opdracht',
                        f.get('evidence_cmd', ''),
                        'gave the following response:' if taal == 'en' else 'gaf de volgende response:'))
                    lines.append('')
                    lines.append('```')
                    lines.append(f.get('evidence_resp', ''))
                    lines.append('```')
                    lines.append('')
                if f.get('uitwerking_detail'):
                    lines.append(_md_markup(f['uitwerking_detail']))
                    lines.append('')
                if f['impact']:
                    lines.append('**{}**'.format(u(t['impact'])))
                    lines.append('')
                    lines.append(_md_markup(f['impact']))
                    lines.append('')
                if f['aanbeveling']:
                    lines.append('**{}**'.format(u(t['aanbeveling'])))
                    lines.append('')
                    lines.append(_md_markup(f['aanbeveling']))
                    lines.append('')
                if f['locatie']:
                    lines.append('**{}:** `{}`'.format(u(t['locatie']), f['locatie']))
                    lines.append('')
                # Metadata: OWASP / CWE / CVSS Vector
                meta_parts = []
                if f['owasp']:
                    meta_parts.append('**OWASP:** {}'.format(f['owasp']))
                if f['cwe']:
                    meta_parts.append('**CWE:** {}'.format(f['cwe']))
                if f['cvss_vector']:
                    meta_parts.append('**CVSS Vector:** `{}`'.format(f['cvss_vector']))
                if f.get('faalmodus'):
                    _fm = _FAALMODUS_LABELS.get(f['faalmodus'], (f['faalmodus'], f['faalmodus']))
                    meta_parts.append('**{}:** {}'.format(
                        'Failure mode' if taal == 'en' else 'Faalmodus',
                        _fm[1] if taal == 'en' else _fm[0]))
                if f.get('control_ref'):
                    meta_parts.append('**{}:** {}'.format(
                        'Control' if taal == 'en' else 'Controle', f['control_ref']))
                if f.get('detecteerbaarheid'):
                    _dt = _DETECT_LABELS.get(f['detecteerbaarheid'], (f['detecteerbaarheid'], f['detecteerbaarheid']))
                    meta_parts.append('**{}:** {}'.format(
                        'Detectable' if taal == 'en' else 'Detecteerbaar',
                        _dt[1] if taal == 'en' else _dt[0]))
                if meta_parts:
                    lines.append(' | '.join(meta_parts))
                    lines.append('')
                if f.get('detectie_notitie'):
                    lines.append('*{}:* {}'.format(
                        'Detection notes' if taal == 'en' else 'Detectie-toelichting',
                        f['detectie_notitie']))
                    lines.append('')
                # Externe referenties
                _refs = f.get('referenties_list') or []
                if _refs:
                    lines.append('**{}:**'.format('References' if taal == 'en' else 'Referenties'))
                    lines.append('')
                    for r in _refs:
                        lines.append('- {}'.format(r))
                    lines.append('')
                # Gekoppelde assets / doelen
                assets = f.get('assets', [])
                if assets:
                    _al = 'Affected assets' if taal == 'en' else 'Getroffen assets'
                    _pa = ['{}{}'.format(a['waarde'], ' ({})'.format(a['type']) if a['type'] else '')
                           for a in assets]
                    lines.append('**{}:** {}'.format(_al, ', '.join(_pa)))
                    lines.append('')
                # Finding relaties
                related = f.get('related', [])
                if related:
                    rel_parts = []
                    for r in related:
                        if r.get('nr'):
                            _nr = str(r['nr']).zfill(3)
                            rel_parts.append('{}: {} ([{}](#bev-{}))'.format(
                                r.get('type_label', r['type']), r['naam'], _nr, _nr))
                        else:
                            rel_parts.append('{}: {}'.format(r.get('type_label', r['type']), r['naam']))
                    lines.append('**Related:** {}'.format(', '.join(rel_parts)))
                    lines.append('')
                # Evidence afbeeldingen. In de gelakte DOCX nooit het origineel:
                # gebruik de gelakte kopie of laat de afbeelding weg (placeholder).
                for ev in f.get('evidence', []):
                    _ep = ev['path']
                    if redact_enabled():
                        _lp = ev.get('lakpath')
                        if _lp and os.path.exists(os.path.join(_RAPPORT_DIR, _lp)):
                            _ep = _lp
                        else:
                            lines.append('*[GELAKT — afbeelding niet opgenomen]*')
                            lines.append('')
                            continue
                    lines.append('![{}]({})'.format(ev['caption'], _ep))
                    if ev.get('sha256'):
                        lines.append('*SHA-256: {}*'.format(ev['sha256']))
                    lines.append('')

    # Overzicht aanbevelingen
    if _sec('aanbevelingen'):
        lines.append('%%SEC:aanbevelingen%%')
        lines.append('# {}'.format(u(t['aanbevelingen'])))
        lines.append('')
        lines.append('| ID | {} | CVSS | {} |'.format(u(t['bevindingen']), u(t['aanbeveling'])))
        lines.append('|---|---|---|---|')
        for f in findings:
            titel = str(f['titel']).replace('|', '\\|')
            aanb = _f_aanbeveling_overzicht(f).replace('|', '\\|')
            lines.append('| {} | {} | {} | {} |'.format(
                str(f['nr']).zfill(3), titel, f['basescore'], aanb))
        lines.append('')

    # Einde herordenbaar gebied; appendix-groep blijft vast achteraan
    lines.append('%%SEC-END%%')

    # Beperkingen & aannames (kwalificeert de bevindingen)
    if _sec('beperkingen'):
        lines.extend(_beperkingen_md_lines(taal, testtype=testtype, testscope=testscope,
                                           test_start=test_start, test_end=test_end,
                                           rapport_omgeving=rapport_omgeving))

    # Retest-voortgang (alleen bij retest-data)
    if _sec('retest_voortgang'):
        lines.extend(_retest_progress_md_lines(findings, taal))

    # Kill chain (appendix-groep)
    if _sec('killchain'):
        lines.extend(_chains_md_lines(taal))

    # Mapping-bijlagen (OWASP Top 10 / NCSC-richtlijnen / ISO-BIO-NIS2)
    if _sec('owasp_mapping'):
        lines.extend(_owasp_mapping_md_lines(findings, taal))
    if _sec('ncsc_mapping'):
        lines.extend(_ncsc_mapping_md_lines(findings, taal))
    if _sec('controls_mapping'):
        lines.extend(_controls_mapping_md_lines(findings, taal))
    if _sec('cia_triad'):
        lines.extend(_cia_triad_md_lines(findings, taal))
    if _sec('subsequent_triad'):
        lines.extend(_subsequent_triad_md_lines(findings, taal))
    if _sec('exploit_profile'):
        lines.extend(_exploit_profile_md_lines(findings, taal))
    if _sec('direct_exploitable'):
        lines.extend(_direct_exploitable_md_lines(findings, taal))
    if _sec('impact_gauge'):
        lines.extend(_impact_gauge_md_lines(findings, taal))

    # CVSS-vectordetail + bewijsregister
    if _sec('cvss_detail'):
        lines.extend(_cvss_detail_md_lines(findings, taal))
    if _sec('bewijsregister'):
        lines.extend(_bewijsregister_md_lines(findings, taal))

    # Checklist appendix
    if _sec('checklists') and checklists:
        heading = 'Checklist Results' if taal == 'en' else 'Checklist resultaten'
        lines.append('# {}'.format(heading))
        lines.append('')
        for cl in checklists:
            lines.append('## {} ({}) — {}'.format(cl['naam'], cl['type'], cl['target']))
            lines.append('')
            st = cl['stats']
            lines.append('**{} pass, {} fail, {} warn, {} skip, {} n/a, {} open**'.format(
                st['pass'], st['fail'], st['warn'], st['skip'], st['na'], st['open']))
            lines.append('')
            for phase in cl['phases']:
                lines.append('### {}'.format(phase['title']))
                lines.append('')
                lines.append('| Ref | Item | Status |')
                lines.append('|---|---|---|')
                for item in phase['items']:
                    lines.append('| {} | {} | {} |'.format(
                        item['ref'], item['title'], item['status'].upper()))
                lines.append('')

    # Begrippen- en afkortingenlijst (naslag, achteraan)
    if _sec('begrippenlijst'):
        lines.extend(_begrippen_md_lines(taal))

    # Sign-off sectie
    lines.append('# Sign-off')
    lines.append('')
    role_l = 'Role' if taal == 'en' else 'Rol'
    name_l = 'Name' if taal == 'en' else 'Naam'
    date_l = 'Date' if taal == 'en' else 'Datum'
    sig_l = 'Signature' if taal == 'en' else 'Handtekening'
    lines.append('| {} | {} | {} | {} |'.format(role_l, name_l, date_l, sig_l))
    lines.append('|---|---|---|---|')
    for role in (['Lead Tester', 'Reviewer', 'Project Manager'] if taal == 'en' else ['Lead Tester', 'Reviewer', 'Projectmanager']):
        lines.append('| {} | | | |'.format(role))
    lines.append('')

    return _reorder_marked('\n'.join(lines), section_order or [], '%%SEC:{k}%%', '%%SEC-END%%')


# ---------------------------------------------------------------------------
# Retestrapport — compact overzicht van de retestcyclus
# ---------------------------------------------------------------------------

def _generate_retest_html(findings, titel, auteur, datum, taal='nl'):
    """Compact HTML-retestrapport: status per oorspronkelijke bevinding."""
    sev_labels = _SEVERITY_LABELS_EN if taal == 'en' else _SEVERITY_LABELS
    heading = 'Retest Report' if taal == 'en' else 'Retestrapport'
    intro = ('This report summarises the retest of previously reported findings.'
             if taal == 'en' else
             'Dit rapport vat de retest van eerder gerapporteerde bevindingen samen.')
    parts = ['<html><head><meta charset="utf-8"><style>',
             'body{font-family:sans-serif;max-width:900px;margin:0 auto;padding:20px}',
             'table{width:100%;border-collapse:collapse;margin:1em 0}',
             'th,td{border:1px solid #ccc;padding:6px 10px;text-align:left;vertical-align:top}',
             'th{background:#154273;color:#fff}',
             '.badge{padding:2px 8px;border-radius:3px;color:#fff;font-size:0.9em}',
             '</style></head><body>']
    parts.append('<h1>{}</h1>'.format(html_escape(heading)))
    parts.append('<p>{}</p>'.format(html_escape(intro)))
    parts.append('<p>{} &mdash; {}</p>'.format(html_escape(auteur), html_escape(datum)))

    # Samenvattingstelling
    tally = {'pending_retest': 0, 'retested_fixed': 0, 'retested_open': 0}
    for f in findings:
        st = f.get('retest_status', '')
        if st in tally:
            tally[st] += 1
    parts.append('<h2>{}</h2>'.format('Summary' if taal == 'en' else 'Samenvatting'))
    parts.append('<table><tr><th>{}</th><th>{}</th></tr>'.format(
        'Status', 'Count' if taal == 'en' else 'Aantal'))
    for st in ('retested_fixed', 'retested_open', 'pending_retest'):
        nl, en, color = _RETEST_LABELS[st]
        parts.append('<tr><td><span class="badge" style="background:{}">{}</span></td><td>{}</td></tr>'.format(
            color, html_escape(en if taal == 'en' else nl), tally[st]))
    parts.append('</table>')

    # Detailtabel
    id_l = 'ID'
    find_l = 'Finding' if taal == 'en' else 'Bevinding'
    sev_l = 'Severity' if taal == 'en' else 'Ernst'
    date_l = 'Retest date' if taal == 'en' else 'Retestdatum'
    notes_l = 'Notes' if taal == 'en' else 'Notities'
    parts.append('<h2>{}</h2>'.format('Details' if taal == 'en' else 'Detailoverzicht'))
    parts.append('<table><tr><th>{}</th><th>{}</th><th>{}</th><th>Status</th><th>{}</th><th>{}</th></tr>'.format(
        id_l, find_l, sev_l, date_l, notes_l))
    for f in findings:
        st = f.get('retest_status', '')
        nl, en, color = _RETEST_LABELS.get(st, ('', '', '#94a3b8'))
        rd = f.get('retest_date')
        rd_str = rd.strftime('%d-%m-%Y') if rd else '&mdash;'
        parts.append('<tr><td>{}</td><td>{}</td><td>{}</td><td><span class="badge" style="background:{}">{}</span></td><td>{}</td><td>{}</td></tr>'.format(
            str(f['nr']).zfill(3), html_escape(f['titel']),
            html_escape(sev_labels.get(f['severity'], f['severity'])),
            color, html_escape(en if taal == 'en' else nl),
            rd_str, html_escape(f.get('retest_notes', '') or '')))
    parts.append('</table>')
    # Normatieve mapping (ISO/BIO/NIS2) — zelfde bijlage als in het hoofdrapport
    _append_controls_mapping_html(parts, findings, taal)
    parts.append('</body></html>')
    return ''.join(parts)


def _generate_retest_markdown(findings, titel, auteur, datum, taal='nl'):
    """Compact Markdown-retestrapport (voor docx-conversie via pandoc)."""
    sev_labels = _SEVERITY_LABELS_EN if taal == 'en' else _SEVERITY_LABELS
    lines = ['---',
             'title: "{}"'.format((titel or '').replace('"', '\\"')),
             'author: "{}"'.format((auteur or '').replace('"', '\\"')),
             'date: "{}"'.format(datum), '---', '']
    lines.append('# {}'.format('Retest Report' if taal == 'en' else 'Retestrapport'))
    lines.append('')
    if taal == 'en':
        lines.append('This report summarises the retest of previously reported findings.')
        lines.append('')
        lines.append('| ID | Finding | Severity | Status | Retest date | Notes |')
    else:
        lines.append('Dit rapport vat de retest van eerder gerapporteerde bevindingen samen.')
        lines.append('')
        lines.append('| ID | Bevinding | Ernst | Status | Retestdatum | Notities |')
    lines.append('|---|---|---|---|---|---|')
    for f in findings:
        st = f.get('retest_status', '')
        nl, en, _c = _RETEST_LABELS.get(st, ('', '', ''))
        rd = f.get('retest_date')
        rd_str = rd.strftime('%d-%m-%Y') if rd else '—'
        notes = (f.get('retest_notes', '') or '').replace('\n', ' ').replace('|', '\\|')
        lines.append('| {} | {} | {} | {} | {} | {} |'.format(
            str(f['nr']).zfill(3), f['titel'], sev_labels.get(f['severity'], f['severity']),
            en if taal == 'en' else nl, rd_str, notes))
    lines.append('')
    # Normatieve mapping (ISO/BIO/NIS2) — zelfde bijlage als in het hoofdrapport
    lines.extend(_controls_mapping_md_lines(findings, taal))
    return '\n'.join(lines)


@rapport_bp.route('/dashboard/report/retest/generate', methods=['GET'])
def gen_retest_rapport():
    """Genereer een compact retestrapport (HTML + Markdown + DOCX indien pandoc)."""
    os.makedirs(_RAPPORT_DIR, exist_ok=True)
    from meuk.flask import project as _project
    _oid = _project.current_opdracht_id()
    s = _project.config_for(_oid) or _get_appdata()
    taal = (getattr(s, 'rapport_taal', '') if s else '') or 'nl'
    titel = ((s.rapport_titel if s else '') or 'Penetration Test Report') + \
            (' — Retest' if taal != 'en' else ' — Retest')
    auteur = (s.rapport_auteur if s else '') or 'Incompetent Bastard'
    datum = datetime.date.today().strftime('%d-%m-%Y')

    # Alleen bevindingen met een actieve retest-status (gescoped op het project)
    retest_statuses = ('pending_retest', 'retested_fixed', 'retested_open')
    base_query = _project.apply_scope(db_bevindingen.query.filter(
        db_bevindingen.deleted_at.is_(None),
        db_bevindingen.retest_status.in_(retest_statuses),
    ), db_bevindingen.opdracht_id, _oid)
    findings = _build_findings_data(base_query, taal=taal)

    html = _generate_retest_html(findings, titel, auteur, datum, taal)
    schrijven(os.path.join(_RAPPORT_DIR, 'rapport_retest.html'), html)
    md = _generate_retest_markdown(findings, titel, auteur, datum, taal)
    md_path = os.path.join(_RAPPORT_DIR, 'rapport_retest.md')
    schrijven(md_path, md)
    try:
        from sh import pandoc
        _ref = (['--reference-doc=' + os.path.abspath(_DOCX_REFERENCE)]
                if os.path.exists(_DOCX_REFERENCE) else [])
        pandoc(md_path, *_ref, '-o', os.path.join(_RAPPORT_DIR, 'rapport_retest.docx'))
    except Exception:
        pass
    return html


# ---------------------------------------------------------------------------
# Debrief (lessons learned) — hoofdstuk 6
# ---------------------------------------------------------------------------

def _build_debrief_stats(taal='nl'):
    """Verzamel automatische debrief-statistieken uit de definitieve bevindingen."""
    from meuk.flask import project as _project
    findings = _project.apply_scope(db_bevindingen.query.filter(
        db_bevindingen.deleted_at.is_(None),
        db_bevindingen.status == 'final',
    ), db_bevindingen.opdracht_id, _project.current_opdracht_id()).all()
    templates = {str(t.id): t for t in db_bevindingen_templates.query.all()}

    faalmodus = {'opzet': 0, 'bestaan': 0, 'werking': 0}
    detectie = {'ja': 0, 'deels': 0, 'nee': 0}
    severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'none': 0}
    mitre = {}
    # Normatieve dekking: per standaard een tally control -> aantal bevindingen
    coverage = {'iso27001': {}, 'bio': {}, 'nis2': {}}
    mapped = 0
    for f in findings:
        tmpl = templates.get(str(f.ref))
        fm = (getattr(f, 'faalmodus', '') or '')
        if fm in faalmodus:
            faalmodus[fm] += 1
        dt = (getattr(f, 'detecteerbaarheid', '') or '')
        if dt in detectie:
            detectie[dt] += 1
        bs = f.basescore or (tmpl.basescore if tmpl else '') or '0'
        sev, _ = _cvss_to_severity(bs)
        severity[sev] = severity.get(sev, 0) + 1
        mt = (tmpl.mitre if tmpl else '') or ''
        if mt:
            mitre[mt] = mitre.get(mt, 0) + 1
        # Controls via CWE/OWASP-categorie van het template
        c = _controls_for_finding({
            'owasp_2025': (tmpl.owasp_2025 if tmpl else '') or '',
            'cwe': (tmpl.cwe if tmpl else '') or '',
        })
        if c:
            mapped += 1
            for std in ('iso27001', 'bio', 'nis2'):
                for ctrl in c[std]:
                    coverage[std][ctrl] = coverage[std].get(ctrl, 0) + 1
    # Sorteer elke standaard op aantal (desc), dan alfabetisch
    coverage_sorted = {
        std: sorted(d.items(), key=lambda kv: (-kv[1], kv[0]))
        for std, d in coverage.items()
    }

    fm_lbl = {k: (_FAALMODUS_LABELS[k][1] if taal == 'en' else _FAALMODUS_LABELS[k][0])
              for k in faalmodus}
    dt_lbl = {k: (_DETECT_LABELS[k][1] if taal == 'en' else _DETECT_LABELS[k][0])
              for k in detectie}
    top_faalmodi = sorted(faalmodus.items(), key=lambda kv: kv[1], reverse=True)
    top_mitre = sorted(mitre.items(), key=lambda kv: kv[1], reverse=True)[:10]
    return {
        'total': len(findings),
        'faalmodus': faalmodus, 'faalmodus_label': fm_lbl, 'top_faalmodi': top_faalmodi,
        'detectie': detectie, 'detectie_label': dt_lbl,
        'severity': severity, 'mitre': top_mitre,
        'coverage': coverage_sorted, 'coverage_mapped': mapped,
    }


def _debrief_fields(s, taal='nl'):
    """Haal de vrije debrief-teksten op uit de instellingen, met labels."""
    labels = {
        'context':  ('Context & opdracht', 'Context & engagement'),
        'werkte':   ('Wat werkte', 'What worked'),
        'faalde':   ('Wat faalde', 'What failed'),
        'detectie': ('Detectieprestatie', 'Detection performance'),
        'vervolg':  ('Aanbevelingen & vervolg', 'Recommendations & next steps'),
    }
    out = []
    for key, (nl, en) in labels.items():
        val = (getattr(s, 'debrief_' + key, '') if s else '') or ''
        out.append((en if taal == 'en' else nl, val))
    return out


def _generate_debrief_html(s, taal='nl'):
    """Debrief-rapport als HTML: vrije tekst + automatische statistieken."""
    stats = _build_debrief_stats(taal)
    heading = 'Debrief — Lessons Learned' if taal == 'en' else 'Debrief — Lessons Learned'
    parts = ['<html><head><meta charset="utf-8"><style>',
             'body{font-family:sans-serif;max-width:900px;margin:0 auto;padding:20px}',
             'table{width:100%;border-collapse:collapse;margin:1em 0}',
             'th,td{border:1px solid #ccc;padding:6px 10px;text-align:left}',
             'th{background:#154273;color:#fff}', '</style></head><body>']
    parts.append('<h1>{}</h1>'.format(html_escape(heading)))
    for label, val in _debrief_fields(s, taal):
        parts.append('<h2>{}</h2>'.format(html_escape(label)))
        parts.append('<p>{}</p>'.format(html_escape(val) if val else '<em>—</em>'))

    # Automatische statistieken
    parts.append('<h2>{}</h2>'.format('Automatic metrics' if taal == 'en' else 'Automatische kerncijfers'))
    parts.append('<p>{}: <strong>{}</strong></p>'.format(
        'Total findings' if taal == 'en' else 'Totaal bevindingen', stats['total']))

    # Faalmodi
    parts.append('<h3>{}</h3>'.format('Failure modes' if taal == 'en' else 'Faalmodi'))
    parts.append('<table><tr><th>{}</th><th>{}</th></tr>'.format(
        'Failure mode' if taal == 'en' else 'Faalmodus', 'Count' if taal == 'en' else 'Aantal'))
    for k, n in stats['top_faalmodi']:
        parts.append('<tr><td>{}</td><td>{}</td></tr>'.format(
            html_escape(stats['faalmodus_label'][k]), n))
    parts.append('</table>')

    # Detectieprestatie
    parts.append('<h3>{}</h3>'.format('Detection performance' if taal == 'en' else 'Detectieprestatie'))
    parts.append('<table><tr><th>{}</th><th>{}</th></tr>'.format(
        'Detectable' if taal == 'en' else 'Detecteerbaar', 'Count' if taal == 'en' else 'Aantal'))
    for k in ('ja', 'deels', 'nee'):
        parts.append('<tr><td>{}</td><td>{}</td></tr>'.format(
            html_escape(stats['detectie_label'][k]), stats['detectie'][k]))
    parts.append('</table>')

    # MITRE
    if stats['mitre']:
        parts.append('<h3>MITRE ATT&amp;CK</h3>')
        parts.append('<table><tr><th>Techniek</th><th>{}</th></tr>'.format(
            'Count' if taal == 'en' else 'Aantal'))
        for tech, n in stats['mitre']:
            parts.append('<tr><td>{}</td><td>{}</td></tr>'.format(html_escape(tech), n))
        parts.append('</table>')

    # Normatieve dekking (ISO/BIO/NIS2) — aggregaat over de bevindingen
    _cov = stats.get('coverage', {})
    if any(_cov.get(std) for std in ('iso27001', 'bio', 'nis2')):
        _en = taal == 'en'
        parts.append('<h3>{}</h3>'.format(
            'Normative coverage (ISO/BIO/NIS2)' if _en else 'Normatieve dekking (ISO/BIO/NIS2)'))
        parts.append('<p style="color:#667085;font-size:12px"><em>{}</em></p>'.format(html_escape(
            '{} of {} findings mapped via CWE/OWASP category; indicative.'.format(stats.get('coverage_mapped', 0), stats['total'])
            if _en else
            '{} van {} bevindingen gekoppeld via CWE/OWASP-categorie; indicatief.'.format(stats.get('coverage_mapped', 0), stats['total']))))
        _std_titels = [('iso27001', 'ISO 27001:2022'), ('bio', 'BIO2'), ('nis2', 'NIS2 art. 21')]
        for std, titel in _std_titels:
            rows = _cov.get(std) or []
            if not rows:
                continue
            parts.append('<h4>{}</h4>'.format(html_escape(titel)))
            parts.append('<table><tr><th>Control</th><th>{}</th></tr>'.format(
                'Count' if _en else 'Aantal'))
            for ctrl, n in rows:
                parts.append('<tr><td>{}</td><td>{}</td></tr>'.format(html_escape(ctrl), n))
            parts.append('</table>')
    parts.append('</body></html>')
    return ''.join(parts)


def _generate_debrief_markdown(s, taal='nl'):
    """Debrief-rapport als Markdown (voor DOCX/LaTeX via pandoc)."""
    stats = _build_debrief_stats(taal)
    lines = ['---', 'title: "Debrief — Lessons Learned"', '---', '']
    lines.append('# Debrief — Lessons Learned')
    lines.append('')
    for label, val in _debrief_fields(s, taal):
        lines.append('## {}'.format(label))
        lines.append('')
        lines.append(val if val else '—')
        lines.append('')
    lines.append('## {}'.format('Automatic metrics' if taal == 'en' else 'Automatische kerncijfers'))
    lines.append('')
    lines.append('{}: **{}**'.format('Total findings' if taal == 'en' else 'Totaal bevindingen', stats['total']))
    lines.append('')
    lines.append('### {}'.format('Failure modes' if taal == 'en' else 'Faalmodi'))
    lines.append('')
    lines.append('| {} | {} |'.format('Failure mode' if taal == 'en' else 'Faalmodus',
                                      'Count' if taal == 'en' else 'Aantal'))
    lines.append('|---|---|')
    for k, n in stats['top_faalmodi']:
        lines.append('| {} | {} |'.format(stats['faalmodus_label'][k], n))
    lines.append('')
    lines.append('### {}'.format('Detection performance' if taal == 'en' else 'Detectieprestatie'))
    lines.append('')
    lines.append('| {} | {} |'.format('Detectable' if taal == 'en' else 'Detecteerbaar',
                                      'Count' if taal == 'en' else 'Aantal'))
    lines.append('|---|---|')
    for k in ('ja', 'deels', 'nee'):
        lines.append('| {} | {} |'.format(stats['detectie_label'][k], stats['detectie'][k]))
    lines.append('')
    if stats['mitre']:
        lines.append('### MITRE ATT&CK')
        lines.append('')
        lines.append('| Techniek | {} |'.format('Count' if taal == 'en' else 'Aantal'))
        lines.append('|---|---|')
        for tech, n in stats['mitre']:
            lines.append('| {} | {} |'.format(tech, n))
        lines.append('')

    # Normatieve dekking (ISO/BIO/NIS2) — aggregaat over de bevindingen
    _cov = stats.get('coverage', {})
    if any(_cov.get(std) for std in ('iso27001', 'bio', 'nis2')):
        _en = taal == 'en'
        lines.append('### {}'.format(
            'Normative coverage (ISO/BIO/NIS2)' if _en else 'Normatieve dekking (ISO/BIO/NIS2)'))
        lines.append('')
        lines.append('*{}*'.format(
            '{} of {} findings mapped via CWE/OWASP category; indicative.'.format(stats.get('coverage_mapped', 0), stats['total'])
            if _en else
            '{} van {} bevindingen gekoppeld via CWE/OWASP-categorie; indicatief.'.format(stats.get('coverage_mapped', 0), stats['total'])))
        lines.append('')
        for std, titel in [('iso27001', 'ISO 27001:2022'), ('bio', 'BIO2'), ('nis2', 'NIS2 art. 21')]:
            rows = _cov.get(std) or []
            if not rows:
                continue
            lines.append('#### {}'.format(titel))
            lines.append('')
            lines.append('| Control | {} |'.format('Count' if _en else 'Aantal'))
            lines.append('|---|---|')
            for ctrl, n in rows:
                lines.append('| {} | {} |'.format(ctrl.replace('|', '\\|'), n))
            lines.append('')
    return '\n'.join(lines)


@rapport_bp.route('/dashboard/report/debrief/generate', methods=['GET'])
def gen_debrief():
    """Genereer het debrief-rapport (HTML + Markdown + DOCX indien pandoc)."""
    os.makedirs(_RAPPORT_DIR, exist_ok=True)
    from meuk.flask import project as _project
    s = _project.current_config() or _get_appdata()
    taal = (getattr(s, 'rapport_taal', '') if s else '') or 'nl'
    html = _generate_debrief_html(s, taal)
    schrijven(os.path.join(_RAPPORT_DIR, 'debrief.html'), html)
    md = _generate_debrief_markdown(s, taal)
    md_path = os.path.join(_RAPPORT_DIR, 'debrief.md')
    schrijven(md_path, md)
    try:
        from sh import pandoc
        _ref = (['--reference-doc=' + os.path.abspath(_DOCX_REFERENCE)]
                if os.path.exists(_DOCX_REFERENCE) else [])
        pandoc(md_path, *_ref, '-o', os.path.join(_RAPPORT_DIR, 'debrief.docx'))
    except Exception:
        pass
    return html


# ---------------------------------------------------------------------------
# SARIF 2.1.0 generatie
# ---------------------------------------------------------------------------

def _generate_sarif(findings, titel='', auteur=''):
    """Genereer SARIF 2.1.0 JSON output."""
    rules = []
    results = []
    for f in findings:
        rule_id = 'FINDING-{}'.format(str(f['nr']).zfill(3))
        rules.append({
            'id': rule_id,
            'name': f['titel'],
            'shortDescription': {'text': f['titel']},
            'fullDescription': {'text': f.get('beschrijving', '') or f['titel']},
            'properties': {
                'cvss': f['basescore'],
                'severity': f['severity'],
            },
        })
        result = {
            'ruleId': rule_id,
            'level': 'error' if f['severity'] in ('critical', 'high') else 'warning' if f['severity'] == 'medium' else 'note',
            'message': {'text': f.get('beschrijving', '') or f['titel']},
            'properties': {
                'cvss_score': f['basescore'],
                'cvss_vector': f.get('cvss_vector', ''),
                'remediation_status': f.get('remediation_status', 'open'),
            },
        }
        if f.get('locatie'):
            result['locations'] = [{'physicalLocation': {'artifactLocation': {'uri': f['locatie']}}}]
        if f.get('aanbeveling'):
            result['fixes'] = [{'description': {'text': _plain_markup(f['aanbeveling'])}}]
        results.append(result)

    return {
        '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {
                'driver': {
                    'name': 'Incompetent Bastard',
                    'version': '1.0',
                    'informationUri': 'https://github.com/incompetentbastard',
                    'rules': rules,
                },
            },
            'results': results,
            'invocations': [{
                'executionSuccessful': True,
                'properties': {
                    'report_title': titel,
                    'author': auteur,
                },
            }],
        }],
    }


# ---------------------------------------------------------------------------
# PPTX generatie
# ---------------------------------------------------------------------------

def _generate_pptx(findings, grouped, counts, titel, auteur, subtitel, datum, output_path):
    """Genereer PowerPoint presentatie met KPI's en findings."""
    from pptx import Presentation
    from pptx.util import Inches, Pt
    from pptx.enum.text import PP_ALIGN

    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)

    # Slide 1: Titelpagina
    slide = prs.slides.add_slide(prs.slide_layouts[0])
    slide.shapes.title.text = titel
    if slide.placeholders[1]:
        slide.placeholders[1].text = '{}\n{}\n{}'.format(subtitel, auteur, datum)

    # Slide 2: KPI overview
    slide = prs.slides.add_slide(prs.slide_layouts[5])
    slide.shapes.title.text = 'Summary'
    left = Inches(1)
    top = Inches(2)
    width = Inches(11)
    height = Inches(4)
    table = slide.shapes.add_table(7, 2, left, top, width, height).table
    table.cell(0, 0).text = 'Severity'
    table.cell(0, 1).text = 'Count'
    for i, sev in enumerate(['critical', 'high', 'medium', 'low', 'none'], 1):
        table.cell(i, 0).text = sev.capitalize()
        table.cell(i, 1).text = str(counts.get(sev, 0))
    table.cell(6, 0).text = 'Total'
    table.cell(6, 1).text = str(len(findings))

    # Slides per finding (top 10 max)
    for f in findings[:10]:
        slide = prs.slides.add_slide(prs.slide_layouts[1])
        slide.shapes.title.text = '[{}] {}'.format(str(f['nr']).zfill(3), f['titel'])
        body = slide.placeholders[1]
        tf = body.text_frame
        tf.text = 'CVSS: {} ({})'.format(f['basescore'], f['severity'])
        if f.get('beschrijving'):
            p = tf.add_paragraph()
            p.text = _plain_markup(f['beschrijving'])[:500]
            p.font.size = Pt(14)
        if f.get('aanbeveling'):
            p = tf.add_paragraph()
            p.text = 'Recommendation: ' + _plain_markup(f['aanbeveling'])[:300]
            p.font.size = Pt(14)
            p.font.bold = True

    prs.save(output_path)


# ---------------------------------------------------------------------------
# Rapport download
# ---------------------------------------------------------------------------

_LAZY_PANDOC_FORMATS = {'odt', 'epub'}


def _ensure_lazy_format(path):
    """Genereer odt/epub on-demand uit rapport_docx.md (niet bij elke build).

    (Her)genereert alleen als het doel ontbreekt of ouder is dan de bron-md.
    """
    src = os.path.join(_RAPPORT_DIR, 'rapport_docx.md')
    if not os.path.exists(src):
        return
    if os.path.exists(path) and os.path.getmtime(path) >= os.path.getmtime(src):
        return
    try:
        from sh import pandoc
        pandoc(src, '--toc', '--toc-depth=2',
               '--resource-path=' + os.path.abspath(_RAPPORT_DIR), '-o', path)
    except Exception:
        pass  # pandoc niet beschikbaar -> val terug op 404


@rapport_bp.route('/api/report/download/<fmt>')
def rapport_download(fmt):
    FORMATS = {
        'html': ('tex.html', 'text/html'),
        'md':   ('tex.md',   'text/markdown'),
        'tex':  ('rapport.tex', 'application/x-tex'),
        'pdf':  ('rapport.pdf', 'application/pdf'),
        'pdf-archief': ('rapport_pdfa.pdf', 'application/pdf'),
        'pdf-secure': ('rapport_secure.pdf', 'application/pdf'),
        'pdf-gelakt': ('rapport_gelakt.pdf', 'application/pdf'),
        'pdf-gelakt-secure': ('rapport_gelakt_secure.pdf', 'application/pdf'),
        'docx-gelakt': ('rapport_gelakt.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'),
        'html-gelakt': ('tex_gelakt.html', 'text/html'),
        'docx': ('rapport.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'),
        'odt':  ('rapport.odt',  'application/vnd.oasis.opendocument.text'),
        'stix': ('rapport.stix.json', 'application/json'),
        'sarif': ('rapport.sarif.json', 'application/json'),
        'pptx': ('rapport.pptx', 'application/vnd.openxmlformats-officedocument.presentationml.presentation'),
        'epub': ('rapport.epub', 'application/epub+zip'),
        'retest-html': ('rapport_retest.html', 'text/html'),
        'retest-md':   ('rapport_retest.md', 'text/markdown'),
        'retest-docx': ('rapport_retest.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'),
        'debrief-html': ('debrief.html', 'text/html'),
        'debrief-md':   ('debrief.md', 'text/markdown'),
        'debrief-docx': ('debrief.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'),
    }
    if fmt not in FORMATS:
        return jsonify({'error': 'Ongeldig formaat'}), 400
    filename, mimetype = FORMATS[fmt]
    path = os.path.join(_RAPPORT_DIR, filename)
    if fmt in _LAZY_PANDOC_FORMATS:
        _ensure_lazy_format(path)  # on-demand genereren bij eerste download
    if not os.path.exists(path):
        return jsonify({'error': 'Genereer eerst het rapport'}), 404
    # Downloadnaam: gebruik de echte bestandsnaam zodat extensies kloppen
    # (bijv. pdf-secure -> rapport_secure.pdf)
    return send_file(path, mimetype=mimetype, as_attachment=True,
                     download_name=filename)


# ---------------------------------------------------------------------------
# Logo upload: POST /api/report/logo
# ---------------------------------------------------------------------------

@rapport_bp.route('/api/report/logo', methods=['POST'])
def rapport_logo_upload():
    from werkzeug.utils import secure_filename as _sf
    if 'file' not in request.files:
        return jsonify({'ok': False, 'error': 'geen bestand'}), 400
    f = request.files['file']
    if not f.filename:
        return jsonify({'ok': False, 'error': 'geen bestandsnaam'}), 400
    ct = f.content_type or ''
    if not ct.startswith('image/'):
        return jsonify({'ok': False, 'error': 'alleen afbeeldingen toegestaan'}), 400
    os.makedirs(_RAPPORT_DIR, exist_ok=True)
    safe = _sf(f.filename)
    dest = os.path.join(_RAPPORT_DIR, 'logo_' + safe)
    f.save(dest)
    from meuk.flask import project as _project
    s = _project.current_config() or _get_appdata()
    if s:
        s.rapport_logo_path = dest
        db.session.commit()
    return jsonify({'ok': True, 'path': dest})


# ---------------------------------------------------------------------------
# Scan-run importeren als rauwe-LaTeX notitie
# ---------------------------------------------------------------------------

def _create_scan_note(run_dir, taal='nl', naam_override=''):
    """Genereer de LaTeX-samenvatting voor een run-map en sla op als notitie.
    Returns (note_dict, None) of (None, foutmelding)."""
    from meuk.flask import project as _project
    from meuk.flask.scan_tex import build_scan_tex
    try:
        naam, tex = build_scan_tex(run_dir, taal=taal)
    except Exception as exc:  # noqa: BLE001 — generator mag de UI nooit breken
        return None, 'generatie mislukt: {}'.format(exc)
    naam = (naam_override or naam)[:255]
    note = db_notes(naam=naam, uitwerken=tex, rapport=True, latex_raw=True,
                    opdracht_id=_project.current_opdracht_id())
    db.session.add(note)
    db.session.commit()
    return {'id': note.id, 'naam': naam}, None


_SCAN_SEV_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3,
                   'warn': 4, 'info': 5, '': 6}

# Concept-hints: scan-term (regex) -> trefwoorden die in de beste templatetitel staan.
_CONCEPT_HINTS = [
    (r'header|x-frame|frame-ancestors|csp|content-security|referrer-policy|'
     r'permissions-policy|x-content-type|hsts|strict-transport',
     ['security headers', 'headers', 'clickjacking']),
    (r'cookie|httponly|samesite|\bsecure\b', ['cookie']),
    (r'\btls\b|\bssl\b|cipher|\bkem\b|certificate|\bcert\b|expires|versleutel|'
     r'crypto|rc4|3des|forward secrecy|\bprotocol', ['tls', 'cryptographic', 'certificate', 'encryption']),
    (r'cors|access-control-allow', ['cors']),
    (r'\bsql', ['sql injection']),
    (r'xss|cross-site scripting|\bscript', ['cross-site scripting']),
    (r'redirect', ['open redirect']),
    (r'directory listing|index of', ['directory listing']),
    (r'outdated|version|verouderd|\bcve', ['outdated', 'vulnerable']),
    (r'traversal|\blfi\b|path', ['path traversal']),
]


def _rank_template(issue_text, cwes, tmpl):
    """Relevantiescore van een template voor een scan-issue (hoger = beter)."""
    score = 0
    if (tmpl.cwe or '') and str(tmpl.cwe) in cwes:
        score += 1000
    title = (tmpl.titel or '').lower()
    for pat, kws in _CONCEPT_HINTS:
        if _re.search(pat, issue_text):
            score += 50 * sum(1 for kw in kws if kw in title)
    toks = {w for w in _re.split(r'[^a-z0-9]+', issue_text) if len(w) >= 4}
    ttoks = {w for w in _re.split(r'[^a-z0-9]+', title) if len(w) >= 4}
    score += len(toks & ttoks)
    return score


_SCAN_EV_SENTINEL = '%%SCANEV%%'


def _scan_evidence(run_dir, evidence_rel, max_lines=40):
    """(commando, response) uit de evidence van een scan-finding, pad-ingekort."""
    if not evidence_rel:
        return '', ''
    from meuk.flask.scan_tex import _read_text, _shorten_paths, _cmd_caption
    ev_abs = os.path.join(run_dir, evidence_rel)
    resp = _read_text(ev_abs)
    cmd = _read_text(os.path.join(os.path.dirname(ev_abs), 'command.txt'))
    run_name = os.path.basename(os.path.normpath(os.path.abspath(run_dir)))
    cmd = _cmd_caption(cmd, run_name=run_name)
    resp = _shorten_paths(resp, run_name, generic=False)
    resp = ''.join(ch for ch in resp if ch in '\n\t' or ord(ch) >= 32)
    lines = resp.splitlines()
    truncated = len(lines) > max_lines
    resp = '\n'.join(lines[:max_lines]).rstrip()
    if truncated:
        resp += '\n... (afgekapt)'
    return cmd, resp


def _finding_evidence_tex(cmd, resp, taal='nl'):
    """Raw-LaTeX bewijsblok voor een bevinding — zelfde vorm als in de scan-notitie."""
    from meuk.flask.scan_tex import _tex, _tex_breakable, _lstlisting
    _en = taal == 'en'
    out = [r'\ibfindingsection{%s}' % _tex('Evidence' if _en else 'Bewijs')]
    out.append(r'\noindent %s \opdracht{%s} %s' % (
        _tex('The following command' if _en else 'De volgende opdracht'),
        _tex_breakable(cmd or '(leeg)'),
        _tex('gave the following response:' if _en else 'gaf de volgende response:')))
    out.append(_lstlisting(resp, cmd))
    return '\n'.join(out)


def _scan_candidates(run_dir, taal='nl'):
    """Gededupliceerde scan-issues met kandidaat-templates (op NCSC-code + CWE).

    Promoot niets automatisch; de operator kiest welke bevinding wordt aangemaakt.
    """
    from meuk.flask.scan_tex import _read_json
    d = _read_json(os.path.join(run_dir, 'findings.json'), {}) or {}
    findings = d.get('findings', []) if isinstance(d, dict) else (d if isinstance(d, list) else [])
    groups = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        title = (f.get('title') or f.get('rule') or '').strip()
        if not title:
            continue
        g = groups.setdefault(title, {'title': title, 'severity': f.get('severity', '') or '',
                                      'count': 0, 'ncsc': set(), 'cwe': set(),
                                      'endpoint': f.get('endpoint', '') or '',
                                      'tool': f.get('tool', '') or '',
                                      'evidence_rel': f.get('evidence', '') or ''})
        g['count'] += 1
        for n in (f.get('ncsc') or []):
            if isinstance(n, dict):
                code = n.get('parent') or n.get('id', '')
            else:
                code = str(n)
            if code:
                g['ncsc'].add(code)
        for c in (f.get('cwe') or []):
            if c:
                g['cwe'].add(str(c))

    out = []
    for g in groups.values():
        cands = {}
        if g['ncsc']:
            for t in db_bevindingen_templates.query.filter(
                    db_bevindingen_templates.ncsc.in_(list(g['ncsc']))).all():
                cands[t.id] = (t, 'NCSC {}'.format(t.ncsc or ''))
        for cwe in g['cwe']:
            for t in db_bevindingen_templates.query.filter(
                    db_bevindingen_templates.cwe == cwe).all():
                cands.setdefault(t.id, (t, 'CWE {}'.format(cwe)))
        issue_text = '{} {}'.format(g['title'], g['tool']).lower()
        scored = [(_rank_template(issue_text, g['cwe'], t), t, why)
                  for t, why in cands.values()]
        scored.sort(key=lambda x: (-x[0], (x[1].titel or '').lower()))
        candidates = [{'id': t.id, 'titel': t.titel, 'bevtype': t.bevtype or '',
                       'basescore': t.basescore or '', 'match': why}
                      for _s, t, why in scored]
        ev_cmd, ev_resp = _scan_evidence(run_dir, g['evidence_rel'])
        out.append({'title': g['title'], 'severity': g['severity'], 'count': g['count'],
                    'ncsc': sorted(g['ncsc']), 'cwe': sorted(g['cwe']),
                    'endpoint': g['endpoint'],
                    'evidence_cmd': ev_cmd, 'evidence_resp': ev_resp,
                    'candidates': candidates})
    out.sort(key=lambda i: (0 if i['candidates'] else 1,
                            _SCAN_SEV_ORDER.get(i['severity'], 9), i['title']))
    return out


def _find_run_dir(base):
    """Vind de scan-run-map (die met config.json) onder een geëxtraheerde zip."""
    if os.path.isfile(os.path.join(base, 'config.json')):
        return base
    for root, _dirs, files in os.walk(base):
        if 'config.json' in files:
            return root
    return None


# Limieten tegen zip-bommen
_ZIP_MAX_MEMBERS = 5000
_ZIP_MAX_TOTAL = 200 * 1024 * 1024  # 200 MB ongecomprimeerd


def _safe_extract_zip(fileobj, dest):
    """Pak een zip veilig uit naar dest (zip-slip- en zip-bom-bescherming)."""
    import zipfile
    with zipfile.ZipFile(fileobj) as zf:
        infos = zf.infolist()
        if len(infos) > _ZIP_MAX_MEMBERS:
            raise ValueError('te veel bestanden in zip')
        total = sum(i.file_size for i in infos)
        if total > _ZIP_MAX_TOTAL:
            raise ValueError('zip te groot (ongecomprimeerd)')
        dest_real = os.path.realpath(dest)
        for info in infos:
            name = info.filename
            if info.is_dir():
                continue
            # Normaliseer en weer absolute paden / traversal
            target = os.path.realpath(os.path.join(dest, name))
            if not (target == dest_real or target.startswith(dest_real + os.sep)):
                raise ValueError('ongeldig pad in zip: {}'.format(name))
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zf.open(info) as src, open(target, 'wb') as out:
                shutil.copyfileobj(src, out)


@rapport_bp.route('/api/report/scan-import', methods=['POST'])
def rapport_scan_import():
    """Lees een scan-run-map op schijf, genereer een LaTeX-samenvatting en sla
    die op als rauwe-LaTeX notitie (rapport=True) bij de actieve opdracht."""
    body = request.get_json(silent=True) or {}
    run_dir = (body.get('run_dir') or '').strip()
    if not run_dir:
        return jsonify({'ok': False, 'error': 'run_dir ontbreekt'}), 400
    run_dir = os.path.abspath(os.path.expanduser(run_dir))
    if not os.path.isdir(run_dir):
        return jsonify({'ok': False, 'error': 'map niet gevonden: {}'.format(run_dir)}), 404
    taal = (body.get('taal') or 'nl').strip() or 'nl'
    note, err = _create_scan_note(run_dir, taal=taal, naam_override=(body.get('naam') or ''))
    if err:
        return jsonify({'ok': False, 'error': err}), 500
    return jsonify({'ok': True, **note, 'candidates': _scan_candidates(run_dir, taal)})


@rapport_bp.route('/api/report/scan-import-zip', methods=['POST'])
def rapport_scan_import_zip():
    """Upload een scan-output-zip, pak 'm veilig uit en verwerk als notitie."""
    import tempfile
    up = request.files.get('zip')
    if up is None or not up.filename:
        return jsonify({'ok': False, 'error': 'geen zip-bestand ontvangen'}), 400
    if not up.filename.lower().endswith('.zip'):
        return jsonify({'ok': False, 'error': 'alleen .zip-bestanden'}), 400
    taal = (request.form.get('taal') or 'nl').strip() or 'nl'
    naam_override = request.form.get('naam') or ''
    tmp = tempfile.mkdtemp(prefix='scanzip_')
    try:
        try:
            _safe_extract_zip(up.stream, tmp)
        except Exception as exc:  # noqa: BLE001
            return jsonify({'ok': False, 'error': 'uitpakken mislukt: {}'.format(exc)}), 400
        run_dir = _find_run_dir(tmp)
        if not run_dir:
            return jsonify({'ok': False, 'error': 'geen scan-run (config.json) in zip'}), 400
        note, err = _create_scan_note(run_dir, taal=taal, naam_override=naam_override)
        if err:
            return jsonify({'ok': False, 'error': err}), 500
        return jsonify({'ok': True, **note, 'candidates': _scan_candidates(run_dir, taal)})
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@rapport_bp.route('/api/report/scan-create-findings', methods=['POST'])
def rapport_scan_create_findings():
    """Maak rapportbevindingen aan uit de door de operator gekozen templates."""
    body = request.get_json(silent=True) or {}
    items = body.get('items') or []
    if not isinstance(items, list) or not items:
        return jsonify({'ok': False, 'error': 'geen items'}), 400
    created = []
    for it in items:
        try:
            tid = int(it.get('template_id'))
        except (TypeError, ValueError):
            continue
        tmpl = db.session.get(db_bevindingen_templates, tid)
        if not tmpl:
            continue
        naam = (it.get('titel') or tmpl.titel or '')[:255]
        bev = db_bevindingen(
            naam=naam, ref=str(tmpl.id),
            locatie=(it.get('locatie') or '')[:255], status='draft',
        )
        bev.invoegen = tmpl.nlbeschrijving or tmpl.enbeschrijving or ''
        bev.basescore = tmpl.basescore or ''
        bev.cvss = tmpl.cvss or ''
        # Scan-evidence gestructureerd opslaan (commando + response) achter een
        # sentinel; de rapportgeneratie bouwt daar het bewijsblok uit.
        cmd = (it.get('evidence_cmd') or '')[:1000]
        resp = (it.get('evidence_resp') or '')[:20000]
        if cmd or resp:
            bev.uitwerken = _SCAN_EV_SENTINEL + json.dumps({'cmd': cmd, 'resp': resp})
        db.session.add(bev)
        db.session.flush()
        created.append({'id': bev.id, 'naam': bev.naam})
    db.session.commit()
    return jsonify({'ok': True, 'created': len(created), 'findings': created})


# Report versions: GET /api/report/versions
# ---------------------------------------------------------------------------

@rapport_bp.route('/api/report/versions', methods=['GET'])
def rapport_versions():
    versions_dir = os.path.join(_RAPPORT_DIR, 'versions')
    if not os.path.exists(versions_dir):
        return jsonify({'versions': []})
    items = []
    for name in sorted(os.listdir(versions_dir), reverse=True):
        path = os.path.join(versions_dir, name)
        if os.path.isdir(path):
            files = os.listdir(path)
            items.append({'timestamp': name, 'files': files,
                          'has_manifest': 'SHA256SUMS' in files})
    return jsonify({'versions': items})


@rapport_bp.route('/api/report/versions/<ts>/manifest', methods=['GET'])
def rapport_version_manifest(ts):
    """Lever het SHA256SUMS-integriteitsmanifest van een versie (timestamp gevalideerd)."""
    if not _re.fullmatch(r'\d{8}_\d{6}', ts or ''):
        return jsonify({'ok': False, 'error': 'ongeldige versie'}), 400
    p = os.path.join(_RAPPORT_DIR, 'versions', ts, 'SHA256SUMS')
    if not os.path.exists(p):
        return jsonify({'ok': False, 'error': 'geen manifest voor deze versie'}), 404
    with open(p, encoding='utf-8') as fh:
        return jsonify({'ok': True, 'timestamp': ts, 'manifest': fh.read()})


def _version_md(ts):
    """Lees de Markdown-snapshot van een versie (timestamp gevalideerd)."""
    if not ts or not _re.fullmatch(r'\d{8}_\d{6}', ts):
        return None
    p = os.path.join(_RAPPORT_DIR, 'versions', ts, 'rapport_docx.md')
    return lezen(p) if os.path.exists(p) else None


def _version_findings(md):
    """Map {finding-id: titel} uit een Markdown-snapshot."""
    return dict(_re.findall(r'^### \[(\d+)\] (.+?) \(CVSS', md or '', _re.M))


@rapport_bp.route('/api/report/versions/diff', methods=['GET'])
def rapport_versions_diff():
    """Vergelijk twee rapportversies: toegevoegde/verwijderde/gewijzigde
    bevindingen + een unified tekst-diff."""
    a = request.args.get('a')
    b = request.args.get('b')
    ma, mb = _version_md(a), _version_md(b)
    if ma is None or mb is None:
        return jsonify({'ok': False, 'error': 'versie niet gevonden'}), 404
    fa, fb = _version_findings(ma), _version_findings(mb)
    added = [{'id': k, 'titel': fb[k]} for k in fb if k not in fa]
    removed = [{'id': k, 'titel': fa[k]} for k in fa if k not in fb]
    changed = [{'id': k, 'van': fa[k], 'naar': fb[k]}
               for k in fa if k in fb and fa[k] != fb[k]]
    diff = list(difflib.unified_diff(ma.splitlines(), mb.splitlines(),
                                     fromfile=a, tofile=b, lineterm=''))
    return jsonify({
        'ok': True, 'a': a, 'b': b,
        'added': added, 'removed': removed, 'changed': changed,
        'count': {'added': len(added), 'removed': len(removed), 'changed': len(changed)},
        'diff': '\n'.join(diff[:600]),
    })


# ---------------------------------------------------------------------------
# Report validation: GET /api/report/validate
# ---------------------------------------------------------------------------

# Placeholderteksten die niet in een definitief auditrapport thuishoren.
_PLACEHOLDER_PAT = _re.compile(
    r'\b(tbd|todo|xxx|lorem ipsum|nader te bepalen|nog in te vullen|placeholder)\b',
    _re.I)


def _findings_completeness(findings, taal='nl'):
    """Preflight-poort per bevinding. Audit-eis: elke geëxporteerde bevinding
    heeft impact, aanbeveling en een CVSS-vector; kritieke/hoge bevindingen
    hebben bewijs. Dit levert blokkerende meldingen (errors). Placeholderteksten
    (TBD/TODO/...) leveren waarschuwingen. Retourneert (errors, warnings)."""
    _en = taal == 'en'

    def _lbl(nr, titel):
        return ('Finding {} ({})' if _en else 'Bevinding {} ({})').format(
            str(nr).zfill(3), titel or '')

    errors, warnings = [], []
    for f in findings:
        lbl = _lbl(f.get('nr'), f.get('titel'))
        if not (f.get('impact') or '').strip():
            errors.append('{}: {}'.format(lbl, 'impact missing' if _en else 'impact ontbreekt'))
        if not (f.get('aanbeveling') or '').strip():
            errors.append('{}: {}'.format(lbl, 'recommendation missing' if _en else 'aanbeveling ontbreekt'))
        if not (f.get('cvss_vector') or '').strip():
            errors.append('{}: {}'.format(lbl, 'CVSS vector missing' if _en else 'CVSS-vector ontbreekt'))
        if f.get('severity') in ('critical', 'high'):
            if not (f.get('evidence_db') or f.get('evidence_cmd') or f.get('evidence_resp')):
                errors.append('{}: {}'.format(
                    lbl, 'no evidence (critical/high)' if _en else 'geen bewijs (kritiek/hoog)'))
        blob = ' '.join(str(f.get(k) or '') for k in ('beschrijving', 'impact', 'aanbeveling'))
        if _PLACEHOLDER_PAT.search(blob):
            warnings.append('{}: {}'.format(
                lbl, 'placeholder text (TBD/TODO)' if _en else 'placeholdertekst (TBD/TODO)'))
    return errors, warnings


@rapport_bp.route('/api/report/validate', methods=['GET'])
def rapport_validate():
    from meuk.flask import project as _project
    _oid = _project.current_opdracht_id()
    s = _project.config_for(_oid) or _get_appdata()
    warnings = []
    errors = []
    notices = []

    if not s or not getattr(s, 'rapport_titel', ''):
        errors.append('Rapport titel is niet ingesteld')
    if not s or not getattr(s, 'rapport_auteur', ''):
        warnings.append('Auteur is niet ingesteld')

    findings = _project.apply_scope(
        db_bevindingen.query.filter(db_bevindingen.status == 'final'),
        db_bevindingen.opdracht_id, _oid).all()
    if not findings:
        warnings.append('Geen findings met status "definitief"')

    templates = db_bevindingen_templates.query.all()
    tmpl_map = {str(t.id): t for t in templates}
    for f in findings:
        if not f.ref or str(f.ref) not in tmpl_map:
            warnings.append('Finding {} ({}) heeft geen geldige template'.format(f.id, f.naam or ''))
        if not f.basescore:
            tmpl = tmpl_map.get(str(f.ref))
            if not tmpl or not tmpl.basescore:
                warnings.append('Finding {} ({}) heeft geen CVSS score'.format(f.id, f.naam or ''))

    notes_count = _project.apply_scope(
        db_notes.query.filter_by(rapport=True),
        db_notes.opdracht_id, _oid).count()
    if notes_count == 0:
        warnings.append('Geen notes geselecteerd voor het rapport')

    # Audit-poort: per-bevinding volledigheidscontrole op dezelfde scope.
    taal = (getattr(s, 'rapport_taal', '') if s else '') or 'nl'
    base_q = _project.apply_scope(
        db_bevindingen.query.filter(db_bevindingen.status == 'final'),
        db_bevindingen.opdracht_id, _oid)
    c_err, c_warn = _findings_completeness(_build_findings_data(base_q, taal=taal), taal=taal)
    errors.extend(c_err)
    warnings.extend(c_warn)

    # Pre-flight lakdekking: welke afbeeldingen missen een gelakte kopie?
    # lak_used = er wordt ergens geredigeerd (lak-tekst of -kopie aanwezig). Bij
    # actieve redactie is een ontbrekende kopie een waarschuwing ([GELAKT]-
    # placeholder in de gelakte versie); zonder actieve redactie tonen we de
    # ontbrekende kopieen als neutrale info-checklist, zodat je bewust kunt
    # kiezen "deze hoeft niet" i.p.v. een gevoelige afbeelding per ongeluk te missen.
    note_texts = [n.uitwerken or '' for n in _project.apply_scope(
        db_notes.query.filter_by(rapport=True), db_notes.opdracht_id, _oid).all()]
    lak_used = os.path.isdir(os.path.join(_SCREENSHOT_SRC, 'lakken'))
    lak_missing = []
    for f in findings:
        if r'\lakken{' in (getattr(f, 'uitwerken', '') or ''):
            lak_used = True
        for ev in db_evidence.query.filter_by(finding_id=f.id).all():
            if not (ev.content_type or '').startswith('image/'):
                continue
            if os.path.exists(os.path.join(_EVIDENCE_SRC, str(f.id),
                                           'lakken', ev.filename)):
                lak_used = True
            else:
                lak_missing.append('bevinding {} / {}'.format(
                    f.id, ev.original_filename or ev.filename))
    if any(r'\lakken{' in t for t in note_texts):
        lak_used = True
    # \plaatje{..}-projectafbeeldingen: alleen bestaande screenshots zonder
    # gelakte kopie flaggen (onbekende namen zijn evidence-assets -> overslaan).
    for t in [getattr(f, 'uitwerken', '') or '' for f in findings] + note_texts:
        for naam in _re.findall(r'\\plaatje\{([^}]+)\}', t):
            naam = naam.strip()
            if not os.path.exists(os.path.join(_SCREENSHOT_SRC, naam)):
                continue
            if os.path.exists(os.path.join(_SCREENSHOT_SRC, 'lakken', naam)):
                lak_used = True
            else:
                lak_missing.append('plaatje {}'.format(naam))
    if lak_missing:
        n = len(lak_missing)
        toon = '; '.join(lak_missing[:8]) + ('; …' if n > 8 else '')
        if lak_used:
            warnings.append(
                '{} afbeelding(en) zonder gelakte kopie: in de gelakte versie '
                'verschijnt daarvoor een [GELAKT]-placeholder ({})'.format(n, toon))
        else:
            notices.append(
                '{} afbeelding(en) hebben geen gelakte kopie en verschijnen '
                'volledig in beide versies. Maak een gelakte kopie als ze gevoelig '
                'zijn ({})'.format(n, toon))

    return jsonify({
        'ok': len(errors) == 0,
        'errors': errors,
        'warnings': warnings,
        'notices': notices,
        'findings_count': len(findings),
    })


# ---------------------------------------------------------------------------
# Report metrics: GET /api/report/metrics
# ---------------------------------------------------------------------------

@rapport_bp.route('/api/report/metrics', methods=['GET'])
def rapport_metrics():
    from meuk.flask import project as _project
    findings = _project.apply_scope(
        db_bevindingen.query.filter(db_bevindingen.status == 'final'),
        db_bevindingen.opdracht_id, _project.current_opdracht_id()).all()
    templates = db_bevindingen_templates.query.all()
    tmpl_map = {str(t.id): t for t in templates}

    severity_dist = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'none': 0}
    remediation_dist = {'open': 0, 'in_progress': 0, 'fixed': 0, 'verified': 0, 'accepted': 0}
    owasp_dist = {}

    for f in findings:
        tmpl = tmpl_map.get(str(f.ref))
        bs = f.basescore or (tmpl.basescore if tmpl else '') or '0'
        sev, _ = _cvss_to_severity(bs)
        severity_dist[sev] = severity_dist.get(sev, 0) + 1

        rem = getattr(f, 'remediation_status', 'open') or 'open'
        remediation_dist[rem] = remediation_dist.get(rem, 0) + 1

        owasp_num = tmpl.owasp if tmpl else ''
        if owasp_num and str(owasp_num).isdigit():
            num = int(owasp_num)
            if 1 <= num <= 10:
                label = owasptop10[num - 1]
                owasp_dist[label] = owasp_dist.get(label, 0) + 1

    return jsonify({
        'total': len(findings),
        'severity': severity_dist,
        'remediation': remediation_dist,
        'owasp': owasp_dist,
    })


# ---------------------------------------------------------------------------
# Async report generation
# ---------------------------------------------------------------------------

def _async_generate(run_id, app, include_draft, include_checklists='', opdracht_id=None):
    """Worker die gen_rapport() uitvoert in een achtergrond-thread."""
    with _async_lock:
        _async_runs[run_id]['status'] = 'running'
    try:
        qs = 'include_draft=' + ('1' if include_draft else '0')
        if include_checklists:
            qs += '&include_checklists=' + include_checklists
        if opdracht_id is not None:
            qs += '&opdracht_id=' + str(opdracht_id)
        with app.test_request_context('/dashboard/report/generate?' + qs):
            gen_rapport()
        with _async_lock:
            _async_runs[run_id]['status'] = 'success'
            _async_runs[run_id]['finished_at'] = datetime.datetime.now().isoformat()
    except Exception as exc:
        with _async_lock:
            _async_runs[run_id]['status'] = 'failed'
            _async_runs[run_id]['finished_at'] = datetime.datetime.now().isoformat()
            _async_runs[run_id]['error'] = str(exc)


@rapport_bp.route('/api/report/generate', methods=['POST'])
def rapport_generate_async():
    """Start async rapport generatie. Retourneert run_id voor polling."""
    from flask import current_app
    run_id = str(_uuid.uuid4())
    include_draft = request.json.get('include_draft', False) if request.is_json else False
    include_checklists = request.json.get('include_checklists', '') if request.is_json else ''
    from meuk.flask import project as _project
    opdracht_id = _project.current_opdracht_id()
    with _async_lock:
        _async_runs[run_id] = {
            'id': run_id,
            'status': 'queued',
            'started_at': datetime.datetime.now().isoformat(),
            'finished_at': None,
            'error': None,
        }
    t = threading.Thread(
        target=_async_generate,
        args=(run_id, current_app._get_current_object(), include_draft,
              include_checklists, opdracht_id),
        daemon=True,
    )
    t.start()
    return jsonify({'ok': True, 'run_id': run_id})


@rapport_bp.route('/api/report/generate/<run_id>', methods=['GET'])
def rapport_generate_status(run_id):
    """Poll async generatie status."""
    with _async_lock:
        run = _async_runs.get(run_id)
    if not run:
        return jsonify({'error': 'run not found'}), 404
    return jsonify(run)


# ===========================================================================
# Rapport-template-beheer: eigen templates + selectie + eigen .tex
# ===========================================================================

_REPORT_TPL_DIR = os.path.join(os.path.dirname(__file__), 'db', 'report_templates')
_VALID_SCOPES = ('all', 'critical_high', 'top3')


def _rtpl_dict(row):
    try:
        secs = json.loads(row.sections or '{}')
    except (json.JSONDecodeError, TypeError):
        secs = {}
    secs = _apply_legacy_sections(secs)
    sections = _all_sections(True)
    sections.update({k: bool(v) for k, v in secs.items() if k in _SECTION_KEYS})
    try:
        order = json.loads(row.section_order or '[]')
    except (json.JSONDecodeError, TypeError):
        order = []
    return {
        'id': row.id, 'naam': row.naam, 'builtin': False,
        'findings_scope': row.findings_scope or 'all',
        'sections': sections,
        'section_order': _normalize_order(order),
        'has_custom_tex': bool(row.custom_tex_path),
        'taal': row.taal or '',
    }


def _clean_sections(raw):
    if not isinstance(raw, dict):
        return _all_sections(True)
    raw = _apply_legacy_sections(dict(raw))
    return {k: bool(raw.get(k, True)) for k in _SECTION_KEYS}


@rapport_bp.route('/api/report/templates', methods=['GET'])
def report_templates_list():
    builtin = [{
        'id': None, 'variant': key, 'naam': key, 'builtin': True,
        'findings_scope': v['findings_scope'], 'sections': v['sections'],
        'section_order': _normalize_order([]),
        'has_custom_tex': False,
    } for key, v in _BUILTIN_VARIANTS.items()]
    custom = [_rtpl_dict(r) for r in db_rapport_template.query.order_by(db_rapport_template.naam).all()]
    # Huidige selectie van het actieve project
    from meuk.flask import project as _project
    cfg = _project.current_config()
    sel = {'template_id': getattr(cfg, 'rapport_template_id', None),
           'variant': (getattr(cfg, 'rapport_template_variant', '') or 'detailed')}
    return jsonify({'ok': True, 'section_keys': list(_SECTION_KEYS),
                    'reorderable_keys': list(_REORDERABLE_SECTIONS),
                    'builtin': builtin, 'custom': custom, 'selected': sel})


@rapport_bp.route('/api/report/templates', methods=['POST'])
def report_templates_create():
    body = request.get_json(silent=True) or {}
    naam = (body.get('naam') or '').strip()
    if not naam:
        return jsonify({'ok': False, 'error': 'naam is verplicht'}), 400
    if db_rapport_template.query.filter_by(naam=naam[:200]).first():
        return jsonify({'ok': False, 'error': 'naam bestaat al'}), 409
    scope = body.get('findings_scope', 'all')
    row = db_rapport_template(
        naam=naam[:200],
        findings_scope=scope if scope in _VALID_SCOPES else 'all',
        sections=json.dumps(_clean_sections(body.get('sections'))),
        section_order=json.dumps(_normalize_order(body.get('section_order') or [])),
        taal=(body.get('taal') or '')[:5],
    )
    db.session.add(row)
    db.session.commit()
    return jsonify({'ok': True, 'id': row.id, 'naam': row.naam})


@rapport_bp.route('/api/report/templates/<int:tid>', methods=['POST'])
def report_templates_update(tid):
    row = db.session.get(db_rapport_template, tid)
    if not row:
        return jsonify({'ok': False, 'error': 'niet gevonden'}), 404
    body = request.get_json(silent=True) or {}
    if 'naam' in body:
        naam = (body.get('naam') or '').strip()
        if not naam:
            return jsonify({'ok': False, 'error': 'naam mag niet leeg zijn'}), 400
        row.naam = naam[:200]
    if 'findings_scope' in body and body['findings_scope'] in _VALID_SCOPES:
        row.findings_scope = body['findings_scope']
    if 'sections' in body:
        row.sections = json.dumps(_clean_sections(body.get('sections')))
    if 'section_order' in body:
        row.section_order = json.dumps(_normalize_order(body.get('section_order') or []))
    if 'taal' in body:
        row.taal = (body.get('taal') or '')[:5]
    db.session.commit()
    return jsonify({'ok': True, 'id': row.id})


@rapport_bp.route('/api/report/templates/<int:tid>', methods=['DELETE'])
def report_templates_delete(tid):
    row = db.session.get(db_rapport_template, tid)
    if not row:
        return jsonify({'ok': False, 'error': 'niet gevonden'}), 404
    # Verwijs-koppelingen op projecten opheffen + eigen .tex opruimen
    for cfg in db_opdracht_config.query.filter_by(rapport_template_id=tid).all():
        cfg.rapport_template_id = None
    if row.custom_tex_path and os.path.exists(row.custom_tex_path):
        try:
            os.remove(row.custom_tex_path)
        except OSError:
            pass
    db.session.delete(row)
    db.session.commit()
    return jsonify({'ok': True})


# ---------------------------------------------------------------------------
# Eigen .tex: variabelen-referentie + dry-run-validatie
# ---------------------------------------------------------------------------

# De variabelen die gen_rapport aan de LaTeX-template doorgeeft. Dit is de
# naslag die in de UI wordt getoond zodat een eigen .tex geldige verwijzingen
# gebruikt (delimiters: [% ... %] voor logica, [[ ... ]] voor waarden).
_TEX_CONTEXT_VARS = [
    {'naam': 'titel', 'type': 'tekst', 'omschrijving': 'Rapporttitel'},
    {'naam': 'subtitel', 'type': 'tekst', 'omschrijving': 'Ondertitel'},
    {'naam': 'auteur', 'type': 'tekst', 'omschrijving': 'Auteur'},
    {'naam': 'project', 'type': 'tekst', 'omschrijving': 'Projectnaam'},
    {'naam': 'classificatie', 'type': 'tekst', 'omschrijving': 'TLP-classificatie'},
    {'naam': 'tlp_color', 'type': 'tekst', 'omschrijving': 'LaTeX-kleurnaam voor de TLP-band'},
    {'naam': 'datum', 'type': 'tekst', 'omschrijving': 'Rapportdatum'},
    {'naam': 'is_draft', 'type': 'bool', 'omschrijving': 'True bij een conceptrapport'},
    {'naam': 'taal', 'type': 'tekst', 'omschrijving': "'nl' of 'en'"},
    {'naam': 'sections', 'type': 'dict', 'omschrijving': 'Per sectiesleutel of die aan staat, bv. [% if sections.bevindingen %]'},
    {'naam': 'findings', 'type': 'lijst', 'omschrijving': 'Bevindingen; velden o.a. id, titel, beschrijving, uitwerking_detail (vrije uitwerking, getoond vóór impact), impact, aanbeveling, aanbeveling_overzicht (beknopt, voor overzichtstabel), basescore, severity, locatie, assets, evidence, related'},
    {'naam': 'grouped_findings', 'type': 'lijst', 'omschrijving': 'Lijst van (groepsnaam, [bevindingen]) gegroepeerd op severity'},
    {'naam': 'bevindingenlijst_rows', 'type': 'lijst', 'omschrijving': 'Compacte bevindingenlijst (id, titel, risk, color, fg), gesorteerd op ernst'},
    {'naam': 'cia_triad', 'type': 'dict', 'omschrijving': 'CIA-triade uit CVSS C/I/A: n, c/i/a (%), c_r/i_r/a_r (TikZ-straal 0..3cm), intro; None als geen bruikbare vectoren'},
    {'naam': 'subsequent_triad', 'type': 'dict', 'omschrijving': 'Vervolgsysteem-impact uit CVSS 4.0 SC/SI/SA; zelfde vorm als cia_triad; None als afwezig'},
    {'naam': 'exploit_profile', 'type': 'dict', 'omschrijving': 'Exploiteerbaarheids-verdeling: n + metrics[] (name, items[]{label,count}); None als geen vectoren'},
    {'naam': 'direct_rows', 'type': 'lijst', 'omschrijving': 'Direct exploiteerbare bevindingen (AV:N/PR:N/UI:N) in bevindingenlijst-vorm (id, titel, risk, color, fg)'},
    {'naam': 'direct_intro', 'type': 'tekst', 'omschrijving': 'Introzin bij de direct-exploiteerbare-bijlage'},
    {'naam': 'impact_gauge', 'type': 'dict', 'omschrijving': 'Impact-meter uit CIA: n, index (0..100), index_label, gauge_angle; None als geen vectoren'},
    {'naam': 'top_risk_gauge', 'type': 'dict', 'omschrijving': 'Risicometer hoogste bevinding: score (CVSS), pct, label, nr, titel, gauge_angle; None als geen scores'},
    {'naam': 'counts', 'type': 'dict', 'omschrijving': 'Aantallen per severity: critical/high/medium/low/none'},
    {'naam': 'scoped_hosts', 'type': 'lijst', 'omschrijving': 'Hosts binnen scope'},
    {'naam': 'scope_targets', 'type': 'lijst', 'omschrijving': 'Scope-doelen (target, type, beschrijving)'},
    {'naam': 'notes', 'type': 'lijst', 'omschrijving': 'Verkenningsnotities'},
    {'naam': 'testtype', 'type': 'tekst', 'omschrijving': "'pentest' of 'redteam'"},
    {'naam': 'testscope', 'type': 'tekst', 'omschrijving': 'blackbox/greybox/whitebox'},
    {'naam': 'testscopes', 'type': 'lijst', 'omschrijving': 'Alle gekozen scope-typen'},
    {'naam': 'management_samenvatting', 'type': 'tekst', 'omschrijving': 'Managementsamenvatting'},
    {'naam': 'legsup_startpunt', 'type': 'tekst', 'omschrijving': 'Red team: assumed-breach startpunt'},
    {'naam': 'legsup_privileges', 'type': 'tekst', 'omschrijving': 'Red team: privilege-niveaus'},
    {'naam': 'legsup_informatie', 'type': 'tekst', 'omschrijving': 'Red team: verstrekte informatie'},
    {'naam': 'scenarios', 'type': 'lijst', 'omschrijving': "Red team: scenario's (naam, beschrijving)"},
    {'naam': 'checklists', 'type': 'lijst', 'omschrijving': 'Gekoppelde checklists'},
    {'naam': 'faalmodus_labels', 'type': 'dict', 'omschrijving': 'Labels voor faalmodus'},
    {'naam': 'detect_labels', 'type': 'dict', 'omschrijving': 'Labels voor detecteerbaarheid'},
    {'naam': 'heatmap_rows', 'type': 'lijst', 'omschrijving': 'Rijen van de risicomatrix (kans, cells)'},
    {'naam': 'sla_rows', 'type': 'lijst', 'omschrijving': 'Oplostijden per bevinding (id, titel, severity, sla, date)'},
    {'naam': 'owasp_rows', 'type': 'lijst', 'omschrijving': 'OWASP-mapping per bevinding'},
    {'naam': 'ncsc_rows', 'type': 'lijst', 'omschrijving': 'NCSC-mapping per bevinding'},
    {'naam': 'detection_tally', 'type': 'dict', 'omschrijving': 'Telling detecteerbaarheid (ja/deels/nee)'},
    {'naam': 'detection_label', 'type': 'dict', 'omschrijving': 'Labels bij detection_tally'},
    {'naam': 'detection_gaps', 'type': 'lijst', 'omschrijving': 'Bevindingen met detectie-hiaten'},
    {'naam': 'detection_rated', 'type': 'bool', 'omschrijving': 'True als er detecteerbaarheid is beoordeeld'},
    {'naam': 'chain_paths', 'type': 'lijst', 'omschrijving': 'Kill-chain-paden (num, steps)'},
]


def _sample_tex_context():
    """Representatieve voorbeeldcontext voor de dry-run-validatie: bevat alle
    variabelen die gen_rapport aan de template doorgeeft, met voorbeeldwaarden."""
    f = {
        'id': 1, 'nr': 1, 'titel': 'Voorbeeldbevinding', 'beschrijving': 'Beschrijving',
        'impact': 'Impact', 'aanbeveling': 'Aanbeveling',
        'uitwerking_detail': 'Uitwerking van de bevinding',
        'aanbeveling_overzicht': 'Aanbeveling', 'basescore': '9.0',
        'cvss_vector': 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:L/SI:N/SA:N',
        'locatie': 'host.example', 'owasp': '', 'owasp_2025': '',
        'cwe': '', 'ncsc': '', 'control_ref': '', 'mitre': '', 'severity': 'critical',
        'referenties': '', 'related': [], 'assets': [], 'evidence': [],
        'faalmodus': '', 'detecteerbaarheid': '', 'detectie_notitie': '',
        'remediation_status': 'open',
    }
    ctx = dict(
        titel='Titel', subtitel='Subtitel', auteur='Auteur', project='Project',
        classificatie='TLP:RED', tlp_color='ored', datum='01-01-2026',
        is_draft=False, sections=_all_sections(True), findings=[f],
        grouped_findings=[('Kritiek', [f])],
        bevindingenlijst_rows=_bevindingenlijst_rows([f], 'nl'),
        cia_triad=_cia_triad_tex([f], 'nl'),
        subsequent_triad=_subsequent_triad_tex([f], 'nl'),
        exploit_profile=_exploit_profile([f], 'nl'),
        direct_rows=_bevindingenlijst_rows(_direct_exploitable([f]), 'nl'),
        direct_intro=_direct_exploitable_intro(len(_direct_exploitable([f])), 'nl'),
        impact_gauge=_impact_gauge([f], 'nl'),
        top_risk_gauge=_top_risk_gauge([f], 'nl'),
        counts=dict(critical=1, high=0, medium=0, low=0, none=0),
        scoped_hosts=['host.example'], scope_targets=[], notes=[],
        testtype='pentest', testscope='blackbox', testscopes=['blackbox'],
        management_samenvatting='Samenvatting', legsup_startpunt='',
        legsup_privileges='', legsup_informatie='', scenarios=[], taal='nl',
        checklists=[], faalmodus_labels=_FAALMODUS_LABELS,
        detect_labels=_DETECT_LABELS,
        begrippen_rows=[{'term': _latex_escape(r['term']),
                         'definitie': _latex_escape(r['definitie'])}
                        for r in _begrippen_rows('nl')],
        beperkingen_lines=[_latex_escape(x) for x in _beperkingen_lines(
            'nl', testscope='blackbox')],
        evidence_register=[],
        cvss_detail_rows=[{'id': r['id'], 'titel': _latex_escape(r['titel']),
                           'score': _latex_escape(r['score']),
                           'summary': _latex_escape(r['summary'])}
                          for r in _cvss_detail_rows([f], 'nl')],
        retest_progress=[], retest_open=[], retest_intro='',
    )
    ctx.update(_build_rapport_appendices([f], taal='nl'))
    return ctx


def _xelatex_dryrun(rendered):
    """Best-effort xelatex-compilatie van een gerenderde .tex in een temp-dir.
    Geeft een waarschuwingstekst terug bij problemen, anders een lege string."""
    import tempfile
    try:
        with tempfile.TemporaryDirectory() as td:
            texf = os.path.join(td, 'dryrun.tex')
            with open(texf, 'w', encoding='utf-8') as fh:
                fh.write(rendered)
            run_env = os.environ.copy()
            handboek_abs = os.path.abspath(_HANDBOEK_DIR)
            run_env['TEXINPUTS'] = '.:{l}:{l}//:{h}:{h}//:'.format(
                l=os.path.abspath(_LAYOUT_DIR), h=handboek_abs)
            p = subprocess.run(
                ['xelatex', '-interaction=nonstopmode', '-halt-on-error',
                 '-no-shell-escape', '-output-directory', td, texf],
                cwd=td, env=run_env, capture_output=True, timeout=60)
            if p.returncode != 0:
                out = (p.stdout or b'').decode('utf-8', 'replace')
                err = [ln for ln in out.splitlines() if ln.startswith('!')]
                detail = err[0] if err else 'xelatex gaf een foutcode terug'
                return 'xelatex-waarschuwing: %s' % detail[:200]
    except subprocess.TimeoutExpired:
        return 'xelatex-dry-run duurde te lang en is overgeslagen'
    except Exception as e:
        return 'xelatex-dry-run niet uitgevoerd: %s' % str(e)[:120]
    return ''


_PREVIEW_PREAMBLE = r"""\documentclass[11pt]{article}
\usepackage{fontspec}
\usepackage[a4paper,margin=20mm]{geometry}
\usepackage{booktabs}
\usepackage{enumitem}
\usepackage{listings}
\lstset{basicstyle=\ttfamily\small,breaklines=true,frame=single}
%% Laad de echte rapport-stijl, zodat ALLE projectmacro's (\cvss, \severity,
%% \cwe/\cve/\owasp, \pad/\host/\route/\param, callouts, \request/\response,
%% \deelsgelakt, \bevinding(ref)/\uitwerking, \lakken, \plaatje, ...) exact zoals
%% in het rapport renderen. Nieuwe macro's in rapport.sty werken zo automatisch
%% mee in de preview. (TEXINPUTS wijst naar handboek/.)
\usepackage{opmaak/packages/rapport}
\graphicspath{%(graphicspath)s}
%% Preview-overrides: toon afbeeldingen uit graphicspath (de preview compileert
%% vanuit de projectroot, niet vanuit rapport/), en lichte stand-ins voor
%% editor-macro's die niet in rapport.sty staan.
\renewcommand{\plaatje}[2]{\begin{center}\includegraphics[width=0.8\linewidth,keepaspectratio]{#1}\par\smallskip{\footnotesize\itshape #2}\end{center}}
%% \opdracht leeft op template-niveau (rapport_latex.tex), niet in rapport.sty;
%% hier een visueel gelijkwaardige stand-in (monospace, grijs, tussen quotes).
\providecommand{\opdracht}[1]{`{\texttt{\textcolor{gray}{#1}}}'}
\providecommand{\gls}[1]{#1}
\providecommand{\glspl}[1]{#1s}
\providecommand{\reconoutput}[2]{\paragraph{#2}\texttt{#1}}
\providecommand{\scanoutput}[2]{\paragraph{#2}\texttt{#1}}
\providecommand{\bibliographystyle}[1]{}
\providecommand{\bibliography}[1]{}
\begin{document}
"""


def _prepare_preview_fragment(content):
    """Maak een editor-fragment veilig renderbaar: verwijder \\input/\\makeglossaries
    (verwijzen naar niet-aanwezige bestanden) en toon een placeholder."""
    def _repl_input(m):
        return r'\textit{[ingevoegd: %s]}' % _latex_escape(m.group(1))
    content = _re.sub(r'\\input\s*\{([^}]*)\}', _repl_input, content)
    content = _re.sub(r'\\makeglossaries\b', '', content)
    return content


@rapport_bp.route('/api/latex/preview', methods=['POST'])
def latex_preview():
    """Compileer een editor-fragment zelfstandig tot een PNG-voorbeeld.
    Retourneert {ok, image(data-URL)} of {ok:false, error}."""
    _check_dashboard_access()
    import tempfile
    import base64
    import glob as _glob
    data = request.get_json(silent=True) or {}
    content = (data.get('content') or '').strip()
    if not content:
        return jsonify({'ok': False, 'error': 'geen inhoud'}), 400
    if len(content) > 100000:
        return jsonify({'ok': False, 'error': 'fragment te groot voor preview'}), 413

    root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    gpaths = ''.join('{%s/}' % os.path.join(root, p)
                     for p in ('raw/screenshots', 'meuk/flask/db/evidence'))
    tex = (_PREVIEW_PREAMBLE % {'graphicspath': gpaths}
           + _prepare_preview_fragment(content) + '\n\\end{document}\n')

    try:
        with tempfile.TemporaryDirectory() as td:
            texf = os.path.join(td, 'preview.tex')
            with open(texf, 'w', encoding='utf-8') as fh:
                fh.write(tex)
            run_env = os.environ.copy()
            handboek_abs = os.path.abspath(_HANDBOEK_DIR)
            # . (=projectroot, voor graphicspath) + layout (rapport.sty) + handboek (afbeeldingen/logo's).
            run_env['TEXINPUTS'] = '.:{l}:{l}//:{h}:{h}//:'.format(
                l=os.path.abspath(_LAYOUT_DIR), h=handboek_abs)
            p = subprocess.run(
                ['xelatex', '-interaction=nonstopmode', '-halt-on-error',
                 '-no-shell-escape', '-output-directory', td, texf],
                cwd=root, env=run_env, capture_output=True, timeout=30)
            pdf = os.path.join(td, 'preview.pdf')
            if p.returncode != 0 or not os.path.exists(pdf):
                out = (p.stdout or b'').decode('utf-8', 'replace')
                lines = out.splitlines()
                errs = [ln for ln in lines if ln.startswith('!')]
                msg = errs[0] if errs else 'compilatie mislukt'
                # Bij "Undefined control sequence" de macronaam erbij zoeken: die
                # staat op de context-regel (l.NN ...) direct na de foutmelding.
                if 'Undefined control sequence' in msg:
                    for i, ln in enumerate(lines):
                        if ln.startswith('!') and 'Undefined control sequence' in ln:
                            ctx = next((lines[j] for j in range(i + 1, min(i + 4, len(lines)))
                                        if lines[j].startswith('l.')), '')
                            m = _re.search(r'(\\[a-zA-Z@]+)\s*$', ctx)
                            if m:
                                msg = 'Onbekende macro %s (niet gedefinieerd in het rapport)' % m.group(1)
                            break
                return jsonify({'ok': False, 'error': msg[:300]})
            subprocess.run(['pdftoppm', '-f', '1', '-l', '1', '-r', '110', '-png',
                            pdf, os.path.join(td, 'page')],
                           capture_output=True, timeout=20)
            pngs = sorted(_glob.glob(os.path.join(td, 'page*.png')))
            if not pngs:
                return jsonify({'ok': False, 'error': 'geen afbeelding gegenereerd'})
            with open(pngs[0], 'rb') as fh:
                b64 = base64.b64encode(fh.read()).decode('ascii')
            return jsonify({'ok': True, 'image': 'data:image/png;base64,' + b64})
    except subprocess.TimeoutExpired:
        return jsonify({'ok': False, 'error': 'preview duurde te lang (time-out)'})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)[:200]})


def _valideer_tex_template(src, met_xelatex=True):
    """Dry-run-validatie van een eigen .tex: rendert met StrictUndefined (vangt
    syntaxfouten en verwijzingen naar onbekende variabelen) en probeert optioneel
    een xelatex-compilatie. Geeft {ok, error, warning}."""
    env = Environment(
        block_start_string='[%', block_end_string='%]',
        variable_start_string='[[', variable_end_string=']]',
        comment_start_string='[#', comment_end_string='#]',
        autoescape=False, undefined=StrictUndefined)
    env.filters['latex_escape'] = _latex_escape
    env.filters['latex_markup'] = _latex_markup
    try:
        rendered = env.from_string(src).render(**_sample_tex_context())
    except TemplateSyntaxError as e:
        return {'ok': False, 'error': 'Syntaxfout (regel %s): %s' % (
            getattr(e, 'lineno', '?'), e.message), 'warning': ''}
    except UndefinedError as e:
        return {'ok': False, 'error': 'Verwijzing naar onbekende variabele: %s'
                % str(e), 'warning': ''}
    except TemplateError as e:
        return {'ok': False, 'error': 'Templatefout: %s' % str(e), 'warning': ''}
    except Exception as e:
        return {'ok': False, 'error': 'Renderfout: %s' % str(e), 'warning': ''}
    warning = ''
    if met_xelatex and shutil.which('xelatex'):
        warning = _xelatex_dryrun(rendered)
    return {'ok': True, 'error': '', 'warning': warning}


@rapport_bp.route('/api/report/templates/tex-variables', methods=['GET'])
def report_templates_tex_variables():
    return jsonify({'ok': True, 'variables': _TEX_CONTEXT_VARS,
                    'delimiters': {'logica': '[% ... %]', 'waarde': '[[ ... ]]',
                                   'commentaar': '[# ... #]'}})


_PDF_PW_SYMBOLS = '!@#$%^&*-_=+?'


@rapport_bp.route('/api/report/pdf/genpw', methods=['GET'])
def report_pdf_genpw():
    """Genereer een sterk, willekeurig wachtwoord voor PDF-beveiliging.

    20 tekens uit kleine/hoofdletters, cijfers en symbolen; gegarandeerd ten
    minste één teken uit elke klasse (cryptografisch via secrets)."""
    import secrets
    import string
    alphabet = string.ascii_letters + string.digits + _PDF_PW_SYMBOLS
    for _ in range(50):
        pw = ''.join(secrets.choice(alphabet) for _ in range(20))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw)
                and any(c in _PDF_PW_SYMBOLS for c in pw)):
            return jsonify({'ok': True, 'password': pw})
    return jsonify({'ok': True, 'password': pw})


@rapport_bp.route('/api/report/templates/<int:tid>/tex', methods=['POST'])
def report_templates_upload_tex(tid):
    row = db.session.get(db_rapport_template, tid)
    if not row:
        return jsonify({'ok': False, 'error': 'niet gevonden'}), 404
    f = request.files.get('file')
    if not f or not f.filename:
        return jsonify({'ok': False, 'error': 'geen bestand'}), 400
    if not f.filename.lower().endswith('.tex'):
        return jsonify({'ok': False, 'error': 'alleen .tex toegestaan'}), 400
    data = f.read()
    if len(data) > 1_000_000:
        return jsonify({'ok': False, 'error': 'bestand te groot (max 1 MB)'}), 400
    try:
        src = data.decode('utf-8')
    except UnicodeDecodeError:
        return jsonify({'ok': False, 'error': 'bestand is geen geldige UTF-8 tekst'}), 400
    # Dry-run: weiger een template dat niet rendert (geen stille terugval meer)
    res = _valideer_tex_template(src)
    if not res['ok']:
        return jsonify({'ok': False, 'error': res['error']}), 400
    os.makedirs(_REPORT_TPL_DIR, exist_ok=True)
    dest = os.path.join(_REPORT_TPL_DIR, '%d.tex' % tid)
    with open(dest, 'w', encoding='utf-8') as fh:
        fh.write(src)
    row.custom_tex_path = dest
    db.session.commit()
    return jsonify({'ok': True, 'warning': res.get('warning', '')})


@rapport_bp.route('/api/report/templates/<int:tid>/tex/validate', methods=['POST'])
def report_templates_validate_tex(tid):
    """Valideer de opgeslagen eigen .tex zonder opnieuw te uploaden."""
    row = db.session.get(db_rapport_template, tid)
    if not row:
        return jsonify({'ok': False, 'error': 'niet gevonden'}), 404
    if not row.custom_tex_path or not os.path.exists(row.custom_tex_path):
        return jsonify({'ok': False, 'error': 'geen eigen .tex ingesteld'}), 400
    try:
        with open(row.custom_tex_path, 'r', encoding='utf-8') as fh:
            src = fh.read()
    except OSError as e:
        return jsonify({'ok': False, 'error': 'kon bestand niet lezen: %s' % e}), 500
    return jsonify(_valideer_tex_template(src))


@rapport_bp.route('/api/report/templates/<int:tid>/tex', methods=['DELETE'])
def report_templates_remove_tex(tid):
    row = db.session.get(db_rapport_template, tid)
    if not row:
        return jsonify({'ok': False, 'error': 'niet gevonden'}), 404
    if row.custom_tex_path and os.path.exists(row.custom_tex_path):
        try:
            os.remove(row.custom_tex_path)
        except OSError:
            pass
    row.custom_tex_path = ''
    db.session.commit()
    return jsonify({'ok': True})


@rapport_bp.route('/api/report/templates/select', methods=['POST'])
def report_templates_select():
    """Kies het actieve rapport-template per project: {template_id} of {variant}."""
    from meuk.flask import project as _project
    cfg = _project.current_config()
    if cfg is None:
        return jsonify({'ok': False, 'error': 'geen actief project'}), 400
    body = request.get_json(silent=True) or {}
    tid = body.get('template_id')
    variant = body.get('variant')
    if tid:
        if not db.session.get(db_rapport_template, int(tid)):
            return jsonify({'ok': False, 'error': 'onbekend template'}), 404
        cfg.rapport_template_id = int(tid)
    else:
        cfg.rapport_template_id = None
        if variant in _BUILTIN_VARIANTS:
            cfg.rapport_template_variant = variant
    db.session.commit()
    return jsonify({'ok': True,
                    'template_id': cfg.rapport_template_id,
                    'variant': cfg.rapport_template_variant})
