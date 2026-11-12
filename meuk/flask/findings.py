from meuk.hacksec import *
from flask import Blueprint, render_template, redirect, url_for, flash, send_from_directory, abort, request, Response, jsonify
from meuk.flask.models import *
from meuk.flask.forms import *
from meuk.flask.security import require_dashboard_access
from werkzeug.utils import secure_filename
import datetime
import hashlib
import json
import os
import re as _re
import uuid


def _get_appdata():
    return db_instellingen.query.first()


def _get_scope_targets():
    """Haal scope targets op uit de config van het actieve project."""
    from meuk.flask import project as _project
    cfg = _project.current_config()
    try:
        return json.loads(getattr(cfg, 'rapport_scope_targets', '[]') or '[]')
    except (json.JSONDecodeError, TypeError):
        return []


# Oplostijd (SLA) in dagen per severity — gelijk aan rapport._SLA_DAYS
_SLA_DAGEN = {'critical': 1, 'high': 7, 'medium': 30, 'low': 90, 'none': 365}
# Herstelstatussen die als "afgehandeld" tellen (niet meer overschrijdbaar)
_REM_AFGEHANDELD = ('fixed', 'verified', 'accepted')


def _sev_van_bevinding(bev, tmpl=None):
    bs = bev.basescore or (tmpl.basescore if tmpl else '') or '0'
    sev, _ = _cvss_to_severity(bs)
    return sev


def _sla_doeldatum(bev, tmpl=None):
    """Bereken de aanbevolen hersteldoeldatum (ontdekdatum/aanmaak + SLA-dagen)."""
    sev = _sev_van_bevinding(bev, tmpl)
    basis = None
    if getattr(bev, 'discovered_at', None):
        basis = bev.discovered_at.date() if hasattr(bev.discovered_at, 'date') else bev.discovered_at
    elif getattr(bev, 'created_at', None):
        basis = bev.created_at.date() if hasattr(bev.created_at, 'date') else bev.created_at
    if basis is None:
        basis = datetime.date.today()
    return basis + datetime.timedelta(days=_SLA_DAGEN.get(sev, 90))


def _zet_sla_doeldatum_indien_leeg(bev, tmpl=None):
    if not getattr(bev, 'remediation_target_date', None):
        bev.remediation_target_date = _sla_doeldatum(bev, tmpl)


def _active_findings(opdracht_id=None):
    """Query van niet-verwijderde bevindingen, gescoped op het actieve project.

    Geen project aanwezig -> geen scoping (alle bevindingen)."""
    from meuk.flask import project as _project
    q = db_bevindingen.query.filter(db_bevindingen.deleted_at.is_(None))
    oid = _project.resolve_opdracht_id(opdracht_id)
    return _project.apply_scope(q, db_bevindingen.opdracht_id, oid)


def _csrf_check(token, as_json=False):
    """Valideer CSRF-token; respecteert WTF_CSRF_ENABLED=False (testmodus)."""
    from flask import current_app
    if not current_app.config.get('WTF_CSRF_ENABLED', True):
        return
    from flask_wtf.csrf import validate_csrf
    try:
        validate_csrf(token)
    except Exception:
        if as_json:
            from flask import jsonify as _j
            raise  # wordt afgehandeld door de aanroeper
        abort(400)


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


# ---------------------------------------------------------------------------
# Markup-model: één parser, drie renderers (LaTeX / HTML / Markdown)
# ---------------------------------------------------------------------------
# Template-velden (beschrijving/impact/aanbeveling/referenties) bevatten een MIX
# van bewuste LaTeX-markup (\begin{description}, \item, \textbf{...}) en
# letterlijke tekst met backslashes (Windows-registerpaden als \SOFTWARE\Microsoft),
# underscores en losse specials. Om PDF (LaTeX), HTML-preview en DOCX (Markdown)
# IDENTIEK te laten renderen, parsen we de markup één keer naar een node-boom en
# renderen die naar elk doelformaat. Bij structureel onbalans (ongesloten
# omgeving, eenzame \item, haakjes-mismatch) valt elke renderer terug op de
# platte escape van zijn eigen formaat, zodat geen enkele build kapotgaat op
# slechte data.
#
# Node-vormen:
#   ('text', str)
#   ('cmd', name, [children])        inline: textbf/textit/emph/texttt/underline/...
#   ('zero', name)                   losse commando's: textbackslash/ldots/...
#   ('env', envname, [items])        description/itemize/enumerate/quote/center
#   item := ('item', label_nodes|None, [body_nodes])
_MK_ENVS = {'description', 'itemize', 'enumerate', 'quote', 'center'}
# Eén-argument-macro's die als \cmd{markup} worden doorgegeven. Naast de
# tekstopmaak ook de rapport-macro's die de LaTeX-toolbar invoegt en die in
# rapport.sty/de template gedefinieerd zijn (\lakken, \codelakken, \opdracht).
# Technische inline-opmaak (monospace) — pad/host/endpoint/param krijgen in
# HTML <code>, in Markdown `...`, in LaTeX \texttt (zie rapport.sty).
_MK_MONO = {'pad', 'host', 'route', 'param'}
# "Slimme" macro's met berekende uitvoer (link/kleur/label) i.p.v. simpele
# opmaak. In LaTeX zijn het echte macro's (rapport.sty); in HTML/MD/plat
# vertalen _smart_inline_* ze. cvss/severity -> gekleurd label, cwe/cve/owasp ->
# klikbare code, bevindingref -> korte kruisverwijzing.
_MK_SMART = {'cvss', 'severity', 'cwe', 'cve', 'owasp', 'bevindingref'}
# Blok-macro's: callout-boxen en HTTP-blokken. Eén markup-argument. Naast de
# drie basis-callouts ook de rijkere, inhoudelijke kaders.
_MK_BLOCKMACRO = {'waarschuwing', 'tip', 'opmerking', 'stap', 'request', 'response',
                  'bestuurlijk', 'principe', 'letop', 'praktijk', 'keten', 'scenario'}
_MK_INLINE = ({'textbf', 'textit', 'emph', 'texttt', 'textrm', 'textsc', 'underline', 'textsf',
               'lakken', 'codelakken', 'opdracht', 'haakjes', 'bevinding', 'uitwerking'}
              | _MK_MONO | _MK_SMART | _MK_BLOCKMACRO)
# Kruisverwijzing-macro's (\bevinding{id}, \uitwerking{id}) hebben in LaTeX een
# paginareferentie; in HTML/Markdown/plat bestaat die niet, dus daar vertalen we
# ze naar leesbare tekst. \haakjes wordt cursief tussen aanhalingstekens.
_MK_REFMACRO = {'bevinding', 'uitwerking'}
# Twee-argument-macro's: eerste arg is een RAUWE bestandsnaam (niet escapen,
# vanwege underscores e.d.), tweede arg is een markup-caption.
_MK_TWOARG = {'plaatje'}
# Twee-argument-macro's waarvan BEIDE argumenten gewone markup zijn.
# \deelsgelakt{zichtbaar}{geheim}: toont het eerste deel, redigeert het tweede.
_MK_TWOARG_MK = {'deelsgelakt'}
# Toegestane tekens in zo'n rauwe bestandsnaam; alles daarbuiten -> veilige
# terugval (voorkomt LaTeX-injectie via het bestandsnaam-argument).
_MK_RAWARG_RE = _re.compile(r'^[\w.\- /]+$')

# --- Severity-model (gedeeld door \cvss en \severity) ---------------------- #
_SEV_LABELS = {'critical': 'Kritiek', 'high': 'Hoog', 'medium': 'Midden',
               'low': 'Laag', 'none': 'Nihil'}
# (achtergrond, tekst) — zelfde palet als de bevindingkop/CVSS-badges.
_SEV_COLORS = {'critical': ('#581c87', '#e9d5ff'), 'high': ('#dc2626', '#ffffff'),
               'medium': ('#f59e0b', '#ffffff'), 'low': ('#22c55e', '#ffffff'),
               'none': ('#e5e7eb', '#374151')}
_SEV_WORDS = {'kritiek': 'critical', 'critical': 'critical', 'crit': 'critical',
              'hoog': 'high', 'high': 'high',
              'midden': 'medium', 'middel': 'medium', 'gemiddeld': 'medium', 'medium': 'medium',
              'laag': 'low', 'low': 'low',
              'nihil': 'none', 'none': 'none', 'info': 'none', 'informatief': 'none'}
# (titel, framekleur, achtergrond) — zelfde palet als de tcolorbox-kaders in
# rapport.sty, zodat HTML en PDF visueel overeenkomen.
_CALLOUT_META = {'waarschuwing': ('Waarschuwing', '#A90000', '#FBEAEA'),
                 'tip': ('Tip', '#275D38', '#EDF5EF'),
                 'opmerking': ('Opmerking', '#154273', '#E5F1F9'),
                 'bestuurlijk': ('Bestuurlijke kern', '#154273', '#E5F1F9'),
                 'principe': ('Leidend principe', '#275D38', '#EDF5EF'),
                 'letop': ('Aandachtspunt', '#E17000', '#FFF3E5'),
                 'praktijk': ('Praktische toepassing', '#154273', '#F3F8FC'),
                 'keten': ('Ketenperspectief', '#5B3F8C', '#F1ECF8'),
                 'scenario': ('Ketenscenario', '#535353', '#F2F2F2')}
_CWE_ARG_RE = _re.compile(r'^\d{1,7}$')
_CVE_ARG_RE = _re.compile(r'^\d{4}-\d{4,}$')
_OWASP_ARG_RE = _re.compile(r'^[A-Za-z0-9:\- ]{1,24}$')


def _sev_from_word(w):
    return _SEV_WORDS.get(str(w or '').strip().lower())


def _link_cwe(arg):
    a = str(arg or '').strip()
    if not _CWE_ARG_RE.match(a):
        return ('CWE-%s' % a, '')
    return ('CWE-%s' % a, 'https://cwe.mitre.org/data/definitions/%s.html' % a)


def _link_cve(arg):
    a = str(arg or '').strip()
    if a.upper().startswith('CVE-'):
        a = a[4:]
    if not _CVE_ARG_RE.match(a):
        return ('CVE-%s' % a, '')
    return ('CVE-%s' % a, 'https://nvd.nist.gov/vuln/detail/CVE-%s' % a)


def _link_owasp(arg):
    a = str(arg or '').strip()
    if not _OWASP_ARG_RE.match(a):
        return (a, '')
    return (a, 'https://owasp.org/Top10/')
_MK_ZERO = {'textbackslash', 'textrightarrow', 'textleftarrow', 'ldots', 'dots',
            'newline', 'par', 'noindent', 'textasciitilde', 'textasciicircum'}
_MK_CMD_RE = _re.compile(r'\\([a-zA-Z]+)')
_MK_ENV_RE = _re.compile(r'\{([a-zA-Z*]+)\}')


class _MkFail(Exception):
    """Markup is structureel onbetrouwbaar; val terug op platte escape."""


# --- Parser --------------------------------------------------------------- #

def _mk_parse(text):
    s = str(text).replace('\r\n', '\n').replace('\r', '\n')
    nodes, i, stop = _mk_parse_nodes(s, 0, 'top')
    return nodes


def _mk_parse_nodes(s, i, mode, envname=None):
    """Parse een reeks nodes.

    mode:
      'top'   -> tot EOF (stop='eof')
      'group' -> tot bijbehorende '}' (stop='brace', geconsumeerd)
      'item'  -> tot '\\item' (stop='item', NIET geconsumeerd behalve de \\item zelf)
                 of '\\end{envname}' (stop='end', geconsumeerd)
    Geeft (nodes, index, stop) terug.
    """
    n = len(s)
    nodes = []
    buf = []

    def flush():
        if buf:
            nodes.append(('text', ''.join(buf)))
            buf.clear()

    while i < n:
        ch = s[i]
        if ch == '}':
            if mode == 'group':
                flush()
                return nodes, i + 1, 'brace'
            buf.append('}')
            i += 1
            continue
        if ch == '{':
            # Kale groep zonder commando -> letterlijke accolades
            buf.append('{')
            i += 1
            continue
        if ch == '\\':
            m = _MK_CMD_RE.match(s, i)
            if not m:
                nxt = s[i + 1] if i + 1 < n else ''
                if nxt in '&%$#_{}':
                    buf.append(nxt)
                    i += 2
                else:
                    buf.append('\\')
                    i += 1
                continue
            cmd = m.group(1)
            j = m.end()
            if cmd == 'begin':
                em = _MK_ENV_RE.match(s, j)
                if not em or em.group(1) not in _MK_ENVS:
                    raise _MkFail()
                flush()
                items, i = _mk_parse_env(s, em.end(), em.group(1))
                nodes.append(('env', em.group(1), items))
                continue
            if cmd == 'end':
                em = _MK_ENV_RE.match(s, j)
                if not em:
                    raise _MkFail()
                if mode == 'item' and em.group(1) == envname:
                    flush()
                    return nodes, em.end(), 'end'
                raise _MkFail()
            if cmd == 'item':
                if mode == 'item':
                    flush()
                    return nodes, j, 'item'
                raise _MkFail()
            if cmd in _MK_INLINE:
                if j < n and s[j] == '{':
                    flush()
                    children, i, _ = _mk_parse_nodes(s, j + 1, 'group')
                    nodes.append(('cmd', cmd, children))
                    continue
                raise _MkFail()
            if cmd in _MK_TWOARG:
                # \plaatje{bestandsnaam}{caption}: arg1 rauw (bestandsnaam),
                # arg2 als markup. Ongeldige bestandsnaam -> veilige terugval.
                if j < n and s[j] == '{':
                    raw1, k = _mk_read_raw_group(s, j + 1)
                    if _MK_RAWARG_RE.match(raw1) and k < n and s[k] == '{':
                        flush()
                        caption, i, _ = _mk_parse_nodes(s, k + 1, 'group')
                        nodes.append(('img', cmd, raw1, caption))
                        continue
                raise _MkFail()
            if cmd in _MK_TWOARG_MK:
                # \deelsgelakt{zichtbaar}{geheim}: beide argumenten zijn markup.
                if j < n and s[j] == '{':
                    flush()
                    a1, k, _ = _mk_parse_nodes(s, j + 1, 'group')
                    if k < n and s[k] == '{':
                        a2, i, _ = _mk_parse_nodes(s, k + 1, 'group')
                        nodes.append(('cmd2', cmd, a1, a2))
                        continue
                raise _MkFail()
            if cmd in _MK_ZERO:
                flush()
                nodes.append(('zero', cmd))
                i = j
                continue
            # Onbekend commando -> letterlijke backslash + letters als tekst
            flush()
            nodes.append(('zero', 'textbackslash'))
            buf.append(cmd)
            i = j
            continue
        buf.append(ch)
        i += 1
    if mode != 'top':
        raise _MkFail()
    flush()
    return nodes, i, 'eof'


def _mk_read_raw_group(s, i):
    """Lees een accolade-groep rauw (geen markup/escape) tot de eerste '}'.

    Bestandsnamen bevatten geen geneste accolades. Geeft (inhoud, index-na-'}').
    """
    n = len(s)
    buf = []
    while i < n and s[i] != '}':
        buf.append(s[i])
        i += 1
    if i >= n:
        raise _MkFail()
    return ''.join(buf), i + 1


def _mk_parse_env(s, i, envname):
    """Parse items van een omgeving; i staat net na \\begin{env}. Geeft (items, idx)."""
    items = []
    n = len(s)
    # Inhoud vóór de eerste \item (meestal witruimte) overslaan.
    _pre, i, stop = _mk_parse_nodes(s, i, 'item', envname)
    if stop == 'end':
        return items, i
    if stop != 'item':
        raise _MkFail()
    while True:
        label = None
        if i < n and s[i] == '[':
            k = i + 1
            while k < n and s[k] != ']':
                k += 1
            if k >= n:
                raise _MkFail()
            label, _, _ = _mk_parse_nodes(s[i + 1:k], 0, 'top')
            i = k + 1
        body, i, stop = _mk_parse_nodes(s, i, 'item', envname)
        items.append(('item', label, body))
        if stop == 'end':
            return items, i
        if stop == 'item':
            continue
        raise _MkFail()


# --- Hulp: blokken splitsen (inline-runs vs. omgevingen) ------------------- #

def _mk_blocks(nodes):
    blocks = []
    buf = []

    def flush():
        if any(not (nd[0] == 'text' and not nd[1].strip()) for nd in buf):
            blocks.append(('p', list(buf)))
        buf.clear()

    for nd in nodes:
        if nd[0] == 'env':
            flush()
            blocks.append(('env', nd))
        else:
            buf.append(nd)
    flush()
    return blocks


# --- LaTeX-renderer ------------------------------------------------------- #

_TEX_SPECIAL = {'&': r'\&', '%': r'\%', '$': r'\$', '#': r'\#', '_': r'\_',
                '~': r'\textasciitilde{}', '^': r'\textasciicircum{}',
                '\\': r'\textbackslash{}', '{': r'\{', '}': r'\}'}
_TEX_ZERO = {'textbackslash': r'\textbackslash{}', 'textrightarrow': r'\textrightarrow{}',
             'textleftarrow': r'\textleftarrow{}', 'ldots': r'\ldots{}', 'dots': r'\dots{}',
             'newline': r'\newline ', 'par': '\n\n', 'noindent': r'\noindent ',
             'textasciitilde': r'\textasciitilde{}', 'textasciicircum': r'\textasciicircum{}'}


def _tex_text(seg):
    return ''.join(_TEX_SPECIAL.get(ch, ch) for ch in seg)


def _mk_to_latex(nodes):
    out = []
    for nd in nodes:
        t = nd[0]
        if t == 'text':
            out.append(_tex_text(nd[1]))
        elif t == 'zero':
            out.append(_TEX_ZERO.get(nd[1], ''))
        elif t == 'cmd':
            out.append('\\%s{%s}' % (nd[1], _mk_to_latex(nd[2])))
        elif t == 'img':
            # nd[2] is de rauwe bestandsnaam (al gevalideerd), nd[3] de caption.
            out.append('\\%s{%s}{%s}' % (nd[1], nd[2], _mk_to_latex(nd[3])))
        elif t == 'cmd2':
            out.append('\\%s{%s}{%s}' % (nd[1], _mk_to_latex(nd[2]), _mk_to_latex(nd[3])))
        elif t == 'env':
            out.append('\\begin{%s}' % nd[1])
            for _it, label, body in nd[2]:
                out.append('\n\\item')
                if label is not None:
                    out.append('[' + _mk_to_latex(label) + ']')
                out.append(' ' + _mk_to_latex(body))
            out.append('\n\\end{%s}\n' % nd[1])
    return ''.join(out)


def _latex_markup(text):
    if not text:
        return ''
    try:
        return _mk_to_latex(_mk_parse(text))
    except (_MkFail, RecursionError):
        return _latex_escape(text)


# --- Lakken (redactie) voor niet-LaTeX-output (HTML/Markdown/DOCX) ---------- #
# In de PDF is \lakken{} een echte LaTeX-macro; in HTML/Markdown/DOCX heeft die
# geen betekenis en zou de ruwe tekst (het geheim!) letterlijk in de output komen.
# Daarom vertalen _html_markup/_md_markup \lakken{X}/\codelakken{X}:
#   - standaard (onthullen): -> X        (de gewone, ongelakte export)
#   - in redactiemodus:      -> ████████ (de gelakte export; lekt geen lengte)
# De modus is thread-local, zodat de gelakte export-build 'm tijdelijk aanzet
# zonder dat gelijktijdige verzoeken elkaar beinvloeden.
import threading as _threading  # noqa: E402

_redact_state = _threading.local()
_LAKKEN_RE = _re.compile(r'\\(?:code)?lakken\s*\{([^{}]*)\}')
_REDACT_BLOCK = '\u2588' * 8


def redact_enabled():
    return getattr(_redact_state, 'on', False)


class redact_mode:
    """Context manager: binnen dit blok vertaalt de markup \\lakken{} naar blokken."""

    def __enter__(self):
        self._prev = getattr(_redact_state, 'on', False)
        _redact_state.on = True
        return self

    def __exit__(self, *exc):
        _redact_state.on = self._prev
        return False


def _apply_lakken(text):
    """Vervang \\lakken{X}/\\codelakken{X} door X (onthullen) of blokken (redactie)."""
    if not text or 'lakken' not in text:
        return text
    repl = (lambda m: _REDACT_BLOCK) if redact_enabled() else (lambda m: m.group(1))
    return _LAKKEN_RE.sub(repl, text)


# --- HTML-renderer (blok-niveau, CSP-veilig: geen inline styles) ----------- #

_HTML_INLINE = {'textbf': ('<strong>', '</strong>'), 'textit': ('<em>', '</em>'),
                'emph': ('<em>', '</em>'), 'texttt': ('<code>', '</code>'),
                'underline': ('<u>', '</u>'), 'textrm': ('', ''),
                'textsc': ('', ''), 'textsf': ('', ''),
                'pad': ('<code>', '</code>'), 'host': ('<code>', '</code>'),
                'route': ('<code>', '</code>'), 'param': ('<code>', '</code>')}
_HTML_ZERO = {'textbackslash': '\\', 'textrightarrow': '&rarr;', 'textleftarrow': '&larr;',
              'ldots': '&hellip;', 'dots': '&hellip;', 'newline': '<br>', 'par': '<br>',
              'noindent': '', 'textasciitilde': '~', 'textasciicircum': '^'}


def _html_esc(seg):
    return seg.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


# --- \plaatje{} -> echte afbeelding in niet-LaTeX-output ------------------- #
# In de PDF is \plaatje een LaTeX-macro (zie rapport.sty); in HTML/Markdown/DOCX
# bestaat die niet. Zonder vertaling verdwijnt de afbeelding (of komt de ruwe
# \plaatje{} letterlijk mee). Daarom lossen we de bestandsnaam hier op naar het
# echte screenshot-bestand: HTML krijgt een zelfstandige data-URI (<img>),
# Markdown een absoluut pad (pandoc bakt het in de DOCX). In redactiemodus komt
# nooit het origineel mee: wel de gelakte kopie uit lakken/, anders [GELAKT].
_SCREENSHOT_DIR_REPORT = os.path.join(os.path.dirname(__file__), '..', '..',
                                      'raw', 'screenshots')
_IMG_MIME = {'.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
             '.gif': 'image/gif', '.webp': 'image/webp', '.svg': 'image/svg+xml',
             '.bmp': 'image/bmp'}


def _plaatje_bronpad(naam):
    """Zoek het bronbestand voor \\plaatje{naam}.

    Retourneert (pad|None, gelakt_placeholder_nodig). In redactiemodus wordt
    uitsluitend de gelakte kopie uit lakken/ teruggegeven; ontbreekt die, dan
    (None, True) zodat de renderer een [GELAKT]-placeholder toont i.p.v. het
    origineel. Alleen de bestandsnaam telt (geen pad-traversal)."""
    base = os.path.basename((naam or '').strip())
    if not base:
        return None, False
    if redact_enabled():
        lak = os.path.join(_SCREENSHOT_DIR_REPORT, 'lakken', base)
        return (lak, False) if os.path.isfile(lak) else (None, True)
    orig = os.path.join(_SCREENSHOT_DIR_REPORT, base)
    return (orig, False) if os.path.isfile(orig) else (None, False)


def _mk_image_html(naam, caption_nodes):
    cap_html = _mk_inline_html(caption_nodes).strip()
    cap_plain = _html_esc(_mk_inline_plain(caption_nodes).strip())
    figcap = ('<figcaption style="font-size:12px;color:#555;font-style:italic;'
              'margin-top:4px">%s</figcaption>' % cap_html) if cap_html else ''
    pad, gelakt = _plaatje_bronpad(naam)
    if gelakt:
        return ('<figure style="margin:12px 0;text-align:center">'
                '<div style="display:inline-block;background:#000;color:#fff;'
                'padding:24px 40px;font-weight:bold;border-radius:4px">[GELAKT]</div>'
                '%s</figure>' % figcap)
    if not pad:
        return '<p><em>[bestand niet gevonden: %s]</em></p>' % _html_esc(
            os.path.basename((naam or '').strip()))
    import base64 as _b64
    ext = os.path.splitext(pad)[1].lower()
    mime = _IMG_MIME.get(ext, 'application/octet-stream')
    try:
        with open(pad, 'rb') as fh:
            data = _b64.b64encode(fh.read()).decode('ascii')
    except OSError:
        return '<p><em>[bestand niet gevonden: %s]</em></p>' % _html_esc(
            os.path.basename((naam or '').strip()))
    return ('<figure style="margin:12px 0;text-align:center">'
            '<img src="data:%s;base64,%s" alt="%s" '
            'style="max-width:100%%;height:auto;border:1px solid #ccc;border-radius:4px" />'
            '%s</figure>' % (mime, data, cap_plain, figcap))


def _mk_image_md(naam, caption_nodes):
    cap = _mk_inline_plain(caption_nodes).strip().replace(']', ' ').replace('\n', ' ')
    pad, gelakt = _plaatje_bronpad(naam)
    if gelakt:
        return '**[GELAKT]**'
    if not pad:
        return '[bestand niet gevonden: %s]' % os.path.basename((naam or '').strip())
    return '![%s](%s)' % (cap, pad)


def _html_link(label, url):
    label = _html_esc(label)
    return ('<a href="%s">%s</a>' % (_html_esc(url), label)) if url else label


def _smart_inline_html(nd):
    """Vertaal een "slimme"/blok-macro naar HTML. None -> standaardopmaak."""
    name = nd[1]
    if name == 'haakjes':
        return '<em>&lsquo;%s&rsquo;</em>' % _mk_inline_html(nd[2])
    if name in _MK_REFMACRO:
        ref = _mk_inline_html(nd[2]).strip()
        if name == 'uitwerking':
            return 'We werken deze bevinding verder uit in &sect;&nbsp;bevinding %s' % ref
        return '&sect;&nbsp;bevinding %s' % ref
    if name == 'bevindingref':
        return '&sect;&nbsp;bevinding %s' % _mk_inline_html(nd[2]).strip()
    if name == 'cwe':
        return _html_link(*_link_cwe(_mk_inline_plain(nd[2]).strip()))
    if name == 'cve':
        return _html_link(*_link_cve(_mk_inline_plain(nd[2]).strip()))
    if name == 'owasp':
        return _html_link(*_link_owasp(_mk_inline_plain(nd[2]).strip()))
    if name == 'cvss':
        arg = _mk_inline_plain(nd[2]).strip()
        key, _r = _cvss_to_severity(arg)
        bg, fg = _SEV_COLORS[key]
        return ('<strong style="background:%s;color:%s;padding:1px 6px;border-radius:3px">'
                '%s (%s)</strong>' % (bg, fg, _html_esc(arg), _SEV_LABELS[key]))
    if name == 'severity':
        key = _sev_from_word(_mk_inline_plain(nd[2]).strip())
        if not key:
            return None
        bg, fg = _SEV_COLORS[key]
        return ('<strong style="background:%s;color:%s;padding:1px 6px;border-radius:3px">'
                '%s</strong>' % (bg, fg, _SEV_LABELS[key]))
    if name in _CALLOUT_META:
        titel, frame, back = _CALLOUT_META[name]
        return ('<div style="border:1px solid %s;background:%s;border-radius:4px;'
                'margin:10px 0;overflow:hidden">'
                '<div style="background:%s;color:#fff;font-weight:bold;padding:4px 10px">%s</div>'
                '<div style="padding:8px 10px">%s</div></div>'
                % (frame, back, frame, titel, _mk_inline_html(nd[2]).strip()))
    if name == 'stap':
        return '<p><strong>Stap:</strong> %s</p>' % _mk_inline_html(nd[2]).strip()
    if name in ('request', 'response'):
        titel = 'Request' if name == 'request' else 'Response'
        return ('<p><strong>%s:</strong></p><pre style="white-space:pre-wrap;'
                'font-family:monospace;font-size:12px;background:#f2f2f2;padding:8px;'
                'border-radius:4px">%s</pre>'
                % (titel, _html_esc(_mk_inline_plain(nd[2]).strip())))
    return None


def _smart_cmd2_html(nd):
    if nd[1] == 'deelsgelakt':
        hidden = _REDACT_BLOCK if redact_enabled() else _mk_inline_html(nd[3])
        return _mk_inline_html(nd[2]) + hidden
    return _mk_inline_html(nd[2]) + _mk_inline_html(nd[3])


def _mk_inline_html(nodes):
    out = []
    for nd in nodes:
        t = nd[0]
        if t == 'text':
            out.append(_html_esc(nd[1]))
        elif t == 'zero':
            out.append(_HTML_ZERO.get(nd[1], ''))
        elif t == 'cmd':
            sp = _smart_inline_html(nd)
            if sp is not None:
                out.append(sp)
            else:
                w = _HTML_INLINE.get(nd[1], ('', ''))
                out.append(w[0] + _mk_inline_html(nd[2]) + w[1])
        elif t == 'cmd2':
            out.append(_smart_cmd2_html(nd))
        elif t == 'img':
            out.append(_mk_image_html(nd[2], nd[3]))
        elif t == 'env':
            out.append(_mk_env_html(nd))
    return ''.join(out)


def _mk_item_body_html(nodes):
    if any(nd[0] == 'env' for nd in nodes):
        return _mk_blocks_html(nodes)
    return _mk_inline_html(nodes).strip()


def _mk_env_html(envnode):
    envname = envnode[1]
    items = envnode[2]
    if envname == 'description':
        out = ['<dl>']
        for _it, label, body in items:
            if label is not None:
                out.append('<dt>%s</dt>' % _mk_inline_html(label).strip())
            out.append('<dd>%s</dd>' % _mk_item_body_html(body))
        out.append('</dl>')
        return ''.join(out)
    if envname in ('itemize', 'enumerate'):
        tag = 'ol' if envname == 'enumerate' else 'ul'
        out = ['<%s>' % tag]
        for _it, label, body in items:
            pre = ('<strong>%s</strong> ' % _mk_inline_html(label).strip()) if label is not None else ''
            out.append('<li>%s%s</li>' % (pre, _mk_item_body_html(body)))
        out.append('</%s>' % tag)
        return ''.join(out)
    if envname == 'quote':
        inner = ''.join('<p>%s</p>' % _mk_inline_html(b).strip() for _i, _l, b in items) \
            if items else ''
        return '<blockquote>%s</blockquote>' % inner
    # center en overig: items/tekst gewoon als paragrafen
    return ''.join('<p>%s</p>' % _mk_item_body_html(b) for _i, _l, b in items)


def _mk_blocks_html(nodes):
    out = []
    for kind, payload in _mk_blocks(nodes):
        if kind == 'p':
            inner = _mk_inline_html(payload).strip()
            if inner:
                out.append('<p>%s</p>' % inner)
        else:
            out.append(_mk_env_html(payload))
    return ''.join(out)


def _html_markup(text):
    """Blok-HTML van template-markup; val bij twijfel terug op platte escape."""
    if not text:
        return ''
    text = _apply_lakken(text)
    try:
        return _mk_blocks_html(_mk_parse(text))
    except (_MkFail, RecursionError):
        return '<p>%s</p>' % _html_esc(str(text)).replace('\n', '<br>')


# --- Markdown-renderer (voor DOCX via pandoc) ------------------------------ #

_MD_INLINE = {'textbf': ('**', '**'), 'textit': ('*', '*'), 'emph': ('*', '*'),
              'texttt': ('`', '`'), 'underline': ('', ''), 'textrm': ('', ''),
              'textsc': ('', ''), 'textsf': ('', ''),
              'pad': ('`', '`'), 'host': ('`', '`'),
              'route': ('`', '`'), 'param': ('`', '`')}
_MD_ZERO = {'textbackslash': '\\\\', 'textrightarrow': '→', 'textleftarrow': '←',
            'ldots': '…', 'dots': '…', 'newline': '  \n', 'par': '\n\n', 'noindent': '',
            'textasciitilde': '~', 'textasciicircum': '^'}
_MD_ESC_RE = _re.compile(r'([\\`*_\[\]<>#|])')


def _md_esc(seg):
    return _MD_ESC_RE.sub(r'\\\1', seg)


def _md_link(label, url):
    return ('[%s](%s)' % (label.replace(']', ' '), url)) if url else label


def _smart_inline_md(nd):
    name = nd[1]
    if name == 'haakjes':
        inner = _mk_inline_md(nd[2]).strip()
        return ("*'%s'*" % inner) if inner else ''
    if name in _MK_REFMACRO:
        ref = _mk_inline_md(nd[2]).strip()
        if name == 'uitwerking':
            return 'We werken deze bevinding verder uit in § bevinding %s' % ref
        return '§ bevinding %s' % ref
    if name == 'bevindingref':
        return '§ bevinding %s' % _mk_inline_md(nd[2]).strip()
    if name == 'cwe':
        return _md_link(*_link_cwe(_mk_inline_plain(nd[2]).strip()))
    if name == 'cve':
        return _md_link(*_link_cve(_mk_inline_plain(nd[2]).strip()))
    if name == 'owasp':
        return _md_link(*_link_owasp(_mk_inline_plain(nd[2]).strip()))
    if name == 'cvss':
        arg = _mk_inline_plain(nd[2]).strip()
        key, _r = _cvss_to_severity(arg)
        return '**%s (%s)**' % (arg, _SEV_LABELS[key])
    if name == 'severity':
        key = _sev_from_word(_mk_inline_plain(nd[2]).strip())
        return ('**%s**' % _SEV_LABELS[key]) if key else None
    if name in _CALLOUT_META:
        titel = _CALLOUT_META[name][0]
        return '\n\n> **%s:** %s\n\n' % (titel, _mk_inline_md(nd[2]).strip())
    if name == 'stap':
        return '**Stap:** %s' % _mk_inline_md(nd[2]).strip()
    if name in ('request', 'response'):
        titel = 'Request' if name == 'request' else 'Response'
        return '\n\n**%s:**\n\n```\n%s\n```\n\n' % (titel, _mk_inline_plain(nd[2]).strip())
    return None


def _smart_cmd2_md(nd):
    if nd[1] == 'deelsgelakt':
        hidden = _REDACT_BLOCK if redact_enabled() else _mk_inline_md(nd[3]).strip()
        return _mk_inline_md(nd[2]).strip() + hidden
    return _mk_inline_md(nd[2]) + _mk_inline_md(nd[3])


def _mk_inline_md(nodes):
    out = []
    for nd in nodes:
        t = nd[0]
        if t == 'text':
            out.append(_md_esc(nd[1]))
        elif t == 'zero':
            out.append(_MD_ZERO.get(nd[1], ''))
        elif t == 'cmd':
            sp = _smart_inline_md(nd)
            if sp is not None:
                out.append(sp)
            else:
                w = _MD_INLINE.get(nd[1], ('', ''))
                inner = _mk_inline_md(nd[2]).strip()
                out.append((w[0] + inner + w[1]) if inner else '')
        elif t == 'cmd2':
            out.append(_smart_cmd2_md(nd))
        elif t == 'img':
            out.append(_mk_image_md(nd[2], nd[3]))
        elif t == 'env':
            out.append('\n\n' + _mk_env_md(nd) + '\n\n')
    return ''.join(out)


def _mk_env_md(envnode):
    envname = envnode[1]
    items = envnode[2]
    lines = []
    for idx, (_it, label, body) in enumerate(items, 1):
        bullet = '%d.' % idx if envname == 'enumerate' else '-'
        lab = ''
        if label is not None:
            lab = '**%s** ' % _mk_inline_md(label).strip()
        body_md = _mk_blocks_md(body).strip()
        if envname == 'quote':
            lines.append('> ' + (lab + body_md).replace('\n', ' ').strip())
            continue
        parts = (lab + body_md).split('\n')
        lines.append(('%s %s' % (bullet, parts[0])).rstrip())
        # vervolgregels (bv. geneste lijst) inspringen onder de bullet
        for p in parts[1:]:
            lines.append(('  ' + p) if p.strip() else '')
    return '\n'.join(lines)


def _mk_blocks_md(nodes):
    out = []
    for kind, payload in _mk_blocks(nodes):
        if kind == 'p':
            inner = _mk_inline_md(payload).strip()
            if inner:
                out.append(inner)
        else:
            out.append(_mk_env_md(payload))
    return '\n\n'.join(out)


def _md_markup(text):
    """Markdown van template-markup; val bij twijfel terug op platte tekst."""
    if not text:
        return ''
    text = _apply_lakken(text)
    try:
        return _mk_blocks_md(_mk_parse(text))
    except (_MkFail, RecursionError):
        return _md_esc(str(text))


# --- Plain-text-renderer (overzichtstabellen, SARIF, pptx) ----------------- #

_PLAIN_ZERO = {'textbackslash': '\\', 'textrightarrow': '→', 'textleftarrow': '←',
               'ldots': '…', 'dots': '…', 'newline': ' ', 'par': ' ', 'noindent': '',
               'textasciitilde': '~', 'textasciicircum': '^'}


_PLAIN_LINK = {'cwe': _link_cwe, 'cve': _link_cve, 'owasp': _link_owasp}


def _smart_inline_plain(nd):
    name = nd[1]
    if name == 'haakjes':
        return "'%s'" % _mk_inline_plain(nd[2]).strip()
    if name in _MK_REFMACRO:
        ref = _mk_inline_plain(nd[2]).strip()
        if name == 'uitwerking':
            return 'We werken deze bevinding verder uit in § bevinding %s' % ref
        return '§ bevinding %s' % ref
    if name == 'bevindingref':
        return '§ bevinding %s' % _mk_inline_plain(nd[2]).strip()
    if name in _PLAIN_LINK:
        label, _u = _PLAIN_LINK[name](_mk_inline_plain(nd[2]).strip())
        return label
    if name == 'cvss':
        arg = _mk_inline_plain(nd[2]).strip()
        key, _r = _cvss_to_severity(arg)
        return '%s (%s)' % (arg, _SEV_LABELS[key])
    if name == 'severity':
        key = _sev_from_word(_mk_inline_plain(nd[2]).strip())
        return _SEV_LABELS[key] if key else None
    if name in _CALLOUT_META:
        titel = _CALLOUT_META[name][0]
        return '%s: %s' % (titel, _mk_inline_plain(nd[2]).strip())
    if name == 'stap':
        return 'Stap: %s' % _mk_inline_plain(nd[2]).strip()
    if name in ('request', 'response'):
        titel = 'Request' if name == 'request' else 'Response'
        return '%s: %s' % (titel, _mk_inline_plain(nd[2]).strip())
    return None


def _mk_inline_plain(nodes):
    out = []
    for nd in nodes:
        t = nd[0]
        if t == 'text':
            out.append(nd[1])
        elif t == 'zero':
            out.append(_PLAIN_ZERO.get(nd[1], ''))
        elif t == 'cmd':
            sp = _smart_inline_plain(nd)
            out.append(sp if sp is not None else _mk_inline_plain(nd[2]))
        elif t == 'cmd2':
            if nd[1] == 'deelsgelakt':
                hidden = _REDACT_BLOCK if redact_enabled() else _mk_inline_plain(nd[3]).strip()
                out.append(_mk_inline_plain(nd[2]).strip() + hidden)
            else:
                out.append(_mk_inline_plain(nd[2]) + _mk_inline_plain(nd[3]))
        elif t == 'img':
            cap = _mk_inline_plain(nd[3]).strip()
            out.append(('[afbeelding: %s]' % cap) if cap else '[afbeelding]')
        elif t == 'env':
            parts = []
            for _it, label, body in nd[2]:
                lab = ''
                if label is not None:
                    lt = _mk_inline_plain(label).strip()
                    lab = lt + (' ' if lt.endswith(':') else ': ')
                parts.append((lab + _mk_inline_plain(body).strip()).strip())
            out.append(' ' + '; '.join(p for p in parts if p) + ' ')
    return ''.join(out)


def _plain_markup(text):
    """Platte tekst van template-markup (geen opmaak), voor tabellen/SARIF/pptx."""
    if not text:
        return ''
    try:
        s = _mk_inline_plain(_mk_parse(text))
    except (_MkFail, RecursionError):
        s = str(text)
    return _re.sub(r'\s+', ' ', s).strip()


# --- Template-gezondheidscheck ------------------------------------------- #
# Scant alle bevinding-templates op markup die niet veilig rendert (en dus in
# de rapportage stil terugvalt op platte tekst). Zo kan de operator de BRON
# opschonen i.p.v. de symptomen.
_HEALTH_FIELDS = ('nlbeschrijving', 'nlimpact', 'nlaanbeveling',
                  'enbeschrijving', 'enimpact', 'enaanbeveling',
                  'nlimpactkort', 'nlaanbevelingkort', 'enimpactkort',
                  'enaanbevelingkort', 'referenties')


def _markup_health_reason(v):
    begins = _re.findall(r'\\begin\{([a-zA-Z*]+)\}', v)
    ends = _re.findall(r'\\end\{([a-zA-Z*]+)\}', v)
    for env in set(begins) | set(ends):
        nb, ne = begins.count(env), ends.count(env)
        if nb != ne:
            return 'omgeving "%s" niet in balans (%d×\\begin, %d×\\end)' % (env, nb, ne)
    if r'\item' in v and not begins:
        return 'los \\item zonder omgeving'
    if v.count('{') != v.count('}'):
        return 'accolades niet in balans'
    return 'ongeldige of niet-ondersteunde markup'


def _template_health():
    """Lijst van templates waarvan een veld niet veilig als markup rendert."""
    from meuk.flask.models import db_bevindingen_templates
    issues = []
    for t in db_bevindingen_templates.query.all():
        for fld in _HEALTH_FIELDS:
            v = getattr(t, fld, '') or ''
            if not v.strip():
                continue
            try:
                _mk_parse(v)
            except (_MkFail, RecursionError):
                issues.append({
                    'id': t.id,
                    'titel': getattr(t, 'titel', '') or '',
                    'veld': fld,
                    'reden': _markup_health_reason(v),
                })
    return issues


@findings_bp.route('/api/findings/templates/health', methods=['GET'])
def templates_health():
    issues = _template_health()
    return jsonify({'ok': True, 'count': len(issues), 'issues': issues})


@findings_bp.app_template_filter('latex_escape')
def latex_escape_filter(text):
    return _latex_escape(text)


@findings_bp.app_template_filter('latex_markup')
def latex_markup_filter(text):
    return _latex_markup(text)


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
    try:
        idx = int(num) - 1
        if 0 <= idx < len(owasptop10):
            return owasptop10[idx]
    except (TypeError, ValueError):
        pass
    return 'A5 - Security Misconfiguration'


@findings_bp.app_template_filter('cvss_severity')
def cvss_severity_filter(basescore):
    sev, _ = _cvss_to_severity(basescore)
    return sev


@findings_bp.app_template_filter('ncsc_richtlijn')
def ncsc_richtlijn_filter(code):
    if code and code in ncsc_richtlijnen:
        return '{} - {}'.format(code, ncsc_richtlijnen[code])
    return code or ''


@findings_bp.app_template_filter('owaspcategorie_2025')
def owaspcategorie_2025(num):
    try:
        idx = int(num) - 1
        if 0 <= idx < len(owasptop10_2025):
            return owasptop10_2025[idx]
    except (TypeError, ValueError):
        pass
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
        nlimpactkort=getattr(item, 'nlimpactkort', '') or '',
        enimpactkort=getattr(item, 'enimpactkort', '') or '',
        nlaanbevelingkort=getattr(item, 'nlaanbevelingkort', '') or '',
        enaanbevelingkort=getattr(item, 'enaanbevelingkort', '') or '',
        referenties=item.referenties,
    )
    return render_template('template_page.html', form=form, title='Template bewerken')


def _strip_latex(text):
    """Verwijder LaTeX-opmaak en geef leesbare platte tekst terug."""
    if not text:
        return ''
    t = str(text)
    # \item[Label:] -> "Label: "
    t = _re.sub(r'\\item\s*\[([^\]]*?)\]', r'\1 ', t)
    t = _re.sub(r'\\item\b', '', t)
    # omgevingen \begin{..}/\end{..}
    t = _re.sub(r'\\(begin|end)\s*\{[^}]*\}', ' ', t)
    # \textbf{x}, \texttt{x}, \emph{x}, \textit{x} -> x
    t = _re.sub(r'\\(?:textbf|texttt|emph|textit|textsc|underline)\s*\{([^{}]*)\}', r'\1', t)
    # \href{url}{tekst} -> tekst
    t = _re.sub(r'\\href\s*\{[^}]*\}\s*\{([^{}]*)\}', r'\1', t)
    # overige commando's met argument -> argument
    t = _re.sub(r'\\[a-zA-Z]+\s*\{([^{}]*)\}', r'\1', t)
    # losse commando's
    t = _re.sub(r'\\[a-zA-Z]+\*?', ' ', t)
    # LaTeX-accenten die als \"e etc. zijn blijven staan
    t = t.replace('\\"', '').replace('\\', '')
    # resterende haakjes/opsommingstekens opruimen
    t = t.replace('{', '').replace('}', '')
    t = _re.sub(r'\s+', ' ', t).strip()
    return t


# Generieke, inhoudsarme openingszinnen die we overslaan bij de impact.
_ZWAKKE_OPENER = _re.compile(
    r'^(de|het)\s+impact\s+van\b.*?(kan|is|hangt|varieert|vari)\b'
    r'|^the\s+impact\s+of\b.*?(can|is|depends|may|varies)\b'
    r'|^de\s+impact\s+(kan|is|hangt|varieert)\b'
    r'|^the\s+impact\s+(can|is|depends|may|varies)\b',
    _re.IGNORECASE)


# Inhoudsarme aanhef die we wegstrippen zodat de kern van de impact vooraan komt
# te staan (bv. "De impact van deze bevinding is dat ..." -> "...").
_ZWAKKE_AANHEF = _re.compile(
    r'^\s*(?:de|het)\s+impact\b[^.]*?\b(?:dat|is|kan|betekent|:)\s+(?:dat\s+)?'
    r'|^\s*the\s+impact\b[^.]*?\b(?:that|is|can|means|:)\s+(?:that\s+)?',
    _re.IGNORECASE)


def _strip_zwakke_aanhef(z):
    """Verwijder een inhoudsarme 'de impact ... is/dat'-aanhef, mits er genoeg
    kern overblijft; anders de zin ongewijzigd laten."""
    m = _ZWAKKE_AANHEF.match(z)
    if m:
        rest = z[m.end():].strip()
        if len(rest) >= 20:
            return rest[0].upper() + rest[1:]
    return z


def _zinnen(t):
    return [z.strip() for z in _re.split(r'(?<=[.!?])\s+', t) if z.strip()]


def _beknopt(text, max_len=255):
    """Beknopte, LaTeX-vrije samenvatting: eerste inhoudelijke zin."""
    t = _strip_latex(text)
    if not t:
        return ''
    zinnen = _zinnen(t)
    gekozen = ''
    for z in zinnen:
        if _ZWAKKE_OPENER.search(z) and len(zinnen) > 1:
            continue  # sla generieke "de impact van ... kan ..." over
        gekozen = z
        break
    if not gekozen:
        gekozen = zinnen[0] if zinnen else t
    gekozen = _strip_zwakke_aanhef(gekozen)
    if len(gekozen) > max_len:
        gekozen = gekozen[:max_len - 1].rstrip() + '…'
    return gekozen


def _beknopt_aanbeveling(text, taal='nl', max_len=255):
    """Beknopte aanbeveling: vat de kernmaatregelen (item-labels) samen, of val
    terug op de eerste inhoudelijke zin."""
    raw = str(text or '')
    # Maatregel-labels uit een LaTeX description-lijst: \item[Label:]
    labels = _re.findall(r'\\item\s*\[([^\]]+?)\]', raw)
    labels = [_strip_latex(lab).rstrip(':').strip() for lab in labels]
    labels = [lab for lab in labels if lab]
    if len(labels) >= 2:
        # Alleen de kernmaatregelen zelf; geen overbodige inleidende tekst.
        s = ', '.join(labels)
        s = s[0].upper() + s[1:]
        if not s.endswith('.'):
            s += '.'
        if len(s) > max_len:
            s = s[:max_len - 1].rstrip() + '…'
        return s
    return _beknopt(text, max_len=max_len)


def _vul_kort_velden(tmpl, overschrijf=False):
    """Vul de *kort-velden met een beknopte samenvatting van de lange impact/
    aanbeveling. overschrijf=False laat reeds ingevulde korte velden ongemoeid."""
    # (kort-veld, lang-veld, soort, taal)
    paren = (
        ('nlimpactkort', 'nlimpact', 'impact', 'nl'),
        ('enimpactkort', 'enimpact', 'impact', 'en'),
        ('nlaanbevelingkort', 'nlaanbeveling', 'aanbeveling', 'nl'),
        ('enaanbevelingkort', 'enaanbeveling', 'aanbeveling', 'en'),
    )
    gewijzigd = 0
    for kort, lang, soort, taal in paren:
        if not overschrijf and (getattr(tmpl, kort, '') or '').strip():
            continue
        bron = getattr(tmpl, lang, '') or ''
        if soort == 'aanbeveling':
            nieuw = _beknopt_aanbeveling(bron, taal=taal)
        else:
            nieuw = _beknopt(bron)
        if nieuw and nieuw != (getattr(tmpl, kort, '') or ''):
            setattr(tmpl, kort, nieuw)
            gewijzigd += 1
    return gewijzigd


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
                tmpl.nlimpactkort = (form.nlimpactkort.data or '').strip()
                tmpl.enimpactkort = (form.enimpactkort.data or '').strip()
                tmpl.nlaanbevelingkort = (form.nlaanbevelingkort.data or '').strip()
                tmpl.enaanbevelingkort = (form.enaanbevelingkort.data or '').strip()
                tmpl.referenties = form.referenties.data
                # Lege korte velden automatisch afleiden; ingevulde blijven staan
                _vul_kort_velden(tmpl, overschrijf=False)
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
                nlimpactkort=(form.nlimpactkort.data or '').strip(),
                enimpactkort=(form.enimpactkort.data or '').strip(),
                nlaanbevelingkort=(form.nlaanbevelingkort.data or '').strip(),
                enaanbevelingkort=(form.enaanbevelingkort.data or '').strip(),
                referenties=form.referenties.data,
            )
            _vul_kort_velden(tmpl, overschrijf=False)
            db.session.add(tmpl)
            db.session.commit()

    return redirect(url_for('findings_bp.bevindingen_overzicht'))


@findings_bp.route('/api/findings/templates/fill-kort', methods=['POST'])
def templates_fill_kort():
    """Vul de beknopte impact-/aanbevelingsvelden van bestaande templates.

    Body: {overschrijf?: bool}. Standaard worden alleen lege korte velden
    gevuld (bestaande handmatige waarden blijven staan)."""
    from flask import current_app
    if current_app.config.get('WTF_CSRF_ENABLED', True):
        from flask_wtf.csrf import validate_csrf
        try:
            validate_csrf(request.headers.get('X-CSRFToken', ''))
        except Exception:
            return jsonify({'ok': False, 'error': 'CSRF-fout'}), 403
    overschrijf = bool((request.get_json(silent=True) or {}).get('overschrijf', False))
    templates_bijgewerkt = 0
    velden_gevuld = 0
    for tmpl in db_bevindingen_templates.query.all():
        n = _vul_kort_velden(tmpl, overschrijf=overschrijf)
        if n:
            templates_bijgewerkt += 1
            velden_gevuld += n
    db.session.commit()
    return jsonify({'ok': True, 'templates': templates_bijgewerkt,
                    'velden': velden_gevuld})


@findings_bp.route('/dashboard/findings/templates/delete/<int:template_id>', methods=['POST'])
def template_verwijderen(template_id):
    _csrf_check(request.form.get('csrf_token'))
    tmpl = db.get_or_404(db_bevindingen_templates, template_id)
    db.session.delete(tmpl)
    db.session.commit()
    return redirect(url_for('findings_bp.bevindingen_overzicht'))


@findings_bp.route('/api/findings/templates')
def api_findings_templates():
    templates = db_bevindingen_templates.query.all()
    return jsonify({'templates': [
        {'id': t.id, 'titel': t.titel, 'bevtype': t.bevtype or '',
         'cwe': getattr(t, 'cwe', '') or '',
         'ncsc': getattr(t, 'ncsc', '') or '',
         'owasp_2025': getattr(t, 'owasp_2025', '') or ''}
        for t in templates
    ]})


@findings_bp.route('/api/findings/templates/<int:template_id>/detail')
def api_findings_template_detail(template_id):
    """Volledige tekst van één standaardbevinding (template), voor read-only
    weergave in de bevinding-editor en als placeholder voor de overrides."""
    t = db.session.get(db_bevindingen_templates, template_id)
    if not t:
        return jsonify({'error': 'template niet gevonden'}), 404
    return jsonify({
        'id': t.id, 'titel': t.titel, 'bevtype': t.bevtype or '',
        'cwe': getattr(t, 'cwe', '') or '', 'ncsc': getattr(t, 'ncsc', '') or '',
        'owasp_2025': getattr(t, 'owasp_2025', '') or '',
        'cvss': getattr(t, 'cvss', '') or '', 'basescore': getattr(t, 'basescore', '') or '',
        'beschrijving': getattr(t, 'nlbeschrijving', '') or '',
        'impact': getattr(t, 'nlimpact', '') or '',
        'aanbeveling': getattr(t, 'nlaanbeveling', '') or '',
        'impact_kort': getattr(t, 'nlimpactkort', '') or '',
        'aanbeveling_kort': getattr(t, 'nlaanbevelingkort', '') or '',
    })


@findings_bp.route('/dashboard/findings/add/<bevinding_id>', methods=['GET', 'POST'])
def bevinding_toevoegen(bevinding_id):

    # '0' (of leeg) betekent: nieuwe bevinding zonder voorgekoppelde template.
    _ref = bevinding_id if (bevinding_id and bevinding_id != '0') else ''
    form = BevindingForm(ref=_ref)
    scope_targets = _get_scope_targets()
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        pagina = render_template('bevinding_toevoegen.html', form=form, scope_targets=scope_targets)
    else:
        pagina = render_template('bevinding_page.html', form=form, title='Nieuwe finding', scope_targets=scope_targets)
    return pagina


@findings_bp.route('/dashboard/findings', methods=['GET'])
@findings_bp.route('/dashboard/findings/', methods=['GET'])
def bevindingen_overzicht():
    findings = _active_findings().all()
    templates = db_bevindingen_templates.query.all()
    template_groups = _group_templates(templates)
    # SLA-overschrijding: doeldatum (expliciet of afgeleid) in het verleden en nog niet afgehandeld
    _vandaag = datetime.date.today()
    overdue_ids = {
        f.id for f in findings
        if (f.remediation_target_date or _sla_doeldatum(f)) < _vandaag
        and (f.remediation_status or 'open') not in _REM_AFGEHANDELD
    }
    deleted_count = db_bevindingen.query.filter(db_bevindingen.deleted_at.isnot(None)).count()
    deleted_findings = db_bevindingen.query.filter(db_bevindingen.deleted_at.isnot(None)).order_by(db_bevindingen.deleted_at.desc()).all() if deleted_count else []
    # OWASP/NCSC leven op de standaardbevinding (template); de bevinding koppelt
    # daaraan via f.ref. Zo kan het overzicht die velden per bevinding tonen.
    template_map = {str(t.id): t for t in templates}
    # Notities (zelfde projectscope als de notes-blueprint) voor het tabblad.
    from meuk.flask import project as _project
    notes = _project.apply_scope(
        db_notes.query, db_notes.opdracht_id, _project.current_opdracht_id()
    ).order_by(db_notes.volgorde.asc(), db_notes.id.desc()).all()
    return render_template('findings_index.html', findings=findings, templates=templates,
                           template_groups=template_groups, deleted_count=deleted_count,
                           deleted_findings=deleted_findings, overdue_ids=overdue_ids,
                           template_map=template_map, notes=notes)


@findings_bp.route('/dashboard/findings/edit/<bevinding_id>', methods=['GET', 'POST'])
def bevinding_bewerken(bevinding_id):

    item = db_bevindingen.query.filter_by(id=bevinding_id).first()
    if not item or item.deleted_at:
        abort(404)

    form = BevindingForm(
        id=item.id, naam=item.naam, invoegen=item.invoegen, ref=item.ref,
        uitwerken=item.uitwerken, locatie=item.locatie,
        beschrijving_override=getattr(item, 'beschrijving_override', '') or '',
        impact_override=getattr(item, 'impact_override', '') or '',
        aanbeveling_override=getattr(item, 'aanbeveling_override', '') or '',
        impact_kort_override=getattr(item, 'impact_kort_override', '') or '',
        aanbeveling_kort_override=getattr(item, 'aanbeveling_kort_override', '') or '',
        cvss=getattr(item, 'cvss', '') or '',
        basescore=getattr(item, 'basescore', '') or '',
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
        tester=getattr(item, 'tester', '') or '',
    )
    scope_targets = _get_scope_targets()
    huidige_opdracht = getattr(item, 'opdracht_id', None)
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        pagina = render_template('bevinding_toevoegen.html', form=form, scope_targets=scope_targets)
    else:
        pagina = render_template('bevinding_page.html', form=form, title='Finding bewerken',
                                 scope_targets=scope_targets, huidige_opdracht=huidige_opdracht)
    return pagina

@findings_bp.route('/dashboard/findings/delete/<int:bevindingen_id>', methods=['POST'])
def bevinding_verwijderen(bevindingen_id):
    _csrf_check(request.form.get('csrf_token'))
    verwijder = db_bevindingen.query.filter_by(id=bevindingen_id).first_or_404()
    verwijder.deleted_at = nu_utc()
    db.session.commit()
    return redirect(url_for('findings_bp.bevindingen_overzicht'))


@findings_bp.route('/dashboard/findings/restore/<int:bevindingen_id>', methods=['POST'])
def bevinding_herstellen(bevindingen_id):
    _csrf_check(request.form.get('csrf_token'))
    bev = db_bevindingen.query.filter_by(id=bevindingen_id).first_or_404()
    bev.deleted_at = None
    db.session.commit()
    return redirect(url_for('findings_bp.bevindingen_overzicht'))


@findings_bp.route('/dashboard/findings/save', methods=['POST'])
def bevinding_opslaan():

    form = BevindingForm()
    if form.validate_on_submit():

        try:
            _id = int(form.id.data)
        except (ValueError, TypeError):
            _id = 0

        if _id > 0:
            bev = db.session.get(db_bevindingen, _id)
            if not bev or bev.deleted_at:
                abort(404)
            # Log gewijzigde velden
            _tracked = [
                ('naam', bev.naam, form.naam.data),
                ('locatie', bev.locatie, form.locatie.data),
                ('status', bev.status, form.status.data),
                ('basescore', bev.basescore, form.basescore.data),
                ('cvss', bev.cvss, form.cvss.data),
                ('remediation_status', bev.remediation_status, form.remediation_status.data),
                ('remediation_target_date', getattr(bev, 'remediation_target_date', None), form.remediation_target_date.data),
                ('remediation_owner', getattr(bev, 'remediation_owner', None), form.remediation_owner.data),
                ('retest_status', bev.retest_status, form.retest_status.data),
                ('retest_date', getattr(bev, 'retest_date', None), form.retest_date.data),
                ('retest_notes', getattr(bev, 'retest_notes', None), form.retest_notes.data),
                ('tester', getattr(bev, 'tester', None), form.tester.data),
            ]
            for field, old, new in _tracked:
                if str(old or '') != str(new or ''):
                    _log_change('db_bevinding', bev.id, field, old, new)
            bev.naam = form.naam.data
            bev.ref = form.ref.data
            bev.uitwerken = form.uitwerken.data
            bev.beschrijving_override = form.beschrijving_override.data or ''
            bev.impact_override = form.impact_override.data or ''
            bev.aanbeveling_override = form.aanbeveling_override.data or ''
            bev.impact_kort_override = form.impact_kort_override.data or ''
            bev.aanbeveling_kort_override = form.aanbeveling_kort_override.data or ''
            bev.locatie = form.locatie.data
            bev.basescore =  form.basescore.data
            bev.cvss =  form.cvss.data
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
            bev.tester            = form.tester.data
            _zet_sla_doeldatum_indien_leeg(bev)
            db.session.commit()
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'ok': True, 'id': bev.id})

        else:
            bevdb = db_bevindingen(
                naam=form.naam.data,
                ref=form.ref.data, uitwerken=form.uitwerken.data,
                beschrijving_override=form.beschrijving_override.data or '',
                impact_override=form.impact_override.data or '',
                aanbeveling_override=form.aanbeveling_override.data or '',
                impact_kort_override=form.impact_kort_override.data or '',
                aanbeveling_kort_override=form.aanbeveling_kort_override.data or '',
                locatie=form.locatie.data, basescore=form.basescore.data,
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
                tester=form.tester.data,
            )
            _zet_sla_doeldatum_indien_leeg(bevdb)
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
    findings = _active_findings().filter(
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
    findings = _active_findings().all()
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
    old_status = bev.status
    bev.status = new_status
    if old_status != new_status:
        _log_change('db_bevinding', finding_id, 'status', old_status, new_status)
    # Bij finaliseren: zet een hersteldoeldatum op basis van de SLA indien nog leeg
    if new_status == 'final':
        _zet_sla_doeldatum_indien_leeg(bev)
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


def _sha256_file(path):
    """Hex-SHA-256 van een bestand, streaming (geschikt voor grote bestanden)."""
    digest = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


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
        'exported_at': nu_utc().isoformat() + 'Z',
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
    lak_dir = os.path.join(_evidence_path(finding_id), 'lakken')
    return jsonify({'evidence': [
        {
            'id': e.id,
            'filename': e.filename,
            'original_filename': e.original_filename,
            'content_type': e.content_type,
            'created_at': e.created_at.isoformat() + 'Z' if e.created_at else None,
            'description': e.description or '',
            'tool_name': e.tool_name or '',
            'evidence_category': e.evidence_category or '',
            'sha256': e.sha256 or '',
            # True als er een gelakte kopie bestaat (voor het gelakte rapport).
            'has_lakken': os.path.exists(os.path.join(lak_dir, e.filename)),
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
    stored_path = os.path.join(dest_dir, stored_name)
    f.save(stored_path)

    # Integriteit (chain of custody): SHA-256 over het opgeslagen bestand, zodat
    # een auditor kan verifiëren dat het bewijs in het rapport niet is gewijzigd.
    sha256 = _sha256_file(stored_path)

    ev = db_evidence(
        finding_id=finding_id,
        filename=stored_name,
        original_filename=original,
        content_type=content_type,
        description=request.form.get('description', '')[:500] or None,
        tool_name=request.form.get('tool_name', '')[:100] or None,
        evidence_category=request.form.get('evidence_category', '')[:50] or None,
        sha256=sha256,
    )
    db.session.add(ev)
    db.session.commit()

    return jsonify({
        'ok': True,
        'id': ev.id,
        'filename': stored_name,
        'original_filename': original,
        'sha256': sha256,
    })


_MAX_REDACT_BYTES = 20 * 1024 * 1024  # 20 MB gedecodeerde PNG


@findings_bp.route('/api/findings/evidence/<int:evidence_id>/redact', methods=['POST', 'DELETE'])
def redact_evidence(evidence_id):
    """Beheer de gelakte kopie van een bewijsafbeelding voor het gelakte rapport.

    POST: ontvangt de in de browser zwartgelakte afbeelding (PNG data-URL) en slaat
    die op als lakken/<filename> naast het origineel. Zo laadt de gelakte
    rapportbuild deze i.p.v. het origineel. DELETE: verwijdert de gelakte kopie.
    """
    ev = db.session.get(db_evidence, evidence_id)
    if not ev:
        return jsonify({'error': 'evidence niet gevonden'}), 404
    if not (ev.content_type or '').startswith('image/'):
        return jsonify({'error': 'alleen afbeeldingen kunnen gelakt worden'}), 400

    lak_dir = os.path.join(_evidence_path(ev.finding_id), 'lakken')
    lak_path = os.path.join(lak_dir, ev.filename)

    if request.method == 'DELETE':
        try:
            if os.path.exists(lak_path):
                os.remove(lak_path)
        except OSError:
            return jsonify({'error': 'verwijderen mislukt'}), 500
        return jsonify({'ok': True, 'has_lakken': False})

    data = request.get_json(silent=True) or {}
    img = (data.get('image') or '')
    m = _re.match(r'^data:image/(?:png|jpeg);base64,(.+)$', img, _re.S)
    if not m:
        return jsonify({'error': 'geen geldige PNG-afbeelding (data-URL verwacht)'}), 400
    import base64
    try:
        raw = base64.b64decode(m.group(1), validate=True)
    except Exception:  # noqa: BLE001
        return jsonify({'error': 'kon afbeelding niet decoderen'}), 400
    if len(raw) > _MAX_REDACT_BYTES:
        return jsonify({'error': 'afbeelding te groot'}), 413

    # Her-encodeer naar het formaat van het origineel (de LaTeX-include kiest de
    # driver op de bestandsextensie, dus die moet bij de inhoud passen).
    os.makedirs(lak_dir, exist_ok=True)
    try:
        import io
        from PIL import Image
        im = Image.open(io.BytesIO(raw))
        if im.mode in ('RGBA', 'P', 'LA'):
            im = im.convert('RGB')
        im.save(lak_path)
    except Exception:  # noqa: BLE001 — PIL mag de UI nooit breken
        return jsonify({'error': 'afbeelding kon niet worden opgeslagen'}), 400

    return jsonify({'ok': True, 'has_lakken': True})


@findings_bp.route('/api/findings/evidence/<int:evidence_id>/download', methods=['GET'])
def download_evidence(evidence_id):
    ev = db.session.get(db_evidence, evidence_id)
    if not ev:
        return jsonify({'error': 'evidence niet gevonden'}), 404
    path = _evidence_path(ev.finding_id)
    return send_from_directory(path, ev.filename, as_attachment=True,
                               download_name=ev.original_filename or ev.filename)


@findings_bp.route('/api/findings/evidence/<int:evidence_id>/verify', methods=['GET'])
def verify_evidence(evidence_id):
    """Herbereken de SHA-256 van het opgeslagen bewijsbestand en vergelijk met de
    bij vastlegging bewaarde hash (chain of custody). status: match | mismatch |
    no_hash (geen hash vastgelegd) | missing_file (bestand weg)."""
    ev = db.session.get(db_evidence, evidence_id)
    if not ev:
        return jsonify({'error': 'evidence niet gevonden'}), 404
    filepath = os.path.join(_evidence_path(ev.finding_id), ev.filename)
    if not os.path.exists(filepath):
        return jsonify({'ok': False, 'status': 'missing_file',
                        'sha256_stored': ev.sha256 or '', 'sha256_actual': ''}), 200
    actual = _sha256_file(filepath)
    if not ev.sha256:
        status = 'no_hash'
    elif actual == ev.sha256:
        status = 'match'
    else:
        status = 'mismatch'
    return jsonify({
        'ok': status == 'match',
        'status': status,
        'sha256_stored': ev.sha256 or '',
        'sha256_actual': actual,
    })


@findings_bp.route('/api/findings/evidence/<int:evidence_id>', methods=['DELETE'])
def delete_evidence(evidence_id):
    from flask import current_app
    if current_app.config.get('WTF_CSRF_ENABLED', True):
        from flask_wtf.csrf import validate_csrf
        try:
            validate_csrf(request.headers.get('X-CSRFToken', ''))
        except Exception:
            return jsonify({'error': 'CSRF-fout'}), 403
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
# Assets & anchors — koppel doelen (host/service/endpoint) aan bevindingen
# ---------------------------------------------------------------------------

def _asset_dedupe_key(asset_type, waarde, poort):
    """Genormaliseerde unieke sleutel voor een asset (type|waarde|poort)."""
    t = (asset_type or 'host').strip().lower()
    w = (waarde or '').strip().lower().rstrip('/')
    p = str(poort) if poort not in (None, '', 0) else ''
    return '{}|{}|{}'.format(t, w, p)


def _asset_dict(a):
    return {
        'id': a.id,
        'opdracht_id': a.opdracht_id,
        'asset_type': a.asset_type,
        'waarde': a.waarde,
        'poort': a.poort,
        'protocol': a.protocol or '',
        'getest': a.getest,
        'in_scope': bool(a.in_scope),
        'notitie': a.notitie or '',
    }


@findings_bp.route('/api/findings/<int:finding_id>/assets', methods=['GET'])
def list_finding_assets(finding_id):
    """Lijst van assets die aan deze bevinding gekoppeld zijn (via anchors)."""
    bev = db.session.get(db_bevindingen, finding_id)
    if not bev:
        return jsonify({'error': 'bevinding niet gevonden'}), 404
    anchors = db_asset_anchor.query.filter_by(finding_id=finding_id).all()
    return jsonify({'assets': [
        dict(_asset_dict(an.asset), anchor_id=an.id, relatie=an.relatie)
        for an in anchors if an.asset is not None
    ]})


@findings_bp.route('/api/findings/<int:finding_id>/assets', methods=['POST'])
def add_finding_asset(finding_id):
    """Maak (of hergebruik) een asset en koppel deze aan de bevinding.

    Body (JSON): {waarde, asset_type?, poort?, protocol?, relatie?, opdracht_id?}.
    Dedupliceert op genormaliseerde sleutel; bestaat de asset al, dan wordt alleen
    een anchor toegevoegd.
    """
    from flask import current_app
    if current_app.config.get('WTF_CSRF_ENABLED', True):
        from flask_wtf.csrf import validate_csrf
        try:
            validate_csrf(request.headers.get('X-CSRFToken', ''))
        except Exception:
            return jsonify({'error': 'CSRF-fout'}), 403
    bev = db.session.get(db_bevindingen, finding_id)
    if not bev:
        return jsonify({'error': 'bevinding niet gevonden'}), 404

    data = request.get_json(silent=True) or {}
    waarde = (data.get('waarde') or '').strip()
    if not waarde:
        return jsonify({'error': 'waarde is verplicht'}), 400
    asset_type = (data.get('asset_type') or 'host').strip().lower()
    poort = data.get('poort') or None
    try:
        poort = int(poort) if poort not in (None, '') else None
    except (TypeError, ValueError):
        poort = None
    protocol = (data.get('protocol') or '').strip().lower()
    relatie = (data.get('relatie') or 'affected').strip().lower()
    opdracht_id = data.get('opdracht_id') or bev.opdracht_id

    dedupe = _asset_dedupe_key(asset_type, waarde, poort)
    asset = db_asset.query.filter_by(dedupe_key=dedupe).first()
    if asset is None:
        asset = db_asset(
            opdracht_id=opdracht_id, asset_type=asset_type, waarde=waarde,
            poort=poort, protocol=protocol, dedupe_key=dedupe,
        )
        db.session.add(asset)
        db.session.flush()   # id beschikbaar voor de anchor

    anchor = db_asset_anchor.query.filter_by(
        asset_id=asset.id, finding_id=finding_id).first()
    if anchor is None:
        anchor = db_asset_anchor(asset_id=asset.id, finding_id=finding_id, relatie=relatie)
        db.session.add(anchor)
    else:
        anchor.relatie = relatie
    db.session.commit()

    return jsonify({'ok': True, 'asset': dict(_asset_dict(asset),
                                              anchor_id=anchor.id, relatie=anchor.relatie)})


@findings_bp.route('/api/findings/assets/anchor/<int:anchor_id>', methods=['DELETE'])
def remove_finding_asset(anchor_id):
    """Verwijder de koppeling (anchor) tussen een asset en een bevinding.

    De asset zelf blijft bestaan (kan aan andere bevindingen hangen).
    """
    from flask import current_app
    if current_app.config.get('WTF_CSRF_ENABLED', True):
        from flask_wtf.csrf import validate_csrf
        try:
            validate_csrf(request.headers.get('X-CSRFToken', ''))
        except Exception:
            return jsonify({'error': 'CSRF-fout'}), 403
    anchor = db.session.get(db_asset_anchor, anchor_id)
    if not anchor:
        return jsonify({'error': 'koppeling niet gevonden'}), 404
    db.session.delete(anchor)
    db.session.commit()
    return jsonify({'ok': True})


@findings_bp.route('/api/assets', methods=['GET'])
def list_assets():
    """Alle assets (optioneel per opdracht) met aantal gekoppelde bevindingen."""
    q = db_asset.query
    opdracht_id = request.args.get('opdracht_id', type=int)
    if opdracht_id:
        q = q.filter(db_asset.opdracht_id == opdracht_id)
    assets = q.order_by(db_asset.asset_type, db_asset.waarde).all()
    return jsonify({'assets': [
        dict(_asset_dict(a), anchors=len(a.anchors)) for a in assets
    ]})


_VALID_ASSET_STATUS = {'untested', 'in_progress', 'tested', 'out_of_scope'}


def _asset_depth_of(aid, by_id):
    """Aantal parent-hops tot de wortel (parentless = 0), met cyclusbescherming."""
    d = 0
    seen = set()
    cur = by_id.get(aid)
    while cur and cur.parent_id and cur.parent_id in by_id and cur.parent_id not in seen:
        seen.add(cur.id)
        cur = by_id[cur.parent_id]
        d += 1
    return d


def build_asset_graph(opdracht_id=None):
    """Bouw de asset-coverage-graaf: knopen (met gekoppelde bevindingen,
    hoogste severity, live host-status en afgeleide dekking), parent->child-
    kanten en dekkingsstatistiek."""
    q = db_asset.query
    if opdracht_id:
        q = q.filter(db_asset.opdracht_id == opdracht_id)
    assets = q.order_by(db_asset.id).all()
    by_id = {a.id: a for a in assets}
    ids = set(by_id)

    fmap = {}           # asset_id -> [findings]
    sevmap = {}         # asset_id -> (severity, rank)
    derivedmap = {}     # asset_id -> bool (afgeleid uit exploration)
    if ids:
        anchors = db_asset_anchor.query.filter(db_asset_anchor.asset_id.in_(ids)).all()
        fids = {an.finding_id for an in anchors}
        bevs = {b.id: b for b in db_bevindingen.query.filter(
            db_bevindingen.id.in_(fids)).all()} if fids else {}
        for an in anchors:
            b = bevs.get(an.finding_id)
            fmap.setdefault(an.asset_id, []).append({
                'id': an.finding_id,
                'naam': (b.naam if b else '') or ('#' + str(an.finding_id)),
                'anchor_id': an.id,
            })
            sev, rank = _cvss_to_severity(b.basescore if b else '0')
            prev = sevmap.get(an.asset_id)
            if prev is None or rank < prev[1]:
                sevmap[an.asset_id] = (sev, rank)
        # Afgeleide dekking uit exploration-anchors (knoop done/achieved)
        ex_anchors = db_explore_asset_anchor.query.filter(
            db_explore_asset_anchor.asset_id.in_(ids)).all()
        if ex_anchors:
            nids = {ea.node_id for ea in ex_anchors}
            exnodes = {n.id: n for n in db_explore_node.query.filter(
                db_explore_node.id.in_(nids)).all()}
            for ea in ex_anchors:
                n = exnodes.get(ea.node_id)
                if n and n.status in ('done', 'achieved'):
                    derivedmap[ea.asset_id] = True

    # Live host-status uit hooked agents (match op hostname/ip)
    agentmap = {}
    for ag in db_agents.query.all():
        for key in (ag.hostname, ag.ip):
            if key:
                agentmap[key.strip().lower()] = {
                    'status': ag.status,
                    'last_seen': ag.last_seen.isoformat() + 'Z' if ag.last_seen else None,
                }

    nodes = []
    for a in assets:
        sev = sevmap.get(a.id)
        nodes.append({
            'id': a.id,
            'type': a.asset_type,
            'label': a.waarde,
            'poort': a.poort,
            'protocol': a.protocol or '',
            'getest': a.getest or 'untested',
            'in_scope': bool(a.in_scope),
            'parent_id': a.parent_id,
            'depth': _asset_depth_of(a.id, by_id),
            'findings': fmap.get(a.id, []),
            'max_severity': sev[0] if sev else None,
            'derived_tested': bool(derivedmap.get(a.id)),
            'agent': agentmap.get((a.waarde or '').strip().lower()),
        })
    edges = [{'from': a.parent_id, 'to': a.id}
             for a in assets if a.parent_id and a.parent_id in ids]
    stats = {
        'total': len(assets),
        'in_scope': sum(1 for a in assets if a.in_scope),
        'tested': sum(1 for a in assets if (a.getest or '') == 'tested'),
        'derived_tested': sum(1 for a in assets if derivedmap.get(a.id)),
    }
    return {'nodes': nodes, 'edges': edges, 'stats': stats}


# ── Asset auto-afleiding uit bestaande data ────────────────────────────────

def _looks_like_ip(s):
    import ipaddress
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _normalize_asset_input(raw):
    """Leid (asset_type, waarde, poort) af uit een vrije string (URL/host/IP).

    Retourneert None voor lege/onbruikbare waarden (bevat witruimte of te lang)."""
    from urllib.parse import urlparse
    v = (raw or '').strip()
    if not v or len(v) > 500 or any(ch.isspace() for ch in v):
        return None
    if '://' in v:
        p = urlparse(v)
        host = p.hostname or v
        if p.path and p.path not in ('', '/'):
            return ('endpoint', v.rstrip('/'), p.port)
        if _looks_like_ip(host):
            return ('ip', host, p.port)
        return ('host', host, p.port)
    poort = None
    hostpart = v
    if v.count(':') == 1 and not _looks_like_ip(v):
        a, b = v.split(':')
        if b.isdigit():
            hostpart, poort = a, int(b)
    if _looks_like_ip(hostpart):
        return ('ip', hostpart, poort)
    return ('host', hostpart, poort)


def _get_or_create_asset(asset_type, waarde, poort=None, opdracht_id=None):
    """Dedupliceer-of-maak een asset. Retourneert (asset, is_nieuw)."""
    dedupe = _asset_dedupe_key(asset_type, waarde, poort)
    a = db_asset.query.filter_by(dedupe_key=dedupe).first()
    if a is not None:
        return a, False
    a = db_asset(asset_type=asset_type, waarde=waarde, poort=poort,
                 dedupe_key=dedupe, opdracht_id=opdracht_id)
    db.session.add(a)
    return a, True


@findings_bp.route('/api/assets/seed-telemetry', methods=['POST'])
def seed_assets_telemetry():
    """Leid assets af uit hooked agents en lab-telemetrie (xxs/xxe/csrf/sqli/ssrf)."""
    from flask import current_app
    if current_app.config.get('WTF_CSRF_ENABLED', True):
        from flask_wtf.csrf import validate_csrf
        try:
            validate_csrf(request.headers.get('X-CSRFToken', ''))
        except Exception:
            return jsonify({'error': 'CSRF-fout'}), 403
    data = request.get_json(silent=True) or {}
    opdracht_id = data.get('opdracht_id') or None
    seen = set()
    created = {'n': 0}

    def add(raw):
        norm = _normalize_asset_input(raw)
        if not norm:
            return
        key = _asset_dedupe_key(*norm)
        if key in seen:
            return
        seen.add(key)
        _, is_new = _get_or_create_asset(norm[0], norm[1], norm[2], opdracht_id)
        if is_new:
            created['n'] += 1

    for ag in db_agents.query.all():
        add(ag.hostname)
        add(ag.ip)
    sources = [
        (db_xxs_cookies, ['ip', 'locatie']), (db_xxs_form, ['ip', 'locatie']),
        (db_xxs_hooked, ['ip']), (db_xxs_localstorage, ['ip', 'locatie']),
        (db_xxs_keylogger, ['ip', 'locatie']), (db_xxe, ['ip']),
        (db_csrf, ['ip', 'locatie']), (db_sqli, ['ip', 'doel']),
        (db_ssrf, ['ip', 'doel']),
    ]
    for model, fields in sources:
        for row in model.query.all():
            for f in fields:
                add(getattr(row, f, None))
    db.session.commit()
    return jsonify({'ok': True, 'created': created['n']})


@findings_bp.route('/api/assets/seed-findings', methods=['POST'])
def seed_assets_findings():
    """Migreer bevinding-locatie/affected_assets naar assets + anchors."""
    from flask import current_app
    if current_app.config.get('WTF_CSRF_ENABLED', True):
        from flask_wtf.csrf import validate_csrf
        try:
            validate_csrf(request.headers.get('X-CSRFToken', ''))
        except Exception:
            return jsonify({'error': 'CSRF-fout'}), 403
    data = request.get_json(silent=True) or {}
    opdracht_id = data.get('opdracht_id') or None
    created = anchored = 0
    for bev in _active_findings().all():
        raws = []
        if bev.locatie:
            raws.append(bev.locatie)
        aa = getattr(bev, 'affected_assets', '') or ''
        if aa:
            for part in aa.replace('\n', ',').replace(';', ',').split(','):
                raws.append(part.strip())
        for raw in raws:
            norm = _normalize_asset_input(raw)
            if not norm:
                continue
            a, is_new = _get_or_create_asset(norm[0], norm[1], norm[2],
                                             opdracht_id or bev.opdracht_id)
            if is_new:
                created += 1
            db.session.flush()
            exists = db_asset_anchor.query.filter_by(
                asset_id=a.id, finding_id=bev.id).first()
            if not exists:
                db.session.add(db_asset_anchor(
                    asset_id=a.id, finding_id=bev.id, relatie='affected'))
                anchored += 1
    db.session.commit()
    return jsonify({'ok': True, 'created': created, 'anchored': anchored})


_SCOPE_TYPE_MAP = {'host': 'host', 'netwerk': 'ip', 'url': 'endpoint', 'applicatie': 'app'}


@findings_bp.route('/api/assets/sync-scope', methods=['POST'])
def sync_scope():
    """Synchroniseer assets met de opdracht-/rapportscope.

    Scope-targets (db_instellingen.rapport_scope_targets) en optioneel
    db_opdracht.scope worden in-scope assets; met mark_others_out=true worden
    assets buiten de scope als out-of-scope gemarkeerd."""
    from flask import current_app
    if current_app.config.get('WTF_CSRF_ENABLED', True):
        from flask_wtf.csrf import validate_csrf
        try:
            validate_csrf(request.headers.get('X-CSRFToken', ''))
        except Exception:
            return jsonify({'error': 'CSRF-fout'}), 403
    data = request.get_json(silent=True) or {}
    opdracht_id = data.get('opdracht_id') or None
    mark_others_out = bool(data.get('mark_others_out', False))

    targets = []   # (raw, type_hint)
    for item in _get_scope_targets():
        if isinstance(item, str) and item.strip():
            targets.append((item.strip(), None))
        elif isinstance(item, dict) and item.get('target'):
            targets.append((str(item['target']).strip(),
                            _SCOPE_TYPE_MAP.get(item.get('type'))))
    if opdracht_id:
        op = db.session.get(db_opdracht, opdracht_id)
        if op and op.scope:
            for part in op.scope.replace('\n', ',').replace(';', ',').split(','):
                if part.strip():
                    targets.append((part.strip(), None))

    created = 0
    in_scope_keys = set()
    for raw, type_hint in targets:
        norm = _normalize_asset_input(raw)
        if not norm:
            continue
        asset_type = type_hint or norm[0]
        a, is_new = _get_or_create_asset(asset_type, norm[1], norm[2], opdracht_id)
        if is_new:
            created += 1
            db.session.flush()   # id + defaults (in_scope=True) toekennen
        if not a.in_scope:
            _log_change('db_asset', a.id, 'in_scope', a.in_scope, True)
            a.in_scope = True
        in_scope_keys.add(a.dedupe_key)

    marked_out = 0
    if mark_others_out and in_scope_keys:
        q = db_asset.query
        if opdracht_id:
            q = q.filter(db_asset.opdracht_id == opdracht_id)
        for a in q.all():
            if a.dedupe_key not in in_scope_keys and a.in_scope:
                _log_change('db_asset', a.id, 'in_scope', a.in_scope, False)
                a.in_scope = False
                marked_out += 1
    db.session.commit()
    return jsonify({'ok': True, 'created': created,
                    'in_scope': len(in_scope_keys), 'marked_out': marked_out})


# ── Scan-/tool-output importeren in de grafen ──────────────────────────────

# Laatste labels die op bestandsextensies lijken (geen hostnamen)
_NIET_TLD = {
    'txt', 'log', 'exe', 'dll', 'ps1', 'sh', 'py', 'json', 'xml', 'html',
    'htm', 'csv', 'md', 'conf', 'ini', 'bak', 'zip', 'gz', 'tar', 'pdf',
    'png', 'jpg', 'jpeg', 'gif', 'bin', 'dat', 'db', 'sqlite', 'yml', 'yaml',
}

_MAX_SCAN_TARGETS = 300


def _extract_targets(text):
    """Haal doelen (URL/host:poort/IP/FQDN) uit vrije scan-output. Gededupliceerd."""
    import re
    if not text:
        return []
    url_re = re.compile(r'https?://[^\s"\'<>()]+')
    hostport_re = re.compile(
        r'\b((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})\b')
    ip_re = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    fqdn_re = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')

    raws = []
    seen = set()

    def push(val):
        v = (val or '').strip().rstrip('.,);:')
        if not v or v.lower() in seen:
            return
        # FQDN met bestandsextensie-achtig laatste label overslaan
        laatste = v.rsplit('.', 1)[-1].lower()
        if '://' not in v and ':' not in v and laatste in _NIET_TLD:
            return
        seen.add(v.lower())
        raws.append(v)

    def mark(val):
        if val:
            seen.add(val.strip().lower())

    from urllib.parse import urlparse
    for m in url_re.findall(text):
        push(m)
        mark(urlparse(m).hostname)   # bare host niet nogmaals toevoegen
    for host, port in hostport_re.findall(text):
        push('{}:{}'.format(host, port))
        mark(host)
    for m in ip_re.findall(text):
        push(m)
    for m in fqdn_re.findall(text):
        push(m)
    return raws[:_MAX_SCAN_TARGETS]


def _scan_text(source, data):
    """Haal de te parseren tekst op uit paste/output-store/task-run. (tekst|None, fout|None)."""
    if source == 'paste':
        return (data.get('text') or ''), None
    if source == 'output':
        oid = data.get('output_id')
        if not oid:
            return None, 'output_id vereist'
        from meuk.flask.output_view import _resolve_output, _MAX_READ_BYTES
        path = _resolve_output(oid)
        if path is None:
            return None, 'output niet gevonden'
        with path.open('r', encoding='utf-8', errors='replace') as fh:
            return fh.read(_MAX_READ_BYTES), None
    if source == 'task':
        rid = data.get('run_id')
        if not rid:
            return None, 'run_id vereist'
        from meuk.flask import tasks
        with tasks._RUNS_LOCK:
            run = tasks._RUNS.get(rid)
            if run is None:
                return None, 'run niet gevonden'
            return '\n'.join(run.get('output') or []), None
    return None, 'ongeldige bron'


_SIGNAL_SCORE = {'critical': '9.5', 'high': '8.0', 'medium': '5.5', 'low': '3.0'}


def _sev_from_line(ln):
    """Grove severity-heuristiek uit een outputregel."""
    low = (ln or '').lower()
    if any(k in low for k in ('critical', 'rce', 'remote code', 'unauth')):
        return 'critical'
    if any(k in low for k in ('high', 'vulnerable', 'exploit')):
        return 'high'
    if 'low' in low:
        return 'low'
    return 'medium'


def _parse_scan(text):
    """Parse nmap-achtige hosts/poorten en vuln-signalen (CVE/VULNERABLE) uit output.

    Retourneert (hosts, signals):
      hosts: {host: {'ip': ip|None, 'services': [{'port','proto','service'}]}}
      signals: [{'cve'|None, 'title', 'severity', 'host'|None}]
    """
    import re
    if not text:
        return {}, []
    cve_re = re.compile(r'CVE-\d{4}-\d{4,7}', re.I)
    port_re = re.compile(r'^\s*(\d{1,5})/(tcp|udp)\s+(open(?:\|filtered)?)\s+(\S+)', re.I)
    host_re = re.compile(r'Nmap scan report for\s+([^\s()]+)(?:\s+\(([\d.]+)\))?', re.I)
    vuln_re = re.compile(r'VULNERABLE|\bexploit\b', re.I)
    hosts = {}
    signals = []
    current = None
    for ln in text.splitlines():
        hm = host_re.search(ln)
        if hm:
            current = hm.group(1)
            hosts.setdefault(current, {'ip': hm.group(2), 'services': []})
            continue
        pm = port_re.match(ln)
        if pm and current:
            hosts[current]['services'].append(
                {'port': int(pm.group(1)), 'proto': pm.group(2).lower(), 'service': pm.group(4)})
            continue
        cm = cve_re.search(ln)
        if cm:
            signals.append({'cve': cm.group(0).upper(), 'title': (ln.strip()[:200] or cm.group(0).upper()),
                            'severity': _sev_from_line(ln), 'host': current})
            continue
        if vuln_re.search(ln):
            signals.append({'cve': None, 'title': ln.strip()[:200],
                            'severity': _sev_from_line(ln), 'host': current})
    return hosts, signals


def _scope_keys():
    keys = set()
    for item in _get_scope_targets():
        raw = item.get('target') if isinstance(item, dict) else item
        n = _normalize_asset_input(raw) if raw else None
        if n:
            keys.add(_asset_dedupe_key(*n))
    return keys


@findings_bp.route('/api/scan/import', methods=['POST'])
def scan_import():
    """Importeer scan-/tool-output in beide grafen.

    Body: {source, text?|output_id?|run_id?, opdracht_id?, status?, label?,
           dry_run?, create_findings?, store_note?}.

    - hosts/poorten -> assets met service-kinderen (hiërarchie), scope-bewust
    - CVE/VULNERABLE-signalen -> vulnerability-knopen + (optioneel) bevindingen,
      geanchord aan de host-asset (die lopen zo mee in rapport/DefectDojo)
    - een scan-knoop (fact) met herkomst, geanchord aan alle assets
    - dry_run: alleen de parse teruggeven, niets aanmaken
    """
    from flask import current_app
    if current_app.config.get('WTF_CSRF_ENABLED', True):
        from flask_wtf.csrf import validate_csrf
        try:
            validate_csrf(request.headers.get('X-CSRFToken', ''))
        except Exception:
            return jsonify({'error': 'CSRF-fout'}), 403
    data = request.get_json(silent=True) or {}
    source = (data.get('source') or 'paste').strip().lower()
    text, err = _scan_text(source, data)
    if err:
        return jsonify({'error': err}), 400

    hosts, signals = _parse_scan(text)
    flat = _extract_targets(text)
    if not hosts and not flat and not signals:
        return jsonify({'ok': False, 'error': 'geen doelen/signalen in de output'}), 400

    if data.get('dry_run'):
        return jsonify({'ok': True, 'preview': True,
                        'hosts': [{'host': h, 'ip': v['ip'], 'services': v['services']}
                                  for h, v in hosts.items()],
                        'signals': signals, 'flat_targets': flat})

    opdracht_id = data.get('opdracht_id') or None
    status = data.get('status') if data.get('status') in _VALID_ASSET_STATUS else 'in_progress'
    create_findings = data.get('create_findings', True)
    store_note = data.get('store_note', True)
    label = (data.get('label') or '').strip() or 'Scan-import ({})'.format(source)
    scope = _scope_keys()

    def mkasset(atype, waarde, poort=None, parent=None, in_scope_override=None):
        a, is_new = _get_or_create_asset(atype, waarde, poort, opdracht_id)
        db.session.flush()
        in_scope = in_scope_override if in_scope_override is not None else (
            (not scope) or (a.dedupe_key in scope))
        st = status if in_scope else 'out_of_scope'
        if a.getest != st:
            _log_change('db_asset', a.id, 'getest', a.getest, st)
            a.getest = st
        a.in_scope = in_scope
        if parent and a.parent_id != parent:
            a.parent_id = parent
        return a, is_new, in_scope

    created = 0
    all_ids = []
    host_asset = {}
    for host, info in hosts.items():
        atype = 'ip' if _looks_like_ip(host) else 'host'
        a, isnew, in_scope = mkasset(atype, host)
        if isnew:
            created += 1
        host_asset[host] = a
        all_ids.append(a.id)
        for svc in info['services']:
            sv, isn, _ = mkasset('service', '{}:{}'.format(host, svc['port']),
                                 svc['port'], parent=a.id, in_scope_override=in_scope)
            if isn:
                created += 1
            sv.protocol = svc['proto']
            all_ids.append(sv.id)

    host_keys = {a.dedupe_key for a in host_asset.values()}
    for raw in flat:
        norm = _normalize_asset_input(raw)
        if not norm or _asset_dedupe_key(*norm) in host_keys:
            continue
        a, isnew, _ = mkasset(norm[0], norm[1], norm[2])
        if isnew:
            created += 1
        all_ids.append(a.id)

    findings_created = nodes_created = 0
    for sig in signals:
        ha = host_asset.get(sig['host'])
        score = _SIGNAL_SCORE.get(sig['severity'], '5.5')
        fid = None
        if create_findings:
            bev = db_bevindingen(
                naam=sig['title'][:255], ref=(sig['cve'] or ''), basescore=score,
                status='draft', locatie=(sig['host'] or ''),
                uitwerken='Automatisch afgeleid uit scan-import ({}).'.format(source),
                opdracht_id=opdracht_id)
            db.session.add(bev)
            db.session.flush()
            fid = bev.id
            findings_created += 1
            if ha is not None:
                db.session.add(db_asset_anchor(asset_id=ha.id, finding_id=bev.id, relatie='affected'))
        vn = db_explore_node(node_type='vulnerability', titel=sig['title'][:255],
                             status='done', prioriteit=7, finding_id=fid, opdracht_id=opdracht_id)
        db.session.add(vn)
        db.session.flush()
        nodes_created += 1
        if ha is not None:
            db.session.add(db_explore_asset_anchor(node_id=vn.id, asset_id=ha.id))

    prov = 'Scan-import · bron={}'.format(source)
    if data.get('output_id'):
        prov += ' · output={}'.format(data['output_id'])
    if data.get('run_id'):
        prov += ' · run={}'.format(data['run_id'])
    prov += ' · {} hosts, {} signalen'.format(len(hosts), len(signals))
    scan_node = db_explore_node(node_type='fact', titel=label, status='done',
                                prioriteit=5, omschrijving=prov, opdracht_id=opdracht_id)
    db.session.add(scan_node)
    db.session.flush()
    for aid in dict.fromkeys(all_ids):
        db.session.add(db_explore_asset_anchor(node_id=scan_node.id, asset_id=aid))

    if store_note and text.strip():
        db.session.add(db_notes(naam='Scan-output: ' + label, uitwerken=text[:20000], rapport=False))

    db.session.commit()
    return jsonify({'ok': True, 'assets_created': created,
                    'assets_total': len(set(all_ids)),
                    'findings_created': findings_created,
                    'nodes_created': nodes_created,
                    'scan_node_id': scan_node.id})


@findings_bp.route('/dashboard/assets', methods=['GET'])
def assets_dashboard():
    """Pagina met de interactieve asset-coverage-graaf."""
    return render_template('assets_graph.html', title='Assets — dekkingsgraaf',
                           scope_targets=_get_scope_targets())


@findings_bp.route('/api/assets/graph', methods=['GET'])
def api_assets_graph():
    opdracht_id = request.args.get('opdracht_id', type=int)
    return jsonify(build_asset_graph(opdracht_id))


@findings_bp.route('/api/assets', methods=['POST'])
def create_asset():
    """Maak (of hergebruik) een losstaande asset — optioneel met ouder/opdracht."""
    from flask import current_app
    if current_app.config.get('WTF_CSRF_ENABLED', True):
        from flask_wtf.csrf import validate_csrf
        try:
            validate_csrf(request.headers.get('X-CSRFToken', ''))
        except Exception:
            return jsonify({'error': 'CSRF-fout'}), 403
    data = request.get_json(silent=True) or {}
    waarde = (data.get('waarde') or '').strip()
    if not waarde:
        return jsonify({'error': 'waarde is verplicht'}), 400
    asset_type = (data.get('asset_type') or 'host').strip().lower()
    poort = data.get('poort') or None
    try:
        poort = int(poort) if poort not in (None, '') else None
    except (TypeError, ValueError):
        poort = None
    dedupe = _asset_dedupe_key(asset_type, waarde, poort)
    asset = db_asset.query.filter_by(dedupe_key=dedupe).first()
    if asset is None:
        asset = db_asset(
            asset_type=asset_type, waarde=waarde, poort=poort,
            protocol=(data.get('protocol') or '').strip().lower(),
            dedupe_key=dedupe,
            opdracht_id=data.get('opdracht_id') or None,
            parent_id=data.get('parent_id') or None,
        )
        db.session.add(asset)
        db.session.commit()
    return jsonify({'ok': True, 'asset': _asset_dict(asset)})


def _would_cycle(asset_id, new_parent_id, by_id):
    """True als new_parent_id onder asset_id hangt (zou een cyclus maken)."""
    seen = set()
    cur = by_id.get(new_parent_id)
    while cur is not None and cur.id not in seen:
        if cur.id == asset_id:
            return True
        seen.add(cur.id)
        cur = by_id.get(cur.parent_id)
    return False


@findings_bp.route('/api/assets/<int:asset_id>', methods=['POST'])
def update_asset(asset_id):
    """Wijzig coverage-status, scope, ouder of notitie van een asset."""
    from flask import current_app
    if current_app.config.get('WTF_CSRF_ENABLED', True):
        from flask_wtf.csrf import validate_csrf
        try:
            validate_csrf(request.headers.get('X-CSRFToken', ''))
        except Exception:
            return jsonify({'error': 'CSRF-fout'}), 403
    a = db.session.get(db_asset, asset_id)
    if not a:
        return jsonify({'error': 'asset niet gevonden'}), 404
    data = request.get_json(silent=True) or {}
    if 'getest' in data:
        if data['getest'] not in _VALID_ASSET_STATUS:
            return jsonify({'error': 'ongeldige status'}), 400
        if a.getest != data['getest']:
            _log_change('db_asset', a.id, 'getest', a.getest, data['getest'])
        a.getest = data['getest']
    if 'in_scope' in data:
        nieuw = bool(data['in_scope'])
        if bool(a.in_scope) != nieuw:
            _log_change('db_asset', a.id, 'in_scope', a.in_scope, nieuw)
        a.in_scope = nieuw
    if 'notitie' in data:
        a.notitie = str(data['notitie'])[:2000]
    if 'parent_id' in data:
        pid = data['parent_id'] or None
        if pid:
            try:
                pid = int(pid)
            except (TypeError, ValueError):
                return jsonify({'error': 'ongeldige parent_id'}), 400
            if pid == asset_id:
                return jsonify({'error': 'asset kan niet zijn eigen ouder zijn'}), 400
            by_id = {x.id: x for x in db_asset.query.all()}
            if _would_cycle(asset_id, pid, by_id):
                return jsonify({'error': 'dit zou een cyclus maken'}), 400
            if a.parent_id != pid:
                _log_change('db_asset', a.id, 'parent_id', a.parent_id, pid)
            a.parent_id = pid
        else:
            if a.parent_id is not None:
                _log_change('db_asset', a.id, 'parent_id', a.parent_id, None)
            a.parent_id = None
    db.session.commit()
    return jsonify({'ok': True, 'asset': _asset_dict(a)})


@findings_bp.route('/api/assets/<int:asset_id>', methods=['DELETE'])
def delete_asset(asset_id):
    """Verwijder een asset (anchors cascaden; kinderen worden losgekoppeld)."""
    from flask import current_app
    if current_app.config.get('WTF_CSRF_ENABLED', True):
        from flask_wtf.csrf import validate_csrf
        try:
            validate_csrf(request.headers.get('X-CSRFToken', ''))
        except Exception:
            return jsonify({'error': 'CSRF-fout'}), 403
    a = db.session.get(db_asset, asset_id)
    if not a:
        return jsonify({'error': 'asset niet gevonden'}), 404
    for kind in list(a.kinderen):
        kind.parent_id = None
    db.session.delete(a)
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
    # Beknopte impact/aanbeveling afleiden uit de lange teksten
    _vul_kort_velden(tmpl, overschrijf=True)
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
            if bev and not bev.deleted_at:
                bev.deleted_at = nu_utc()
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
    q = _active_findings()

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
            'sla_target': str(_sla_doeldatum(bev, tmpl)),
            'sla_overdue': bool(
                (bev.remediation_target_date or _sla_doeldatum(bev, tmpl)) < datetime.date.today()
                and (bev.remediation_status or 'open') not in _REM_AFGEHANDELD),
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
    from flask import current_app
    if current_app.config.get('WTF_CSRF_ENABLED', True):
        from flask_wtf.csrf import validate_csrf
        try:
            validate_csrf(request.headers.get('X-CSRFToken', ''))
        except Exception:
            return jsonify({'ok': False, 'error': 'CSRF-fout'}), 403
    rel = db.session.get(db_finding_related, relation_id)
    if not rel:
        return jsonify({'ok': False, 'error': 'not found'}), 404
    db.session.delete(rel)
    db.session.commit()
    return jsonify({'ok': True})


# ---------------------------------------------------------------------------
# Changelog: GET /api/changelog
# ---------------------------------------------------------------------------

@findings_bp.route('/dashboard/changelog')
def changelog_overzicht():
    return render_template('changelog.html')


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


# ---------------------------------------------------------------------------
# Duplicaten: detecteren + samenvoegen (merge)
# ---------------------------------------------------------------------------

def _dedupe_sleutel(bev):
    """Sleutel om duplicaten te groeperen: ref (indien gezet) of naam, + locatie."""
    kern = (bev.ref or '').strip() or (bev.naam or '').strip().lower()
    return (kern, (bev.locatie or '').strip().lower())


@findings_bp.route('/api/findings/duplicates', methods=['GET'])
def findings_duplicates():
    require_dashboard_access()
    groepen = {}
    for bev in _active_findings().all():
        k = _dedupe_sleutel(bev)
        if not k[0]:
            continue
        groepen.setdefault(k, []).append(bev)
    out = []
    for (kern, loc), bevs in groepen.items():
        if len(bevs) < 2:
            continue
        out.append({
            'sleutel': kern + ('@' + loc if loc else ''),
            'findings': [{'id': b.id, 'naam': b.naam or '', 'locatie': b.locatie or '',
                          'basescore': b.basescore or '', 'status': b.status or 'draft'}
                         for b in sorted(bevs, key=lambda x: x.id)],
        })
    return jsonify({'ok': True, 'groups': out})


@findings_bp.route('/api/findings/merge', methods=['POST'])
def findings_merge():
    require_dashboard_access()
    from flask import current_app
    if current_app.config.get('WTF_CSRF_ENABLED', True):
        from flask_wtf.csrf import validate_csrf
        try:
            validate_csrf(request.headers.get('X-CSRFToken', ''))
        except Exception:
            return jsonify({'ok': False, 'error': 'CSRF-fout'}), 403
    data = request.get_json(silent=True) or {}
    try:
        keep_id = int(data.get('keep_id'))
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'keep_id ontbreekt'}), 400
    ids = [int(x) for x in (data.get('ids') or []) if str(x).isdigit() and int(x) != keep_id]
    keep = db.session.get(db_bevindingen, keep_id)
    if not keep or keep.deleted_at is not None:
        return jsonify({'ok': False, 'error': 'doelbevinding niet gevonden'}), 404

    keep_assets = {a.asset_id for a in db_asset_anchor.query.filter_by(finding_id=keep_id).all()}
    samengevoegd = 0
    for mid in ids:
        m = db.session.get(db_bevindingen, mid)
        if not m or m.deleted_at is not None:
            continue
        # Bewijs herkoppelen
        db_evidence.query.filter_by(finding_id=mid).update({'finding_id': keep_id})
        # Asset-anchors herkoppelen (dubbele overslaan)
        for a in db_asset_anchor.query.filter_by(finding_id=mid).all():
            if a.asset_id in keep_assets:
                db.session.delete(a)
            else:
                a.finding_id = keep_id
                keep_assets.add(a.asset_id)
        # Relaties herkoppelen; self-/lege relaties verwijderen
        for r in db_finding_related.query.filter(
                db.or_(db_finding_related.finding_id == mid,
                       db_finding_related.related_id == mid)).all():
            if r.finding_id == mid:
                r.finding_id = keep_id
            if r.related_id == mid:
                r.related_id = keep_id
            if r.finding_id == r.related_id:
                db.session.delete(r)
        # Uitwerking samenvoegen
        if (m.uitwerken or '').strip():
            keep.uitwerken = ((keep.uitwerken or '').rstrip()
                              + '\n\n--- Samengevoegd uit #{} ---\n'.format(mid)
                              + m.uitwerken)
        m.deleted_at = nu_utc()
        _log_change('db_bevinding', mid, 'merged_into', '', str(keep_id))
        samengevoegd += 1
    db.session.commit()
    return jsonify({'ok': True, 'keep_id': keep_id, 'merged': samengevoegd})
