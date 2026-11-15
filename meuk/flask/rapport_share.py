"""Rapport delen: één opdracht/engagement exporteren naar een self-contained
.zip (teksten, bevindingen, evidence, screenshots, notities, gekoppelde
standaardbevindingen) en op een andere installatie importeren om verder te
werken.

Ontwerp-uitgangspunten
----------------------
* Eenheid van delen = één ``db_opdracht`` (het rapport) met al zijn gekoppelde
  data.
* Export sluit operator-geheimen uit (PDF-wachtwoorden, DefectDojo-credentials).
* Export neemt alléén de screenshots mee waar dit rapport naar verwijst
  (``\\plaatje{...}``), niet de hele screenshot-map — zo lekt er geen materiaal
  van andere engagements.
* Import schrijft bestanden naar zélf-afgeleide, opgeschoonde paden en leest de
  inhoud via de in het manifest gedeclareerde namen; er wordt nooit op een
  zip-pad geëxtraheerd (zip-slip onmogelijk). Groepering, aantal leden en
  (on)gecomprimeerde grootte zijn begrensd (zip-bom-bescherming).
* Import-modus ``new`` maakt een verse opdracht (niets wordt overschreven);
  ``merge`` voegt bevindingen/notities/evidence/screenshots toe aan een
  bestaande opdracht en laat de teksten van die opdracht ongemoeid.
"""

import os
import re
import io
import json
import uuid
import zipfile
import hashlib
import datetime as _dt
from pathlib import Path

from flask import Blueprint, request, jsonify, send_file, flash, redirect, url_for
from sqlalchemy import Date, DateTime, Boolean

from meuk.flask.models import (
    db, db_opdracht, db_opdracht_config, db_bevindingen,
    db_bevindingen_templates, db_evidence, db_notes, _PROJECT_CONFIG_FIELDS,
)
from meuk.flask.security import require_dashboard_access
from meuk.flask import project as _project

share_bp = Blueprint('rapport_share', __name__)

BUNDLE_FORMAT = 'incompetentbastard-rapport'
BUNDLE_VERSION = 1

# Limieten (zip-bom / resource-bescherming).
_MAX_BUNDLE_SIZE = 500 * 1024 * 1024      # .zip zelf
_MAX_UNCOMPRESSED = 1024 * 1024 * 1024    # som van uitgepakte leden
_MAX_MEMBER_SIZE = 60 * 1024 * 1024       # één lid
_MAX_MEMBERS = 5000

_SCREENSHOT_DIR = Path('raw/screenshots')
_LAKKEN_DIR = _SCREENSHOT_DIR / 'lakken'
_EVIDENCE_DIR = Path(os.path.join(os.path.dirname(__file__), 'db', 'evidence'))

_IMAGE_SUFFIXES = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.svg'}
_EVIDENCE_SUFFIXES = {
    '.png', '.jpg', '.jpeg', '.gif', '.webp', '.pdf', '.txt', '.html',
    '.csv', '.json', '.xml', '.zip', '.log', '.bin',
}

# Geheimen die nooit in een deelbare bundel horen.
_SECRET_CONFIG_FIELDS = {
    'rapport_pdf_password', 'rapport_pdf_owner_password',
    'dd_url', 'dd_api_key', 'dd_product_id', 'dd_engagement_id',
    'dd_verify_ssl', 'dd_auto_push',
}
_EXPORT_CONFIG_FIELDS = [f for f in _PROJECT_CONFIG_FIELDS if f not in _SECRET_CONFIG_FIELDS]

_PLAATJE_RE = re.compile(r'\\plaatje\{([^}]+)\}')


# ── Serialisatie-helpers ────────────────────────────────────────────────────

def _col_kind(model, name):
    col = model.__table__.columns.get(name)
    if col is None:
        return 'other'
    t = col.type
    if isinstance(t, DateTime):
        return 'datetime'
    if isinstance(t, Date):
        return 'date'
    if isinstance(t, Boolean):
        return 'bool'
    return 'other'


def _ser(model, name, val):
    if val is None:
        return None
    if _col_kind(model, name) in ('datetime', 'date'):
        try:
            return val.isoformat()
        except AttributeError:
            return None
    return val


def _parse(model, name, val):
    if val is None:
        return None
    kind = _col_kind(model, name)
    try:
        if kind == 'datetime':
            return _dt.datetime.fromisoformat(val)
        if kind == 'date':
            return _dt.date.fromisoformat(val)
        if kind == 'bool':
            return bool(val)
    except (ValueError, TypeError):
        return None
    return val


def _model_cols(model, exclude=()):
    return [c.name for c in model.__table__.columns if c.name not in exclude]


def _sha_bytes(blob):
    return hashlib.sha256(blob).hexdigest()


def _sha_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def _plaatjes_in(*texts):
    names = set()
    for t in texts:
        if t:
            for m in _PLAATJE_RE.finditer(str(t)):
                names.add(m.group(1).strip())
    return names


# ── Export ──────────────────────────────────────────────────────────────────

def _opdracht_findings(opdracht_id):
    q = _project.apply_scope(db_bevindingen.query, db_bevindingen.opdracht_id, opdracht_id)
    return q.filter(db_bevindingen.deleted_at.is_(None)).order_by(db_bevindingen.id.asc()).all()


def _opdracht_notes(opdracht_id):
    q = _project.apply_scope(db_notes.query, db_notes.opdracht_id, opdracht_id)
    return q.order_by(db_notes.volgorde.asc(), db_notes.id.asc()).all()


def _build_bundle(opdracht):
    """Bouw (manifest-dict, [(arcname, bytes)]) voor één opdracht."""
    cfg = _project.get_or_create_config(opdracht)
    findings = _opdracht_findings(opdracht.id)
    notes = _opdracht_notes(opdracht.id)

    fcols = _model_cols(db_bevindingen, exclude=('id', 'opdracht_id'))
    ecols = _model_cols(db_evidence, exclude=('id', 'finding_id'))
    tcols = _model_cols(db_bevindingen_templates)

    files = []           # (arcname, bytes)
    manifest = {
        'format': BUNDLE_FORMAT,
        'version': BUNDLE_VERSION,
        'exported_at': _dt.datetime.now(_dt.timezone.utc).isoformat(),
        'opdracht': {
            k: _ser(db_opdracht, k, getattr(opdracht, k))
            for k in ('naam', 'klant', 'scope', 'roe', 'start_datum', 'eind_datum', 'status')
        },
        'config': {},
        'templates': [],
        'findings': [],
        'notes': [],
        'screenshots': [],
    }

    # Config (zonder geheimen).
    if cfg is not None:
        manifest['config'] = {
            f: _ser(db_opdracht_config, f, getattr(cfg, f, None)) for f in _EXPORT_CONFIG_FIELDS
        }

    # Tekstbronnen voor screenshot-verzameling.
    text_sources = []
    if cfg is not None:
        for f in _EXPORT_CONFIG_FIELDS:
            v = getattr(cfg, f, None)
            if isinstance(v, str):
                text_sources.append(v)

    # Bevindingen + evidence.
    referenced_templates = {}  # old_id(str) -> template-object
    for idx, bev in enumerate(findings):
        fd = {c: _ser(db_bevindingen, c, getattr(bev, c)) for c in fcols}
        fd['_idx'] = idx
        text_sources.extend(str(getattr(bev, c) or '') for c in
                            ('invoegen', 'uitwerken', 'beschrijving_override',
                             'impact_override', 'aanbeveling_override',
                             'impact_kort_override', 'aanbeveling_kort_override'))
        # Gekoppelde standaardbevinding (ref = template-id).
        ref = (bev.ref or '').strip()
        if ref and ref.isdigit() and ref not in referenced_templates:
            tmpl = db_bevindingen_templates.query.filter_by(id=int(ref)).first()
            if tmpl is not None:
                referenced_templates[ref] = tmpl
        # Evidence.
        ev_list = []
        for ev in getattr(bev, 'evidence_files', []) or []:
            src = _EVIDENCE_DIR / str(bev.id) / ev.filename
            if not src.is_file():
                continue
            arc = 'evidence/{}/{}'.format(idx, ev.filename)
            try:
                with open(src, 'rb') as fh:
                    files.append((arc, fh.read()))
            except OSError:
                continue
            em = {c: _ser(db_evidence, c, getattr(ev, c)) for c in ecols}
            em['file'] = arc
            ev_list.append(em)
        fd['evidence'] = ev_list
        manifest['findings'].append(fd)

    # Standaardbevindingen (templates) die bevindingen gebruiken.
    for old_id, tmpl in referenced_templates.items():
        td = {c: _ser(db_bevindingen_templates, c, getattr(tmpl, c)) for c in tcols}
        text_sources.append(str(getattr(tmpl, 'nlbeschrijving', '') or ''))
        text_sources.append(str(getattr(tmpl, 'enbeschrijving', '') or ''))
        manifest['templates'].append(td)

    # Notities.
    for n in notes:
        manifest['notes'].append({
            'naam': n.naam, 'uitwerken': n.uitwerken,
            'rapport': bool(n.rapport), 'latex_raw': bool(n.latex_raw),
            'volgorde': n.volgorde or 0,
        })
        text_sources.append(str(n.uitwerken or ''))

    # Screenshots: alleen degene waar het rapport naar verwijst.
    try:
        gecontroleerd = set(json.loads(getattr(cfg, 'rapport_lak_gecontroleerd', '[]') or '[]'))
    except (ValueError, TypeError):
        gecontroleerd = set()
    names = _plaatjes_in(*text_sources) | set(n for n in gecontroleerd if isinstance(n, str))
    for name in sorted(names):
        safe = os.path.basename(name)
        if safe != name or not safe:
            continue
        src = _SCREENSHOT_DIR / safe
        if not src.is_file():
            continue
        try:
            with open(src, 'rb') as fh:
                blob = fh.read()
        except OSError:
            continue
        files.append(('screenshots/' + safe, blob))
        entry = {'name': safe, 'sha256': _sha_bytes(blob),
                 'redacted': False, 'gecontroleerd': safe in gecontroleerd}
        lak = _LAKKEN_DIR / safe
        if lak.is_file():
            try:
                with open(lak, 'rb') as fh:
                    files.append(('screenshots/lakken/' + safe, fh.read()))
                entry['redacted'] = True
            except OSError:
                pass
        manifest['screenshots'].append(entry)

    return manifest, files


@share_bp.route('/dashboard/report/export', methods=['GET'])
def export_opdracht():
    require_dashboard_access()
    oid = _project.resolve_opdracht_id(request.args.get('opdracht_id', type=int))
    opdracht = db.session.get(db_opdracht, oid) if oid else None
    if opdracht is None:
        return jsonify({'error': 'opdracht niet gevonden'}), 404

    manifest, files = _build_bundle(opdracht)

    readme = (
        'Incompetent Bastard — rapportbundel\n'
        '===================================\n\n'
        'Dit bestand bevat één engagement/opdracht (teksten, bevindingen,\n'
        'evidence, screenshots en notities) om op een andere installatie verder\n'
        'aan het rapport te werken. Importeer via het tabblad Delen.\n\n'
        'LET OP: dit materiaal kan vertrouwelijke bevindingen bevatten. Deel het\n'
        'alleen via vertrouwde kanalen met gemachtigde ontvangers.\n'
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('manifest.json', json.dumps(manifest, ensure_ascii=False, indent=2))
        zf.writestr('README.txt', readme)
        for arc, blob in files:
            zf.writestr(arc, blob)
    buf.seek(0)

    klant = re.sub(r'[^A-Za-z0-9_-]+', '-', (opdracht.klant or opdracht.naam or 'rapport')).strip('-') or 'rapport'
    stamp = _dt.date.today().isoformat()
    fname = 'rapport_{}_{}_{}.zip'.format(klant, opdracht.id, stamp)
    return send_file(buf, mimetype='application/zip', as_attachment=True, download_name=fname)


# ── Import ──────────────────────────────────────────────────────────────────

def _safe_media_name(name, suffixes):
    """Opgeschoonde basisnaam met toegestaan achtervoegsel, of None."""
    base = os.path.basename(str(name or ''))
    if not base or base in ('.', '..'):
        return None
    ext = os.path.splitext(base)[1].lower()
    if ext not in suffixes:
        return None
    # Alleen een beperkte tekenset toestaan.
    if not re.match(r'^[A-Za-z0-9._-]+$', base):
        return None
    return base


def _new_screenshot_name(base):
    stem, ext = os.path.splitext(base)
    return '{}_{}{}'.format(stem[:40].strip('._-') or 'img', uuid.uuid4().hex[:8], ext)


def _apply_renames(text, rename_map):
    if not text or not rename_map:
        return text
    for old, new in rename_map.items():
        if old != new:
            text = text.replace('\\plaatje{' + old + '}', '\\plaatje{' + new + '}')
    return text


def _read_member(zf, arcname, budget):
    """Lees één lid; handhaaf de grootte-budgetten (zip-bom)."""
    try:
        info = zf.getinfo(arcname)
    except KeyError:
        return None, budget
    if info.file_size > _MAX_MEMBER_SIZE:
        raise ValueError('bestand te groot in bundel: ' + arcname)
    if info.file_size > budget:
        raise ValueError('bundel te groot (uitgepakt)')
    data = zf.read(arcname)
    return data, budget - len(data)


@share_bp.route('/dashboard/report/import', methods=['POST'])
def import_opdracht():
    require_dashboard_access()
    up = request.files.get('file')
    if up is None:
        return jsonify({'error': 'geen bestand meegegeven'}), 400

    raw = up.read()
    if not raw:
        return jsonify({'error': 'leeg bestand'}), 400
    if len(raw) > _MAX_BUNDLE_SIZE:
        return jsonify({'error': 'bundel te groot (max 500 MB)'}), 413

    mode = (request.form.get('mode') or 'new').strip()
    if mode not in ('new', 'merge'):
        return jsonify({'error': 'onbekende modus'}), 400

    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile:
        return jsonify({'error': 'ongeldig zip-bestand'}), 400

    with zf:
        if len(zf.infolist()) > _MAX_MEMBERS:
            return jsonify({'error': 'te veel bestanden in bundel'}), 400
        try:
            manifest = json.loads(zf.read('manifest.json').decode('utf-8'))
        except (KeyError, ValueError, UnicodeDecodeError):
            return jsonify({'error': 'manifest ontbreekt of is ongeldig'}), 400
        if manifest.get('format') != BUNDLE_FORMAT:
            return jsonify({'error': 'onbekend bundelformaat'}), 400
        if int(manifest.get('version', 0)) > BUNDLE_VERSION:
            return jsonify({'error': 'bundel is van een nieuwere versie'}), 400

        if mode == 'merge':
            target_id = request.form.get('target_opdracht_id', type=int)
            opdracht = db.session.get(db_opdracht, target_id) if target_id else None
            if opdracht is None:
                return jsonify({'error': 'doel-opdracht niet gevonden'}), 404
        else:
            o_meta = manifest.get('opdracht', {}) or {}
            opdracht = db_opdracht(
                naam=(o_meta.get('naam') or 'Geïmporteerd rapport')[:255],
                klant=(o_meta.get('klant') or '')[:255],
                scope=o_meta.get('scope') or '',
                roe=o_meta.get('roe') or '',
                start_datum=_parse(db_opdracht, 'start_datum', o_meta.get('start_datum')),
                eind_datum=_parse(db_opdracht, 'eind_datum', o_meta.get('eind_datum')),
                status=(o_meta.get('status') or 'gepland')[:20],
            )
            db.session.add(opdracht)
            db.session.flush()  # id beschikbaar

        counts = {'findings': 0, 'notes': 0, 'evidence': 0, 'screenshots': 0, 'templates': 0}
        budget = _MAX_UNCOMPRESSED

        try:
            # 1) Screenshots eerst → rename-map (bij naam-botsing met andere inhoud).
            rename_map = {}
            final_gecontroleerd = set()
            _SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
            for s in manifest.get('screenshots', []):
                orig = str(s.get('name') or '')
                safe = _safe_media_name(orig, _IMAGE_SUFFIXES)
                if not safe:
                    continue
                data, budget = _read_member(zf, 'screenshots/' + orig, budget)
                if data is None:
                    continue
                dest = _SCREENSHOT_DIR / safe
                final = safe
                if dest.is_file():
                    if _sha_file(dest) == _sha_bytes(data):
                        final = safe  # identiek: hergebruik
                    else:
                        final = _new_screenshot_name(safe)
                        with open(_SCREENSHOT_DIR / final, 'wb') as out:
                            out.write(data)
                        counts['screenshots'] += 1
                else:
                    with open(dest, 'wb') as out:
                        out.write(data)
                    counts['screenshots'] += 1
                if final != orig:
                    rename_map[orig] = final
                # Gelakte kopie.
                if s.get('redacted'):
                    ldata, budget = _read_member(zf, 'screenshots/lakken/' + orig, budget)
                    if ldata is not None:
                        _LAKKEN_DIR.mkdir(parents=True, exist_ok=True)
                        with open(_LAKKEN_DIR / final, 'wb') as out:
                            out.write(ldata)
                if s.get('gecontroleerd'):
                    final_gecontroleerd.add(final)

            # 2) Config (alleen in 'new'-modus; 'merge' laat teksten ongemoeid).
            cfg = _project.get_or_create_config(opdracht)
            if mode == 'new' and cfg is not None:
                for f, v in (manifest.get('config') or {}).items():
                    if f not in _EXPORT_CONFIG_FIELDS:
                        continue
                    pv = _parse(db_opdracht_config, f, v)
                    if isinstance(pv, str):
                        pv = _apply_renames(pv, rename_map)
                    setattr(cfg, f, pv)
                # Lak-gecontroleerd samenvoegen met de (eventueel) hernoemde namen.
                if final_gecontroleerd:
                    cfg.rapport_lak_gecontroleerd = json.dumps(sorted(final_gecontroleerd))
            elif mode == 'merge' and cfg is not None and final_gecontroleerd:
                try:
                    cur = set(json.loads(cfg.rapport_lak_gecontroleerd or '[]'))
                except (ValueError, TypeError):
                    cur = set()
                cfg.rapport_lak_gecontroleerd = json.dumps(sorted(cur | final_gecontroleerd))

            # 3) Standaardbevindingen (templates) → id-map.
            tmpl_map = {}  # old_id(str) -> new_id(int)
            for td in manifest.get('templates', []):
                old_id = str(td.get('id'))
                titel = td.get('titel') or ''
                existing = db_bevindingen_templates.query.filter_by(titel=titel).first() if titel else None
                if existing is not None:
                    tmpl_map[old_id] = existing.id
                    continue
                nt = db_bevindingen_templates()
                for c in _model_cols(db_bevindingen_templates, exclude=('id',)):
                    if c in td:
                        setattr(nt, c, _parse(db_bevindingen_templates, c, td.get(c)))
                db.session.add(nt)
                db.session.flush()
                tmpl_map[old_id] = nt.id
                counts['templates'] += 1

            # 4) Bevindingen + evidence.
            fcols = _model_cols(db_bevindingen, exclude=('id', 'opdracht_id'))
            text_fields = {'invoegen', 'uitwerken', 'beschrijving_override',
                           'impact_override', 'aanbeveling_override',
                           'impact_kort_override', 'aanbeveling_kort_override'}
            for fd in manifest.get('findings', []):
                bev = db_bevindingen(opdracht_id=opdracht.id)
                for c in fcols:
                    if c not in fd:
                        continue
                    val = _parse(db_bevindingen, c, fd.get(c))
                    if c in text_fields and isinstance(val, str):
                        val = _apply_renames(val, rename_map)
                    setattr(bev, c, val)
                # ref → hernoemde template-id.
                ref = (fd.get('ref') or '').strip()
                if ref in tmpl_map:
                    bev.ref = str(tmpl_map[ref])
                db.session.add(bev)
                db.session.flush()
                counts['findings'] += 1
                # Evidence-bestanden.
                for em in fd.get('evidence', []) or []:
                    arc = em.get('file') or ''
                    safe = _safe_media_name(em.get('filename') or os.path.basename(arc), _EVIDENCE_SUFFIXES)
                    if not safe or not arc.startswith('evidence/'):
                        continue
                    data, budget = _read_member(zf, arc, budget)
                    if data is None:
                        continue
                    dest_dir = _EVIDENCE_DIR / str(bev.id)
                    dest_dir.mkdir(parents=True, exist_ok=True)
                    with open(dest_dir / safe, 'wb') as out:
                        out.write(data)
                    ev = db_evidence(finding_id=bev.id, filename=safe)
                    for c in _model_cols(db_evidence, exclude=('id', 'finding_id', 'filename')):
                        if c in em:
                            setattr(ev, c, _parse(db_evidence, c, em.get(c)))
                    ev.sha256 = _sha_bytes(data)
                    db.session.add(ev)
                    counts['evidence'] += 1

            # 5) Notities.
            base_order = 0
            if mode == 'merge':
                existing_notes = _opdracht_notes(opdracht.id)
                base_order = (existing_notes[-1].volgorde or 0) + 1 if existing_notes else 0
            for i, n in enumerate(manifest.get('notes', [])):
                db.session.add(db_notes(
                    opdracht_id=opdracht.id,
                    naam=(n.get('naam') or '')[:255],
                    uitwerken=_apply_renames(n.get('uitwerken') or '', rename_map),
                    rapport=bool(n.get('rapport')),
                    latex_raw=bool(n.get('latex_raw')),
                    volgorde=base_order + (n.get('volgorde') or i),
                ))
                counts['notes'] += 1

            db.session.commit()
        except ValueError as exc:
            db.session.rollback()
            return jsonify({'error': str(exc)}), 400
        except Exception:
            db.session.rollback()
            return jsonify({'error': 'import mislukt'}), 500

    return jsonify({
        'ok': True,
        'mode': mode,
        'opdracht_id': opdracht.id,
        'naam': opdracht.naam,
        'counts': counts,
    })
