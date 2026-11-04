"""Verrijk de bevindingen-templates met de OWASP Top 10 (2025) CWE-catalogus.

Leest een SQLite-catalogus (tabel `library` met JSON-kolom `data`) en upsert
deze als `db_bevindingen_templates`. Upsert-sleutel: (cwe, owasp_2025).

Verrijkingsbeleid (standaard):
  - niet-bestaande template -> aanmaken met alle velden
  - bestaande template     -> alleen lege velden invullen; referenties samenvoegen
    (bestaande, met de hand gecureerde teksten worden niet overschreven)
"""

import json
import re
import sqlite3

from meuk.flask.models import db, db_bevindingen_templates

# OWASP Top 10 2025 code -> interne nummer-string ('A01:2025' -> '1')
_OWASP_2025_NUMS = {
    'A01:2025': '1', 'A02:2025': '2', 'A03:2025': '3', 'A04:2025': '4', 'A05:2025': '5',
    'A06:2025': '6', 'A07:2025': '7', 'A08:2025': '8', 'A09:2025': '9', 'A10:2025': '10',
}


def _cwe_num(val):
    """'CWE-5' / 'CWE-1004' -> '5' / '1004'."""
    if not val:
        return ''
    m = re.search(r'(\d+)', str(val))
    return m.group(1) if m else ''


def _owasp_2025_num(val):
    """Eerste OWASP-2025-code uit de JSON -> interne nummer-string."""
    if isinstance(val, list) and val:
        code = str(val[0])
    else:
        code = str(val or '')
    # 'A02:2025 Security Misconfiguration' -> 'A02:2025'
    m = re.search(r'A\d{2}:2025', code)
    return _OWASP_2025_NUMS.get(m.group(0), '') if m else ''


def _merge_references(bestaand, nieuw):
    """Voeg referentie-URL's samen zonder dubbelen, volgorde behouden."""
    def _lines(t):
        return [x.strip() for x in (t or '').splitlines() if x.strip()]
    seen = []
    for line in _lines(bestaand) + _lines(nieuw):
        if line not in seen:
            seen.append(line)
    return '\n'.join(seen)


def _map_record(d):
    """Zet een library.data-JSON-record om naar template-veldwaarden."""
    return {
        'titel': (d.get('title_nl') or d.get('title') or '').strip()[:255],
        'bevtype': (d.get('cwe_kind') or 'CWE')[:255],
        'cwe': _cwe_num(d.get('cwe'))[:5],
        'owasp_2025': _owasp_2025_num(d.get('owasp_2025') or d.get('category')),
        'cvss': (d.get('cvss_vector') or '')[:255],
        'basescore': (str(d.get('cvss_score')) if d.get('cvss_score') is not None else '')[:10],
        'nlbeschrijving': d.get('definition_nl') or d.get('description') or '',
        'nlimpact': d.get('impact_nl') or d.get('impact') or '',
        'nlaanbeveling': d.get('recommendation_nl') or d.get('recommendation') or '',
        'enbeschrijving': d.get('source_definition_en') or '',
        'enimpact': d.get('source_impact_en') or '',
        'enaanbeveling': d.get('source_recommendation_en') or '',
        'referenties': d.get('references') or '',
    }


# Velden die bij 'enrich' alleen worden ingevuld als ze leeg zijn
_FILL_IF_EMPTY = (
    'bevtype', 'cvss', 'basescore',
    'nlbeschrijving', 'nlimpact', 'nlaanbeveling',
    'enbeschrijving', 'enimpact', 'enaanbeveling',
)


def _load_records(sqlite_path):
    """Lees alle JSON-records uit de library-tabel (alleen-lezen)."""
    con = sqlite3.connect('file:{}?mode=ro'.format(sqlite_path), uri=True)
    try:
        rows = con.execute('SELECT data FROM library').fetchall()
    finally:
        con.close()
    records = []
    for (raw,) in rows:
        try:
            records.append(json.loads(raw))
        except (ValueError, TypeError):
            continue
    return records


def import_owasp2025(sqlite_path, enrich=True):
    """Importeer/verrijk templates uit de OWASP-2025 SQLite.

    Returns een dict met statistieken: created, enriched, skipped, total.
    """
    records = _load_records(sqlite_path)
    created = enriched = skipped = 0

    for d in records:
        vals = _map_record(d)
        if not vals['titel'] or not vals['cwe']:
            skipped += 1
            continue

        # Zoek bestaande template op (cwe, owasp_2025)
        existing = db_bevindingen_templates.query.filter_by(
            cwe=vals['cwe'], owasp_2025=vals['owasp_2025']).first()

        if existing is None:
            tmpl = db_bevindingen_templates(**vals)
            db.session.add(tmpl)
            created += 1
        elif enrich:
            # Alleen lege velden aanvullen; referenties altijd samenvoegen
            for field in _FILL_IF_EMPTY:
                if not (getattr(existing, field, '') or '').strip() and vals[field]:
                    setattr(existing, field, vals[field])
            existing.referenties = _merge_references(existing.referenties, vals['referenties'])
            enriched += 1
        else:
            skipped += 1

    db.session.commit()
    return {'created': created, 'enriched': enriched, 'skipped': skipped, 'total': len(records)}
