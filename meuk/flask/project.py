"""Actief-project (opdracht) helpers voor multi-project werking.

Het actieve project wordt per sessie gekozen (projectkiezer in de header) en
bepaalt waarop dashboards, rapport en DefectDojo zich richten. Per-project
configuratie (rapport/scope/DefectDojo/debrief) staat in db_opdracht_config.

Scoping-regel: data van het actieve project PLUS nog niet-toegewezen data
(opdracht_id IS NULL) zolang het actieve project het standaardproject is. Zo
blijft bestaande (legacy) data zichtbaar tot ze met de backfill aan een project
is toegewezen, terwijl andere projecten alleen hun eigen data tonen.
"""

from flask import session, has_request_context, g
from sqlalchemy import event

from meuk.flask.models import (
    db, db_opdracht, db_opdracht_config, db_instellingen,
    db_bevindingen, db_asset, db_explore_node, db_notes, db_checklist,
    db_defectdojo_sync, _PROJECT_CONFIG_FIELDS,
)

SESSION_KEY = 'opdracht_id'
DEFAULT_NAAM = 'Algemeen'


def ensure_default_opdracht():
    """Zorg dat er minstens één project bestaat; retourneer het standaardproject."""
    o = db_opdracht.query.order_by(db_opdracht.id.asc()).first()
    if o is None:
        o = db_opdracht(naam=DEFAULT_NAAM, status='actief')
        db.session.add(o)
        db.session.commit()
    return o


def default_opdracht_id():
    o = db_opdracht.query.order_by(db_opdracht.id.asc()).first()
    return o.id if o else None


def set_override(opdracht_id):
    """Zet een per-request override (bv. tijdens rapportgeneratie) die voorrang
    heeft op de sessiekeuze. Werkt alleen binnen een request-context."""
    if has_request_context():
        g.active_opdracht_id = opdracht_id


def current_opdracht_id():
    """Het actieve project-id: override > sessiekeuze > standaardproject."""
    oid = None
    if has_request_context():
        oid = getattr(g, 'active_opdracht_id', None)
        if oid is None:
            oid = session.get(SESSION_KEY)
    if oid is not None:
        try:
            oid = int(oid)
        except (TypeError, ValueError):
            oid = None
        if oid is not None and db.session.get(db_opdracht, oid) is not None:
            return oid
    return default_opdracht_id()


def current_opdracht():
    oid = current_opdracht_id()
    return db.session.get(db_opdracht, oid) if oid else None


def set_active(opdracht_id):
    """Zet het actieve project in de sessie. None wist de keuze (val terug op standaard)."""
    if opdracht_id is None:
        session.pop(SESSION_KEY, None)
    else:
        session[SESSION_KEY] = int(opdracht_id)


def get_or_create_config(opdracht):
    """Config van een project; maakt 'm aan (seed uit db_instellingen voor het
    standaardproject) bij eerste gebruik."""
    if opdracht is None:
        return None
    cfg = opdracht.config
    if cfg is not None:
        return cfg
    cfg = db_opdracht_config(opdracht_id=opdracht.id)
    # Seed het standaardproject uit de legacy-singleton zodat bestaande
    # rapport-/DefectDojo-config niet verloren gaat.
    if opdracht.id == default_opdracht_id():
        s = db_instellingen.query.first()
        if s is not None:
            for f in _PROJECT_CONFIG_FIELDS:
                val = getattr(s, f, None)
                if val is not None:
                    setattr(cfg, f, val)
    # Neem de engagement-gegevens van het project zelf over in de rapportconfig.
    if opdracht.roe:
        cfg.rapport_roe = opdracht.roe
    if opdracht.start_datum:
        cfg.rapport_test_start_date = opdracht.start_datum
    if opdracht.eind_datum:
        cfg.rapport_test_end_date = opdracht.eind_datum
    if opdracht.klant and not cfg.rapport_project:
        cfg.rapport_project = opdracht.klant
    db.session.add(cfg)
    db.session.commit()
    return cfg


def current_config():
    """Config van het actieve project (maakt standaardproject + config indien nodig)."""
    o = current_opdracht()
    if o is None:
        o = ensure_default_opdracht()
    return get_or_create_config(o)


def config_for(opdracht_id):
    """Config van een specifiek project (maakt 'm aan indien nodig). None → None."""
    if opdracht_id is None:
        return None
    o = db.session.get(db_opdracht, opdracht_id)
    return get_or_create_config(o) if o else None


def resolve_opdracht_id(explicit=None):
    """Bepaal het te gebruiken project-id: expliciet > sessie/standaard."""
    if explicit is not None:
        try:
            return int(explicit)
        except (TypeError, ValueError):
            return None
    return current_opdracht_id()


def scope_filter(column, opdracht_id):
    """SQLAlchemy-filter om op een project te scopen.

    Toont rijen van het project; voor het standaardproject ook niet-toegewezen
    (NULL) rijen. opdracht_id None → geen filter (alles)."""
    if opdracht_id is None:
        return None
    if opdracht_id == default_opdracht_id():
        return db.or_(column == opdracht_id, column.is_(None))
    return column == opdracht_id


def apply_scope(query, column, opdracht_id):
    cond = scope_filter(column, opdracht_id)
    return query.filter(cond) if cond is not None else query


# ── Backfill: bestaande data aan het standaardproject toewijzen ──────────────

# ── Auto-koppeling van nieuwe records aan het expliciet gekozen project ──────
# Gebruikt alleen de sessie-keuze (geen DB-query tijdens flush); records blijven
# anders NULL en vallen onder het standaardproject.

def _assign_active_opdracht(mapper, connection, target):
    if getattr(target, 'opdracht_id', None) is not None:
        return
    if not has_request_context():
        return
    oid = session.get(SESSION_KEY)
    if oid is not None:
        try:
            target.opdracht_id = int(oid)
        except (TypeError, ValueError):
            pass


for _model in (db_bevindingen, db_notes, db_checklist):
    event.listen(_model, 'before_insert', _assign_active_opdracht)


def backfill_to_default():
    """Wijs niet-toegewezen data toe aan het standaardproject en seed diens config.

    Idempotent; retourneert een telling per model."""
    o = ensure_default_opdracht()
    get_or_create_config(o)
    counts = {}
    mapping = {
        'bevindingen': db_bevindingen,
        'assets': db_asset,
        'explore_nodes': db_explore_node,
        'notes': db_notes,
        'checklists': db_checklist,
        'dd_sync': db_defectdojo_sync,
    }
    for naam, model in mapping.items():
        rows = model.query.filter(model.opdracht_id.is_(None)).all()
        for r in rows:
            r.opdracht_id = o.id
        counts[naam] = len(rows)
    db.session.commit()
    return {'opdracht_id': o.id, 'naam': o.naam, 'counts': counts}
