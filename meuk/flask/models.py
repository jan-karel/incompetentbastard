import base64
import datetime
from datetime import date
import os

from flask import current_app as app
from app import db


class db_xxs_cookies(db.Model):
    """Bevindingen model."""
    __tablename__ = 'db_xxs_cookies'
    id = db.Column(db.Integer, primary_key=True)
    datum = db.Column(db.DateTime, default=date.today())
    agent = db.Column(db.String(255))
    ip = db.Column(db.String(255))
    naam = db.Column(db.String(255))
    md5 = db.Column(db.String(32))
    cookies = db.Column(db.Text())
    locatie = db.Column(db.Text())


class db_xxs_form(db.Model):
    """Bevindingen model."""
    __tablename__ = 'db_xxs_form'
    id = db.Column(db.Integer, primary_key=True)
    datum = db.Column(db.DateTime, default=date.today())
    agent = db.Column(db.String(255))
    ip = db.Column(db.String(255))
    naam = db.Column(db.String(255))
    md5 = db.Column(db.String(32))
    form = db.Column(db.Text())
    locatie = db.Column(db.Text())

class db_xxs_hooked(db.Model):
    """Bevindingen model."""
    __tablename__ = 'db_xxs_hooked'
    id = db.Column(db.Integer, primary_key=True)
    datum = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    agent = db.Column(db.String(255))
    ip = db.Column(db.String(255))
    md5 = db.Column(db.String(32))

class db_xxs_login(db.Model):
    """Bevindingen model."""
    __tablename__ = 'db_xxs_login'
    id = db.Column(db.Integer, primary_key=True)
    datum = db.Column(db.DateTime, default=date.today())
    agent = db.Column(db.String(255))
    ip = db.Column(db.String(255))
    username = db.Column(db.String(255))
    md5 = db.Column(db.String(32))
    password = db.Column(db.String(255))

class db_xxs_localstorage(db.Model):
    """Bevindingen model."""
    __tablename__ = 'db_xxs_localstorage'
    id = db.Column(db.Integer, primary_key=True)
    datum = db.Column(db.DateTime, default=date.today())
    agent = db.Column(db.String(255))
    ip = db.Column(db.String(255))
    naam = db.Column(db.String(255))
    md5 = db.Column(db.String(32))
    localstorage = db.Column(db.Text())
    locatie = db.Column(db.Text())

class db_xxs_keylogger(db.Model):
    """Bevindingen model."""
    __tablename__ = 'db_xxs_keylogger'
    id = db.Column(db.Integer, primary_key=True)
    datum = db.Column(db.DateTime, default=date.today())
    agent = db.Column(db.String(255))
    ip = db.Column(db.String(255))
    naam = db.Column(db.String(255))
    md5 = db.Column(db.String(32))
    toetsen = db.Column(db.Text())
    locatie = db.Column(db.Text())

class db_xxs_commands(db.Model):
    """Bevindingen model."""
    __tablename__ = 'db_xxs_commands'
    id = db.Column(db.Integer, primary_key=True)
    host = db.Column(db.String(32), default='*')
    opdracht = db.Column(db.Text())
    status = db.Column(db.String(16), default='queued')
    result = db.Column(db.Text())
    created = db.Column(db.DateTime, default=datetime.datetime.utcnow)



class db_instellingen(db.Model):
    """Bevindingen model."""
    __tablename__ = 'db_instellingen'
    id = db.Column(db.Integer, primary_key=True)
    localhost = db.Column(db.String(255), default='http://127.0.0.1')
    ikzelf = db.Column(db.String(255))
    allowlist = db.Column(db.Text(), default='*')
    public_upload = db.Column(db.Boolean, default=False)
    public_downloads = db.Column(db.Boolean, default=False)
    public_payloads = db.Column(db.Boolean, default=False)
    behind_proxy = db.Column(db.Boolean, default=False)
    obfuscate_downloads = db.Column(db.Boolean, default=False)
    obfuscate_technique = db.Column(db.String(20), default='mixed')
    default_payload = db.Column(db.String(255), default='')
    rapport_titel = db.Column(db.String(200), default='Penetration Test Report')
    rapport_auteur = db.Column(db.String(200), default='')
    rapport_subtitel = db.Column(db.String(200), default='')
    rapport_project = db.Column(db.String(200), default='')
    rapport_omgeving = db.Column(db.String(200), default='')
    rapport_classificatie = db.Column(db.String(200), default='TLP:RED')
    rapport_taal = db.Column(db.String(5), default='nl')
    rapport_isdraft = db.Column(db.Boolean, default=True)
    rapport_testtype = db.Column(db.String(20), default='pentest')
    rapport_testscope = db.Column(db.String(60), default='blackbox')
    rapport_management_samenvatting = db.Column(db.Text(), default='')
    rapport_legsup_startpunt = db.Column(db.Text(), default='')
    rapport_legsup_privileges = db.Column(db.Text(), default='')
    rapport_legsup_informatie = db.Column(db.Text(), default='')
    rapport_scenarios = db.Column(db.Text(), default='[]')
    rapport_scope_targets = db.Column(db.Text(), default='[]')
    rapport_logo_path = db.Column(db.String(300), default='')
    rapport_template_variant = db.Column(db.String(20), default='detailed')
    rapport_roe = db.Column(db.Text(), default='')
    rapport_test_start_date = db.Column(db.Date)
    rapport_test_end_date = db.Column(db.Date)
    rapport_versie = db.Column(db.String(20), default='')
    rapport_versie_status = db.Column(db.String(20), default='concept')
    rapport_pdf_password = db.Column(db.String(200), default='')
    # Debrief (lessons learned) — hoofdstuk 6
    debrief_context = db.Column(db.Text(), default='')
    debrief_werkte = db.Column(db.Text(), default='')
    debrief_faalde = db.Column(db.Text(), default='')
    debrief_detectie = db.Column(db.Text(), default='')
    debrief_vervolg = db.Column(db.Text(), default='')
    # DefectDojo integratie
    dd_url = db.Column(db.String(300), default='')
    dd_api_key = db.Column(db.String(300), default='')
    dd_product_id = db.Column(db.Integer)
    dd_engagement_id = db.Column(db.Integer)
    dd_verify_ssl = db.Column(db.Boolean, default=True)
    dd_auto_push = db.Column(db.Boolean, default=False)


class db_bevindingen_templates(db.Model):
    """Bevindingen model."""
    __tablename__ = 'db_bevindingen_templates'
    id = db.Column(db.Integer, primary_key=True)
    titel = db.Column(db.String(255))
    bevtype = db.Column(db.String(255))
    cwe = db.Column(db.String(5))
    owasp = db.Column(db.String(255))
    owasp_2025 = db.Column(db.String(16))
    ncsc = db.Column(db.String(16))
    mitre = db.Column(db.String(10))
    cvss = db.Column(db.String(255))
    basescore = db.Column(db.String(10))
    kans = db.Column(db.String(5))
    impact = db.Column(db.String(5))
    nlbeschrijving = db.Column(db.Text())
    enbeschrijving = db.Column(db.Text())
    nlimpactkort = db.Column(db.String(255))
    enimpactkort = db.Column(db.String(255))
    nlimpact = db.Column(db.Text())
    enimpact = db.Column(db.Text())
    nlaanbevelingkort = db.Column(db.String(255))
    enaanbevelingkort = db.Column(db.String(255))
    nlaanbeveling = db.Column(db.Text())
    enaanbeveling = db.Column(db.Text())
    referenties = db.Column(db.Text())

    def __repr__(self):
        return '<db_bevindingen_templates %r>' % self.titel


class db_bevindingen(db.Model):
    """Bevindingen model."""
    __tablename__ = 'db_bevinding'
    id = db.Column(db.Integer, primary_key=True)
    naam = db.Column(db.String(255))
    invoegen = db.Column(db.Text())
    ref = db.Column(db.String(20))
    uitwerken = db.Column(db.Text())
    locatie = db.Column(db.String(255))
    basescore = db.Column(db.String(10))
    cvss = db.Column(db.String(255))
    gebruikersvlag = db.Column(db.String(255))
    rootvlag = db.Column(db.String(255))
    status = db.Column(db.String(16), default='draft')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    discovered_at = db.Column(db.DateTime)
    remediation_status = db.Column(db.String(20), default='open')
    remediation_target_date = db.Column(db.Date)
    remediation_owner = db.Column(db.String(200))
    affected_assets = db.Column(db.Text(), default='')
    data_classification = db.Column(db.String(50), default='')
    business_impact = db.Column(db.Text(), default='')
    remediation_effort = db.Column(db.String(20), default='')
    # Retest workflow
    retest_status = db.Column(db.String(20), default='not_applicable')
    retest_date = db.Column(db.Date)
    retest_notes = db.Column(db.Text(), default='')
    # WOEF faalmodus + controle-referentie
    faalmodus = db.Column(db.String(20), default='')
    control_ref = db.Column(db.String(200), default='')
    # Detecteerbaarheid
    detecteerbaarheid = db.Column(db.String(10), default='')
    detectie_notitie = db.Column(db.Text(), default='')
    # Risicomatrix assen (handmatig of afgeleid van CVSS)
    kans = db.Column(db.String(5), default='')
    impact_niveau = db.Column(db.String(5), default='')
    # Soft-delete
    deleted_at = db.Column(db.DateTime, nullable=True)
    # Koppeling aan opdracht/engagement
    opdracht_id = db.Column(db.Integer, db.ForeignKey('db_opdracht.id'), nullable=True, index=True)

class db_opdracht(db.Model):
    """Opdracht/engagement — scope, tijdvenster en Rules of Engagement (hoofdstuk 2)."""
    __tablename__ = 'db_opdracht'
    id = db.Column(db.Integer, primary_key=True)
    naam = db.Column(db.String(255), nullable=False)
    klant = db.Column(db.String(255), default='')
    scope = db.Column(db.Text(), default='')
    roe = db.Column(db.Text(), default='')
    start_datum = db.Column(db.Date)
    eind_datum = db.Column(db.Date)
    status = db.Column(db.String(20), default='gepland')   # gepland / actief / afgerond
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    bevindingen = db.relationship('db_bevindingen', backref='opdracht', lazy='selectin')
    config = db.relationship('db_opdracht_config', backref='opdracht', uselist=False,
                             cascade='all, delete-orphan', lazy='selectin')


# Velden die per project verschillen (rapport/scope/DefectDojo/debrief).
# Deze staan los van db_instellingen, dat alleen globale app-instellingen houdt.
_PROJECT_CONFIG_FIELDS = (
    'rapport_titel', 'rapport_auteur', 'rapport_subtitel', 'rapport_project',
    'rapport_omgeving', 'rapport_classificatie', 'rapport_taal', 'rapport_isdraft',
    'rapport_testtype', 'rapport_testscope', 'rapport_management_samenvatting',
    'rapport_legsup_startpunt', 'rapport_legsup_privileges', 'rapport_legsup_informatie',
    'rapport_scenarios', 'rapport_scope_targets', 'rapport_logo_path',
    'rapport_template_variant', 'rapport_roe', 'rapport_test_start_date',
    'rapport_test_end_date', 'rapport_versie', 'rapport_versie_status',
    'rapport_pdf_password', 'debrief_context', 'debrief_werkte', 'debrief_faalde',
    'debrief_detectie', 'debrief_vervolg', 'dd_url', 'dd_api_key', 'dd_product_id',
    'dd_engagement_id', 'dd_verify_ssl', 'dd_auto_push',
)


class db_opdracht_config(db.Model):
    """Per-project rapport-, scope-, DefectDojo- en debrief-configuratie (1:1 met db_opdracht)."""
    __tablename__ = 'db_opdracht_config'
    id = db.Column(db.Integer, primary_key=True)
    opdracht_id = db.Column(db.Integer, db.ForeignKey('db_opdracht.id'),
                            unique=True, nullable=False, index=True)
    rapport_titel = db.Column(db.String(200), default='Penetration Test Report')
    rapport_auteur = db.Column(db.String(200), default='')
    rapport_subtitel = db.Column(db.String(200), default='')
    rapport_project = db.Column(db.String(200), default='')
    rapport_omgeving = db.Column(db.String(200), default='')
    rapport_classificatie = db.Column(db.String(200), default='TLP:RED')
    rapport_taal = db.Column(db.String(5), default='nl')
    rapport_isdraft = db.Column(db.Boolean, default=True)
    rapport_testtype = db.Column(db.String(20), default='pentest')
    rapport_testscope = db.Column(db.String(60), default='blackbox')
    rapport_management_samenvatting = db.Column(db.Text(), default='')
    rapport_legsup_startpunt = db.Column(db.Text(), default='')
    rapport_legsup_privileges = db.Column(db.Text(), default='')
    rapport_legsup_informatie = db.Column(db.Text(), default='')
    rapport_scenarios = db.Column(db.Text(), default='[]')
    rapport_scope_targets = db.Column(db.Text(), default='[]')
    rapport_logo_path = db.Column(db.String(300), default='')
    rapport_template_variant = db.Column(db.String(20), default='detailed')
    rapport_roe = db.Column(db.Text(), default='')
    rapport_test_start_date = db.Column(db.Date)
    rapport_test_end_date = db.Column(db.Date)
    rapport_versie = db.Column(db.String(20), default='')
    rapport_versie_status = db.Column(db.String(20), default='concept')
    rapport_pdf_password = db.Column(db.String(200), default='')
    debrief_context = db.Column(db.Text(), default='')
    debrief_werkte = db.Column(db.Text(), default='')
    debrief_faalde = db.Column(db.Text(), default='')
    debrief_detectie = db.Column(db.Text(), default='')
    debrief_vervolg = db.Column(db.Text(), default='')
    dd_url = db.Column(db.String(300), default='')
    dd_api_key = db.Column(db.String(300), default='')
    dd_product_id = db.Column(db.Integer)
    dd_engagement_id = db.Column(db.Integer)
    dd_verify_ssl = db.Column(db.Boolean, default=True)
    dd_auto_push = db.Column(db.Boolean, default=False)


class db_evidence(db.Model):
    __tablename__ = 'db_evidence'
    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(db.Integer, db.ForeignKey('db_bevinding.id'), nullable=False, index=True)
    filename = db.Column(db.String(300), nullable=False)
    original_filename = db.Column(db.String(300))
    content_type = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    tool_name = db.Column(db.String(100))
    timestamp_captured = db.Column(db.DateTime)
    evidence_category = db.Column(db.String(50))
    description = db.Column(db.Text())

    finding = db.relationship('db_bevindingen', backref=db.backref('evidence_files', lazy='selectin', cascade='all, delete-orphan'))


class db_notes(db.Model):
    """Bevindingen model."""
    __tablename__ = 'db_notes'
    id = db.Column(db.Integer, primary_key=True)
    naam = db.Column(db.String(255))
    uitwerken = db.Column(db.Text())
    rapport = db.Column(db.Boolean, default=False)
    volgorde = db.Column(db.Integer, default=0)
    opdracht_id = db.Column(db.Integer, db.ForeignKey('db_opdracht.id'), nullable=True, index=True)

class db_agents(db.Model):
    __tablename__ = 'db_agents'
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(64), unique=True, nullable=False)
    hostname = db.Column(db.String(255))
    username = db.Column(db.String(255))
    os_info = db.Column(db.String(255))
    ip = db.Column(db.String(45))
    script = db.Column(db.String(64))
    last_seen = db.Column(db.DateTime)
    registered = db.Column(db.DateTime)
    status = db.Column(db.String(16), default='active')

class db_commands(db.Model):
    __tablename__ = 'db_commands'
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(64), nullable=False)
    command = db.Column(db.Text())
    response = db.Column(db.Text())
    status = db.Column(db.String(16), default='queued')
    created = db.Column(db.DateTime)
    completed = db.Column(db.DateTime)


class db_xxe(db.Model):
    __tablename__ = 'db_xxe'
    id = db.Column(db.Integer, primary_key=True)
    datum = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    ip = db.Column(db.String(255))
    bestand = db.Column(db.Text())
    data = db.Column(db.Text())
    methode = db.Column(db.String(16))
    md5 = db.Column(db.String(32))


class db_csrf(db.Model):
    __tablename__ = 'db_csrf'
    id = db.Column(db.Integer, primary_key=True)
    datum = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    ip = db.Column(db.String(255))
    agent = db.Column(db.String(255))
    locatie = db.Column(db.Text())
    methode = db.Column(db.String(10))
    actie = db.Column(db.Text())
    data = db.Column(db.Text())
    md5 = db.Column(db.String(32))


class db_sqli(db.Model):
    __tablename__ = 'db_sqli'
    id = db.Column(db.Integer, primary_key=True)
    datum = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    ip = db.Column(db.String(255))
    doel = db.Column(db.Text())
    methode = db.Column(db.String(10))
    payload = db.Column(db.Text())
    response = db.Column(db.Text())
    status = db.Column(db.String(16))
    md5 = db.Column(db.String(32))


class db_sqli_secondorder(db.Model):
    __tablename__ = 'db_sqli_secondorder'
    id = db.Column(db.Integer, primary_key=True)
    datum = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    ip = db.Column(db.String(255))
    label = db.Column(db.String(255))
    stap = db.Column(db.Integer)
    doel_store = db.Column(db.Text())
    doel_trigger = db.Column(db.Text())
    payload = db.Column(db.Text())
    store_response = db.Column(db.Text())
    trigger_response = db.Column(db.Text())
    status = db.Column(db.String(16))
    md5 = db.Column(db.String(32))


class db_sqli_mssql_link(db.Model):
    __tablename__ = 'db_sqli_mssql_link'
    id = db.Column(db.Integer, primary_key=True)
    datum = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    ip = db.Column(db.String(255))
    instance = db.Column(db.String(255))
    linked_to = db.Column(db.String(255))
    keten = db.Column(db.Text())
    sysadmin = db.Column(db.Boolean)
    methode = db.Column(db.String(64))
    resultaat = db.Column(db.Text())
    md5 = db.Column(db.String(32))


class db_ssrf(db.Model):
    __tablename__ = 'db_ssrf'
    id = db.Column(db.Integer, primary_key=True)
    datum = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    ip = db.Column(db.String(255))
    doel = db.Column(db.Text())
    callback_data = db.Column(db.Text())
    bron = db.Column(db.String(64))


class db_finding_related(db.Model):
    __tablename__ = 'db_finding_related'
    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(db.Integer, db.ForeignKey('db_bevinding.id'), nullable=False, index=True)
    related_id = db.Column(db.Integer, db.ForeignKey('db_bevinding.id'), nullable=False, index=True)
    relation_type = db.Column(db.String(20), default='related')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    finding = db.relationship('db_bevindingen', foreign_keys=[finding_id], backref=db.backref('related_from', lazy='selectin'))
    related = db.relationship('db_bevindingen', foreign_keys=[related_id], backref=db.backref('related_to', lazy='selectin'))


class db_checklist(db.Model):
    __tablename__ = 'db_checklist'
    id = db.Column(db.Integer, primary_key=True)
    naam = db.Column(db.String(255), nullable=False)
    checklist_type = db.Column(db.String(40), nullable=False)
    target = db.Column(db.String(255), default='')
    status = db.Column(db.String(16), default='active')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    opdracht_id = db.Column(db.Integer, db.ForeignKey('db_opdracht.id'), nullable=True, index=True)
    items = db.relationship('db_checklist_item', backref='checklist', cascade='all, delete-orphan', lazy='selectin')


class db_checklist_template(db.Model):
    """Eigen (bewerkbare) checklist-sjablonen naast de ingebouwde JSON-types."""
    __tablename__ = 'db_checklist_template'
    id = db.Column(db.Integer, primary_key=True)
    type_key = db.Column(db.String(40), unique=True, nullable=False, index=True)
    title = db.Column(db.String(255), nullable=False)
    icon = db.Column(db.String(40), default='list')
    scope = db.Column(db.String(255), default='')
    description = db.Column(db.Text(), default='')
    data = db.Column(db.Text(), nullable=False, default='{"phases": []}')  # JSON: {"phases": [...]}
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)


class db_checklist_item(db.Model):
    __tablename__ = 'db_checklist_item'
    id = db.Column(db.Integer, primary_key=True)
    checklist_id = db.Column(db.Integer, db.ForeignKey('db_checklist.id'), nullable=False, index=True)
    item_ref = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(16), default='open')
    notitie = db.Column(db.Text(), default='')
    note_id = db.Column(db.Integer)
    finding_id = db.Column(db.Integer)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)


class db_changelog(db.Model):
    __tablename__ = 'db_changelog'
    id = db.Column(db.Integer, primary_key=True)
    table_name = db.Column(db.String(100), nullable=False)
    record_id = db.Column(db.Integer, nullable=False)
    field_name = db.Column(db.String(100), nullable=False)
    old_value = db.Column(db.Text())
    new_value = db.Column(db.Text())
    changed_by = db.Column(db.String(200), default='operator')
    changed_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class db_defectdojo_sync(db.Model):
    """Koppeling tussen een IB-bevinding en een DefectDojo-finding + sync-historie."""
    __tablename__ = 'db_defectdojo_sync'
    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(db.Integer, db.ForeignKey('db_bevinding.id'), nullable=False, index=True)
    opdracht_id = db.Column(db.Integer, db.ForeignKey('db_opdracht.id'), nullable=True, index=True)
    dd_finding_id = db.Column(db.Integer)
    dd_engagement_id = db.Column(db.Integer)
    last_action = db.Column(db.String(20), default='')   # 'create', 'update', 'status'
    last_status = db.Column(db.String(20), default='')   # resultaat: 'ok', 'error'
    last_message = db.Column(db.Text(), default='')
    synced_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class db_asset(db.Model):
    """Asset-inventaris — gededupliceerde doelen (domein/host/service/endpoint).

    Gedeeld over opdrachten (asset-graph), zelf-refererend voor lineage
    (domein -> subdomein -> service -> endpoint). Vervangt het vrije-tekstveld
    db_bevindingen.affected_assets door een eerste-klas entiteit, zodat
    coverage-views en gestructureerde DefectDojo-endpoints mogelijk worden.
    """
    __tablename__ = 'db_asset'
    id = db.Column(db.Integer, primary_key=True)
    opdracht_id = db.Column(db.Integer, db.ForeignKey('db_opdracht.id'), nullable=True, index=True)
    parent_id = db.Column(db.Integer, db.ForeignKey('db_asset.id'), nullable=True, index=True)
    asset_type = db.Column(db.String(20), default='host')   # domain/subdomain/ip/service/app/endpoint
    waarde = db.Column(db.String(500), nullable=False)        # bijv. example.com, 10.0.0.1, https://x/login
    dedupe_key = db.Column(db.String(600), unique=True, index=True)  # genormaliseerde sleutel
    poort = db.Column(db.Integer, nullable=True)
    protocol = db.Column(db.String(20), default='')
    getest = db.Column(db.String(16), default='untested')    # untested/in_progress/tested/out_of_scope
    in_scope = db.Column(db.Boolean, default=True)
    notitie = db.Column(db.Text(), default='')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    opdracht = db.relationship('db_opdracht', backref=db.backref('assets', lazy='selectin'))
    kinderen = db.relationship('db_asset', backref=db.backref('ouder', remote_side=[id]), lazy='selectin')

    def __repr__(self):
        return '<db_asset %r>' % self.waarde


class db_asset_anchor(db.Model):
    """Anchor — koppelt een asset aan een bevinding (ARTEX-stijl).

    Maakt zichtbaar welke bevinding op welk doel slaat en, omgekeerd, welke
    assets wel/niet geraakt zijn (coverage).
    """
    __tablename__ = 'db_asset_anchor'
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('db_asset.id'), nullable=False, index=True)
    finding_id = db.Column(db.Integer, db.ForeignKey('db_bevinding.id'), nullable=False, index=True)
    relatie = db.Column(db.String(20), default='affected')   # affected/tested/pivot
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('asset_id', 'finding_id', name='uq_anchor_asset_finding'),
    )

    asset = db.relationship('db_asset', backref=db.backref('anchors', lazy='selectin', cascade='all, delete-orphan'))
    finding = db.relationship('db_bevindingen', backref=db.backref('asset_anchors', lazy='selectin', cascade='all, delete-orphan'))


class db_explore_node(db.Model):
    """Knoop in de exploration-/aanvalsketen-graaf (ARTEX-stijl, handmatig).

    node_type: start/goal/intent/fact/vulnerability/hint
    status:    pending/in_progress/done/achieved
    Een 'vulnerability'-knoop kan naar een bestaande bevinding verwijzen.
    """
    __tablename__ = 'db_explore_node'
    id = db.Column(db.Integer, primary_key=True)
    opdracht_id = db.Column(db.Integer, db.ForeignKey('db_opdracht.id'), nullable=True, index=True)
    node_type = db.Column(db.String(20), default='intent')
    titel = db.Column(db.String(255), nullable=False)
    omschrijving = db.Column(db.Text(), default='')
    status = db.Column(db.String(20), default='pending')
    prioriteit = db.Column(db.Integer, default=5)   # 0..9 (hoger = belangrijker)
    finding_id = db.Column(db.Integer, db.ForeignKey('db_bevinding.id'), nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    opdracht = db.relationship('db_opdracht', backref=db.backref('explore_nodes', lazy='selectin'))
    finding = db.relationship('db_bevindingen', backref=db.backref('explore_nodes', lazy='selectin'))

    def __repr__(self):
        return '<db_explore_node %r>' % self.titel


class db_explore_edge(db.Model):
    """Gerichte, getypeerde kant in de exploration-graaf.

    edge_type: derive (afgeleid) / intent_chain (intent-keten) /
               produce (produceert) / prove (bewijst)
    """
    __tablename__ = 'db_explore_edge'
    id = db.Column(db.Integer, primary_key=True)
    from_node = db.Column(db.Integer, db.ForeignKey('db_explore_node.id'), nullable=False, index=True)
    to_node = db.Column(db.Integer, db.ForeignKey('db_explore_node.id'), nullable=False, index=True)
    edge_type = db.Column(db.String(20), default='derive')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('from_node', 'to_node', 'edge_type', name='uq_explore_edge'),
    )

    bron = db.relationship('db_explore_node', foreign_keys=[from_node],
                           backref=db.backref('uitgaand', lazy='selectin', cascade='all, delete-orphan'))
    doel = db.relationship('db_explore_node', foreign_keys=[to_node],
                           backref=db.backref('inkomend', lazy='selectin', cascade='all, delete-orphan'))


class db_explore_asset_anchor(db.Model):
    """Anchor tussen een exploration-knoop en een asset (ARTEX-mechanisme).

    Hiermee volgt de dekking van een asset uit de voortgang van de
    exploration-graaf: een asset geldt als 'aangeraakt' zodra een gekoppelde
    knoop de status done/achieved heeft.
    """
    __tablename__ = 'db_explore_asset_anchor'
    id = db.Column(db.Integer, primary_key=True)
    node_id = db.Column(db.Integer, db.ForeignKey('db_explore_node.id'), nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('db_asset.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('node_id', 'asset_id', name='uq_explore_asset_anchor'),
    )

    node = db.relationship('db_explore_node', backref=db.backref(
        'asset_anchors', lazy='selectin', cascade='all, delete-orphan'))
    asset = db.relationship('db_asset', backref=db.backref(
        'explore_anchors', lazy='selectin', cascade='all, delete-orphan'))


class db_amsi_preset(db.Model):
    __tablename__ = 'db_amsi_preset'
    id = db.Column(db.Integer, primary_key=True)
    naam = db.Column(db.String(100), nullable=False)
    categorie = db.Column(db.String(10), default='amsi')      # 'amsi' of 'clm'
    architectuur = db.Column(db.String(10), default='any')    # 'any', 'x64', 'x86', 'arm64'
    methode = db.Column(db.String(30), default='')            # 'reflection', 'patch', 'context', ...
    omschrijving = db.Column(db.String(300), default='')
    code = db.Column(db.Text(), default='')
    actief = db.Column(db.Boolean, default=True)
    ingebouwd = db.Column(db.Boolean, default=False)          # ingebouwde presets niet verwijderbaar
    volgorde = db.Column(db.Integer, default=99)

