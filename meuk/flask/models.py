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
    checklist_type = db.Column(db.String(20), nullable=False)
    target = db.Column(db.String(255), default='')
    status = db.Column(db.String(16), default='active')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    items = db.relationship('db_checklist_item', backref='checklist', cascade='all, delete-orphan', lazy='selectin')


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

