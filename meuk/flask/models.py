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
    datum = db.Column(db.DateTime, default=date.today())
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



class db_instellingen(db.Model):
    """Bevindingen model."""
    __tablename__ = 'db_instellingen'
    id = db.Column(db.Integer, primary_key=True)
    localhost = db.Column(db.String(255), default='http://127.0.0.1')
    ikzelf = db.Column(db.String(255))
    allowlist = db.Column(db.Text(), default='*')


class db_bevindingen_templates(db.Model):
    """Bevindingen model."""
    __tablename__ = 'db_bevindingen_templates'
    id = db.Column(db.Integer, primary_key=True)
    titel = db.Column(db.String(255))
    cwe = db.Column(db.String(5))
    owasp = db.Column(db.String(255))
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

class db_notes(db.Model):
    """Bevindingen model."""
    __tablename__ = 'db_notes'
    id = db.Column(db.Integer, primary_key=True)
    naam = db.Column(db.String(255))
    uitwerken = db.Column(db.Text())

class db_agents(db.Model):
    """Bevindingen model."""
    __tablename__ = 'db_agents'
    id = db.Column(db.Integer, primary_key=True)
    agent = db.Column(db.String(255))
    uitwerken = db.Column(db.Text())

class db_commands(db.Model):
    """Bevindingen model."""
    __tablename__ = 'db_commands'
    id = db.Column(db.Integer, primary_key=True)
    agent = db.Column(db.String(255))
    response = db.Column(db.Text())
    command = db.Column(db.Text())








