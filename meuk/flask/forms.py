#!/bin/env python3
# -*- coding: utf-8 -*-

'''
 forms.py
 Formulieren binnen de applicatie
 Let op de corresponderende modellen bij het aanpassen

 Rapportage tool
 Copyright 2020 Jan-Karel Visser - all rights are reserved
 Licensed under the AGPL-3.0-or-later (https://www.gnu.org/licenses/agpl-3.0.html)

 This program is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

'''

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField, MultipleFileField, DateField, DateTimeField, HiddenField
from wtforms.validators import DataRequired, EqualTo, Length




class BevindingForm(FlaskForm):
    id = HiddenField('id')
    naam = StringField('Name the finding')
    invoegen = TextAreaField('Hoe kwam de bevinding tot stand?')
    ref = HiddenField('ref')
    uitwerken = TextAreaField('Werk de bevinding uit...')
    locatie = StringField('Host')
    basescore = StringField('CVSS basescore')
    cvss = StringField('CVSS string')
    gebruikersvlag = StringField('User flag')
    rootvlag = StringField('Root flag')
    status = SelectField('Status', choices=[
        ('draft', 'Concept'), ('final', 'Definitief'), ('closed', 'Gesloten')
    ], default='draft')
    remediation_status = SelectField('Remediation status', choices=[
        ('open', 'Open'), ('in_progress', 'In progress'), ('fixed', 'Fixed'),
        ('verified', 'Verified'), ('accepted', 'Accepted')
    ], default='open')
    remediation_target_date = DateField('Remediation target date', format='%Y-%m-%d', validators=[])
    remediation_owner = StringField('Remediation owner')
    affected_assets = TextAreaField('Affected assets')
    data_classification = SelectField('Data classification', choices=[
        ('', '-- Select --'), ('public', 'Public'), ('internal', 'Internal'),
        ('confidential', 'Confidential'), ('restricted', 'Restricted')
    ], default='')
    business_impact = TextAreaField('Business impact')
    remediation_effort = SelectField('Remediation effort', choices=[
        ('', '-- Select --'), ('low', 'Low'), ('medium', 'Medium'), ('high', 'High')
    ], default='')
    # Retest workflow
    retest_status = SelectField('Retest status', choices=[
        ('not_applicable', 'Niet van toepassing'),
        ('pending_retest', 'Retest gepland'),
        ('retested_fixed', 'Getest — Opgelost'),
        ('retested_open',  'Getest — Nog open'),
    ], default='not_applicable')
    retest_date  = DateField('Retest datum', format='%Y-%m-%d', validators=[])
    retest_notes = TextAreaField('Retest notities')
    # WOEF faalmodus + controle-referentie
    faalmodus = SelectField('Faalmodus', choices=[
        ('',        '-- Selecteer --'),
        ('opzet',   'Opzet (beleid / norm ontbreekt)'),
        ('bestaan', 'Bestaan (maatregel niet geïmplementeerd)'),
        ('werking', 'Werking (maatregel niet effectief)'),
    ], default='')
    control_ref = StringField('Controle-referentie')
    # Detecteerbaarheid
    detecteerbaarheid = SelectField('Detecteerbaarheid', choices=[
        ('',      '-- Selecteer --'),
        ('ja',    'Ja — had gedetecteerd kunnen worden'),
        ('deels', 'Deels — beperkte detectiemogelijkheden'),
        ('nee',   'Nee — geen detectiemogelijkheid'),
    ], default='')
    detectie_notitie = TextAreaField('Detectie toelichting')
    # Risicomatrix assen
    kans = SelectField('Kans (likelihood)', choices=[
        ('', '--'), ('1', '1 - Zeer laag'), ('2', '2 - Laag'),
        ('3', '3 - Midden'), ('4', '4 - Hoog'), ('5', '5 - Zeer hoog'),
    ], default='')
    impact_niveau = SelectField('Impact niveau', choices=[
        ('', '--'), ('1', '1 - Verwaarloosbaar'), ('2', '2 - Beperkt'),
        ('3', '3 - Aanzienlijk'), ('4', '4 - Ernstig'), ('5', '5 - Kritiek'),
    ], default='')
    submit = SubmitField('Opslaan')

class BevindingTemplateForm(FlaskForm):
    """Template bevindingen formulier."""
    id = HiddenField('id')
    titel = StringField('Titel', validators=[DataRequired()])
    bevtype = StringField('Type / code')
    ncsc = SelectField('NCSC/DigiD Richtlijn', choices=[
        ('', '-- Selecteer --'),
        ('U/TV.01', 'U/TV.01 - Toegangsvoorzieningsmiddelen'),
        ('U/WA.01', 'U/WA.01 - Operationeel beleid webapplicaties'),
        ('U/WA.02', 'U/WA.02 - Webapplicatiebeheer'),
        ('U/WA.03', 'U/WA.03 - Webapplicatie-invoer beperken'),
        ('U/WA.04', 'U/WA.04 - Webapplicatie-uitvoer beperken'),
        ('U/WA.05', 'U/WA.05 - Vertrouwelijkheid gegevens'),
        ('U/WA.06', 'U/WA.06 - Webapplicatie-informatie beperken'),
        ('U/WA.07', 'U/WA.07 - Webapplicatie-integratie communiceren'),
        ('U/WA.08', 'U/WA.08 - Webapplicatiesessie beëindigen'),
        ('U/WA.09', 'U/WA.09 - Webapplicatiearchitectuur'),
        ('U/PW.01', 'U/PW.01 - Operationeel beleid platformen'),
        ('U/PW.02', 'U/PW.02 - Webprotocollen garanderen'),
        ('U/PW.03', 'U/PW.03 - Webserver inrichten'),
        ('U/PW.04', 'U/PW.04 - Isolatie processen en bestanden'),
        ('U/PW.05', 'U/PW.05 - Toegang beheermechanismen'),
        ('U/PW.06', 'U/PW.06 - Platform-netwerkkoppeling filteren'),
        ('U/PW.07', 'U/PW.07 - Hardening platformen'),
        ('U/PW.08', 'U/PW.08 - Platform- en webserverarchitectuur'),
        ('U/NW.01', 'U/NW.01 - Operationeel beleid netwerken'),
        ('U/NW.02', 'U/NW.02 - Beschikbaarheid netwerken'),
        ('U/NW.03', 'U/NW.03 - Netwerkzonering'),
        ('U/NW.04', 'U/NW.04 - Protectie- en detectiefunctie'),
        ('U/NW.05', 'U/NW.05 - Beheer- en productieomgeving'),
        ('U/NW.06', 'U/NW.06 - Hardening netwerken'),
        ('U/NW.07', 'U/NW.07 - Netwerktoegang webapplicaties'),
        ('U/NW.08', 'U/NW.08 - Netwerkarchitectuur'),
    ])
    owasp_2025 = SelectField('OWASP Top 10 (2025)', choices=[
        ('', '-- Selecteer --'),
        ('1', 'A1 - Broken Access Control'),
        ('2', 'A2 - Security Misconfiguration'),
        ('3', 'A3 - Software Supply Chain Failures'),
        ('4', 'A4 - Cryptographic Failures'),
        ('5', 'A5 - Injection'),
        ('6', 'A6 - Insecure Design'),
        ('7', 'A7 - Authentication Failures'),
        ('8', 'A8 - Software or Data Integrity Failures'),
        ('9', 'A9 - Security Logging and Alerting Failures'),
        ('10', 'A10 - Mishandling of Exceptional Conditions'),
    ])
    cwe = StringField('CWE')
    mitre = StringField('MITRE ATT&CK')
    cvss = StringField('CVSS 4.0 vector')
    basescore = StringField('CVSS basescore')
    nlbeschrijving = TextAreaField('Beschrijving (NL)')
    enbeschrijving = TextAreaField('Beschrijving (EN)')
    nlimpact = TextAreaField('Impact (NL)')
    enimpact = TextAreaField('Impact (EN)')
    nlaanbeveling = TextAreaField('Aanbeveling (NL)')
    enaanbeveling = TextAreaField('Aanbeveling (EN)')
    referenties = TextAreaField('Referenties')
    submit = SubmitField('Opslaan')