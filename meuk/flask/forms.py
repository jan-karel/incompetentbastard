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
    submit = SubmitField('Opslaan')

class BevindingTemplateForm(FlaskForm):
    """Template bevindingen formulier."""
    id = HiddenField('id')
    titel = StringField('Titel', validators=[DataRequired()])
    bevtype = StringField('Type / code')
    owasp = SelectField('OWASP Top 10', choices=[
        ('', '-- Selecteer --'),
        ('1', 'A1 - Broken Access Control'),
        ('2', 'A2 - Cryptographic Failures'),
        ('3', 'A3 - Injection'),
        ('4', 'A4 - Insecure Design'),
        ('5', 'A5 - Security Misconfiguration'),
        ('6', 'A6 - Vulnerable and Outdated Components'),
        ('7', 'A7 - Identification and Authentication Failures'),
        ('8', 'A8 - Software and Data Integrity Failures'),
        ('9', 'A9 - Security Logging and Monitoring Failures'),
        ('10', 'A10 - Server Side Request Forgery (SSRF)'),
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