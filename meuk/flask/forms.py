#!/bin/env python3
# -*- coding: utf-8 -*-

'''
 forms.py
 Formulieren binnen de applicatie
 Let op de corresponderende modellen bij het aanpassen

 Rapportage tool
 Copyright 2020 Jan-Karel Visser - all rights are reserved
 Licensed under the LGPLv3 (http://www.gnu.org/licenses/lgpl.html)

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
    gebruikersvlag = StringField('User flag')
    rootvlag = StringField('Root flag')
    submit = SubmitField('Opslaan')

class BevindingTemplateForm(FlaskForm):
    """Bevindingen velden."""
    naam = StringField('Naam', validators=[DataRequired()])
    owasp = SelectField('OWASP top 10', choices=[('1', 'A1 - Broken Access Control'),
                                                 ('2', 'A2 - Cryptographic Failures'),
                                                 ('3', 'A3 - Injection'),
                                                 ('4', 'A4 - Insecure Design'),
                                                 ('5', 'A5 - Security Misconfiguration'),
                                                 ('6', 'A6 - Vulnerable and Outdated Components'),
                                                 ('7', 'A7 - Identification and Authentication Failures'),
                                                 ('8', 'A8 - Software and Data Integrity Failures'),
                                                 ('9', 'A9 - Security Logging and Monitoring Failures'),
                                                 ('10', 'A10 - Server Side Request Forgery (SSRF)')])
    risico = SelectField(u'Risico', choices=[('1', 'Critical'),
                                             ('2', 'High'),
                                             ('3', 'Medium'),
                                             ('4', 'Low')])
    koppel = StringField('Koppel')
    inhoud = TextAreaField('Inhoud')
    submit = SubmitField('Opslaan')