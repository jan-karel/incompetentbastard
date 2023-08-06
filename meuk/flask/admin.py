#!/bin/env python3
# -*- coding: utf-8 -*-

'''
 admin.py
 Beheer functionaliteit

 Rapportage tool
 Copyright 2020 Jan-Karel Visser - all rights are reserved
 Licensed under the LGPLv3 (http://www.gnu.org/licenses/lgpl.html)

 This program is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

'''

import os.path as op

from flask import current_app as app
from flask_admin import Admin, AdminIndexView, BaseView
from flask_admin.contrib.fileadmin import FileAdmin
from flask_admin.contrib.sqla import ModelView
from flask_login import current_user
from flask import redirect, request, url_for

#from .models import db_bevindingen_templates, db_bevindingen, db_instellingen
from .models import *

class Bevindingen_templatesview(ModelView):

    def is_accessible(self):
        return True

    form_choices = {
        'owasp': [
            ('1', 'A1 - Broken Access Control'),
            ('2', 'A2 - Crypthographic Failures'),
            ('3', 'A3 - Injection'),
            ('4', 'A4 - Insecure Design'),
            ('5', 'A5 - Security Misconfiguration'),
            ('6', 'A6 - Vulnerable and Outdated Components'),
            ('7', 'A7 - Identification and Authentication Failures'),
            ('8', 'A8 - Software and Data Integrity Failures'),
            ('9', 'A9 - Security Logging and Monitoring Failures'),
            ('10', 'A10 - Server Side Request Forgery')
            ]

    }
    column_exclude_list = ['kans','impact','cve','nlbeschrijving', 'enbeschrijving', 'nlimpact', 'enimpact', 'nlimpactkort', 'enimpactkort','nlaanbevelingkort','nlaanbeveling','enaanbeveling', 'enaanbevelingkort','referenties']





class Bevindingen_view(ModelView):

    def is_accessible(self):
        return True

class Instellingen(ModelView):

    def is_accessible(self):
        return True

class Tijdelijk(ModelView):

    def is_accessible(self):
        return True


admin = Admin(app, name='incompetent bastard', template_mode='bootstrap3', url='/dashboard/admin')
admin.add_view(Bevindingen_templatesview(db_bevindingen_templates, db.session, name='Templates'))
admin.add_view(Bevindingen_view(db_bevindingen, db.session, name='Bevindingen'))
admin.add_view(Tijdelijk(db_xxs_cookies, db.session, name='db_xxs_cookies', category="XSS"))
admin.add_view(Tijdelijk(db_xxs_hooked, db.session, name='db_xxs_hooked', category="XSS"))
admin.add_view(Tijdelijk(db_xxs_login, db.session, name='db_xxs_login', category="XSS"))
admin.add_view(Tijdelijk(db_xxs_localstorage, db.session, name='db_xxs_localstorage', category="XSS"))
admin.add_view(Tijdelijk(db_xxs_keylogger, db.session, name='db_xxs_keylogger', category="XSS"))
admin.add_view(Tijdelijk(db_xxs_form, db.session, name='db_xxs_form', category="XSS"))
admin.add_view(Instellingen(db_instellingen, db.session, name='Instellingen'))


